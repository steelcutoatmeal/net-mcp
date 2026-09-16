"""PeeringDB lookup tools.

Queries the free PeeringDB API for network, IXP, and facility data.
No API key required for read-only access. Requests go through the shared
pooled ``httpx`` client from :mod:`net_mcp`, which already sets the
User-Agent PeeringDB requires; no PeeringDB-specific headers are needed.

Error contract: upstream failures (HTTP errors, 429 rate limiting, timeouts,
malformed JSON) are never reported as "no data". Every result model carries an
``error`` field that is populated on failure while ``source`` stays "PeeringDB".
Invalid user input raises :class:`fastmcp.exceptions.ToolError`.
"""

from __future__ import annotations

import logging
from typing import Annotated

import httpx
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from net_mcp import get_http_client

logger = logging.getLogger(__name__)

PEERINGDB_API = "https://www.peeringdb.com/api"
HTTP_TIMEOUT = 15

_MAX_ASN = 4_294_967_295
_MAX_IX_RESULTS = 20
_MAX_FAC_RESULTS = 30
_MAX_MEMBERS = 100

_NETIXLAN_FIELDS = "ix_id,asn,name,ipaddr4,ipaddr6,speed,is_rs_peer"

_ERROR_FIELD_DESC = (
    "Set when the PeeringDB request failed; other fields may be empty or partial."
)
_SPEED_DESC = (
    "Port speed at the IX in Mbit/s (e.g. 10000 = 10G, 100000 = 100G); 0 if unknown."
)
_RS_PEER_DESC = (
    "True if the network peers with the IX route servers, so it can be reached "
    "via the route server without negotiating a bilateral session."
)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class PeeringExchange(BaseModel):
    ix_id: int = Field(description="PeeringDB IX id; pass to peeringdb_ix for details.")
    ix_name: str = Field(description="Exchange name as listed in PeeringDB.")
    ipv4: str | None = Field(
        default=None, description="IPv4 address on the IX peering LAN, if any."
    )
    ipv6: str | None = Field(
        default=None, description="IPv6 address on the IX peering LAN, if any."
    )
    speed_mbps: int = Field(default=0, description=_SPEED_DESC)
    is_rs_peer: bool = Field(default=False, description=_RS_PEER_DESC)


class PeeringNetwork(BaseModel):
    asn: int = Field(description="Autonomous System Number of the network.")
    name: str = Field(description="Network name as registered in PeeringDB.")
    aka: str = Field(
        default="", description="Alternate names / brands the network is also known as."
    )
    website: str = Field(default="", description="Network website URL.")
    irr_as_set: str = Field(
        default="",
        description=(
            "IRR as-set or route-set that describes the network's customer cone, "
            "optionally prefixed with the IRR source (e.g. 'RADB::AS-EXAMPLE'). "
            "Use with irr_as_set_expand to build prefix filters."
        ),
    )
    info_type: str = Field(
        default="",
        description=(
            "PeeringDB network type: e.g. 'NSP' (transit provider), 'Content', "
            "'Cable/DSL/ISP' (eyeball), 'Enterprise', 'Educational/Research', "
            "'Non-Profit', 'Route Server', 'Network Services', 'Route Collector', "
            "'Government'. Empty if not set."
        ),
    )
    peering_policy: str = Field(
        default="",
        description=(
            "General peering policy from PeeringDB's policy_general: 'Open' (will "
            "peer with anyone), 'Selective' (case-by-case, usually requires meeting "
            "traffic/location criteria), 'Restrictive' (rarely adds new peers), or "
            "'No' (does not peer). Empty if not set."
        ),
    )
    ipv4_prefixes: int = Field(
        default=0,
        description="Approximate number of IPv4 prefixes announced (self-reported).",
    )
    ipv6_prefixes: int = Field(
        default=0,
        description="Approximate number of IPv6 prefixes announced (self-reported).",
    )
    exchanges: list[PeeringExchange] = Field(
        default_factory=list,
        description="Every IX presence the network has registered, with LAN addresses and port speed.",
    )


class PeeringNetworkResult(BaseModel):
    query_asn: int = Field(description="The ASN that was looked up.")
    network: PeeringNetwork | None = Field(
        description="Matching PeeringDB record, or null if the ASN has no PeeringDB entry."
    )
    source: str = Field(default="PeeringDB", description="Data source name.")
    error: str | None = Field(default=None, description=_ERROR_FIELD_DESC)


class IXPMember(BaseModel):
    asn: int = Field(description="Member network's ASN.")
    name: str = Field(description="Member network's name.")
    ipv4: str | None = Field(
        default=None, description="Member's IPv4 address on the IX peering LAN, if any."
    )
    ipv6: str | None = Field(
        default=None, description="Member's IPv6 address on the IX peering LAN, if any."
    )
    speed_mbps: int = Field(default=0, description=_SPEED_DESC)
    is_rs_peer: bool = Field(default=False, description=_RS_PEER_DESC)


class IXPInfo(BaseModel):
    ix_id: int = Field(
        description="PeeringDB IX id; pass as the query for an exact lookup."
    )
    name: str = Field(description="Exchange name.")
    city: str = Field(default="", description="City where the exchange operates.")
    country: str = Field(default="", description="ISO 3166-1 alpha-2 country code.")
    website: str = Field(default="", description="Exchange website URL.")
    members: list[IXPMember] = Field(
        default_factory=list,
        description=(
            f"Member networks (one entry per ASN, capped at {_MAX_MEMBERS}). Only populated "
            "when include_members is set and this is the IX chosen for the member fetch; "
            "check members_included."
        ),
    )
    members_included: bool = Field(
        default=False,
        description=(
            "True when the member list was fetched for this exchange. Members are fetched "
            "for at most one exchange per call, so other results have this set to false "
            "even when include_members was requested."
        ),
    )
    total_members: int = Field(
        default=0,
        description=(
            "Number of distinct networks connected to the exchange, from PeeringDB's "
            "net_count. Always populated, even when members were not fetched."
        ),
    )


class IXPResult(BaseModel):
    query: str = Field(description="The search string that was used.")
    exchanges: list[IXPInfo] = Field(
        default_factory=list,
        description=f"Matching exchanges (at most {_MAX_IX_RESULTS}).",
    )
    total: int = Field(default=0, description="Number of exchanges returned.")
    source: str = Field(default="PeeringDB", description="Data source name.")
    error: str | None = Field(default=None, description=_ERROR_FIELD_DESC)


class FacilityInfo(BaseModel):
    fac_id: int = Field(description="PeeringDB facility id.")
    name: str = Field(description="Facility name.")
    city: str = Field(default="", description="City where the facility is located.")
    country: str = Field(default="", description="ISO 3166-1 alpha-2 country code.")
    website: str = Field(default="", description="Facility operator website URL.")
    networks_count: int = Field(
        default=0,
        description="Number of networks present at the facility, from PeeringDB's net_count.",
    )
    exchanges_count: int = Field(
        default=0,
        description="Number of IXPs with a presence at the facility, from PeeringDB's ix_count.",
    )


class FacilityResult(BaseModel):
    query: str = Field(description="The search string that was used.")
    facilities: list[FacilityInfo] = Field(
        default_factory=list,
        description=f"Matching facilities (at most {_MAX_FAC_RESULTS}).",
    )
    total: int = Field(default=0, description="Number of facilities returned.")
    source: str = Field(default="PeeringDB", description="Data source name.")
    error: str | None = Field(default=None, description=_ERROR_FIELD_DESC)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_peeringdb_tools(mcp: FastMCP) -> None:

    @mcp.tool(tags={"peeringdb", "peering"})
    def peeringdb_network(
        asn: Annotated[int, Field(description="ASN to look up (e.g. 13335)")],
    ) -> PeeringNetworkResult:
        """Look up a network in PeeringDB by ASN.

        Returns peering policy, network type, IRR as-set, website, and every
        IXP where the network peers (with LAN addresses, port speeds, and
        route-server participation). Useful for understanding a network's
        peering footprint and how to reach it.

        Data source: PeeringDB (two requests: the net record, then its
        netixlan entries). A null `network` with no `error` means the ASN has
        no PeeringDB entry; if `error` is set the lookup failed upstream and
        the record may be missing or partial (e.g. exchanges empty).
        """
        if asn < 1 or asn > _MAX_ASN:
            raise ToolError(
                f"asn must be an integer between 1 and {_MAX_ASN} (e.g. 13335); got {asn}"
            )

        try:
            data = _pdb_get("net", params={"asn": asn, "depth": 0})
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning(
                "peeringdb_network: net lookup for AS%s failed: %s", asn, exc
            )
            return PeeringNetworkResult(
                query_asn=asn, network=None, error=_describe_error(exc)
            )

        nets = data.get("data") or []
        if not nets:
            return PeeringNetworkResult(query_asn=asn, network=None)

        net = nets[0]
        net_id = _int(net.get("id"))

        exchanges: list[PeeringExchange] = []
        error: str | None = None
        if net_id:
            try:
                ix_data = _pdb_get(
                    "netixlan", params={"net_id": net_id, "fields": _NETIXLAN_FIELDS}
                )
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning(
                    "peeringdb_network: netixlan lookup for AS%s failed: %s", asn, exc
                )
                error = f"{_describe_error(exc)} (network record returned, exchange list missing)"
            else:
                exchanges = [
                    PeeringExchange(
                        ix_id=_int(entry.get("ix_id")),
                        ix_name=_str(entry.get("name")),
                        ipv4=_opt_str(entry.get("ipaddr4")),
                        ipv6=_opt_str(entry.get("ipaddr6")),
                        speed_mbps=_int(entry.get("speed")),
                        is_rs_peer=bool(entry.get("is_rs_peer")),
                    )
                    for entry in ix_data.get("data") or []
                ]

        network = PeeringNetwork(
            asn=_int(net.get("asn"), asn),
            name=_str(net.get("name")),
            aka=_str(net.get("aka")),
            website=_str(net.get("website")),
            irr_as_set=_str(net.get("irr_as_set")),
            info_type=_str(net.get("info_type")),
            peering_policy=_str(net.get("policy_general")),
            ipv4_prefixes=_int(net.get("info_prefixes4")),
            ipv6_prefixes=_int(net.get("info_prefixes6")),
            exchanges=exchanges,
        )
        return PeeringNetworkResult(query_asn=asn, network=network, error=error)

    @mcp.tool(tags={"peeringdb", "peering"})
    def peeringdb_ix(
        query: Annotated[
            str,
            Field(
                description=(
                    "IXP name or city to search (e.g. 'AMS-IX', 'Amsterdam', 'DE-CIX'), "
                    "or a numeric PeeringDB IX id for an exact lookup."
                )
            ),
        ],
        include_members: Annotated[
            bool,
            Field(
                description=(
                    "Fetch the member list for the best-matching exchange only "
                    "(exact name match if present, otherwise the first result). "
                    "Costs one extra request; use a specific name or IX id to "
                    "target the exchange you want."
                )
            ),
        ] = False,
    ) -> IXPResult:
        """Search for Internet Exchange Points (IXPs) in PeeringDB.

        Returns exchange name, location, website, and the number of connected
        networks (`total_members`) for every match. With `include_members`,
        the member list (ASN, LAN addresses, port speed, route-server flag) is
        fetched for ONE exchange only: the exact name match if there is one,
        otherwise the first result. That entry has `members_included=true`.
        To get members of a specific exchange, query by its numeric IX id.

        Data source: PeeringDB. A name search that returns nothing falls back
        to a city search. `total_members` comes from PeeringDB's net_count and
        costs no extra requests. If `error` is set the search or the member
        fetch failed upstream and the payload may be empty or partial.
        """
        query = query.strip()
        if not query:
            raise ToolError(
                "query must be a non-empty IXP name, city, or numeric PeeringDB IX id "
                "(e.g. 'AMS-IX', 'Amsterdam', or '26')"
            )

        try:
            if query.isdigit():
                data = _pdb_get("ix", params={"id": int(query)})
            else:
                data = _pdb_get(
                    "ix", params={"name__contains": query, "limit": _MAX_IX_RESULTS}
                )
                if not data.get("data"):
                    data = _pdb_get(
                        "ix", params={"city__contains": query, "limit": _MAX_IX_RESULTS}
                    )
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("peeringdb_ix: search for %r failed: %s", query, exc)
            return IXPResult(query=query, error=_describe_error(exc))

        matches = (data.get("data") or [])[:_MAX_IX_RESULTS]
        exchanges = [
            IXPInfo(
                ix_id=_int(ix.get("id")),
                name=_str(ix.get("name")),
                city=_str(ix.get("city")),
                country=_str(ix.get("country")),
                website=_str(ix.get("website")),
                total_members=_int(ix.get("net_count")),
            )
            for ix in matches
        ]

        error: str | None = None
        if include_members and exchanges:
            target = _pick_member_target(exchanges, query)
            if target.ix_id:
                try:
                    member_data = _pdb_get(
                        "netixlan",
                        params={"ix_id": target.ix_id, "fields": _NETIXLAN_FIELDS},
                    )
                except (httpx.HTTPError, ValueError) as exc:
                    logger.warning(
                        "peeringdb_ix: member fetch for IX %s failed: %s",
                        target.ix_id,
                        exc,
                    )
                    error = (
                        f"{_describe_error(exc)} (exchange list returned, "
                        f"member list for {target.name!r} missing)"
                    )
                else:
                    members = _dedupe_members(member_data.get("data") or [])
                    target.members = members[:_MAX_MEMBERS]
                    target.members_included = True
                    if not target.total_members:
                        target.total_members = len(members)

        return IXPResult(
            query=query, exchanges=exchanges, total=len(exchanges), error=error
        )

    @mcp.tool(tags={"peeringdb", "peering"})
    def peeringdb_facility(
        query: Annotated[
            str,
            Field(
                description=(
                    "Facility name or city to search (e.g. 'Equinix', 'Ashburn'), "
                    "or a numeric PeeringDB facility id for an exact lookup."
                )
            ),
        ],
    ) -> FacilityResult:
        """Search for data center facilities in PeeringDB.

        Returns facility name, location, website, how many networks are
        present (`networks_count`), and how many IXPs are reachable there
        (`exchanges_count`). Useful for understanding colocation options and
        where networks can physically interconnect.

        Data source: PeeringDB, one request (two if the name search is empty
        and falls back to a city search). Counts come from PeeringDB's own
        net_count / ix_count fields, so no per-facility lookups are made.
        If `error` is set the search failed upstream and `facilities` is empty.
        """
        query = query.strip()
        if not query:
            raise ToolError(
                "query must be a non-empty facility name, city, or numeric PeeringDB "
                "facility id (e.g. 'Equinix', 'Ashburn', or '1')"
            )

        try:
            if query.isdigit():
                data = _pdb_get("fac", params={"id": int(query)})
            else:
                data = _pdb_get(
                    "fac", params={"name__contains": query, "limit": _MAX_FAC_RESULTS}
                )
                if not data.get("data"):
                    data = _pdb_get(
                        "fac",
                        params={"city__contains": query, "limit": _MAX_FAC_RESULTS},
                    )
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("peeringdb_facility: search for %r failed: %s", query, exc)
            return FacilityResult(query=query, error=_describe_error(exc))

        facilities = [
            FacilityInfo(
                fac_id=_int(fac.get("id")),
                name=_str(fac.get("name")),
                city=_str(fac.get("city")),
                country=_str(fac.get("country")),
                website=_str(fac.get("website")),
                networks_count=_int(fac.get("net_count")),
                exchanges_count=_int(fac.get("ix_count")),
            )
            for fac in (data.get("data") or [])[:_MAX_FAC_RESULTS]
        ]
        return FacilityResult(query=query, facilities=facilities, total=len(facilities))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pdb_get(endpoint: str, params: dict | None = None) -> dict:
    """GET a PeeringDB API endpoint and return the parsed JSON body.

    Raises ``httpx.HTTPError`` on network failure or a non-2xx status and
    ``ValueError`` on a malformed or unexpectedly shaped body. Callers turn
    these into the result model's ``error`` field via :func:`_describe_error`.
    """
    resp = get_http_client().get(
        f"{PEERINGDB_API}/{endpoint}", params=params or {}, timeout=HTTP_TIMEOUT
    )
    resp.raise_for_status()
    body = resp.json()
    if not isinstance(body, dict):
        raise ValueError(
            f"unexpected response shape from /{endpoint}: {type(body).__name__}"
        )
    return body


def _describe_error(exc: Exception) -> str:
    """Turn an upstream failure into a short, actionable message for the LLM."""
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status == 429:
            retry_after = exc.response.headers.get("Retry-After")
            hint = f"retry after {retry_after}s" if retry_after else "retry later"
            return f"PeeringDB rate limit exceeded (HTTP 429); {hint}"
        return f"PeeringDB returned HTTP {status} for {exc.request.url.path}"
    if isinstance(exc, httpx.TimeoutException):
        return f"PeeringDB request timed out after {HTTP_TIMEOUT}s"
    if isinstance(exc, httpx.HTTPError):
        return f"PeeringDB request failed: {exc}"
    return f"PeeringDB response could not be parsed: {exc}"


def _pick_member_target(exchanges: list[IXPInfo], query: str) -> IXPInfo:
    """Choose the single exchange whose members are fetched.

    Prefers an exact (case-insensitive) name match so that a search for
    'AMS-IX' returns members of AMS-IX itself rather than of whichever
    'AMS-IX <city>' record PeeringDB happens to list first.
    """
    wanted = query.casefold()
    for ix in exchanges:
        if ix.name.casefold() == wanted:
            return ix
    return exchanges[0]


def _dedupe_members(entries: list[dict]) -> list[IXPMember]:
    """Collapse netixlan rows to one IXPMember per ASN (first row wins)."""
    seen: set[int] = set()
    members: list[IXPMember] = []
    for m in entries:
        m_asn = _int(m.get("asn"))
        if m_asn in seen:
            continue
        seen.add(m_asn)
        members.append(
            IXPMember(
                asn=m_asn,
                name=_str(m.get("name")),
                ipv4=_opt_str(m.get("ipaddr4")),
                ipv6=_opt_str(m.get("ipaddr6")),
                speed_mbps=_int(m.get("speed")),
                is_rs_peer=bool(m.get("is_rs_peer")),
            )
        )
    return members


def _int(value: object, default: int = 0) -> int:
    """Coerce a PeeringDB numeric field (may be null or a string) to int."""
    if value is None or isinstance(value, bool):
        return default
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _str(value: object) -> str:
    return "" if value is None else str(value)


def _opt_str(value: object) -> str | None:
    return None if value in (None, "") else str(value)
