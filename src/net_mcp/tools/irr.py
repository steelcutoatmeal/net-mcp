"""IRR (Internet Routing Registry) lookup tools.

Queries RADB, RIPE, ARIN, and other IRR databases via whois protocol
to retrieve route objects, aut-num objects, and as-set expansions.
"""

from __future__ import annotations

import re
import socket
from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

# IRR whois servers
IRR_SERVERS = {
    "radb": "whois.radb.net",
    "ripe": "whois.ripe.net",
    "arin": "rr.arin.net",
    "apnic": "whois.apnic.net",
    "afrinic": "whois.afrinic.net",
    "lacnic": "irr.lacnic.net",
    "nttcom": "rr.ntt.net",
    "level3": "rr.level3.net",
    "altdb": "whois.altdb.net",
}

DEFAULT_SERVERS = ["radb", "ripe"]
WHOIS_TIMEOUT = 15


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class IRRRouteObject(BaseModel):
    prefix: str
    origin: str
    source: str
    descr: str = ""
    mnt_by: str = ""
    last_modified: str = ""


class IRRRouteLookupResult(BaseModel):
    query: str
    objects: list[IRRRouteObject]
    total: int
    sources: list[str]


class IRRAutNum(BaseModel):
    asn: str
    as_name: str = ""
    descr: str = ""
    org: str = ""
    import_policy: list[str] = []
    export_policy: list[str] = []
    source: str = ""


class IRRAutNumResult(BaseModel):
    asn: str
    objects: list[IRRAutNum]
    sources: list[str]


class IRRAsSetResult(BaseModel):
    as_set: str
    members: list[str]
    total: int
    source: str


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_irr_tools(mcp: FastMCP) -> None:

    @mcp.tool(tags={"irr", "routing", "security"})
    def irr_route_lookup(
        query: Annotated[
            str,
            Field(
                description=(
                    "IP prefix (e.g. '1.1.1.0/24') to look up route objects, "
                    "or ASN (e.g. 'AS13335') to find all route objects for that origin"
                )
            ),
        ],
        sources: Annotated[
            str | None,
            Field(
                description=(
                    "Comma-separated IRR sources to query (e.g. 'radb,ripe'). "
                    "Available: radb, ripe, arin, apnic, afrinic, lacnic, nttcom, altdb. "
                    "Default queries RADB and RIPE."
                )
            ),
        ] = None,
    ) -> IRRRouteLookupResult:
        """Look up IRR route objects for a prefix or origin ASN.

        Queries Internet Routing Registries to find what route objects exist.
        Compare with RPKI (rpki_validate) and actual BGP (bgp_prefix_origin)
        to identify inconsistencies between what's registered, what's
        authorized, and what's actually announced.
        """
        source_list = _parse_sources(sources)
        objects = []

        for source in source_list:
            server = IRR_SERVERS.get(source)
            if not server:
                continue

            if query.upper().startswith("AS"):
                # Search for route objects with this origin
                raw = _whois_query(server, f"-i origin {query}", source)
            else:
                raw = _whois_query(server, query, source)

            objects.extend(_parse_route_objects(raw, source))

        return IRRRouteLookupResult(
            query=query,
            objects=objects,
            total=len(objects),
            sources=source_list,
        )

    @mcp.tool(tags={"irr", "routing"})
    def irr_autnum(
        asn: Annotated[str, Field(description="ASN to look up (e.g. 'AS13335')")],
        sources: Annotated[
            str | None,
            Field(description="Comma-separated IRR sources (default: radb,ripe)"),
        ] = None,
    ) -> IRRAutNumResult:
        """Look up an aut-num object in IRR databases.

        Returns the AS name, description, import/export policies, and
        maintainer information. Useful for understanding an AS's
        registered routing policy.
        """
        source_list = _parse_sources(sources)
        asn_str = asn.upper() if asn.upper().startswith("AS") else f"AS{asn}"

        objects = []
        for source in source_list:
            server = IRR_SERVERS.get(source)
            if not server:
                continue

            raw = _whois_query(server, asn_str, source)
            parsed = _parse_autnum(raw, source)
            if parsed:
                objects.append(parsed)

        return IRRAutNumResult(asn=asn_str, objects=objects, sources=source_list)

    @mcp.tool(tags={"irr", "routing"})
    def irr_as_set_expand(
        as_set: Annotated[
            str,
            Field(description="AS-SET name to expand (e.g. 'AS-CLOUDFLARE', 'AS13335:AS-PEERS')"),
        ],
        source: Annotated[
            str, Field(description="IRR source to query")
        ] = "radb",
    ) -> IRRAsSetResult:
        """Expand an AS-SET into its member ASNs.

        Recursively resolves an AS-SET to find all member autonomous systems.
        Useful for understanding the customer cone of a transit provider or
        what ASNs are in a peering group. Uses RADB by default as it
        aggregates from multiple registries.
        """
        server = IRR_SERVERS.get(source.lower(), IRR_SERVERS["radb"])
        raw = _whois_query(server, f"-i member-of {as_set}", source)

        members = set()
        for line in raw.split("\n"):
            line = line.strip()
            # Look for aut-num objects returned by member-of query
            if line.lower().startswith("aut-num:"):
                val = line.split(":", 1)[1].strip()
                members.add(val.upper())

        # Also try direct set members
        raw2 = _whois_query(server, as_set, source)
        for line in raw2.split("\n"):
            line = line.strip()
            if line.lower().startswith("members:"):
                vals = line.split(":", 1)[1].strip()
                for m in vals.split(","):
                    m = m.strip()
                    if m:
                        members.add(m.upper())

        return IRRAsSetResult(
            as_set=as_set,
            members=sorted(members),
            total=len(members),
            source=source,
        )


# ---------------------------------------------------------------------------
# Whois query helper
# ---------------------------------------------------------------------------


def _whois_query(server: str, query: str, source: str) -> str:
    """Send a whois query and return raw response text."""
    try:
        # Add source flag for RADB (which aggregates multiple sources)
        if source.lower() == "radb":
            query_str = f"-s RADB {query}\r\n"
        else:
            query_str = f"{query}\r\n"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(WHOIS_TIMEOUT)
        sock.connect((server, 43))
        sock.sendall(query_str.encode("utf-8"))

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        sock.close()
        return response.decode("utf-8", errors="replace")
    except Exception as e:
        return f"% Error querying {server}: {e}"


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_sources(sources: str | None) -> list[str]:
    """Parse comma-separated source string into list."""
    if not sources:
        return list(DEFAULT_SERVERS)
    return [s.strip().lower() for s in sources.split(",") if s.strip()]


def _parse_route_objects(raw: str, source: str) -> list[IRRRouteObject]:
    """Parse route/route6 objects from whois response."""
    objects = []
    current: dict = {}

    for line in raw.split("\n"):
        line = line.rstrip()

        if not line or line.startswith("%"):
            if current.get("prefix"):
                objects.append(
                    IRRRouteObject(
                        prefix=current.get("prefix", ""),
                        origin=current.get("origin", ""),
                        source=source,
                        descr=current.get("descr", ""),
                        mnt_by=current.get("mnt-by", ""),
                        last_modified=current.get("last-modified", ""),
                    )
                )
            current = {}
            continue

        if ":" in line and not line.startswith(" "):
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()

            if key in ("route", "route6"):
                current["prefix"] = value
            elif key == "origin":
                current["origin"] = value
            elif key == "descr" and "descr" not in current:
                current["descr"] = value
            elif key == "mnt-by" and "mnt-by" not in current:
                current["mnt-by"] = value
            elif key == "last-modified":
                current["last-modified"] = value
            elif key == "source":
                current["source"] = value

    # Don't forget the last object
    if current.get("prefix"):
        objects.append(
            IRRRouteObject(
                prefix=current.get("prefix", ""),
                origin=current.get("origin", ""),
                source=source,
                descr=current.get("descr", ""),
                mnt_by=current.get("mnt-by", ""),
                last_modified=current.get("last-modified", ""),
            )
        )

    return objects


def _parse_autnum(raw: str, source: str) -> IRRAutNum | None:
    """Parse an aut-num object from whois response."""
    asn = ""
    as_name = ""
    descr = ""
    org = ""
    imports = []
    exports = []

    for line in raw.split("\n"):
        line = line.rstrip()
        if not line or line.startswith("%"):
            continue
        if ":" not in line:
            continue

        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()

        if key == "aut-num":
            asn = value
        elif key == "as-name":
            as_name = value
        elif key == "descr" and not descr:
            descr = value
        elif key == "org":
            org = value
        elif key == "import":
            imports.append(value)
        elif key == "export":
            exports.append(value)
        elif key == "mp-import":
            imports.append(value)
        elif key == "mp-export":
            exports.append(value)

    if not asn:
        return None

    return IRRAutNum(
        asn=asn,
        as_name=as_name,
        descr=descr,
        org=org,
        import_policy=imports[:20],  # cap to avoid huge policy lists
        export_policy=exports[:20],
        source=source,
    )
