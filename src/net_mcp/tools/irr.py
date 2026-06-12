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

# AS-SET recursion bounds
_MAX_SET_DEPTH = 6
_MAX_SET_MEMBERS = 20000
_ASN_RE = re.compile(r"^AS\d+$", re.IGNORECASE)


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

        Recursively resolves an AS-SET: reads its `members`/`mp-members`
        attributes, follows any nested AS-SET members, and collects every
        member ASN. Useful for understanding the customer cone of a transit
        provider or what ASNs are in a peering group. Uses RADB by default
        because it mirrors objects from many registries.

        Recursion is bounded (6 levels deep, 20000 ASNs) to keep very large
        transit cones from running unbounded.
        """
        server = IRR_SERVERS.get(source.lower(), IRR_SERVERS["radb"])

        members: set[str] = set()
        visited: set[str] = set()
        _expand_as_set(server, as_set.upper(), source, visited, members)

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
    """Send a whois query and return raw response text.

    No source restriction is applied: RADB mirrors many registries, and
    restricting to `-s RADB` would exclude those mirrored objects, defeating
    the point of querying an aggregating server.
    """
    try:
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


def _rpsl_attrs(raw: str):
    """Yield (key, value) pairs from an RPSL object, merging continuation lines.

    RPSL continuation: a physical line beginning with a space, tab, or '+' is
    a continuation of the previous attribute's value. Without this, multi-line
    attributes (common for large `members:` lists) are silently truncated.
    """
    key: str | None = None
    parts: list[str] = []

    def flush():
        nonlocal key, parts
        if key is not None:
            yield_val = (key, " ".join(p for p in parts if p))
            parts = []
            key = None
            return yield_val
        return None

    for line in raw.split("\n"):
        if not line.strip() or line.startswith("%"):
            out = flush()
            if out:
                yield out
            continue
        if line[0] in " \t+":
            cont = line.strip().lstrip("+").strip()
            if cont:
                parts.append(cont)
            continue
        if ":" in line:
            out = flush()
            if out:
                yield out
            k, _, v = line.partition(":")
            key = k.strip().lower()
            parts = [v.strip()]

    out = flush()
    if out:
        yield out


def _rpsl_set_members(raw: str) -> list[str]:
    """Extract member tokens from an AS-SET's members/mp-members attributes."""
    out: list[str] = []
    for key, value in _rpsl_attrs(raw):
        if key in ("members", "mp-members"):
            for tok in re.split(r"[\s,]+", value):
                tok = tok.strip()
                if tok:
                    out.append(tok)
    return out


def _looks_like_set(token: str) -> bool:
    """True if a member token names an AS-SET/route-set rather than an ASN."""
    t = token.upper()
    return ("AS-" in t) or ("RS-" in t) or (":" in t)


def _expand_as_set(
    server: str,
    name: str,
    source: str,
    visited: set[str],
    members: set[str],
    depth: int = 0,
) -> None:
    """Recursively expand an AS-SET, collecting member ASNs into `members`."""
    if depth > _MAX_SET_DEPTH or len(members) >= _MAX_SET_MEMBERS:
        return

    name = name.upper()
    if name in visited:
        return
    visited.add(name)

    raw = _whois_query(server, name, source)
    for token in _rpsl_set_members(raw):
        t = token.upper()
        if _ASN_RE.match(t):
            members.add(t)
        elif _looks_like_set(t):
            _expand_as_set(server, t, source, visited, members, depth + 1)
        if len(members) >= _MAX_SET_MEMBERS:
            return


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
