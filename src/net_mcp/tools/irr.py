"""IRR (Internet Routing Registry) lookup tools.

Queries RADB, RIPE, ARIN, and other IRR databases via the whois protocol
(raw TCP, port 43) to retrieve route objects, aut-num objects, and as-set
expansions.

Every tool result carries an ``error`` field. A whois failure (DNS, connect,
timeout, oversized response) is reported there rather than being disguised as
an empty result, so the caller can tell "no objects registered" apart from
"the registry could not be reached".
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from collections.abc import Iterator
from typing import Annotated

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

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

# Hard cap on the bytes read from a single whois response. A misbehaving or
# hostile server could otherwise stream data until the process runs out of
# memory. Responses that hit the cap are truncated and flagged via `error`.
_MAX_WHOIS_RESPONSE_BYTES = 8 * 1024 * 1024

# AS-SET recursion bounds
_MAX_SET_DEPTH = 6
_MAX_SET_MEMBERS = 20000
_ASN_RE = re.compile(r"^AS\d+$", re.IGNORECASE)

# Accepts 'AS13335', 'as13335', or a bare '13335' for normalisation to 'ASnnn'.
_ASN_INPUT_RE = re.compile(r"^(?:AS)?(\d+)$", re.IGNORECASE)
_MAX_ASN = 4_294_967_295  # 32-bit ASN space

# RPSL set names: 'AS-FOO', 'AS13335:AS-CUSTOMERS', 'RS-BAR'. Letters, digits,
# '-', '_' and ':' only; this also excludes whois flags and control characters.
_SET_NAME_RE = re.compile(r"^[A-Z0-9][A-Z0-9_:-]*$", re.IGNORECASE)

# Max route objects returned by irr_route_lookup. A busy origin AS has thousands
# of route objects across mirrored registries; returning them all floods the
# model's context. The full count is still reported via `total`.
_MAX_ROUTE_OBJECTS = 200

# Max import/export policy lines kept per aut-num object.
_MAX_POLICY_LINES = 20

_VALID_SOURCES_HELP = f"Valid sources: {', '.join(IRR_SERVERS)}."


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class IRRRouteObject(BaseModel):
    prefix: str = Field(
        description="Prefix from the route:/route6: attribute, e.g. '1.1.1.0/24'"
    )
    origin: str = Field(
        description="Origin ASN from the origin: attribute, e.g. 'AS13335'"
    )
    registry: str = Field(
        description=(
            "IRR server this object was fetched from (one of the queried sources, "
            "e.g. 'radb'). Aggregating registries such as RADB and NTTCOM mirror "
            "objects from RIPE, ARIN, APNIC and others, so this is where the object "
            "was found, not necessarily who maintains it."
        )
    )
    source: str = Field(
        description=(
            "The object's own source: attribute — the registry that authoritatively "
            "holds it (e.g. 'RIPE' for a RIPE object mirrored by RADB). Falls back to "
            "the registry name (upper-cased) if the object has no source: attribute."
        )
    )
    descr: str = Field(
        default="", description="First descr: attribute, with continuation lines joined"
    )
    mnt_by: str = Field(default="", description="First mnt-by: attribute (maintainer)")
    last_modified: str = Field(
        default="", description="last-modified: attribute, if the registry provides one"
    )


class IRRRouteLookupResult(BaseModel):
    query: str = Field(
        description="Normalised query: an ASN as 'ASnnn' or a prefix in CIDR form"
    )
    objects: list[IRRRouteObject] = Field(
        default_factory=list,
        description="Route objects found, capped at 200; `total` holds the uncapped count",
    )
    total: int = Field(
        description="Total route objects found across all queried registries, before the cap"
    )
    sources: list[str] = Field(
        default_factory=list, description="Registries queried, in order"
    )
    error: str | None = Field(
        default=None,
        description="Set when the whois query failed; other fields may be empty or partial.",
    )


class IRRAutNum(BaseModel):
    asn: str = Field(description="ASN from the aut-num: attribute, e.g. 'AS13335'")
    as_name: str = Field(default="", description="as-name: attribute")
    descr: str = Field(
        default="", description="First descr: attribute, with continuation lines joined"
    )
    org: str = Field(
        default="", description="org: attribute (organisation handle), if present"
    )
    import_policy: list[str] = Field(
        default_factory=list,
        description="import: and mp-import: policy lines, capped at 20",
    )
    export_policy: list[str] = Field(
        default_factory=list,
        description="export: and mp-export: policy lines, capped at 20",
    )
    registry: str = Field(
        description="IRR server this object was fetched from (e.g. 'radb'); may be a mirror"
    )
    source: str = Field(
        description=(
            "The object's own source: attribute (the registry that authoritatively "
            "holds it). Falls back to the registry name (upper-cased) if absent."
        )
    )


class IRRAutNumResult(BaseModel):
    asn: str = Field(description="Normalised ASN that was looked up, e.g. 'AS13335'")
    objects: list[IRRAutNum] = Field(
        default_factory=list,
        description="One aut-num object per registry that returned a match",
    )
    sources: list[str] = Field(
        default_factory=list, description="Registries queried, in order"
    )
    error: str | None = Field(
        default=None,
        description="Set when the whois query failed; other fields may be empty or partial.",
    )


class IRRAsSetResult(BaseModel):
    as_set: str = Field(description="AS-SET name that was expanded (upper-cased)")
    members: list[str] = Field(
        default_factory=list,
        description="Sorted, de-duplicated member ASNs after recursive expansion",
    )
    total: int = Field(description="Number of member ASNs")
    source: str = Field(description="Registry queried (e.g. 'radb')")
    error: str | None = Field(
        default=None,
        description="Set when the whois query failed; other fields may be empty or partial.",
    )


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
                    "or ASN (e.g. 'AS13335' or '13335') to find all route objects "
                    "registered with that origin"
                )
            ),
        ],
        sources: Annotated[
            str | None,
            Field(
                description=(
                    "Comma-separated IRR sources to query (e.g. 'radb,ripe'). "
                    f"Available: {', '.join(IRR_SERVERS)}. "
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

        The query must be an ASN ('AS13335' or bare '13335', normalised to
        'AS13335') or an IP prefix/address (normalised to CIDR form); anything
        else is rejected. Each returned object reports both `registry` (the
        server it was fetched from) and `source` (the registry that
        authoritatively holds it), which differ for objects mirrored by RADB.
        Results are capped at 200 objects; `total` is the uncapped count.
        If a registry cannot be reached, `error` is set and the objects from
        the remaining registries are still returned.
        """
        source_list = _parse_sources(sources)
        kind, normalised = _classify_route_query(query)
        whois_q = f"-i origin {normalised}" if kind == "asn" else normalised

        objects: list[IRRRouteObject] = []
        errors: list[str] = []
        for source in source_list:
            raw, err = _whois_query(IRR_SERVERS[source], whois_q)
            if err:
                errors.append(f"{source}: {err}")
            objects.extend(_parse_route_objects(raw, source))

        # Cap the returned list to keep responses bounded; `total` keeps the
        # real count so the caller knows the result was truncated.
        return IRRRouteLookupResult(
            query=normalised,
            objects=objects[:_MAX_ROUTE_OBJECTS],
            total=len(objects),
            sources=source_list,
            error="; ".join(errors) or None,
        )

    @mcp.tool(tags={"irr", "routing"})
    def irr_autnum(
        asn: Annotated[
            str, Field(description="ASN to look up (e.g. 'AS13335' or '13335')")
        ],
        sources: Annotated[
            str | None,
            Field(
                description=(
                    "Comma-separated IRR sources (default: radb,ripe). "
                    f"Available: {', '.join(IRR_SERVERS)}."
                )
            ),
        ] = None,
    ) -> IRRAutNumResult:
        """Look up an aut-num object in IRR databases.

        Returns the AS name, description, import/export policies (capped at
        20 lines each), and organisation handle. Useful for understanding an
        AS's registered routing policy. The ASN may be given as 'AS13335' or
        a bare '13335'.

        One object is returned per queried registry: the first aut-num object
        in that registry's response whose aut-num matches the requested ASN.
        `registry` is the server queried and `source` is the object's own
        source: attribute (they differ for mirrored objects). If a registry
        cannot be reached, `error` is set and results from the remaining
        registries are still returned.
        """
        source_list = _parse_sources(sources)
        asn_str = _normalise_asn(asn)

        objects: list[IRRAutNum] = []
        errors: list[str] = []
        for source in source_list:
            raw, err = _whois_query(IRR_SERVERS[source], asn_str)
            if err:
                errors.append(f"{source}: {err}")
            parsed = _parse_autnum(raw, source, asn_str)
            if parsed:
                objects.append(parsed)

        return IRRAutNumResult(
            asn=asn_str,
            objects=objects,
            sources=source_list,
            error="; ".join(errors) or None,
        )

    @mcp.tool(tags={"irr", "routing"})
    def irr_as_set_expand(
        as_set: Annotated[
            str,
            Field(
                description="AS-SET name to expand (e.g. 'AS-CLOUDFLARE', 'AS13335:AS-PEERS')"
            ),
        ],
        source: Annotated[
            str,
            Field(
                description=f"IRR source to query. Available: {', '.join(IRR_SERVERS)}."
            ),
        ] = "radb",
    ) -> IRRAsSetResult:
        """Expand an AS-SET into its member ASNs.

        Recursively resolves an AS-SET: reads its `members`/`mp-members`
        attributes, follows any nested AS-SET members, and collects every
        member ASN. Useful for understanding the customer cone of a transit
        provider or what ASNs are in a peering group. Uses RADB by default
        because it mirrors objects from many registries.

        The name must look like an RPSL set ('AS-...', 'RS-...', or a
        hierarchical 'AS13335:AS-...' name); bare ASNs are rejected.
        Recursion is bounded (6 levels deep, 20000 ASNs) to keep very large
        transit cones from running unbounded. If any lookup during expansion
        fails, `error` is set and the members collected so far are returned.
        """
        source_key = _resolve_source(source)
        set_name = _validate_set_name(as_set)

        members: set[str] = set()
        visited: set[str] = set()
        errors: list[str] = []
        _expand_as_set(IRR_SERVERS[source_key], set_name, visited, members, errors)

        return IRRAsSetResult(
            as_set=set_name,
            members=sorted(members),
            total=len(members),
            source=source_key,
            error="; ".join(errors) or None,
        )


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def _check_whois_safe(value: str, what: str) -> str:
    """Reject input that could alter the whois request; return it stripped.

    A CR/LF would terminate the query line and let the rest of the string be
    sent as a second whois command; a leading '-' would be parsed by the
    server as a query flag.
    """
    if "\r" in value or "\n" in value:
        raise ToolError(f"{what} must be a single line with no CR/LF characters.")
    stripped = value.strip()
    if not stripped:
        raise ToolError(f"{what} must not be empty.")
    if stripped.startswith("-"):
        raise ToolError(
            f"{what} must not start with '-' (whois flags are not accepted)."
        )
    return stripped


def _normalise_asn(value: str) -> str:
    """Return 'ASnnn' for 'AS13335', 'as13335' or '13335'; raise ToolError otherwise."""
    stripped = _check_whois_safe(value, "ASN")
    m = _ASN_INPUT_RE.match(stripped)
    if not m:
        raise ToolError(
            f"Invalid ASN {stripped!r}: expected 'AS13335' or a bare number like '13335'."
        )
    number = int(m.group(1))
    if number > _MAX_ASN:
        raise ToolError(f"Invalid ASN {stripped!r}: ASNs range from 0 to {_MAX_ASN}.")
    return f"AS{number}"


def _classify_route_query(query: str) -> tuple[str, str]:
    """Classify a route lookup query as ('asn', 'ASnnn') or ('prefix', cidr).

    ASNs accept 'AS13335' or '13335'. Prefixes are validated with
    ``ipaddress.ip_network(strict=False)`` and normalised to their network
    address; a bare IP address is passed through without a /32 or /128 suffix
    so the registry performs its usual containing-route search.
    """
    stripped = _check_whois_safe(query, "query")
    if _ASN_INPUT_RE.match(stripped):
        return "asn", _normalise_asn(stripped)
    try:
        net = ipaddress.ip_network(stripped, strict=False)
    except ValueError:
        raise ToolError(
            f"Invalid query {stripped!r}: expected an ASN like 'AS13335' or '13335', "
            "or an IP prefix like '1.1.1.0/24' or '2606:4700::/32'."
        ) from None
    if "/" in stripped:
        return "prefix", str(net)
    return "prefix", str(net.network_address)


def _validate_set_name(value: str) -> str:
    """Validate an AS-SET/route-set name and return it upper-cased."""
    stripped = _check_whois_safe(value, "AS-SET name").upper()
    if not _SET_NAME_RE.match(stripped) or not _looks_like_set(stripped):
        raise ToolError(
            f"Invalid AS-SET name {stripped!r}: expected a name like 'AS-CLOUDFLARE' "
            "or 'AS13335:AS-PEERS' (letters, digits, '-', '_' and ':' only)."
        )
    return stripped


def _resolve_source(source: str) -> str:
    """Return the canonical IRR_SERVERS key for a source name; raise ToolError if unknown."""
    key = source.strip().lower()
    if key not in IRR_SERVERS:
        raise ToolError(f"Unknown IRR source {source.strip()!r}. {_VALID_SOURCES_HELP}")
    return key


def _parse_sources(sources: str | None) -> list[str]:
    """Parse a comma-separated source string into de-duplicated registry keys.

    Falls back to DEFAULT_SERVERS when empty. Unknown names raise ToolError so a
    typo never silently queries the wrong registry.
    """
    if not sources or not sources.strip():
        return list(DEFAULT_SERVERS)
    out: list[str] = []
    for part in sources.split(","):
        if not part.strip():
            continue
        key = _resolve_source(part)
        if key not in out:
            out.append(key)
    return out or list(DEFAULT_SERVERS)


# ---------------------------------------------------------------------------
# Whois query helper
# ---------------------------------------------------------------------------


def _whois_query(server: str, query: str) -> tuple[str, str | None]:
    """Send one whois query and return ``(response_text, error)``.

    ``error`` is ``None`` on success. On a network failure the text is empty
    and ``error`` describes the failure; if the response exceeds the size cap
    the text is truncated and ``error`` says so. Callers must never treat an
    error as "no objects found".

    No source restriction is applied: RADB mirrors many registries, and
    restricting to `-s RADB` would exclude those mirrored objects, defeating
    the point of querying an aggregating server.
    """
    chunks: list[bytes] = []
    size = 0
    truncated = False
    try:
        with socket.create_connection((server, 43), timeout=WHOIS_TIMEOUT) as sock:
            sock.sendall(f"{query}\r\n".encode())
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size >= _MAX_WHOIS_RESPONSE_BYTES:
                    truncated = True
                    break
    except OSError as exc:  # DNS failure, refused, timeout, reset
        logger.warning("whois query to %s failed: %s", server, exc)
        return "", f"whois query to {server} failed: {type(exc).__name__}: {exc}"

    text = b"".join(chunks).decode("utf-8", errors="replace")
    if truncated:
        logger.warning(
            "whois response from %s exceeded %d bytes; truncated",
            server,
            _MAX_WHOIS_RESPONSE_BYTES,
        )
        return text, (
            f"whois response from {server} exceeded "
            f"{_MAX_WHOIS_RESPONSE_BYTES // (1024 * 1024)} MB and was truncated"
        )
    return text, None


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


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


def _iter_rpsl_objects(raw: str) -> Iterator[dict[str, list[str]]]:
    """Split a whois response into objects and yield each as an attribute map.

    Objects are separated by blank lines. Each yielded dict maps a lower-cased
    attribute name to the list of its values in document order (attributes
    such as `mnt-by:` and `import:` may repeat), with continuation lines
    already merged by `_rpsl_attrs`. Blocks with no attributes (server
    banners and `%` comments) are skipped.
    """
    for block in re.split(r"\n\s*\n", raw):
        attrs: dict[str, list[str]] = {}
        for key, value in _rpsl_attrs(block):
            attrs.setdefault(key, []).append(value)
        if attrs:
            yield attrs


def _first(attrs: dict[str, list[str]], key: str) -> str:
    """Return the first value of an attribute, or '' if absent."""
    values = attrs.get(key)
    return values[0] if values else ""


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
    visited: set[str],
    members: set[str],
    errors: list[str],
    depth: int = 0,
) -> None:
    """Recursively expand an AS-SET, collecting member ASNs into `members`.

    Lookup failures are appended to `errors` (one entry per failed set) and
    expansion continues with whatever else is reachable.
    """
    if depth > _MAX_SET_DEPTH or len(members) >= _MAX_SET_MEMBERS:
        return

    name = name.upper()
    if name in visited:
        return
    visited.add(name)

    raw, err = _whois_query(server, name)
    if err:
        errors.append(f"{name}: {err}")
    for token in _rpsl_set_members(raw):
        t = token.upper()
        if _ASN_RE.match(t):
            members.add(t)
        elif _looks_like_set(t):
            _expand_as_set(server, t, visited, members, errors, depth + 1)
        if len(members) >= _MAX_SET_MEMBERS:
            return


def _parse_route_objects(raw: str, registry: str) -> list[IRRRouteObject]:
    """Parse every route/route6 object from a whois response.

    `registry` is the IRR_SERVERS key the response came from; the object's
    own `source:` attribute is reported separately so mirrored objects are
    not misattributed to the mirror.
    """
    objects: list[IRRRouteObject] = []
    for attrs in _iter_rpsl_objects(raw):
        prefix = _first(attrs, "route") or _first(attrs, "route6")
        if not prefix:
            continue
        objects.append(
            IRRRouteObject(
                prefix=prefix,
                origin=_first(attrs, "origin"),
                registry=registry,
                source=_first(attrs, "source") or registry.upper(),
                descr=_first(attrs, "descr"),
                mnt_by=_first(attrs, "mnt-by"),
                last_modified=_first(attrs, "last-modified"),
            )
        )
    return objects


def _parse_autnum(raw: str, registry: str, asn: str | None = None) -> IRRAutNum | None:
    """Parse the first aut-num object in a whois response.

    When `asn` is given, only an object whose `aut-num:` matches it is
    accepted; objects for other ASNs that a registry may include in the same
    response are skipped rather than having their policies merged in.
    """
    wanted = asn.upper() if asn else None
    for attrs in _iter_rpsl_objects(raw):
        obj_asn = _first(attrs, "aut-num").upper()
        if not obj_asn or (wanted and obj_asn != wanted):
            continue
        imports = attrs.get("import", []) + attrs.get("mp-import", [])
        exports = attrs.get("export", []) + attrs.get("mp-export", [])
        return IRRAutNum(
            asn=obj_asn,
            as_name=_first(attrs, "as-name"),
            descr=_first(attrs, "descr"),
            org=_first(attrs, "org"),
            import_policy=imports[:_MAX_POLICY_LINES],
            export_policy=exports[:_MAX_POLICY_LINES],
            registry=registry,
            source=_first(attrs, "source") or registry.upper(),
        )
    return None
