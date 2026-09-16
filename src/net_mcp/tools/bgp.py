"""BGP route lookup and analysis tools.

Data sources (see each tool's docstring for the order it uses):
  - RIPEstat        Free, no key. Looking glass, routing status, prefix/ASN
                    data, RIS collector metadata. Primary for most tools.
  - Cloudflare Radar Free with API token. Real-time routes, prefix-to-ASN
                    with RPKI status (primary for bgp_prefix_origin), and the
                    only source for bgp_hijacks / bgp_leaks.
  - bgproutes.io    Requires API key. RIB snapshots with RPKI + ASPA
                    validation, AS topology. Only called when configured.
  - bgp.tools       Free, no key, custom User-Agent required. ASN-to-name
                    CSV (cached in memory) and the full BGP table (last resort).
  - RIPE RIS MRT    Historical RIB dumps / update files via BGPKIT.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from net_mcp import (
    cloudflare_get,
    cloudflare_unavailable_reason,
    get_http_client,
    ripestat_get,
)
from net_mcp.config import get_config
from net_mcp.models import (
    ASNInfo,
    BGPHijackEvent,
    BGPHijackResult,
    BGPLeakEvent,
    BGPLeakResult,
    BGPRoute,
    BGPRouteLookupResult,
    CollectorPeerSummary,
    HistoricalBGPEntry,
    HistoricalBGPResult,
    MRTFile,
    MRTSearchResult,
    PrefixOrigin,
    PrefixOriginResult,
    RouteCollector,
    RouteCollectorResult,
)

logger = logging.getLogger(__name__)

BGP_TOOLS_BASE = "https://bgp.tools"
BGPROUTES_API_BASE = "https://api.bgproutes.io/v1"
HTTP_TIMEOUT = 30
DOWNLOAD_TIMEOUT = 120  # full-table and MRT downloads

# Max routes returned per lookup; `total` still reports how many were seen.
_ROUTE_CAP = 20

# Max prefixes per family returned by bgp_asn_info — large ASes announce
# tens of thousands; the full count is still reported via total_prefixes.
_ASN_PREFIX_CAP = 100

# Max MRT files listed by mrt_search — a multi-day 'update' window is one file
# every 5 minutes; the full count is still reported via `total`.
_MRT_FILE_CAP = 200

_DATA_TYPES = ("rib", "update")


def _normalize_data_type(data_type: str) -> str:
    dt = data_type.strip().lower()
    if dt not in _DATA_TYPES:
        raise ToolError("data_type must be 'rib' or 'update'")
    return dt


def _parse_as_path(raw: str | list | None) -> list[int]:
    """Normalise an AS path from a space-separated string or a list."""
    if not raw:
        return []
    if isinstance(raw, str):
        return [int(a) for a in raw.split() if a.isdigit()]
    return [int(a) for a in raw if str(a).isdigit()]


def _parse_communities(raw: str | list | None) -> list[str]:
    """Normalise communities from a comma-separated string or a list."""
    if not raw:
        return []
    if isinstance(raw, str):
        return [c.strip() for c in raw.split(",") if c.strip()]
    return [str(c) for c in raw]


def _get_bgproutes_key() -> str | None:
    """Return bgproutes.io API key from config or environment."""
    return get_config().bgproutes_api_key


def register_bgp_tools(mcp: FastMCP) -> None:
    @mcp.tool(tags={"bgp", "routing"})
    def bgp_route_lookup(
        prefix: Annotated[
            str, Field(description="IP prefix in CIDR notation (e.g. '1.1.1.0/24')")
        ],
        collector: Annotated[
            str | None,
            Field(
                description=(
                    "RIPE RIS collector ID to filter by (e.g. 'RRC00', 'RRC06'). "
                    "Use ris_collectors to see available collectors and their locations. "
                    "None queries all collectors."
                )
            ),
        ] = None,
    ) -> BGPRouteLookupResult:
        """Look up current BGP routes for a prefix from global routing tables.

        Returns BGP route entries including origin AS, AS path, communities,
        and peer information. Optionally filter by a specific RIPE RIS collector
        to get a regional perspective (e.g. RRC06 for Tokyo, RRC15 for Sao Paulo).

        Source order: RIPEstat looking glass, then Cloudflare Radar (if a
        token is configured), then bgproutes.io (if a key is configured), then
        the bgp.tools full table only if RIPEstat itself failed. At most 20
        routes are returned; `total` reports how many were observed. Use
        ris_collectors first to pick a collector ID for a regional view.
        """
        # 1a. RIPEstat looking glass (free, no key, reliable)
        ripestat_result = _ripestat_route_lookup(prefix, collector=collector)
        if ripestat_result.routes:
            return ripestat_result

        # 1b. Cloudflare Radar realtime routes (free with token)
        result = _cloudflare_route_lookup(prefix)
        if result is not None and result.routes:
            return result

        # 2. bgproutes.io (requires API key, includes RPKI ROV + ASPA)
        api_key = _get_bgproutes_key()
        if api_key:
            result = _bgproutes_route_lookup(prefix, api_key)
            if result is not None:
                return result

        # 3. bgp.tools table — downloads the full BGP table, so only use it as
        #    a true last resort when the primary source actually failed. If
        #    RIPEstat answered successfully but the prefix simply isn't routed,
        #    return that empty result rather than pulling the whole table.
        if ripestat_result.error:
            return _bgptools_route_lookup(prefix)
        return ripestat_result

    @mcp.tool(tags={"bgp", "routing", "collectors"})
    def ris_collectors(
        region: Annotated[
            str | None,
            Field(
                description=(
                    "Filter by region keyword (e.g. 'europe', 'asia', 'us', "
                    "'south america', 'africa'). Case-insensitive. None returns all."
                )
            ),
        ] = None,
        active_only: Annotated[
            bool, Field(description="Only return active collectors")
        ] = True,
    ) -> RouteCollectorResult:
        """List RIPE RIS route collectors with location, peer counts, and status.

        Use this to understand where BGP data is collected from. Each collector
        is at a specific IXP or operates as a multihop peer. Collectors with
        more full-feed peers provide better global visibility.

        Common use cases:
        - Need Asian perspective? Use RRC06 (Tokyo) or RRC23 (Singapore)
        - Need US perspective? Use RRC11 (NYC), RRC14 (Palo Alto), RRC16 (Miami)
        - Need South American view? Use RRC15 (Sao Paulo) or RRC24 (Montevideo)
        - Need African view? Use RRC19 (Johannesburg)
        - Need best global visibility? Use RRC00 or RRC25 (multihop, most peers)
        """
        return _get_ris_collectors(region=region, active_only=active_only)

    @mcp.tool(tags={"bgp", "routing", "historical"})
    def mrt_search(
        time_start: Annotated[
            str,
            Field(
                description="Start time in ISO 8601 format (e.g. '2026-03-22T00:00:00')"
            ),
        ],
        time_end: Annotated[
            str,
            Field(
                description=(
                    "End time in ISO 8601 format. For a RIB snapshot at a point "
                    "in time, set end = start + 8 hours (RIB dumps are every 8h)."
                )
            ),
        ],
        data_type: Annotated[
            str,
            Field(
                description=(
                    "'rib' for routing table snapshots (large, ~400MB, every 8h) "
                    "or 'update' for BGP update messages (small, ~3MB, every 5min). "
                    "Use 'rib' to see full routing state at a point in time. "
                    "Use 'update' to see what changed during a time window."
                )
            ),
        ] = "rib",
        collector: Annotated[
            str | None,
            Field(
                description=(
                    "RIPE RIS collector ID (e.g. 'rrc00'). Use ris_collectors to "
                    "find the right one. Defaults to the configured collector "
                    "(rrc00, global multihop)."
                )
            ),
        ] = None,
    ) -> MRTSearchResult:
        """Find available MRT data files for a given time range and collector.

        Use this to discover what historical BGP data is available before
        calling bgp_historical_lookup. Returns URLs, sizes, and timestamps
        for each MRT file.

        RIB dumps (bview) are snapshots of the full routing table, taken
        every 8 hours at 00:00, 08:00, 16:00 UTC. Use these to see what
        the routing table looked like at a specific time.

        Update files contain BGP announcements and withdrawals, archived
        every 5 minutes. Use these to see route changes during an incident.
        """
        return _mrt_search(time_start, time_end, data_type, collector)

    @mcp.tool(tags={"bgp", "routing", "historical"})
    def bgp_historical_lookup(
        prefix: Annotated[
            str, Field(description="IP prefix in CIDR notation (e.g. '1.1.1.0/24')")
        ],
        time_start: Annotated[
            str,
            Field(
                description="Start time in ISO 8601 format (e.g. '2026-03-22T00:00:00')"
            ),
        ],
        time_end: Annotated[
            str,
            Field(description="End time in ISO 8601 format"),
        ],
        data_type: Annotated[
            str,
            Field(
                description="'rib' for routing table snapshot or 'update' for BGP changes"
            ),
        ] = "rib",
        collector: Annotated[
            str | None,
            Field(
                description="RIPE RIS collector ID (e.g. 'rrc00'). Defaults to the configured collector (rrc00)."
            ),
        ] = None,
        max_results: Annotated[
            int, Field(description="Maximum entries to return (default 50)")
        ] = 50,
    ) -> HistoricalBGPResult:
        """Look up historical BGP routes for a prefix from MRT archive data.

        Downloads and parses MRT files from RIPE RIS to show what BGP routes
        existed for a prefix at a specific point in time (rib) or what route
        changes occurred during a time window (update).

        For RIB lookups: shows all routes for the prefix at that snapshot.
        For update lookups: shows announcements and withdrawals during the window.

        Note: RIB files are ~400MB and take 30-60s to download and parse.
        Update files are ~3MB and parse in seconds. Prefer 'update' for
        narrow time windows and 'rib' for full routing state.
        """
        return _bgp_historical_lookup(
            prefix, time_start, time_end, data_type, collector, max_results
        )

    @mcp.tool(tags={"bgp", "routing"})
    def bgp_prefix_origin(
        prefix: Annotated[
            str, Field(description="IP prefix in CIDR notation (e.g. '1.1.1.0/24')")
        ],
    ) -> PrefixOriginResult:
        """Find which AS(es) originate a given prefix.

        Returns the distinct origin ASN(s) with AS names. Cloudflare Radar
        (pfx2as) is queried first because it also reports per-origin RPKI
        status; if it is not configured or returns nothing, RIPEstat
        routing-status is used (no rpki_status). `error` is set only when
        every source failed, so an empty `origins` with no error means the
        prefix is genuinely not announced.
        """
        origins: list[PrefixOrigin] = []
        source = ""
        errors: list[str] = []

        # 1. Cloudflare Radar pfx2as (includes RPKI status per origin)
        cf_data = cloudflare_get("radar/bgp/routes/pfx2as", params={"prefix": prefix})
        if cf_data and cf_data.get("success"):
            source = "Cloudflare Radar pfx2as"
            for entry in cf_data.get("result", {}).get("prefix_origins", []):
                origins.append(
                    PrefixOrigin(
                        prefix=entry.get("prefix", prefix),
                        origin_asn=entry.get("origin", 0),
                        rpki_status=entry.get("rpki_validation"),
                    )
                )
        elif get_config().cloudflare_api_token:
            errors.append("Cloudflare Radar request failed")

        # 2. RIPEstat fallback
        if not origins:
            try:
                data = ripestat_get(
                    "routing-status/data.json", params={"resource": prefix}
                ).get("data", {})
                source = "RIPEstat routing-status"
                for entry in data.get("origins", []):
                    origin_asn = entry.get("origin", 0)
                    if origin_asn:
                        origins.append(
                            PrefixOrigin(
                                prefix=data.get("resource", prefix),
                                origin_asn=origin_asn,
                            )
                        )
            except Exception as exc:
                logger.warning("RIPEstat routing-status failed for %s: %s", prefix, exc)
                errors.append(f"RIPEstat request failed: {exc}")

        # Deduplicate by origin ASN
        seen: set[int] = set()
        unique_origins = []
        for o in origins:
            if o.origin_asn and o.origin_asn not in seen:
                seen.add(o.origin_asn)
                unique_origins.append(o)

        # Enrich with AS names
        for origin in unique_origins:
            origin.as_name = _get_as_name(origin.origin_asn)

        error = None
        if not source and errors:
            error = "; ".join(errors)

        return PrefixOriginResult(
            query_prefix=prefix, origins=unique_origins, source=source, error=error
        )

    @mcp.tool(tags={"bgp", "routing"})
    def bgp_asn_info(
        asn: Annotated[int, Field(description="Autonomous System Number (e.g. 13335)")],
    ) -> ASNInfo:
        """Get information about an Autonomous System.

        Returns the AS name, announced prefixes (v4 and v6), upstream
        providers, and total prefix count. Use this to understand an
        AS's footprint on the Internet.
        """
        name = _get_as_name(asn)
        prefixes_v4, prefixes_v6, error = _get_announced_prefixes(asn)
        upstreams = _get_upstreams(asn)

        # A large transit AS announces tens of thousands of prefixes. Returning
        # them all would flood the model's context, so cap each list and report
        # the true counts via total_prefixes / note. The full lists are still
        # available via bgp_route_lookup or announced-prefixes per prefix.
        total = len(prefixes_v4) + len(prefixes_v6)
        note = ""
        if len(prefixes_v4) > _ASN_PREFIX_CAP or len(prefixes_v6) > _ASN_PREFIX_CAP:
            note = (
                f"Prefix lists truncated to {_ASN_PREFIX_CAP} each of "
                f"{len(prefixes_v4)} IPv4 / {len(prefixes_v6)} IPv6 announced. "
                "total_prefixes reflects the full count."
            )

        return ASNInfo(
            asn=asn,
            name=name,
            prefixes_v4=prefixes_v4[:_ASN_PREFIX_CAP],
            prefixes_v6=prefixes_v6[:_ASN_PREFIX_CAP],
            upstream_asns=upstreams,
            total_prefixes=total,
            note=note,
            error=error,
        )

    @mcp.tool(tags={"bgp", "security"})
    def bgp_hijacks(
        prefix: Annotated[
            str | None,
            Field(description="Filter by affected prefix (e.g. '1.1.1.0/24')"),
        ] = None,
        asn: Annotated[
            int | None,
            Field(description="Filter by involved ASN (hijacker or victim)"),
        ] = None,
        date_start: Annotated[
            str | None,
            Field(description="Start date in ISO 8601 (e.g. '2026-03-01T00:00:00')"),
        ] = None,
        date_end: Annotated[
            str | None,
            Field(description="End date in ISO 8601"),
        ] = None,
        min_confidence: Annotated[
            int, Field(description="Minimum confidence score (0-100)")
        ] = 50,
        max_results: Annotated[int, Field(description="Max events to return")] = 20,
    ) -> BGPHijackResult:
        """Search for BGP origin hijack events.

        Detects when an AS announces prefixes it is not authorized to
        originate (based on RPKI, IRR, and historical data). Each event
        includes a confidence score, the hijacker and victim ASNs,
        affected prefixes, and duration.

        Requires Cloudflare Radar API token (CLOUDFLARE_API_TOKEN).
        """
        return _cloudflare_hijacks(
            prefix, asn, date_start, date_end, min_confidence, max_results
        )

    @mcp.tool(tags={"bgp", "security"})
    def bgp_leaks(
        asn: Annotated[
            int | None,
            Field(description="Filter by involved ASN (leaker or affected)"),
        ] = None,
        date_start: Annotated[
            str | None,
            Field(description="Start date in ISO 8601 (e.g. '2026-03-01T00:00:00')"),
        ] = None,
        date_end: Annotated[
            str | None,
            Field(description="End date in ISO 8601"),
        ] = None,
        max_results: Annotated[int, Field(description="Max events to return")] = 20,
    ) -> BGPLeakResult:
        """Search for BGP route leak events.

        Detects when an AS improperly propagates routes it received from
        one peer to another peer (violating expected routing policy).
        Each event includes the leaking AS, affected origin/prefix counts,
        and detection timestamps.

        Requires Cloudflare Radar API token (CLOUDFLARE_API_TOKEN).
        """
        return _cloudflare_leaks(asn, date_start, date_end, max_results)


# ---------------------------------------------------------------------------
# bgp.tools backends
# ---------------------------------------------------------------------------


# bgp.tools asks that table.jsonl not be fetched more than every 30 minutes.
_BGPTOOLS_TABLE_TTL = 1800


def _bgptools_table_path() -> Path:
    """Local cache path for the bgp.tools full BGP table (inside the MRT cache dir).

    It is a .jsonl file, so the *.gz eviction in _enforce_cache_limit never
    removes it; the 30-minute TTL below governs refresh instead.
    """
    return get_config().ensure_mrt_cache_dir() / "bgptools-table.jsonl"


def _download_bgptools_table(path: Path) -> None:
    """Download bgp.tools/table.jsonl to a local cache file (atomic replace)."""
    tmp = path.with_suffix(".tmp")
    try:
        with get_http_client().stream(
            "GET", f"{BGP_TOOLS_BASE}/table.jsonl", timeout=DOWNLOAD_TIMEOUT
        ) as resp:
            resp.raise_for_status()
            with open(tmp, "wb") as f:
                for chunk in resp.iter_bytes(chunk_size=1024 * 256):
                    f.write(chunk)
        tmp.replace(path)
    finally:
        if tmp.exists():
            tmp.unlink()


def _bgptools_route_lookup(prefix: str) -> BGPRouteLookupResult:
    """Look up a prefix via bgp.tools table.jsonl (full table, filter locally).

    Downloads the full BGP table (~15MB compressed) and caches it on disk.
    The cached copy is reused for 30 minutes (bgp.tools' requested minimum
    refetch interval), so repeated fallbacks don't re-download. This is a
    last-resort source used only when the primary lookups fail.
    """
    try:
        path = _bgptools_table_path()
        fresh = (
            path.exists() and (time.time() - path.stat().st_mtime) < _BGPTOOLS_TABLE_TTL
        )
        if not fresh:
            try:
                _download_bgptools_table(path)
            except Exception as exc:
                # Fall back to a stale cached copy if the refetch failed.
                logger.warning("bgp.tools table download failed: %s", exc)
                if not path.exists():
                    raise

        routes = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if entry.get("CIDR") == prefix:
                    routes.append(
                        BGPRoute(
                            prefix=entry["CIDR"],
                            origin_asn=entry.get("ASN", 0),
                            as_path=[entry.get("ASN", 0)],
                            communities=[],
                            peer_asn=0,
                            peer_ip="",
                            timestamp="",
                            collector="bgp.tools",
                        )
                    )
                    if len(routes) >= _ROUTE_CAP:
                        break

        return BGPRouteLookupResult(
            prefix=prefix,
            routes=routes,
            total=len(routes),
            source="bgp.tools table",
        )
    except Exception as exc:
        logger.warning("bgp.tools table lookup failed for %s: %s", prefix, exc)
        return BGPRouteLookupResult(
            prefix=prefix,
            routes=[],
            total=0,
            source="bgp.tools table",
            error=f"bgp.tools lookup failed: {exc}",
        )


_bgptools_asn_cache: dict[int, str] | None = None


def _bgptools_load_asn_cache() -> dict[int, str]:
    """Download and cache bgp.tools/asns.csv (~120k ASN-to-name mappings).

    Cached in-memory for the lifetime of the server process. The CSV is small
    (~3MB) and bgp.tools asks it not be fetched more than every 30 minutes.
    """
    global _bgptools_asn_cache
    if _bgptools_asn_cache is not None:
        return _bgptools_asn_cache

    try:
        resp = get_http_client().get(f"{BGP_TOOLS_BASE}/asns.csv", timeout=HTTP_TIMEOUT)
        resp.raise_for_status()

        cache = {}
        reader = csv.DictReader(io.StringIO(resp.text))
        for row in reader:
            asn_str = row.get("asn", "").replace("AS", "")
            if asn_str.isdigit():
                cache[int(asn_str)] = row.get("name", "")

        _bgptools_asn_cache = cache
        return cache
    except Exception as exc:
        # Don't poison the cache on a transient failure — leave it unset so
        # the next lookup retries the download instead of returning empty
        # for the lifetime of the process.
        logger.warning("bgp.tools asns.csv download failed: %s", exc)
        return {}


def _bgptools_get_as_name(asn: int) -> str | None:
    """Look up AS name from bgp.tools asns.csv (cached in-memory)."""
    cache = _bgptools_load_asn_cache()
    return cache.get(asn)


# ---------------------------------------------------------------------------
# bgproutes.io backends (requires API key)
# ---------------------------------------------------------------------------


def _bgproutes_route_lookup(prefix: str, api_key: str) -> BGPRouteLookupResult | None:
    """Look up routes via bgproutes.io RIB endpoint.

    Returns routes with RPKI ROV and ASPA validation status per entry.
    Requires BGPROUTES_API_KEY environment variable.
    """
    try:
        resp = get_http_client().get(
            f"{BGPROUTES_API_BASE}/rib",
            params={"prefix_exact_match": prefix},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        entries = data.get("data", data) if isinstance(data, dict) else data
        if not isinstance(entries, list):
            entries = [entries] if entries else []

        routes = []
        for entry in entries[:_ROUTE_CAP]:
            as_path = _parse_as_path(entry.get("aspath", entry.get("as_path")))
            communities = _parse_communities(
                entry.get("communities", entry.get("community"))
            )

            origin_asn = as_path[-1] if as_path else entry.get("origin_asn", 0)

            routes.append(
                BGPRoute(
                    prefix=entry.get("prefix", entry.get("prefixes", prefix)),
                    origin_asn=origin_asn,
                    as_path=as_path,
                    communities=communities,
                    peer_asn=entry.get("vp_asn", 0),
                    peer_ip=entry.get("vp_ip", ""),
                    timestamp=entry.get("timestamp", ""),
                    collector=f"bgproutes.io (VP AS{entry.get('vp_asn', '?')})",
                )
            )

        if not routes:
            return None

        return BGPRouteLookupResult(
            prefix=prefix,
            routes=routes,
            total=len(routes),
            source="bgproutes.io (includes RPKI ROV + ASPA validation)",
        )
    except Exception as exc:
        logger.warning("bgproutes.io RIB lookup failed for %s: %s", prefix, exc)
        return None


def _bgproutes_get_topology(api_key: str, asn: int) -> list[int] | None:
    """Get upstream ASNs via bgproutes.io topology endpoint."""
    try:
        resp = get_http_client().get(
            f"{BGPROUTES_API_BASE}/topology",
            params={"asn": asn},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        entries = data.get("data", data) if isinstance(data, dict) else data
        if not isinstance(entries, list):
            return None

        upstreams = set()
        for entry in entries:
            provider = entry.get("provider_asn", entry.get("upstream_asn"))
            if provider:
                upstreams.add(int(provider))

        return sorted(upstreams) if upstreams else None
    except Exception as exc:
        logger.warning("bgproutes.io topology failed for AS%s: %s", asn, exc)
        return None


# ---------------------------------------------------------------------------
# Cloudflare Radar backends (free with API token)
# ---------------------------------------------------------------------------


def _cloudflare_route_lookup(prefix: str) -> BGPRouteLookupResult | None:
    """Look up real-time BGP routes via Cloudflare Radar."""
    data = cloudflare_get("radar/bgp/routes/realtime", params={"prefix": prefix})
    if not data or not data.get("success"):
        return None

    result = data.get("result", {})
    raw_routes = result.get("routes", [])
    if not raw_routes:
        return None

    routes = []
    for r in raw_routes[:_ROUTE_CAP]:
        as_path = r.get("as_path", [])
        origin_asn = as_path[-1] if as_path else 0
        routes.append(
            BGPRoute(
                prefix=r.get("prefix", prefix),
                origin_asn=origin_asn,
                as_path=as_path,
                communities=[str(c) for c in r.get("communities", [])],
                peer_asn=0,
                peer_ip="",
                timestamp=r.get("timestamp", ""),
                collector=r.get("collector", "cloudflare-radar"),
            )
        )

    return BGPRouteLookupResult(
        prefix=prefix,
        routes=routes,
        total=len(raw_routes),
        source="Cloudflare Radar (real-time)",
    )


def _first(d: dict, *keys, default=None):
    """Return the first present key's value from d, else default.

    Cloudflare's BGP event field names are not contractually stable and could
    not be verified against the live API here (no token in CI). Trying a few
    plausible aliases makes parsing resilient to a renamed field rather than
    silently returning zeros for every event.
    """
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def _cloudflare_hijacks(
    prefix: str | None,
    asn: int | None,
    date_start: str | None,
    date_end: str | None,
    min_confidence: int,
    max_results: int,
) -> BGPHijackResult:
    """Query BGP hijack events from Cloudflare Radar."""
    params: dict = {
        "per_page": max_results,
        "minConfidence": min_confidence,
        "sortBy": "TIME",
        "sortOrder": "DESC",
    }
    if prefix:
        params["prefix"] = prefix
    if asn:
        params["involvedAsn"] = asn
    if date_start:
        params["dateStart"] = date_start
    if date_end:
        params["dateEnd"] = date_end

    data = cloudflare_get("radar/bgp/hijacks/events", params=params)
    if not data or not data.get("success"):
        return BGPHijackResult(
            events=[],
            total=0,
            source="Cloudflare Radar",
            error=cloudflare_unavailable_reason(),
        )

    result = data.get("result", {})
    events = []
    for e in result.get("events", []):
        ongoing_count = _first(e, "on_going_count", "ongoing_count", default=0)
        is_ongoing = e.get(
            "is_ongoing",
            ongoing_count > 0 if isinstance(ongoing_count, (int, float)) else False,
        )
        events.append(
            BGPHijackEvent(
                id=_first(e, "id", default=0),
                confidence_score=_first(e, "confidence_score", "confidence", default=0),
                hijacker_asn=_first(e, "hijacker_asn", "hijack_asn", default=0),
                victim_asns=_first(e, "victim_asns", "victims", default=[]),
                prefixes=_first(e, "prefixes", default=[]),
                hijacker_country=_first(e, "hijacker_country"),
                victim_countries=_first(e, "victim_countries", default=[]),
                duration=_first(e, "duration", default=0),
                is_ongoing=bool(is_ongoing),
                detected_at=_first(e, "min_hijack_ts", "start_time", default=""),
                last_seen=_first(e, "max_hijack_ts", "end_time", default=""),
                peer_count=_first(e, "peer_ip_count", "peer_count", default=0),
                tags=[t.get("name", "") for t in _first(e, "tags", default=[])],
            )
        )

    total = data.get("result_info", {}).get("total_count", len(events))
    return BGPHijackResult(
        events=events,
        total=total,
        source="Cloudflare Radar",
    )


def _cloudflare_leaks(
    asn: int | None,
    date_start: str | None,
    date_end: str | None,
    max_results: int,
) -> BGPLeakResult:
    """Query BGP route leak events from Cloudflare Radar."""
    params: dict = {
        "per_page": max_results,
        "sortBy": "TIME",
        "sortOrder": "DESC",
    }
    if asn:
        params["involvedAsn"] = asn
    if date_start:
        params["dateStart"] = date_start
    if date_end:
        params["dateEnd"] = date_end

    data = cloudflare_get("radar/bgp/leaks/events", params=params)
    if not data or not data.get("success"):
        return BGPLeakResult(
            events=[],
            total=0,
            source="Cloudflare Radar",
            error=cloudflare_unavailable_reason(),
        )

    result = data.get("result", {})
    events = []
    for e in result.get("events", []):
        events.append(
            BGPLeakEvent(
                id=_first(e, "id", default=0),
                leak_asn=_first(e, "leak_asn", "leaker_asn", default=0),
                leak_segment=_first(e, "leak_seg", "leak_segment", default=[]),
                leak_type=_first(e, "leak_type", default=0),
                origin_count=_first(e, "origin_count", default=0),
                prefix_count=_first(e, "prefix_count", default=0),
                peer_count=_first(e, "peer_count", "peer_ip_count", default=0),
                countries=_first(e, "countries", default=[]),
                detected_at=_first(e, "min_ts", "start_time", default=""),
                last_seen=_first(e, "max_ts", "end_time", default=""),
                finished=_first(e, "finished", default=False),
            )
        )

    total = data.get("result_info", {}).get("total_count", len(events))
    return BGPLeakResult(
        events=events,
        total=total,
        source="Cloudflare Radar",
    )


# ---------------------------------------------------------------------------
# RIPEstat backends
# ---------------------------------------------------------------------------

# Region keywords mapped to collector locations for filtering
_REGION_KEYWORDS = {
    "europe": [
        "netherlands",
        "united kingdom",
        "france",
        "germany",
        "switzerland",
        "austria",
        "sweden",
        "italy",
        "spain",
        "russian",
        "romania",
        "bucharest",
    ],
    "asia": ["japan", "tokyo", "singapore", "dubai", "uae"],
    "us": ["california", "new york", "miami", "florida", "palo alto", "san jose"],
    "north america": [
        "california",
        "new york",
        "miami",
        "florida",
        "palo alto",
        "san jose",
    ],
    "south america": ["brazil", "sao paulo", "uruguay", "montevideo"],
    "africa": ["south africa", "johannesburg"],
    "middle east": ["dubai", "uae"],
    "oceania": [],  # no collectors yet
}


def _get_ris_collectors(
    region: str | None = None, active_only: bool = True
) -> RouteCollectorResult:
    """Fetch RIPE RIS route collector metadata."""
    try:
        data = ripestat_get("rrc-info/data.json").get("data", {})
    except Exception as exc:
        logger.warning("RIPEstat rrc-info failed: %s", exc)
        return RouteCollectorResult(
            collectors=[],
            total=0,
            active=0,
            error=f"Failed to fetch collector data from RIPEstat: {exc}",
        )

    collectors = []
    for rrc in data.get("rrcs", []):
        active = not rrc.get("deactivated_on")
        if active_only and not active:
            continue

        location = rrc.get("geographical_location", "")

        # Region filter
        if region:
            region_lower = region.lower()
            keywords = _REGION_KEYWORDS.get(region_lower, [region_lower])
            if not any(kw in location.lower() for kw in keywords):
                continue

        peers = rrc.get("peers", [])
        unique_asns = len({p.get("asn") for p in peers})

        collectors.append(
            RouteCollector(
                id=f"RRC{rrc['id']:02d}",
                name=rrc.get("name", f"RRC{rrc['id']:02d}"),
                location=location,
                type="multihop" if rrc.get("multihop") else "IXP",
                active=active,
                activated_on=rrc.get("activated_on", ""),
                peers=CollectorPeerSummary(
                    total_peers=len(peers),
                    full_feed_v4=sum(1 for p in peers if p.get("is_full_feed_v4")),
                    full_feed_v6=sum(1 for p in peers if p.get("is_full_feed_v6")),
                    unique_asns=unique_asns,
                ),
            )
        )

    active_count = sum(1 for c in collectors if c.active)

    tip = (
        "For best global visibility, use RRC00 or RRC25 (multihop, most peers). "
        "For regional perspective: RRC06/RRC23 (Asia-Pacific), RRC11/RRC14/RRC16 (US), "
        "RRC15/RRC24 (South America), RRC19 (Africa), RRC26 (Middle East). "
        "IXP-based collectors show routes exchanged at that IXP; multihop collectors "
        "peer with networks worldwide via BGP multihop sessions."
    )

    return RouteCollectorResult(
        collectors=collectors,
        total=len(collectors),
        active=active_count,
        tip=tip,
    )


def _broker_query(
    time_start: str, time_end: str, data_type: str, collector: str
) -> list:
    """Query the BGPKIT Broker for MRT files. Raises on broker failure."""
    import bgpkit  # native extension; imported lazily to keep server start fast

    return bgpkit.Broker().query(
        ts_start=time_start,
        ts_end=time_end,
        data_type=data_type,
        collector_id=collector.lower(),
    )


def _mrt_search(
    time_start: str, time_end: str, data_type: str, collector: str | None
) -> MRTSearchResult:
    """Find MRT files via BGPKIT Broker."""
    collector = collector or get_config().default_collector
    data_type = _normalize_data_type(data_type)

    try:
        items = _broker_query(time_start, time_end, data_type, collector)

        files = []
        for item in items:
            files.append(
                MRTFile(
                    url=item.url,
                    collector=item.collector_id,
                    data_type=item.data_type,
                    timestamp_start=item.ts_start,
                    timestamp_end=item.ts_end,
                    size_bytes=item.rough_size,
                )
            )

        # A wide 'update' window yields one file every 5 minutes — thousands of
        # entries for a multi-day range. Cap the returned list; `total` still
        # reports how many files actually exist in the range.
        total_files = len(files)
        truncated = total_files > _MRT_FILE_CAP
        files = files[:_MRT_FILE_CAP]

        if data_type == "rib":
            tip = (
                "RIB files are full routing table snapshots (~400MB). They are "
                "created every 8 hours at 00:00, 08:00, 16:00 UTC. Use "
                "bgp_historical_lookup with data_type='rib' to parse one for "
                "a specific prefix. Parsing takes 30-60s due to file size."
            )
        else:
            tip = (
                "Update files contain BGP announcements and withdrawals (~3MB "
                "each, every 5 minutes). Use bgp_historical_lookup with "
                "data_type='update' to see route changes for a specific prefix. "
                "These parse in seconds."
            )

        if truncated:
            tip = (
                f"Showing the first {_MRT_FILE_CAP} of {total_files} files in "
                f"this range — narrow the time window for the rest. " + tip
            )

        return MRTSearchResult(
            query_start=time_start,
            query_end=time_end,
            collector=collector,
            data_type=data_type,
            files=files,
            total=total_files,
            tip=tip,
        )
    except Exception as exc:
        logger.warning("BGPKIT broker query failed: %s", exc)
        return MRTSearchResult(
            query_start=time_start,
            query_end=time_end,
            collector=collector,
            data_type=data_type,
            files=[],
            total=0,
            error=f"MRT file search failed: {exc}",
        )


def _bgp_historical_lookup(
    prefix: str,
    time_start: str,
    time_end: str,
    data_type: str,
    collector: str | None,
    max_results: int,
) -> HistoricalBGPResult:
    """Download and parse MRT files for historical BGP data.

    Files are cached in the configured mrt_cache_dir. If the file already
    exists locally, it is reused without re-downloading.
    """
    import bgpkit  # native extension; imported lazily to keep server start fast

    cfg = get_config()
    cache_dir = cfg.ensure_mrt_cache_dir()

    collector = collector or cfg.default_collector
    data_type = _normalize_data_type(data_type)

    try:
        items = _broker_query(time_start, time_end, data_type, collector)

        if not items:
            return HistoricalBGPResult(
                prefix=prefix,
                time_start=time_start,
                time_end=time_end,
                collector=collector,
                data_type=data_type,
                entries=[],
                total=0,
                mrt_file="",
                source=f"RIPE RIS MRT archive ({collector})",
                error=f"No MRT files found for {collector} between {time_start} and {time_end}",
            )

        # For RIB: use the closest dump. For updates: parse all files in range.
        if data_type == "rib":
            target_file = items[0]  # earliest RIB in range
            files_to_parse = [target_file]
        else:
            files_to_parse = items

        entries = []
        parsed_url = ""
        for mrt_item in files_to_parse:
            parsed_url = mrt_item.url

            # Check if file is already cached locally
            local_path = _cached_mrt_path(cache_dir, mrt_item.url)
            if local_path.exists():
                parse_target = str(local_path)
            else:
                # Download to cache, then parse locally. Enforce the cache size
                # limit *after* the download (you can't evict to make room for a
                # file you haven't fetched yet), keeping the file we just pulled.
                local_path = _download_mrt(mrt_item.url, cache_dir)
                if local_path is not None:
                    _enforce_cache_limit(
                        cache_dir, cfg.mrt_max_cache_gb, keep=local_path
                    )
                parse_target = str(local_path) if local_path else mrt_item.url

            parser = bgpkit.Parser(url=parse_target, filters={"prefix": prefix})

            for elem in parser:
                origin_asns = elem.origin_asns or []
                origin_asn = origin_asns[0] if origin_asns else 0

                as_path = _parse_as_path(elem.as_path)
                communities = elem.communities or []

                ts = elem.timestamp
                ts_str = (
                    datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%S"
                    )
                    if ts
                    else ""
                )

                entries.append(
                    HistoricalBGPEntry(
                        prefix=elem.prefix,
                        origin_asn=origin_asn,
                        as_path=as_path,
                        communities=communities,
                        peer_asn=elem.peer_asn,
                        peer_ip=elem.peer_ip,
                        timestamp=ts_str,
                        elem_type=elem.elem_type,
                        collector=mrt_item.collector_id,
                        next_hop=elem.next_hop,
                    )
                )

                if len(entries) >= max_results:
                    break

            if len(entries) >= max_results:
                break

        file_urls = (
            parsed_url if len(files_to_parse) == 1 else f"{len(files_to_parse)} files"
        )

        return HistoricalBGPResult(
            prefix=prefix,
            time_start=time_start,
            time_end=time_end,
            collector=collector,
            data_type=data_type,
            entries=entries,
            total=len(entries),
            mrt_file=file_urls,
            source=f"RIPE RIS MRT archive ({collector})",
        )
    except Exception as exc:
        logger.warning("MRT lookup failed for %s: %s", prefix, exc)
        return HistoricalBGPResult(
            prefix=prefix,
            time_start=time_start,
            time_end=time_end,
            collector=collector,
            data_type=data_type,
            entries=[],
            total=0,
            source=f"RIPE RIS MRT archive ({collector})",
            error=f"MRT download/parse failed: {exc}",
        )


def _cached_mrt_path(cache_dir: Path, url: str) -> Path:
    """Derive a local cache path from an MRT URL.

    Preserves the collector/year.month/filename structure:
      https://data.ris.ripe.net/rrc00/2026.03/bview.20260322.0000.gz
      → <cache_dir>/rrc00/2026.03/bview.20260322.0000.gz
    """
    parsed = urlparse(url)
    # path: /rrc00/2026.03/bview.20260322.0000.gz
    rel = parsed.path.lstrip("/")
    return cache_dir / rel


def _download_mrt(url: str, cache_dir: Path) -> Path | None:
    """Download an MRT file to the cache directory. Returns local path or None."""
    local_path = _cached_mrt_path(cache_dir, url)
    local_path.parent.mkdir(parents=True, exist_ok=True)

    # Stream to a temp file and rename atomically: tools run concurrently in a
    # thread pool, so another lookup must never parse a half-written file.
    tmp = local_path.with_suffix(local_path.suffix + ".part")
    try:
        with get_http_client().stream("GET", url, timeout=DOWNLOAD_TIMEOUT) as resp:
            resp.raise_for_status()
            with open(tmp, "wb") as f:
                for chunk in resp.iter_bytes(chunk_size=1024 * 256):
                    f.write(chunk)
        tmp.replace(local_path)
        return local_path
    except Exception as exc:
        logger.warning("MRT download failed for %s: %s", url, exc)
        return None
    finally:
        if tmp.exists():
            tmp.unlink()


def _enforce_cache_limit(
    cache_dir: Path, max_gb: float, keep: Path | None = None
) -> None:
    """Remove oldest cached MRT files if total cache exceeds max_gb.

    `keep`, if given, is never evicted — used to protect a file that was just
    downloaded and is about to be parsed.
    """
    if not cache_dir.exists():
        return

    keep_resolved = keep.resolve() if keep else None
    max_bytes = max_gb * 1024 * 1024 * 1024
    files = sorted(cache_dir.rglob("*.gz"), key=lambda p: p.stat().st_mtime)
    total = sum(f.stat().st_size for f in files)

    while total > max_bytes and files:
        oldest = files.pop(0)
        if keep_resolved is not None and oldest.resolve() == keep_resolved:
            continue
        total -= oldest.stat().st_size
        oldest.unlink()


def _ripestat_route_lookup(
    prefix: str, collector: str | None = None
) -> BGPRouteLookupResult:
    """Route lookup via RIPEstat looking glass, optionally filtered by collector."""
    try:
        data = ripestat_get(
            "looking-glass/data.json",
            params={"resource": prefix},
        ).get("data", {})

        routes = []
        for rrc in data.get("rrcs", []):
            rrc_name = rrc.get("rrc", "")

            # Filter by collector if specified
            if collector and rrc_name.upper() != collector.upper():
                continue

            for peer in rrc.get("peers", []):
                as_path = _parse_as_path(peer.get("as_path"))
                origin_asn = as_path[-1] if as_path else 0
                # The peer ASN is the collector's direct neighbour — the first
                # hop of the AS path — not the route's origin (which is the
                # last hop). RIPEstat's `asn_origin` field is the origin AS.
                peer_asn = as_path[0] if as_path else int(peer.get("peer_asn", 0))
                communities = _parse_communities(peer.get("community"))
                routes.append(
                    BGPRoute(
                        prefix=peer.get("prefix", prefix),
                        origin_asn=origin_asn,
                        as_path=as_path,
                        communities=communities,
                        peer_asn=peer_asn,
                        peer_ip=peer.get("peer", peer.get("ip", "")),
                        timestamp=peer.get("latest_time", ""),
                        collector=rrc_name,
                    )
                )

        source = "RIPEstat Looking Glass"
        if collector:
            source += f" (filtered: {collector.upper()})"

        return BGPRouteLookupResult(
            prefix=prefix,
            routes=routes[:_ROUTE_CAP],
            total=len(routes),
            source=source,
        )
    except Exception as exc:
        logger.warning("RIPEstat looking-glass failed for %s: %s", prefix, exc)
        return BGPRouteLookupResult(
            prefix=prefix,
            routes=[],
            total=0,
            source="RIPEstat Looking Glass",
            error=f"RIPEstat lookup failed: {exc}",
        )


# ---------------------------------------------------------------------------
# Shared helpers (multi-source with fallback)
# ---------------------------------------------------------------------------


def _get_as_name(asn: int) -> str | None:
    """Look up AS name. Tries RIPEstat first, then bgp.tools CSV cache."""
    # 1. RIPEstat
    try:
        name = (
            ripestat_get(
                "as-overview/data.json",
                params={"resource": f"AS{asn}"},
                timeout=10,
            )
            .get("data", {})
            .get("holder")
        )
        if name:
            return name
    except Exception as exc:
        logger.warning("RIPEstat as-overview failed for AS%s: %s", asn, exc)

    # 2. bgp.tools asns.csv (cached in-memory)
    return _bgptools_get_as_name(asn)


def _get_announced_prefixes(asn: int) -> tuple[list[str], list[str], str | None]:
    """Get prefixes announced by an ASN via RIPEstat.

    Returns (v4, v6, error). `error` is set when RIPEstat failed, so callers
    can tell "announces nothing" from "could not check".
    """
    try:
        data = ripestat_get(
            "announced-prefixes/data.json",
            params={"resource": f"AS{asn}"},
        ).get("data", {})

        v4 = []
        v6 = []
        for entry in data.get("prefixes", []):
            pfx = entry.get("prefix", "")
            if ":" in pfx:
                v6.append(pfx)
            elif pfx:
                v4.append(pfx)
        return _sort_prefixes(v4), _sort_prefixes(v6), None
    except Exception as exc:
        logger.warning("RIPEstat announced-prefixes failed for AS%s: %s", asn, exc)
        return [], [], f"RIPEstat announced-prefixes lookup failed: {exc}"


def _sort_prefixes(prefixes: list[str]) -> list[str]:
    """Sort prefixes numerically by network address (not lexicographically).

    Lexicographic sort places '100.0.0.0/8' before '11.0.0.0/8'; numeric sort
    keeps the order sensible, which matters when the list is later truncated.
    """

    def key(p: str):
        try:
            net = ipaddress.ip_network(p, strict=False)
            return (int(net.network_address), net.prefixlen)
        except ValueError:
            return (0, 0)

    return sorted(prefixes, key=key)


def _get_upstreams(asn: int) -> list[int]:
    """Get upstream ASNs. Tries RIPEstat first, then bgproutes.io topology."""
    # 1. RIPEstat (free, no key)
    try:
        data = ripestat_get(
            "asn-neighbours/data.json",
            params={"resource": f"AS{asn}"},
        ).get("data", {})

        upstreams = []
        for neighbour in data.get("neighbours", []):
            if neighbour.get("type") == "left":  # upstream
                upstreams.append(neighbour.get("asn", 0))
        if upstreams:
            return sorted(upstreams)
    except Exception as exc:
        logger.warning("RIPEstat asn-neighbours failed for AS%s: %s", asn, exc)

    # 2. bgproutes.io topology (requires API key)
    api_key = _get_bgproutes_key()
    if api_key:
        result = _bgproutes_get_topology(api_key, asn)
        if result is not None:
            return result

    return []
