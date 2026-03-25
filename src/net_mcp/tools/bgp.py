"""BGP route lookup and analysis tools.

Data sources (in priority order):
  1. RIPEstat      — Free, no API key. Looking glass, routing status, prefix/ASN data.
  2. bgproutes.io  — Requires API key (set BGPROUTES_API_KEY env var). RIB snapshots
                     with RPKI + ASPA validation, BGP updates, AS topology.
                     Only called when API key is configured.
  3. bgp.tools     — Free, no API key. Custom User-Agent required. ASN-to-name
                     mappings (asns.csv), full BGP table (table.jsonl). Last resort.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import httpx
from fastmcp import FastMCP
from pydantic import Field

from net_mcp import ripestat_get
from net_mcp.config import get_config
from net_mcp.models import (
    ASNInfo,
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

BGP_TOOLS_BASE = "https://bgp.tools"
BGP_TOOLS_HEADERS = {"User-Agent": "net-mcp/0.1.0 (https://github.com/net-mcp)"}
BGPROUTES_API_BASE = "https://api.bgproutes.io/v1"
HTTP_TIMEOUT = 30


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

        Use ris_collectors first to see which collectors are available and where
        they are located, then pass a collector ID here for targeted lookups.
        """
        # 1. RIPEstat looking glass (free, no key, reliable)
        result = _ripestat_route_lookup(prefix, collector=collector)
        if result.routes:
            return result

        # 2. bgproutes.io (requires API key, includes RPKI ROV + ASPA)
        api_key = _get_bgproutes_key()
        if api_key:
            result = _bgproutes_route_lookup(prefix, api_key)
            if result is not None:
                return result

        # 3. bgp.tools table (full table download, last resort)
        return _bgptools_route_lookup(prefix)

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
                description=(
                    "Start time in ISO 8601 format (e.g. '2026-03-22T00:00:00') "
                    "or relative like '2 days ago' converted to ISO 8601."
                )
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
                    "find the right one. Defaults to rrc00 (global multihop)."
                )
            ),
        ] = "rrc00",
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
            Field(description="Start time in ISO 8601 format (e.g. '2026-03-22T00:00:00')"),
        ],
        time_end: Annotated[
            str,
            Field(description="End time in ISO 8601 format"),
        ],
        data_type: Annotated[
            str,
            Field(description="'rib' for routing table snapshot or 'update' for BGP changes"),
        ] = "rib",
        collector: Annotated[
            str | None,
            Field(description="RIPE RIS collector ID (e.g. 'rrc00'). Defaults to rrc00."),
        ] = "rrc00",
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

        Returns origin ASN(s) with AS name and RPKI validation status.
        Use this to answer 'who announces this prefix?' questions.
        """
        try:
            data = ripestat_get(
                "routing-status/data.json",
                params={"resource": prefix},
            ).get("data", {})

            origins = []
            for entry in data.get("origins", []):
                origin_asn = entry.get("origin", 0)
                if origin_asn:
                    origins.append(
                        PrefixOrigin(
                            prefix=data.get("resource", prefix),
                            origin_asn=origin_asn,
                        )
                    )

            # Deduplicate by origin ASN
            seen = set()
            unique_origins = []
            for o in origins:
                if o.origin_asn not in seen:
                    seen.add(o.origin_asn)
                    unique_origins.append(o)

            # Enrich with AS names
            for origin in unique_origins:
                origin.as_name = _get_as_name(origin.origin_asn)

            return PrefixOriginResult(query_prefix=prefix, origins=unique_origins)
        except Exception:
            return PrefixOriginResult(query_prefix=prefix, origins=[])

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
        prefixes_v4, prefixes_v6 = _get_announced_prefixes(asn)
        upstreams = _get_upstreams(asn)

        return ASNInfo(
            asn=asn,
            name=name,
            prefixes_v4=prefixes_v4,
            prefixes_v6=prefixes_v6,
            upstream_asns=upstreams,
            total_prefixes=len(prefixes_v4) + len(prefixes_v6),
        )


# ---------------------------------------------------------------------------
# bgp.tools backends
# ---------------------------------------------------------------------------


def _bgptools_route_lookup(prefix: str) -> BGPRouteLookupResult:
    """Look up a prefix via bgp.tools table.jsonl (full table, filter locally).

    Note: Downloads the full BGP table (~15MB compressed). This is a last-resort
    fallback. bgp.tools asks that this not be fetched more than every 30 minutes.
    """
    try:
        with httpx.Client(timeout=60, headers=BGP_TOOLS_HEADERS) as client:
            routes = []
            with client.stream("GET", f"{BGP_TOOLS_BASE}/table.jsonl") as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if not line:
                        continue
                    import json

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
                    if len(routes) >= 20:
                        break

        return BGPRouteLookupResult(
            prefix=prefix,
            routes=routes,
            total=len(routes),
            source="bgp.tools table",
        )
    except Exception as e:
        return BGPRouteLookupResult(
            prefix=prefix, routes=[], total=0, source=f"bgp.tools error: {e}"
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
        import csv
        import io

        with httpx.Client(timeout=30, headers=BGP_TOOLS_HEADERS) as client:
            resp = client.get(f"{BGP_TOOLS_BASE}/asns.csv")
            resp.raise_for_status()

        cache = {}
        reader = csv.DictReader(io.StringIO(resp.text))
        for row in reader:
            asn_str = row.get("asn", "").replace("AS", "")
            if asn_str.isdigit():
                cache[int(asn_str)] = row.get("name", "")

        _bgptools_asn_cache = cache
        return cache
    except Exception:
        _bgptools_asn_cache = {}
        return {}


def _bgptools_get_as_name(asn: int) -> str | None:
    """Look up AS name from bgp.tools asns.csv (cached in-memory)."""
    cache = _bgptools_load_asn_cache()
    return cache.get(asn)


# ---------------------------------------------------------------------------
# bgproutes.io backends (requires API key)
# ---------------------------------------------------------------------------


def _bgproutes_route_lookup(
    prefix: str, api_key: str
) -> BGPRouteLookupResult | None:
    """Look up routes via bgproutes.io RIB endpoint.

    Returns routes with RPKI ROV and ASPA validation status per entry.
    Requires BGPROUTES_API_KEY environment variable.
    """
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        with httpx.Client(timeout=HTTP_TIMEOUT, headers=headers) as client:
            resp = client.get(
                f"{BGPROUTES_API_BASE}/rib",
                params={"prefix_exact_match": prefix},
            )
            resp.raise_for_status()
            data = resp.json()

        entries = data.get("data", data) if isinstance(data, dict) else data
        if not isinstance(entries, list):
            entries = [entries] if entries else []

        routes = []
        for entry in entries[:20]:
            as_path_raw = entry.get("aspath", entry.get("as_path", ""))
            if isinstance(as_path_raw, str):
                as_path = [int(a) for a in as_path_raw.split() if a.isdigit()]
            else:
                as_path = [int(a) for a in as_path_raw]

            communities_raw = entry.get("communities", entry.get("community", ""))
            if isinstance(communities_raw, str):
                communities = [c.strip() for c in communities_raw.split(",") if c.strip()]
            elif isinstance(communities_raw, list):
                communities = [str(c) for c in communities_raw]
            else:
                communities = []

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
    except Exception:
        return None


def _bgproutes_get_topology(api_key: str, asn: int) -> list[int] | None:
    """Get upstream ASNs via bgproutes.io topology endpoint."""
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        with httpx.Client(timeout=HTTP_TIMEOUT, headers=headers) as client:
            resp = client.get(
                f"{BGPROUTES_API_BASE}/topology",
                params={"asn": asn},
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
    except Exception:
        return None


# ---------------------------------------------------------------------------
# RIPEstat backends
# ---------------------------------------------------------------------------

# Region keywords mapped to collector locations for filtering
_REGION_KEYWORDS = {
    "europe": ["netherlands", "united kingdom", "france", "germany", "switzerland",
               "austria", "sweden", "italy", "spain", "russian", "romania", "bucharest"],
    "asia": ["japan", "tokyo", "singapore", "dubai", "uae"],
    "us": ["california", "new york", "miami", "florida", "palo alto", "san jose"],
    "north america": ["california", "new york", "miami", "florida", "palo alto", "san jose"],
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
    except Exception:
        return RouteCollectorResult(
            collectors=[], total=0, active=0,
            tip="Failed to fetch collector data from RIPEstat.",
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


def _mrt_search(
    time_start: str, time_end: str, data_type: str, collector: str | None
) -> MRTSearchResult:
    """Find MRT files via BGPKIT Broker."""
    import bgpkit

    collector = collector or "rrc00"
    data_type = data_type.lower()
    if data_type not in ("rib", "update"):
        data_type = "rib"

    try:
        broker = bgpkit.Broker()
        items = broker.query(
            ts_start=time_start,
            ts_end=time_end,
            data_type=data_type,
            collector_id=collector.lower(),
        )

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

        return MRTSearchResult(
            query_start=time_start,
            query_end=time_end,
            collector=collector,
            data_type=data_type,
            files=files,
            total=len(files),
            tip=tip,
        )
    except Exception as e:
        return MRTSearchResult(
            query_start=time_start,
            query_end=time_end,
            collector=collector,
            data_type=data_type,
            files=[],
            total=0,
            tip=f"Error searching MRT files: {e}",
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
    import bgpkit
    from datetime import datetime, timezone

    cfg = get_config()
    cache_dir = cfg.ensure_mrt_cache_dir()

    collector = collector or cfg.default_collector
    data_type = data_type.lower()
    if data_type not in ("rib", "update"):
        data_type = "rib"

    try:
        broker = bgpkit.Broker()
        items = broker.query(
            ts_start=time_start,
            ts_end=time_end,
            data_type=data_type,
            collector_id=collector.lower(),
        )

        if not items:
            return HistoricalBGPResult(
                prefix=prefix,
                time_start=time_start,
                time_end=time_end,
                collector=collector,
                data_type=data_type,
                entries=[],
                total=0,
                mrt_file="none",
                source=f"No MRT files found for {collector} between {time_start} and {time_end}",
            )

        # For RIB: use the closest dump. For updates: parse all files in range.
        if data_type == "rib":
            target_file = items[0]  # earliest RIB in range
            files_to_parse = [target_file]
        else:
            files_to_parse = items

        # Enforce cache size limit before downloading
        _enforce_cache_limit(cache_dir, cfg.mrt_max_cache_gb)

        entries = []
        parsed_url = ""
        for mrt_item in files_to_parse:
            parsed_url = mrt_item.url

            # Check if file is already cached locally
            local_path = _cached_mrt_path(cache_dir, mrt_item.url)
            if local_path.exists():
                parse_target = str(local_path)
            else:
                # Download to cache, then parse locally
                local_path = _download_mrt(mrt_item.url, cache_dir)
                parse_target = str(local_path) if local_path else mrt_item.url

            parser = bgpkit.Parser(url=parse_target, filters={"prefix": prefix})

            for elem in parser:
                origin_asns = elem.origin_asns or []
                origin_asn = origin_asns[0] if origin_asns else 0

                as_path_str = elem.as_path or ""
                as_path = [int(a) for a in as_path_str.split() if a.isdigit()]

                communities = elem.communities or []

                ts = elem.timestamp
                ts_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") if ts else ""

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

        file_urls = parsed_url if len(files_to_parse) == 1 else f"{len(files_to_parse)} files"

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
    except Exception as e:
        return HistoricalBGPResult(
            prefix=prefix,
            time_start=time_start,
            time_end=time_end,
            collector=collector or "rrc00",
            data_type=data_type,
            entries=[],
            total=0,
            mrt_file="error",
            source=f"MRT parsing error: {e}",
        )


def _cached_mrt_path(cache_dir: Path, url: str) -> Path:
    """Derive a local cache path from an MRT URL.

    Preserves the collector/year.month/filename structure:
      https://data.ris.ripe.net/rrc00/2026.03/bview.20260322.0000.gz
      → <cache_dir>/rrc00/2026.03/bview.20260322.0000.gz
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    # path: /rrc00/2026.03/bview.20260322.0000.gz
    rel = parsed.path.lstrip("/")
    return cache_dir / rel


def _download_mrt(url: str, cache_dir: Path) -> Path | None:
    """Download an MRT file to the cache directory. Returns local path or None."""
    local_path = _cached_mrt_path(cache_dir, url)
    local_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with httpx.Client(timeout=120) as client:
            with client.stream("GET", url) as resp:
                resp.raise_for_status()
                with open(local_path, "wb") as f:
                    for chunk in resp.iter_bytes(chunk_size=1024 * 256):
                        f.write(chunk)
        return local_path
    except Exception:
        # Clean up partial download
        if local_path.exists():
            local_path.unlink()
        return None


def _enforce_cache_limit(cache_dir: Path, max_gb: float) -> None:
    """Remove oldest cached MRT files if total cache exceeds max_gb."""
    if not cache_dir.exists():
        return

    max_bytes = max_gb * 1024 * 1024 * 1024
    files = sorted(cache_dir.rglob("*.gz"), key=lambda p: p.stat().st_mtime)
    total = sum(f.stat().st_size for f in files)

    while total > max_bytes and files:
        oldest = files.pop(0)
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
                as_path_str = peer.get("as_path", "")
                as_path = [int(a) for a in as_path_str.split() if a.isdigit()]
                origin_asn = as_path[-1] if as_path else 0
                community = peer.get("community", "")
                if isinstance(community, str):
                    communities = [c.strip() for c in community.split(",") if c.strip()]
                else:
                    communities = [str(c) for c in community]
                routes.append(
                    BGPRoute(
                        prefix=peer.get("prefix", prefix),
                        origin_asn=origin_asn,
                        as_path=as_path,
                        communities=communities,
                        peer_asn=int(peer.get("asn_origin", peer.get("peer_asn", 0))),
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
            routes=routes[:20],
            total=len(routes),
            source=source,
        )
    except Exception as e:
        return BGPRouteLookupResult(
            prefix=prefix, routes=[], total=0, source=f"RIPEstat error: {e}"
        )


# ---------------------------------------------------------------------------
# Shared helpers (multi-source with fallback)
# ---------------------------------------------------------------------------


def _get_as_name(asn: int) -> str | None:
    """Look up AS name. Tries RIPEstat first, then bgp.tools CSV cache."""
    # 1. RIPEstat
    try:
        name = ripestat_get(
            "as-overview/data.json",
            params={"resource": f"AS{asn}"},
            timeout=10,
        ).get("data", {}).get("holder")
        if name:
            return name
    except Exception:
        pass

    # 2. bgp.tools asns.csv (cached in-memory)
    return _bgptools_get_as_name(asn)


def _get_announced_prefixes(asn: int) -> tuple[list[str], list[str]]:
    """Get prefixes announced by an ASN via RIPEstat."""
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
            else:
                v4.append(pfx)
        return sorted(v4), sorted(v6)
    except Exception:
        return [], []


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
    except Exception:
        pass

    # 2. bgproutes.io topology (requires API key)
    api_key = _get_bgproutes_key()
    if api_key:
        result = _bgproutes_get_topology(api_key, asn)
        if result is not None:
            return result

    return []
