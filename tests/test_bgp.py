"""Tests for BGP parsing and cache helpers (no live network)."""

from __future__ import annotations

import os

import net_mcp.tools.bgp as bgp
from net_mcp.server import mcp


def test_ripestat_route_lookup_peer_asn(monkeypatch):
    # peer_asn must be the first hop (collector's neighbour), origin the last hop.
    fake = {
        "data": {
            "rrcs": [
                {
                    "rrc": "RRC00",
                    "peers": [
                        {
                            "as_path": "64500 64501 13335",
                            "prefix": "1.1.1.0/24",
                            "peer": "192.0.2.1",
                            "community": "64500:100,64500:200",
                            "latest_time": "2026-01-01T00:00:00",
                        }
                    ],
                }
            ]
        }
    }
    monkeypatch.setattr(bgp, "ripestat_get", lambda *a, **k: fake)

    result = bgp._ripestat_route_lookup("1.1.1.0/24")
    assert len(result.routes) == 1
    route = result.routes[0]
    assert route.origin_asn == 13335
    assert route.peer_asn == 64500
    assert route.as_path == [64500, 64501, 13335]
    assert route.communities == ["64500:100", "64500:200"]


def test_ripestat_route_lookup_collector_filter(monkeypatch):
    fake = {
        "data": {
            "rrcs": [
                {
                    "rrc": "RRC00",
                    "peers": [{"as_path": "1 13335", "prefix": "1.1.1.0/24"}],
                },
                {
                    "rrc": "RRC06",
                    "peers": [{"as_path": "2 13335", "prefix": "1.1.1.0/24"}],
                },
            ]
        }
    }
    monkeypatch.setattr(bgp, "ripestat_get", lambda *a, **k: fake)

    result = bgp._ripestat_route_lookup("1.1.1.0/24", collector="RRC06")
    assert all(r.collector == "RRC06" for r in result.routes)
    assert result.routes[0].peer_asn == 2


def test_ripestat_route_lookup_failure_sets_error(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setattr(bgp, "ripestat_get", boom)
    result = bgp._ripestat_route_lookup("1.1.1.0/24")
    assert result.routes == []
    assert result.source == "RIPEstat Looking Glass"
    assert result.error and "network down" in result.error


async def test_route_lookup_falls_back_to_bgptools_only_on_ripestat_error(monkeypatch):
    """An empty-but-successful RIPEstat answer must NOT trigger the full-table download."""
    from net_mcp.models import BGPRouteLookupResult

    calls = []

    def fake_bgptools(prefix):
        calls.append(prefix)
        return BGPRouteLookupResult(
            prefix=prefix, routes=[], total=0, source="bgp.tools table"
        )

    empty_ok = BGPRouteLookupResult(
        prefix="p", routes=[], total=0, source="RIPEstat Looking Glass"
    )
    failed = BGPRouteLookupResult(
        prefix="p", routes=[], total=0, source="RIPEstat Looking Glass", error="down"
    )

    monkeypatch.setattr(bgp, "_cloudflare_route_lookup", lambda prefix: None)
    monkeypatch.setattr(bgp, "_get_bgproutes_key", lambda: None)
    monkeypatch.setattr(bgp, "_bgptools_route_lookup", fake_bgptools)

    monkeypatch.setattr(
        bgp, "_ripestat_route_lookup", lambda prefix, collector=None: empty_ok
    )
    res = await mcp.call_tool("bgp_route_lookup", {"prefix": "10.0.0.0/8"})
    assert res.structured_content["source"] == "RIPEstat Looking Glass"
    assert calls == []

    monkeypatch.setattr(
        bgp, "_ripestat_route_lookup", lambda prefix, collector=None: failed
    )
    res = await mcp.call_tool("bgp_route_lookup", {"prefix": "10.0.0.0/8"})
    assert res.structured_content["source"] == "bgp.tools table"
    assert calls == ["10.0.0.0/8"]


async def test_prefix_origin_reports_error_when_all_sources_fail(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("ripestat down")

    monkeypatch.setattr(bgp, "cloudflare_get", lambda *a, **k: None)
    monkeypatch.setattr(bgp, "ripestat_get", boom)
    res = await mcp.call_tool("bgp_prefix_origin", {"prefix": "1.1.1.0/24"})
    data = res.structured_content
    assert data["origins"] == []
    assert data["error"] and "ripestat down" in data["error"]


def test_parse_as_path_and_communities():
    assert bgp._parse_as_path("13335 174 3356") == [13335, 174, 3356]
    assert bgp._parse_as_path([1, "2", "{3}"]) == [1, 2]
    assert bgp._parse_as_path(None) == []
    assert bgp._parse_communities("174:21100, 174:22013") == ["174:21100", "174:22013"]
    assert bgp._parse_communities([1, "2:3"]) == ["1", "2:3"]
    assert bgp._parse_communities("") == []


def test_enforce_cache_limit_never_evicts_kept_file(tmp_path):
    files = []
    for i in range(3):
        p = tmp_path / f"f{i}.gz"
        p.write_bytes(b"x" * 1000)
        files.append(p)
    # Stagger mtimes: f0 oldest ... f2 newest.
    for i, p in enumerate(files):
        os.utime(p, (1000 + i, 1000 + i))

    keep = files[-1]
    # Tiny limit forces eviction of everything except the protected file.
    bgp._enforce_cache_limit(tmp_path, max_gb=1 / (1024**3), keep=keep)

    assert keep.exists()
    assert not files[0].exists()


def test_asn_cache_not_poisoned_on_failure(monkeypatch):
    # A transient download failure must leave the cache unset (None) so the
    # next call retries, rather than caching an empty dict permanently.
    monkeypatch.setattr(bgp, "_bgptools_asn_cache", None)

    class FakeClient:
        def get(self, *a, **k):
            raise RuntimeError("boom")

    monkeypatch.setattr(bgp, "get_http_client", lambda: FakeClient())
    assert bgp._bgptools_load_asn_cache() == {}
    assert bgp._bgptools_asn_cache is None  # not poisoned


def test_sort_prefixes_is_numeric_not_lexicographic():
    # Lexicographic order would put 100.0.0.0/8 before 11.0.0.0/8.
    out = bgp._sort_prefixes(["11.0.0.0/8", "100.0.0.0/8", "9.0.0.0/8"])
    assert out == ["9.0.0.0/8", "11.0.0.0/8", "100.0.0.0/8"]


def test_first_prefers_present_keys_and_skips_none():
    assert bgp._first({"a": 1}, "a", "b") == 1
    assert bgp._first({"b": 2}, "a", "b") == 2
    # None is treated as missing so a real fallback can win.
    assert bgp._first({"a": None, "b": 5}, "a", "b") == 5
    assert bgp._first({}, "a", default=7) == 7


async def test_bgp_asn_info_caps_prefix_lists(monkeypatch):
    # A large AS announces far more than the cap; the lists are truncated but
    # total_prefixes stays exact and a truncation note is set.
    v4 = [f"10.{i}.0.0/24" for i in range(150)]
    v6 = [f"2001:db8:{i:x}::/48" for i in range(150)]
    monkeypatch.setattr(bgp, "_get_as_name", lambda asn: "TESTAS")
    monkeypatch.setattr(bgp, "_get_announced_prefixes", lambda asn: (v4, v6, None))
    monkeypatch.setattr(bgp, "_get_upstreams", lambda asn: [1, 2])

    res = await mcp.call_tool("bgp_asn_info", {"asn": 64500})
    data = res.structured_content
    assert len(data["prefixes_v4"]) == bgp._ASN_PREFIX_CAP
    assert len(data["prefixes_v6"]) == bgp._ASN_PREFIX_CAP
    assert data["total_prefixes"] == 300
    assert data["note"]  # truncation note present


async def test_bgp_asn_info_small_as_not_truncated(monkeypatch):
    monkeypatch.setattr(bgp, "_get_as_name", lambda asn: "SMALLAS")
    monkeypatch.setattr(
        bgp, "_get_announced_prefixes", lambda asn: (["1.1.1.0/24"], [], None)
    )
    monkeypatch.setattr(bgp, "_get_upstreams", lambda asn: [])

    res = await mcp.call_tool("bgp_asn_info", {"asn": 64501})
    data = res.structured_content
    assert data["prefixes_v4"] == ["1.1.1.0/24"]
    assert data["total_prefixes"] == 1
    assert data["note"] == ""
