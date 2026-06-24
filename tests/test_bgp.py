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
                {"rrc": "RRC00", "peers": [{"as_path": "1 13335", "prefix": "1.1.1.0/24"}]},
                {"rrc": "RRC06", "peers": [{"as_path": "2 13335", "prefix": "1.1.1.0/24"}]},
            ]
        }
    }
    monkeypatch.setattr(bgp, "ripestat_get", lambda *a, **k: fake)

    result = bgp._ripestat_route_lookup("1.1.1.0/24", collector="RRC06")
    assert all(r.collector == "RRC06" for r in result.routes)
    assert result.routes[0].peer_asn == 2


def test_ripestat_route_lookup_error_marks_source(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setattr(bgp, "ripestat_get", boom)
    result = bgp._ripestat_route_lookup("1.1.1.0/24")
    assert result.routes == []
    assert result.source.startswith("RIPEstat error")


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
    bgp._enforce_cache_limit(tmp_path, max_gb=1 / (1024 ** 3), keep=keep)

    assert keep.exists()
    assert not files[0].exists()


def test_asn_cache_not_poisoned_on_failure(monkeypatch):
    # A transient download failure must leave the cache unset (None) so the
    # next call retries, rather than caching an empty dict permanently.
    monkeypatch.setattr(bgp, "_bgptools_asn_cache", None)

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, *a, **k):
            raise RuntimeError("boom")

    monkeypatch.setattr(bgp.httpx, "Client", FakeClient)
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
    monkeypatch.setattr(bgp, "_get_announced_prefixes", lambda asn: (v4, v6))
    monkeypatch.setattr(bgp, "_get_upstreams", lambda asn: [1, 2])

    res = await mcp.call_tool("bgp_asn_info", {"asn": 64500})
    data = res.structured_content
    assert len(data["prefixes_v4"]) == bgp._ASN_PREFIX_CAP
    assert len(data["prefixes_v6"]) == bgp._ASN_PREFIX_CAP
    assert data["total_prefixes"] == 300
    assert data["note"]  # truncation note present


async def test_bgp_asn_info_small_as_not_truncated(monkeypatch):
    monkeypatch.setattr(bgp, "_get_as_name", lambda asn: "SMALLAS")
    monkeypatch.setattr(bgp, "_get_announced_prefixes", lambda asn: (["1.1.1.0/24"], []))
    monkeypatch.setattr(bgp, "_get_upstreams", lambda asn: [])

    res = await mcp.call_tool("bgp_asn_info", {"asn": 64501})
    data = res.structured_content
    assert data["prefixes_v4"] == ["1.1.1.0/24"]
    assert data["total_prefixes"] == 1
    assert data["note"] == ""
