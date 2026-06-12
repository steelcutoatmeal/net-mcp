"""Tests for BGP parsing and cache helpers (no live network)."""

from __future__ import annotations

import os

import net_mcp.tools.bgp as bgp


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
