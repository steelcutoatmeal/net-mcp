"""Tests for IP/subnet math and bogon detection (pure computation, no network)."""

from __future__ import annotations

import pytest

from net_mcp.server import mcp


async def _call(name: str, args: dict):
    result = await mcp.call_tool(name, args)
    return result.structured_content


async def test_subnet_info_ipv4():
    data = await _call("subnet_info", {"prefix": "10.0.0.0/24"})
    assert data["network_address"] == "10.0.0.0"
    assert data["broadcast_address"] == "10.0.0.255"
    assert data["total_addresses"] == 256
    assert data["usable_hosts"] == 254
    assert data["is_private"] is True
    assert data["ip_version"] == 4


async def test_subnet_info_single_ip():
    data = await _call("subnet_info", {"prefix": "1.1.1.1"})
    assert data["prefix_length"] == 32
    assert data["total_addresses"] == 1


async def test_subnet_split_counts_arithmetically_without_materializing():
    # /8 -> /32 is 16.7M subnets; total must be exact but the list capped at 256.
    data = await _call("subnet_split", {"prefix": "10.0.0.0/8", "new_prefix_length": 32})
    assert data["total"] == 2 ** (32 - 8)
    assert len(data["subnets"]) == 256
    assert data["subnets"][0] == "10.0.0.0/32"


async def test_subnet_split_small():
    data = await _call("subnet_split", {"prefix": "10.0.0.0/24", "new_prefix_length": 26})
    assert data["total"] == 4
    assert data["subnets"] == [
        "10.0.0.0/26",
        "10.0.0.64/26",
        "10.0.0.128/26",
        "10.0.0.192/26",
    ]


async def test_subnet_split_rejects_shorter_prefix():
    with pytest.raises(Exception):
        await _call("subnet_split", {"prefix": "10.0.0.0/24", "new_prefix_length": 23})


async def test_ip_contains_true():
    data = await _call("ip_contains", {"network": "10.0.0.0/8", "address": "10.5.5.1"})
    assert data["contains"] is True


async def test_ip_contains_subnet():
    data = await _call("ip_contains", {"network": "192.168.0.0/16", "address": "192.168.1.0/24"})
    assert data["contains"] is True


async def test_ip_contains_mixed_version_does_not_raise():
    # Previously raised TypeError; should now return a clean negative result.
    data = await _call("ip_contains", {"network": "10.0.0.0/8", "address": "::1"})
    assert data["contains"] is False
    assert "IPv" in data["detail"]


async def test_ip_contains_mixed_version_prefix():
    data = await _call("ip_contains", {"network": "10.0.0.0/8", "address": "2001:db8::/32"})
    assert data["contains"] is False


async def test_prefix_overlap_contains():
    data = await _call("prefix_overlap", {"prefix_a": "10.0.0.0/24", "prefix_b": "10.0.0.128/25"})
    assert data["overlaps"] is True
    assert data["relationship"] == "a_contains_b"


async def test_prefix_overlap_disjoint():
    data = await _call("prefix_overlap", {"prefix_a": "10.0.0.0/24", "prefix_b": "10.0.1.0/24"})
    assert data["overlaps"] is False
    assert data["relationship"] == "disjoint"


async def test_prefix_overlap_mixed_version_disjoint():
    data = await _call("prefix_overlap", {"prefix_a": "10.0.0.0/8", "prefix_b": "2001:db8::/32"})
    assert data["overlaps"] is False
    assert data["relationship"] == "disjoint"


async def test_supernet_aggregate_success():
    data = await _call("supernet_aggregate", {"prefixes": "10.0.0.0/25,10.0.0.128/25"})
    assert data["aggregatable"] is True
    assert data["supernet"] == "10.0.0.0/24"


async def test_supernet_aggregate_non_contiguous():
    data = await _call("supernet_aggregate", {"prefixes": "10.0.0.0/24,10.0.2.0/24"})
    assert data["aggregatable"] is False
    assert data["supernet"] is None


async def test_bogon_check_private():
    data = await _call("bogon_check", {"query": "192.168.1.0/24"})
    assert data["is_bogon"] is True
    assert any("RFC 1918" in m for m in data["matches"])


async def test_bogon_check_cgnat():
    data = await _call("bogon_check", {"query": "100.64.0.1"})
    assert data["is_bogon"] is True
    assert any("6598" in m for m in data["matches"])


async def test_bogon_check_global():
    data = await _call("bogon_check", {"query": "1.1.1.0/24"})
    assert data["is_bogon"] is False
    assert data["matches"] == []


async def test_bogon_check_ipv6_documentation():
    data = await _call("bogon_check", {"query": "2001:db8::/32"})
    assert data["is_bogon"] is True
