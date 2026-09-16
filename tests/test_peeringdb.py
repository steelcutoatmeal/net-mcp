"""Offline tests for the PeeringDB tools (no network).

Successful-path tests monkeypatch the module's ``_pdb_get`` fetch helper and
record every call so request fan-out can be asserted. Failure-path tests swap
the shared HTTP client for one backed by ``httpx.MockTransport`` so the real
``_pdb_get`` (raise_for_status, JSON parsing) and ``_describe_error`` run.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
from fastmcp.exceptions import ToolError

import net_mcp.tools.peeringdb as pdb
from net_mcp.server import mcp

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakePDB:
    """Stand-in for ``_pdb_get`` that records calls and serves canned bodies.

    ``responses`` maps endpoint -> body dict, or endpoint -> callable(params)
    returning a body dict (or raising).
    """

    def __init__(self, responses: dict[str, dict | Callable[[dict], dict]]):
        self.responses = responses
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, endpoint: str, params: dict | None = None) -> dict:
        params = dict(params or {})
        self.calls.append((endpoint, params))
        handler = self.responses[endpoint]
        return handler(params) if callable(handler) else handler

    def endpoints(self) -> list[str]:
        return [ep for ep, _ in self.calls]


def _install_mock_transport(
    monkeypatch, handler: Callable[[httpx.Request], httpx.Response]
):
    client = httpx.Client(
        transport=httpx.MockTransport(handler), headers={"User-Agent": "test"}
    )
    monkeypatch.setattr(pdb, "get_http_client", lambda: client)
    return client


def _http_status_error(status: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", f"{pdb.PEERINGDB_API}/netixlan")
    response = httpx.Response(status, request=request)
    return httpx.HTTPStatusError("boom", request=request, response=response)


NET_RECORD = {
    "id": 4224,
    "asn": 13335,
    "name": "Cloudflare",
    "aka": "Cloudflare, Inc.",
    "website": "https://www.cloudflare.com",
    "irr_as_set": "AS13335:AS-CLOUDFLARE",
    "info_type": "Content",
    "policy_general": "Open",
    "info_prefixes4": 1000,
    "info_prefixes6": 500,
}

NETIXLAN_ROWS = [
    {
        "ix_id": 26,
        "asn": 13335,
        "name": "AMS-IX",
        "ipaddr4": "80.249.211.140",
        "ipaddr6": "2001:7f8:1::a501:3335:1",
        "speed": 100000,
        "is_rs_peer": True,
    },
    {
        "ix_id": 31,
        "asn": 13335,
        "name": "DE-CIX Frankfurt",
        "ipaddr4": "80.81.194.176",
        "ipaddr6": None,
        "speed": None,  # PeeringDB sometimes returns null speeds
        "is_rs_peer": False,
    },
]


# ---------------------------------------------------------------------------
# peeringdb_network
# ---------------------------------------------------------------------------


async def test_network_lookup_success(monkeypatch):
    fake = FakePDB({"net": {"data": [NET_RECORD]}, "netixlan": {"data": NETIXLAN_ROWS}})
    monkeypatch.setattr(pdb, "_pdb_get", fake)

    res = await mcp.call_tool("peeringdb_network", {"asn": 13335})
    data = res.structured_content

    assert data["error"] is None
    assert data["source"] == "PeeringDB"
    assert data["query_asn"] == 13335

    net = data["network"]
    assert net["asn"] == 13335
    assert net["name"] == "Cloudflare"
    assert net["irr_as_set"] == "AS13335:AS-CLOUDFLARE"
    assert net["info_type"] == "Content"
    assert net["peering_policy"] == "Open"
    assert net["ipv4_prefixes"] == 1000
    assert net["ipv6_prefixes"] == 500

    assert len(net["exchanges"]) == 2
    amsix, decix = net["exchanges"]
    assert amsix["ix_id"] == 26
    assert amsix["ix_name"] == "AMS-IX"
    assert amsix["ipv4"] == "80.249.211.140"
    assert amsix["speed_mbps"] == 100000
    assert amsix["is_rs_peer"] is True
    assert decix["ipv6"] is None
    assert decix["speed_mbps"] == 0  # null speed coerced, not a validation error
    assert decix["is_rs_peer"] is False

    # Exactly two requests: the net record, then its netixlan rows.
    assert fake.endpoints() == ["net", "netixlan"]
    assert fake.calls[1][1]["net_id"] == 4224


async def test_network_not_found_is_not_an_error(monkeypatch):
    fake = FakePDB({"net": {"data": []}})
    monkeypatch.setattr(pdb, "_pdb_get", fake)

    res = await mcp.call_tool("peeringdb_network", {"asn": 64512})
    data = res.structured_content

    assert data["network"] is None
    assert data["error"] is None
    assert data["source"] == "PeeringDB"
    assert fake.endpoints() == ["net"]


async def test_network_partial_result_when_exchange_fetch_fails(monkeypatch):
    def failing_netixlan(params):
        raise _http_status_error(503)

    fake = FakePDB({"net": {"data": [NET_RECORD]}, "netixlan": failing_netixlan})
    monkeypatch.setattr(pdb, "_pdb_get", fake)

    res = await mcp.call_tool("peeringdb_network", {"asn": 13335})
    data = res.structured_content

    # The network record is still returned; only the exchange list is missing.
    assert data["network"]["name"] == "Cloudflare"
    assert data["network"]["exchanges"] == []
    assert data["source"] == "PeeringDB"
    assert data["error"] is not None
    assert "503" in data["error"]
    assert "exchange list missing" in data["error"]


async def test_network_rejects_invalid_asn(monkeypatch):
    fake = FakePDB({})
    monkeypatch.setattr(pdb, "_pdb_get", fake)

    with pytest.raises(ToolError, match="between 1 and 4294967295"):
        await mcp.call_tool("peeringdb_network", {"asn": 0})
    with pytest.raises(ToolError):
        await mcp.call_tool("peeringdb_network", {"asn": 4294967296})
    assert fake.calls == []  # rejected before any request


# ---------------------------------------------------------------------------
# peeringdb_ix
# ---------------------------------------------------------------------------

IX_ROWS = [
    {
        "id": 31,
        "name": "DE-CIX Frankfurt",
        "city": "Frankfurt",
        "country": "DE",
        "website": "https://www.de-cix.net",
        "net_count": 1050,
    },
    {
        "id": 48,
        "name": "DE-CIX Munich",
        "city": "Munich",
        "country": "DE",
        "website": "https://www.de-cix.net",
        "net_count": 210,
    },
]

MEMBER_ROWS = [
    {
        "ix_id": 31,
        "asn": 13335,
        "name": "Cloudflare",
        "ipaddr4": "80.81.192.1",
        "ipaddr6": None,
        "speed": 100000,
        "is_rs_peer": True,
    },
    # Second port for the same ASN must be collapsed into one member entry.
    {
        "ix_id": 31,
        "asn": 13335,
        "name": "Cloudflare",
        "ipaddr4": "80.81.192.2",
        "ipaddr6": None,
        "speed": 100000,
        "is_rs_peer": True,
    },
    {
        "ix_id": 31,
        "asn": 3320,
        "name": "Deutsche Telekom",
        "ipaddr4": "80.81.192.3",
        "ipaddr6": "2001:7f8::cf8:0:1",
        "speed": 400000,
        "is_rs_peer": False,
    },
]


async def test_ix_search_with_members_fetches_one_exchange_only(monkeypatch):
    fake = FakePDB({"ix": {"data": IX_ROWS}, "netixlan": {"data": MEMBER_ROWS}})
    monkeypatch.setattr(pdb, "_pdb_get", fake)

    res = await mcp.call_tool(
        "peeringdb_ix", {"query": "DE-CIX", "include_members": True}
    )
    data = res.structured_content

    assert data["error"] is None
    assert data["source"] == "PeeringDB"
    assert data["total"] == 2
    frankfurt, munich = data["exchanges"]

    # No exact name match for "DE-CIX", so the first result gets the member fetch.
    assert frankfurt["members_included"] is True
    assert [m["asn"] for m in frankfurt["members"]] == [13335, 3320]  # deduped
    assert frankfurt["members"][0]["ipv4"] == "80.81.192.1"  # first row wins
    assert frankfurt["members"][0]["is_rs_peer"] is True
    assert frankfurt["members"][1]["speed_mbps"] == 400000
    assert frankfurt["total_members"] == 1050  # from net_count, not len(members)

    # The other match still carries net_count but no member list.
    assert munich["members_included"] is False
    assert munich["members"] == []
    assert munich["total_members"] == 210

    # Exactly one search request plus one member fetch for the chosen IX.
    assert fake.endpoints() == ["ix", "netixlan"]
    assert fake.calls[1][1]["ix_id"] == 31


async def test_ix_members_prefer_exact_name_match(monkeypatch):
    rows = [
        {
            "id": 100,
            "name": "AMS-IX Chicago",
            "city": "Chicago",
            "country": "US",
            "net_count": 40,
        },
        {
            "id": 26,
            "name": "AMS-IX",
            "city": "Amsterdam",
            "country": "NL",
            "net_count": 900,
        },
    ]
    fake = FakePDB({"ix": {"data": rows}, "netixlan": {"data": []}})
    monkeypatch.setattr(pdb, "_pdb_get", fake)

    res = await mcp.call_tool(
        "peeringdb_ix", {"query": "ams-ix", "include_members": True}
    )
    data = res.structured_content

    assert fake.endpoints() == ["ix", "netixlan"]
    assert fake.calls[1][1]["ix_id"] == 26
    included = [ix["name"] for ix in data["exchanges"] if ix["members_included"]]
    assert included == ["AMS-IX"]


async def test_ix_search_without_members_makes_one_request(monkeypatch):
    fake = FakePDB({"ix": {"data": IX_ROWS}})
    monkeypatch.setattr(pdb, "_pdb_get", fake)

    res = await mcp.call_tool("peeringdb_ix", {"query": "DE-CIX"})
    data = res.structured_content

    assert data["total"] == 2
    assert all(ix["members_included"] is False for ix in data["exchanges"])
    assert data["exchanges"][0]["total_members"] == 1050
    assert fake.endpoints() == ["ix"]
    assert fake.calls[0][1] == {
        "name__contains": "DE-CIX",
        "limit": pdb._MAX_IX_RESULTS,
    }


async def test_ix_search_falls_back_to_city_then_numeric_id(monkeypatch):
    def ix_handler(params):
        if "name__contains" in params:
            return {"data": []}
        if "city__contains" in params:
            return {"data": [IX_ROWS[0]]}
        if "id" in params:
            return {"data": [IX_ROWS[1]]}
        raise AssertionError(f"unexpected params {params}")

    fake = FakePDB({"ix": ix_handler})
    monkeypatch.setattr(pdb, "_pdb_get", fake)

    res = await mcp.call_tool("peeringdb_ix", {"query": "Frankfurt"})
    assert [ix["name"] for ix in res.structured_content["exchanges"]] == [
        "DE-CIX Frankfurt"
    ]
    assert fake.endpoints() == ["ix", "ix"]

    fake.calls.clear()
    res = await mcp.call_tool("peeringdb_ix", {"query": "48"})
    assert res.structured_content["exchanges"][0]["ix_id"] == 48
    assert fake.calls == [("ix", {"id": 48})]


async def test_ix_rejects_blank_query(monkeypatch):
    fake = FakePDB({})
    monkeypatch.setattr(pdb, "_pdb_get", fake)

    with pytest.raises(ToolError, match="non-empty"):
        await mcp.call_tool("peeringdb_ix", {"query": "   "})
    assert fake.calls == []


# ---------------------------------------------------------------------------
# peeringdb_facility
# ---------------------------------------------------------------------------

FAC_ROWS = [
    {
        "id": 1,
        "name": "Equinix DC1",
        "city": "Ashburn",
        "country": "US",
        "website": "https://www.equinix.com",
        "net_count": 320,
        "ix_count": 5,
    },
    {
        "id": 2,
        "name": "Equinix DC2",
        "city": "Ashburn",
        "country": "US",
        "website": "https://www.equinix.com",
        "net_count": 280,
        "ix_count": 4,
    },
    {
        "id": 3,
        "name": "Equinix AM1",
        "city": "Amsterdam",
        "country": "NL",
        "website": "https://www.equinix.com",
        "net_count": None,
        "ix_count": 0,
    },
]


async def test_facility_search_uses_net_count_with_no_per_facility_calls(monkeypatch):
    fake = FakePDB({"fac": {"data": FAC_ROWS}})
    monkeypatch.setattr(pdb, "_pdb_get", fake)

    res = await mcp.call_tool("peeringdb_facility", {"query": "Equinix"})
    data = res.structured_content

    assert data["error"] is None
    assert data["source"] == "PeeringDB"
    assert data["total"] == 3
    assert [f["networks_count"] for f in data["facilities"]] == [320, 280, 0]
    assert [f["exchanges_count"] for f in data["facilities"]] == [5, 4, 0]
    assert data["facilities"][0]["fac_id"] == 1
    assert data["facilities"][0]["city"] == "Ashburn"

    # One search request, zero netfac lookups regardless of result count.
    assert len(fake.calls) == 1
    assert fake.endpoints() == ["fac"]
    assert "netfac" not in fake.endpoints()


async def test_facility_search_falls_back_to_city(monkeypatch):
    def fac_handler(params):
        if "name__contains" in params:
            return {"data": []}
        return {"data": FAC_ROWS[:2]}

    fake = FakePDB({"fac": fac_handler})
    monkeypatch.setattr(pdb, "_pdb_get", fake)

    res = await mcp.call_tool("peeringdb_facility", {"query": "Ashburn"})
    assert res.structured_content["total"] == 2
    assert fake.endpoints() == ["fac", "fac"]
    assert fake.calls[1][1] == {
        "city__contains": "Ashburn",
        "limit": pdb._MAX_FAC_RESULTS,
    }


async def test_facility_rejects_blank_query(monkeypatch):
    fake = FakePDB({})
    monkeypatch.setattr(pdb, "_pdb_get", fake)

    with pytest.raises(ToolError, match="non-empty"):
        await mcp.call_tool("peeringdb_facility", {"query": ""})
    assert fake.calls == []


# ---------------------------------------------------------------------------
# Upstream failures populate `error`; `source` stays "PeeringDB"
# ---------------------------------------------------------------------------


async def test_facility_rate_limit_sets_error(monkeypatch):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            429, headers={"Retry-After": "30"}, json={"meta": {"error": "throttled"}}
        )

    _install_mock_transport(monkeypatch, handler)

    res = await mcp.call_tool("peeringdb_facility", {"query": "Equinix"})
    data = res.structured_content

    assert data["source"] == "PeeringDB"
    assert data["facilities"] == []
    assert data["total"] == 0
    assert data["error"] is not None
    assert "429" in data["error"]
    assert "retry after 30s" in data["error"]
    # Failure short-circuits: no city fallback attempted after a 429.
    assert len(seen) == 1
    assert seen[0].url.path == "/api/fac"
    assert seen[0].headers["User-Agent"] == "test"  # shared client is used


async def test_network_http_500_sets_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal error")

    _install_mock_transport(monkeypatch, handler)

    res = await mcp.call_tool("peeringdb_network", {"asn": 13335})
    data = res.structured_content

    assert data["network"] is None
    assert data["source"] == "PeeringDB"
    assert data["error"] is not None
    assert "HTTP 500" in data["error"]


async def test_ix_malformed_json_sets_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>maintenance</html>")

    _install_mock_transport(monkeypatch, handler)

    res = await mcp.call_tool("peeringdb_ix", {"query": "AMS-IX"})
    data = res.structured_content

    assert data["exchanges"] == []
    assert data["source"] == "PeeringDB"
    assert data["error"] is not None
    assert "could not be parsed" in data["error"]


async def test_ix_timeout_sets_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow upstream", request=request)

    _install_mock_transport(monkeypatch, handler)

    res = await mcp.call_tool("peeringdb_ix", {"query": "AMS-IX"})
    data = res.structured_content

    assert data["exchanges"] == []
    assert data["source"] == "PeeringDB"
    assert data["error"] is not None
    assert "timed out" in data["error"]


async def test_ix_member_fetch_failure_keeps_exchange_list(monkeypatch):
    def failing_members(params):
        raise _http_status_error(429)

    fake = FakePDB({"ix": {"data": IX_ROWS}, "netixlan": failing_members})
    monkeypatch.setattr(pdb, "_pdb_get", fake)

    res = await mcp.call_tool(
        "peeringdb_ix", {"query": "DE-CIX", "include_members": True}
    )
    data = res.structured_content

    # Exchange list survives; only the member fetch is reported as failed.
    assert data["total"] == 2
    assert data["exchanges"][0]["members"] == []
    assert data["exchanges"][0]["members_included"] is False
    assert data["exchanges"][0]["total_members"] == 1050
    assert data["source"] == "PeeringDB"
    assert data["error"] is not None
    assert "429" in data["error"]
    assert "member list for 'DE-CIX Frankfurt' missing" in data["error"]
