"""Tests for IRR RPSL parsing and AS-SET expansion logic (no network)."""

from __future__ import annotations

import net_mcp.tools.irr as irr
from net_mcp.server import mcp
from net_mcp.tools.irr import (
    _looks_like_set,
    _parse_autnum,
    _parse_route_objects,
    _rpsl_attrs,
    _rpsl_set_members,
)


def test_rpsl_attrs_merges_continuation_lines():
    raw = (
        "as-set:        AS-EXAMPLE\n"
        "members:       AS1, AS2,\n"
        "               AS3, AS4\n"
        "members:       AS-NESTED\n"
        "source:        RADB\n"
    )
    attrs = list(_rpsl_attrs(raw))
    members = [v for k, v in attrs if k == "members"]
    assert members[0] == "AS1, AS2, AS3, AS4"
    assert members[1] == "AS-NESTED"


def test_rpsl_set_members_handles_multiline_and_commas():
    raw = (
        "as-set: AS-FOO\n"
        "members: AS100, AS200,\n"
        "         AS300\n"
        "mp-members: AS400 AS500\n"
    )
    members = _rpsl_set_members(raw)
    assert set(members) == {"AS100", "AS200", "AS300", "AS400", "AS500"}


def test_looks_like_set():
    assert _looks_like_set("AS-CLOUDFLARE")
    assert _looks_like_set("AS13335:AS-CUSTOMERS")
    assert _looks_like_set("RS-FOO")
    assert not _looks_like_set("AS13335")
    assert not _looks_like_set("AS65000")


def test_expand_as_set_recurses(monkeypatch):
    # Simulate an IRR server: AS-TOP contains AS1 and a nested set AS-CHILD,
    # which contains AS2 and AS3. Expansion must follow the nesting.
    responses = {
        "AS-TOP": "as-set: AS-TOP\nmembers: AS1, AS-CHILD\n",
        "AS-CHILD": "as-set: AS-CHILD\nmembers: AS2,\n         AS3\n",
    }

    def fake_whois(server, query, source):
        return responses.get(query.upper(), "")

    monkeypatch.setattr(irr, "_whois_query", fake_whois)

    members: set[str] = set()
    visited: set[str] = set()
    irr._expand_as_set("whois.radb.net", "AS-TOP", "radb", visited, members)
    assert members == {"AS1", "AS2", "AS3"}


def test_expand_as_set_handles_cycles(monkeypatch):
    # A references B, B references A — must terminate without infinite recursion.
    responses = {
        "AS-A": "as-set: AS-A\nmembers: AS1, AS-B\n",
        "AS-B": "as-set: AS-B\nmembers: AS2, AS-A\n",
    }

    def fake_whois(server, query, source):
        return responses.get(query.upper(), "")

    monkeypatch.setattr(irr, "_whois_query", fake_whois)

    members: set[str] = set()
    visited: set[str] = set()
    irr._expand_as_set("whois.radb.net", "AS-A", "radb", visited, members)
    assert members == {"AS1", "AS2"}


def test_parse_route_objects():
    raw = (
        "route:      1.1.1.0/24\n"
        "origin:     AS13335\n"
        "descr:      Cloudflare\n"
        "mnt-by:     MAINT-CF\n"
        "source:     RADB\n"
        "\n"
        "route:      1.0.0.0/24\n"
        "origin:     AS13335\n"
        "source:     RADB\n"
    )
    objs = _parse_route_objects(raw, "radb")
    assert len(objs) == 2
    assert objs[0].prefix == "1.1.1.0/24"
    assert objs[0].origin == "AS13335"
    assert objs[0].descr == "Cloudflare"


def test_parse_autnum():
    raw = (
        "aut-num:    AS13335\n"
        "as-name:    CLOUDFLARENET\n"
        "descr:      Cloudflare\n"
        "import:     from AS1 accept ANY\n"
        "export:     to AS1 announce AS-CLOUDFLARE\n"
        "source:     RADB\n"
    )
    obj = _parse_autnum(raw, "radb")
    assert obj is not None
    assert obj.asn == "AS13335"
    assert obj.as_name == "CLOUDFLARENET"
    assert "from AS1 accept ANY" in obj.import_policy
    assert "to AS1 announce AS-CLOUDFLARE" in obj.export_policy


def test_parse_autnum_empty_returns_none():
    assert _parse_autnum("% no object found\n", "radb") is None


async def test_irr_route_lookup_caps_objects(monkeypatch):
    # A busy origin AS returns many route objects; the response list is capped
    # while `total` still reflects the real count.
    raw = "\n".join(
        f"route: 10.{i}.0.0/24\norigin: AS64500\nsource: RADB\n" for i in range(5)
    )
    monkeypatch.setattr(irr, "_whois_query", lambda server, query, source: raw)
    monkeypatch.setattr(irr, "_MAX_ROUTE_OBJECTS", 2)

    res = await mcp.call_tool("irr_route_lookup", {"query": "AS64500", "sources": "radb"})
    data = res.structured_content
    assert data["total"] == 5
    assert len(data["objects"]) == 2
