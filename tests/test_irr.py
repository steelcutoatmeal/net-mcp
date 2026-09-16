"""Tests for IRR RPSL parsing, input validation, and tool behaviour (no network)."""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

import net_mcp.tools.irr as irr
from net_mcp.server import mcp
from net_mcp.tools.irr import (
    _looks_like_set,
    _parse_autnum,
    _parse_route_objects,
    _rpsl_attrs,
    _rpsl_set_members,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeSocket:
    """Minimal stand-in for the socket returned by socket.create_connection."""

    def __init__(self, chunks):
        self._chunks = list(chunks)
        self.sent = b""
        self.exited = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.exited = True
        return False

    def sendall(self, data):
        self.sent += data

    def recv(self, bufsize):
        return self._chunks.pop(0) if self._chunks else b""


def _ok(raw: str):
    """Build a _whois_query replacement that always succeeds with `raw`."""
    return lambda server, query: (raw, None)


# ---------------------------------------------------------------------------
# RPSL parsing
# ---------------------------------------------------------------------------


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
    assert objs[0].mnt_by == "MAINT-CF"
    assert objs[1].prefix == "1.0.0.0/24"


def test_parse_route_objects_preserves_multiline_descr():
    raw = (
        "route:      192.0.2.0/24\n"
        "descr:      Example Networks\n"
        "            Building 4, Floor 2\n"
        "+           Anytown\n"
        "origin:     AS64500\n"
        "source:     RADB\n"
    )
    objs = _parse_route_objects(raw, "radb")
    assert len(objs) == 1
    assert objs[0].descr == "Example Networks Building 4, Floor 2 Anytown"
    assert objs[0].origin == "AS64500"


def test_parse_route_objects_registry_vs_source():
    # RADB mirrors RIPE: an object fetched from RADB whose own source: is RIPE
    # must report registry=radb and source=RIPE. Without a source: attribute,
    # source falls back to the upper-cased registry name.
    raw = (
        "route:      192.0.2.0/24\n"
        "origin:     AS64500\n"
        "source:     RIPE\n"
        "\n"
        "route6:     2001:db8::/32\n"
        "origin:     AS64500\n"
    )
    objs = _parse_route_objects(raw, "radb")
    assert [(o.registry, o.source) for o in objs] == [
        ("radb", "RIPE"),
        ("radb", "RADB"),
    ]
    assert objs[1].prefix == "2001:db8::/32"


def test_parse_route_objects_skips_banners_and_comments():
    raw = (
        "% This is the RADb whois server.\n"
        "% Use '-h' for help.\n"
        "\n"
        "route:      192.0.2.0/24\n"
        "origin:     AS64500\n"
        "source:     RADB\n"
        "\n"
        "% Query complete.\n"
    )
    objs = _parse_route_objects(raw, "radb")
    assert len(objs) == 1
    assert objs[0].prefix == "192.0.2.0/24"
    assert _parse_route_objects("% no entries found\n", "radb") == []


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
    assert obj.import_policy == ["from AS1 accept ANY"]
    assert obj.export_policy == ["to AS1 announce AS-CLOUDFLARE"]
    assert obj.registry == "radb"
    assert obj.source == "RADB"


def test_parse_autnum_empty_returns_none():
    assert _parse_autnum("% no object found\n", "radb") is None


def test_parse_autnum_picks_matching_object_without_merging():
    # A registry may return more than one aut-num object. Only the object for
    # the requested ASN is used; policies from the other must not leak in.
    raw = (
        "aut-num:    AS64499\n"
        "as-name:    OTHER\n"
        "import:     from AS9 accept ANY\n"
        "source:     RADB\n"
        "\n"
        "aut-num:    AS64500\n"
        "as-name:    WANTED\n"
        "descr:      Example\n"
        "            Networks Ltd\n"
        "mp-import:  afi ipv6.unicast from AS1 accept ANY\n"
        "export:     to AS1 announce AS64500\n"
        "source:     RIPE\n"
    )
    obj = _parse_autnum(raw, "radb", "as64500")
    assert obj is not None
    assert obj.asn == "AS64500"
    assert obj.as_name == "WANTED"
    assert obj.descr == "Example Networks Ltd"
    assert obj.import_policy == ["afi ipv6.unicast from AS1 accept ANY"]
    assert obj.export_policy == ["to AS1 announce AS64500"]
    assert obj.registry == "radb"
    assert obj.source == "RIPE"
    # Requesting an ASN that is not in the response yields nothing.
    assert _parse_autnum(raw, "radb", "AS1") is None


# ---------------------------------------------------------------------------
# AS-SET expansion
# ---------------------------------------------------------------------------


def test_expand_as_set_recurses(monkeypatch):
    # Simulate an IRR server: AS-TOP contains AS1 and a nested set AS-CHILD,
    # which contains AS2 and AS3. Expansion must follow the nesting.
    responses = {
        "AS-TOP": "as-set: AS-TOP\nmembers: AS1, AS-CHILD\n",
        "AS-CHILD": "as-set: AS-CHILD\nmembers: AS2,\n         AS3\n",
    }
    monkeypatch.setattr(
        irr,
        "_whois_query",
        lambda server, query: (responses.get(query.upper(), ""), None),
    )

    members: set[str] = set()
    visited: set[str] = set()
    errors: list[str] = []
    irr._expand_as_set("whois.radb.net", "AS-TOP", visited, members, errors)
    assert members == {"AS1", "AS2", "AS3"}
    assert errors == []


def test_expand_as_set_handles_cycles(monkeypatch):
    # A references B, B references A — must terminate without infinite recursion.
    responses = {
        "AS-A": "as-set: AS-A\nmembers: AS1, AS-B\n",
        "AS-B": "as-set: AS-B\nmembers: AS2, AS-A\n",
    }
    monkeypatch.setattr(
        irr,
        "_whois_query",
        lambda server, query: (responses.get(query.upper(), ""), None),
    )

    members: set[str] = set()
    visited: set[str] = set()
    errors: list[str] = []
    irr._expand_as_set("whois.radb.net", "AS-A", visited, members, errors)
    assert members == {"AS1", "AS2"}


def test_expand_as_set_records_nested_lookup_errors(monkeypatch):
    # A failure while expanding a nested set is recorded, and the members that
    # were reachable are still collected.
    def fake_whois(server, query):
        if query == "AS-BROKEN":
            return "", "whois query to whois.radb.net failed: TimeoutError: timed out"
        return "as-set: AS-TOP\nmembers: AS1, AS-BROKEN\n", None

    monkeypatch.setattr(irr, "_whois_query", fake_whois)

    members: set[str] = set()
    visited: set[str] = set()
    errors: list[str] = []
    irr._expand_as_set("whois.radb.net", "AS-TOP", visited, members, errors)
    assert members == {"AS1"}
    assert errors == [
        "AS-BROKEN: whois query to whois.radb.net failed: TimeoutError: timed out"
    ]


# ---------------------------------------------------------------------------
# Whois transport
# ---------------------------------------------------------------------------


def test_whois_query_sends_single_line_and_closes_socket(monkeypatch):
    sock = _FakeSocket([b"route: 192.0.2.0/24\n", b"origin: AS64500\n"])
    calls = []

    def fake_connect(address, timeout=None, **kwargs):
        calls.append((address, timeout))
        return sock

    monkeypatch.setattr(irr.socket, "create_connection", fake_connect)

    text, err = irr._whois_query("whois.example.net", "-i origin AS64500")
    assert err is None
    assert text == "route: 192.0.2.0/24\norigin: AS64500\n"
    assert sock.sent == b"-i origin AS64500\r\n"
    assert sock.exited  # socket released via the context manager
    assert calls == [(("whois.example.net", 43), irr.WHOIS_TIMEOUT)]


def test_whois_query_failure_returns_error(monkeypatch):
    def fake_connect(address, timeout=None, **kwargs):
        raise ConnectionRefusedError(61, "Connection refused")

    monkeypatch.setattr(irr.socket, "create_connection", fake_connect)

    text, err = irr._whois_query("whois.example.net", "AS64500")
    assert text == ""
    assert err is not None
    assert "whois.example.net" in err
    assert "ConnectionRefusedError" in err


def test_whois_query_truncates_oversized_response(monkeypatch):
    class _Firehose(_FakeSocket):
        def recv(self, bufsize):
            return b"x" * 64  # never ends

    sock = _Firehose([])
    monkeypatch.setattr(irr.socket, "create_connection", lambda *a, **k: sock)
    monkeypatch.setattr(irr, "_MAX_WHOIS_RESPONSE_BYTES", 200)

    text, err = irr._whois_query("whois.example.net", "AS64500")
    assert 200 <= len(text) < 200 + 64
    assert err is not None
    assert "truncated" in err
    assert sock.exited


# ---------------------------------------------------------------------------
# irr_route_lookup
# ---------------------------------------------------------------------------


async def test_irr_route_lookup_caps_objects(monkeypatch):
    # A busy origin AS returns many route objects; the response list is capped
    # while `total` still reflects the real count.
    raw = "\n".join(
        f"route: 10.{i}.0.0/24\norigin: AS64500\nsource: RADB\n" for i in range(5)
    )
    monkeypatch.setattr(irr, "_whois_query", _ok(raw))
    monkeypatch.setattr(irr, "_MAX_ROUTE_OBJECTS", 2)

    res = await mcp.call_tool(
        "irr_route_lookup", {"query": "AS64500", "sources": "radb"}
    )
    data = res.structured_content
    assert data["total"] == 5
    assert len(data["objects"]) == 2
    assert data["error"] is None


async def test_irr_route_lookup_normalises_bare_asn(monkeypatch):
    sent = []

    def fake_whois(server, query):
        sent.append((server, query))
        return "route: 192.0.2.0/24\norigin: AS64500\nsource: RIPE\n", None

    monkeypatch.setattr(irr, "_whois_query", fake_whois)

    res = await mcp.call_tool(
        "irr_route_lookup", {"query": " 64500 ", "sources": "radb"}
    )
    data = res.structured_content
    assert sent == [("whois.radb.net", "-i origin AS64500")]
    assert data["query"] == "AS64500"
    assert data["sources"] == ["radb"]
    assert data["objects"][0]["registry"] == "radb"
    assert data["objects"][0]["source"] == "RIPE"

    # Lower-case 'as' prefix is normalised too.
    sent.clear()
    await mcp.call_tool("irr_route_lookup", {"query": "as64500", "sources": "radb"})
    assert sent == [("whois.radb.net", "-i origin AS64500")]


async def test_irr_route_lookup_normalises_prefix(monkeypatch):
    sent = []

    def fake_whois(server, query):
        sent.append(query)
        return "", None

    monkeypatch.setattr(irr, "_whois_query", fake_whois)

    res = await mcp.call_tool(
        "irr_route_lookup", {"query": "1.1.1.1/24", "sources": "radb"}
    )
    assert res.structured_content["query"] == "1.1.1.0/24"

    res = await mcp.call_tool(
        "irr_route_lookup", {"query": "2001:DB8::1", "sources": "radb"}
    )
    assert res.structured_content["query"] == "2001:db8::1"

    assert sent == ["1.1.1.0/24", "2001:db8::1"]


async def test_irr_route_lookup_rejects_invalid_query(monkeypatch):
    monkeypatch.setattr(irr, "_whois_query", _ok(""))

    with pytest.raises(ToolError, match="expected an ASN"):
        await mcp.call_tool("irr_route_lookup", {"query": "not-a-prefix"})
    with pytest.raises(ToolError, match="CR/LF"):
        await mcp.call_tool("irr_route_lookup", {"query": "AS64500\r\n-k"})
    with pytest.raises(ToolError, match="CR/LF"):
        await mcp.call_tool("irr_route_lookup", {"query": "1.1.1.0/24\nAS1"})
    with pytest.raises(ToolError, match="must not start with '-'"):
        await mcp.call_tool("irr_route_lookup", {"query": "-i origin AS64500"})
    with pytest.raises(ToolError, match="must not be empty"):
        await mcp.call_tool("irr_route_lookup", {"query": "   "})
    with pytest.raises(ToolError, match="range from 0"):
        await mcp.call_tool("irr_route_lookup", {"query": "AS99999999999"})


async def test_irr_route_lookup_rejects_unknown_source(monkeypatch):
    monkeypatch.setattr(irr, "_whois_query", _ok(""))

    with pytest.raises(ToolError, match="Unknown IRR source 'bogus'") as excinfo:
        await mcp.call_tool(
            "irr_route_lookup", {"query": "AS64500", "sources": "radb,bogus"}
        )
    for key in irr.IRR_SERVERS:
        assert key in str(excinfo.value)


async def test_irr_route_lookup_reports_whois_error(monkeypatch):
    # One registry fails, the other answers: the error is surfaced AND the
    # partial results are kept.
    def fake_whois(server, query):
        if server == "whois.ripe.net":
            return "", "whois query to whois.ripe.net failed: TimeoutError: timed out"
        return "route: 192.0.2.0/24\norigin: AS64500\nsource: RADB\n", None

    monkeypatch.setattr(irr, "_whois_query", fake_whois)

    res = await mcp.call_tool("irr_route_lookup", {"query": "AS64500"})
    data = res.structured_content
    assert (
        data["error"]
        == "ripe: whois query to whois.ripe.net failed: TimeoutError: timed out"
    )
    assert data["total"] == 1
    assert data["objects"][0]["prefix"] == "192.0.2.0/24"


# ---------------------------------------------------------------------------
# irr_autnum
# ---------------------------------------------------------------------------


async def test_irr_autnum_via_tool(monkeypatch):
    raw = (
        "aut-num:    AS64500\n"
        "as-name:    EXAMPLE\n"
        "descr:      Example\n"
        "            Networks\n"
        "org:        ORG-EX1-RIPE\n"
        "import:     from AS1 accept ANY\n"
        "export:     to AS1 announce AS64500\n"
        "source:     RIPE\n"
    )
    sent = []

    def fake_whois(server, query):
        sent.append((server, query))
        return raw, None

    monkeypatch.setattr(irr, "_whois_query", fake_whois)

    res = await mcp.call_tool("irr_autnum", {"asn": "64500", "sources": "radb"})
    data = res.structured_content
    assert sent == [("whois.radb.net", "AS64500")]
    assert data["asn"] == "AS64500"
    assert data["sources"] == ["radb"]
    assert data["error"] is None
    assert len(data["objects"]) == 1
    obj = data["objects"][0]
    assert obj["asn"] == "AS64500"
    assert obj["as_name"] == "EXAMPLE"
    assert obj["descr"] == "Example Networks"
    assert obj["org"] == "ORG-EX1-RIPE"
    assert obj["import_policy"] == ["from AS1 accept ANY"]
    assert obj["export_policy"] == ["to AS1 announce AS64500"]
    assert obj["registry"] == "radb"
    assert obj["source"] == "RIPE"


async def test_irr_autnum_rejects_bad_input(monkeypatch):
    monkeypatch.setattr(irr, "_whois_query", _ok(""))

    with pytest.raises(ToolError, match="CR/LF"):
        await mcp.call_tool("irr_autnum", {"asn": "AS64500\r\n-k"})
    with pytest.raises(ToolError, match="must not start with '-'"):
        await mcp.call_tool("irr_autnum", {"asn": "-k"})
    with pytest.raises(ToolError, match="Invalid ASN"):
        await mcp.call_tool("irr_autnum", {"asn": "AS-SET-NAME"})
    with pytest.raises(ToolError, match="Unknown IRR source"):
        await mcp.call_tool("irr_autnum", {"asn": "AS64500", "sources": "nope"})


async def test_irr_autnum_reports_whois_error(monkeypatch):
    monkeypatch.setattr(
        irr,
        "_whois_query",
        lambda server, query: ("", f"whois query to {server} failed: OSError: down"),
    )

    res = await mcp.call_tool("irr_autnum", {"asn": "AS64500"})
    data = res.structured_content
    assert data["objects"] == []
    assert data["error"] == (
        "radb: whois query to whois.radb.net failed: OSError: down; "
        "ripe: whois query to whois.ripe.net failed: OSError: down"
    )


# ---------------------------------------------------------------------------
# irr_as_set_expand
# ---------------------------------------------------------------------------


async def test_irr_as_set_expand_via_tool(monkeypatch):
    responses = {
        "AS-TOP": "as-set: AS-TOP\nmembers: AS3, AS-CHILD, AS1\n",
        "AS-CHILD": "as-set: AS-CHILD\nmembers: AS2,\n         AS3\n",
    }
    sent = []

    def fake_whois(server, query):
        sent.append((server, query))
        return responses.get(query, ""), None

    monkeypatch.setattr(irr, "_whois_query", fake_whois)

    res = await mcp.call_tool(
        "irr_as_set_expand", {"as_set": "as-top", "source": "RIPE"}
    )
    data = res.structured_content
    assert sent == [("whois.ripe.net", "AS-TOP"), ("whois.ripe.net", "AS-CHILD")]
    assert data["as_set"] == "AS-TOP"
    assert data["members"] == ["AS1", "AS2", "AS3"]
    assert data["total"] == 3
    assert data["source"] == "ripe"
    assert data["error"] is None


async def test_irr_as_set_expand_rejects_bad_input(monkeypatch):
    monkeypatch.setattr(irr, "_whois_query", _ok(""))

    with pytest.raises(ToolError, match="CR/LF"):
        await mcp.call_tool("irr_as_set_expand", {"as_set": "AS-TOP\r\n-k"})
    with pytest.raises(ToolError, match="must not start with '-'"):
        await mcp.call_tool("irr_as_set_expand", {"as_set": "-k AS-TOP"})
    with pytest.raises(ToolError, match="Invalid AS-SET name"):
        await mcp.call_tool("irr_as_set_expand", {"as_set": "AS64500"})
    with pytest.raises(ToolError, match="Invalid AS-SET name"):
        await mcp.call_tool("irr_as_set_expand", {"as_set": "AS-TOP AS-OTHER"})
    with pytest.raises(ToolError, match="Unknown IRR source"):
        await mcp.call_tool(
            "irr_as_set_expand", {"as_set": "AS-TOP", "source": "bogus"}
        )


async def test_irr_as_set_expand_reports_whois_error(monkeypatch):
    monkeypatch.setattr(
        irr,
        "_whois_query",
        lambda server, query: (
            "",
            f"whois query to {server} failed: TimeoutError: timed out",
        ),
    )

    res = await mcp.call_tool("irr_as_set_expand", {"as_set": "AS-TOP"})
    data = res.structured_content
    assert data["members"] == []
    assert data["total"] == 0
    assert (
        data["error"]
        == "AS-TOP: whois query to whois.radb.net failed: TimeoutError: timed out"
    )
