"""Tests for local-tool input validation and the active-tool gate.

Everything here is offline: ``_run`` is stubbed so no subprocess is spawned,
and ``_find_cmd`` is stubbed so the tests do not depend on which binaries are
installed on the machine running them.
"""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError
from fastmcp.exceptions import ValidationError as FastMCPValidationError
from pydantic import ValidationError

import net_mcp.tools.local as local_mod
from net_mcp import USER_AGENT
from net_mcp.server import mcp
from net_mcp.tools.local import (
    CommandResult,
    _disabled_result,
    _filter_connection_lines,
    _validate_host,
    _validate_nmap_target,
    _validate_port,
    _validate_port_spec,
    _validate_record_type,
)

# FastMCP wraps argument-validation failures in its own ValidationError.
_SCHEMA_ERRORS = (ValidationError, FastMCPValidationError, ToolError)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


class _Cfg:
    def __init__(self, allow: bool):
        self.allow_active_local_tools = allow


def _capture_run(monkeypatch, stdout: str = "ok", rc: int = 0) -> list[list[str]]:
    """Stub _run so tools never spawn a process; return the list of argv seen."""
    calls: list[list[str]] = []

    def fake_run(cmd, timeout=30):
        calls.append(cmd)
        return rc, stdout, ""

    monkeypatch.setattr(local_mod, "_run", fake_run)
    return calls


def _binaries_present(monkeypatch) -> None:
    """Pretend every looked-up binary exists (and use its bare name as argv[0])."""
    monkeypatch.setattr(local_mod, "_find_cmd", lambda *names: names[0])


def _on_macos(monkeypatch) -> None:
    monkeypatch.setattr(local_mod, "_IS_WINDOWS", False)
    monkeypatch.setattr(local_mod, "_IS_LINUX", False)
    monkeypatch.setattr(local_mod, "_IS_MACOS", True)


# ---------------------------------------------------------------------------
# _validate_host
# ---------------------------------------------------------------------------


def test_validate_host_accepts_normal_hosts():
    assert _validate_host("cloudflare.com") == "cloudflare.com"
    assert _validate_host("1.1.1.1") == "1.1.1.1"
    assert _validate_host("2606:4700:4700::1111") == "2606:4700:4700::1111"
    assert _validate_host("fe80::1%en0") == "fe80::1%en0"
    assert _validate_host("10.0.0.0/24") == "10.0.0.0/24"


def test_validate_host_strips_ipv6_brackets():
    assert _validate_host("[::1]") == "::1"
    assert _validate_host("[2606:4700:4700::1111]") == "2606:4700:4700::1111"
    assert _validate_host(" [fe80::1%en0] ") == "fe80::1%en0"


def test_validate_host_rejects_stray_brackets_and_bracketed_flags():
    with pytest.raises(ValueError):
        _validate_host("a[b]")
    with pytest.raises(ValueError):
        _validate_host("[]")
    # Brackets are stripped before the leading-dash check, so this cannot
    # smuggle a flag through.
    with pytest.raises(ValueError):
        _validate_host("[-oN/tmp/x]")


def test_validate_host_rejects_leading_dash():
    # Arg-injection guard: a host starting with '-' could be parsed as a flag.
    with pytest.raises(ValueError):
        _validate_host("-oN/tmp/x")
    with pytest.raises(ValueError):
        _validate_host("--script=evil")


def test_validate_host_rejects_leading_slash():
    with pytest.raises(ValueError):
        _validate_host("/etc/passwd")


def test_validate_host_rejects_shell_metacharacters():
    for bad in ["a;b", "a|b", "a`b`", "a$b", "a b", "a,b", "a_b"]:
        with pytest.raises(ValueError):
            _validate_host(bad)


def test_validate_host_rejects_empty_and_too_long():
    with pytest.raises(ValueError):
        _validate_host("")
    with pytest.raises(ValueError):
        _validate_host("a" * 254)


# ---------------------------------------------------------------------------
# Other validators
# ---------------------------------------------------------------------------


def test_validate_record_type():
    assert _validate_record_type("a") == "A"
    assert _validate_record_type(" aaaa ") == "AAAA"
    assert _validate_record_type("type65") == "TYPE65"
    for bad in ["+trace", "-x", "+SHORT", "A B", "", "A" * 11, "@8.8.8.8", "a.b"]:
        with pytest.raises(ValueError):
            _validate_record_type(bad)


def test_validate_port_range():
    assert _validate_port(443) == 443
    assert _validate_port(1) == 1
    assert _validate_port(65535) == 65535
    with pytest.raises(ValueError):
        _validate_port(0)
    with pytest.raises(ValueError):
        _validate_port(70000)


def test_validate_port_spec():
    assert _validate_port_spec("22,80,443") == "22,80,443"
    assert _validate_port_spec("1-1024") == "1-1024"
    assert _validate_port_spec(" 22, 80-90 ") == "22,80-90"
    for bad in ["70000", "0", "80-22", "abc", "22,,80", "-p", "1-", "22;80", ""]:
        with pytest.raises(ValueError):
            _validate_port_spec(bad)


@pytest.mark.parametrize(
    "target",
    [
        "10.0.0.0/24",
        "10.0.0.1",
        "example.com",
        "host-1.example.com.",
        "2001:db8::/120",
        "2001:db8::1",
        "[2001:db8::1]",
    ],
)
def test_validate_nmap_target_accepts(target):
    assert _validate_nmap_target(target) == target.strip("[]")


@pytest.mark.parametrize(
    "target",
    [
        "10.0.0.0/8",
        "10.0.0.0/23",
        "10.0.0-255.1",
        "10.0.0.1,10.0.0.2",
        "10.0.0.*",
        "2001:db8::/64",
        "2001:db8::/119",
        "10.0.0.256",
        "1-2",
        "example.com/24",
        "10.0.0.0/33",
    ],
)
def test_validate_nmap_target_rejects(target):
    with pytest.raises(ValueError):
        _validate_nmap_target(target)


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


def test_command_result_fields_have_descriptions():
    for name, field in CommandResult.model_fields.items():
        assert field.description, f"CommandResult.{name} has no description"


def test_disabled_result_shape():
    r = _disabled_result("nmap")
    assert r.success is False
    assert r.returncode == 126
    assert "disabled" in r.stderr.lower()
    assert r.error == r.stderr


# ---------------------------------------------------------------------------
# Active-tool gate
# ---------------------------------------------------------------------------


async def test_nmap_disabled_by_default(monkeypatch):
    monkeypatch.setattr(local_mod, "get_config", lambda: _Cfg(False))
    calls = _capture_run(monkeypatch)
    res = await mcp.call_tool("local_nmap", {"target": "127.0.0.1"})
    assert res.structured_content["success"] is False
    assert "disabled" in res.structured_content["stderr"].lower()
    assert calls == []


async def test_curl_disabled_by_default(monkeypatch):
    monkeypatch.setattr(local_mod, "get_config", lambda: _Cfg(False))
    calls = _capture_run(monkeypatch)
    res = await mcp.call_tool("local_curl", {"url": "https://example.com"})
    assert res.structured_content["success"] is False
    assert "disabled" in res.structured_content["stderr"].lower()
    assert calls == []


async def test_nmap_gate_can_be_enabled(monkeypatch):
    monkeypatch.setattr(local_mod, "get_config", lambda: _Cfg(True))
    _binaries_present(monkeypatch)
    calls = _capture_run(monkeypatch)
    res = await mcp.call_tool("local_nmap", {"target": "127.0.0.1", "ports": "1-10"})
    assert res.structured_content["success"] is True
    assert calls == [["nmap", "-sT", "-Pn", "--open", "-p", "1-10", "127.0.0.1"]]


# ---------------------------------------------------------------------------
# local_ping
# ---------------------------------------------------------------------------


async def test_ping_macos_uses_milliseconds(monkeypatch):
    # macOS/BSD ping -W is per-packet wait in milliseconds, so timeout=5 -> 5000.
    _on_macos(monkeypatch)
    _capture_run(monkeypatch)
    res = await mcp.call_tool(
        "local_ping", {"host": "1.1.1.1", "count": 2, "timeout": 5}
    )
    tokens = res.structured_content["command"].split()
    assert tokens[tokens.index("-W") + 1] == "5000"


async def test_ping_linux_uses_seconds(monkeypatch):
    # Linux iputils ping -W is in seconds, so timeout=5 stays 5.
    monkeypatch.setattr(local_mod, "_IS_WINDOWS", False)
    monkeypatch.setattr(local_mod, "_IS_MACOS", False)
    _capture_run(monkeypatch)
    res = await mcp.call_tool(
        "local_ping", {"host": "1.1.1.1", "count": 2, "timeout": 5}
    )
    tokens = res.structured_content["command"].split()
    assert tokens[tokens.index("-W") + 1] == "5"


async def test_ping_bracketed_ipv6_is_stripped(monkeypatch):
    _on_macos(monkeypatch)
    calls = _capture_run(monkeypatch)
    res = await mcp.call_tool("local_ping", {"host": "[::1]"})
    assert res.structured_content["success"] is True
    assert calls[0][-1] == "::1"


async def test_ping_validation_failure_returns_result_not_exception(monkeypatch):
    calls = _capture_run(monkeypatch)
    res = await mcp.call_tool("local_ping", {"host": "-oN/tmp/x"})
    body = res.structured_content
    assert body["success"] is False
    assert body["returncode"] == 2
    assert body["error"] and body["error"] == body["stderr"]
    assert calls == []


@pytest.mark.parametrize(
    "args",
    [{"count": 0}, {"count": -1}, {"count": 101}, {"timeout": 0}, {"timeout": 31}],
)
async def test_ping_numeric_bounds_enforced_by_schema(monkeypatch, args):
    calls = _capture_run(monkeypatch)
    with pytest.raises(_SCHEMA_ERRORS):
        await mcp.call_tool("local_ping", {"host": "1.1.1.1", **args})
    assert calls == []


async def test_traceroute_and_mtr_bounds_enforced_by_schema(monkeypatch):
    _binaries_present(monkeypatch)
    calls = _capture_run(monkeypatch)
    with pytest.raises(_SCHEMA_ERRORS):
        await mcp.call_tool("local_traceroute", {"host": "1.1.1.1", "max_hops": 0})
    with pytest.raises(_SCHEMA_ERRORS):
        await mcp.call_tool("local_mtr", {"host": "1.1.1.1", "count": 0})
    assert calls == []


# ---------------------------------------------------------------------------
# local_dig
# ---------------------------------------------------------------------------


async def test_dig_rejects_plus_option_record_type(monkeypatch):
    _binaries_present(monkeypatch)
    calls = _capture_run(monkeypatch)
    res = await mcp.call_tool(
        "local_dig", {"name": "example.com", "record_type": "+trace"}
    )
    body = res.structured_content
    assert body["success"] is False
    assert "record type" in body["error"].lower()
    assert calls == []


async def test_dig_accepts_numeric_type_underscore_names_and_at_server(monkeypatch):
    _binaries_present(monkeypatch)
    calls = _capture_run(monkeypatch)
    res = await mcp.call_tool(
        "local_dig",
        {
            "name": "_dmarc.example.com",
            "record_type": "type65",
            "server": "@[2001:4860:4860::8888]",
            "short": True,
        },
    )
    assert res.structured_content["success"] is True
    assert calls == [
        ["dig", "_dmarc.example.com", "TYPE65", "@2001:4860:4860::8888", "+short"]
    ]


async def test_dig_rejects_option_like_name(monkeypatch):
    _binaries_present(monkeypatch)
    calls = _capture_run(monkeypatch)
    for bad in ["+trace", "-x", "@8.8.8.8", "a b.com"]:
        res = await mcp.call_tool("local_dig", {"name": bad})
        assert res.structured_content["success"] is False
        assert res.structured_content["error"]
    assert calls == []


# ---------------------------------------------------------------------------
# local_nmap
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target", ["10.0.0.0/8", "10.0.0-255.1", "10.0.0.1,10.0.0.2", "2001:db8::/64"]
)
async def test_nmap_rejects_large_or_multi_host_targets(monkeypatch, target):
    monkeypatch.setattr(local_mod, "get_config", lambda: _Cfg(True))
    _binaries_present(monkeypatch)
    calls = _capture_run(monkeypatch)
    res = await mcp.call_tool("local_nmap", {"target": target})
    body = res.structured_content
    assert body["success"] is False
    assert body["error"]
    assert calls == []


@pytest.mark.parametrize("target", ["10.0.0.0/24", "scanme.example.com", "10.0.0.1"])
async def test_nmap_accepts_small_prefix_and_single_hosts(monkeypatch, target):
    monkeypatch.setattr(local_mod, "get_config", lambda: _Cfg(True))
    _binaries_present(monkeypatch)
    calls = _capture_run(monkeypatch)
    res = await mcp.call_tool("local_nmap", {"target": target})
    assert res.structured_content["success"] is True
    assert calls == [["nmap", "-sT", "-Pn", "--open", target]]


async def test_nmap_ipv6_target_adds_dash_6(monkeypatch):
    monkeypatch.setattr(local_mod, "get_config", lambda: _Cfg(True))
    _binaries_present(monkeypatch)
    calls = _capture_run(monkeypatch)
    await mcp.call_tool("local_nmap", {"target": "[2001:db8::1]", "ports": "443"})
    assert calls == [["nmap", "-sT", "-Pn", "--open", "-6", "-p", "443", "2001:db8::1"]]


async def test_nmap_rejects_bad_port_spec(monkeypatch):
    monkeypatch.setattr(local_mod, "get_config", lambda: _Cfg(True))
    _binaries_present(monkeypatch)
    calls = _capture_run(monkeypatch)
    for bad in ["70000", "80-22", "abc", "-p"]:
        res = await mcp.call_tool("local_nmap", {"target": "10.0.0.1", "ports": bad})
        assert res.structured_content["success"] is False
        assert "port" in res.structured_content["error"].lower()
    assert calls == []


# ---------------------------------------------------------------------------
# local_curl
# ---------------------------------------------------------------------------


async def test_curl_argv_starts_with_q_and_contains_g(monkeypatch):
    monkeypatch.setattr(local_mod, "get_config", lambda: _Cfg(True))
    _binaries_present(monkeypatch)
    calls = _capture_run(monkeypatch)
    res = await mcp.call_tool("local_curl", {"url": "https://example.com/[1-1000]"})
    assert res.structured_content["success"] is True
    cmd = calls[0]
    assert cmd[0] == "curl"
    assert cmd[1] == "-q"
    assert "-g" in cmd
    assert cmd[-1] == "https://example.com/[1-1000]"


async def test_curl_assumes_https_and_rejects_bad_urls(monkeypatch):
    monkeypatch.setattr(local_mod, "get_config", lambda: _Cfg(True))
    _binaries_present(monkeypatch)
    calls = _capture_run(monkeypatch)
    await mcp.call_tool("local_curl", {"url": "example.com/path"})
    assert calls[0][-1] == "https://example.com/path"
    for bad in [
        "https://exa mple.com",
        "ftp://example.com",
        "https://a;b",
        "https://a`b`",
    ]:
        res = await mcp.call_tool("local_curl", {"url": bad})
        assert res.structured_content["success"] is False
        assert "url" in res.structured_content["error"].lower()
    assert len(calls) == 1


async def test_curl_truncates_long_output(monkeypatch):
    monkeypatch.setattr(local_mod, "get_config", lambda: _Cfg(True))
    _binaries_present(monkeypatch)
    _capture_run(monkeypatch, stdout="x" * 20_000)
    res = await mcp.call_tool("local_curl", {"url": "https://example.com"})
    body = res.structured_content
    assert len(body["stdout"]) == 10_000
    assert "truncated" in body["note"].lower()


async def test_public_ip_uses_shared_user_agent_and_ignores_curlrc(monkeypatch):
    _binaries_present(monkeypatch)
    calls = _capture_run(monkeypatch, stdout="203.0.113.7\n")
    res = await mcp.call_tool("local_public_ip", {})
    assert res.structured_content["stdout"] == "203.0.113.7"
    cmd = calls[0]
    assert cmd[1] == "-q"
    assert cmd[cmd.index("-A") + 1] == USER_AGENT


# ---------------------------------------------------------------------------
# local_connections
# ---------------------------------------------------------------------------

_MACOS_NETSTAT = """\
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  192.168.1.5.52345      93.184.216.34.443      ESTABLISHED
tcp4       0      0  192.168.1.5.52346      93.184.216.35.443      TIME_WAIT
tcp46      0      0  *.8080                 *.*                    LISTEN
udp4       0      0  *.5353                 *.*
"""

_WINDOWS_NETSTAT = """\

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    192.168.1.5:52345      93.184.216.34:443      ESTABLISHED
  UDP    0.0.0.0:5353           *:*
"""


def test_filter_connection_lines():
    est = _filter_connection_lines(_MACOS_NETSTAT, "established")
    assert "ESTABLISHED" in est
    assert "TIME_WAIT" not in est
    assert "LISTEN" not in est
    assert est.startswith("Active Internet connections")

    lst = _filter_connection_lines(_WINDOWS_NETSTAT, "listen")
    assert "LISTENING" in lst
    assert "ESTABLISHED" not in lst
    assert "UDP" not in lst
    assert "Proto" in lst

    assert _filter_connection_lines(_MACOS_NETSTAT, "all") == _MACOS_NETSTAT


async def test_connections_macos_filters_client_side(monkeypatch):
    _on_macos(monkeypatch)
    calls = _capture_run(monkeypatch, stdout=_MACOS_NETSTAT)
    res = await mcp.call_tool("local_connections", {"state": "established"})
    body = res.structured_content
    assert calls == [["netstat", "-an", "-p", "tcp"]]
    assert "ESTABLISHED" in body["stdout"]
    assert "LISTEN" not in body["stdout"]
    assert "filtered" in body["note"].lower()


async def test_connections_all_is_unfiltered(monkeypatch):
    _on_macos(monkeypatch)
    _capture_run(monkeypatch, stdout=_MACOS_NETSTAT)
    res = await mcp.call_tool("local_connections", {})
    body = res.structured_content
    assert body["stdout"] == _MACOS_NETSTAT
    assert body["note"] == ""


async def test_connections_rejects_unknown_state(monkeypatch):
    calls = _capture_run(monkeypatch)
    with pytest.raises(_SCHEMA_ERRORS):
        await mcp.call_tool("local_connections", {"state": "closed"})
    assert calls == []
