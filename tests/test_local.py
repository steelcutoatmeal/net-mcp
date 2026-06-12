"""Tests for local-tool input validation and the active-tool gate (no network)."""

from __future__ import annotations

import pytest

import net_mcp.tools.local as local_mod
from net_mcp.server import mcp
from net_mcp.tools.local import _disabled_result, _validate_host, _validate_port


def test_validate_host_accepts_normal_hosts():
    assert _validate_host("cloudflare.com") == "cloudflare.com"
    assert _validate_host("1.1.1.1") == "1.1.1.1"
    assert _validate_host("2606:4700:4700::1111") == "2606:4700:4700::1111"
    assert _validate_host("10.0.0.0/24") == "10.0.0.0/24"


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
    for bad in ["a;b", "a|b", "a`b`", "a$b", "a b"]:
        with pytest.raises(ValueError):
            _validate_host(bad)


def test_validate_host_rejects_empty_and_too_long():
    with pytest.raises(ValueError):
        _validate_host("")
    with pytest.raises(ValueError):
        _validate_host("a" * 254)


def test_validate_port_range():
    assert _validate_port(443) == 443
    assert _validate_port(1) == 1
    assert _validate_port(65535) == 65535
    with pytest.raises(ValueError):
        _validate_port(0)
    with pytest.raises(ValueError):
        _validate_port(70000)


def test_disabled_result_shape():
    r = _disabled_result("nmap")
    assert r.success is False
    assert r.returncode == 126
    assert "disabled" in r.stderr.lower()


class _Cfg:
    def __init__(self, allow: bool):
        self.allow_active_local_tools = allow


async def test_nmap_disabled_by_default(monkeypatch):
    monkeypatch.setattr(local_mod, "get_config", lambda: _Cfg(False))
    res = await mcp.call_tool("local_nmap", {"target": "127.0.0.1"})
    assert res.structured_content["success"] is False
    assert "disabled" in res.structured_content["stderr"].lower()


async def test_curl_disabled_by_default(monkeypatch):
    monkeypatch.setattr(local_mod, "get_config", lambda: _Cfg(False))
    res = await mcp.call_tool("local_curl", {"url": "https://example.com"})
    assert res.structured_content["success"] is False
    assert "disabled" in res.structured_content["stderr"].lower()


async def test_nmap_gate_can_be_enabled(monkeypatch):
    # With the gate on, it no longer short-circuits as "disabled" (it will
    # instead try to run nmap, succeeding or reporting "not found").
    monkeypatch.setattr(local_mod, "get_config", lambda: _Cfg(True))
    res = await mcp.call_tool("local_nmap", {"target": "127.0.0.1", "ports": "1-10"})
    assert "disabled" not in res.structured_content["stderr"].lower()
