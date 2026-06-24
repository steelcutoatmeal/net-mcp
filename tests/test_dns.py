"""Tests for DNSSEC status derivation (no network)."""

from __future__ import annotations

from types import SimpleNamespace

import dns.flags
import dns.rdatatype

from net_mcp.tools.dns import _dnssec_from_response


def _rrset(rdtype):
    return SimpleNamespace(rdtype=rdtype)


def test_dnssec_signed_and_validated():
    resp = SimpleNamespace(
        answer=[_rrset(dns.rdatatype.A), _rrset(dns.rdatatype.RRSIG)],
        flags=dns.flags.AD,
    )
    status = _dnssec_from_response(resp)
    assert status.enabled is True
    assert status.valid is True


def test_dnssec_signed_but_not_validated():
    resp = SimpleNamespace(
        answer=[_rrset(dns.rdatatype.A), _rrset(dns.rdatatype.RRSIG)],
        flags=0,
    )
    status = _dnssec_from_response(resp)
    assert status.enabled is True
    assert status.valid is False


def test_dnssec_not_enabled():
    resp = SimpleNamespace(answer=[_rrset(dns.rdatatype.A)], flags=0)
    status = _dnssec_from_response(resp)
    assert status.enabled is False
    assert status.valid is None


def test_dns_trace_result_dropped_unused_query_type():
    # record_type was accepted but never used; the field was removed to avoid
    # misleading the model that it influences the delegation trace.
    from net_mcp.models import DNSTraceResult

    assert "query_type" not in DNSTraceResult.model_fields
