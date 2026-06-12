"""Tests for RPKI status normalization and detail strings (no network)."""

from __future__ import annotations

from net_mcp.tools.rpki import _build_detail, _parse_roas


def test_build_detail_valid():
    detail = _build_detail("VALID", 2, "1.1.1.0/24", 13335)
    assert "VALID" in detail
    assert "2 matching ROA" in detail


def test_build_detail_invalid_uses_reason():
    detail = _build_detail("INVALID", 1, "1.1.1.0/24", 9999, reason="origin ASN not authorized")
    assert "INVALID" in detail
    # The most important case must NOT claim NOT_FOUND.
    assert "NOT_FOUND" not in detail
    assert "origin ASN not authorized" in detail


def test_build_detail_invalid_without_reason_has_default():
    detail = _build_detail("INVALID", 1, "1.1.1.0/24", 9999)
    assert "INVALID" in detail
    assert "NOT_FOUND" not in detail


def test_build_detail_not_found():
    detail = _build_detail("NOT_FOUND", 0, "1.1.1.0/24", 13335)
    assert "NOT_FOUND" in detail


def test_parse_roas():
    vrps = [
        {"prefix": "1.1.1.0/24", "max_length": 24, "origin": 13335, "source": "RIPE"},
        {"prefix": "1.0.0.0/24", "max_length": 24, "origin": 13335},
    ]
    roas = _parse_roas(vrps)
    assert len(roas) == 2
    assert roas[0].prefix == "1.1.1.0/24"
    assert roas[0].asn == 13335
    assert roas[0].trust_anchor == "RIPE"
    assert roas[1].trust_anchor is None


def test_parse_roas_empty():
    assert _parse_roas([]) == []
