"""DNS tools with DNSSEC validation support."""

from __future__ import annotations

import time
from typing import Annotated

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
from fastmcp import FastMCP
from pydantic import Field

from net_mcp.config import get_config

from net_mcp.models import (
    DelegationStep,
    DNSLookupResult,
    DNSRecord,
    DNSSECStatus,
    DNSTraceResult,
)

VALID_RECORD_TYPES = {
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "SOA",
    "CNAME",
    "PTR",
    "SRV",
    "CAA",
    "DNSKEY",
    "DS",
}


def _default_resolver() -> str:
    return get_config().default_dns_resolver


def register_dns_tools(mcp: FastMCP) -> None:
    @mcp.tool(tags={"dns", "dnssec"})
    def dns_lookup(
        name: Annotated[str, Field(description="Domain name to query (e.g. 'cloudflare.com')")],
        record_type: Annotated[
            str, Field(description="DNS record type: A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV, CAA")
        ] = "A",
        resolver: Annotated[
            str | None,
            Field(description="DNS resolver IP to use. Defaults to the configured resolver."),
        ] = None,
    ) -> DNSLookupResult:
        """Query DNS records for a domain with DNSSEC validation status.

        Returns the requested records along with whether DNSSEC is enabled
        and whether validation passes. Use this to check DNS configuration
        and DNSSEC health for any domain.

        If the resolver returns SERVFAIL (which a validating resolver does
        when DNSSEC validation fails), this re-queries with the CD
        (Checking Disabled) bit to distinguish a genuine DNSSEC failure
        from an unrelated server error.
        """
        record_type = record_type.upper()
        if record_type not in VALID_RECORD_TYPES:
            raise ValueError(
                f"Unsupported record type '{record_type}'. "
                f"Supported: {', '.join(sorted(VALID_RECORD_TYPES))}"
            )

        resolver = resolver or _default_resolver()

        res = dns.resolver.Resolver()
        res.nameservers = [resolver]
        res.use_edns(0, dns.flags.DO, 4096)  # request DNSSEC records

        start = time.monotonic()
        try:
            answer = res.resolve(name, record_type, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            elapsed = (time.monotonic() - start) * 1000
            return DNSLookupResult(
                query_name=name,
                query_type=record_type,
                resolver=resolver,
                records=[],
                dnssec=DNSSECStatus(enabled=False, valid=None, detail="NXDOMAIN — domain does not exist"),
                response_time_ms=round(elapsed, 2),
            )
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            # SERVFAIL (NoNameservers) or timeout. A validating resolver
            # returns SERVFAIL when DNSSEC validation fails — diagnose it.
            elapsed = (time.monotonic() - start) * 1000
            records, dnssec_status = _diagnose_servfail(name, record_type, resolver, exc)
            return DNSLookupResult(
                query_name=name,
                query_type=record_type,
                resolver=resolver,
                records=records,
                dnssec=dnssec_status,
                response_time_ms=round(elapsed, 2),
            )
        elapsed = (time.monotonic() - start) * 1000

        records = []
        if answer.rrset is not None:
            for rdata in answer.rrset:
                records.append(
                    DNSRecord(
                        name=str(answer.qname),
                        record_type=record_type,
                        ttl=answer.rrset.ttl,
                        value=str(rdata),
                    )
                )

        # Reuse the response we already have rather than issuing a second query.
        if answer.rrset is None:
            dnssec_status = DNSSECStatus(
                enabled=False, valid=None, detail=f"No {record_type} records found"
            )
        else:
            dnssec_status = _dnssec_from_response(answer.response)

        return DNSLookupResult(
            query_name=name,
            query_type=record_type,
            resolver=resolver,
            records=records,
            dnssec=dnssec_status,
            response_time_ms=round(elapsed, 2),
        )

    @mcp.tool(tags={"dns", "dnssec"})
    def dns_trace(
        name: Annotated[str, Field(description="Domain name to trace (e.g. 'example.com')")],
        record_type: Annotated[str, Field(description="DNS record type to trace")] = "A",
    ) -> DNSTraceResult:
        """Trace DNS resolution from root to authoritative nameservers.

        Walks the actual delegation chain (zone cuts) from the root down,
        showing each zone's nameservers and DNSSEC signing status. Labels
        that are not their own zone (e.g. 'www' as a record inside a parent
        zone) are skipped so they are not mistaken for a broken delegation.

        A DNSSEC break is reported when a zone is signed (publishes DNSKEY)
        but its parent publishes no DS record for it — an "island of
        security" that breaks the chain of trust.
        """
        record_type = record_type.upper()
        target = dns.name.from_text(name)
        labels = str(target).rstrip(".").split(".")

        # Candidate zones, root -> tld -> domain -> subdomain...
        candidates = ["."]
        for i in range(len(labels)):
            candidates.append(".".join(labels[-(i + 1) :]) + ".")

        # Only keep candidates that are actual zone cuts (have NS delegation).
        chain: list[DelegationStep] = []
        for zone in candidates:
            step, is_zone = _probe_zone(zone)
            if zone == "." or is_zone:
                chain.append(step)

        chain_intact = True
        break_point = None
        for i, step in enumerate(chain):
            if i == 0:  # root is the trust anchor
                continue
            # A genuine break: the zone is signed but the parent publishes no
            # DS for it, so the chain of trust cannot reach this zone.
            if step.dnssec_signed and not step.ds_records_present:
                chain_intact = False
                break_point = step.zone
                break

        return DNSTraceResult(
            query_name=name,
            query_type=record_type,
            delegation_chain=chain,
            dnssec_chain_intact=chain_intact,
            break_point=break_point,
        )


def _dnssec_from_response(response: dns.message.Message) -> DNSSECStatus:
    """Derive DNSSEC status from a resolver response (no extra query)."""
    has_rrsig = any(
        rrset.rdtype == dns.rdatatype.RRSIG for rrset in response.answer
    )
    if not has_rrsig:
        return DNSSECStatus(
            enabled=False,
            valid=None,
            detail="No RRSIG records in response — DNSSEC not enabled for this name",
        )

    ad_flag = bool(response.flags & dns.flags.AD)
    if ad_flag:
        return DNSSECStatus(
            enabled=True,
            valid=True,
            detail="DNSSEC enabled and validated (AD flag set by resolver)",
        )
    return DNSSECStatus(
        enabled=True,
        valid=False,
        detail="DNSSEC records present but AD flag not set — validation may have failed",
    )


def _diagnose_servfail(
    name: str, record_type: str, resolver: str, exc: Exception
) -> tuple[list[DNSRecord], DNSSECStatus]:
    """Diagnose a SERVFAIL/timeout by re-querying with the CD bit set.

    If the name resolves with Checking Disabled but failed without it, the
    original SERVFAIL was a DNSSEC validation failure. Returns the records
    recovered via the CD query (so the caller can still see what is there)
    and a DNSSECStatus describing the failure.
    """
    try:
        qtype = dns.rdatatype.from_text(record_type)
        request = dns.message.make_query(name, record_type, want_dnssec=True)
        request.flags |= dns.flags.CD
        response = dns.query.udp(request, resolver, timeout=5)

        if response.rcode() == dns.rcode.NOERROR:
            records = []
            for rrset in response.answer:
                if rrset.rdtype != qtype:
                    continue
                for rdata in rrset:
                    records.append(
                        DNSRecord(
                            name=str(rrset.name),
                            record_type=record_type,
                            ttl=rrset.ttl,
                            value=str(rdata),
                        )
                    )
            if records:
                return records, DNSSECStatus(
                    enabled=True,
                    valid=False,
                    detail=(
                        "DNSSEC validation FAILED — the resolver returned SERVFAIL, "
                        "but the records resolve when the CD (Checking Disabled) bit "
                        "is set. This confirms a DNSSEC signature or chain-of-trust "
                        "validation failure."
                    ),
                )
    except Exception:
        pass

    return [], DNSSECStatus(
        enabled=False,
        valid=None,
        detail=(
            f"Resolver returned SERVFAIL or timed out ({type(exc).__name__}). "
            "The name could not be resolved; this may indicate a DNSSEC "
            "validation failure or an unreachable/broken resolver."
        ),
    )


def _probe_zone(zone: str) -> tuple[DelegationStep, bool]:
    """Probe a zone for NS records and DNSSEC status.

    Returns the DelegationStep and a flag indicating whether the name is an
    actual zone cut (has an NS delegation). The root (".") is always a zone.
    """
    try:
        res = dns.resolver.Resolver()
        res.nameservers = [_default_resolver()]

        # Get NS records — presence indicates this name is a zone cut.
        try:
            ns_answer = res.resolve(zone, "NS")
            nameservers = sorted(str(ns) for ns in ns_answer)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            nameservers = []

        is_zone = zone == "." or bool(nameservers)

        # Check for DNSKEY (indicates zone is signed)
        dnssec_signed = False
        try:
            res.resolve(zone, "DNSKEY")
            dnssec_signed = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass

        # Check for DS records (indicates parent has delegation signer)
        ds_present = False
        if zone != ".":
            try:
                res.resolve(zone, "DS")
                ds_present = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass

        detail = f"{'Signed' if dnssec_signed else 'Unsigned'}"
        if ds_present:
            detail += ", DS in parent"

        return (
            DelegationStep(
                zone=zone.rstrip(".") or ".",
                nameservers=nameservers,
                dnssec_signed=dnssec_signed,
                ds_records_present=ds_present,
                detail=detail,
            ),
            is_zone,
        )
    except Exception as e:
        return (
            DelegationStep(
                zone=zone.rstrip(".") or ".",
                nameservers=[],
                dnssec_signed=False,
                ds_records_present=False,
                detail=f"Probe failed: {e}",
            ),
            False,
        )
