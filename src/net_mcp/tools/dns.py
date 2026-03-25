"""DNS tools with DNSSEC validation support."""

from __future__ import annotations

import time
from typing import Annotated

import dns.dnssec
import dns.message
import dns.name
import dns.query
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
            str, Field(description="DNS resolver IP to use")
        ] = _default_resolver(),
    ) -> DNSLookupResult:
        """Query DNS records for a domain with DNSSEC validation status.

        Returns the requested records along with whether DNSSEC is enabled
        and whether validation passes. Use this to check DNS configuration
        and DNSSEC health for any domain.
        """
        record_type = record_type.upper()
        if record_type not in VALID_RECORD_TYPES:
            raise ValueError(
                f"Unsupported record type '{record_type}'. "
                f"Supported: {', '.join(sorted(VALID_RECORD_TYPES))}"
            )

        res = dns.resolver.Resolver()
        res.nameservers = [resolver]
        res.use_edns(0, dns.flags.DO, 4096)  # request DNSSEC records

        start = time.monotonic()
        try:
            answer = res.resolve(name, record_type)
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
        except dns.resolver.NoAnswer:
            elapsed = (time.monotonic() - start) * 1000
            return DNSLookupResult(
                query_name=name,
                query_type=record_type,
                resolver=resolver,
                records=[],
                dnssec=DNSSECStatus(enabled=False, valid=None, detail=f"No {record_type} records found"),
                response_time_ms=round(elapsed, 2),
            )
        elapsed = (time.monotonic() - start) * 1000

        records = []
        for rdata in answer:
            records.append(
                DNSRecord(
                    name=str(answer.qname),
                    record_type=record_type,
                    ttl=answer.ttl,
                    value=str(rdata),
                )
            )

        dnssec_status = _check_dnssec(name, record_type, resolver)

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

        Walks the delegation chain showing each zone's nameservers and
        DNSSEC signing status. Identifies where DNSSEC breaks if the
        chain is incomplete. Useful for diagnosing delegation and DNSSEC
        deployment issues.
        """
        record_type = record_type.upper()
        target = dns.name.from_text(name)
        labels = str(target).rstrip(".").split(".")

        # Build zones to check: root -> tld -> domain -> subdomain...
        zones = ["."]
        for i in range(len(labels)):
            zone = ".".join(labels[-(i + 1) :]) + "."
            zones.append(zone)

        chain: list[DelegationStep] = []
        chain_intact = True
        break_point = None

        for zone in zones:
            step = _probe_zone(zone)
            chain.append(step)
            if chain_intact and not step.dnssec_signed and zone != ".":
                # Root is always signed; if a child zone isn't, chain breaks
                if len(chain) > 1 and chain[-2].dnssec_signed:
                    chain_intact = False
                    break_point = zone.rstrip(".")

        return DNSTraceResult(
            query_name=name,
            query_type=record_type,
            delegation_chain=chain,
            dnssec_chain_intact=chain_intact,
            break_point=break_point,
        )


def _check_dnssec(name: str, record_type: str, resolver: str) -> DNSSECStatus:
    """Check DNSSEC status for a name by querying for RRSIG records."""
    try:
        qname = dns.name.from_text(name)
        request = dns.message.make_query(qname, record_type, want_dnssec=True)
        response = dns.query.udp(request, resolver, timeout=5)

        has_rrsig = False
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                has_rrsig = True
                break

        if not has_rrsig:
            return DNSSECStatus(
                enabled=False,
                valid=None,
                detail="No RRSIG records in response — DNSSEC not enabled for this name",
            )

        # Check the AD (Authenticated Data) flag from a validating resolver
        ad_flag = bool(response.flags & dns.flags.AD)
        if ad_flag:
            return DNSSECStatus(
                enabled=True,
                valid=True,
                detail="DNSSEC enabled and validated (AD flag set by resolver)",
            )
        else:
            return DNSSECStatus(
                enabled=True,
                valid=False,
                detail="DNSSEC records present but AD flag not set — validation may have failed",
            )
    except Exception as e:
        return DNSSECStatus(
            enabled=False,
            valid=None,
            detail=f"DNSSEC check failed: {e}",
        )


def _probe_zone(zone: str) -> DelegationStep:
    """Probe a zone for its NS records and DNSSEC status."""
    try:
        res = dns.resolver.Resolver()
        res.nameservers = [_default_resolver()]

        # Get NS records
        try:
            ns_answer = res.resolve(zone, "NS")
            nameservers = sorted(str(ns) for ns in ns_answer)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            nameservers = []

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

        return DelegationStep(
            zone=zone.rstrip(".") or ".",
            nameservers=nameservers,
            dnssec_signed=dnssec_signed,
            ds_records_present=ds_present,
            detail=detail,
        )
    except Exception as e:
        return DelegationStep(
            zone=zone.rstrip(".") or ".",
            nameservers=[],
            dnssec_signed=False,
            ds_records_present=False,
            detail=f"Probe failed: {e}",
        )
