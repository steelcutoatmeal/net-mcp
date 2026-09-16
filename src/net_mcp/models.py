"""Pydantic models shared by the DNS, RPKI, and BGP tool modules.

Every tool returns a model; FastMCP turns it into the tool's output schema, so
field descriptions are read by the LLM. IRR, PeeringDB, iptools, and local
tools keep their (module-specific) models next to the tool code.

Error contract: result models that depend on an upstream API carry
``error: str | None``. It is set when the lookup failed, so an empty result
can be distinguished from "the source answered and there is nothing".
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

_ERROR_DESC = (
    "Set when an upstream lookup failed; other fields may be empty or partial."
)
_SOURCE_DESC = "Which data source produced this result"


# --- DNS Models ---


class DNSRecord(BaseModel):
    name: str = Field(description="Owner name the record belongs to")
    record_type: str = Field(description="Record type (A, AAAA, MX, ...)")
    ttl: int = Field(description="Time to live in seconds")
    value: str = Field(description="Record data in presentation format")


class DNSSECStatus(BaseModel):
    enabled: bool = Field(description="Whether DNSSEC records are present")
    valid: bool | None = Field(
        None, description="Whether DNSSEC validation passed (None if not enabled)"
    )
    detail: str = Field(description="Human-readable DNSSEC status")


class DNSLookupResult(BaseModel):
    query_name: str = Field(description="Name that was queried")
    query_type: str = Field(description="Record type that was queried")
    resolver: str = Field(description="Resolver IP the query was sent to")
    records: list[DNSRecord] = Field(description="Answer records (empty if none)")
    dnssec: DNSSECStatus = Field(description="DNSSEC status of the answer")
    response_time_ms: float = Field(description="Round-trip time in milliseconds")


class DelegationStep(BaseModel):
    zone: str = Field(description="Zone name ('.' for the root)")
    nameservers: list[str] = Field(description="Authoritative nameservers for the zone")
    dnssec_signed: bool = Field(description="Zone publishes a DNSKEY (is signed)")
    ds_records_present: bool = Field(
        description="Parent publishes a DS record for this zone"
    )
    detail: str = Field(description="Human-readable summary of this step")


class DNSTraceResult(BaseModel):
    query_name: str = Field(description="Name that was traced")
    delegation_chain: list[DelegationStep] = Field(
        description="Zone cuts from the root down to the queried name"
    )
    dnssec_chain_intact: bool = Field(
        description="False if a signed zone has no DS in its parent (chain of trust broken)"
    )
    break_point: str | None = Field(
        None, description="Zone where DNSSEC chain breaks, if applicable"
    )


# --- RPKI Models ---


class ROA(BaseModel):
    prefix: str = Field(description="Prefix covered by the ROA")
    max_length: int = Field(description="Longest prefix length the ROA authorises")
    asn: int = Field(description="Origin AS authorised by the ROA")
    trust_anchor: str | None = Field(
        None, description="RIR trust anchor (e.g. 'RIPE', 'ARIN')"
    )


RPKIStatus = Literal["VALID", "INVALID", "NOT_FOUND", "ERROR"]


class RPKIValidationResult(BaseModel):
    prefix: str = Field(description="Prefix that was validated")
    origin_asn: int = Field(description="Origin AS that was validated")
    status: RPKIStatus = Field(
        description="VALID, INVALID, NOT_FOUND (no covering ROA), or ERROR (all sources failed)"
    )
    matching_roas: list[ROA] = Field(
        description="ROAs covering the prefix (may be empty)"
    )
    detail: str = Field(description="Human-readable explanation of the status")


class ROALookupResult(BaseModel):
    query: str = Field(description="The prefix or ASN that was queried")
    roas: list[ROA] = Field(description="Matching ROAs")
    total: int = Field(description="Number of ROAs returned")
    note: str = Field(
        default="", description="Set when results were truncated or partial"
    )
    error: str | None = Field(default=None, description=_ERROR_DESC)


# --- ASPA Models ---


class ASPAObject(BaseModel):
    customer_asn: int = Field(description="The customer AS that created this ASPA")
    providers: list[int] = Field(description="Authorized upstream provider ASNs")
    customer_name: str | None = Field(None, description="Customer AS name, if known")
    customer_country: str | None = Field(None, description="Customer AS country code")


class ASPASnapshotResult(BaseModel):
    objects: list[ASPAObject] = Field(
        description="ASPA objects (may be truncated; see total)"
    )
    total: int = Field(
        description="Total matching objects, even if the list is truncated"
    )
    data_time: str = Field(default="", description="Timestamp of the snapshot")
    source: str = Field(description=_SOURCE_DESC)
    error: str | None = Field(default=None, description=_ERROR_DESC)


class ASPAChange(BaseModel):
    date: str = Field(description="Date of the change (YYYY-MM-DD)")
    customer_asn: int = Field(description="Customer AS whose ASPA changed")
    providers: list[int] = Field(description="Provider ASNs after the change")
    change_type: str = Field(description="'added', 'removed', or 'modified'")


class ASPAChangesResult(BaseModel):
    changes: list[ASPAChange] = Field(description="ASPA changes in the window")
    total: int = Field(description="Number of changes returned")
    date_start: str = Field(default="", description="Start of the queried window")
    date_end: str = Field(default="", description="End of the queried window")
    source: str = Field(description=_SOURCE_DESC)
    error: str | None = Field(default=None, description=_ERROR_DESC)


# --- Route Collector Models ---


class CollectorPeerSummary(BaseModel):
    total_peers: int = Field(description="Number of BGP peers feeding the collector")
    full_feed_v4: int = Field(description="Peers sending a full IPv4 table")
    full_feed_v6: int = Field(description="Peers sending a full IPv6 table")
    unique_asns: int = Field(description="Distinct peer ASNs")


class RouteCollector(BaseModel):
    id: str = Field(description="Collector ID (e.g. 'RRC00')")
    name: str = Field(description="Collector name")
    location: str = Field(description="Geographic location")
    type: str = Field(description="'multihop' or 'IXP'")
    active: bool = Field(description="Whether the collector is currently active")
    activated_on: str = Field(description="Date the collector went live")
    peers: CollectorPeerSummary = Field(description="Peer feed summary")


class RouteCollectorResult(BaseModel):
    collectors: list[RouteCollector] = Field(description="Matching collectors")
    total: int = Field(description="Number of collectors returned")
    active: int = Field(description="How many of them are active")
    tip: str = Field(
        default="",
        description="Guidance on which collectors to use for common scenarios",
    )
    error: str | None = Field(default=None, description=_ERROR_DESC)


# --- MRT / Historical Models ---


class MRTFile(BaseModel):
    url: str = Field(description="Download URL of the MRT file")
    collector: str = Field(description="Collector that produced the file")
    data_type: str = Field(description="'rib' or 'update'")
    timestamp_start: str = Field(description="Start of the period the file covers")
    timestamp_end: str = Field(description="End of the period the file covers")
    size_bytes: int = Field(description="Approximate file size in bytes")


class MRTSearchResult(BaseModel):
    query_start: str = Field(description="Start of the searched window")
    query_end: str = Field(description="End of the searched window")
    collector: str = Field(description="Collector that was searched")
    data_type: str = Field(description="'rib' or 'update'")
    files: list[MRTFile] = Field(
        description="Matching files (may be truncated; see total)"
    )
    total: int = Field(
        description="Total files in the window, even if the list is truncated"
    )
    tip: str = Field(default="", description="Guidance on how to use these files")
    error: str | None = Field(default=None, description=_ERROR_DESC)


class HistoricalBGPEntry(BaseModel):
    prefix: str = Field(description="Prefix in the MRT record")
    origin_asn: int = Field(description="Origin AS (last hop of the AS path)")
    as_path: list[int] = Field(description="AS path, peer first, origin last")
    communities: list[str] = Field(description="BGP communities as 'asn:value' strings")
    peer_asn: int = Field(description="Collector peer that received the route")
    peer_ip: str = Field(description="IP of the collector peer")
    timestamp: str = Field(description="Record time (ISO 8601, UTC)")
    elem_type: str = Field(description="'A' (announce) or 'W' (withdraw)")
    collector: str = Field(description="Collector the record came from")
    next_hop: str | None = Field(None, description="BGP next hop, if present")


class HistoricalBGPResult(BaseModel):
    prefix: str = Field(description="Prefix that was queried")
    time_start: str = Field(description="Start of the queried window")
    time_end: str = Field(description="End of the queried window")
    collector: str = Field(description="Collector that was queried")
    data_type: str = Field(description="'rib' or 'update'")
    entries: list[HistoricalBGPEntry] = Field(
        description="Matching records (capped by max_results)"
    )
    total: int = Field(description="Number of entries returned")
    mrt_file: str = Field(
        default="", description="MRT file URL that was parsed, or a file count"
    )
    source: str = Field(description=_SOURCE_DESC)
    error: str | None = Field(default=None, description=_ERROR_DESC)


# --- BGP Models ---


class BGPRoute(BaseModel):
    prefix: str = Field(description="Announced prefix")
    origin_asn: int = Field(description="Origin AS (last hop of the AS path)")
    as_path: list[int] = Field(description="AS path, peer first, origin last")
    communities: list[str] = Field(description="BGP communities as 'asn:value' strings")
    peer_asn: int = Field(
        description="Collector peer (first hop); 0 if the source does not report it"
    )
    peer_ip: str = Field(description="IP of the collector peer, if known")
    timestamp: str = Field(description="When the route was last seen, if known")
    collector: str = Field(
        description="Collector or vantage point that observed the route"
    )


class BGPRouteLookupResult(BaseModel):
    prefix: str = Field(description="Prefix that was queried")
    routes: list[BGPRoute] = Field(description="Observed routes (capped; see total)")
    total: int = Field(
        description="Total routes observed, even if the list is truncated"
    )
    source: str = Field(description=_SOURCE_DESC)
    error: str | None = Field(default=None, description=_ERROR_DESC)


class PrefixOrigin(BaseModel):
    prefix: str = Field(description="Announced prefix (may be a covering prefix)")
    origin_asn: int = Field(description="Origin AS number")
    as_name: str | None = Field(None, description="AS holder name, if resolvable")
    rpki_status: str | None = Field(
        None,
        description="RPKI status of this origin; only populated by Cloudflare Radar",
    )
    first_seen: str | None = Field(None, description="First observation time, if known")


class PrefixOriginResult(BaseModel):
    query_prefix: str = Field(description="Prefix that was queried")
    origins: list[PrefixOrigin] = Field(description="Distinct origin ASes")
    source: str = Field(default="", description=_SOURCE_DESC)
    error: str | None = Field(default=None, description=_ERROR_DESC)


class ASNInfo(BaseModel):
    asn: int = Field(description="AS number")
    name: str | None = Field(None, description="AS holder name, if resolvable")
    prefixes_v4: list[str] = Field(
        description="Announced IPv4 prefixes (may be truncated; see total_prefixes and note)"
    )
    prefixes_v6: list[str] = Field(
        description="Announced IPv6 prefixes (may be truncated; see total_prefixes and note)"
    )
    upstream_asns: list[int] = Field(description="Transit providers (upstream ASNs)")
    total_prefixes: int = Field(
        description="Total announced prefix count (v4+v6), even if the lists above are truncated"
    )
    note: str = Field(
        default="",
        description="Set when the prefix lists were truncated to limit response size",
    )
    error: str | None = Field(default=None, description=_ERROR_DESC)


# --- BGP Hijack / Leak Models ---


class BGPHijackEvent(BaseModel):
    id: int = Field(description="Cloudflare Radar event ID")
    confidence_score: float = Field(description="Detection confidence, 0-100")
    hijacker_asn: int = Field(
        description="AS that announced the prefix without authorisation"
    )
    victim_asns: list[int] = Field(description="Legitimate origin ASes")
    prefixes: list[str] = Field(description="Affected prefixes")
    hijacker_country: str | None = Field(
        None, description="Country code of the hijacker AS"
    )
    victim_countries: list[str] = Field(
        default_factory=list, description="Country codes of victim ASes"
    )
    duration: int = Field(description="Duration in seconds")
    is_ongoing: bool = Field(
        default=False, description="Whether the event is still active"
    )
    detected_at: str = Field(default="", description="First detection time")
    last_seen: str = Field(default="", description="Most recent observation time")
    peer_count: int = Field(
        default=0, description="Number of vantage points that saw the hijack"
    )
    tags: list[str] = Field(
        default_factory=list, description="Cloudflare classification tags"
    )


class BGPHijackResult(BaseModel):
    events: list[BGPHijackEvent] = Field(description="Matching events (newest first)")
    total: int = Field(
        description="Total matching events, even if the list is truncated"
    )
    source: str = Field(description=_SOURCE_DESC)
    error: str | None = Field(default=None, description=_ERROR_DESC)


class BGPLeakEvent(BaseModel):
    id: int = Field(description="Cloudflare Radar event ID")
    leak_asn: int = Field(description="AS that leaked the routes")
    leak_segment: list[int] = Field(
        default_factory=list,
        description="AS path segment around the leak (prev, leaker, next)",
    )
    leak_type: int = Field(
        description="Leak type code as classified by Cloudflare Radar (RFC 7908 taxonomy)"
    )
    origin_count: int = Field(description="Number of distinct origin ASes affected")
    prefix_count: int = Field(description="Number of prefixes affected")
    peer_count: int = Field(description="Number of vantage points that saw the leak")
    countries: list[str] = Field(
        default_factory=list, description="Country codes involved"
    )
    detected_at: str = Field(default="", description="First detection time")
    last_seen: str = Field(default="", description="Most recent observation time")
    finished: bool = Field(default=False, description="Whether the leak has ended")


class BGPLeakResult(BaseModel):
    events: list[BGPLeakEvent] = Field(description="Matching events (newest first)")
    total: int = Field(
        description="Total matching events, even if the list is truncated"
    )
    source: str = Field(description=_SOURCE_DESC)
    error: str | None = Field(default=None, description=_ERROR_DESC)
