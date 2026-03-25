"""Pydantic models for net-mcp tool inputs and outputs."""

from __future__ import annotations

from pydantic import BaseModel, Field


# --- DNS Models ---


class DNSRecord(BaseModel):
    name: str
    record_type: str
    ttl: int
    value: str


class DNSSECStatus(BaseModel):
    enabled: bool = Field(description="Whether DNSSEC records are present")
    valid: bool | None = Field(
        None, description="Whether DNSSEC validation passed (None if not enabled)"
    )
    detail: str = Field(description="Human-readable DNSSEC status")


class DNSLookupResult(BaseModel):
    query_name: str
    query_type: str
    resolver: str
    records: list[DNSRecord]
    dnssec: DNSSECStatus
    response_time_ms: float


class DelegationStep(BaseModel):
    zone: str
    nameservers: list[str]
    dnssec_signed: bool
    ds_records_present: bool
    detail: str


class DNSTraceResult(BaseModel):
    query_name: str
    query_type: str
    delegation_chain: list[DelegationStep]
    dnssec_chain_intact: bool
    break_point: str | None = Field(
        None, description="Zone where DNSSEC chain breaks, if applicable"
    )


# --- RPKI Models ---


class ROA(BaseModel):
    prefix: str
    max_length: int
    asn: int
    trust_anchor: str | None = None


class RPKIValidationResult(BaseModel):
    prefix: str
    origin_asn: int
    status: str = Field(description="VALID, INVALID, or NOT_FOUND")
    matching_roas: list[ROA]
    detail: str


class ROALookupResult(BaseModel):
    query: str = Field(description="The prefix or ASN that was queried")
    roas: list[ROA]
    total: int


# --- Route Collector Models ---


class CollectorPeerSummary(BaseModel):
    total_peers: int
    full_feed_v4: int
    full_feed_v6: int
    unique_asns: int


class RouteCollector(BaseModel):
    id: str = Field(description="Collector ID (e.g. 'RRC00')")
    name: str = Field(description="Collector name")
    location: str = Field(description="Geographic location")
    type: str = Field(description="'multihop' or 'IXP'")
    active: bool
    activated_on: str
    peers: CollectorPeerSummary


class RouteCollectorResult(BaseModel):
    collectors: list[RouteCollector]
    total: int
    active: int
    tip: str = Field(
        description="Guidance on which collectors to use for common scenarios"
    )


# --- MRT / Historical Models ---


class MRTFile(BaseModel):
    url: str
    collector: str
    data_type: str = Field(description="'rib' or 'update'")
    timestamp_start: str
    timestamp_end: str
    size_bytes: int


class MRTSearchResult(BaseModel):
    query_start: str
    query_end: str
    collector: str | None
    data_type: str
    files: list[MRTFile]
    total: int
    tip: str = Field(description="Guidance on how to use these files")


class HistoricalBGPEntry(BaseModel):
    prefix: str
    origin_asn: int
    as_path: list[int]
    communities: list[str]
    peer_asn: int
    peer_ip: str
    timestamp: str
    elem_type: str = Field(description="'A' (announce) or 'W' (withdraw)")
    collector: str
    next_hop: str | None = None


class HistoricalBGPResult(BaseModel):
    prefix: str
    time_start: str
    time_end: str
    collector: str
    data_type: str
    entries: list[HistoricalBGPEntry]
    total: int
    mrt_file: str = Field(description="MRT file URL that was parsed")
    source: str


# --- BGP Models ---


class BGPRoute(BaseModel):
    prefix: str
    origin_asn: int
    as_path: list[int]
    communities: list[str]
    peer_asn: int
    peer_ip: str
    timestamp: str
    collector: str


class BGPRouteLookupResult(BaseModel):
    prefix: str
    routes: list[BGPRoute]
    total: int
    source: str = Field(description="Data source (e.g. RouteViews, RIPE RIS)")


class PrefixOrigin(BaseModel):
    prefix: str
    origin_asn: int
    as_name: str | None = None
    rpki_status: str | None = None
    first_seen: str | None = None


class PrefixOriginResult(BaseModel):
    query_prefix: str
    origins: list[PrefixOrigin]


class ASNInfo(BaseModel):
    asn: int
    name: str | None = None
    prefixes_v4: list[str]
    prefixes_v6: list[str]
    upstream_asns: list[int]
    total_prefixes: int


# --- BGP Hijack / Leak Models ---


class BGPHijackEvent(BaseModel):
    id: int
    confidence_score: float
    hijacker_asn: int
    victim_asns: list[int]
    prefixes: list[str]
    hijacker_country: str | None = None
    victim_countries: list[str] = []
    duration: int = Field(description="Duration in seconds")
    is_ongoing: bool = False
    detected_at: str = ""
    last_seen: str = ""
    peer_count: int = 0
    tags: list[str] = []


class BGPHijackResult(BaseModel):
    events: list[BGPHijackEvent]
    total: int
    source: str


class BGPLeakEvent(BaseModel):
    id: int
    leak_asn: int
    leak_segment: list[int] = []
    leak_type: int
    origin_count: int
    prefix_count: int
    peer_count: int
    countries: list[str] = []
    detected_at: str = ""
    last_seen: str = ""
    finished: bool = False


class BGPLeakResult(BaseModel):
    events: list[BGPLeakEvent]
    total: int
    source: str
