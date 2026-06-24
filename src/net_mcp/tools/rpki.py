"""RPKI validation, ROA lookup, and ASPA tools.

Data sources (in priority order):
  1. RIPEstat    — Free, no key. RPKI validation with ROA details.
  2. Cloudflare  — Free with API token. RPKI status via pfx2as, ASPA data.
"""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from net_mcp import cloudflare_get, ripestat_get
from net_mcp.models import (
    ROA,
    ROALookupResult,
    RPKIValidationResult,
    ASPAChange,
    ASPAChangesResult,
    ASPAObject,
    ASPASnapshotResult,
)

HTTP_TIMEOUT = 15

# Per-prefix RPKI lookups for an ASN query are fanned out across a thread pool.
# Cap how many announced prefixes we scan and how many run concurrently so the
# tool returns within a sane wall-clock even for large ASes.
_ASN_PREFIX_SCAN_CAP = 50
_ROA_LOOKUP_WORKERS = 16
_ROA_LOOKUP_TIMEOUT = 10

# Max ASPA objects returned by rpki_aspa_lookup. An unfiltered snapshot is the
# entire dataset; the full count is still reported via `total`.
_ASPA_OBJECT_CAP = 200


def register_rpki_tools(mcp: FastMCP) -> None:
    @mcp.tool(tags={"rpki", "security"})
    def rpki_validate(
        prefix: Annotated[str, Field(description="IP prefix in CIDR notation (e.g. '1.1.1.0/24')")],
        origin_asn: Annotated[int, Field(description="Origin AS number to validate (e.g. 13335)")],
    ) -> RPKIValidationResult:
        """Validate a BGP route origin against RPKI ROAs.

        Checks whether a given prefix + origin ASN pair is VALID, INVALID,
        or NOT_FOUND in RPKI. Returns matching ROAs and details about any
        max-length issues.

        Queries RIPEstat first for full ROA details. If RIPEstat returns
        NOT_FOUND, Cloudflare Radar is consulted to confirm the status. If
        RIPEstat is unavailable entirely, falls back to Cloudflare Radar
        (status only, no ROA details).
        """
        # 1. RIPEstat — returns full ROA details
        result = _validate_ripestat(prefix, origin_asn)
        if result is not None:
            # Enrich with Cloudflare status if available
            cf_status = _validate_cloudflare(prefix, origin_asn)
            if cf_status and result.status == "NOT_FOUND" and cf_status != "NOT_FOUND":
                result.status = cf_status
                result.detail = f"Route {prefix} from AS{origin_asn} is RPKI {cf_status} (Cloudflare Radar)."
            return result

        # 2. Cloudflare Radar fallback (no ROA details, but gives status)
        cf_status = _validate_cloudflare(prefix, origin_asn)
        if cf_status:
            return RPKIValidationResult(
                prefix=prefix,
                origin_asn=origin_asn,
                status=cf_status,
                matching_roas=[],
                detail=f"Route {prefix} from AS{origin_asn} is RPKI {cf_status} (Cloudflare Radar). ROA details not available from this source.",
            )

        return RPKIValidationResult(
            prefix=prefix,
            origin_asn=origin_asn,
            status="ERROR",
            matching_roas=[],
            detail="Both RIPEstat and Cloudflare Radar failed.",
        )

    @mcp.tool(tags={"rpki", "security"})
    def rpki_roa_lookup(
        query: Annotated[
            str,
            Field(
                description=(
                    "Prefix in CIDR notation (e.g. '1.1.1.0/24') or "
                    "ASN as integer (e.g. '13335') to look up ROAs for"
                )
            ),
        ],
    ) -> ROALookupResult:
        """Look up RPKI ROAs for a prefix or ASN.

        Returns all Route Origin Authorizations matching the query,
        including max-length, trust anchor, and ASN. Useful for
        understanding what routes an AS is authorized to originate
        or what ROAs cover a given prefix.
        """
        try:
            if "/" in query:
                data = ripestat_get(
                    "rpki-validation/data.json",
                    params={"resource": 0, "prefix": query},
                    timeout=HTTP_TIMEOUT,
                ).get("data", {})
                roas = _parse_roas(data.get("validating_roas", []))
                return ROALookupResult(query=query, roas=roas, total=len(roas))
            else:
                # ASN query — get announced prefixes first, then check ROAs.
                pfx_data = ripestat_get(
                    "announced-prefixes/data.json",
                    params={"resource": f"AS{query}"},
                    timeout=HTTP_TIMEOUT,
                ).get("data", {})
                prefixes_list = pfx_data.get("prefixes", [])

                targets = [
                    p.get("prefix", "")
                    for p in prefixes_list[:_ASN_PREFIX_SCAN_CAP]
                    if p.get("prefix")
                ]

                # Run the per-prefix RPKI lookups concurrently. Done serially
                # (the previous behaviour) this is 50 × up-to-15s requests, which
                # blows past any MCP client timeout; a thread pool bounds the
                # wall-clock to a few batches.
                all_roas: list[ROA] = []
                if targets:
                    from concurrent.futures import ThreadPoolExecutor

                    with ThreadPoolExecutor(
                        max_workers=min(_ROA_LOOKUP_WORKERS, len(targets))
                    ) as pool:
                        for roas in pool.map(
                            lambda pfx: _roas_for_prefix(query, pfx), targets
                        ):
                            all_roas.extend(roas)

                # Deduplicate
                seen = set()
                unique_roas = []
                for roa in all_roas:
                    key = (roa.prefix, roa.asn, roa.max_length)
                    if key not in seen:
                        seen.add(key)
                        unique_roas.append(roa)

                return ROALookupResult(query=query, roas=unique_roas, total=len(unique_roas))

        except Exception:
            return ROALookupResult(query=query, roas=[], total=0)

    @mcp.tool(tags={"rpki", "aspa", "security"})
    def rpki_aspa_lookup(
        asn: Annotated[
            int | None,
            Field(description="Filter by customer ASN or provider ASN"),
        ] = None,
        role: Annotated[
            str,
            Field(description="'customer' to find ASPA objects where ASN is the customer, 'provider' to find where ASN is listed as a provider"),
        ] = "customer",
        date: Annotated[
            str | None,
            Field(description="Historical date in ISO 8601 (e.g. '2026-03-01'). Default is current."),
        ] = None,
    ) -> ASPASnapshotResult:
        """Look up RPKI ASPA (AS Provider Authorization) objects.

        ASPA defines which upstream providers an AS authorizes for its
        route announcements. This is a newer RPKI extension that helps
        prevent route leaks by validating AS path relationships.

        Use 'customer' role to see who an AS has authorized as providers.
        Use 'provider' role to see which ASes have authorized a given AS
        as their provider.

        Requires Cloudflare Radar API token (CLOUDFLARE_API_TOKEN).
        """
        params: dict = {}
        if asn:
            if role == "provider":
                params["providerAsn"] = asn
            else:
                params["customerAsn"] = asn
        if date:
            params["date"] = date
        params["includeAsnInfo"] = True

        data = cloudflare_get("radar/bgp/rpki/aspa/snapshot", params=params)
        if not data or not data.get("success"):
            from net_mcp.config import get_config

            if not get_config().cloudflare_api_token:
                return ASPASnapshotResult(
                    objects=[], total=0,
                    source="Cloudflare Radar API token not configured. Set CLOUDFLARE_API_TOKEN.",
                )
            return ASPASnapshotResult(
                objects=[], total=0, source="Cloudflare Radar API error",
            )

        result = data.get("result", {})
        asn_info = result.get("asnInfo", {})
        meta = result.get("meta", {})

        raw_objects = result.get("aspaObjects", [])
        objects = []
        # An unfiltered snapshot is the entire ASPA dataset (thousands of
        # objects). Cap the returned list; `total` reports the real count.
        for obj in raw_objects[:_ASPA_OBJECT_CAP]:
            customer = obj.get("customerAsn", 0)
            info = asn_info.get(str(customer), {})
            objects.append(
                ASPAObject(
                    customer_asn=customer,
                    providers=obj.get("providers", []),
                    customer_name=info.get("name"),
                    customer_country=info.get("country"),
                )
            )

        return ASPASnapshotResult(
            objects=objects,
            total=meta.get("totalCount", len(raw_objects)),
            data_time=meta.get("dataTime", ""),
            source="Cloudflare Radar",
        )

    @mcp.tool(tags={"rpki", "aspa", "security"})
    def rpki_aspa_changes(
        asn: Annotated[
            int | None,
            Field(description="Filter by ASN to see its ASPA changes"),
        ] = None,
        date_start: Annotated[
            str | None,
            Field(description="Start date in ISO 8601 (e.g. '2026-03-01')"),
        ] = None,
        date_end: Annotated[
            str | None,
            Field(description="End date in ISO 8601"),
        ] = None,
    ) -> ASPAChangesResult:
        """Track changes to RPKI ASPA objects over time.

        Shows when ASPA objects were added, removed, or modified.
        Useful for monitoring provider authorization changes and
        detecting potential routing policy shifts.

        Requires Cloudflare Radar API token (CLOUDFLARE_API_TOKEN).
        """
        params: dict = {"includeAsnInfo": True}
        if asn:
            params["asn"] = asn
        if date_start:
            params["dateStart"] = date_start
        if date_end:
            params["dateEnd"] = date_end

        data = cloudflare_get("radar/bgp/rpki/aspa/changes", params=params)
        if not data or not data.get("success"):
            from net_mcp.config import get_config

            if not get_config().cloudflare_api_token:
                return ASPAChangesResult(
                    changes=[], total=0,
                    source="Cloudflare Radar API token not configured. Set CLOUDFLARE_API_TOKEN.",
                )
            return ASPAChangesResult(
                changes=[], total=0, source="Cloudflare Radar API error",
            )

        result = data.get("result", {})
        changes = []

        for day in result.get("changes", []):
            date_str = day.get("date", "")
            for entry in day.get("entries", []):
                changes.append(
                    ASPAChange(
                        date=date_str,
                        customer_asn=entry.get("customerAsn", 0),
                        providers=entry.get("providers", []),
                        change_type=entry.get("type", "unknown"),
                    )
                )

        return ASPAChangesResult(
            changes=changes,
            total=len(changes),
            date_start=date_start or "",
            date_end=date_end or "",
            source="Cloudflare Radar",
        )


# ---------------------------------------------------------------------------
# RIPEstat backend
# ---------------------------------------------------------------------------


def _validate_ripestat(prefix: str, origin_asn: int) -> RPKIValidationResult | None:
    """Validate via RIPEstat — returns full ROA details."""
    try:
        data = ripestat_get(
            "rpki-validation/data.json",
            params={"resource": origin_asn, "prefix": prefix},
            timeout=HTTP_TIMEOUT,
        ).get("data", {})

        # RIPEstat returns granular statuses: "valid", "invalid_asn",
        # "invalid_length", "unknown". Normalize to the three documented
        # values while preserving the reason for the detail string.
        raw_status = str(data.get("status", "unknown")).lower()
        reason = None
        if raw_status == "valid":
            status = "VALID"
        elif raw_status.startswith("invalid"):
            status = "INVALID"
            if "asn" in raw_status:
                reason = "origin ASN not authorized by any covering ROA"
            elif "length" in raw_status:
                reason = "prefix length exceeds the ROA max-length"
        elif raw_status in ("unknown", "not_found", ""):
            status = "NOT_FOUND"
        else:
            status = raw_status.upper()

        roas = _parse_roas(data.get("validating_roas", []))
        detail = _build_detail(status, len(roas), prefix, origin_asn, reason)

        return RPKIValidationResult(
            prefix=prefix,
            origin_asn=origin_asn,
            status=status,
            matching_roas=roas,
            detail=detail,
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Cloudflare Radar backend
# ---------------------------------------------------------------------------


def _validate_cloudflare(prefix: str, origin_asn: int) -> str | None:
    """Validate via Cloudflare Radar pfx2as — returns status string only."""
    data = cloudflare_get(
        "radar/bgp/routes/pfx2as",
        params={"prefix": prefix, "origin": origin_asn},
    )
    if not data or not data.get("success"):
        return None

    for entry in data.get("result", {}).get("prefix_origins", []):
        if entry.get("origin") == origin_asn:
            rpki = entry.get("rpki_validation", "").upper()
            if rpki in ("VALID", "INVALID", "UNKNOWN"):
                return rpki if rpki != "UNKNOWN" else "NOT_FOUND"

    return None


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _roas_for_prefix(query: str, prefix: str) -> list[ROA]:
    """Fetch the validating ROAs for one (ASN, prefix) pair. Never raises."""
    try:
        d = ripestat_get(
            "rpki-validation/data.json",
            params={"resource": query, "prefix": prefix},
            timeout=_ROA_LOOKUP_TIMEOUT,
        ).get("data", {})
        return _parse_roas(d.get("validating_roas", []))
    except Exception:
        return []


def _parse_roas(vrps: list[dict]) -> list[ROA]:
    """Parse VRP entries from RIPEstat into ROA models."""
    roas = []
    for vrp in vrps:
        roas.append(
            ROA(
                prefix=vrp.get("prefix", ""),
                max_length=vrp.get("max_length", 0),
                asn=vrp.get("origin", 0),
                trust_anchor=vrp.get("source"),
            )
        )
    return roas


def _build_detail(
    status: str, roa_count: int, prefix: str, origin_asn: int, reason: str | None = None
) -> str:
    """Build a human-readable detail string for RPKI validation."""
    if status == "VALID":
        return f"Route {prefix} from AS{origin_asn} is RPKI VALID — {roa_count} matching ROA(s)."
    elif status == "INVALID":
        why = reason or "origin ASN or prefix length does not match a covering ROA"
        return f"Route {prefix} from AS{origin_asn} is RPKI INVALID — {why}."
    elif status == "NOT_FOUND":
        return f"No ROAs found covering {prefix} — RPKI status is NOT_FOUND."
    else:
        return f"Route {prefix} from AS{origin_asn} RPKI status: {status}."
