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

        Queries RIPEstat (returns ROA details) and Cloudflare Radar
        (faster, includes RPKI status). Uses whichever responds first.
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
                # ASN query — get announced prefixes first, then check ROAs
                pfx_data = ripestat_get(
                    "announced-prefixes/data.json",
                    params={"resource": f"AS{query}"},
                    timeout=HTTP_TIMEOUT,
                ).get("data", {})
                prefixes_list = pfx_data.get("prefixes", [])

                all_roas = []
                for pfx_entry in prefixes_list[:50]:
                    pfx = pfx_entry.get("prefix", "")
                    if not pfx:
                        continue
                    try:
                        d = ripestat_get(
                            "rpki-validation/data.json",
                            params={"resource": query, "prefix": pfx},
                            timeout=HTTP_TIMEOUT,
                        ).get("data", {})
                        all_roas.extend(_parse_roas(d.get("validating_roas", [])))
                    except Exception:
                        continue

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

        objects = []
        for obj in result.get("aspaObjects", []):
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
            total=meta.get("totalCount", len(objects)),
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

        status = data.get("status", "unknown").upper()
        if status not in ("VALID", "INVALID", "NOT_FOUND"):
            status = {"UNKNOWN": "NOT_FOUND"}.get(status, status)

        roas = _parse_roas(data.get("validating_roas", []))
        detail = _build_detail(status, len(roas), prefix, origin_asn)

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


def _build_detail(status: str, roa_count: int, prefix: str, origin_asn: int) -> str:
    """Build a human-readable detail string for RPKI validation."""
    if status == "VALID":
        return f"Route {prefix} from AS{origin_asn} is RPKI VALID — {roa_count} matching ROA(s)."
    elif status == "INVALID":
        return f"Route {prefix} from AS{origin_asn} is RPKI INVALID — ASN or prefix length mismatch."
    else:
        return f"No ROAs found covering {prefix} — RPKI status is NOT_FOUND."
