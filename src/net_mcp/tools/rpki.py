"""RPKI validation and ROA lookup tools."""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from net_mcp import ripestat_get
from net_mcp.models import ROA, ROALookupResult, RPKIValidationResult

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

        Use this to verify whether a route announcement is authorized by
        the prefix holder via RPKI.
        """
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
        except Exception as e:
            return RPKIValidationResult(
                prefix=prefix,
                origin_asn=origin_asn,
                status="ERROR",
                matching_roas=[],
                detail=f"RPKI validation failed: {e}",
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
