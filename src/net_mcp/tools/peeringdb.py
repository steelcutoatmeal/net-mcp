"""PeeringDB lookup tools.

Queries the free PeeringDB API for network, IXP, and facility data.
No API key required for read-only access.
"""

from __future__ import annotations

from typing import Annotated

import httpx
from fastmcp import FastMCP
from pydantic import BaseModel, Field

PEERINGDB_API = "https://www.peeringdb.com/api"
PEERINGDB_HEADERS = {"User-Agent": "net-mcp/0.1.0"}
HTTP_TIMEOUT = 15


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class PeeringExchange(BaseModel):
    ix_id: int
    ix_name: str
    ipv4: str | None = None
    ipv6: str | None = None
    speed_mbps: int = 0
    is_rs_peer: bool = False


class PeeringNetwork(BaseModel):
    asn: int
    name: str
    aka: str = ""
    website: str = ""
    irr_as_set: str = ""
    info_type: str = ""
    peering_policy: str = ""
    ipv4_prefixes: int = 0
    ipv6_prefixes: int = 0
    exchanges: list[PeeringExchange] = []


class PeeringNetworkResult(BaseModel):
    query_asn: int
    network: PeeringNetwork | None
    source: str = "PeeringDB"


class IXPMember(BaseModel):
    asn: int
    name: str
    ipv4: str | None = None
    ipv6: str | None = None
    speed_mbps: int = 0
    is_rs_peer: bool = False


class IXPInfo(BaseModel):
    ix_id: int
    name: str
    city: str = ""
    country: str = ""
    website: str = ""
    members: list[IXPMember] = []
    total_members: int = 0


class IXPResult(BaseModel):
    query: str
    exchanges: list[IXPInfo]
    total: int
    source: str = "PeeringDB"


class FacilityInfo(BaseModel):
    fac_id: int
    name: str
    city: str = ""
    country: str = ""
    website: str = ""
    networks_count: int = 0


class FacilityResult(BaseModel):
    query: str
    facilities: list[FacilityInfo]
    total: int
    source: str = "PeeringDB"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_peeringdb_tools(mcp: FastMCP) -> None:

    @mcp.tool(tags={"peeringdb", "peering"})
    def peeringdb_network(
        asn: Annotated[int, Field(description="ASN to look up (e.g. 13335)")],
    ) -> PeeringNetworkResult:
        """Look up a network in PeeringDB by ASN.

        Returns peering policy, IRR as-set, website, and all IXPs where
        the network peers (with IP addresses and port speeds). Useful for
        understanding a network's peering footprint and connectivity.
        """
        try:
            data = _pdb_get("net", params={"asn": asn, "depth": 0})
            nets = data.get("data", [])
            if not nets:
                return PeeringNetworkResult(query_asn=asn, network=None)

            net = nets[0]
            net_id = net.get("id")

            # Get peering exchange info
            exchanges = []
            if net_id:
                ix_data = _pdb_get(
                    "netixlan",
                    params={"net_id": net_id, "fields": "ix_id,name,ipaddr4,ipaddr6,speed,is_rs_peer"},
                )
                for entry in ix_data.get("data", []):
                    exchanges.append(
                        PeeringExchange(
                            ix_id=entry.get("ix_id", 0),
                            ix_name=entry.get("name", ""),
                            ipv4=entry.get("ipaddr4"),
                            ipv6=entry.get("ipaddr6"),
                            speed_mbps=entry.get("speed", 0),
                            is_rs_peer=entry.get("is_rs_peer", False),
                        )
                    )

            network = PeeringNetwork(
                asn=net.get("asn", asn),
                name=net.get("name", ""),
                aka=net.get("aka", ""),
                website=net.get("website", ""),
                irr_as_set=net.get("irr_as_set", ""),
                info_type=net.get("info_type", ""),
                peering_policy=net.get("policy_general", ""),
                ipv4_prefixes=net.get("info_prefixes4", 0),
                ipv6_prefixes=net.get("info_prefixes6", 0),
                exchanges=exchanges,
            )

            return PeeringNetworkResult(query_asn=asn, network=network)
        except Exception as e:
            return PeeringNetworkResult(query_asn=asn, network=None, source=f"PeeringDB error: {e}")

    @mcp.tool(tags={"peeringdb", "peering"})
    def peeringdb_ix(
        query: Annotated[
            str,
            Field(
                description=(
                    "IXP name or city to search (e.g. 'AMS-IX', 'Amsterdam', 'DE-CIX'). "
                    "Or an IX ID number for exact lookup."
                )
            ),
        ],
        include_members: Annotated[
            bool, Field(description="Include member list (can be large for big IXPs)")
        ] = False,
    ) -> IXPResult:
        """Search for Internet Exchange Points (IXPs) in PeeringDB.

        Returns IXP name, location, website, and optionally the full member
        list with ASN, IP addresses, and port speeds. Useful for understanding
        peering options in a region.
        """
        try:
            # Try numeric ID first
            if query.isdigit():
                data = _pdb_get("ix", params={"id": int(query)})
            else:
                # Search by name
                data = _pdb_get("ix", params={"name__contains": query})
                if not data.get("data"):
                    # Try city
                    data = _pdb_get("ix", params={"city__contains": query})

            exchanges = []
            for ix in data.get("data", [])[:20]:
                ix_id = ix.get("id", 0)

                members = []
                total_members = 0
                if include_members and ix_id:
                    member_data = _pdb_get(
                        "netixlan",
                        params={"ix_id": ix_id, "fields": "asn,name,ipaddr4,ipaddr6,speed,is_rs_peer"},
                    )
                    member_list = member_data.get("data", [])
                    total_members = len(member_list)
                    # Deduplicate by ASN, keep first entry
                    seen_asns = set()
                    for m in member_list:
                        m_asn = m.get("asn", 0)
                        if m_asn not in seen_asns:
                            seen_asns.add(m_asn)
                            members.append(
                                IXPMember(
                                    asn=m_asn,
                                    name=m.get("name", ""),
                                    ipv4=m.get("ipaddr4"),
                                    ipv6=m.get("ipaddr6"),
                                    speed_mbps=m.get("speed", 0),
                                    is_rs_peer=m.get("is_rs_peer", False),
                                )
                            )

                exchanges.append(
                    IXPInfo(
                        ix_id=ix_id,
                        name=ix.get("name", ""),
                        city=ix.get("city", ""),
                        country=ix.get("country", ""),
                        website=ix.get("website", ""),
                        members=members[:100],  # cap to prevent huge responses
                        total_members=total_members,
                    )
                )

            return IXPResult(query=query, exchanges=exchanges, total=len(exchanges))
        except Exception as e:
            return IXPResult(query=query, exchanges=[], total=0, source=f"PeeringDB error: {e}")

    @mcp.tool(tags={"peeringdb", "peering"})
    def peeringdb_facility(
        query: Annotated[
            str,
            Field(description="Facility name or city to search (e.g. 'Equinix', 'Ashburn')"),
        ],
    ) -> FacilityResult:
        """Search for data center facilities in PeeringDB.

        Returns facility name, location, and how many networks are present.
        Useful for understanding colocation options and where networks
        can physically interconnect.
        """
        try:
            data = _pdb_get("fac", params={"name__contains": query})
            if not data.get("data"):
                data = _pdb_get("fac", params={"city__contains": query})

            facilities = []
            for fac in data.get("data", [])[:30]:
                fac_id = fac.get("id", 0)

                # Count networks at this facility
                net_count = 0
                if fac_id:
                    try:
                        nf_data = _pdb_get("netfac", params={"fac_id": fac_id, "fields": "net_id"})
                        net_count = len(nf_data.get("data", []))
                    except Exception:
                        pass

                facilities.append(
                    FacilityInfo(
                        fac_id=fac_id,
                        name=fac.get("name", ""),
                        city=fac.get("city", ""),
                        country=fac.get("country", ""),
                        website=fac.get("website", ""),
                        networks_count=net_count,
                    )
                )

            return FacilityResult(query=query, facilities=facilities, total=len(facilities))
        except Exception as e:
            return FacilityResult(query=query, facilities=[], total=0, source=f"PeeringDB error: {e}")


# ---------------------------------------------------------------------------
# API helper
# ---------------------------------------------------------------------------


def _pdb_get(endpoint: str, params: dict | None = None) -> dict:
    """Query the PeeringDB API."""
    with httpx.Client(timeout=HTTP_TIMEOUT, headers=PEERINGDB_HEADERS) as client:
        resp = client.get(f"{PEERINGDB_API}/{endpoint}", params=params or {})
        resp.raise_for_status()
        return resp.json()
