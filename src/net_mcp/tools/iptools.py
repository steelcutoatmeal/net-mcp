"""IP/subnet math and bogon detection tools.

Pure computation — no external APIs. Handles IPv4 and IPv6.
"""

from __future__ import annotations

import ipaddress
from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Bogon / reserved prefix lists (from IANA + RFCs)
# ---------------------------------------------------------------------------

_BOGON_V4 = [
    ("0.0.0.0/8", "RFC 791 — This host on this network"),
    ("10.0.0.0/8", "RFC 1918 — Private use"),
    ("100.64.0.0/10", "RFC 6598 — Shared address space (CGNAT)"),
    ("127.0.0.0/8", "RFC 1122 — Loopback"),
    ("169.254.0.0/16", "RFC 3927 — Link-local"),
    ("172.16.0.0/12", "RFC 1918 — Private use"),
    ("192.0.0.0/24", "RFC 6890 — IETF protocol assignments"),
    ("192.0.2.0/24", "RFC 5737 — Documentation (TEST-NET-1)"),
    ("192.88.99.0/24", "RFC 7526 — Deprecated 6to4 relay anycast"),
    ("192.168.0.0/16", "RFC 1918 — Private use"),
    ("198.18.0.0/15", "RFC 2544 — Benchmarking"),
    ("198.51.100.0/24", "RFC 5737 — Documentation (TEST-NET-2)"),
    ("203.0.113.0/24", "RFC 5737 — Documentation (TEST-NET-3)"),
    ("224.0.0.0/4", "RFC 5771 — Multicast"),
    ("240.0.0.0/4", "RFC 1112 — Reserved for future use"),
    ("255.255.255.255/32", "RFC 919 — Limited broadcast"),
]

_BOGON_V6 = [
    ("::/128", "RFC 4291 — Unspecified address"),
    ("::1/128", "RFC 4291 — Loopback"),
    ("::ffff:0:0/96", "RFC 4291 — IPv4-mapped"),
    ("64:ff9b::/96", "RFC 6052 — IPv4/IPv6 translation"),
    ("64:ff9b:1::/48", "RFC 8215 — IPv4/IPv6 translation"),
    ("100::/64", "RFC 6666 — Discard-only prefix"),
    ("2001::/23", "RFC 2928 — IETF protocol assignments"),
    ("2001::/32", "RFC 4380 — Teredo"),
    ("2001:2::/48", "RFC 5180 — Benchmarking"),
    ("2001:db8::/32", "RFC 3849 — Documentation"),
    ("2001:10::/28", "RFC 4843 — ORCHID"),
    ("2002::/16", "RFC 7526 — Deprecated 6to4"),
    ("fc00::/7", "RFC 4193 — Unique local (ULA)"),
    ("fe80::/10", "RFC 4291 — Link-local"),
    ("ff00::/8", "RFC 4291 — Multicast"),
]

# Pre-parse for fast lookups
_BOGON_NETS_V4 = [(ipaddress.ip_network(p), desc) for p, desc in _BOGON_V4]
_BOGON_NETS_V6 = [(ipaddress.ip_network(p), desc) for p, desc in _BOGON_V6]


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class SubnetInfo(BaseModel):
    prefix: str
    network_address: str
    broadcast_address: str
    netmask: str
    hostmask: str
    prefix_length: int
    total_addresses: int
    usable_hosts: int
    ip_version: int
    is_private: bool
    is_global: bool
    is_multicast: bool
    is_loopback: bool
    is_link_local: bool


class SubnetSplitResult(BaseModel):
    original: str
    new_prefix_length: int
    subnets: list[str]
    total: int


class ContainsResult(BaseModel):
    address: str
    network: str
    contains: bool
    detail: str


class OverlapResult(BaseModel):
    prefix_a: str
    prefix_b: str
    overlaps: bool
    relationship: str = Field(
        description="'disjoint', 'a_contains_b', 'b_contains_a', or 'equal'"
    )


class SupernetResult(BaseModel):
    prefixes: list[str]
    supernet: str | None
    aggregatable: bool
    detail: str


class BogonCheckResult(BaseModel):
    query: str
    is_bogon: bool
    matches: list[str] = Field(description="Matching reserved ranges with RFC references")
    detail: str


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_iptools(mcp: FastMCP) -> None:

    @mcp.tool(tags={"ip", "subnet"})
    def subnet_info(
        prefix: Annotated[
            str,
            Field(description="IP prefix in CIDR (e.g. '10.0.0.0/24') or single IP (e.g. '1.1.1.1')"),
        ],
    ) -> SubnetInfo:
        """Get detailed information about an IP prefix or address.

        Returns network/broadcast addresses, netmask, host count,
        and classification (private, global, multicast, etc.).
        Works with both IPv4 and IPv6.
        """
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            # Single IP — wrap as /32 or /128
            addr = ipaddress.ip_address(prefix)
            pfx_len = 32 if addr.version == 4 else 128
            net = ipaddress.ip_network(f"{addr}/{pfx_len}")

        if net.version == 4:
            usable = max(0, net.num_addresses - 2) if net.prefixlen < 31 else net.num_addresses
        else:
            usable = net.num_addresses

        return SubnetInfo(
            prefix=str(net),
            network_address=str(net.network_address),
            broadcast_address=str(net.broadcast_address),
            netmask=str(net.netmask),
            hostmask=str(net.hostmask),
            prefix_length=net.prefixlen,
            total_addresses=net.num_addresses,
            usable_hosts=usable,
            ip_version=net.version,
            is_private=net.is_private,
            is_global=net.is_global,
            is_multicast=net.is_multicast,
            is_loopback=net.is_loopback,
            is_link_local=net.is_link_local,
        )

    @mcp.tool(tags={"ip", "subnet"})
    def subnet_split(
        prefix: Annotated[str, Field(description="IP prefix to split (e.g. '10.0.0.0/24')")],
        new_prefix_length: Annotated[
            int,
            Field(description="New prefix length for subnets (must be longer than current)"),
        ],
    ) -> SubnetSplitResult:
        """Split an IP prefix into smaller subnets.

        For example, split 10.0.0.0/24 into /26s to get 4 subnets.
        Works with both IPv4 and IPv6.
        """
        net = ipaddress.ip_network(prefix, strict=False)
        if new_prefix_length <= net.prefixlen:
            raise ValueError(
                f"New prefix length ({new_prefix_length}) must be longer than "
                f"current ({net.prefixlen})"
            )

        max_len = 32 if net.version == 4 else 128
        if new_prefix_length > max_len:
            raise ValueError(f"Prefix length cannot exceed {max_len} for IPv{net.version}")

        subnets = [str(s) for s in net.subnets(new_prefix=new_prefix_length)]

        # Cap output for very large splits
        total = len(subnets)
        if total > 256:
            subnets = subnets[:256]

        return SubnetSplitResult(
            original=str(net),
            new_prefix_length=new_prefix_length,
            subnets=subnets,
            total=total,
        )

    @mcp.tool(tags={"ip", "subnet"})
    def ip_contains(
        network: Annotated[str, Field(description="IP network in CIDR (e.g. '10.0.0.0/8')")],
        address: Annotated[str, Field(description="IP address or prefix to check (e.g. '10.5.5.1')")],
    ) -> ContainsResult:
        """Check if an IP address or prefix is within a network.

        Answers questions like 'is 10.5.5.1 in 10.0.0.0/8?' or
        'is 192.168.1.0/24 inside 192.168.0.0/16?'.
        """
        net = ipaddress.ip_network(network, strict=False)

        try:
            addr = ipaddress.ip_address(address)
            contained = addr in net
            detail = f"{address} {'is' if contained else 'is NOT'} within {net}"
        except ValueError:
            subnet = ipaddress.ip_network(address, strict=False)
            contained = subnet.subnet_of(net)
            detail = f"{subnet} {'is' if contained else 'is NOT'} a subnet of {net}"

        return ContainsResult(
            address=address,
            network=str(net),
            contains=contained,
            detail=detail,
        )

    @mcp.tool(tags={"ip", "subnet"})
    def prefix_overlap(
        prefix_a: Annotated[str, Field(description="First IP prefix (e.g. '10.0.0.0/24')")],
        prefix_b: Annotated[str, Field(description="Second IP prefix (e.g. '10.0.0.128/25')")],
    ) -> OverlapResult:
        """Check if two IP prefixes overlap.

        Returns the relationship: disjoint, one contains the other, or equal.
        Useful for detecting conflicts in IP allocation or routing policy.
        """
        a = ipaddress.ip_network(prefix_a, strict=False)
        b = ipaddress.ip_network(prefix_b, strict=False)

        if a == b:
            relationship = "equal"
            overlaps = True
        elif a.overlaps(b):
            overlaps = True
            if b.subnet_of(a):
                relationship = "a_contains_b"
            elif a.subnet_of(b):
                relationship = "b_contains_a"
            else:
                relationship = "partial_overlap"
        else:
            overlaps = False
            relationship = "disjoint"

        return OverlapResult(
            prefix_a=str(a),
            prefix_b=str(b),
            overlaps=overlaps,
            relationship=relationship,
        )

    @mcp.tool(tags={"ip", "subnet"})
    def supernet_aggregate(
        prefixes: Annotated[
            str,
            Field(
                description=(
                    "Comma-separated list of IP prefixes to aggregate "
                    "(e.g. '10.0.0.0/25,10.0.0.128/25')"
                )
            ),
        ],
    ) -> SupernetResult:
        """Try to aggregate a list of IP prefixes into a supernet.

        Given contiguous subnets, returns the smallest covering supernet.
        Useful for summarizing route announcements.
        """
        nets = []
        for p in prefixes.split(","):
            p = p.strip()
            if p:
                nets.append(ipaddress.ip_network(p, strict=False))

        if not nets:
            raise ValueError("No valid prefixes provided")

        collapsed = list(ipaddress.collapse_addresses(nets))

        if len(collapsed) == 1:
            return SupernetResult(
                prefixes=[str(n) for n in nets],
                supernet=str(collapsed[0]),
                aggregatable=True,
                detail=f"{len(nets)} prefix(es) aggregate to {collapsed[0]}",
            )
        else:
            return SupernetResult(
                prefixes=[str(n) for n in nets],
                supernet=None,
                aggregatable=False,
                detail=(
                    f"Cannot aggregate into a single prefix. "
                    f"Collapses to {len(collapsed)} prefixes: "
                    f"{', '.join(str(c) for c in collapsed[:10])}"
                ),
            )

    @mcp.tool(tags={"ip", "security"})
    def bogon_check(
        query: Annotated[
            str,
            Field(description="IP address or prefix to check (e.g. '192.168.1.0/24', '10.0.0.1')"),
        ],
    ) -> BogonCheckResult:
        """Check if an IP address or prefix is a bogon (reserved/non-routable).

        Tests against all IANA reserved ranges including RFC 1918 (private),
        RFC 6598 (CGNAT), RFC 5737 (documentation), multicast, loopback,
        link-local, and other special-use prefixes.

        A bogon appearing in the global routing table usually indicates
        a misconfiguration or a hijack attempt.
        """
        try:
            net = ipaddress.ip_network(query, strict=False)
        except ValueError:
            addr = ipaddress.ip_address(query)
            pfx_len = 32 if addr.version == 4 else 128
            net = ipaddress.ip_network(f"{addr}/{pfx_len}")

        bogon_list = _BOGON_NETS_V4 if net.version == 4 else _BOGON_NETS_V6
        matches = []

        for bogon_net, desc in bogon_list:
            if net.overlaps(bogon_net):
                matches.append(f"{bogon_net} — {desc}")

        is_bogon = len(matches) > 0

        if is_bogon:
            detail = f"{query} is a bogon/reserved address. Matches {len(matches)} reserved range(s)."
        else:
            detail = f"{query} is NOT a bogon. It is a globally routable {'IPv4' if net.version == 4 else 'IPv6'} prefix."

        return BogonCheckResult(
            query=query,
            is_bogon=is_bogon,
            matches=matches,
            detail=detail,
        )
