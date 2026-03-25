"""net-mcp: MCP server for network engineering."""

from fastmcp import FastMCP

from net_mcp.tools.bgp import register_bgp_tools
from net_mcp.tools.dns import register_dns_tools
from net_mcp.tools.local import register_local_tools
from net_mcp.tools.rpki import register_rpki_tools

mcp = FastMCP(
    "net-mcp",
    instructions=(
        "Network engineering MCP server providing BGP route analysis, "
        "RPKI validation, DNSSEC-aware DNS lookups, and local network "
        "diagnostics using public data sources and local CLI tools."
    ),
)

register_dns_tools(mcp)
register_rpki_tools(mcp)
register_bgp_tools(mcp)
register_local_tools(mcp)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
