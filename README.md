# net-mcp

MCP server for network engineering — BGP routing analysis, RPKI validation, DNSSEC-aware DNS, and historical route data from MRT archives.

Gives LLMs structured access to real network state using public data sources (RIPE RIS, RIPEstat, RPKI repositories, bgp.tools, bgproutes.io).

## Example Queries

Once connected as an MCP server, an LLM can answer questions like:

- "Is 1.1.1.0/24 RPKI valid?" → `rpki_validate`
- "Who originates 8.8.8.0/24?" → `bgp_prefix_origin`
- "What does Cloudflare's AS footprint look like?" → `bgp_asn_info(13335)`
- "Is cloudflare.com DNSSEC signed?" → `dns_lookup` or `dns_trace`
- "Show me routes to 1.1.1.0/24 from Tokyo" → `ris_collectors(region='asia')` then `bgp_route_lookup(prefix, collector='RRC06')`
- "What did routing look like for 8.8.8.0/24 two days ago?" → `mrt_search` then `bgp_historical_lookup`
- "What route objects does AS13335 have in IRR?" → `irr_route_lookup`
- "Where does Cloudflare peer?" → `peeringdb_network(13335)`
- "What ASes are at AMS-IX?" → `peeringdb_ix("AMS-IX", include_members=True)`
- "Split 10.0.0.0/24 into /26s" → `subnet_split`
- "Is 192.168.1.1 a bogon?" → `bogon_check`
- "Do these two prefixes overlap?" → `prefix_overlap`
- "Ping 1.1.1.1 from my machine" → `local_ping`
- "What's my public IP?" → `local_public_ip`
- "Trace the path to 8.8.8.8" → `local_traceroute`
- "What ports are open on 192.168.1.1?" → `local_nmap`
- "Show my routing table" → `local_routes`

## Tools

### DNS

| Tool | Description |
|------|-------------|
| `dns_lookup` | Query DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV, CAA) with DNSSEC validation status |
| `dns_trace` | Trace delegation chain from root to authoritative, showing DNSSEC signing status at each zone level |

### RPKI & ASPA

| Tool | Description |
|------|-------------|
| `rpki_validate` | Validate a prefix + origin ASN pair against RPKI ROAs. Queries RIPEstat (ROA details) and Cloudflare Radar (status cross-check) |
| `rpki_roa_lookup` | Look up all ROAs for a given prefix or ASN, including max-length and trust anchor |
| `rpki_aspa_lookup` | Look up ASPA objects — which upstream providers an AS has authorized (Cloudflare Radar) |
| `rpki_aspa_changes` | Track ASPA object changes over time — additions, removals, modifications (Cloudflare Radar) |

### BGP — Live

| Tool | Description |
|------|-------------|
| `bgp_route_lookup` | Look up current BGP routes for a prefix. Optionally filter by RIPE RIS collector for regional perspective |
| `bgp_prefix_origin` | Find which AS(es) originate a prefix, with AS name enrichment |
| `bgp_asn_info` | Get AS name, all announced prefixes (v4/v6), upstream providers, and total prefix count |

### BGP — Collectors & Historical

| Tool | Description |
|------|-------------|
| `ris_collectors` | List RIPE RIS route collectors with location, peer counts, and type (IXP vs multihop). Filter by region |
| `mrt_search` | Find available MRT archive files (RIB dumps or updates) for a time range and collector |
| `bgp_historical_lookup` | Download and parse MRT files to retrieve BGP routes for a prefix at a specific point in time |

### BGP — Security (Cloudflare Radar)

| Tool | Description |
|------|-------------|
| `bgp_hijacks` | Search BGP origin hijack events with confidence scores, affected prefixes, hijacker/victim ASNs |
| `bgp_leaks` | Search BGP route leak events — improper route propagation between peers |

These tools require a Cloudflare Radar API token (`CLOUDFLARE_API_TOKEN`). Free to obtain at [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens).

### IRR (Internet Routing Registry)

| Tool | Description |
|------|-------------|
| `irr_route_lookup` | Look up route objects by prefix or origin ASN across RADB, RIPE, ARIN, and other registries |
| `irr_autnum` | Look up aut-num objects — AS name, description, import/export policies |
| `irr_as_set_expand` | Expand an AS-SET into its member ASNs (e.g. AS-CLOUDFLARE → list of ASNs) |

### PeeringDB

| Tool | Description |
|------|-------------|
| `peeringdb_network` | Look up a network by ASN — peering policy, IXP presence, port speeds, IRR as-set |
| `peeringdb_ix` | Search IXPs by name or city — location, member list, route server info |
| `peeringdb_facility` | Search data center facilities — location, network count |

### IP/Subnet Math & Bogon Detection

| Tool | Description |
|------|-------------|
| `subnet_info` | Get full details on a prefix — network/broadcast, host count, private/global classification |
| `subnet_split` | Split a prefix into smaller subnets (e.g. /24 → four /26s) |
| `ip_contains` | Check if an IP or prefix is within a network (e.g. is 10.5.5.1 in 10.0.0.0/8?) |
| `prefix_overlap` | Check if two prefixes overlap and the relationship (contains, equal, disjoint) |
| `supernet_aggregate` | Aggregate contiguous prefixes into the smallest covering supernet |
| `bogon_check` | Check if an IP/prefix is reserved space (RFC 1918, CGNAT, documentation, multicast, etc.) |

### Local Diagnostics

Tools that run standard CLI commands on the user's machine. All inputs are validated and passed as list arguments to subprocess (never `shell=True`) to prevent command injection.

| Tool | Description | Admin Required |
|------|-------------|:-:|
| `local_ping` | Ping a host with configurable count and timeout | No |
| `local_traceroute` | Trace network path to a host (UDP mode) | No |
| `local_mtr` | Combined ping + traceroute with per-hop stats | Yes (raw sockets) |
| `local_dig` | DNS lookup via dig (falls back to nslookup) | No |
| `local_interfaces` | Show network interfaces and IP addresses | No |
| `local_routes` | Show the local routing table | No |
| `local_connections` | Show active TCP/UDP connections and listening ports | No (PIDs need admin) |
| `local_arp` | Show ARP table (IP-to-MAC mappings) | No |
| `local_whois` | Whois lookup for domains, IPs, or ASNs | No |
| `local_curl` | Make HTTP requests, check headers and connectivity | No |
| `local_nmap` | TCP connect scan (port scanning, no SYN scan) | No |
| `local_netstat_stats` | Show TCP/UDP/ICMP protocol statistics | No |
| `local_public_ip` | Get the public-facing IP of the machine | No |

Tools that require admin privileges will attempt to run and return a clear error message if permission is denied. Cross-platform: macOS, Linux, and Windows.

## Data Sources

Data sources are queried in this priority order:

| Source | Auth | Used For |
|--------|------|----------|
| **RIPEstat** | None (free) | BGP looking glass, routing status, prefix origins, AS info, RPKI validation, collector metadata. Primary for most queries |
| **Cloudflare Radar** | Free API token | Real-time BGP routes, prefix-to-ASN with RPKI status, BGP hijack detection, BGP route leak detection. Primary alongside RIPEstat |
| **bgproutes.io** | API key required | RIB snapshots with RPKI ROV + ASPA validation, BGP updates, AS topology. Only used when API key is configured |
| **bgp.tools** | None (free) | ASN-to-name mappings (asns.csv, cached in-memory), full BGP table (table.jsonl, last resort) |
| **RIPE RIS MRT archive** | None (free) | Historical RIB dumps and BGP update files, accessed via BGPKIT Broker + Parser |
| **IRR databases** | None (free) | Route objects, aut-num, AS-SET expansion via whois protocol (RADB, RIPE, ARIN, APNIC, etc.) |
| **PeeringDB** | None (free) | Network peering info, IXP membership, facility data. No API key needed for read-only |
| **dnspython** | N/A (local) | All DNS queries and DNSSEC validation |

All RIPEstat requests include `sourceapp=net-mcp` per their API guidelines.

## Usage

### With Claude Code

Add to your MCP server configuration (`~/.claude/settings.json` or project `.claude/settings.json`):

```json
{
  "mcpServers": {
    "net-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/net-mcp", "net-mcp"]
    }
  }
}
```

### Standalone

```bash
uv run net-mcp
```

## Configuration

Settings are loaded from (in priority order):

1. Environment variables (`NET_MCP_*` prefix)
2. Config file (`config.toml`)
3. Built-in defaults

Config file is searched at:

1. Path in `NET_MCP_CONFIG` env var
2. `./config.toml` (next to pyproject.toml)
3. `~/.config/net-mcp/config.toml`

### config.toml

```toml
[storage]
# Directory for downloaded MRT files (RIB dumps can be ~400MB each).
# Default: system temp directory (/tmp/net-mcp/mrt)
mrt_cache_dir = "/path/to/mrt/cache"

# Maximum cache size in GB. Oldest files are removed when exceeded.
mrt_max_cache_gb = 10

[api]
# bgproutes.io API key (or set BGPROUTES_API_KEY env var)
bgproutes_api_key = "your-key-here"

[bgp]
# Default RIPE RIS collector for queries
default_collector = "rrc00"

[dns]
# Default DNS resolver
resolver = "1.1.1.1"
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NET_MCP_CONFIG` | Path to config file | (auto-detected) |
| `NET_MCP_MRT_CACHE_DIR` | MRT file download/cache directory | `/tmp/net-mcp/mrt` |
| `NET_MCP_MRT_MAX_CACHE_GB` | Max cache size before evicting old files | `10` |
| `NET_MCP_DEFAULT_COLLECTOR` | Default RIPE RIS collector ID | `rrc00` |
| `NET_MCP_DNS_RESOLVER` | Default DNS resolver IP | `1.1.1.1` |
| `CLOUDFLARE_API_TOKEN` | Cloudflare Radar API token ([get one free](https://dash.cloudflare.com/profile/api-tokens)) | (none) |
| `BGPROUTES_API_KEY` | bgproutes.io API key | (none) |

## MRT File Caching

Historical BGP lookups download MRT files from the RIPE RIS archive. These files can be large:

- **RIB dumps** (`bview`): ~400MB each, created every 8 hours (00:00, 08:00, 16:00 UTC)
- **Update files** (`updates`): ~3MB each, created every 5 minutes

Downloaded files are cached at `<mrt_cache_dir>/<collector>/<year.month>/<filename>.gz` and reused on subsequent queries. The cache is automatically pruned when it exceeds `mrt_max_cache_gb`.

## Development

```bash
git clone <repo>
cd net-mcp
uv sync --group dev
uv run pytest
```

## License

MIT
