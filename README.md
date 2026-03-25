# net-mcp

MCP server for network engineering — BGP routing analysis, RPKI validation, DNSSEC-aware DNS, and historical route data from MRT archives.

Gives LLMs structured access to real network state using public data sources (RIPE RIS, RIPEstat, RPKI repositories, bgp.tools, bgproutes.io).

## Tools

### DNS

| Tool | Description |
|------|-------------|
| `dns_lookup` | Query DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV, CAA) with DNSSEC validation status |
| `dns_trace` | Trace delegation chain from root to authoritative, showing DNSSEC signing status at each zone level |

### RPKI

| Tool | Description |
|------|-------------|
| `rpki_validate` | Validate a prefix + origin ASN pair against RPKI ROAs. Returns VALID, INVALID, or NOT_FOUND with matching ROAs |
| `rpki_roa_lookup` | Look up all ROAs for a given prefix or ASN, including max-length and trust anchor |

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

## Data Sources

Data sources are queried in this priority order:

| Source | Auth | Used For |
|--------|------|----------|
| **RIPEstat** | None (free) | BGP looking glass, routing status, prefix origins, AS info, RPKI validation, collector metadata |
| **bgproutes.io** | API key required | RIB snapshots with RPKI ROV + ASPA validation, BGP updates, AS topology. Only used when API key is configured |
| **bgp.tools** | None (free) | ASN-to-name mappings (asns.csv, cached in-memory), full BGP table (table.jsonl, last resort) |
| **RIPE RIS MRT archive** | None (free) | Historical RIB dumps and BGP update files, accessed via BGPKIT Broker + Parser |
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
| `BGPROUTES_API_KEY` | bgproutes.io API key | (none) |

## MRT File Caching

Historical BGP lookups download MRT files from the RIPE RIS archive. These files can be large:

- **RIB dumps** (`bview`): ~400MB each, created every 8 hours (00:00, 08:00, 16:00 UTC)
- **Update files** (`updates`): ~3MB each, created every 5 minutes

Downloaded files are cached at `<mrt_cache_dir>/<collector>/<year.month>/<filename>.gz` and reused on subsequent queries. The cache is automatically pruned when it exceeds `mrt_max_cache_gb`.

## Example Queries

Once connected as an MCP server, an LLM can answer questions like:

- "Is 1.1.1.0/24 RPKI valid?" → `rpki_validate`
- "Who originates 8.8.8.0/24?" → `bgp_prefix_origin`
- "What does Cloudflare's AS footprint look like?" → `bgp_asn_info(13335)`
- "Is cloudflare.com DNSSEC signed?" → `dns_lookup` or `dns_trace`
- "Show me routes to 1.1.1.0/24 from Tokyo" → `ris_collectors(region='asia')` then `bgp_route_lookup(prefix, collector='RRC06')`
- "What did routing look like for 8.8.8.0/24 two days ago?" → `mrt_search` then `bgp_historical_lookup`

## Development

```bash
git clone <repo>
cd net-mcp
uv sync --group dev
uv run pytest
```

## License

MIT
