# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

net-mcp is a FastMCP server (39 tools) that gives LLMs structured access to network engineering data: BGP routing, RPKI/ASPA validation, DNS/DNSSEC, IRR, PeeringDB, IP math, and local diagnostics.

## Commands

```bash
uv sync                  # Install dependencies
uv sync --group dev      # Install with test dependencies
uv run net-mcp           # Run the MCP server
uv run pytest            # Run tests (pytest-asyncio, auto mode)
```

Test tools interactively:
```python
import asyncio
from net_mcp.server import mcp

async def main():
    tools = await mcp.list_tools()
    result = await mcp.call_tool('tool_name', {'param': 'value'})
    print(result.structured_content)

asyncio.run(main())
```

## Architecture

**Entry point:** `src/net_mcp/server.py` — creates `FastMCP("net-mcp")`, calls `register_*_tools(mcp)` from each tool module, exposes `main()`.

**Tool modules** (`src/net_mcp/tools/`): Each module exports one `register_<domain>_tools(mcp: FastMCP)` function. Inside, tools are defined with `@mcp.tool(tags={...})` decorators. Private helper functions are prefixed with `_`. Seven modules: `bgp.py`, `dns.py`, `rpki.py`, `irr.py`, `peeringdb.py`, `iptools.py`, `local.py`.

**Models** (`src/net_mcp/models.py`): All Pydantic `BaseModel` classes for tool inputs/outputs. Every tool returns a model. Parameters use `Annotated[type, Field(description="...")]`.

**Shared API helpers** (`src/net_mcp/__init__.py`):
- `ripestat_get(path, params)` — adds `sourceapp=net-mcp` to all RIPEstat requests
- `cloudflare_get(path, params)` — adds Bearer token, returns `None` if no token configured (callers must handle graceful fallback)

**Config** (`src/net_mcp/config.py`): Singleton via `get_config()`. Loads from env vars (`NET_MCP_*`) → `config.toml` → defaults. Key settings: `mrt_cache_dir`, `cloudflare_api_token`, `bgproutes_api_key`, `default_collector`, `default_dns_resolver`, `allow_active_local_tools` (gates `local_nmap`/`local_curl`, off by default).

## Data Source Priority Pattern

Tools query multiple APIs with fallback chains. The standard order is:

1. **RIPEstat** — free, no key, always available
2. **Cloudflare Radar** — free with token, returns `None` from `cloudflare_get()` if unconfigured
3. **bgproutes.io** — requires API key, checked via `get_config().bgproutes_api_key`
4. **bgp.tools** — last resort (ASN name cache via `asns.csv`, full table via `table.jsonl`)

When adding a new data source: try it, check for `None`/empty result, fall through to next source. Never raise on API failure in a fallback chain.

## Adding a New Tool

1. Create or edit a module in `src/net_mcp/tools/`
2. Define return model in `models.py` (or inline if module-specific)
3. Add tool inside the `register_*_tools(mcp)` function with `@mcp.tool(tags={...})`
4. All parameters must use `Annotated[type, Field(description="...")]`
5. Tool docstrings are sent to the LLM — explain what it does, which data sources it queries, and when to use it
6. Register in `server.py` if it's a new module

## Key Conventions

- `bgp.py` is the largest module (1200+ lines) — contains live lookups, collector metadata, historical MRT parsing, hijack/leak detection, and all backend functions for RIPEstat/Cloudflare/bgproutes/bgp.tools
- IRR tools use raw TCP socket whois queries (port 43), not HTTP
- PeeringDB uses HTTP REST API at `peeringdb.com/api/`
- `local.py` tools run subprocess commands — always use `subprocess.run()` with list args (never `shell=True`), validate inputs with `_validate_host()`, and return `CommandResult` model
- MRT files are cached to `config.mrt_cache_dir` with automatic eviction at `mrt_max_cache_gb`
- The `_bgptools_asn_cache` in `bgp.py` is a module-level dict loaded once from `bgp.tools/asns.csv` (~120k entries)
