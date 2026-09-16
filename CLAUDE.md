# CLAUDE.md

net-mcp is a FastMCP server that gives LLMs structured access to network engineering data: BGP, RPKI/ASPA, DNS/DNSSEC, IRR, PeeringDB, IP math, and local diagnostics.

## Commands

```bash
uv sync --group dev       # install (dev group includes pytest + ruff)
uv run pytest -q          # tests are fully offline; ~1s
uv run ruff check src tests && uv run ruff format src tests
uv run net-mcp            # run the server on stdio
```

Poke a tool in-process (this is also how the tests call tools):

```python
import asyncio
from net_mcp.server import mcp

async def main():
    res = await mcp.call_tool("bgp_prefix_origin", {"prefix": "1.1.1.0/24"})
    print(res.structured_content)

asyncio.run(main())
```

`.mcp.json` registers the server for Claude Code sessions opened in this repo.

## Architecture

- `server.py` creates `FastMCP("net-mcp")` and calls each module's `register_<domain>_tools(mcp)`. Register a new module there.
- `tools/<domain>.py` defines tools inside that register function with `@mcp.tool(tags={...})`; private helpers are `_`-prefixed and live at module level so tests can monkeypatch them.
- `models.py` holds the DNS/RPKI/BGP result models. IRR, PeeringDB, iptools, and local keep their models in their own module. Both are fine; do not move them for consistency's sake.
- `__init__.py` holds the shared HTTP layer: `get_http_client()` (one pooled `httpx.Client`, sets `User-Agent`), `ripestat_get()`, `cloudflare_get()`, `cloudflare_unavailable_reason()`.
- `config.py` is a singleton via `get_config()`. Precedence: `NET_MCP_*` env vars, then `config.toml`, then defaults. `config.toml` is gitignored (it may hold API tokens); `config.example.toml` is the documented template.

## Conventions you cannot infer from one file

**Tools are sync `def` on purpose.** FastMCP runs sync tools in a thread pool, so blocking `httpx`, `socket`, `subprocess`, dnspython, and `bgpkit` calls are correct. Do not make a tool `async def` unless every I/O call inside it is also async, or it will block the whole server.

**Error contract.** Never let an upstream failure look like an empty result.
- Upstream API/network failure: return the normal model with `error` set (every API-backed result model has `error: str | None`). Keep `source` as the source name, never an error string.
- Invalid input: `raise ToolError("what valid input looks like")` from `fastmcp.exceptions`.
- `local.py` tools return `CommandResult(success=False, error=...)` for both cases.
- Every fallback `except` logs via the module `logger` (`logging.getLogger(__name__)`). Logging goes to stderr; stdout is the MCP transport.

**HTTP helper asymmetry.** `ripestat_get()` raises on failure; `cloudflare_get()` returns `None` when no token is configured or the request fails. Wrap RIPEstat calls in try/except inside fallback chains; test Cloudflare results for `None`.

**Data source order is per tool, and the tool docstring must state it.** The usual order is RIPEstat, then Cloudflare Radar (token), then bgproutes.io (key), then bgp.tools. Exceptions: `bgp_prefix_origin` queries Cloudflare first (it carries RPKI status); the bgp.tools full table is only fetched when RIPEstat itself failed, not when the prefix is simply unrouted; ASPA and hijack/leak tools are Cloudflare-only.

**Output caps.** Any list that can be large is capped (`_ROUTE_CAP`, `_ASN_PREFIX_CAP`, `_MRT_FILE_CAP`, `_ASPA_OBJECT_CAP`, IRR 200 objects) and the model reports the true count in `total` and explains truncation in `note` or `tip`. Keep that pattern for new tools and mention the cap in the docstring.

**Docstrings and `Field(description=...)` are the LLM's only documentation.** Every tool parameter and every model field needs a description. Tool docstrings say what the tool returns, when to use it over a sibling tool, which sources it uses in what order, and any cap.

**`local.py` security rules.** `subprocess.run()` with a list argv and a timeout, never `shell=True`. Every user-supplied host, name, target, URL, or port spec goes through a validator (`_validate_host`, `_validate_nmap_target`, `_validate_port_spec`, or the dig/curl-specific ones) before it touches argv; a leading `-` is always rejected so input can never become a flag. Validators raise `ValueError` internally and the tool converts that to `CommandResult(success=False, returncode=2, error=...)`. `local_nmap` and `local_curl` stay behind `allow_active_local_tools` (off by default); they deliberately do not block private or metadata addresses, and the docstring says so.

**IRR uses raw whois over TCP 43**, not HTTP; queries are validated (no CR/LF, no leading `-`) and responses are size-capped.

**bgp.tools etiquette.** `asns.csv` is cached in memory for the process lifetime and `table.jsonl` on disk with a 30-minute TTL; do not add call paths that fetch either more often.

**MRT cache.** Files land under `mrt_cache_dir/<collector>/<yyyy.mm>/`, are written atomically (`.part` then rename) because tools run concurrently, and are evicted oldest-first past `mrt_max_cache_gb`.

## Adding a tool

1. Define the result model (with descriptions and `error` if API-backed).
2. Add the tool inside `register_<domain>_tools` with `@mcp.tool(tags={...})`, `Annotated[..., Field(description=...)]` params, and a docstring per the rules above.
3. Put backend calls in `_`-prefixed module-level helpers so tests can monkeypatch them.
4. Add an offline test in `tests/test_<domain>.py`: monkeypatch `ripestat_get`/`cloudflare_get`/the helper on the tool module (they are imported by name, so patch `net_mcp.tools.<domain>.ripestat_get`), then `await mcp.call_tool(...)` and assert on `structured_content`.
5. `tests/test_server.py` will fail if the tool lacks tags, a description, an output schema, or a parameter description.
6. Run `uv run ruff check --fix` and `uv run ruff format` before committing; CI runs both plus pytest on 3.10/3.12/3.14.
