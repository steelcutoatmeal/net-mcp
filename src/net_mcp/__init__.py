"""net-mcp: MCP server for network engineering.

Shared HTTP plumbing lives here so every data-source backend sends the same
User-Agent, reuses one connection pool, and follows the same error contract:

- ``ripestat_get`` RAISES on HTTP/network failure. Call sites in fallback chains
  must catch and fall through.
- ``cloudflare_get`` returns ``None`` when no token is configured OR the request
  fails, so call sites can fall through without try/except.
"""

from importlib.metadata import PackageNotFoundError, version

import httpx

from net_mcp.config import get_config

try:
    __version__ = version("net-mcp")
except PackageNotFoundError:  # running from a source checkout without install
    __version__ = "0.0.0"

USER_AGENT = f"net-mcp/{__version__} (+https://github.com/steelcutoatmeal/net-mcp)"

RIPESTAT_API = "https://stat.ripe.net/data"
RIPESTAT_SOURCEAPP = "net-mcp"
CLOUDFLARE_RADAR_API = "https://api.cloudflare.com/client/v4"

DEFAULT_HTTP_TIMEOUT = 30

CLOUDFLARE_TOKEN_MISSING = (
    "Cloudflare Radar API token not configured. Set CLOUDFLARE_API_TOKEN."
)

_http_client: httpx.Client | None = None


def get_http_client() -> httpx.Client:
    """Return the process-wide HTTP client (thread-safe, pooled connections).

    Tools run in FastMCP's thread pool, so one shared ``httpx.Client`` is both
    safe and much cheaper than constructing a client per request. Pass
    ``timeout=`` per call to override the default.
    """
    global _http_client
    if _http_client is None:
        _http_client = httpx.Client(
            timeout=DEFAULT_HTTP_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            follow_redirects=True,
        )
    return _http_client


def ripestat_get(
    path: str, params: dict | None = None, timeout: int = DEFAULT_HTTP_TIMEOUT
) -> dict:
    """GET a RIPEstat data call, adding the mandatory ``sourceapp`` parameter.

    Args:
        path: API path after /data/ (e.g. "rpki-validation/data.json")
        params: Query parameters (sourceapp is added automatically)
        timeout: Request timeout in seconds

    Returns:
        Parsed JSON response as dict.

    Raises:
        httpx.HTTPError: on network failure or non-2xx status.
    """
    url = f"{RIPESTAT_API}/{path}"
    query = {"sourceapp": RIPESTAT_SOURCEAPP}
    if params:
        query.update(params)
    resp = get_http_client().get(url, params=query, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def cloudflare_get(
    path: str, params: dict | None = None, timeout: int = DEFAULT_HTTP_TIMEOUT
) -> dict | None:
    """GET a Cloudflare Radar endpoint with the configured bearer token.

    Returns ``None`` if no token is configured or the request fails, so callers
    can fall through to the next data source without a try/except.

    Args:
        path: API path after /client/v4/ (e.g. "radar/bgp/routes/pfx2as")
        params: Query parameters
        timeout: Request timeout in seconds
    """
    token = get_config().cloudflare_api_token
    if not token:
        return None

    url = f"{CLOUDFLARE_RADAR_API}/{path}"
    query = {"format": "json"}
    if params:
        query.update(params)

    try:
        resp = get_http_client().get(
            url,
            params=query,
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json()
    except (httpx.HTTPError, ValueError):  # ValueError: malformed JSON body
        return None


def cloudflare_unavailable_reason() -> str:
    """Explain why ``cloudflare_get`` returned None, for a result's ``error`` field."""
    if not get_config().cloudflare_api_token:
        return CLOUDFLARE_TOKEN_MISSING
    return "Cloudflare Radar API request failed or returned an error."
