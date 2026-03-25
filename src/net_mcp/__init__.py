"""net-mcp: MCP server for network engineering."""

import httpx

RIPESTAT_API = "https://stat.ripe.net/data"
RIPESTAT_SOURCEAPP = "net-mcp"
CLOUDFLARE_RADAR_API = "https://api.cloudflare.com/client/v4"


def ripestat_get(path: str, params: dict | None = None, timeout: int = 30) -> dict:
    """Make a GET request to RIPEstat with sourceapp parameter included.

    Args:
        path: API path after /data/ (e.g. "rpki-validation/data.json")
        params: Query parameters (sourceapp is added automatically)
        timeout: Request timeout in seconds

    Returns:
        Parsed JSON response as dict.
    """
    url = f"{RIPESTAT_API}/{path}"
    query = {"sourceapp": RIPESTAT_SOURCEAPP}
    if params:
        query.update(params)
    with httpx.Client(timeout=timeout) as client:
        resp = client.get(url, params=query)
        resp.raise_for_status()
        return resp.json()


def cloudflare_get(
    path: str, params: dict | None = None, timeout: int = 30
) -> dict | None:
    """Make a GET request to Cloudflare Radar API.

    Requires CLOUDFLARE_API_TOKEN in config. Returns None if token is not
    configured or the request fails, so callers can fall back to other sources.

    Args:
        path: API path after /client/v4/ (e.g. "radar/bgp/routes/pfx2as")
        params: Query parameters
        timeout: Request timeout in seconds

    Returns:
        Parsed JSON response as dict, or None on failure/no token.
    """
    from net_mcp.config import get_config

    token = get_config().cloudflare_api_token
    if not token:
        return None

    url = f"{CLOUDFLARE_RADAR_API}/{path}"
    query = {"format": "json"}
    if params:
        query.update(params)

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(
                url,
                params=query,
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception:
        return None
