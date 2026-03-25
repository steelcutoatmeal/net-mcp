"""net-mcp: MCP server for network engineering."""

import httpx

RIPESTAT_API = "https://stat.ripe.net/data"
RIPESTAT_SOURCEAPP = "net-mcp"


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
