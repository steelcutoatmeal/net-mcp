"""net-mcp configuration.

Configuration is loaded from (in order of priority):
  1. Environment variables (NET_MCP_* prefix)
  2. Config file (config.toml)
  3. Built-in defaults

Config file locations checked (first found wins):
  1. Path in NET_MCP_CONFIG env var
  2. ./config.toml (next to pyproject.toml)
  3. ~/.config/net-mcp/config.toml
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_config: NetMCPConfig | None = None


class NetMCPConfig:
    def __init__(self) -> None:
        raw = _load_config_file()

        storage = raw.get("storage", {})
        self.mrt_cache_dir: Path = Path(
            os.environ.get(
                "NET_MCP_MRT_CACHE_DIR",
                storage.get("mrt_cache_dir", ""),
            )
            or os.path.join(tempfile.gettempdir(), "net-mcp", "mrt")
        )

        self.mrt_max_cache_gb: float = float(
            os.environ.get(
                "NET_MCP_MRT_MAX_CACHE_GB",
                storage.get("mrt_max_cache_gb", 10),
            )
        )

        api = raw.get("api", {})
        self.bgproutes_api_key: str | None = (
            os.environ.get("BGPROUTES_API_KEY")
            or api.get("bgproutes_api_key")
            or None
        )

        self.default_collector: str = (
            os.environ.get("NET_MCP_DEFAULT_COLLECTOR")
            or raw.get("bgp", {}).get("default_collector", "rrc00")
        )

        self.default_dns_resolver: str = (
            os.environ.get("NET_MCP_DNS_RESOLVER")
            or raw.get("dns", {}).get("resolver", "1.1.1.1")
        )

    def ensure_mrt_cache_dir(self) -> Path:
        """Create the MRT cache directory if it doesn't exist. Returns the path."""
        self.mrt_cache_dir.mkdir(parents=True, exist_ok=True)
        return self.mrt_cache_dir


def get_config() -> NetMCPConfig:
    """Get the singleton config instance."""
    global _config
    if _config is None:
        _config = NetMCPConfig()
    return _config


def _load_config_file() -> dict:
    """Find and load config.toml, returning empty dict if not found."""
    candidates = []

    env_path = os.environ.get("NET_MCP_CONFIG")
    if env_path:
        candidates.append(Path(env_path))

    candidates.append(Path("config.toml"))
    candidates.append(Path.home() / ".config" / "net-mcp" / "config.toml")

    for path in candidates:
        if path.is_file():
            try:
                import tomllib
            except ImportError:
                import tomli as tomllib  # type: ignore[no-redef]

            with open(path, "rb") as f:
                return tomllib.load(f)

    return {}
