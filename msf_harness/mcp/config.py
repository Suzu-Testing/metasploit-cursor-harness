"""Configuration loaded from .env file and environment variables.

Supports msfmcpd-compatible aliases (MSF_API_HOST, MSF_API_PASSWORD, etc.)
so the same .env works for both our harness and official msfmcpd.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

_ENV_ALIASES = {
    "MSF_API_HOST": "MSF_HOST",
    "MSF_API_PORT": "MSF_PORT",
    "MSF_API_USER": "MSF_USER",
    "MSF_API_PASSWORD": "MSF_PASSWORD",
    "MSF_API_SSL": "MSF_SSL",
}


def _load_dotenv() -> None:
    """Parse project-root .env into os.environ (existing vars take precedence)."""
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        os.environ.setdefault(key, value)

    for alias, canonical in _ENV_ALIASES.items():
        if alias in os.environ and canonical not in os.environ:
            os.environ[canonical] = os.environ[alias]


_load_dotenv()


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _parse_port(raw: str) -> int:
    try:
        port = int(raw)
    except (ValueError, TypeError):
        raise ValueError(f"MSF_PORT must be an integer, got: {raw!r}")
    if not (1 <= port <= 65535):
        raise ValueError(f"MSF_PORT must be 1-65535, got: {port}")
    return port


@dataclass(frozen=True)
class MsfConfig:
    host: str = field(default_factory=lambda: _env("MSF_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _parse_port(_env("MSF_PORT", "55553")))
    user: str = field(default_factory=lambda: _env("MSF_USER", "msf"))
    password: str = field(default_factory=lambda: _env("MSF_PASSWORD"))
    ssl: bool = field(default_factory=lambda: _env("MSF_SSL", "false").lower() in ("true", "1", "yes"))

    @property
    def uri(self) -> str:
        scheme = "https" if self.ssl else "http"
        return f"{scheme}://{self.host}:{self.port}"


_config: MsfConfig | None = None


def get_config() -> MsfConfig:
    global _config
    if _config is None:
        _config = MsfConfig()
    return _config
