"""Tests for MCP server configuration in msf_harness.mcp.config."""

from __future__ import annotations

import pytest

from msf_harness.mcp.config import _ENV_ALIASES, MsfConfig, _parse_port


class TestParsePort:
    """Tests for _parse_port validation."""

    def test_accepts_valid_port(self) -> None:
        assert _parse_port("55553") == 55553

    def test_rejects_non_integer(self) -> None:
        with pytest.raises(ValueError, match="must be an integer"):
            _parse_port("abc")

    def test_rejects_zero(self) -> None:
        with pytest.raises(ValueError, match="1-65535"):
            _parse_port("0")

    def test_rejects_port_above_max(self) -> None:
        with pytest.raises(ValueError, match="1-65535"):
            _parse_port("70000")

    def test_rejects_empty_string(self) -> None:
        with pytest.raises(ValueError, match="must be an integer"):
            _parse_port("")


class TestMsfConfigUri:
    """Tests for MsfConfig.uri property."""

    def test_http_uri_when_ssl_disabled(self) -> None:
        cfg = MsfConfig(host="127.0.0.1", port=55553, user="msf", password="", ssl=False)
        assert cfg.uri == "http://127.0.0.1:55553"

    def test_https_uri_when_ssl_enabled(self) -> None:
        cfg = MsfConfig(host="127.0.0.1", port=55553, user="msf", password="", ssl=True)
        assert cfg.uri == "https://127.0.0.1:55553"


class TestEnvAliases:
    """Tests for msfmcpd-compatible environment variable aliases."""

    def test_env_aliases_maps_api_host_to_host(self) -> None:
        assert _ENV_ALIASES["MSF_API_HOST"] == "MSF_HOST"
        assert _ENV_ALIASES["MSF_API_PORT"] == "MSF_PORT"
        assert _ENV_ALIASES["MSF_API_USER"] == "MSF_USER"
        assert _ENV_ALIASES["MSF_API_PASSWORD"] == "MSF_PASSWORD"
        assert _ENV_ALIASES["MSF_API_SSL"] == "MSF_SSL"
