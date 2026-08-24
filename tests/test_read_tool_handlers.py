"""Mock-based tests for read-only tool handlers."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.models.inputs import MAX_QUERY_LENGTH
from msf_harness.mcp.tools import read_tools


@pytest.fixture
def read_registry(roe_paths: dict[str, Path]) -> dict[str, Any]:
    mcp = FastMCP("test-read")
    read_tools.register(mcp)
    return {
        name: mcp._tool_manager.get_tool(name).fn
        for name in (
            "msf_search_modules",
            "msf_module_info",
            "msf_host_info",
            "msf_service_info",
            "msf_vulnerability_info",
        )
    }


class TestSearchModules:
    @pytest.mark.asyncio
    async def test_query_too_long_rejected(self, read_registry: dict[str, Any]) -> None:
        result = await read_registry["msf_search_modules"](query="x" * (MAX_QUERY_LENGTH + 1))
        assert result["status"] == "error"
        assert "too long" in result["reason"].lower()

    @pytest.mark.asyncio
    async def test_valid_search(
        self,
        read_registry: dict[str, Any],
        mock_rpc_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_rpc_client.modules.search.return_value = [
            {"fullname": "exploit/test/mod", "name": "Test", "rank": 300},
        ]
        monkeypatch.setattr("msf_harness.mcp.tools.read_tools.get_rpc", lambda: mock_rpc_client)
        result = await read_registry["msf_search_modules"](query="test")
        assert result["status"] == "ok"


class TestHostInfo:
    @pytest.mark.asyncio
    async def test_invalid_workspace_rejected(self, read_registry: dict[str, Any]) -> None:
        result = await read_registry["msf_host_info"](workspace="bad name!")
        assert result["status"] == "error"
        assert "workspace" in result["reason"].lower()

    @pytest.mark.asyncio
    async def test_valid_query(
        self,
        read_registry: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "msf_harness.mcp.tools.read_tools.safe_rpc_call",
            lambda *a, **kw: {"hosts": [{"address": "10.0.0.2", "os_name": "Linux"}]},
        )
        result = await read_registry["msf_host_info"]()
        assert result["status"] == "ok"


class TestVulnerabilityInfo:
    @pytest.mark.asyncio
    async def test_invalid_ports_rejected(self, read_registry: dict[str, Any]) -> None:
        result = await read_registry["msf_vulnerability_info"](ports="abc")
        assert result["status"] == "error"
        assert "port" in result["reason"].lower()

    @pytest.mark.asyncio
    async def test_valid_query(
        self,
        read_registry: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "msf_harness.mcp.tools.read_tools.safe_rpc_call",
            lambda *a, **kw: {"vulns": []},
        )
        result = await read_registry["msf_vulnerability_info"](ports="80,443")
        assert result["status"] == "ok"
