"""Tests for MCP tool handler validation with mocked RPC."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.models import inputs
from msf_harness.mcp.policy.roe import enforce_roe
from msf_harness.mcp.tools import handler_tools, module_tools, read_tools, workspace_tools


@pytest.fixture
def tool_registry() -> dict[str, Any]:
    """Register handler modules on a test FastMCP and return tool callables."""
    mcp = FastMCP("test-tools")
    handler_tools.register(mcp)
    workspace_tools.register(mcp)
    read_tools.register(mcp)
    module_tools.register(mcp)
    return {
        name: mcp._tool_manager.get_tool(name).fn
        for name in (
            "msf_start_listener",
            "msf_db_import",
            "msf_search_modules",
        )
    }


class TestMsfRunExploitRoe:
    """Tests for msf_run_exploit ROE denial (via enforce_roe + target extraction)."""

    def test_denied_when_target_out_of_scope(self, roe_paths: dict[str, Path]) -> None:
        options = {"RHOSTS": "8.8.8.8"}
        target = module_tools._extract_target(options)
        denial = enforce_roe(
            roe_paths["engagement_id"],
            targets=target,
            module_path="exploit/windows/smb/ms17_010_eternalblue",
            check_sessions=True,
            is_exploit=True,
            check_was_run=True,
        )
        assert denial is not None
        assert denial["status"] == "denied"
        assert "outside authorized scope" in denial["reason"]


class TestMsfStartListener:
    """Tests for msf_start_listener port validation."""

    @pytest.mark.asyncio
    async def test_rejects_port_zero(self, tool_registry: dict[str, Any]) -> None:
        result = await tool_registry["msf_start_listener"](
            engagement_id="test-engagement",
            payload="generic/shell_reverse_tcp",
            lhost="0.0.0.0",
            lport=0,
        )
        assert result["status"] == "error"
        assert "Invalid port" in result["reason"]

    @pytest.mark.asyncio
    async def test_rejects_port_above_max(self, tool_registry: dict[str, Any]) -> None:
        result = await tool_registry["msf_start_listener"](
            engagement_id="test-engagement",
            payload="generic/shell_reverse_tcp",
            lhost="0.0.0.0",
            lport=99999,
        )
        assert result["status"] == "error"
        assert "Invalid port" in result["reason"]


class TestMsfDbImport:
    """Tests for msf_db_import path safety checks."""

    @pytest.mark.asyncio
    async def test_rejects_unsafe_path_traversal(
        self,
        tool_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await tool_registry["msf_db_import"](
            engagement_id=roe_paths["engagement_id"],
            file_path="../../etc/passwd",
        )
        assert result["status"] == "error"
        assert "Path traversal not allowed" in result["reason"]


class TestMsfSearchModules:
    """Tests for msf_search_modules input validation."""

    @pytest.mark.asyncio
    async def test_rejects_query_longer_than_max(
        self,
        tool_registry: dict[str, Any],
        mock_rpc_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "msf_harness.mcp.tools.read_tools.get_rpc",
            lambda: mock_rpc_client,
        )
        long_query = "x" * (inputs.MAX_QUERY_LENGTH + 1)
        result = await tool_registry["msf_search_modules"](query=long_query)
        assert result["status"] == "error"
        assert f"max {inputs.MAX_QUERY_LENGTH} chars" in result["reason"]
        mock_rpc_client.modules.search.assert_not_called()
