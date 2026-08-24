"""Mock-based tests for console tool handlers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.tools import console_tools


@pytest.fixture
def console_registry(roe_paths: dict[str, Path]) -> dict[str, Any]:
    mcp = FastMCP("test-console")
    console_tools.register(mcp)
    return {
        name: mcp._tool_manager.get_tool(name).fn
        for name in (
            "msf_console_execute",
            "msf_console_list",
        )
    }


class TestConsoleExecute:
    @pytest.mark.asyncio
    async def test_empty_command_rejected(
        self,
        console_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await console_registry["msf_console_execute"](
            engagement_id=roe_paths["engagement_id"],
            command="  ",
        )
        assert result["status"] == "error"
        assert "cannot be empty" in result["reason"]

    @pytest.mark.asyncio
    async def test_multiline_command_rejected(
        self,
        console_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await console_registry["msf_console_execute"](
            engagement_id=roe_paths["engagement_id"],
            command="use exploit/test\nexploit",
        )
        assert result["status"] == "error"
        assert "Multi-line" in result["reason"]

    @pytest.mark.asyncio
    async def test_command_too_long_rejected(
        self,
        console_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await console_registry["msf_console_execute"](
            engagement_id=roe_paths["engagement_id"],
            command="x" * 5000,
        )
        assert result["status"] == "error"
        assert "too long" in result["reason"].lower()

    @pytest.mark.asyncio
    async def test_bad_engagement_denied(self, console_registry: dict[str, Any]) -> None:
        result = await console_registry["msf_console_execute"](
            engagement_id="../evil",
            command="version",
        )
        assert result["status"] == "denied"

    @pytest.mark.asyncio
    async def test_dos_module_blocked(
        self,
        console_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await console_registry["msf_console_execute"](
            engagement_id=roe_paths["engagement_id"],
            command="use auxiliary/dos/tcp/synflood",
        )
        assert result["status"] == "denied"

    @pytest.mark.asyncio
    async def test_out_of_scope_target_denied(
        self,
        console_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await console_registry["msf_console_execute"](
            engagement_id=roe_paths["engagement_id"],
            command="set RHOSTS 8.8.8.8",
        )
        assert result["status"] == "denied"
