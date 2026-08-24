"""Mock-based tests for handler/listener tool handlers."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.tools import handler_tools


@pytest.fixture
def handler_registry(roe_paths: dict[str, Path]) -> dict[str, Any]:
    mcp = FastMCP("test-handler")
    handler_tools.register(mcp)
    return {
        name: mcp._tool_manager.get_tool(name).fn
        for name in (
            "msf_list_listeners",
            "msf_start_listener",
            "msf_stop_job",
            "msf_job_info",
        )
    }


class TestStartListener:
    @pytest.mark.asyncio
    async def test_invalid_lhost_rejected(
        self,
        handler_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await handler_registry["msf_start_listener"](
            engagement_id=roe_paths["engagement_id"],
            payload="windows/meterpreter/reverse_tcp",
            lhost="not-an-ip",
            lport=4444,
        )
        assert result["status"] == "error"
        assert "lhost" in result["reason"].lower() or "Invalid" in result["reason"]

    @pytest.mark.asyncio
    async def test_port_zero_rejected(
        self,
        handler_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await handler_registry["msf_start_listener"](
            engagement_id=roe_paths["engagement_id"],
            payload="windows/meterpreter/reverse_tcp",
            lhost="0.0.0.0",
            lport=0,
        )
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_port_above_max_rejected(
        self,
        handler_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await handler_registry["msf_start_listener"](
            engagement_id=roe_paths["engagement_id"],
            payload="windows/meterpreter/reverse_tcp",
            lhost="0.0.0.0",
            lport=70000,
        )
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_bad_engagement_denied(self, handler_registry: dict[str, Any]) -> None:
        result = await handler_registry["msf_start_listener"](
            engagement_id="../evil",
            payload="windows/meterpreter/reverse_tcp",
            lhost="0.0.0.0",
            lport=4444,
        )
        assert result["status"] == "denied"


class TestListListeners:
    @pytest.mark.asyncio
    async def test_returns_empty_list(
        self,
        handler_registry: dict[str, Any],
        mock_rpc_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_rpc_client.jobs.list = {}
        monkeypatch.setattr("msf_harness.mcp.tools.handler_tools.get_rpc", lambda: mock_rpc_client)
        result = await handler_registry["msf_list_listeners"]()
        assert result["status"] == "ok"
        assert result["data"] == []


class TestStopJob:
    @pytest.mark.asyncio
    async def test_bad_engagement_denied(self, handler_registry: dict[str, Any]) -> None:
        result = await handler_registry["msf_stop_job"](
            engagement_id="../evil",
            job_id=1,
        )
        assert result["status"] == "denied"
