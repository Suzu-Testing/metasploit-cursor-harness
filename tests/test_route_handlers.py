"""Mock-based tests for route tool handlers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.tools import route_tools


@pytest.fixture
def route_registry(roe_paths: dict[str, Path]) -> dict[str, Any]:
    mcp = FastMCP("test-route")
    route_tools.register(mcp)
    return {
        name: mcp._tool_manager.get_tool(name).fn
        for name in (
            "msf_route_list",
            "msf_route_add",
            "msf_route_delete",
            "msf_autoroute",
        )
    }


class TestRouteAdd:
    @pytest.mark.asyncio
    async def test_out_of_scope_subnet_denied(
        self,
        route_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await route_registry["msf_route_add"](
            engagement_id=roe_paths["engagement_id"],
            subnet="192.168.100.0",
            netmask="255.255.255.0",
            session_id=1,
        )
        assert result["status"] == "denied"

    @pytest.mark.asyncio
    async def test_invalid_subnet_rejected(
        self,
        route_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await route_registry["msf_route_add"](
            engagement_id=roe_paths["engagement_id"],
            subnet="not-an-ip",
            netmask="255.255.255.0",
            session_id=1,
        )
        assert result["status"] in ("error", "denied")

    @pytest.mark.asyncio
    async def test_invalid_netmask_rejected(
        self,
        route_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await route_registry["msf_route_add"](
            engagement_id=roe_paths["engagement_id"],
            subnet="10.10.10.0",
            netmask="bad",
            session_id=1,
        )
        assert result["status"] == "error"
        assert "netmask" in result["reason"].lower()

    @pytest.mark.asyncio
    async def test_injection_in_subnet_rejected(
        self,
        route_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await route_registry["msf_route_add"](
            engagement_id=roe_paths["engagement_id"],
            subnet="10.10.10.0;id",
            netmask="255.255.255.0",
            session_id=1,
        )
        assert result["status"] in ("error", "denied")


class TestRouteDelete:
    @pytest.mark.asyncio
    async def test_invalid_netmask_rejected(
        self,
        route_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await route_registry["msf_route_delete"](
            engagement_id=roe_paths["engagement_id"],
            subnet="10.10.10.0",
            netmask="garbage",
        )
        assert result["status"] == "error"


class TestAutoroute:
    @pytest.mark.asyncio
    async def test_out_of_scope_subnet_denied(
        self,
        route_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await route_registry["msf_autoroute"](
            engagement_id=roe_paths["engagement_id"],
            session_id=1,
            subnet="192.168.100.0",
        )
        assert result["status"] == "denied"

    @pytest.mark.asyncio
    async def test_bad_engagement_denied(
        self,
        route_registry: dict[str, Any],
    ) -> None:
        result = await route_registry["msf_autoroute"](
            engagement_id="../evil",
            session_id=1,
        )
        assert result["status"] == "denied"
