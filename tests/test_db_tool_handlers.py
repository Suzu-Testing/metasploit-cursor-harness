"""Mock-based tests for database write tool handlers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.tools import db_tools


@pytest.fixture
def db_registry(roe_paths: dict[str, Path]) -> dict[str, Any]:
    mcp = FastMCP("test-db")
    db_tools.register(mcp)
    return {
        name: mcp._tool_manager.get_tool(name).fn
        for name in (
            "msf_report_host",
            "msf_credential_add",
            "msf_db_add_note",
            "msf_db_status",
        )
    }


class TestReportHost:
    @pytest.mark.asyncio
    async def test_roe_denial_out_of_scope(self, db_registry: dict[str, Any], roe_paths: dict[str, Path]) -> None:
        result = await db_registry["msf_report_host"](
            engagement_id=roe_paths["engagement_id"],
            host="8.8.8.8",
        )
        assert result["status"] == "denied"

    @pytest.mark.asyncio
    async def test_invalid_host_rejected(self, db_registry: dict[str, Any], roe_paths: dict[str, Path]) -> None:
        result = await db_registry["msf_report_host"](
            engagement_id=roe_paths["engagement_id"],
            host="not-an-ip",
        )
        assert result["status"] == "error"
        assert "Invalid IP" in result["reason"]

    @pytest.mark.asyncio
    async def test_invalid_workspace_rejected(self, db_registry: dict[str, Any], roe_paths: dict[str, Path]) -> None:
        result = await db_registry["msf_report_host"](
            engagement_id=roe_paths["engagement_id"],
            host="10.10.10.2",
            workspace="bad workspace!",
        )
        assert result["status"] == "error"
        assert "Invalid workspace" in result["reason"]

    @pytest.mark.asyncio
    async def test_valid_host_succeeds(
        self,
        db_registry: dict[str, Any],
        roe_paths: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "msf_harness.mcp.tools.db_tools.safe_rpc_call",
            lambda *a, **kw: {"result": "success"},
        )
        result = await db_registry["msf_report_host"](
            engagement_id=roe_paths["engagement_id"],
            host="10.10.10.2",
        )
        assert result["status"] == "ok"
        assert result["data"]["host"] == "10.10.10.2"


class TestCredentialAdd:
    @pytest.mark.asyncio
    async def test_invalid_host_rejected(self, db_registry: dict[str, Any], roe_paths: dict[str, Path]) -> None:
        result = await db_registry["msf_credential_add"](
            engagement_id=roe_paths["engagement_id"],
            host="not-valid",
            port=22,
            username="root",
            private_data="password123",
        )
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_invalid_port_rejected(
        self,
        db_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await db_registry["msf_credential_add"](
            engagement_id=roe_paths["engagement_id"],
            host="10.10.10.2",
            port=0,
            username="root",
            private_data="password123",
        )
        assert result["status"] == "error"
        assert "Invalid port" in result["reason"]

    @pytest.mark.asyncio
    async def test_invalid_private_type_rejected(
        self,
        db_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await db_registry["msf_credential_add"](
            engagement_id=roe_paths["engagement_id"],
            host="10.10.10.2",
            port=22,
            username="root",
            private_data="pw",
            private_type="invalid_type",
        )
        assert result["status"] == "error"
        assert "private_type" in result["reason"]

    @pytest.mark.asyncio
    async def test_valid_credential_succeeds(
        self,
        db_registry: dict[str, Any],
        roe_paths: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "msf_harness.mcp.tools.db_tools.safe_rpc_call",
            lambda *a, **kw: {"result": "success"},
        )
        result = await db_registry["msf_credential_add"](
            engagement_id=roe_paths["engagement_id"],
            host="10.10.10.2",
            port=22,
            username="root",
            private_data="password123",
        )
        assert result["status"] == "ok"
        assert result["data"]["username"] == "root"


class TestDbAddNote:
    @pytest.mark.asyncio
    async def test_empty_ntype_rejected(self, db_registry: dict[str, Any], roe_paths: dict[str, Path]) -> None:
        result = await db_registry["msf_db_add_note"](
            engagement_id=roe_paths["engagement_id"],
            ntype="  ",
            data="test",
        )
        assert result["status"] == "error"
        assert "ntype" in result["reason"].lower()

    @pytest.mark.asyncio
    async def test_host_out_of_scope_denied(self, db_registry: dict[str, Any], roe_paths: dict[str, Path]) -> None:
        result = await db_registry["msf_db_add_note"](
            engagement_id=roe_paths["engagement_id"],
            ntype="host.os",
            data="Linux",
            host="8.8.8.8",
        )
        assert result["status"] == "denied"


class TestDbStatus:
    @pytest.mark.asyncio
    async def test_returns_ok_on_success(
        self,
        db_registry: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "msf_harness.mcp.tools.db_tools.safe_rpc_call",
            lambda *a, **kw: {"driver": "postgresql", "db": "msf"},
        )
        result = await db_registry["msf_db_status"]()
        assert result["status"] == "ok"
        assert result["data"]["driver"] == "postgresql"
