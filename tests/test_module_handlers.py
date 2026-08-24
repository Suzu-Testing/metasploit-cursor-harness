"""Mock-based tests for module tool handlers (check, exploit, aux, post)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.policy.roe import record_check
from msf_harness.mcp.tools import module_tools


@pytest.fixture
def module_registry(roe_paths: dict[str, Path]) -> dict[str, Any]:
    mcp = FastMCP("test-module")
    module_tools.register(mcp)
    return {
        name: mcp._tool_manager.get_tool(name).fn
        for name in (
            "msf_status",
            "msf_module_check",
            "msf_cleanup_jobs",
            "msf_run_exploit",
            "msf_run_auxiliary_module",
            "msf_run_post_module",
        )
    }


class TestModuleCheck:
    @pytest.mark.asyncio
    async def test_invalid_module_type_rejected(
        self,
        module_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await module_registry["msf_module_check"](
            engagement_id=roe_paths["engagement_id"],
            module_type="invalid",
            module_name="test/module",
        )
        assert result["status"] == "error"
        assert "Invalid module type" in result["reason"]

    @pytest.mark.asyncio
    async def test_dos_module_denied(
        self,
        module_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await module_registry["msf_module_check"](
            engagement_id=roe_paths["engagement_id"],
            module_type="auxiliary",
            module_name="auxiliary/dos/tcp/synflood",
        )
        assert result["status"] == "denied"


class TestRunExploit:
    @pytest.mark.asyncio
    async def test_out_of_scope_denied(
        self,
        module_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await module_registry["msf_run_exploit"](
            engagement_id=roe_paths["engagement_id"],
            module_name="exploit/test/module",
            options={"RHOSTS": "8.8.8.8"},
        )
        assert result["status"] == "denied"

    @pytest.mark.asyncio
    async def test_exploit_without_check_denied(
        self,
        module_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await module_registry["msf_run_exploit"](
            engagement_id=roe_paths["engagement_id"],
            module_name="exploit/test/module",
            options={"RHOSTS": "10.10.10.2"},
            run_check_first=False,
        )
        assert result["status"] == "denied"
        assert "check" in result["reason"].lower()

    @pytest.mark.asyncio
    async def test_exploit_with_prior_check_passes_gate(
        self,
        module_registry: dict[str, Any],
        roe_paths: dict[str, Path],
        mock_rpc_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        record_check(roe_paths["engagement_id"], "exploit/test/module", "10.10.10.2")
        mock_rpc_client.sessions.list = {}
        monkeypatch.setattr("msf_harness.mcp.tools.module_tools.get_rpc", lambda: mock_rpc_client)
        monkeypatch.setattr("msf_harness.mcp.rpc.client.get_rpc", lambda: mock_rpc_client)
        monkeypatch.setattr(
            "msf_harness.mcp.tools.module_tools.execute_module_via_console",
            lambda *a, **kw: {"status": "success", "session_id": 1, "message": "Opened session"},
        )
        monkeypatch.setattr(
            "msf_harness.mcp.tools.module_tools.cleanup_jobs",
            lambda c: [],
        )
        result = await module_registry["msf_run_exploit"](
            engagement_id=roe_paths["engagement_id"],
            module_name="exploit/test/module",
            options={"RHOSTS": "10.10.10.2"},
            run_check_first=False,
        )
        assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_module_path_normalized_for_check_lookup(
        self,
        module_registry: dict[str, Any],
        roe_paths: dict[str, Path],
        mock_rpc_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify that recording check with full path and querying with short path works."""
        record_check(roe_paths["engagement_id"], "exploit/test/module", "10.10.10.2")
        mock_rpc_client.sessions.list = {}
        monkeypatch.setattr("msf_harness.mcp.tools.module_tools.get_rpc", lambda: mock_rpc_client)
        monkeypatch.setattr("msf_harness.mcp.rpc.client.get_rpc", lambda: mock_rpc_client)
        monkeypatch.setattr(
            "msf_harness.mcp.tools.module_tools.execute_module_via_console",
            lambda *a, **kw: {"status": "success", "session_id": 1, "message": "ok"},
        )
        monkeypatch.setattr("msf_harness.mcp.tools.module_tools.cleanup_jobs", lambda c: [])

        result = await module_registry["msf_run_exploit"](
            engagement_id=roe_paths["engagement_id"],
            module_name="test/module",
            options={"RHOSTS": "10.10.10.2"},
            run_check_first=False,
        )
        assert result["status"] == "ok"


class TestRunAuxiliary:
    @pytest.mark.asyncio
    async def test_out_of_scope_denied(
        self,
        module_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await module_registry["msf_run_auxiliary_module"](
            engagement_id=roe_paths["engagement_id"],
            module_name="auxiliary/scanner/portscan/tcp",
            options={"RHOSTS": "8.8.8.8"},
        )
        assert result["status"] == "denied"


class TestCleanupJobs:
    @pytest.mark.asyncio
    async def test_bad_engagement_denied(self, module_registry: dict[str, Any]) -> None:
        result = await module_registry["msf_cleanup_jobs"](engagement_id="../evil")
        assert result["status"] == "denied"

    @pytest.mark.asyncio
    async def test_valid_cleanup(
        self,
        module_registry: dict[str, Any],
        roe_paths: dict[str, Path],
        mock_rpc_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("msf_harness.mcp.tools.module_tools.get_rpc", lambda: mock_rpc_client)
        monkeypatch.setattr("msf_harness.mcp.tools.module_tools.cleanup_jobs", lambda c: [1, 2])
        result = await module_registry["msf_cleanup_jobs"](
            engagement_id=roe_paths["engagement_id"],
        )
        assert result["status"] == "ok"
        assert result["data"]["stopped_jobs"] == [1, 2]
