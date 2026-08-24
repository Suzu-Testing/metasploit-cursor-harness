"""Mock-based tests for session and meterpreter tool handlers."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.tools import meterpreter_tools, session_tools


@pytest.fixture
def session_registry(roe_paths: dict[str, Path]) -> dict[str, Any]:
    """Register session tools and return callables."""
    mcp = FastMCP("test-sessions")
    session_tools.register(mcp)
    return {
        name: mcp._tool_manager.get_tool(name).fn
        for name in (
            "msf_list_active_sessions",
            "msf_send_session_command",
            "msf_terminate_session",
            "msf_session_info",
            "msf_session_run_script",
            "msf_session_upgrade",
        )
    }


@pytest.fixture
def meterpreter_registry(roe_paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Register meterpreter tools and return callables."""
    root = roe_paths["root"]
    monkeypatch.setattr(meterpreter_tools, "PROJECT_ROOT", root)
    monkeypatch.setattr(meterpreter_tools, "EVIDENCE_DIR", root / "evidence" / "msf")
    monkeypatch.setattr(meterpreter_tools, "_ALLOWED_UPLOAD_DIRS", [root / "evidence" / "msf"])

    mcp = FastMCP("test-meterpreter")
    meterpreter_tools.register(mcp)
    return {
        name: mcp._tool_manager.get_tool(name).fn
        for name in (
            "msf_session_sysinfo",
            "msf_session_getuid",
            "msf_session_ps",
            "msf_session_download",
            "msf_session_upload",
        )
    }


class TestListActiveSessions:
    """Tests for msf_list_active_sessions."""

    @pytest.mark.asyncio
    async def test_returns_empty_list(
        self,
        session_registry: dict[str, Any],
        mock_rpc_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_rpc_client.sessions.list = {}
        monkeypatch.setattr("msf_harness.mcp.tools.session_tools.get_rpc", lambda: mock_rpc_client)
        result = await session_registry["msf_list_active_sessions"]()
        assert result["status"] == "ok"
        assert result["data"] == []

    @pytest.mark.asyncio
    async def test_returns_sessions(
        self,
        session_registry: dict[str, Any],
        mock_rpc_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_rpc_client.sessions.list = {
            "1": {"type": "meterpreter", "target_host": "10.10.10.1"},
        }
        monkeypatch.setattr("msf_harness.mcp.tools.session_tools.get_rpc", lambda: mock_rpc_client)
        result = await session_registry["msf_list_active_sessions"]()
        assert result["status"] == "ok"
        assert len(result["data"]) == 1
        assert result["data"][0]["session_id"] == "1"


class TestTerminateSession:
    """Tests for msf_terminate_session."""

    @pytest.mark.asyncio
    async def test_roe_denial_on_bad_engagement(
        self,
        session_registry: dict[str, Any],
    ) -> None:
        result = await session_registry["msf_terminate_session"](
            engagement_id="../evil",
            session_id=1,
        )
        assert result["status"] == "denied"


class TestSessionInfo:
    """Tests for msf_session_info."""

    @pytest.mark.asyncio
    async def test_session_not_found(
        self,
        session_registry: dict[str, Any],
        mock_rpc_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_rpc_client.sessions.list = {}
        monkeypatch.setattr("msf_harness.mcp.tools.session_tools.get_rpc", lambda: mock_rpc_client)
        result = await session_registry["msf_session_info"](session_id=999)
        assert result["status"] == "session_not_found"
        assert "not found" in result["reason"]


class TestSessionRunScript:
    """Tests for msf_session_run_script."""

    @pytest.mark.asyncio
    async def test_empty_script_rejected(
        self,
        session_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await session_registry["msf_session_run_script"](
            engagement_id=roe_paths["engagement_id"],
            session_id=1,
            script="  ",
        )
        assert result["status"] == "error"
        assert "cannot be empty" in result["reason"]

    @pytest.mark.asyncio
    async def test_non_meterpreter_rejected(
        self,
        session_registry: dict[str, Any],
        mock_rpc_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        roe_paths: dict[str, Path],
    ) -> None:
        mock_rpc_client.sessions.list = {
            "1": {"type": "shell", "target_host": "10.10.10.1"},
        }
        monkeypatch.setattr("msf_harness.mcp.tools.session_tools.get_rpc", lambda: mock_rpc_client)
        result = await session_registry["msf_session_run_script"](
            engagement_id=roe_paths["engagement_id"],
            session_id=1,
            script="getsystem",
        )
        assert result["status"] == "session_wrong_type"
        assert "meterpreter" in result["reason"].lower()


class TestSessionUpgrade:
    """Tests for msf_session_upgrade."""

    @pytest.mark.asyncio
    async def test_rejects_invalid_port(
        self,
        session_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await session_registry["msf_session_upgrade"](
            engagement_id=roe_paths["engagement_id"],
            session_id=1,
            lhost="0.0.0.0",
            lport=99999,
        )
        assert result["status"] == "error"
        assert "Invalid port" in result["reason"]


class TestMeterpreterSysinfo:
    """Tests for msf_session_sysinfo ROE and session validation."""

    @pytest.mark.asyncio
    async def test_roe_denial_on_bad_engagement(
        self,
        meterpreter_registry: dict[str, Any],
    ) -> None:
        result = await meterpreter_registry["msf_session_sysinfo"](
            engagement_id="../evil",
            session_id=1,
        )
        assert result["status"] == "denied"

    @pytest.mark.asyncio
    async def test_session_not_found(
        self,
        meterpreter_registry: dict[str, Any],
        mock_rpc_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        roe_paths: dict[str, Path],
    ) -> None:
        mock_rpc_client.sessions.list = {}
        monkeypatch.setattr("msf_harness.mcp.tools.meterpreter_tools.get_rpc", lambda: mock_rpc_client)
        result = await meterpreter_registry["msf_session_sysinfo"](
            engagement_id=roe_paths["engagement_id"],
            session_id=999,
        )
        assert result["status"] == "session_not_found"
        assert "not found" in result["reason"]

    @pytest.mark.asyncio
    async def test_rejects_non_meterpreter(
        self,
        meterpreter_registry: dict[str, Any],
        mock_rpc_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        roe_paths: dict[str, Path],
    ) -> None:
        mock_rpc_client.sessions.list = {
            "1": {"type": "shell", "target_host": "10.10.10.1"},
        }
        monkeypatch.setattr("msf_harness.mcp.tools.meterpreter_tools.get_rpc", lambda: mock_rpc_client)
        result = await meterpreter_registry["msf_session_sysinfo"](
            engagement_id=roe_paths["engagement_id"],
            session_id=1,
        )
        assert result["status"] == "session_wrong_type"
        assert "not a Meterpreter session" in result["reason"]


class TestMeterpreterDownload:
    """Tests for msf_session_download path validation."""

    @pytest.mark.asyncio
    async def test_empty_remote_path_rejected(
        self,
        meterpreter_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await meterpreter_registry["msf_session_download"](
            engagement_id=roe_paths["engagement_id"],
            session_id=1,
            remote_path="  ",
        )
        assert result["status"] == "error"
        assert "cannot be empty" in result["reason"]

    @pytest.mark.asyncio
    async def test_dangerous_path_rejected(
        self,
        meterpreter_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await meterpreter_registry["msf_session_download"](
            engagement_id=roe_paths["engagement_id"],
            session_id=1,
            remote_path='C:\\Users\\"evil',
        )
        assert result["status"] == "error"
        assert "forbidden characters" in result["reason"]


class TestMeterpreterUpload:
    """Tests for msf_session_upload path validation and sandboxing."""

    @pytest.mark.asyncio
    async def test_upload_outside_evidence_rejected(
        self,
        meterpreter_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await meterpreter_registry["msf_session_upload"](
            engagement_id=roe_paths["engagement_id"],
            session_id=1,
            local_path="C:\\Windows\\System32\\cmd.exe",
            remote_path="/tmp/cmd.exe",
        )
        assert result["status"] == "error"
        assert "must be inside" in result["reason"]

    @pytest.mark.asyncio
    async def test_empty_remote_path_rejected(
        self,
        meterpreter_registry: dict[str, Any],
        roe_paths: dict[str, Path],
    ) -> None:
        result = await meterpreter_registry["msf_session_upload"](
            engagement_id=roe_paths["engagement_id"],
            session_id=1,
            local_path="evidence/msf/payload.bin",
            remote_path="  ",
        )
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_dangerous_remote_path_rejected(
        self,
        meterpreter_registry: dict[str, Any],
        roe_paths: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        evidence_dir = roe_paths["root"] / "evidence" / "msf"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        payload_file = evidence_dir / "payload.bin"
        payload_file.write_bytes(b"\x90\x90")

        result = await meterpreter_registry["msf_session_upload"](
            engagement_id=roe_paths["engagement_id"],
            session_id=1,
            local_path=str(payload_file),
            remote_path='/tmp/evil"\nid',
        )
        assert result["status"] == "error"
        assert "forbidden characters" in result["reason"]
