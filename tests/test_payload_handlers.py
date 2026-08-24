"""Mock-based tests for payload tool handlers."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.models.inputs import MAX_QUERY_LENGTH
from msf_harness.mcp.tools import payload_tools


@pytest.fixture
def payload_registry(roe_paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr(payload_tools, "PROJECT_ROOT", roe_paths["root"])
    monkeypatch.setattr(payload_tools, "EVIDENCE_DIR", roe_paths["root"] / "evidence" / "msf")
    monkeypatch.setattr(
        payload_tools,
        "_ALLOWED_OUTPUT_DIRS",
        (roe_paths["root"] / "evidence", roe_paths["root"] / "engagements"),
    )
    mcp = FastMCP("test-payload")
    payload_tools.register(mcp)
    return {
        name: mcp._tool_manager.get_tool(name).fn
        for name in (
            "msf_list_payloads",
            "msf_generate_payload",
            "msf_compatible_payloads",
        )
    }


class TestListPayloads:
    @pytest.mark.asyncio
    async def test_query_too_long_rejected(self, payload_registry: dict[str, Any]) -> None:
        result = await payload_registry["msf_list_payloads"](query="x" * (MAX_QUERY_LENGTH + 1))
        assert result["status"] == "error"
        assert "too long" in result["reason"].lower()

    @pytest.mark.asyncio
    async def test_valid_query_succeeds(
        self,
        payload_registry: dict[str, Any],
        mock_rpc_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_rpc_client.modules.payloads = ["windows/meterpreter/reverse_tcp", "linux/x64/shell_reverse_tcp"]
        monkeypatch.setattr("msf_harness.mcp.tools.payload_tools.get_rpc", lambda: mock_rpc_client)
        result = await payload_registry["msf_list_payloads"](query="meterpreter")
        assert result["status"] == "ok"
        assert len(result["data"]) == 1
        assert "meterpreter" in result["data"][0]


class TestCompatiblePayloads:
    @pytest.mark.asyncio
    async def test_invalid_module_type_rejected(self, payload_registry: dict[str, Any]) -> None:
        result = await payload_registry["msf_compatible_payloads"](
            module_type="invalid",
            module_name="test/module",
        )
        assert result["status"] == "error"
        assert "Invalid module type" in result["reason"]

    @pytest.mark.asyncio
    async def test_valid_query_succeeds(
        self,
        payload_registry: dict[str, Any],
        mock_rpc_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_rpc_client.call.return_value = {"payloads": ["windows/meterpreter/reverse_tcp"]}
        monkeypatch.setattr("msf_harness.mcp.tools.payload_tools.get_rpc", lambda: mock_rpc_client)
        result = await payload_registry["msf_compatible_payloads"](
            module_type="exploit",
            module_name="windows/smb/ms17_010_eternalblue",
        )
        assert result["status"] == "ok"
        assert len(result["data"]) == 1


class TestGeneratePayload:
    @pytest.mark.asyncio
    async def test_bad_engagement_denied(self, payload_registry: dict[str, Any]) -> None:
        result = await payload_registry["msf_generate_payload"](
            engagement_id="../evil",
            payload="windows/meterpreter/reverse_tcp",
        )
        assert result["status"] == "denied"

    @pytest.mark.asyncio
    async def test_output_path_outside_allowed_rejected(
        self,
        payload_registry: dict[str, Any],
        roe_paths: dict[str, Path],
        mock_rpc_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_mod = MagicMock()
        mock_mod.runoptions = {}
        mock_mod.__setitem__ = MagicMock()
        mock_rpc_client.modules.use.return_value = mock_mod
        mock_rpc_client.call.return_value = {"payload": b"\x90\x90"}
        monkeypatch.setattr("msf_harness.mcp.tools.payload_tools.get_rpc", lambda: mock_rpc_client)
        result = await payload_registry["msf_generate_payload"](
            engagement_id=roe_paths["engagement_id"],
            payload="windows/meterpreter/reverse_tcp",
            output_path="../../../etc/evil.exe",
        )
        assert result["status"] == "error"
        assert "traversal" in result["reason"].lower() or "evidence" in result["reason"].lower()
