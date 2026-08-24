"""Structured Meterpreter session tools for post-exploitation.

Wraps Meterpreter RPC calls for reliable, parsed output instead of
brittle send_session_command text parsing.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.models import outputs
from msf_harness.mcp.policy.roe import PROJECT_ROOT, enforce_roe
from msf_harness.mcp.rpc.client import RpcConnectionError, get_rpc, run_in_thread, safe_rpc_call
from msf_harness.mcp.tools.session_tools import _session_target_host

logger = logging.getLogger("msf_harness.tools.meterpreter")

EVIDENCE_DIR = PROJECT_ROOT / "evidence" / "msf"
_ALLOWED_UPLOAD_DIRS = [EVIDENCE_DIR]


def _validate_meterpreter_session(sessions: dict, session_id: int) -> dict | None:
    """Return error dict if session is missing or not Meterpreter, else None."""
    sid_str = str(session_id)
    if sid_str not in sessions:
        return outputs.error(f"Session {session_id} not found", code="session_not_found")
    if sessions[sid_str].get("type") != "meterpreter":
        return outputs.error(
            f"Session {session_id} is not a Meterpreter session "
            f"(type={sessions[sid_str].get('type')}). Use msf_session_upgrade first.",
            code="session_wrong_type",
        )
    return None


def _is_safe_path(path: Path, allowed_dirs: list[Path]) -> bool:
    """Check the resolved path is inside one of the allowed directories."""
    resolved = path.resolve()
    return any(
        resolved == d or str(resolved).startswith(str(d) + "\\") or str(resolved).startswith(str(d) + "/")
        for d in allowed_dirs
    )


_DANGEROUS_PATH_CHARS = frozenset({'"', "\n", "\r", "\x00"})


def _validate_remote_path(path: str) -> str | None:
    """Reject paths containing characters that could break Meterpreter command quoting."""
    dangerous = set(path) & _DANGEROUS_PATH_CHARS
    if dangerous:
        return f"Path contains forbidden characters: {dangerous}"
    return None


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="msf_session_sysinfo",
        annotations={
            "title": "Get session system info",
            "readOnlyHint": False,
            "destructiveHint": False,
        },
    )
    async def msf_session_sysinfo(engagement_id: str, session_id: int) -> dict:
        """Retrieve system information from a Meterpreter session (OS, arch, hostname)."""
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        try:
            client = await run_in_thread(get_rpc)
            sessions = await run_in_thread(getattr, client.sessions, "list")
            err = _validate_meterpreter_session(sessions, session_id)
            if err:
                return err

            target_host = _session_target_host(sessions[str(session_id)])
            if target_host:
                scope_denial = enforce_roe(engagement_id, targets=target_host)
                if scope_denial:
                    return scope_denial

            await run_in_thread(
                safe_rpc_call,
                "session.meterpreter_write",
                [session_id, "sysinfo\n"],
            )
            await asyncio.sleep(2)
            result = await run_in_thread(
                safe_rpc_call,
                "session.meterpreter_read",
                [session_id],
            )
            data = result.get("data", "") if isinstance(result, dict) else str(result)
            return outputs.ok(
                {
                    "session_id": session_id,
                    "sysinfo": data.strip(),
                    "engagement_id": engagement_id,
                }
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("sysinfo failed on session %d", session_id)
            return outputs.error(f"sysinfo failed: {e}")

    @mcp.tool(
        name="msf_session_getuid",
        annotations={
            "title": "Get session user identity",
            "readOnlyHint": False,
            "destructiveHint": False,
        },
    )
    async def msf_session_getuid(engagement_id: str, session_id: int) -> dict:
        """Get the current user identity from a Meterpreter session."""
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        try:
            client = await run_in_thread(get_rpc)
            sessions = await run_in_thread(getattr, client.sessions, "list")
            err = _validate_meterpreter_session(sessions, session_id)
            if err:
                return err

            target_host = _session_target_host(sessions[str(session_id)])
            if target_host:
                scope_denial = enforce_roe(engagement_id, targets=target_host)
                if scope_denial:
                    return scope_denial

            await run_in_thread(
                safe_rpc_call,
                "session.meterpreter_write",
                [session_id, "getuid\n"],
            )
            await asyncio.sleep(1)
            result = await run_in_thread(
                safe_rpc_call,
                "session.meterpreter_read",
                [session_id],
            )
            data = result.get("data", "") if isinstance(result, dict) else str(result)
            return outputs.ok(
                {
                    "session_id": session_id,
                    "uid": data.strip(),
                    "engagement_id": engagement_id,
                }
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("getuid failed on session %d", session_id)
            return outputs.error(f"getuid failed: {e}")

    @mcp.tool(
        name="msf_session_ps",
        annotations={
            "title": "List session processes",
            "readOnlyHint": False,
            "destructiveHint": False,
        },
    )
    async def msf_session_ps(engagement_id: str, session_id: int) -> dict:
        """List running processes in a Meterpreter session."""
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        try:
            client = await run_in_thread(get_rpc)
            sessions = await run_in_thread(getattr, client.sessions, "list")
            err = _validate_meterpreter_session(sessions, session_id)
            if err:
                return err

            target_host = _session_target_host(sessions[str(session_id)])
            if target_host:
                scope_denial = enforce_roe(engagement_id, targets=target_host)
                if scope_denial:
                    return scope_denial

            await run_in_thread(
                safe_rpc_call,
                "session.meterpreter_write",
                [session_id, "ps\n"],
            )
            await asyncio.sleep(3)
            result = await run_in_thread(
                safe_rpc_call,
                "session.meterpreter_read",
                [session_id],
            )
            data = result.get("data", "") if isinstance(result, dict) else str(result)
            return outputs.ok(
                {
                    "session_id": session_id,
                    "process_list": data.strip(),
                    "engagement_id": engagement_id,
                }
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("ps failed on session %d", session_id)
            return outputs.error(f"ps failed: {e}")

    @mcp.tool(
        name="msf_session_download",
        annotations={
            "title": "Download file from target",
            "readOnlyHint": False,
            "destructiveHint": False,
        },
    )
    async def msf_session_download(
        engagement_id: str,
        session_id: int,
        remote_path: str,
    ) -> dict:
        """Download a file from a Meterpreter session target to evidence/msf/."""
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        if not remote_path.strip():
            return outputs.error("remote_path cannot be empty")

        path_err = _validate_remote_path(remote_path)
        if path_err:
            return outputs.error(path_err)

        try:
            client = await run_in_thread(get_rpc)
            sessions = await run_in_thread(getattr, client.sessions, "list")
            err = _validate_meterpreter_session(sessions, session_id)
            if err:
                return err

            target_host = _session_target_host(sessions[str(session_id)])
            if target_host:
                scope_denial = enforce_roe(engagement_id, targets=target_host)
                if scope_denial:
                    return scope_denial

            EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

            cmd = f'download "{remote_path}" "{EVIDENCE_DIR}"\n'
            await run_in_thread(
                safe_rpc_call,
                "session.meterpreter_write",
                [session_id, cmd],
            )
            await asyncio.sleep(5)
            result = await run_in_thread(
                safe_rpc_call,
                "session.meterpreter_read",
                [session_id],
            )
            data = result.get("data", "") if isinstance(result, dict) else str(result)
            logger.info("Downloaded %s from session %d", remote_path, session_id)
            return outputs.ok(
                {
                    "session_id": session_id,
                    "remote_path": remote_path,
                    "local_dir": str(EVIDENCE_DIR),
                    "output": data.strip(),
                    "engagement_id": engagement_id,
                }
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("download failed on session %d", session_id)
            return outputs.error(f"download failed: {e}")

    @mcp.tool(
        name="msf_session_upload",
        annotations={
            "title": "Upload file to target",
            "readOnlyHint": False,
            "destructiveHint": True,
        },
    )
    async def msf_session_upload(
        engagement_id: str,
        session_id: int,
        local_path: str,
        remote_path: str,
    ) -> dict:
        """Upload a file from evidence/msf/ to a Meterpreter session target.

        local_path must be inside the evidence/msf/ directory (sandboxed).
        """
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        local = Path(local_path)
        if not _is_safe_path(local, _ALLOWED_UPLOAD_DIRS):
            return outputs.error(f"Upload source must be inside {EVIDENCE_DIR}. Got: {local_path}")
        if not local.exists():
            return outputs.error(f"Local file not found: {local_path}")

        if not remote_path.strip():
            return outputs.error("remote_path cannot be empty")

        path_err = _validate_remote_path(remote_path)
        if path_err:
            return outputs.error(path_err)
        path_err = _validate_remote_path(local_path)
        if path_err:
            return outputs.error(path_err)

        try:
            client = await run_in_thread(get_rpc)
            sessions = await run_in_thread(getattr, client.sessions, "list")
            err = _validate_meterpreter_session(sessions, session_id)
            if err:
                return err

            target_host = _session_target_host(sessions[str(session_id)])
            if target_host:
                scope_denial = enforce_roe(engagement_id, targets=target_host)
                if scope_denial:
                    return scope_denial

            cmd = f'upload "{local_path}" "{remote_path}"\n'
            await run_in_thread(
                safe_rpc_call,
                "session.meterpreter_write",
                [session_id, cmd],
            )
            await asyncio.sleep(5)
            result = await run_in_thread(
                safe_rpc_call,
                "session.meterpreter_read",
                [session_id],
            )
            data = result.get("data", "") if isinstance(result, dict) else str(result)
            logger.info("Uploaded %s to session %d -> %s", local_path, session_id, remote_path)
            return outputs.ok(
                {
                    "session_id": session_id,
                    "local_path": local_path,
                    "remote_path": remote_path,
                    "output": data.strip(),
                    "engagement_id": engagement_id,
                }
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("upload failed on session %d", session_id)
            return outputs.error(f"upload failed: {e}")
