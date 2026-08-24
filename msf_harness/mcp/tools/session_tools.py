"""Session management MCP tools: list, interact, terminate."""

from __future__ import annotations

import asyncio
import logging

from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.models import inputs, outputs
from msf_harness.mcp.policy.roe import enforce_roe
from msf_harness.mcp.rpc.client import RpcConnectionError, get_rpc, run_in_thread, safe_rpc_call

logger = logging.getLogger("msf_harness.tools.session")


def _session_target_host(session_info: dict) -> str | None:
    """Extract the target host IP from session metadata."""
    for key in ("target_host", "session_host", "tunnel_peer"):
        val = session_info.get(key)
        if val:
            host = str(val).split(":")[0].strip()
            if host:
                return host
    return None


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="msf_list_active_sessions",
        annotations={"title": "List active sessions", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_list_active_sessions() -> dict:
        """Show all current Metasploit sessions with type, target, and connection info."""
        try:
            client = await run_in_thread(get_rpc)
            sessions = await run_in_thread(getattr, client.sessions, "list")
            items = []
            if isinstance(sessions, dict):
                for sid, info in sessions.items():
                    items.append({"session_id": sid, **info})
            return outputs.ok(items, message=f"{len(items)} active session(s)")
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Session list failed")
            return outputs.error(f"Session list failed: {e}")

    @mcp.tool(
        name="msf_send_session_command",
        annotations={
            "title": "Run command in session",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
    )
    async def msf_send_session_command(
        engagement_id: str,
        session_id: int,
        command: str,
        timeout: int = 30,
    ) -> dict:
        """Run a command in an active shell or Meterpreter session. Requires engagement_id for ROE."""
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        try:
            client = await run_in_thread(get_rpc)
            sessions = await run_in_thread(getattr, client.sessions, "list")
            sid_str = str(session_id)
            if sid_str not in sessions:
                return outputs.error(f"Session {session_id} not found", code="session_not_found")

            target_host = _session_target_host(sessions[sid_str])
            if target_host:
                scope_denial = enforce_roe(engagement_id, targets=target_host)
                if scope_denial:
                    return scope_denial

            wait_secs = min(max(timeout, 1), 300)
            session_type = sessions[sid_str].get("type", "shell")
            logger.info(
                "Sending command to session %d (%s): %s",
                session_id,
                session_type,
                command[:120],
            )

            if session_type == "meterpreter":
                await run_in_thread(safe_rpc_call, "session.meterpreter_write", [session_id, command + "\n"])
            else:
                await run_in_thread(safe_rpc_call, "session.shell_write", [session_id, command + "\n"])

            read_method = "session.meterpreter_read" if session_type == "meterpreter" else "session.shell_read"
            chunks: list[str] = []
            elapsed = 0.0
            poll_interval = 1.0
            idle_rounds = 0
            while elapsed < wait_secs:
                await asyncio.sleep(poll_interval)
                elapsed += poll_interval
                result = await run_in_thread(safe_rpc_call, read_method, [session_id])
                data = result.get("data", "")
                if data:
                    chunks.append(data)
                    idle_rounds = 0
                else:
                    idle_rounds += 1
                    if idle_rounds >= 3 and chunks:
                        break

            output = "".join(chunks)
            return outputs.ok(
                {
                    "session_id": session_id,
                    "command": command,
                    "output": output,
                    "engagement_id": engagement_id,
                }
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Session command failed on session %d", session_id)
            return outputs.error(f"Session command failed: {e}")

    @mcp.tool(
        name="msf_terminate_session",
        annotations={
            "title": "Terminate session",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": True,
        },
    )
    async def msf_terminate_session(engagement_id: str, session_id: int) -> dict:
        """Forcefully terminate an active Metasploit session. Requires engagement_id for ROE."""
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        try:
            client = await run_in_thread(get_rpc)
            sessions = await run_in_thread(getattr, client.sessions, "list")
            sid_str = str(session_id)
            if sid_str in sessions:
                target_host = _session_target_host(sessions[sid_str])
                if target_host:
                    scope_denial = enforce_roe(engagement_id, targets=target_host)
                    if scope_denial:
                        return scope_denial
            result = await run_in_thread(safe_rpc_call, "session.stop", [session_id])
            logger.info("Terminated session %d", session_id)
            return outputs.ok(
                {
                    "session_id": session_id,
                    "terminated": True,
                    "result": result,
                    "engagement_id": engagement_id,
                }
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Session termination failed for session %d", session_id)
            return outputs.error(f"Session termination failed: {e}")

    @mcp.tool(
        name="msf_wait_for_session",
        annotations={
            "title": "Wait for new session",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_wait_for_session(
        engagement_id: str,
        timeout: int = 60,
        poll_interval: float = 2.0,
    ) -> dict:
        """Poll for a new Metasploit session after exploit/handler. Returns session info when found."""
        import time as _time

        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        try:
            client = await run_in_thread(get_rpc)
            initial = await run_in_thread(getattr, client.sessions, "list")
            initial_ids = set(initial.keys()) if isinstance(initial, dict) else set()
            deadline = _time.time() + min(max(timeout, 5), 300)
            poll_secs = max(poll_interval, 1.0)

            logger.info("Waiting for new session (timeout=%ds, %d existing)", timeout, len(initial_ids))

            while _time.time() < deadline:
                await asyncio.sleep(poll_secs)
                sessions = await run_in_thread(getattr, client.sessions, "list")
                if isinstance(sessions, dict):
                    new_ids = set(sessions.keys()) - initial_ids
                    if new_ids:
                        sid = sorted(new_ids, key=int)[0]
                        elapsed = timeout - (deadline - _time.time())
                        logger.info("New session %s detected after %.1fs", sid, elapsed)
                        return outputs.ok(
                            {
                                "session_id": int(sid),
                                "session_info": sessions[sid],
                                "engagement_id": engagement_id,
                                "wait_seconds": round(elapsed, 1),
                            },
                            message=f"Session {sid} opened",
                        )

            return outputs.error(
                f"No new session within {timeout}s",
                code="session_wait_timeout",
                data={
                    "session_id": None,
                    "existing_sessions": len(initial_ids),
                    "engagement_id": engagement_id,
                    "timeout": timeout,
                },
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Wait for session failed")
            return outputs.error(f"Wait for session failed: {e}")

    @mcp.tool(
        name="msf_session_info",
        annotations={
            "title": "Get single session details",
            "readOnlyHint": True,
            "destructiveHint": False,
        },
    )
    async def msf_session_info(session_id: int) -> dict:
        """Get detailed information about a single session.

        Returns type, platform, arch, tunnel info, target host, and other
        metadata. Lighter than msf_list_active_sessions when you already
        know the session ID.
        """
        try:
            client = await run_in_thread(get_rpc)
            sessions = await run_in_thread(getattr, client.sessions, "list")
            sid_str = str(session_id)
            if sid_str not in sessions:
                return outputs.error(f"Session {session_id} not found", code="session_not_found")
            info = sessions[sid_str]
            return outputs.ok(
                {
                    "session_id": session_id,
                    **info,
                }
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Session info failed for session %d", session_id)
            return outputs.error(f"Session info failed: {e}")

    @mcp.tool(
        name="msf_session_run_script",
        annotations={
            "title": "Run Meterpreter script",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
    )
    async def msf_session_run_script(
        engagement_id: str,
        session_id: int,
        script: str,
        timeout: int = 30,
    ) -> dict:
        """Run a Meterpreter script or single command in a session.

        Uses session.meterpreter_run_single for reliable single-command
        execution (e.g., 'run autoroute -s 10.0.0.0/24', 'getsystem',
        'hashdump'). Different from msf_send_session_command which uses
        write/read polling.
        """
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        if not script.strip():
            return outputs.error("Script command cannot be empty")

        try:
            client = await run_in_thread(get_rpc)
            sessions = await run_in_thread(getattr, client.sessions, "list")
            sid_str = str(session_id)
            if sid_str not in sessions:
                return outputs.error(f"Session {session_id} not found", code="session_not_found")

            session_type = sessions[sid_str].get("type", "shell")
            if session_type != "meterpreter":
                return outputs.error(
                    f"Session {session_id} is type '{session_type}', not meterpreter. Use msf_session_upgrade first.",
                    code="session_wrong_type",
                )

            target_host = _session_target_host(sessions[sid_str])
            if target_host:
                scope_denial = enforce_roe(engagement_id, targets=target_host)
                if scope_denial:
                    return scope_denial

            await run_in_thread(
                safe_rpc_call,
                "session.meterpreter_run_single",
                [session_id, script.strip()],
            )

            wait_secs = min(max(timeout, 1), 300)
            chunks: list[str] = []
            elapsed = 0.0
            poll_interval = 1.0
            idle_rounds = 0
            while elapsed < wait_secs:
                await asyncio.sleep(poll_interval)
                elapsed += poll_interval
                result = await run_in_thread(
                    safe_rpc_call,
                    "session.meterpreter_read",
                    [session_id],
                )
                data = result.get("data", "")
                if data:
                    chunks.append(data)
                    idle_rounds = 0
                else:
                    idle_rounds += 1
                    if idle_rounds >= 3 and chunks:
                        break

            output = "".join(chunks)
            logger.info("Ran script '%s' on session %d", script[:80], session_id)
            return outputs.ok(
                {
                    "session_id": session_id,
                    "script": script,
                    "output": output,
                    "engagement_id": engagement_id,
                }
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Session run_script failed on session %d", session_id)
            return outputs.error(f"Session run_script failed: {e}")

    @mcp.tool(
        name="msf_session_upgrade",
        annotations={
            "title": "Upgrade shell to Meterpreter",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
        },
    )
    async def msf_session_upgrade(
        engagement_id: str,
        session_id: int,
        lhost: str,
        lport: int = 4433,
    ) -> dict:
        """Upgrade a basic shell session to a Meterpreter session. Requires engagement_id for ROE."""
        ip_err = inputs.validate_ip(lhost)
        if ip_err:
            return outputs.error(f"Invalid lhost: {ip_err}")

        if not (1 <= lport <= 65535):
            return outputs.error(f"Invalid port: {lport}. Must be 1-65535.")

        denial = enforce_roe(engagement_id, check_sessions=True)
        if denial:
            return denial

        try:
            client = await run_in_thread(get_rpc)
            sessions = await run_in_thread(getattr, client.sessions, "list")
            sid_str = str(session_id)
            if sid_str not in sessions:
                return outputs.error(f"Session {session_id} not found", code="session_not_found")

            session_type = sessions[sid_str].get("type", "shell")
            if session_type == "meterpreter":
                return outputs.ok(
                    {
                        "session_id": session_id,
                        "upgraded": False,
                        "engagement_id": engagement_id,
                    },
                    message="Session is already Meterpreter; no upgrade needed",
                )

            result = await run_in_thread(safe_rpc_call, "session.shell_upgrade", [session_id, lhost, lport])
            logger.info("Upgrading session %d to Meterpreter via %s:%d", session_id, lhost, lport)
            return outputs.ok(
                {
                    "session_id": session_id,
                    "lhost": lhost,
                    "lport": lport,
                    "result": result,
                    "engagement_id": engagement_id,
                },
                message="Upgrade initiated; use msf_wait_for_session to detect the new Meterpreter session",
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Session upgrade failed for session %d", session_id)
            return outputs.error(f"Session upgrade failed: {e}")
