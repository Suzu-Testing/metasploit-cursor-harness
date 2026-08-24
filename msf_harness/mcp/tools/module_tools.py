"""Action tools for module operations: status, check, run_exploit, run_auxiliary, run_post."""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.models import inputs, outputs
from msf_harness.mcp.models.inputs import parse_options_gracefully
from msf_harness.mcp.policy.roe import enforce_roe, record_check, was_check_run
from msf_harness.mcp.rpc.client import RpcConnectionError, get_rpc, run_in_thread
from msf_harness.mcp.rpc.console import execute_module_via_console
from msf_harness.mcp.rpc.execute import check_module, cleanup_jobs, execute_module
from msf_harness.mcp.tools.session_tools import _session_target_host

logger = logging.getLogger("msf_harness.tools.module")


def _extract_target(options: dict[str, Any] | None) -> str | None:
    """Extract target IP from options, checking RHOSTS, rhosts, RHOST, and rhost."""
    if not options:
        return None
    for key in ("RHOSTS", "rhosts", "RHOST", "rhost"):
        val = options.get(key)
        if val:
            return str(val)
    return None


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="msf_status",
        annotations={"title": "Check RPC connectivity", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_status() -> dict:
        """Check Metasploit RPC connectivity, version, and session count."""
        try:
            client = await run_in_thread(get_rpc)
            version = await run_in_thread(client.call, "core.version", [])
            sessions = await run_in_thread(getattr, client.sessions, "list")
            return outputs.ok(
                {
                    "connected": True,
                    "version": version.get("version", "unknown"),
                    "ruby": version.get("ruby", "unknown"),
                    "api": version.get("api", "unknown"),
                    "active_sessions": len(sessions) if isinstance(sessions, dict) else 0,
                }
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Status check failed")
            return outputs.error(f"Status check failed: {e}")

    @mcp.tool(
        name="msf_module_check",
        annotations={
            "title": "Run module vulnerability check",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_module_check(
        engagement_id: str,
        module_type: str,
        module_name: str,
        options: dict[str, Any] | None = None,
    ) -> dict:
        """Run a module's check method (safe probe, not exploitation). Requires engagement_id for ROE."""
        type_err = inputs.validate_module_type(module_type)
        if type_err:
            return outputs.error(type_err)

        full_name = module_name if "/" in module_name else f"{module_type}/{module_name}"
        target = _extract_target(options)

        denial = enforce_roe(engagement_id, targets=target, module_path=full_name)
        if denial:
            return denial

        try:
            client = await run_in_thread(get_rpc)
            result = await run_in_thread(check_module, client, module_type, module_name, options)
            logger.info("Module check %s on %s: %s", full_name, target, result)
            record_check(engagement_id, full_name, target)
            return outputs.ok(
                {
                    "module": full_name,
                    "check_result": result,
                    "engagement_id": engagement_id,
                }
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Module check failed: %s", full_name)
            return outputs.error(f"Module check failed: {e}")

    @mcp.tool(
        name="msf_cleanup_jobs",
        annotations={
            "title": "Stop all background MSF jobs",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": True,
        },
    )
    async def msf_cleanup_jobs(engagement_id: str) -> dict:
        """Stop all running Metasploit background jobs (handlers, scanners). Frees listener ports."""
        denial = enforce_roe(engagement_id)
        if denial:
            return denial
        try:
            client = await run_in_thread(get_rpc)
            stopped = await run_in_thread(cleanup_jobs, client)
            return outputs.ok(
                {
                    "stopped_jobs": stopped,
                    "engagement_id": engagement_id,
                },
                message=f"Stopped {len(stopped)} job(s)",
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Job cleanup failed")
            return outputs.error(f"Job cleanup failed: {e}")

    @mcp.tool(
        name="msf_run_exploit",
        annotations={
            "title": "Execute exploit module",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
    )
    async def msf_run_exploit(
        engagement_id: str,
        module_name: str,
        options: dict[str, Any],
        payload: str | None = None,
        payload_options: dict[str, Any] | None = None,
        run_check_first: bool = True,
        run_as_job: bool = False,
        timeout: int = 90,
    ) -> dict:
        """Execute an exploit module against a target. Requires engagement_id for ROE enforcement.

        By default uses MSF console execution (run_as_job=False), matching GH05TCREW/MetasploitMCP
        behaviour: options are set explicitly, output is captured, and sessions are detected from
        console text. Set run_as_job=True for async RPC job execution with session polling.

        If the engagement ROE has require_check_before_exploit=true, exploitation
        is blocked unless run_check_first=True (the check runs inline).

        timeout controls how long (seconds) to wait for console output (default 90, max 300).
        """
        target = _extract_target(options)
        try:
            options = parse_options_gracefully(options)
        except ValueError as e:
            return outputs.error(str(e))
        exploit_full_name = module_name if module_name.startswith("exploit/") else f"exploit/{module_name}"
        check_satisfied = run_check_first or was_check_run(engagement_id, exploit_full_name, target)
        denial = enforce_roe(
            engagement_id,
            targets=target,
            module_path=exploit_full_name,
            check_sessions=True,
            is_exploit=True,
            check_was_run=check_satisfied,
        )
        if denial:
            return denial

        try:
            client = await run_in_thread(get_rpc)
            if run_check_first:
                try:
                    check_result = await run_in_thread(
                        check_module,
                        client,
                        "exploit",
                        module_name,
                        options,
                    )
                    logger.info("Pre-exploit check %s on %s: %s", module_name, target, check_result)
                    record_check(engagement_id, exploit_full_name, target)
                    check_str = str(check_result).lower() if check_result else ""
                    if (
                        check_result in ("safe", False)
                        or (isinstance(check_result, dict) and check_result.get("result") == "safe")
                        or "not vulnerable" in check_str
                    ):
                        return outputs.error(
                            "Check indicates target is not vulnerable. Exploit not executed.",
                            code="not_vulnerable",
                            data={
                                "module": module_name,
                                "check_result": check_result,
                                "engagement_id": engagement_id,
                            },
                        )
                except Exception as check_exc:
                    logger.error("Pre-exploit check failed (blocking exploit as safety measure): %s", check_exc)
                    return outputs.error(
                        f"Pre-exploit check failed: {check_exc}. "
                        "Cannot confirm vulnerability status; exploit blocked. "
                        "Run msf_module_check separately to diagnose, or set run_check_first=False to skip.",
                        code="module_check_failed",
                    )

            exploit_timeout = max(10, min(timeout, 300))
            logger.info(
                "Executing exploit %s against %s (console=%s, timeout=%ds)",
                module_name,
                target,
                not run_as_job,
                exploit_timeout,
            )
            stopped = await run_in_thread(cleanup_jobs, client)

            if run_as_job:
                result = await run_in_thread(
                    execute_module,
                    client,
                    "exploit",
                    module_name,
                    options,
                    payload,
                    payload_options,
                    engagement_id,
                )
                return outputs.ok(
                    {
                        "module": module_name,
                        "execution_mode": "rpc_job",
                        "execution_result": result,
                        "stopped_jobs": stopped,
                        "engagement_id": engagement_id,
                    }
                )

            console_result = await run_in_thread(
                execute_module_via_console,
                client,
                "exploit",
                module_name,
                options,
                payload,
                payload_options,
                "exploit",
                exploit_timeout,
            )
            status = console_result.get("status", "error")
            if status == "success":
                return outputs.ok(
                    {
                        "module": module_name,
                        "execution_mode": "console",
                        "session_id": console_result.get("session_id"),
                        "module_output": console_result.get("module_output"),
                        "stopped_jobs": stopped,
                        "engagement_id": engagement_id,
                    },
                    message=console_result.get("message"),
                )
            return outputs.error(
                console_result.get("message", "Exploit failed"),
                data={
                    "module": module_name,
                    "execution_mode": "console",
                    "module_output": console_result.get("module_output"),
                    "stopped_jobs": stopped,
                    "engagement_id": engagement_id,
                },
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Exploit execution failed: %s", module_name)
            return outputs.error(f"Exploit execution failed: {e}")

    @mcp.tool(
        name="msf_run_auxiliary_module",
        annotations={
            "title": "Run auxiliary module",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
    )
    async def msf_run_auxiliary_module(
        engagement_id: str,
        module_name: str,
        options: dict[str, Any] | None = None,
        run_as_job: bool = False,
        timeout: int = 120,
    ) -> dict:
        """Run a Metasploit auxiliary module (scanner, fuzzer, etc.).

        By default uses console execution for captured output (better for
        agents to see scan results). Set run_as_job=True for background
        RPC job execution. timeout controls console wait time (default 120s,
        max 300). Requires engagement_id for ROE.
        """
        target = _extract_target(options)
        denial = enforce_roe(engagement_id, targets=target, module_path=module_name)
        if denial:
            return denial

        try:
            options = parse_options_gracefully(options)
        except ValueError as e:
            return outputs.error(str(e))

        aux_timeout = max(10, min(timeout, 300))

        try:
            client = await run_in_thread(get_rpc)

            if run_as_job:
                result = await run_in_thread(
                    execute_module,
                    client,
                    "auxiliary",
                    module_name,
                    options,
                    engagement_id=engagement_id,
                )
                logger.info("Auxiliary module %s on %s started as job", module_name, target)
                return outputs.ok(
                    {
                        "module": module_name,
                        "execution_mode": "rpc_job",
                        "execution_result": result,
                        "engagement_id": engagement_id,
                    }
                )

            console_result = await run_in_thread(
                execute_module_via_console,
                client,
                "auxiliary",
                module_name,
                options,
                None,
                None,
                "run",
                aux_timeout,
            )
            logger.info("Auxiliary module %s on %s completed (console)", module_name, target)
            console_status = console_result.get("status", "error")
            result_data = {
                "module": module_name,
                "execution_mode": "console",
                "module_output": console_result.get("module_output"),
                "engagement_id": engagement_id,
            }
            if console_status == "error":
                return outputs.error(
                    console_result.get("message", "Auxiliary module failed"),
                    data=result_data,
                )
            return outputs.ok(result_data, message=console_result.get("message"))
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Auxiliary module failed: %s", module_name)
            return outputs.error(f"Auxiliary module failed: {e}")

    @mcp.tool(
        name="msf_run_post_module",
        annotations={
            "title": "Run post-exploitation module",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
    )
    async def msf_run_post_module(
        engagement_id: str,
        module_name: str,
        session_id: int,
        options: dict[str, Any] | None = None,
        run_as_job: bool = False,
        timeout: int = 120,
    ) -> dict:
        """Execute a post-exploitation module against an existing session.

        By default uses console execution for captured output. Set
        run_as_job=True for background RPC job execution. timeout controls
        console wait time (default 120s, max 300). Requires engagement_id
        for ROE.
        """
        denial = enforce_roe(engagement_id, module_path=module_name)
        if denial:
            return denial

        try:
            options = parse_options_gracefully(options)
        except ValueError as e:
            return outputs.error(str(e))

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
            else:
                return outputs.error(f"Session {session_id} not found", code="session_not_found")

            merged_opts = {**(options or {}), "SESSION": str(session_id)}
            post_timeout = max(10, min(timeout, 300))

            if run_as_job:
                result = await run_in_thread(
                    execute_module,
                    client,
                    "post",
                    module_name,
                    merged_opts,
                    engagement_id=engagement_id,
                )
                logger.info("Post module %s on session %d started as job", module_name, session_id)
                return outputs.ok(
                    {
                        "module": module_name,
                        "session_id": session_id,
                        "execution_mode": "rpc_job",
                        "execution_result": result,
                        "engagement_id": engagement_id,
                    }
                )

            console_result = await run_in_thread(
                execute_module_via_console,
                client,
                "post",
                module_name,
                merged_opts,
                None,
                None,
                "run",
                post_timeout,
            )
            logger.info("Post module %s on session %d completed (console)", module_name, session_id)
            console_status = console_result.get("status", "error")
            result_data = {
                "module": module_name,
                "session_id": session_id,
                "execution_mode": "console",
                "module_output": console_result.get("module_output"),
                "engagement_id": engagement_id,
            }
            if console_status == "error":
                return outputs.error(
                    console_result.get("message", "Post module failed"),
                    data=result_data,
                )
            return outputs.ok(result_data, message=console_result.get("message"))
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Post module failed: %s", module_name)
            return outputs.error(f"Post module failed: {e}")
