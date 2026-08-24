"""MCP console bridge for running arbitrary msfconsole commands via RPC."""

from __future__ import annotations

import logging
import re

from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.models import outputs
from msf_harness.mcp.policy.roe import enforce_roe, was_check_run
from msf_harness.mcp.rpc.client import RpcConnectionError, run_in_thread, safe_rpc_call
from msf_harness.mcp.rpc.console import msf_console, run_console_command

logger = logging.getLogger("msf_harness.tools.console")

_RHOSTS_RE = re.compile(r"\b(?:set|setg)\s+(?:RHOSTS?|rhosts?)\s+(\S+)", re.IGNORECASE)
_MODULE_RE = re.compile(r"\buse\s+((?:exploit|auxiliary|post|payload)/\S+)", re.IGNORECASE)
_DB_NMAP_RE = re.compile(r"\bdb_nmap\b.*?\s([\d./,\s]+)", re.IGNORECASE)
_EXPLOIT_VERB_RE = re.compile(r"\b(?:exploit|run)\b", re.IGNORECASE)


def _extract_console_targets(command: str) -> list[str]:
    """Pull IPs/CIDRs from set RHOSTS and db_nmap commands."""
    targets: list[str] = []
    for m in _RHOSTS_RE.finditer(command):
        targets.extend(m.group(1).replace(",", " ").split())
    for m in _DB_NMAP_RE.finditer(command):
        targets.extend(m.group(1).replace(",", " ").split())
    return [t.strip() for t in targets if t.strip()]


def _extract_console_modules(command: str) -> list[str]:
    return [m.group(1) for m in _MODULE_RE.finditer(command)]


def _console_has_exploit_verb(command: str) -> bool:
    """Return True if the command contains exploit/run verbs."""
    return bool(_EXPLOIT_VERB_RE.search(command))


def _console_has_exploit_module(modules: list[str]) -> bool:
    """Return True if any extracted module is an exploit type."""
    return any(m.startswith("exploit/") for m in modules)


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="msf_console_execute",
        annotations={
            "title": "Run msfconsole command",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
    )
    async def msf_console_execute(
        engagement_id: str,
        command: str,
        timeout: int = 60,
    ) -> dict:
        """Execute a raw msfconsole command via the RPC console API.

        Creates a temporary console, runs the command, collects output, then
        destroys the console. Use for operations not covered by other MCP tools.
        Requires engagement_id for ROE enforcement.

        The command string is parsed for targets (set RHOSTS, db_nmap) and module
        paths (use exploit/...) to enforce scope, module, and exploit-gate
        restrictions. If the command runs an exploit, the check-before-exploit
        gate applies.
        """
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        if not command.strip():
            return outputs.error("Command cannot be empty")

        _MAX_COMMAND_LENGTH = 4096
        if len(command) > _MAX_COMMAND_LENGTH:
            return outputs.error(f"Command too long ({len(command)} chars). Max is {_MAX_COMMAND_LENGTH}.")

        if "\n" in command or "\r" in command:
            return outputs.error("Multi-line commands are not allowed. Use separate msf_console_execute calls.")
        if ";" in command:
            logger.warning("Console command contains semicolons (multi-command): %r", command[:200])

        extracted_targets = _extract_console_targets(command)
        for target in extracted_targets:
            target_denial = enforce_roe(engagement_id, targets=target)
            if target_denial:
                return target_denial

        extracted_modules = _extract_console_modules(command)
        for module_path in extracted_modules:
            mod_denial = enforce_roe(engagement_id, module_path=module_path)
            if mod_denial:
                return mod_denial

        if _console_has_exploit_verb(command) and _console_has_exploit_module(extracted_modules):
            exploit_module = extracted_modules[0] if extracted_modules else None
            exploit_target = extracted_targets[0] if extracted_targets else None
            check_done = was_check_run(engagement_id, exploit_module or "", exploit_target)
            exploit_denial = enforce_roe(
                engagement_id,
                targets=exploit_target,
                module_path=exploit_module,
                is_exploit=True,
                check_was_run=check_done,
                check_sessions=True,
            )
            if exploit_denial:
                return exploit_denial

        timeout_secs = max(5, min(timeout, 300))

        try:
            from msf_harness.mcp.rpc.client import get_rpc

            def _run_console_cmd() -> tuple[str, bool]:
                client = get_rpc()
                with msf_console(client) as console:
                    logger.info("Console executing: %r (timeout=%ds)", command[:200], timeout_secs)
                    return run_console_command(console, command, timeout=timeout_secs)

            full_output, timed_out = await run_in_thread(_run_console_cmd)

            if timed_out:
                return outputs.error(
                    f"Console command timed out after {timeout_secs}s (partial output available)",
                    code="timeout",
                    data={
                        "command": command,
                        "output": full_output,
                        "timed_out": True,
                        "engagement_id": engagement_id,
                    },
                )

            return outputs.ok(
                {
                    "command": command,
                    "output": full_output,
                    "timed_out": False,
                    "engagement_id": engagement_id,
                }
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Console execute failed")
            return outputs.error(f"Console execute failed: {e}")

    @mcp.tool(
        name="msf_console_list",
        annotations={"title": "List active consoles", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_console_list() -> dict:
        """List all active msfconsole instances managed via RPC."""
        try:
            result = await run_in_thread(safe_rpc_call, "console.list", [])
            consoles = result.get("consoles", []) if isinstance(result, dict) else []
            logger.info("Listed %d active console(s)", len(consoles))
            return outputs.ok(consoles, message=f"{len(consoles)} active console(s)")
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Console list failed")
            return outputs.error(f"Console list failed: {e}")
