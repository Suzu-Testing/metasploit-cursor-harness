"""Workspace management and database import MCP tools."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.models import inputs, outputs
from msf_harness.mcp.policy.roe import PROJECT_ROOT, enforce_roe
from msf_harness.mcp.rpc.client import RpcConnectionError, get_rpc, run_in_thread, safe_rpc_call
from msf_harness.mcp.rpc.console import msf_console, run_console_command

logger = logging.getLogger("msf_harness.tools.workspace")

_ALLOWED_IMPORT_DIRS = (
    PROJECT_ROOT / "evidence",
    PROJECT_ROOT / "engagements",
)
_ALLOWED_IMPORT_EXTS = {".xml", ".nessus", ".csv", ".json", ".txt"}

_NMAP_ARG_RE = re.compile(r"^-[a-zA-Z0-9]+$")
_NMAP_VALUE_RE = re.compile(r"^[\w.,/:=-]+$")


def _validate_safe_path(raw_path: str, allowed_dirs: tuple[Path, ...]) -> Path | str:
    """Resolve path and reject traversal or paths outside allowed dirs.

    Returns the resolved Path on success, or an error string on failure.
    """
    p = Path(raw_path)
    if p.is_absolute():
        resolved = p.resolve()
    else:
        resolved = (PROJECT_ROOT / p).resolve()

    if ".." in p.parts:
        return f"Path traversal not allowed: {raw_path}"

    for allowed in allowed_dirs:
        try:
            resolved.relative_to(allowed.resolve())
            return resolved
        except ValueError:
            continue
    return f"Path must be inside {' or '.join(str(d) for d in allowed_dirs)}: {raw_path}"


def _sanitize_nmap_args(nmap_args: str) -> str | None:
    """Validate nmap_args against an allowlist of safe flag patterns.

    Returns None on success, or an error string if a suspicious token is found.
    """
    tokens = nmap_args.split()
    for token in tokens:
        if _NMAP_ARG_RE.match(token):
            continue
        if _NMAP_VALUE_RE.match(token):
            continue
        return f"Disallowed nmap argument: {token!r}. Only standard nmap flags are permitted."
    return None


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="msf_list_workspaces",
        annotations={"title": "List workspaces", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_list_workspaces() -> dict:
        """List all Metasploit database workspaces."""
        try:
            result = await run_in_thread(safe_rpc_call, "db.workspaces", [])
            workspaces = result.get("workspaces", []) if isinstance(result, dict) else []
            logger.info("Listed %d workspace(s)", len(workspaces))
            return outputs.ok(workspaces, message=f"{len(workspaces)} workspace(s)")
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Workspace list failed")
            return outputs.error(f"Workspace list failed: {e}")

    @mcp.tool(
        name="msf_create_workspace",
        annotations={
            "title": "Create workspace",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_create_workspace(
        engagement_id: str,
        name: str,
    ) -> dict:
        """Create a new Metasploit database workspace. Requires engagement_id for ROE."""
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        ws_err = inputs.validate_workspace(name)
        if ws_err:
            return outputs.error(ws_err)

        try:
            result = await run_in_thread(safe_rpc_call, "db.add_workspace", [name])
            logger.info("Created workspace: %s", name)
            return outputs.ok(
                {
                    "workspace": name,
                    "result": result,
                    "engagement_id": engagement_id,
                },
                message=f"Workspace '{name}' created",
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Workspace creation failed: %s", name)
            return outputs.error(f"Workspace creation failed: {e}")

    @mcp.tool(
        name="msf_set_workspace",
        annotations={
            "title": "Switch active workspace",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_set_workspace(
        engagement_id: str,
        name: str,
    ) -> dict:
        """Switch the active Metasploit database workspace. Requires engagement_id for ROE."""
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        ws_err = inputs.validate_workspace(name)
        if ws_err:
            return outputs.error(ws_err)

        try:
            result = await run_in_thread(safe_rpc_call, "db.set_workspace", [name])
            logger.info("Switched to workspace: %s", name)
            return outputs.ok(
                {
                    "workspace": name,
                    "result": result,
                    "engagement_id": engagement_id,
                },
                message=f"Active workspace set to '{name}'",
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Workspace switch failed: %s", name)
            return outputs.error(f"Workspace switch failed: {e}")

    @mcp.tool(
        name="msf_delete_workspace",
        annotations={
            "title": "Delete workspace",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": True,
        },
    )
    async def msf_delete_workspace(
        engagement_id: str,
        name: str,
    ) -> dict:
        """Delete a Metasploit database workspace. Cannot delete 'default'."""
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        ws_err = inputs.validate_workspace(name)
        if ws_err:
            return outputs.error(ws_err)

        if name.lower() == "default":
            return outputs.error("Cannot delete the 'default' workspace")

        try:
            result = await run_in_thread(safe_rpc_call, "db.del_workspace", [name])
            logger.info("Deleted workspace: %s", name)
            return outputs.ok(
                {
                    "workspace": name,
                    "result": result,
                    "engagement_id": engagement_id,
                },
                message=f"Workspace '{name}' deleted",
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Workspace deletion failed: %s", name)
            return outputs.error(f"Workspace deletion failed: {e}")

    @mcp.tool(
        name="msf_db_import",
        annotations={
            "title": "Import scan data into DB",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_db_import(
        engagement_id: str,
        file_path: str,
        workspace: str = "default",
    ) -> dict:
        """Import scan data (nmap XML, Nessus, etc.) into the Metasploit database.

        Requires engagement_id. File must be in evidence/ or engagements/ directories.
        """
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        ws_err = inputs.validate_workspace(workspace)
        if ws_err:
            return outputs.error(ws_err)

        result = _validate_safe_path(file_path, _ALLOWED_IMPORT_DIRS)
        if isinstance(result, str):
            return outputs.error(result)
        data_path = result

        if data_path.suffix.lower() not in _ALLOWED_IMPORT_EXTS:
            return outputs.error(
                f"Unsupported file type: {data_path.suffix}. Allowed: {', '.join(sorted(_ALLOWED_IMPORT_EXTS))}"
            )

        if not data_path.exists():
            return outputs.error(f"File not found: {file_path}")

        try:
            raw_bytes = data_path.read_bytes()
            data = raw_bytes.decode("utf-8", errors="replace")
            rpc_result = await run_in_thread(safe_rpc_call, "db.import_data", [{"workspace": workspace, "data": data}])
            logger.info("Imported %s into workspace %s", data_path, workspace)
            return outputs.ok(
                {
                    "file": str(data_path),
                    "workspace": workspace,
                    "result": rpc_result,
                    "engagement_id": engagement_id,
                },
                message=f"Imported {data_path.name} into workspace '{workspace}'",
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("DB import failed: %s", file_path)
            return outputs.error(f"DB import failed: {e}")

    @mcp.tool(
        name="msf_db_nmap",
        annotations={
            "title": "Run nmap and import results",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
    )
    async def msf_db_nmap(
        engagement_id: str,
        targets: str,
        nmap_args: str = "-sV -sC",
        workspace: str = "default",
    ) -> dict:
        """Run nmap via Metasploit's db_nmap and auto-import results.

        Requires engagement_id for ROE. Targets and nmap_args are validated
        against scope and an allowlist of safe flags respectively.
        """
        denial = enforce_roe(engagement_id, targets=targets)
        if denial:
            return denial

        ws_err = inputs.validate_workspace(workspace)
        if ws_err:
            return outputs.error(ws_err)

        nmap_err = _sanitize_nmap_args(nmap_args)
        if nmap_err:
            return outputs.error(nmap_err)

        for target_token in targets.replace(",", " ").split():
            ip_err = inputs.validate_ip(target_token.strip())
            if ip_err:
                return outputs.error(ip_err)

        try:

            def _run_db_nmap() -> str:
                client = get_rpc()
                with msf_console(client) as console:
                    run_console_command(console, f"workspace {workspace}", timeout=10)
                    return run_console_command(
                        console,
                        f"db_nmap {nmap_args} {targets}",
                        timeout=240,
                    )

            full_output = await run_in_thread(_run_db_nmap)

            logger.info("db_nmap completed on %s in workspace %s", targets, workspace)

            return outputs.ok(
                {
                    "targets": targets,
                    "nmap_args": nmap_args,
                    "workspace": workspace,
                    "output": full_output,
                    "engagement_id": engagement_id,
                },
                message=f"db_nmap scan of {targets} complete",
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("db_nmap failed for targets %s", targets)
            return outputs.error(f"db_nmap failed: {e}")
