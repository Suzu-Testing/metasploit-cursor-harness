"""Database write tools and status queries.

Extends the read-only db.* surface with write operations (report host,
add note, store credential) that require engagement_id and ROE scope
validation, plus a standalone db.status check.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.models import inputs, outputs
from msf_harness.mcp.policy.roe import enforce_roe
from msf_harness.mcp.rpc.client import RpcConnectionError, run_in_thread, safe_rpc_call

logger = logging.getLogger("msf_harness.tools.db")


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="msf_report_host",
        annotations={
            "title": "Report host to database",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_report_host(
        engagement_id: str,
        host: str,
        os_name: str | None = None,
        os_flavor: str | None = None,
        os_sp: str | None = None,
        name: str | None = None,
        purpose: str | None = None,
        info: str | None = None,
        workspace: str = "default",
    ) -> dict:
        """Manually report a host to the Metasploit database. Host must be in scope."""
        ip_err = inputs.validate_ip(host)
        if ip_err:
            return outputs.error(ip_err)
        ws_err = inputs.validate_workspace(workspace)
        if ws_err:
            return outputs.error(ws_err)

        denial = enforce_roe(engagement_id, targets=host)
        if denial:
            return denial

        try:
            report_args = {"host": host, "workspace": workspace}
            if os_name:
                report_args["os_name"] = os_name
            if os_flavor:
                report_args["os_flavor"] = os_flavor
            if os_sp:
                report_args["os_sp"] = os_sp
            if name:
                report_args["name"] = name
            if purpose:
                report_args["purpose"] = purpose
            if info:
                report_args["info"] = info

            result = await run_in_thread(safe_rpc_call, "db.report_host", [report_args])
            logger.info("Reported host %s to workspace %s", host, workspace)
            return outputs.ok(
                {
                    "host": host,
                    "workspace": workspace,
                    "result": result,
                    "engagement_id": engagement_id,
                },
                message=f"Host {host} reported to database",
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Report host failed for %s", host)
            return outputs.error(f"Report host failed: {e}")

    @mcp.tool(
        name="msf_credential_add",
        annotations={
            "title": "Store credential in database",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_credential_add(
        engagement_id: str,
        host: str,
        port: int,
        username: str,
        private_data: str,
        private_type: str = "password",
        service_name: str | None = None,
        protocol: str = "tcp",
        workspace: str = "default",
    ) -> dict:
        """Store a discovered credential in the Metasploit database.

        private_type should be one of: password, ntlm_hash, ssh_key.
        The target host must be in scope.
        """
        ip_err = inputs.validate_ip(host)
        if ip_err:
            return outputs.error(ip_err)
        ws_err = inputs.validate_workspace(workspace)
        if ws_err:
            return outputs.error(ws_err)

        denial = enforce_roe(engagement_id, targets=host)
        if denial:
            return denial

        if not (1 <= port <= 65535):
            return outputs.error(f"Invalid port: {port}. Must be 1-65535.")

        if private_type not in ("password", "ntlm_hash", "ssh_key"):
            return outputs.error(f"Invalid private_type: {private_type}. Must be one of: password, ntlm_hash, ssh_key.")

        try:
            cred_args = {
                "workspace": workspace,
                "host": host,
                "port": port,
                "username": username,
                "private_data": private_data,
                "private_type": private_type,
                "protocol": protocol,
            }
            if service_name:
                cred_args["service_name"] = service_name

            result = await run_in_thread(
                safe_rpc_call,
                "db.create_credential",
                [cred_args],
            )
            logger.info(
                "Stored credential for %s@%s:%d in workspace %s",
                username,
                host,
                port,
                workspace,
            )
            return outputs.ok(
                {
                    "host": host,
                    "port": port,
                    "username": username,
                    "private_type": private_type,
                    "workspace": workspace,
                    "result": result,
                    "engagement_id": engagement_id,
                },
                message=f"Credential stored: {username}@{host}:{port}",
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Credential add failed for %s@%s:%d", username, host, port)
            return outputs.error(f"Credential add failed: {e}")

    @mcp.tool(
        name="msf_db_add_note",
        annotations={
            "title": "Add note to database",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_db_add_note(
        engagement_id: str,
        ntype: str,
        data: str,
        host: str | None = None,
        port: int | None = None,
        protocol: str | None = None,
        workspace: str = "default",
    ) -> dict:
        """Add a note/annotation to the Metasploit database.

        Notes are typed free-form data attached to hosts or services.
        Common ntypes: host.os, host.info, service.info, vuln.detail.
        If host is provided, it must be in scope.
        """
        if host:
            denial = enforce_roe(engagement_id, targets=host)
        else:
            denial = enforce_roe(engagement_id)
        if denial:
            return denial

        ws_err = inputs.validate_workspace(workspace)
        if ws_err:
            return outputs.error(ws_err)

        if not ntype.strip():
            return outputs.error("Note type (ntype) cannot be empty")

        try:
            note_args: dict[str, Any] = {
                "workspace": workspace,
                "type": ntype,
                "data": data,
            }
            if host:
                note_args["host"] = host
            if port is not None:
                note_args["port"] = port
            if protocol:
                note_args["proto"] = protocol

            result = await run_in_thread(
                safe_rpc_call,
                "db.report_note",
                [note_args],
            )
            logger.info("Added note type=%s host=%s workspace=%s", ntype, host, workspace)
            return outputs.ok(
                {
                    "ntype": ntype,
                    "host": host,
                    "workspace": workspace,
                    "result": result,
                    "engagement_id": engagement_id,
                },
                message=f"Note added: {ntype}" + (f" on {host}" if host else ""),
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Add note failed for type=%s host=%s", ntype, host)
            return outputs.error(f"Add note failed: {e}")

    @mcp.tool(
        name="msf_db_status",
        annotations={
            "title": "Check database status",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_db_status() -> dict:
        """Check Metasploit database connectivity and driver information.

        Separate from msf_status which checks RPC connectivity. This tool
        verifies the PostgreSQL backend is connected and reports the
        database driver and name.
        """
        try:
            result = await run_in_thread(safe_rpc_call, "db.status", [])
            if isinstance(result, dict):
                return outputs.ok(
                    {
                        "driver": result.get("driver", "unknown"),
                        "db": result.get("db", "unknown"),
                    }
                )
            return outputs.ok({"raw": result})
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("DB status check failed")
            return outputs.error(f"DB status check failed: {e}")
