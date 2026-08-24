"""Route and pivot management MCP tools for multi-subnet engagements.

Exposes route operations (list, add, delete) and autoroute post-module
for establishing connectivity to otherwise unreachable targets through
compromised sessions.
"""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.models import inputs, outputs
from msf_harness.mcp.policy.roe import enforce_roe
from msf_harness.mcp.rpc.client import RpcConnectionError, get_rpc, run_in_thread
from msf_harness.mcp.rpc.console import msf_console, run_console_command
from msf_harness.mcp.rpc.execute import execute_module

logger = logging.getLogger("msf_harness.tools.route")


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="msf_route_list",
        annotations={
            "title": "List active routes",
            "readOnlyHint": True,
            "destructiveHint": False,
        },
    )
    async def msf_route_list() -> dict:
        """List all active routes configured in Metasploit for session pivoting."""
        try:

            def _list_routes() -> str:
                client = get_rpc()
                with msf_console(client) as console:
                    return run_console_command(console, "route print", timeout=15)

            output = await run_in_thread(_list_routes)
            return outputs.ok(
                {
                    "routes": output.strip(),
                },
                message="Current routes listed",
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Route list failed")
            return outputs.error(f"Route list failed: {e}")

    @mcp.tool(
        name="msf_route_add",
        annotations={
            "title": "Add route through session",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_route_add(
        engagement_id: str,
        subnet: str,
        netmask: str,
        session_id: int,
    ) -> dict:
        """Add a route to a subnet through a Meterpreter session for pivoting.

        The target subnet must be in scope per ROE.
        """
        denial = enforce_roe(engagement_id, targets=subnet)
        if denial:
            return denial

        ip_err = inputs.validate_ip(subnet)
        if ip_err:
            return outputs.error(ip_err)
        mask_err = inputs.validate_netmask(netmask)
        if mask_err:
            return outputs.error(mask_err)
        safe_err = inputs.validate_console_safe(subnet, "subnet") or inputs.validate_console_safe(netmask, "netmask")
        if safe_err:
            return outputs.error(safe_err)

        try:

            def _add_route() -> str:
                client = get_rpc()
                with msf_console(client) as console:
                    cmd = f"route add {subnet} {netmask} {session_id}"
                    return run_console_command(console, cmd, timeout=15)

            output = await run_in_thread(_add_route)
            logger.info("Added route %s/%s via session %d", subnet, netmask, session_id)
            return outputs.ok(
                {
                    "subnet": subnet,
                    "netmask": netmask,
                    "session_id": session_id,
                    "output": output.strip(),
                    "engagement_id": engagement_id,
                },
                message=f"Route added: {subnet}/{netmask} via session {session_id}",
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Route add failed")
            return outputs.error(f"Route add failed: {e}")

    @mcp.tool(
        name="msf_route_delete",
        annotations={
            "title": "Remove a route",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_route_delete(
        engagement_id: str,
        subnet: str,
        netmask: str,
    ) -> dict:
        """Remove an active route from Metasploit's routing table."""
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        ip_err = inputs.validate_ip(subnet)
        if ip_err:
            return outputs.error(ip_err)
        mask_err = inputs.validate_netmask(netmask)
        if mask_err:
            return outputs.error(mask_err)
        safe_err = inputs.validate_console_safe(subnet, "subnet") or inputs.validate_console_safe(netmask, "netmask")
        if safe_err:
            return outputs.error(safe_err)

        try:

            def _del_route() -> str:
                client = get_rpc()
                with msf_console(client) as console:
                    cmd = f"route remove {subnet} {netmask}"
                    return run_console_command(console, cmd, timeout=15)

            output = await run_in_thread(_del_route)
            logger.info("Removed route %s/%s", subnet, netmask)
            return outputs.ok(
                {
                    "subnet": subnet,
                    "netmask": netmask,
                    "output": output.strip(),
                    "engagement_id": engagement_id,
                },
                message=f"Route removed: {subnet}/{netmask}",
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Route delete failed")
            return outputs.error(f"Route delete failed: {e}")

    @mcp.tool(
        name="msf_autoroute",
        annotations={
            "title": "Autoroute via session",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_autoroute(
        engagement_id: str,
        session_id: int,
        subnet: str | None = None,
    ) -> dict:
        """Run post/multi/manage/autoroute on a session to auto-add routes.

        If subnet is specified, it must be in scope. If omitted, autoroute
        discovers reachable subnets from the session.
        """
        denial = enforce_roe(engagement_id, targets=subnet)
        if denial:
            return denial

        try:
            client = await run_in_thread(get_rpc)
            opts = {"SESSION": str(session_id), "CMD": "autoadd"}
            if subnet:
                opts["SUBNET"] = subnet
            result = await run_in_thread(
                execute_module,
                client,
                "post",
                "multi/manage/autoroute",
                opts,
            )
            logger.info("Autoroute on session %d completed", session_id)
            return outputs.ok(
                {
                    "session_id": session_id,
                    "subnet": subnet,
                    "result": result,
                    "engagement_id": engagement_id,
                },
                message=f"Autoroute completed on session {session_id}",
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Autoroute failed on session %d", session_id)
            return outputs.error(f"Autoroute failed: {e}")
