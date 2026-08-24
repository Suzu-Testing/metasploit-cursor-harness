"""Handler/listener management MCP tools: list, start, stop."""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.models import inputs, outputs
from msf_harness.mcp.models.inputs import parse_options_gracefully
from msf_harness.mcp.policy.roe import enforce_roe
from msf_harness.mcp.rpc.client import RpcConnectionError, get_rpc, run_in_thread, safe_rpc_call
from msf_harness.mcp.rpc.execute import execute_module

logger = logging.getLogger("msf_harness.tools.handler")


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="msf_list_listeners",
        annotations={"title": "List active handlers", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_list_listeners() -> dict:
        """Show all active handlers and background jobs in Metasploit."""
        try:
            client = await run_in_thread(get_rpc)
            jobs = await run_in_thread(getattr, client.jobs, "list")
            items = []
            if isinstance(jobs, dict):
                for jid, info in jobs.items():
                    items.append({"job_id": jid, **(info if isinstance(info, dict) else {"name": info})})
            return outputs.ok(items, message=f"{len(items)} active job(s)")
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Job list failed")
            return outputs.error(f"Job list failed: {e}")

    @mcp.tool(
        name="msf_job_info",
        annotations={
            "title": "Get job details",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_job_info(job_id: int) -> dict:
        """Get detailed information about a specific running job.

        Returns the module name, datastore options, start time, and
        current status. Use msf_list_listeners to see all jobs first,
        then this tool for details on a specific one.
        """
        try:
            client = await run_in_thread(get_rpc)
            jobs = await run_in_thread(getattr, client.jobs, "list")
            jid_str = str(job_id)
            if not isinstance(jobs, dict) or jid_str not in jobs:
                return outputs.error(f"Job {job_id} not found")

            info = jobs[jid_str]
            try:
                detail = await run_in_thread(client.call, "job.info", [job_id])
            except Exception:
                detail = None

            result: dict = {"job_id": job_id}
            if isinstance(info, dict):
                result.update(info)
            else:
                result["name"] = str(info)
            if isinstance(detail, dict):
                result["detail"] = detail

            return outputs.ok(result)
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Job info failed for job %d", job_id)
            return outputs.error(f"Job info failed: {e}")

    @mcp.tool(
        name="msf_start_listener",
        annotations={
            "title": "Start multi/handler",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
        },
    )
    async def msf_start_listener(
        engagement_id: str,
        payload: str,
        lhost: str,
        lport: int,
        options: dict[str, Any] | None = None,
    ) -> dict:
        """Create a new multi/handler listener. Requires engagement_id. WARNING: opens a network port."""
        if not (1 <= lport <= 65535):
            return outputs.error(f"Invalid port: {lport}. Must be 1-65535.")

        ip_err = inputs.validate_ip(lhost)
        if ip_err:
            return outputs.error(f"Invalid lhost: {ip_err}")

        denial = enforce_roe(engagement_id, check_sessions=True)
        if denial:
            return denial

        try:
            options = parse_options_gracefully(options)
        except ValueError as e:
            return outputs.error(str(e))

        try:
            client = await run_in_thread(get_rpc)
            handler_options = {
                "PAYLOAD": payload,
                "LHOST": lhost,
                "LPORT": str(lport),
                **(options or {}),
            }
            logger.info("Starting handler: %s on %s:%d", payload, lhost, lport)
            result = await run_in_thread(execute_module, client, "exploit", "multi/handler", handler_options)
            return outputs.ok(
                {
                    "payload": payload,
                    "lhost": lhost,
                    "lport": lport,
                    "result": result,
                    "engagement_id": engagement_id,
                }
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Handler start failed")
            return outputs.error(f"Handler start failed: {e}")

    @mcp.tool(
        name="msf_stop_job",
        annotations={
            "title": "Stop background job",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": True,
        },
    )
    async def msf_stop_job(engagement_id: str, job_id: int) -> dict:
        """Terminate a running job or handler by ID. Requires engagement_id for ROE."""
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        try:
            await run_in_thread(get_rpc)
            result = await run_in_thread(safe_rpc_call, "job.stop", [job_id])
            logger.info("Stopped job %d", job_id)
            return outputs.ok({"job_id": job_id, "stopped": True, "result": result, "engagement_id": engagement_id})
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Job stop failed for job %d", job_id)
            return outputs.error(f"Job stop failed: {e}")
