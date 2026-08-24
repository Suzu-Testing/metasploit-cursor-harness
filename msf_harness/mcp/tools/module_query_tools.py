"""Module intelligence query tools: options, results, running stats, list by type.

Provides focused module introspection tools that agents need constantly
during reconnaissance and exploitation planning. Complements the
broader msf_search_modules and msf_module_info in read_tools.py.
"""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.models import inputs, outputs
from msf_harness.mcp.policy.roe import enforce_roe
from msf_harness.mcp.rpc.client import RpcConnectionError, get_rpc, run_in_thread, safe_rpc_call

logger = logging.getLogger("msf_harness.tools.module_query")

_MODULE_TYPE_ATTR = {
    "exploit": "exploits",
    "auxiliary": "auxiliary",
    "post": "post",
    "payload": "payloads",
    "encoder": "encoders",
    "nop": "nops",
}


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="msf_module_options",
        annotations={
            "title": "Get module options",
            "readOnlyHint": True,
            "destructiveHint": False,
        },
    )
    async def msf_module_options(module_type: str, module_name: str) -> dict:
        """Get only the configurable options for a module.

        Returns each option's required status, default value, type, and
        description. Much lighter than msf_module_info for agents that
        just need to know what to set before running a module.
        """
        err = inputs.validate_module_type(module_type)
        if err:
            return outputs.error(err)

        try:
            client = await run_in_thread(get_rpc)
            base_name = module_name
            if module_name.startswith(f"{module_type}/"):
                base_name = module_name.split("/", 1)[1]

            raw = await run_in_thread(client.call, "module.info", [module_type, base_name])

            if isinstance(raw, dict) and raw.get("options"):
                options = raw["options"]
                required = [k for k, v in options.items() if isinstance(v, dict) and v.get("required")]
                return outputs.ok(
                    {
                        "module": f"{module_type}/{base_name}",
                        "options": options,
                        "required_options": required,
                    }
                )

            mod = await run_in_thread(client.modules.use, module_type, base_name)
            options = getattr(mod, "options", {})
            required = getattr(mod, "required", [])
            return outputs.ok(
                {
                    "module": f"{module_type}/{base_name}",
                    "options": options,
                    "required_options": required,
                }
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Module options query failed for %s/%s", module_type, module_name)
            return outputs.error(f"Module options query failed: {e}")

    @mcp.tool(
        name="msf_module_results",
        annotations={
            "title": "Get async module job results",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_module_results(engagement_id: str, uuid: str) -> dict:
        """Query results of an async module execution by its UUID.

        When a module is run as a background job (run_as_job=True), it
        returns a UUID. Use this tool to check whether the job has
        completed and retrieve its output.
        """
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        if not uuid.strip():
            return outputs.error("UUID cannot be empty")

        try:
            result = await run_in_thread(
                safe_rpc_call,
                "module.results",
                [uuid.strip()],
            )
            return outputs.ok(
                {
                    "uuid": uuid,
                    "results": result,
                    "engagement_id": engagement_id,
                }
            )
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Module results query failed for UUID %s", uuid)
            return outputs.error(f"Module results query failed: {e}")

    @mcp.tool(
        name="msf_running_stats",
        annotations={
            "title": "Get running module statistics",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_running_stats() -> dict:
        """Get statistics on currently running modules (waiting, running, results).

        Useful for understanding what Metasploit is currently executing
        and whether async jobs have completed.
        """
        try:
            result = await run_in_thread(
                safe_rpc_call,
                "module.running_stats",
                [],
            )
            return outputs.ok(result if isinstance(result, dict) else {"raw": result})
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Running stats query failed")
            return outputs.error(f"Running stats query failed: {e}")

    @mcp.tool(
        name="msf_list_modules",
        annotations={
            "title": "List modules by type",
            "readOnlyHint": True,
            "destructiveHint": False,
        },
    )
    async def msf_list_modules(
        module_type: str,
        query: str = "",
        limit: int = inputs.DEFAULT_LIMIT,
        offset: int = inputs.DEFAULT_OFFSET,
    ) -> dict:
        """List Metasploit modules of a specific type with optional keyword filter.

        More targeted than msf_search_modules: specify the module type
        (exploit, auxiliary, post, payload, encoder, nop) and get a
        filtered list back. Good for browsing available modules of a
        given category.
        """
        err = inputs.validate_module_type(module_type)
        if err:
            return outputs.error(err)

        attr_name = _MODULE_TYPE_ATTR.get(module_type)
        if not attr_name:
            return outputs.error(f"Unsupported module type for listing: {module_type}")

        limit = inputs.clamp_limit(limit)

        try:
            client = await run_in_thread(get_rpc)
            all_modules = await run_in_thread(getattr, client.modules, attr_name)

            if query:
                query_lower = query.lower()
                filtered = [m for m in all_modules if query_lower in m.lower()]
            else:
                filtered = list(all_modules)

            total = len(filtered)
            page = filtered[offset : offset + limit]
            logger.info(
                "Listed %d/%d %s modules (query=%r)",
                len(page),
                total,
                module_type,
                query,
            )
            return outputs.paginated(page, total, limit, offset)
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Module listing failed for type %s", module_type)
            return outputs.error(f"Module listing failed: {e}")
