"""Read-only MCP tools matching official msfmcpd tool surface.

8 tools: msf_search_modules, msf_module_info, msf_host_info, msf_service_info,
msf_vulnerability_info, msf_note_info, msf_credential_info, msf_loot_info.
"""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.models import inputs, outputs
from msf_harness.mcp.rpc.client import RpcConnectionError, get_rpc, run_in_thread, safe_rpc_call

logger = logging.getLogger("msf_harness.tools.read")


def _normalize_module_name(module_type: str, name: str) -> str:
    if name.startswith(f"{module_type}/"):
        return name.split("/", 1)[1]
    return name


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="msf_search_modules",
        annotations={"title": "Search Metasploit modules", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_search_modules(
        query: str,
        limit: int = inputs.DEFAULT_LIMIT,
        offset: int = inputs.DEFAULT_OFFSET,
    ) -> dict:
        """Search for Metasploit modules by keywords, CVE IDs, or module names."""
        if len(query) > inputs.MAX_QUERY_LENGTH:
            return outputs.error(f"Query too long (max {inputs.MAX_QUERY_LENGTH} chars)")
        limit = inputs.clamp_limit(limit)
        try:
            client = await run_in_thread(get_rpc)
            results = await run_in_thread(client.modules.search, query)
            total = len(results)
            page = results[offset : offset + limit]
            logger.info("Module search query=%r returned %d/%d results", query, len(page), total)
            return outputs.paginated(page, total, limit, offset)
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Module search failed")
            return outputs.error(f"Module search failed: {e}")

    @mcp.tool(
        name="msf_module_info",
        annotations={"title": "Get module details", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_module_info(module_type: str, module_name: str) -> dict:
        """Get detailed information about a specific Metasploit module including options, targets, and references."""
        err = inputs.validate_module_type(module_type)
        if err:
            return outputs.error(err)
        try:
            client = await run_in_thread(get_rpc)
            fullname = (
                module_name
                if "/" in module_name and not module_name.startswith(f"{module_type}/")
                else (module_name if module_name.startswith(f"{module_type}/") else f"{module_type}/{module_name}")
            )
            mod_path = _normalize_module_name(module_type, module_name)
            raw = await run_in_thread(client.call, "module.info", [module_type, mod_path])

            if isinstance(raw, dict):
                info = {
                    "type": raw.get("type", module_type),
                    "name": raw.get("name", module_name),
                    "fullname": raw.get("fullname", fullname),
                    "description": raw.get("description", ""),
                    "rank": raw.get("rank", ""),
                    "platform": raw.get("platform", []),
                    "options": raw.get("options", {}),
                    "required_options": [
                        k for k, v in (raw.get("options") or {}).items() if isinstance(v, dict) and v.get("required")
                    ],
                }
                if raw.get("references"):
                    info["references"] = raw["references"]
                if raw.get("targets"):
                    info["targets"] = raw["targets"]
                return outputs.ok(info)

            mod = await run_in_thread(client.modules.use, module_type, module_name)
            info = {
                "type": module_type,
                "name": module_name,
                "fullname": getattr(mod, "fullname", fullname),
                "description": getattr(mod, "description", ""),
                "authors": getattr(mod, "authors", []),
                "references": getattr(mod, "references", []),
                "rank": getattr(mod, "rank", ""),
                "options": getattr(mod, "options", {}),
                "required_options": getattr(mod, "required", []),
            }
            if hasattr(mod, "targets") and mod.targets:
                info["targets"] = mod.targets
            return outputs.ok(info)
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            return outputs.error(f"Module info failed: {e}")

    @mcp.tool(
        name="msf_host_info",
        annotations={"title": "Query discovered hosts", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_host_info(
        workspace: str = "default",
        addresses: str | None = None,
        only_up: bool = False,
        limit: int = inputs.DEFAULT_LIMIT,
        offset: int = inputs.DEFAULT_OFFSET,
    ) -> dict:
        """Query discovered hosts from the Metasploit database."""
        ws_err = inputs.validate_workspace(workspace)
        if ws_err:
            return outputs.error(ws_err)
        if addresses:
            ip_err = inputs.validate_ip(addresses)
            if ip_err:
                return outputs.error(ip_err)
        limit = inputs.clamp_limit(limit)
        try:
            kwargs: dict = {}
            if addresses:
                kwargs["addresses"] = addresses
            hosts = await run_in_thread(safe_rpc_call, "db.hosts", [{"workspace": workspace, **kwargs}])
            items = hosts.get("hosts", [])
            if only_up:
                items = [h for h in items if h.get("state") == "alive"]
            total = len(items)
            page = items[offset : offset + limit]
            logger.info("Host query workspace=%s returned %d/%d hosts", workspace, len(page), total)
            return outputs.paginated(page, total, limit, offset)
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Host query failed")
            return outputs.error(f"Host query failed: {e}")

    @mcp.tool(
        name="msf_service_info",
        annotations={"title": "Query discovered services", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_service_info(
        workspace: str = "default",
        host: str | None = None,
        ports: str | None = None,
        names: str | None = None,
        protocol: str | None = None,
        only_up: bool = False,
        limit: int = inputs.DEFAULT_LIMIT,
        offset: int = inputs.DEFAULT_OFFSET,
    ) -> dict:
        """Query discovered services on hosts."""
        ws_err = inputs.validate_workspace(workspace)
        if ws_err:
            return outputs.error(ws_err)
        if ports:
            port_err = inputs.validate_ports(ports)
            if port_err:
                return outputs.error(port_err)
        limit = inputs.clamp_limit(limit)
        try:
            kwargs: dict = {"workspace": workspace}
            if host:
                kwargs["addresses"] = host
            if ports:
                kwargs["ports"] = ports
            if names:
                kwargs["names"] = names
            if protocol:
                kwargs["proto"] = protocol
            services = await run_in_thread(safe_rpc_call, "db.services", [kwargs])
            items = services.get("services", [])
            if only_up:
                items = [s for s in items if s.get("state") == "open"]
            total = len(items)
            page = items[offset : offset + limit]
            logger.info("Service query workspace=%s returned %d/%d services", workspace, len(page), total)
            return outputs.paginated(page, total, limit, offset)
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Service query failed")
            return outputs.error(f"Service query failed: {e}")

    @mcp.tool(
        name="msf_vulnerability_info",
        annotations={"title": "Query discovered vulnerabilities", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_vulnerability_info(
        workspace: str = "default",
        host: str | None = None,
        ports: str | None = None,
        limit: int = inputs.DEFAULT_LIMIT,
        offset: int = inputs.DEFAULT_OFFSET,
    ) -> dict:
        """Query discovered vulnerabilities from the Metasploit database."""
        ws_err = inputs.validate_workspace(workspace)
        if ws_err:
            return outputs.error(ws_err)
        if ports:
            port_err = inputs.validate_ports(ports)
            if port_err:
                return outputs.error(port_err)
        limit = inputs.clamp_limit(limit)
        try:
            kwargs: dict = {"workspace": workspace}
            if host:
                kwargs["addresses"] = host
            if ports:
                kwargs["ports"] = ports
            vulns = await run_in_thread(safe_rpc_call, "db.vulns", [kwargs])
            items = vulns.get("vulns", [])
            total = len(items)
            page = items[offset : offset + limit]
            logger.info("Vuln query workspace=%s returned %d/%d vulns", workspace, len(page), total)
            return outputs.paginated(page, total, limit, offset)
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Vulnerability query failed")
            return outputs.error(f"Vulnerability query failed: {e}")

    @mcp.tool(
        name="msf_note_info",
        annotations={"title": "Query database notes", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_note_info(
        workspace: str = "default",
        host: str | None = None,
        ntype: str | None = None,
        limit: int = inputs.DEFAULT_LIMIT,
        offset: int = inputs.DEFAULT_OFFSET,
    ) -> dict:
        """Query notes stored in the Metasploit database."""
        ws_err = inputs.validate_workspace(workspace)
        if ws_err:
            return outputs.error(ws_err)
        limit = inputs.clamp_limit(limit)
        try:
            kwargs: dict = {"workspace": workspace}
            if host:
                kwargs["addresses"] = host
            if ntype:
                kwargs["ntype"] = ntype
            notes = await run_in_thread(safe_rpc_call, "db.notes", [kwargs])
            items = notes.get("notes", [])
            total = len(items)
            page = items[offset : offset + limit]
            return outputs.paginated(page, total, limit, offset)
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Note query failed")
            return outputs.error(f"Note query failed: {e}")

    @mcp.tool(
        name="msf_credential_info",
        annotations={"title": "Query discovered credentials", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_credential_info(
        workspace: str = "default",
        limit: int = inputs.DEFAULT_LIMIT,
        offset: int = inputs.DEFAULT_OFFSET,
    ) -> dict:
        """Query discovered credentials from the Metasploit database."""
        ws_err = inputs.validate_workspace(workspace)
        if ws_err:
            return outputs.error(ws_err)
        limit = inputs.clamp_limit(limit)
        try:
            creds = await run_in_thread(safe_rpc_call, "db.creds", [{"workspace": workspace}])
            items = creds.get("creds", [])
            total = len(items)
            page = items[offset : offset + limit]
            return outputs.paginated(page, total, limit, offset)
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Credential query failed")
            return outputs.error(f"Credential query failed: {e}")

    @mcp.tool(
        name="msf_loot_info",
        annotations={"title": "Query collected loot", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_loot_info(
        workspace: str = "default",
        limit: int = inputs.DEFAULT_LIMIT,
        offset: int = inputs.DEFAULT_OFFSET,
    ) -> dict:
        """Query collected loot (files, data dumps) from the Metasploit database."""
        ws_err = inputs.validate_workspace(workspace)
        if ws_err:
            return outputs.error(ws_err)
        limit = inputs.clamp_limit(limit)
        try:
            loot = await run_in_thread(safe_rpc_call, "db.loots", [{"workspace": workspace}])
            items = loot.get("loots", [])
            total = len(items)
            page = items[offset : offset + limit]
            return outputs.paginated(page, total, limit, offset)
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Loot query failed")
            return outputs.error(f"Loot query failed: {e}")
