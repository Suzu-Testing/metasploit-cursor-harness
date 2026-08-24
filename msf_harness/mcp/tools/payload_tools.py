"""Payload listing and generation MCP tools."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.models import inputs, outputs
from msf_harness.mcp.models.inputs import parse_options_gracefully
from msf_harness.mcp.policy.roe import PROJECT_ROOT, enforce_roe
from msf_harness.mcp.rpc.client import RpcConnectionError, get_rpc, run_in_thread

logger = logging.getLogger("msf_harness.tools.payload")

EVIDENCE_DIR = PROJECT_ROOT / "evidence" / "msf"

_ALLOWED_OUTPUT_DIRS = (
    PROJECT_ROOT / "evidence",
    PROJECT_ROOT / "engagements",
)


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="msf_list_payloads",
        annotations={"title": "List available payloads", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_list_payloads(
        query: str = "",
        platform: str | None = None,
        arch: str | None = None,
    ) -> dict:
        """Search and list available Metasploit payload modules with optional filtering."""
        if len(query) > inputs.MAX_QUERY_LENGTH:
            return outputs.error(f"Query too long ({len(query)} chars). Max is {inputs.MAX_QUERY_LENGTH}.")
        try:
            client = await run_in_thread(get_rpc)
            payloads = await run_in_thread(getattr, client.modules, "payloads")
            results = []
            for p in payloads:
                name = p if isinstance(p, str) else str(p)
                if query and query.lower() not in name.lower():
                    continue
                if platform and platform.lower() not in name.lower():
                    continue
                if arch and arch.lower() not in name.lower():
                    continue
                results.append(name)
            return outputs.ok(results, message=f"{len(results)} payload(s) found")
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Payload list failed")
            return outputs.error(f"Payload list failed: {e}")

    @mcp.tool(
        name="msf_generate_payload",
        annotations={
            "title": "Generate payload file",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def msf_generate_payload(
        engagement_id: str,
        payload: str,
        format: str = "raw",
        options: dict[str, Any] | None = None,
        output_path: str | None = None,
        encoder: str | None = None,
        iterations: int = 0,
        bad_chars: str | None = None,
        nop_sled_size: int = 0,
        template_path: str | None = None,
        force_encode: bool = False,
        output_filename: str | None = None,
    ) -> dict:
        """Generate a payload file using Metasploit. Saves to evidence/msf/ by default.

        Supports advanced generation options: encoder (e.g. x86/shikata_ga_nai),
        encoding iterations, bad character avoidance, NOP sled, and template
        injection for AV evasion. Requires engagement_id.
        """
        denial = enforce_roe(engagement_id)
        if denial:
            return denial

        try:
            options = parse_options_gracefully(options)
        except ValueError as e:
            return outputs.error(str(e))

        try:
            client = await run_in_thread(get_rpc)
            mod = await run_in_thread(client.modules.use, "payload", payload)
            for k, v in (options or {}).items():
                mod[k] = v

            generate_opts = {**mod.runoptions, "format": format}

            if encoder:
                generate_opts["Encoder"] = encoder
            if iterations > 0:
                generate_opts["Iterations"] = iterations
            if bad_chars is not None:
                generate_opts["BadChars"] = bad_chars
            if nop_sled_size > 0:
                generate_opts["NopSledSize"] = nop_sled_size
            if template_path:
                tmpl_candidate = Path(template_path)
                if tmpl_candidate.is_absolute():
                    tmpl_resolved = tmpl_candidate.resolve()
                else:
                    tmpl_resolved = (PROJECT_ROOT / tmpl_candidate).resolve()
                if ".." in tmpl_candidate.parts:
                    return outputs.error(f"Path traversal not allowed in template_path: {template_path}")
                tmpl_allowed = False
                for d in _ALLOWED_OUTPUT_DIRS:
                    try:
                        tmpl_resolved.relative_to(d.resolve())
                        tmpl_allowed = True
                        break
                    except ValueError:
                        continue
                if not tmpl_allowed:
                    return outputs.error(f"template_path must be inside evidence/ or engagements/: {template_path}")
                generate_opts["Template"] = str(tmpl_resolved)
            if force_encode:
                generate_opts["ForceEncode"] = True

            result = await run_in_thread(client.call, "module.execute", ["payload", payload, generate_opts])

            raw_payload = result.get("payload") if isinstance(result, dict) else result

            if output_path:
                candidate = Path(output_path)
                if candidate.is_absolute():
                    resolved = candidate.resolve()
                else:
                    resolved = (PROJECT_ROOT / candidate).resolve()
                if ".." in candidate.parts:
                    return outputs.error(f"Path traversal not allowed: {output_path}")
                allowed = False
                for d in _ALLOWED_OUTPUT_DIRS:
                    try:
                        resolved.relative_to(d.resolve())
                        allowed = True
                        break
                    except ValueError:
                        continue
                if not allowed:
                    return outputs.error(f"Output path must be inside evidence/ or engagements/: {output_path}")
                out = resolved
            else:
                ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
                safe_name = payload.replace("/", "_")
                if output_filename:
                    import re

                    sanitized = re.sub(r"[^a-zA-Z0-9_.\-]", "_", Path(output_filename).name)
                    if sanitized:
                        safe_name = sanitized
                EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
                out = EVIDENCE_DIR / f"{ts}-payload-{safe_name}.{format}"

            out.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(raw_payload, bytes):
                out.write_bytes(raw_payload)
            elif raw_payload:
                out.write_text(str(raw_payload), encoding="utf-8")

            logger.info("Generated payload %s (%s) -> %s", payload, format, out)
            gen_info: dict[str, Any] = {
                "payload": payload,
                "format": format,
                "output_path": str(out),
                "size_bytes": out.stat().st_size if out.exists() else 0,
                "engagement_id": engagement_id,
                "generated": True,
            }
            if encoder:
                gen_info["encoder"] = encoder
            if iterations > 0:
                gen_info["iterations"] = iterations
            return outputs.ok(gen_info)
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Payload generation failed: %s", payload)
            return outputs.error(f"Payload generation failed: {e}")

    @mcp.tool(
        name="msf_compatible_payloads",
        annotations={"title": "List compatible payloads for module", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_compatible_payloads(
        module_type: str,
        module_name: str,
    ) -> dict:
        """List payloads compatible with a given exploit or auxiliary module."""
        type_err = inputs.validate_module_type(module_type)
        if type_err:
            return outputs.error(type_err)
        try:
            client = await run_in_thread(get_rpc)
            full_name = module_name
            if not module_name.startswith(f"{module_type}/"):
                full_name = f"{module_type}/{module_name}"
            result = await run_in_thread(client.call, "module.compatible_payloads", [full_name])
            payloads = result.get("payloads", []) if isinstance(result, dict) else []
            logger.info("Compatible payloads for %s: %d found", full_name, len(payloads))
            return outputs.ok(payloads, message=f"{len(payloads)} compatible payload(s)")
        except RpcConnectionError as e:
            return outputs.error(str(e), code="rpc_unavailable")
        except Exception as e:
            logger.exception("Compatible payloads query failed for %s/%s", module_type, module_name)
            return outputs.error(f"Compatible payloads query failed: {e}")
