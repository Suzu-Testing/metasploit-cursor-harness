"""Helpers for executing Metasploit modules via RPC."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pymetasploit3.msfrpc import MsfRpcClient

logger = logging.getLogger("msf_harness.rpc.execute")

PROJECT_ROOT = Path(__file__).resolve().parents[3]
LHOST_FILE = PROJECT_ROOT / "engagements" / "lab-default" / "lhost.yaml"

_INT_OPTION_KEYS = frozenset(
    {
        "THREADS",
        "TIMEOUT",
        "RPORT",
        "LPORT",
        "SESSION",
        "DELAY",
        "JITTER",
        "RETRY_COUNT",
        "RETRY_DELAY",
        "BATCHSIZE",
        "CONCURRENT",
        "SNAPLEN",
        "TARGET",
    }
)

# Payloads that need LHOST when used with cmd/arch exploits (MSF 6 defaults).
_REVERSE_PAYLOAD_MARKERS = ("reverse", "meterpreter", "bind_tcp")  # bind_tcp needs LPORT not LHOST


def _coerce_option(key: str, value: Any) -> Any:
    """MSF RPC rejects string values for integer module options."""
    if isinstance(value, str) and key.upper() in _INT_OPTION_KEYS:
        try:
            return int(value)
        except ValueError:
            pass
    return value


def apply_module_options(mod: Any, options: dict[str, Any] | None) -> None:
    for k, v in (options or {}).items():
        if k.upper() == "PAYLOAD":
            continue
        try:
            mod[k] = _coerce_option(k, v)
        except KeyError:
            logger.warning("Skipping unknown option %s for %s", k, getattr(mod, "modulename", "?"))


def _load_lhost(engagement_id: str | None = None) -> str | None:
    """Load LHOST from engagement-specific lhost.yaml, falling back to lab-default."""
    if engagement_id:
        eng_lhost = PROJECT_ROOT / "engagements" / engagement_id / "lhost.yaml"
        if eng_lhost.exists():
            data = yaml.safe_load(eng_lhost.read_text(encoding="utf-8")) or {}
            val = data.get("lhost") or data.get("lhost_wsl") or data.get("lhost_docker_gateway")
            if val:
                return val
    if not LHOST_FILE.exists():
        return None
    data = yaml.safe_load(LHOST_FILE.read_text(encoding="utf-8")) or {}
    return data.get("lhost") or data.get("lhost_wsl") or data.get("lhost_docker_gateway")


def _payload_needs_lhost(payload_name: str) -> bool:
    name = payload_name.lower()
    if "bind" in name and "reverse" not in name:
        return False
    return any(m in name for m in ("reverse", "meterpreter", "http/", "https/"))


def cleanup_jobs(client: MsfRpcClient) -> list[int]:
    """Stop all background MSF jobs to free handler ports."""
    stopped: list[int] = []
    jobs = client.jobs.list or {}
    for jid in list(jobs.keys()):
        try:
            client.call("job.stop", [int(jid)])
            stopped.append(int(jid))
        except Exception as exc:
            logger.warning("Failed to stop job %s: %s", jid, exc)
    if stopped:
        logger.info("Stopped stale jobs: %s", stopped)
    return stopped


def _resolve_exploit_payload(
    mod: Any,
    payload: str | None,
    payload_options: dict[str, Any] | None,
    options: dict[str, Any] | None,
    engagement_id: str | None = None,
) -> tuple[str | None, dict[str, Any]]:
    """Pick a valid exploit payload and inject LHOST when MSF 6 requires it."""
    merged_opts = dict(options or {})
    extra: dict[str, Any] = dict(payload_options or {})

    if payload:
        chosen = payload
    else:
        # MSF 6: calling execute() without payload lets msfrpcd use global meterpreter default.
        # Prefer the module target default, else first compatible payload.
        chosen = (mod.runoptions.get("PAYLOAD") or "").strip() or None
        if not chosen:
            compatible = mod.targetpayloads() if hasattr(mod, "targetpayloads") else []
            # Prefer inline reverse shell (no HTTP fetch handler on 8080).
            for candidate in compatible:
                if candidate == "generic/shell_reverse_tcp":
                    chosen = candidate
                    break
            if not chosen:
                for candidate in compatible:
                    if "shell/reverse_tcp" in candidate and "meterpreter" not in candidate and "http/" not in candidate:
                        chosen = candidate
                        break
            if not chosen and compatible:
                chosen = compatible[0]

    if chosen and _payload_needs_lhost(chosen):
        if not merged_opts.get("LHOST") and not extra.get("LHOST"):
            lhost = _load_lhost(engagement_id)
            if lhost:
                extra["LHOST"] = lhost
                logger.info("Auto-set LHOST=%s for payload %s", lhost, chosen)

    return chosen, extra


def execute_module_raw(
    client: MsfRpcClient,
    module_type: str,
    module_name: str,
    runopts: dict[str, Any],
) -> Any:
    """Execute via raw RPC, bypassing pymetasploit3 payload validation."""
    coerced = {k: _coerce_option(k, v) for k, v in runopts.items()}
    return client.call("module.execute", [module_type, module_name, coerced])


def execute_module(
    client: MsfRpcClient,
    module_type: str,
    module_name: str,
    options: dict[str, Any] | None = None,
    payload: str | None = None,
    payload_options: dict[str, Any] | None = None,
    engagement_id: str | None = None,
) -> Any:
    """Execute a module with options and optional payload passed correctly to pymetasploit3."""
    opts = dict(options or {})
    if not payload and opts.get("PAYLOAD"):
        payload = str(opts.pop("PAYLOAD"))

    mod = client.modules.use(module_type, module_name)
    apply_module_options(mod, opts)

    if module_type == "exploit":
        chosen_payload, extra_payload_opts = _resolve_exploit_payload(
            mod,
            payload,
            payload_options,
            opts,
            engagement_id,
        )
        runopts = dict(mod.runoptions)
        for k, v in opts.items():
            runopts[k] = _coerce_option(k, v)
        runopts["TARGET"] = mod.target
        if chosen_payload:
            runopts["PAYLOAD"] = chosen_payload
        for k, v in extra_payload_opts.items():
            runopts[k] = _coerce_option(k, v)
        logger.debug(
            "Executing exploit %s payload=%s rhosts=%s",
            module_name,
            runopts.get("PAYLOAD"),
            runopts.get("RHOSTS"),
        )
        return execute_module_raw(client, module_type, module_name, runopts)

    execute_kwargs: dict[str, Any] = {}
    if payload:
        execute_kwargs["payload"] = payload
    if payload_options:
        for k, v in payload_options.items():
            execute_kwargs[k] = v

    if execute_kwargs:
        return mod.execute(**execute_kwargs)
    return mod.execute()


def check_module(
    client: MsfRpcClient,
    module_type: str,
    module_name: str,
    options: dict[str, Any] | None = None,
) -> Any:
    """Run module check via RPC, handling MSF 6.x API differences."""
    mod = client.modules.use(module_type, module_name)
    apply_module_options(mod, options)
    checker = getattr(mod, "check", None)
    if callable(checker):
        return checker()
    return client.call("module.check", [module_type, module_name, mod.runoptions])
