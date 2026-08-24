"""MSF console execution - matches GH05TCREW/MetasploitMCP approach.

RPC mod.execute() returns a job_id immediately and MSF 6 applies global
default payloads, so exploits often fail without visible output. Console
execution sets options explicitly, runs synchronously, and parses session output.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from pymetasploit3.msfrpc import MsfConsole, MsfRpcClient

logger = logging.getLogger("msf_harness.rpc.console")

MSF_PROMPT_RE = re.compile(rb"\x01\x02msf\d+\x01\x02 \x01\x02> \x01\x02")
SESSION_OPENED_RE = re.compile(
    r"(?:meterpreter|command shell)\s+session\s+(\d+)\s+opened",
    re.IGNORECASE,
)
FAIL_MARKERS = (
    "exploit completed, but no session was created",
    "exploit failed",
    "run failed",
    "optionvalidateerror",
    "bad-config",
)


_OPTION_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def _quote_val(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    text = str(value)
    if any(c in text for c in (" ", '"', "'", "\\", "\n", "\r", ";", "\x00")):
        escaped = text.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return text


def validate_option_key(key: str) -> None:
    """Raise ValueError if key is not a valid MSF option name."""
    if not _OPTION_KEY_RE.match(key):
        raise ValueError(f"Invalid option key: {key!r}. Must match [A-Za-z][A-Za-z0-9_]*")


def _normalize_module_path(module_type: str, module_name: str) -> str:
    if "/" in module_name:
        if module_name.startswith(f"{module_type}/"):
            return module_name
        if module_name.split("/", 1)[0] in ("exploit", "auxiliary", "post", "payload"):
            return module_name
        return f"{module_type}/{module_name}"
    return f"{module_type}/{module_name}"


def _payload_base_name(payload: str) -> str:
    if payload.startswith("payload/"):
        return payload.split("/", 1)[1]
    return payload


@contextmanager
def msf_console(client: MsfRpcClient) -> Iterator[MsfConsole]:
    """Create and destroy a temporary MSF console."""
    console = client.consoles.console()
    try:
        console.read()  # clear banner buffer
        yield console
    finally:
        cid = getattr(console, "cid", None)
        if cid is not None:
            try:
                client.consoles.destroy(str(cid))
            except Exception as exc:
                logger.warning("Failed to destroy console %s: %s", cid, exc)


def run_console_command(console: MsfConsole, cmd: str, timeout: int = 60) -> tuple[str, bool]:
    """Write a command and read output until prompt or timeout.

    Returns (output_text, timed_out) tuple.
    """
    console.write(cmd + "\n")
    deadline = time.time() + timeout
    chunks: list[str] = []
    timed_out = True

    while time.time() < deadline:
        result = console.read()
        data = result.get("data", "") if isinstance(result, dict) else str(result)
        if data:
            chunks.append(data)
        prompt = result.get("prompt", b"") if isinstance(result, dict) else b""
        if isinstance(prompt, str):
            prompt = prompt.encode("utf-8", errors="replace")
        if prompt and MSF_PROMPT_RE.search(prompt):
            timed_out = False
            break
        if data and MSF_PROMPT_RE.search(data.encode("utf-8", errors="replace")):
            timed_out = False
            break
        time.sleep(0.3)

    output = "".join(chunks)
    logger.debug("Console cmd=%r output_len=%d timed_out=%s", cmd, len(output), timed_out)
    return output, timed_out


def execute_module_via_console(
    client: MsfRpcClient,
    module_type: str,
    module_name: str,
    options: dict[str, Any] | None = None,
    payload: str | None = None,
    payload_options: dict[str, Any] | None = None,
    command: str = "run",
    timeout: int = 90,
) -> dict[str, Any]:
    """Run a module synchronously via msfconsole-style commands."""
    full_path = _normalize_module_path(module_type, module_name)
    setup_cmds = [f"use {full_path}"]

    for key, value in (options or {}).items():
        if key.upper() == "PAYLOAD":
            continue
        validate_option_key(key)
        setup_cmds.append(f"set {key} {_quote_val(value)}")

    if payload:
        setup_cmds.append(f"set PAYLOAD {_payload_base_name(payload)}")
    for key, value in (payload_options or {}).items():
        validate_option_key(key)
        setup_cmds.append(f"set {key} {_quote_val(value)}")

    module_output = ""
    with msf_console(client) as console:
        for cmd in setup_cmds:
            out, _ = run_console_command(console, cmd, timeout=15)
            module_output += out
            lower = out.lower()
            if "unknown module" in lower or "invalid option" in lower or "error setting" in lower:
                return {
                    "status": "error",
                    "module": full_path,
                    "message": f"Setup failed on '{cmd}'",
                    "module_output": module_output,
                }

        run_output, run_timed_out = run_console_command(console, command, timeout=timeout)
        module_output += run_output

    session_id = None
    match = SESSION_OPENED_RE.search(module_output)
    if match:
        session_id = int(match.group(1))

    lower_out = module_output.lower()
    failed = any(m in lower_out for m in FAIL_MARKERS)
    if session_id is not None:
        status = "success"
        message = f"Session {session_id} opened"
    elif failed:
        status = "error"
        message = "Module execution failed (see module_output)"
    else:
        status = "warning"
        message = "Module completed; no session detected in output"

    return {
        "status": status,
        "message": message,
        "module": full_path,
        "session_id": session_id,
        "module_output": module_output,
        "command": command,
        "timed_out": run_timed_out,
    }
