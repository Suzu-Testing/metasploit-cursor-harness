"""End-to-end harness test against Docker lab targets.

Tests MCP tool code paths directly (same functions the MCP server calls).
Requires: msfrpcd running, Docker lab up, engagement lab-default configured.
"""

import asyncio
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load .env file if present (same mechanism as start-msfrpcd.sh)
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_env_file = os.path.join(_project_root, ".env")
if os.path.isfile(_env_file):
    with open(_env_file) as _f:
        for _line in _f:
            _line = _line.strip()
            if not _line or _line.startswith("#") or "=" not in _line:
                continue
            _key, _val = _line.split("=", 1)
            os.environ.setdefault(_key.strip(), _val.strip().strip("\"'"))

os.environ.setdefault("MSF_HOST", "127.0.0.1")
os.environ.setdefault("MSF_PORT", "55553")
os.environ.setdefault("MSF_SSL", "false")
os.environ.setdefault("MSF_USER", "msf")

if not os.environ.get("MSF_PASSWORD"):
    print("ERROR: MSF_PASSWORD not set. Configure it in .env or as an environment variable.")
    sys.exit(1)

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("test-harness", json_response=True)

from msf_harness.mcp.tools import (
    module_tools, module_query_tools, read_tools, session_tools,
    handler_tools, payload_tools, lab_tools, workspace_tools,
    console_tools, meterpreter_tools, route_tools, db_tools,
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

ENGAGEMENT = "lab-default"
TARGET = "127.0.0.1"

PASS = 0
FAIL = 0


def _is_ok(data):
    return isinstance(data, dict) and data.get("status") == "ok"


def _is_err(data):
    return isinstance(data, dict) and data.get("status") != "ok"


def result(name, data):
    global PASS, FAIL
    if _is_ok(data):
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}")
        if isinstance(data, dict):
            reason = data.get("reason", "")
            d = data.get("data", {})
            output = d.get("module_output", "") if isinstance(d, dict) else ""
            print(f"       reason: {reason[:200]}")
            if output:
                print(f"       output: {output[:500]}")
        else:
            print(f"       {str(data)[:200]}")
    return data


def expect_denied(name, data):
    """For tests where we expect ROE denial."""
    global PASS, FAIL
    if _is_err(data):
        PASS += 1
        reason = data.get("reason", "unknown") if isinstance(data, dict) else str(data)
        print(f"[PASS] {name} (correctly denied: {reason[:80]})")
    else:
        FAIL += 1
        print(f"[FAIL] {name} (expected denial but got ok)")
    return data


async def get_tool(name):
    return mcp._tool_manager._tools[name].fn


async def run_tests():
    global PASS, FAIL

    print("=" * 60)
    print("PHASE 1: Connectivity and Read Tools")
    print("=" * 60)

    fn = await get_tool("msf_status")
    result("msf_status", await fn())

    fn = await get_tool("msf_db_status")
    result("msf_db_status", await fn())

    fn = await get_tool("msf_get_lab_network")
    result("msf_get_lab_network", await fn())

    fn = await get_tool("msf_running_stats")
    result("msf_running_stats", await fn())

    fn = await get_tool("msf_list_workspaces")
    result("msf_list_workspaces", await fn())

    fn = await get_tool("msf_list_active_sessions")
    result("msf_list_active_sessions", await fn())

    fn = await get_tool("msf_list_listeners")
    result("msf_list_listeners", await fn())

    print()
    print("=" * 60)
    print("PHASE 2: Recon (nmap + DB + Search)")
    print("=" * 60)

    nmap_fn = await get_tool("msf_db_nmap")
    r = result("msf_db_nmap (MS3 ports)",
               await nmap_fn(
                   targets=TARGET,
                   nmap_args="-sV -p 10022,10021,10080,10445,10667,10306 --open",
                   engagement_id=ENGAGEMENT,
               ))

    host_fn = await get_tool("msf_host_info")
    result("msf_host_info", await host_fn(addresses=TARGET))

    svc_fn = await get_tool("msf_service_info")
    result("msf_service_info", await svc_fn(host=TARGET))

    search_fn = await get_tool("msf_search_modules")
    result("msf_search_modules (ircd)", await search_fn(query="unreal_ircd"))
    result("msf_search_modules (samba)", await search_fn(query="samba is_known_pipename"))

    print()
    print("=" * 60)
    print("PHASE 3: Exploit Flow (ROE Enforcement)")
    print("=" * 60)

    check_fn = await get_tool("msf_module_check")
    result("msf_module_check (ircd)",
           await check_fn(
               module_type="exploit",
               module_name="exploit/unix/irc/unreal_ircd_3281_backdoor",
               options={"RHOSTS": TARGET, "RPORT": 10667},
               engagement_id=ENGAGEMENT,
           ))

    aux_login_fn = await get_tool("msf_run_auxiliary_module")
    r = result("msf_run_auxiliary_module (ssh_login)",
               await aux_login_fn(
                   module_name="auxiliary/scanner/ssh/ssh_login",
                   options={
                       "RHOSTS": TARGET,
                       "RPORT": 10022,
                       "USERNAME": "msfadmin",
                       "PASSWORD": "msfadmin",
                       "CreateSession": True,
                   },
                   engagement_id=ENGAGEMENT,
                   timeout=60,
               ))
    if isinstance(r, dict):
        d = r.get("data", {})
        mo = d.get("module_output", "") if isinstance(d, dict) else ""
        if mo:
            print(f"  [DEBUG] ssh_login output: {mo[:600]}")

    sessions_fn = await get_tool("msf_list_active_sessions")
    sessions_check = await sessions_fn()
    if isinstance(sessions_check, dict):
        sd = sessions_check.get("data", [])
        print(f"  [DEBUG] Sessions after login: {json.dumps(sd, default=str)[:400]}")

    await asyncio.sleep(3)

    wait_fn = await get_tool("msf_wait_for_session")
    r = result("msf_wait_for_session",
               await wait_fn(timeout=20, engagement_id=ENGAGEMENT))

    sessions_fn = await get_tool("msf_list_active_sessions")
    sessions = result("msf_list_active_sessions (post-exploit)", await sessions_fn())

    session_id = None
    if _is_ok(sessions):
        slist = sessions.get("data", [])
        if isinstance(slist, list) and slist:
            s0 = slist[0]
            if isinstance(s0, dict):
                session_id = s0.get("session_id") or s0.get("id")
            else:
                session_id = s0
        elif isinstance(slist, dict):
            for k in slist:
                session_id = k
                break
    if session_id is not None:
        session_id = int(session_id)

    print()
    print("=" * 60)
    print("PHASE 4: Session Management")
    print("=" * 60)

    if session_id:
        print(f"  [INFO] Using session {session_id}")

        info_fn = await get_tool("msf_session_info")
        result("msf_session_info", await info_fn(session_id=session_id))

        cmd_fn = await get_tool("msf_send_session_command")
        result("send_session_command (id)",
               await cmd_fn(session_id=session_id, command="id", engagement_id=ENGAGEMENT))

        await asyncio.sleep(1)
        result("send_session_command (uname)",
               await cmd_fn(session_id=session_id, command="uname -a", engagement_id=ENGAGEMENT))

        await asyncio.sleep(1)
        result("send_session_command (whoami)",
               await cmd_fn(session_id=session_id, command="whoami", engagement_id=ENGAGEMENT))
    else:
        print("  [SKIP] No session available - session management tests skipped")
        FAIL += 4

    print()
    print("=" * 60)
    print("PHASE 5: Post-Exploitation")
    print("=" * 60)

    if session_id:
        post_fn = await get_tool("msf_run_post_module")
        result("msf_run_post_module (env)",
               await post_fn(
                   module_name="post/multi/gather/env",
                   session_id=session_id,
                   engagement_id=ENGAGEMENT,
               ))

        cred_fn = await get_tool("msf_credential_add")
        result("msf_credential_add",
               await cred_fn(
                   host=TARGET, port=22,
                   username="root", private_data="toor",
                   private_type="password",
                   service_name="ssh",
                   protocol="tcp",
                   engagement_id=ENGAGEMENT,
               ))

        report_fn = await get_tool("msf_report_host")
        result("msf_report_host",
               await report_fn(
                   host=TARGET, os_name="Linux", os_flavor="Ubuntu 14.04",
                   name="lab-ms3",
                   engagement_id=ENGAGEMENT,
               ))

        note_fn = await get_tool("msf_db_add_note")
        result("msf_db_add_note",
               await note_fn(
                   host=TARGET, ntype="e2e_test",
                   data="End-to-end test passed",
                   engagement_id=ENGAGEMENT,
               ))
    else:
        print("  [SKIP] No session for post-exploitation tests")
        FAIL += 4

    print()
    print("=" * 60)
    print("PHASE 6: Negative Tests (ROE Denials)")
    print("=" * 60)

    expect_denied("DENY: out-of-scope IP (8.8.8.8)",
                  await nmap_fn(targets="8.8.8.8", nmap_args="-sV -p 80", engagement_id=ENGAGEMENT))

    aux_fn = await get_tool("msf_run_auxiliary_module")
    expect_denied("DENY: DoS module blocked",
                  await aux_fn(
                      module_name="auxiliary/dos/http/slowloris",
                      options={"RHOSTS": TARGET},
                      engagement_id=ENGAGEMENT,
                  ))

    expect_denied("DENY: missing engagement_id",
                  await nmap_fn(targets=TARGET, nmap_args="-sV -p 80", engagement_id=""))

    print()
    print("=" * 60)
    print("PHASE 7: Cleanup")
    print("=" * 60)

    if session_id:
        kill_fn = await get_tool("msf_terminate_session")
        result("msf_terminate_session",
               await kill_fn(session_id=session_id, engagement_id=ENGAGEMENT))

    cleanup_fn = await get_tool("msf_cleanup_jobs")
    result("msf_cleanup_jobs", await cleanup_fn(engagement_id=ENGAGEMENT))

    fn = await get_tool("msf_list_active_sessions")
    result("msf_list_active_sessions (clean)", await fn())

    print()
    print("=" * 60)
    print(f"RESULTS: {PASS} passed, {FAIL} failed")
    print("=" * 60)

    return FAIL == 0


if __name__ == "__main__":
    success = asyncio.run(run_tests())
    sys.exit(0 if success else 1)
