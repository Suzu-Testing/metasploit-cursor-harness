#!/usr/bin/env python3
"""Quick validation that MCP harness can talk to msfrpcd."""

from __future__ import annotations

import sys

from msf_harness.mcp.rpc.client import get_rpc, RpcConnectionError
from msf_harness.mcp.rpc.execute import cleanup_jobs


def main() -> int:
    try:
        client = get_rpc()
        version = client.call("core.version", [])
        print(f"RPC OK: Metasploit {version.get('version', '?')}")

        raw = client.call("module.info", ["exploit", "unix/ftp/vsftpd_234_backdoor"])
        print(f"module.info OK: {raw.get('fullname', '?')}")

        stopped = cleanup_jobs(client)
        print(f"cleanup_jobs OK: stopped {len(stopped)} job(s)")

        print("All checks passed.")
        return 0
    except RpcConnectionError as exc:
        print(f"RPC FAILED: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
