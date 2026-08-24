#!/usr/bin/env python3
"""Health check for Metasploit Cursor Harness setup."""

from __future__ import annotations

import platform
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

PROJECT_ROOT = Path(__file__).resolve().parent.parent

Status = Literal["pass", "fail", "warn"]


@dataclass
class CheckResult:
    status: Status
    message: str
    fix: str | None = None


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse a simple KEY=VALUE .env file."""
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def check_python_version() -> CheckResult:
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"
    if version >= (3, 10):
        return CheckResult("pass", f"Python {version_str}")
    return CheckResult(
        "fail",
        f"Python {version_str} (requires >= 3.10)",
        "Install Python 3.10 or newer: https://www.python.org/downloads/",
    )


def check_msf_harness_import() -> CheckResult:
    try:
        import msf_harness  # noqa: F401
    except ImportError:
        return CheckResult(
            "fail",
            "msf-harness package not installed",
            'pip install -e ".[mcp]"',
        )
    return CheckResult("pass", "msf-harness package installed")


def check_env_file() -> CheckResult:
    env_path = PROJECT_ROOT / ".env"
    if not env_path.is_file():
        return CheckResult(
            "fail",
            ".env file not found",
            "cp .env.example .env && edit MSF_PASSWORD",
        )

    env = parse_env_file(env_path)
    password = env.get("MSF_PASSWORD", "").strip()
    if not password:
        return CheckResult(
            "fail",
            "MSF_PASSWORD not set in .env",
            "Edit .env and set MSF_PASSWORD to your msfrpcd password",
        )
    if password.lower() == "changeme":
        return CheckResult(
            "fail",
            'MSF_PASSWORD is still "changeme"',
            "Edit .env and set MSF_PASSWORD to your msfrpcd password",
        )
    return CheckResult("pass", ".env configured")


def _rpc_endpoint() -> tuple[str, int]:
    env_path = PROJECT_ROOT / ".env"
    env = parse_env_file(env_path)
    host = env.get("MSF_HOST", "127.0.0.1").strip() or "127.0.0.1"
    port_str = env.get("MSF_PORT", "55553").strip() or "55553"
    try:
        port = int(port_str)
    except ValueError:
        port = 55553
    return host, port


def check_msfrpcd_reachable() -> CheckResult:
    host, port = _rpc_endpoint()
    endpoint = f"{host}:{port}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((host, port))
    except (TimeoutError, OSError):
        is_windows = platform.system() == "Windows"
        if is_windows:
            fix = ".\\scripts\\start-msfrpcd.ps1"
        else:
            fix = (
                'msfdb start; msfrpcd -U msf -P <password> -S -a 127.0.0.1 -p 55553'
            )
        return CheckResult(
            "warn",
            f"msfrpcd not reachable at {endpoint}",
            fix,
        )
    finally:
        sock.close()
    return CheckResult("pass", f"msfrpcd reachable at {endpoint}")


def check_msfrpcd_auth() -> CheckResult:
    """Try actual RPC authentication (not just TCP)."""
    try:
        from msf_harness.mcp.rpc.client import get_rpc
        client = get_rpc()
        ver = client.call("core.version", [])
        version_str = ver.get(b"version", b"unknown").decode(errors="replace")
        return CheckResult("pass", f"RPC authenticated (MSF {version_str})")
    except ImportError:
        return CheckResult("warn", "Cannot test RPC auth (msf_harness not installed)")
    except Exception as exc:
        return CheckResult(
            "warn",
            f"RPC auth failed: {str(exc)[:80]}",
            "Verify MSF_PASSWORD in .env matches msfrpcd startup password",
        )


def check_scope_file() -> CheckResult:
    scope_path = PROJECT_ROOT / "scope" / "scope-master.txt"
    if not scope_path.is_file():
        return CheckResult(
            "fail",
            "scope/scope-master.txt not found",
            "Create scope/scope-master.txt with authorized target CIDRs",
        )

    has_entry = False
    for line in scope_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            has_entry = True
            break

    if not has_entry:
        return CheckResult(
            "fail",
            "scope/scope-master.txt is empty",
            "Add at least one authorized CIDR or IP (one per line)",
        )
    return CheckResult("pass", "scope/scope-master.txt configured")


def check_engagement_exists() -> CheckResult:
    engagements_dir = PROJECT_ROOT / "engagements"
    if not engagements_dir.is_dir():
        return CheckResult(
            "fail",
            "engagements/ directory not found",
            'python scripts/create-engagement.py --name <name>',
        )

    excluded = {"_template", "catalogs"}
    engagement_dirs = [
        p
        for p in engagements_dir.iterdir()
        if p.is_dir() and p.name not in excluded
    ]

    if not engagement_dirs:
        return CheckResult(
            "fail",
            "No engagement directories found",
            'python scripts/create-engagement.py --name <name>',
        )

    names = ", ".join(sorted(p.name for p in engagement_dirs))
    return CheckResult("pass", f"Engagement(s) found: {names}")


def check_mcp_json() -> CheckResult:
    mcp_path = PROJECT_ROOT / ".cursor" / "mcp.json"
    if not mcp_path.is_file():
        return CheckResult(
            "fail",
            ".cursor/mcp.json not found",
            "Configure the msf-harness MCP server in Cursor settings",
        )
    return CheckResult("pass", ".cursor/mcp.json exists")


def check_pwsh() -> CheckResult:
    pwsh = shutil.which("pwsh")
    if pwsh:
        return CheckResult("pass", f"pwsh available ({pwsh})")
    return CheckResult(
        "fail",
        "pwsh not found on PATH",
        "Install PowerShell 7+: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell",
    )


def check_docker() -> CheckResult:
    docker = shutil.which("docker")
    if not docker:
        return CheckResult(
            "warn",
            "Docker not found on PATH",
            "Install Docker Desktop for lab targets (optional): https://docs.docker.com/get-docker/",
        )

    try:
        result = subprocess.run(
            [docker, "info"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return CheckResult(
            "warn",
            "Docker found but not responding",
            "Start Docker Desktop or the Docker daemon",
        )

    if result.returncode == 0:
        return CheckResult("pass", "Docker available")
    return CheckResult(
        "warn",
        "Docker found but daemon not running",
        "Start Docker Desktop or the Docker daemon",
    )


def check_wsl() -> CheckResult:
    if platform.system() != "Windows":
        return CheckResult("pass", "WSL not required on this platform")

    wsl = shutil.which("wsl")
    if not wsl:
        return CheckResult(
            "warn",
            "WSL not found on PATH",
            "Install WSL for msfrpcd: wsl --install",
        )

    try:
        result = subprocess.run(
            [wsl, "--status"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return CheckResult(
            "warn",
            "WSL command failed",
            "Install or repair WSL: wsl --install",
        )

    if result.returncode == 0:
        return CheckResult("pass", "WSL available")
    return CheckResult(
        "warn",
        "WSL installed but may need setup",
        "Run wsl --install and set up a Linux distribution (e.g. Kali)",
    )


def check_logs_dir() -> CheckResult:
    """Ensure logs/ directory exists (hooks and workflow scripts write here)."""
    logs_dir = PROJECT_ROOT / "logs"
    if logs_dir.is_dir():
        return CheckResult("pass", "logs/ directory exists")
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
        return CheckResult("pass", "logs/ directory created")
    except OSError as exc:
        return CheckResult("fail", f"Cannot create logs/: {exc}")


def check_hooks_json() -> CheckResult:
    """Validate .cursor/hooks.json is parseable."""
    import json as _json
    hooks_path = PROJECT_ROOT / ".cursor" / "hooks.json"
    if not hooks_path.is_file():
        return CheckResult(
            "warn",
            ".cursor/hooks.json not found",
            "Hook pipeline will not activate. Re-clone or restore hooks.json.",
        )
    try:
        data = _json.loads(hooks_path.read_text(encoding="utf-8"))
        hook_count = sum(len(v) for v in data.get("hooks", {}).values())
        return CheckResult("pass", f"hooks.json valid ({hook_count} hook entries)")
    except (ValueError, KeyError) as exc:
        return CheckResult("fail", f"hooks.json parse error: {exc}")


CHECKS = [
    check_python_version,
    check_msf_harness_import,
    check_env_file,
    check_msfrpcd_reachable,
    check_msfrpcd_auth,
    check_scope_file,
    check_engagement_exists,
    check_mcp_json,
    check_hooks_json,
    check_logs_dir,
    check_pwsh,
    check_docker,
    check_wsl,
]

STATUS_TAG = {
    "pass": "PASS",
    "fail": "FAIL",
    "warn": "WARN",
}


def main() -> int:
    print("Metasploit Cursor Harness - Health Check")
    print("=" * 40)
    print()

    passed = failed = warnings = 0

    for check_fn in CHECKS:
        result = check_fn()
        tag = STATUS_TAG[result.status]
        print(f"[{tag}] {result.message}")
        if result.fix:
            print(f"       Fix: {result.fix}")

        if result.status == "pass":
            passed += 1
        elif result.status == "fail":
            failed += 1
        else:
            warnings += 1

    print()
    print(f"Summary: {passed} passed, {failed} failed, {warnings} warnings")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
