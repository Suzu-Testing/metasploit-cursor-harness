"""Lab network helpers for Docker Metasploitable2 target."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml
from mcp.server.fastmcp import FastMCP

from msf_harness.mcp.models import outputs

logger = logging.getLogger("msf_harness.tools.lab")

PROJECT_ROOT = Path(__file__).resolve().parents[3]
LHOST_FILE = PROJECT_ROOT / "engagements" / "lab-default" / "lhost.yaml"
SCOPE_DETAILS = PROJECT_ROOT / "scope" / "scope-details.yaml"

DEFAULT_RHOST = "10.255.255.254"
DEFAULT_LPORT = 4444
DEFAULT_PAYLOAD = "generic/shell_reverse_tcp"
DEFAULT_PORTS = {
    "ftp": 9021,
    "ssh": 9022,
    "telnet": 9023,
    "smtp": 9025,
    "http": 9080,
    "smb": 9445,
    "irc": 9667,
    "mysql": 9306,
    "distcc": 9632,
}


def _detect_attacker_ip() -> str | None:
    import subprocess
    import sys

    if sys.platform == "win32":
        try:
            r = subprocess.run(
                [
                    "wsl",
                    "-e",
                    "bash",
                    "-lc",
                    "ip -4 addr show eth0 | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}' | head -1",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            ip = r.stdout.strip()
            if ip:
                return ip
        except Exception:
            pass

    try:
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="msf_get_lab_network",
        annotations={"title": "Get lab network config", "readOnlyHint": True, "destructiveHint": False},
    )
    async def msf_get_lab_network() -> dict:
        """Return RHOST, LHOST, mapped ports, and Docker target info for Metasploitable2."""
        try:
            lhost_data: dict = {}
            if LHOST_FILE.exists():
                lhost_data = yaml.safe_load(LHOST_FILE.read_text(encoding="utf-8")) or {}

            target_info: dict = {}
            if SCOPE_DETAILS.exists():
                details = yaml.safe_load(SCOPE_DETAILS.read_text(encoding="utf-8")) or {}
                for t in details.get("targets", []):
                    if t.get("hostname") == "metasploitable2" or t.get("ip") == "172.17.0.2":
                        target_info = t
                        break

            lhost = lhost_data.get("lhost_wsl") or lhost_data.get("lhost") or _detect_attacker_ip()

            return outputs.ok(
                {
                    "rhost": DEFAULT_RHOST,
                    "rhost_note": "Docker port-mapped target; use mapped ports from host",
                    "container_ip": "172.17.0.2",
                    "lhost": lhost,
                    "lhost_docker_gateway": lhost_data.get("lhost_docker_gateway", "172.17.0.1"),
                    "default_lport": lhost_data.get("default_lport", DEFAULT_LPORT),
                    "default_payload": DEFAULT_PAYLOAD,
                    "portproxy_configured": lhost_data.get("portproxy_configured", False),
                    "mapped_ports": DEFAULT_PORTS,
                    "target": target_info,
                    "engagement_id": "lab-default",
                }
            )
        except Exception as e:
            logger.exception("Lab network config failed")
            return outputs.error(f"Lab network config failed: {e}")
