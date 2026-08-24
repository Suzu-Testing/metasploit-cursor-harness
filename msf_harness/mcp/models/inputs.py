"""Input validation constants and helpers matching msfmcpd conventions."""

from __future__ import annotations

import ipaddress
import re

MAX_QUERY_LENGTH = 500
MAX_LIMIT = 1000
DEFAULT_LIMIT = 100
DEFAULT_OFFSET = 0
WORKSPACE_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")
PORT_RANGE_PATTERN = re.compile(r"^\d+(-\d+)?(,\d+(-\d+)?)*$")
MODULE_TYPES = ("exploit", "auxiliary", "post", "payload", "encoder", "nop")


def validate_workspace(workspace: str) -> str | None:
    if not WORKSPACE_PATTERN.match(workspace):
        return f"Invalid workspace name: {workspace}. Use alphanumeric, underscore, or hyphen only."
    return None


def validate_ip(ip_str: str) -> str | None:
    try:
        ipaddress.ip_address(ip_str.strip())
        return None
    except ValueError:
        pass
    try:
        ipaddress.ip_network(ip_str.strip(), strict=False)
        return None
    except ValueError:
        return f"Invalid IP or CIDR: {ip_str}"


NETMASK_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def validate_netmask(netmask: str) -> str | None:
    if not NETMASK_PATTERN.match(netmask.strip()):
        return f"Invalid netmask format: {netmask}. Must be dotted-decimal (e.g. 255.255.255.0)."
    octets = netmask.strip().split(".")
    for o in octets:
        if not (0 <= int(o) <= 255):
            return f"Invalid netmask octet: {o}"
    return None


def validate_console_safe(value: str, field_name: str) -> str | None:
    """Reject values containing characters that could inject console commands."""
    dangerous = set(value) & {"\n", "\r", ";", "\x00"}
    if dangerous:
        return f"{field_name} contains forbidden characters: {dangerous}"
    return None


def validate_ports(ports: str) -> str | None:
    if not PORT_RANGE_PATTERN.match(ports.strip()):
        return f"Invalid port specification: {ports}"
    for part in ports.split(","):
        if "-" in part:
            lo, hi = part.split("-", 1)
            if not (1 <= int(lo) <= 65535 and 1 <= int(hi) <= 65535):
                return f"Port out of range in: {part}"
        else:
            if not (1 <= int(part) <= 65535):
                return f"Port out of range: {part}"
    return None


def validate_module_type(module_type: str) -> str | None:
    if module_type not in MODULE_TYPES:
        return f"Invalid module type: {module_type}. Must be one of: {', '.join(MODULE_TYPES)}"
    return None


def clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIMIT))


def parse_options_gracefully(
    options: dict | str | None,
) -> dict:
    """Normalize module options from various input formats.

    Handles:
    - dict: returned as-is
    - str: parsed as comma-separated KEY=VALUE pairs
    - None: returns empty dict

    Coerces 'true'/'false' to bool and digit strings to int.
    """
    if options is None:
        return {}

    if isinstance(options, dict):
        return options

    if isinstance(options, str):
        if not options.strip():
            return {}
        parsed: dict = {}
        pairs = [p.strip() for p in options.split(",") if p.strip()]
        for pair in pairs:
            if "=" not in pair:
                raise ValueError(f"Invalid option format: '{pair}' (missing '=')")
            key, value = pair.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key:
                raise ValueError(f"Invalid option format: '{pair}' (empty key)")
            if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            if isinstance(value, str):
                if value.lower() in ("true", "false"):
                    parsed[key] = value.lower() == "true"
                elif value.isdigit():
                    parsed[key] = int(value)
                else:
                    parsed[key] = value
            else:
                parsed[key] = value
        return parsed

    try:
        return dict(options)
    except (TypeError, ValueError) as e:
        raise ValueError(
            f"Options must be a dict or comma-separated 'KEY=VALUE' string. Got {type(options).__name__}: {options}"
        ) from e
