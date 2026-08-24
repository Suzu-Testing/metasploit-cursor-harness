"""Rules of Engagement enforcement for the Metasploit harness.

Validates targets against authorized CIDRs and exclusion lists, blocks
forbidden modules, enforces session limits, domain authorization, and
CIDR scan width before any RPC call reaches the Metasploit backend.
"""

from __future__ import annotations

import ipaddress
import logging
import re as _re
import threading
import time as _time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger("msf_harness.roe")

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SCOPE_FILE = PROJECT_ROOT / "scope" / "scope-master.txt"
ENGAGEMENTS_DIR = PROJECT_ROOT / "engagements"
ENGAGEMENT_ID_PATTERN = _re.compile(r"^[a-zA-Z0-9_-]+$")


@dataclass
class RoePolicy:
    engagement_id: str
    authorized_cidrs: list[str] = field(default_factory=list)
    excluded_ips: list[str] = field(default_factory=list)
    forbidden_module_prefixes: list[str] = field(default_factory=lambda: ["auxiliary/dos/"])
    require_check_before_exploit: bool = True
    max_sessions: int = 5
    authorized_domains: list[str] = field(default_factory=list)
    max_scan_cidr: int = 24

    @property
    def networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        nets = []
        for cidr in self.authorized_cidrs:
            try:
                nets.append(ipaddress.ip_network(cidr.strip(), strict=False))
            except ValueError:
                logger.warning("Skipping invalid CIDR in ROE: %s", cidr)
                continue
        return nets


_policy_cache: dict[str, tuple[RoePolicy, float, float]] = {}

# In-memory registry of completed vulnerability checks.
# Key: (engagement_id, module_name_normalized, target_normalized)
# Value: timestamp of the check.
# Used by the check-before-exploit gate to detect when msf_module_check
# was called separately before msf_run_exploit.
_check_registry: dict[tuple[str, str, str], float] = {}
_check_registry_lock = threading.Lock()
_CHECK_REGISTRY_TTL = 3600  # checks expire after 1 hour


def record_check(engagement_id: str, module_path: str, target: str | None) -> None:
    """Record that a vulnerability check was run for a module+target."""
    key = (engagement_id, module_path.lower(), (target or "").strip().lower())
    with _check_registry_lock:
        _check_registry[key] = _time.time()


def was_check_run(engagement_id: str, module_path: str, target: str | None) -> bool:
    """Return True if a valid (non-expired) check record exists."""
    key = (engagement_id, module_path.lower(), (target or "").strip().lower())
    with _check_registry_lock:
        ts = _check_registry.get(key)
        if ts is None:
            return False
        if _time.time() - ts > _CHECK_REGISTRY_TTL:
            _check_registry.pop(key, None)
            return False
        return True


def _file_mtime(path: Path) -> float:
    """Return mtime of a file, or 0.0 if it doesn't exist."""
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _load_scope_file() -> tuple[list[str], list[str]]:
    """Parse scope/scope-master.txt into (authorized CIDRs, excluded IPs)."""
    if not SCOPE_FILE.exists():
        return [], []
    cidrs: list[str] = []
    exclusions: list[str] = []
    for line in SCOPE_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            ip = line.lstrip("!").split("#")[0].strip()
            if ip:
                exclusions.append(ip)
        else:
            entry = line.split("#")[0].strip()
            if entry:
                cidrs.append(entry)
    return cidrs, exclusions


def _load_domains_file() -> list[str]:
    """Load authorized domains from scope/in-scope-domains.txt."""
    domains_file = PROJECT_ROOT / "scope" / "in-scope-domains.txt"
    if not domains_file.exists():
        return []
    domains: list[str] = []
    for line in domains_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entry = line.split("#")[0].strip()
        if entry:
            domains.append(entry.lower())
    return domains


def validate_engagement_id(engagement_id: str) -> str | None:
    """Return an error if engagement_id contains path separators or invalid chars."""
    if not engagement_id or not ENGAGEMENT_ID_PATTERN.match(engagement_id):
        return f"Invalid engagement_id: {engagement_id!r}. Use alphanumeric characters, underscores, or hyphens only."
    return None


def load_roe(engagement_id: str) -> RoePolicy:
    """Load ROE from engagements/{engagement_id}/roe.yaml, falling back to scope-master.txt.

    Uses mtime-based cache invalidation: if either the scope file or the
    engagement roe.yaml has been modified since the last load, the cached
    policy is discarded and reloaded from disk.
    """
    roe_path = ENGAGEMENTS_DIR / engagement_id / "roe.yaml"
    current_scope_mtime = _file_mtime(SCOPE_FILE)
    current_roe_mtime = _file_mtime(roe_path)

    if engagement_id in _policy_cache:
        cached_policy, cached_scope_mt, cached_roe_mt = _policy_cache[engagement_id]
        if current_scope_mtime == cached_scope_mt and current_roe_mtime == cached_roe_mt:
            return cached_policy
        logger.info("ROE cache invalidated for %s (file changed on disk)", engagement_id)

    scope_cidrs, scope_exclusions = _load_scope_file()
    scope_domains = _load_domains_file()

    if roe_path.exists():
        data = yaml.safe_load(roe_path.read_text(encoding="utf-8")) or {}
        roe_excluded = data.get("excluded_ips", [])
        all_excluded = list(set(scope_exclusions + [str(ip) for ip in roe_excluded]))
        roe_domains = [d.lower() for d in data.get("authorized_domains", [])]
        all_domains = list(set(scope_domains + roe_domains))
        policy = RoePolicy(
            engagement_id=data.get("engagement_id", engagement_id),
            authorized_cidrs=data.get("authorized_cidrs", scope_cidrs),
            excluded_ips=all_excluded,
            forbidden_module_prefixes=data.get("forbidden_module_prefixes", ["auxiliary/dos/"]),
            require_check_before_exploit=data.get("require_check_before_exploit", True),
            max_sessions=data.get("max_sessions", 5),
            authorized_domains=all_domains,
            max_scan_cidr=data.get("max_scan_cidr", 24),
        )
    else:
        policy = RoePolicy(
            engagement_id=engagement_id,
            authorized_cidrs=scope_cidrs,
            excluded_ips=scope_exclusions,
            authorized_domains=scope_domains,
        )

    logger.info(
        "Loaded ROE for %s: %d CIDRs, %d exclusions, %d domains, max_sessions=%d",
        engagement_id,
        len(policy.authorized_cidrs),
        len(policy.excluded_ips),
        len(policy.authorized_domains),
        policy.max_sessions,
    )
    _policy_cache[engagement_id] = (policy, current_scope_mtime, current_roe_mtime)
    return policy


def clear_policy_cache() -> None:
    """Drop cached policies so the next call reloads from disk."""
    _policy_cache.clear()


def validate_not_excluded(policy: RoePolicy, target: str) -> str | None:
    """Return an error if the target is on the exclusion list."""
    try:
        addr = ipaddress.ip_address(target.strip())
    except ValueError:
        return None
    for excl in policy.excluded_ips:
        try:
            if ipaddress.ip_address(excl.strip()) == addr:
                return f"Target {target} is on the exclusion list and must not be targeted"
        except ValueError:
            continue
    return None


def validate_target(policy: RoePolicy, target: str) -> str | None:
    """Return None if target is authorized and not excluded, or an error message.

    Supports both single IPs and CIDR notation. For CIDRs, every host address
    in the range must fall within an authorized network.
    """
    if not policy.authorized_cidrs:
        return "No authorized CIDRs configured. Add targets to scope/scope-master.txt or create an engagement ROE."

    stripped = target.strip()

    if "/" in stripped:
        try:
            target_net = ipaddress.ip_network(stripped, strict=False)
        except ValueError:
            return f"Invalid CIDR: {stripped}"
        for host in target_net.hosts() if target_net.num_addresses > 1 else [target_net.network_address]:
            excl_err = validate_not_excluded(policy, str(host))
            if excl_err:
                return excl_err
            if not any(host in net for net in policy.networks):
                return f"Target {host} (from {stripped}) is outside authorized scope {policy.authorized_cidrs}"
        return None

    try:
        addr = ipaddress.ip_address(stripped)
    except ValueError:
        return f"Invalid IP address: {stripped}"

    excl_err = validate_not_excluded(policy, stripped)
    if excl_err:
        return excl_err

    for net in policy.networks:
        if addr in net:
            return None
    return f"Target {stripped} is outside authorized scope {policy.authorized_cidrs}"


def validate_targets(policy: RoePolicy, targets: str) -> str | None:
    """Validate a target string split on commas, spaces, or both."""
    import re as _re

    tokens = _re.split(r"[,\s]+", targets.strip())
    for t in tokens:
        if not t:
            continue
        err = validate_target(policy, t)
        if err:
            return err
    return None


def validate_module(policy: RoePolicy, module_path: str) -> str | None:
    """Return None if module is allowed, or an error message if forbidden."""
    for prefix in policy.forbidden_module_prefixes:
        if module_path.startswith(prefix):
            return f"Module {module_path} is blocked by ROE (forbidden prefix: {prefix})"
    return None


def validate_cidr_width(policy: RoePolicy, targets: str) -> str | None:
    """Block scan targets broader than max_scan_cidr (default /24)."""
    for token in targets.replace(",", " ").split():
        token = token.strip()
        if not token:
            continue
        if "/" in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
                if net.prefixlen < policy.max_scan_cidr:
                    return (
                        f"CIDR {token} (/{net.prefixlen}) is broader than the allowed "
                        f"max /{policy.max_scan_cidr}. Narrow the scan target."
                    )
            except ValueError:
                pass
    return None


def validate_domain(policy: RoePolicy, domain: str) -> str | None:
    """Return None if domain is authorized, or an error message.

    Fails closed: if domain validation is requested but authorized_domains is
    empty, the domain is denied rather than silently allowed.
    """
    if not policy.authorized_domains:
        return f"Domain {domain} denied: no authorized domains configured (fail-closed)"
    domain_lower = domain.strip().lower()
    for auth_domain in policy.authorized_domains:
        if domain_lower == auth_domain or domain_lower.endswith("." + auth_domain):
            return None
    return f"Domain {domain} is not in the authorized domain list"


def check_session_limit(policy: RoePolicy) -> str | None:
    """Return an error if the current session count is at or above max_sessions."""
    try:
        from msf_harness.mcp.rpc.client import get_rpc

        client = get_rpc()
        sessions = client.sessions.list
        count = len(sessions) if isinstance(sessions, dict) else 0
        if count >= policy.max_sessions:
            return f"Session limit reached ({count}/{policy.max_sessions}). Terminate sessions before opening new ones."
    except Exception as exc:
        logger.error("Session limit check failed (denying as safety measure): %s", exc)
        return f"Cannot verify session count (RPC error: {exc}). Denying as a safety precaution."
    return None


def _deny(reason: str, engagement_id: str) -> dict:
    """Build a standardized denial response using outputs.denied()."""
    from msf_harness.mcp.models.outputs import denied

    return denied(reason, engagement_id=engagement_id)


def enforce_roe(
    engagement_id: str,
    targets: str | None = None,
    module_path: str | None = None,
    domain: str | None = None,
    check_sessions: bool = False,
    is_exploit: bool = False,
    check_was_run: bool = False,
) -> dict | None:
    """Run all ROE checks. Returns a deny dict if any check fails, or None if all pass.

    Args:
        engagement_id: Active engagement identifier.
        targets: Comma/space-separated target IPs or CIDRs.
        module_path: Metasploit module path to validate.
        domain: Domain name to validate against authorized domains.
        check_sessions: Whether to enforce session limit.
        is_exploit: True when called from msf_run_exploit (triggers check-before-exploit gate).
        check_was_run: True if the caller already ran msf_module_check for this target.
    """
    eid_err = validate_engagement_id(engagement_id)
    if eid_err:
        return _deny(eid_err, engagement_id)

    policy = load_roe(engagement_id)

    if targets:
        err = validate_targets(policy, targets)
        if err:
            logger.warning("ROE DENIED target: %s", err)
            return _deny(err, engagement_id)

        err = validate_cidr_width(policy, targets)
        if err:
            logger.warning("ROE DENIED CIDR width: %s", err)
            return _deny(err, engagement_id)

    if domain:
        err = validate_domain(policy, domain)
        if err:
            logger.warning("ROE DENIED domain: %s", err)
            return _deny(err, engagement_id)

    if module_path:
        err = validate_module(policy, module_path)
        if err:
            logger.warning("ROE DENIED module: %s", err)
            return _deny(err, engagement_id)

    if is_exploit and policy.require_check_before_exploit and not check_was_run:
        reason = (
            "ROE requires msf_module_check before exploitation. Run msf_module_check first or set run_check_first=True."
        )
        logger.warning("ROE DENIED exploit without check: %s", module_path)
        return _deny(reason, engagement_id)

    if check_sessions:
        err = check_session_limit(policy)
        if err:
            logger.warning("ROE DENIED session limit: %s", err)
            return _deny(err, engagement_id)

    return None
