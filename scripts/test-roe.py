#!/usr/bin/env python3
"""Quick ROE policy validation test."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from msf_harness.mcp.policy.roe import (
    clear_policy_cache, enforce_roe, load_roe, validate_module,
    validate_not_excluded, validate_target,
)

clear_policy_cache()
policy = load_roe("lab-default")

print("=== ROE Policy ===")
print("CIDRs:", policy.authorized_cidrs)
print("Exclusions:", policy.excluded_ips)
print("Max sessions:", policy.max_sessions)
print()

scope_file = Path(__file__).resolve().parents[1] / "scope" / "scope-master.txt"
excluded_from_scope = []
for line in scope_file.read_text().splitlines():
    line = line.strip()
    if line.startswith("!"):
        excluded_from_scope.append(line.lstrip("!").split("#")[0].strip())

print("=== Exclusion Tests ===")
for ip in excluded_from_scope:
    err = validate_not_excluded(policy, ip)
    print(f"  {ip}: {'DENY (excluded)' if err else 'BUG - should be excluded!'}")

print()
print("=== In-Scope Tests ===")
for ip in ["10.10.0.10", "10.255.255.254", "172.17.0.2"]:
    err = validate_target(policy, ip)
    print(f"  {ip}: {'ALLOW' if err is None else 'DENY - ' + err}")

print()
print("=== Out-of-Scope Tests ===")
for ip in ["8.8.8.8", "1.2.3.4"]:
    err = validate_target(policy, ip)
    print(f"  {ip}: {'DENY' if err else 'BUG - should be denied!'}")

print()
print("=== Module Block Tests ===")
for mod in ["auxiliary/dos/tcp/synflood", "auxiliary/scanner/ssh/ssh_version"]:
    err = validate_module(policy, mod)
    print(f"  {mod}: {'DENY' if err else 'ALLOW'}")

print()
print("=== enforce_roe Full Tests ===")
print("  out-of-scope:", enforce_roe("lab-default", targets="8.8.8.8"))
print("  in-scope:", enforce_roe("lab-default", targets="10.255.255.254"))
print("  dos module:", enforce_roe("lab-default", module_path="auxiliary/dos/tcp/synflood"))

passed = all([
    validate_not_excluded(policy, ip) is not None for ip in excluded_from_scope
]) and all([
    validate_target(policy, ip) is None for ip in ["10.10.0.10", "10.255.255.254"]
]) and all([
    validate_target(policy, ip) is not None for ip in ["8.8.8.8"]
])

print()
print("ALL TESTS PASSED" if passed else "SOME TESTS FAILED")
