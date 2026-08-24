"""Tests for Rules of Engagement enforcement in msf_harness.mcp.policy.roe."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from msf_harness.mcp.policy import roe as roe_module
from msf_harness.mcp.policy.roe import (
    RoePolicy,
    _load_scope_file,
    check_session_limit,
    clear_policy_cache,
    enforce_roe,
    load_roe,
    validate_cidr_width,
    validate_domain,
    validate_module,
    validate_not_excluded,
    validate_target,
    validate_targets,
)


class TestLoadScopeFile:
    """Tests for parsing scope/scope-master.txt."""

    def test_parses_cidrs_and_exclusions(self, roe_paths: dict[str, Path]) -> None:
        cidrs, exclusions = _load_scope_file()
        assert cidrs == ["10.0.0.0/24", "192.168.1.0/24"]
        assert exclusions == ["10.0.0.1", "192.168.1.254"]

    def test_returns_empty_when_scope_file_missing(
        self, roe_paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        missing = roe_paths["root"] / "missing-scope.txt"
        monkeypatch.setattr(roe_module, "SCOPE_FILE", missing)
        cidrs, exclusions = _load_scope_file()
        assert cidrs == []
        assert exclusions == []


class TestLoadRoe:
    """Tests for loading engagement ROE from disk and cache behavior."""

    def test_loads_from_roe_yaml(self, roe_paths: dict[str, Path]) -> None:
        policy = load_roe(roe_paths["engagement_id"])
        assert policy.engagement_id == "test-engagement"
        assert "10.10.10.0/24" in policy.authorized_cidrs
        assert "172.16.0.0/24" in policy.authorized_cidrs
        assert "10.10.10.5" in policy.excluded_ips
        assert "10.0.0.1" in policy.excluded_ips  # merged from scope-master.txt
        assert "example.test" in policy.authorized_domains
        assert "lab.test" in policy.authorized_domains  # merged from domains file
        assert policy.max_sessions == 3
        assert policy.max_scan_cidr == 24

    def test_fallback_to_scope_master_only(self, scope_only_policy: RoePolicy) -> None:
        assert scope_only_policy.engagement_id == "no-engagement-yaml"
        assert scope_only_policy.authorized_cidrs == ["10.0.0.0/24", "192.168.1.0/24"]
        assert "10.0.0.1" in scope_only_policy.excluded_ips
        assert "lab.test" in scope_only_policy.authorized_domains
        assert scope_only_policy.max_sessions == 5

    def test_caches_loaded_policy(self, roe_paths: dict[str, Path]) -> None:
        first = load_roe(roe_paths["engagement_id"])
        second = load_roe(roe_paths["engagement_id"])
        assert first is second


class TestValidateTarget:
    """Tests for single-target IP authorization and exclusion checks."""

    def test_in_scope_ip_passes(self, loaded_policy: RoePolicy) -> None:
        assert validate_target(loaded_policy, "10.10.10.50") is None

    def test_out_of_scope_ip_fails(self, loaded_policy: RoePolicy) -> None:
        err = validate_target(loaded_policy, "8.8.8.8")
        assert err is not None
        assert "outside authorized scope" in err

    def test_excluded_ip_fails(self, loaded_policy: RoePolicy) -> None:
        err = validate_target(loaded_policy, "10.10.10.5")
        assert err is not None
        assert "exclusion list" in err

    def test_invalid_ip_errors(self, loaded_policy: RoePolicy) -> None:
        err = validate_target(loaded_policy, "not-an-ip")
        assert err is not None
        assert "Invalid IP address" in err

    def test_no_authorized_cidrs_errors(self) -> None:
        policy = RoePolicy(engagement_id="empty", authorized_cidrs=[])
        err = validate_target(policy, "10.0.0.1")
        assert err is not None
        assert "No authorized CIDRs configured" in err

    def test_cidr_target_in_scope(self, loaded_policy: RoePolicy) -> None:
        assert validate_target(loaded_policy, "10.10.10.16/28") is None

    def test_cidr_target_out_of_scope(self, loaded_policy: RoePolicy) -> None:
        err = validate_target(loaded_policy, "8.8.8.0/24")
        assert err is not None
        assert "outside authorized scope" in err

    def test_invalid_cidr_errors(self, loaded_policy: RoePolicy) -> None:
        err = validate_target(loaded_policy, "not-a-cidr/24")
        assert err is not None
        assert "Invalid" in err


class TestValidateTargets:
    """Tests for comma- and space-separated target validation."""

    def test_comma_separated_all_valid(self, loaded_policy: RoePolicy) -> None:
        assert validate_targets(loaded_policy, "10.10.10.10,10.10.10.20") is None

    def test_comma_separated_one_invalid(self, loaded_policy: RoePolicy) -> None:
        err = validate_targets(loaded_policy, "10.10.10.10,8.8.8.8")
        assert err is not None
        assert "outside authorized scope" in err

    def test_space_separated_all_valid(self, loaded_policy: RoePolicy) -> None:
        assert validate_targets(loaded_policy, "10.10.10.10 10.10.10.20") is None

    def test_space_separated_one_excluded(self, loaded_policy: RoePolicy) -> None:
        err = validate_targets(loaded_policy, "10.10.10.10 10.10.10.5")
        assert err is not None
        assert "exclusion list" in err

    def test_single_target_without_separator(self, loaded_policy: RoePolicy) -> None:
        assert validate_targets(loaded_policy, "10.10.10.10") is None

    def test_mixed_separator_targets(self, loaded_policy: RoePolicy) -> None:
        assert validate_targets(loaded_policy, "10.10.10.10, 10.10.10.20 10.10.10.30") is None

    def test_cidr_in_mixed_targets(self) -> None:
        policy = RoePolicy(
            engagement_id="mixed-cidr",
            authorized_cidrs=["10.10.10.0/24"],
            excluded_ips=[],
        )
        assert validate_targets(policy, "10.10.10.10,10.10.10.0/28") is None


class TestValidateNotExcluded:
    """Tests for exclusion-list checks independent of CIDR scope."""

    def test_non_excluded_ip_passes(self, loaded_policy: RoePolicy) -> None:
        assert validate_not_excluded(loaded_policy, "10.10.10.50") is None

    def test_excluded_ip_fails(self, loaded_policy: RoePolicy) -> None:
        err = validate_not_excluded(loaded_policy, "10.10.10.5")
        assert err is not None
        assert "exclusion list" in err

    def test_invalid_ip_returns_none(self, loaded_policy: RoePolicy) -> None:
        assert validate_not_excluded(loaded_policy, "not-an-ip") is None


class TestValidateModule:
    """Tests for forbidden module prefix enforcement."""

    def test_dos_module_blocked(self, loaded_policy: RoePolicy) -> None:
        err = validate_module(loaded_policy, "auxiliary/dos/http/slowloris")
        assert err is not None
        assert "blocked by ROE" in err
        assert "auxiliary/dos/" in err

    def test_exploit_module_allowed(self, loaded_policy: RoePolicy) -> None:
        assert validate_module(loaded_policy, "exploit/windows/smb/ms17_010_eternalblue") is None


class TestValidateCidrWidth:
    """Tests for maximum scan CIDR width enforcement."""

    def test_slash_24_allowed(self, loaded_policy: RoePolicy) -> None:
        assert validate_cidr_width(loaded_policy, "10.10.10.0/24") is None

    def test_slash_16_blocked_when_max_is_24(self, loaded_policy: RoePolicy) -> None:
        err = validate_cidr_width(loaded_policy, "10.0.0.0/16")
        assert err is not None
        assert "broader than the allowed max /24" in err

    def test_comma_separated_cidrs_checked(self, loaded_policy: RoePolicy) -> None:
        err = validate_cidr_width(loaded_policy, "10.10.10.0/24,172.16.0.0/16")
        assert err is not None
        assert "/16" in err


class TestValidateDomain:
    """Tests for authorized domain matching."""

    def test_exact_match_passes(self, loaded_policy: RoePolicy) -> None:
        assert validate_domain(loaded_policy, "example.test") is None

    def test_subdomain_match_passes(self, loaded_policy: RoePolicy) -> None:
        assert validate_domain(loaded_policy, "app.example.test") is None

    def test_unauthorized_domain_fails(self, loaded_policy: RoePolicy) -> None:
        err = validate_domain(loaded_policy, "evil.com")
        assert err is not None
        assert "not in the authorized domain list" in err

    def test_no_domains_configured_fails_closed(self) -> None:
        policy = RoePolicy(engagement_id="no-domains", authorized_domains=[])
        err = validate_domain(policy, "anything.example")
        assert err is not None
        assert "fail-closed" in err


class TestCheckSessionLimit:
    """Tests for session count enforcement against RPC."""

    def test_under_limit_passes(self, manual_policy: RoePolicy, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_client = MagicMock()
        mock_client.sessions.list = {"1": {}, "2": {}}
        monkeypatch.setattr(
            "msf_harness.mcp.rpc.client.get_rpc",
            lambda: mock_client,
        )
        assert check_session_limit(manual_policy) is None

    def test_at_limit_fails(self, manual_policy: RoePolicy, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_client = MagicMock()
        mock_client.sessions.list = {str(i): {} for i in range(manual_policy.max_sessions)}
        monkeypatch.setattr(
            "msf_harness.mcp.rpc.client.get_rpc",
            lambda: mock_client,
        )
        err = check_session_limit(manual_policy)
        assert err is not None
        assert "Session limit reached" in err

    def test_rpc_exception_fails_closed(self, manual_policy: RoePolicy, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise_rpc() -> None:
            raise ConnectionError("RPC unavailable")

        monkeypatch.setattr("msf_harness.mcp.rpc.client.get_rpc", _raise_rpc)
        err = check_session_limit(manual_policy)
        assert err is not None
        assert "Cannot verify session count" in err
        assert "Denying as a safety precaution" in err


class TestEnforceRoe:
    """Tests for full ROE orchestration via enforce_roe()."""

    def test_all_checks_pass_returns_none(self, roe_paths: dict[str, Path]) -> None:
        result = enforce_roe(
            roe_paths["engagement_id"],
            targets="10.10.10.10",
            module_path="exploit/linux/http/apache_mod_cgi_bash_env_exec",
            domain="app.example.test",
        )
        assert result is None

    def test_denies_out_of_scope_target(self, roe_paths: dict[str, Path]) -> None:
        result = enforce_roe(roe_paths["engagement_id"], targets="8.8.8.8")
        assert result is not None
        assert result["status"] == "denied"
        assert result["engagement_id"] == roe_paths["engagement_id"]
        assert "outside authorized scope" in result["reason"]

    def test_denies_forbidden_module(self, roe_paths: dict[str, Path]) -> None:
        result = enforce_roe(
            roe_paths["engagement_id"],
            module_path="auxiliary/dos/tcp/synflood",
        )
        assert result is not None
        assert result["status"] == "denied"
        assert "blocked by ROE" in result["reason"]

    def test_denies_exploit_without_check(self, roe_paths: dict[str, Path]) -> None:
        result = enforce_roe(
            roe_paths["engagement_id"],
            targets="10.10.10.10",
            module_path="exploit/linux/http/apache_mod_cgi_bash_env_exec",
            is_exploit=True,
            check_was_run=False,
        )
        assert result is not None
        assert result["status"] == "denied"
        assert "msf_module_check" in result["reason"]

    def test_allows_exploit_when_check_was_run(self, roe_paths: dict[str, Path]) -> None:
        result = enforce_roe(
            roe_paths["engagement_id"],
            targets="10.10.10.10",
            module_path="exploit/linux/http/apache_mod_cgi_bash_env_exec",
            is_exploit=True,
            check_was_run=True,
        )
        assert result is None

    def test_denies_broad_cidr_scan(self, roe_paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
        # validate_target accepts host IPs only; patch target check to isolate CIDR width gate.
        monkeypatch.setattr(roe_module, "validate_targets", lambda _policy, _targets: None)
        result = enforce_roe(roe_paths["engagement_id"], targets="10.10.10.0/16")
        assert result is not None
        assert result["status"] == "denied"
        assert "broader than the allowed" in result["reason"]

    def test_denies_when_session_limit_check_fails(
        self, roe_paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_client = MagicMock()
        mock_client.sessions.list = {"1": {}, "2": {}, "3": {}}
        monkeypatch.setattr("msf_harness.mcp.rpc.client.get_rpc", lambda: mock_client)
        result = enforce_roe(
            roe_paths["engagement_id"],
            targets="10.10.10.10",
            check_sessions=True,
        )
        assert result is not None
        assert result["status"] == "denied"
        assert "Session limit reached" in result["reason"]

    def test_denies_unauthorized_domain(self, roe_paths: dict[str, Path]) -> None:
        result = enforce_roe(roe_paths["engagement_id"], domain="evil.com")
        assert result is not None
        assert result["status"] == "denied"
        assert "not in the authorized domain list" in result["reason"]

    def test_allows_authorized_domain(self, roe_paths: dict[str, Path]) -> None:
        assert enforce_roe(roe_paths["engagement_id"], domain="app.example.test") is None


class TestRoeCacheInvalidation:
    """Tests for mtime-based ROE policy cache invalidation."""

    def test_mtime_change_invalidates_cache(self, roe_paths: dict[str, Path]) -> None:
        engagement_id = roe_paths["engagement_id"]
        first = load_roe(engagement_id)

        scope_file = roe_paths["scope_file"]
        new_mtime = scope_file.stat().st_mtime + 10
        os.utime(scope_file, (new_mtime, new_mtime))

        second = load_roe(engagement_id)
        assert first is not second

    def test_roe_yaml_change_invalidates_cache(self, roe_paths: dict[str, Path]) -> None:
        engagement_id = roe_paths["engagement_id"]
        first = load_roe(engagement_id)

        roe_yaml = roe_paths["engagement_dir"] / "roe.yaml"
        roe_yaml.write_text(
            roe_yaml.read_text(encoding="utf-8").replace("max_sessions: 3", "max_sessions: 4"),
            encoding="utf-8",
        )

        second = load_roe(engagement_id)
        assert first is not second
        assert second.max_sessions == 4


class TestClearPolicyCache:
    """Tests for ROE policy cache invalidation."""

    def test_clear_policy_cache_forces_reload(self, roe_paths: dict[str, Path]) -> None:
        engagement_id = roe_paths["engagement_id"]
        first = load_roe(engagement_id)
        clear_policy_cache()
        roe_paths["scope_file"].write_text("203.0.113.0/24\n", encoding="utf-8")
        fallback = load_roe("cache-fallback-test")
        assert "203.0.113.0/24" in fallback.authorized_cidrs

        clear_policy_cache()
        reloaded = load_roe(engagement_id)
        assert reloaded is not first
        assert first.authorized_cidrs != reloaded.authorized_cidrs or first is not reloaded
