"""Tests for new MCP enhancement features: parse_options_gracefully and check registry."""

from __future__ import annotations

import pytest

from msf_harness.mcp.models.inputs import parse_options_gracefully
from msf_harness.mcp.policy.roe import (
    _CHECK_REGISTRY_TTL,
    _check_registry,
    record_check,
    was_check_run,
)


class TestParseOptionsGracefully:
    """Tests for the graceful option parsing helper."""

    def test_none_returns_empty_dict(self) -> None:
        assert parse_options_gracefully(None) == {}

    def test_dict_returned_as_is(self) -> None:
        opts = {"RHOSTS": "10.0.0.1", "LPORT": 4444}
        assert parse_options_gracefully(opts) is opts

    def test_empty_string_returns_empty_dict(self) -> None:
        assert parse_options_gracefully("") == {}
        assert parse_options_gracefully("   ") == {}

    def test_single_key_value_pair(self) -> None:
        result = parse_options_gracefully("RHOSTS=10.0.0.1")
        assert result == {"RHOSTS": "10.0.0.1"}

    def test_multiple_comma_separated_pairs(self) -> None:
        result = parse_options_gracefully("RHOSTS=10.0.0.1,LPORT=4444,THREADS=10")
        assert result == {"RHOSTS": "10.0.0.1", "LPORT": 4444, "THREADS": 10}

    def test_boolean_coercion(self) -> None:
        result = parse_options_gracefully("SSL=true,VERBOSE=false")
        assert result == {"SSL": True, "VERBOSE": False}

    def test_int_coercion(self) -> None:
        result = parse_options_gracefully("LPORT=4444")
        assert result["LPORT"] == 4444
        assert isinstance(result["LPORT"], int)

    def test_quoted_values(self) -> None:
        result = parse_options_gracefully('PASS="my password"')
        assert result == {"PASS": "my password"}

    def test_missing_equals_raises(self) -> None:
        with pytest.raises(ValueError, match="missing '='"):
            parse_options_gracefully("BADFORMAT")

    def test_empty_key_raises(self) -> None:
        with pytest.raises(ValueError, match="empty key"):
            parse_options_gracefully("=value")


class TestCheckRegistry:
    """Tests for the in-memory check-before-exploit registry."""

    def setup_method(self) -> None:
        _check_registry.clear()

    def test_record_and_query(self) -> None:
        record_check("eng-1", "exploit/windows/smb/ms17_010", "10.0.0.5")
        assert was_check_run("eng-1", "exploit/windows/smb/ms17_010", "10.0.0.5")

    def test_case_insensitive_module(self) -> None:
        record_check("eng-1", "Exploit/Windows/SMB/MS17_010", "10.0.0.5")
        assert was_check_run("eng-1", "exploit/windows/smb/ms17_010", "10.0.0.5")

    def test_different_engagement_not_found(self) -> None:
        record_check("eng-1", "exploit/windows/smb/ms17_010", "10.0.0.5")
        assert not was_check_run("eng-2", "exploit/windows/smb/ms17_010", "10.0.0.5")

    def test_different_target_not_found(self) -> None:
        record_check("eng-1", "exploit/windows/smb/ms17_010", "10.0.0.5")
        assert not was_check_run("eng-1", "exploit/windows/smb/ms17_010", "10.0.0.6")

    def test_none_target(self) -> None:
        record_check("eng-1", "exploit/test", None)
        assert was_check_run("eng-1", "exploit/test", None)
        assert was_check_run("eng-1", "exploit/test", "")

    def test_expired_entry_not_found(self) -> None:
        import time

        record_check("eng-1", "exploit/test", "10.0.0.5")
        key = ("eng-1", "exploit/test", "10.0.0.5")
        _check_registry[key] = time.time() - _CHECK_REGISTRY_TTL - 1
        assert not was_check_run("eng-1", "exploit/test", "10.0.0.5")
        assert key not in _check_registry

    def test_unrecorded_returns_false(self) -> None:
        assert not was_check_run("eng-1", "exploit/test", "10.0.0.5")
