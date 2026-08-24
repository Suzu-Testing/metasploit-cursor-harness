"""Tests for MCP input validation in msf_harness.mcp.models.inputs."""

from __future__ import annotations

import pytest

from msf_harness.mcp.models.inputs import (
    MAX_LIMIT,
    clamp_limit,
    validate_ip,
    validate_module_type,
    validate_ports,
    validate_workspace,
)


class TestValidateWorkspace:
    """Tests for Metasploit workspace name validation."""

    @pytest.mark.parametrize(
        "name",
        ["default", "lab_workspace", "engagement-1", "Workspace123"],
    )
    def test_valid_names_pass(self, name: str) -> None:
        assert validate_workspace(name) is None

    @pytest.mark.parametrize(
        "name",
        ["bad name", "has/slash", "dot.name", "spaces here", "unicode™"],
    )
    def test_special_chars_fail(self, name: str) -> None:
        err = validate_workspace(name)
        assert err is not None
        assert "Invalid workspace name" in err


class TestValidateIp:
    """Tests for IP address and CIDR validation."""

    @pytest.mark.parametrize(
        "ip",
        ["127.0.0.1", "10.0.0.1", "192.168.1.100", "::1", "2001:db8::1"],
    )
    def test_valid_ipv4_and_ipv6_pass(self, ip: str) -> None:
        assert validate_ip(ip) is None

    @pytest.mark.parametrize(
        "cidr",
        ["10.0.0.0/24", "192.168.1.0/32", "2001:db8::/32"],
    )
    def test_valid_cidr_passes(self, cidr: str) -> None:
        assert validate_ip(cidr) is None

    @pytest.mark.parametrize(
        "bad",
        ["not-an-ip", "999.999.999.999", "10.0.0.0/99", "", "10.0.0"],
    )
    def test_invalid_strings_fail(self, bad: str) -> None:
        err = validate_ip(bad)
        assert err is not None
        assert "Invalid IP or CIDR" in err


class TestValidatePorts:
    """Tests for port and port-range specification validation."""

    def test_single_port_passes(self) -> None:
        assert validate_ports("443") is None

    def test_port_range_passes(self) -> None:
        assert validate_ports("80-443") is None

    def test_comma_separated_and_ranges_pass(self) -> None:
        assert validate_ports("22,80-90,443") is None

    @pytest.mark.parametrize(
        "ports",
        ["0", "65536", "80-70000", "abc", "80-", "-443"],
    )
    def test_out_of_range_or_malformed_fail(self, ports: str) -> None:
        err = validate_ports(ports)
        assert err is not None


class TestValidateModuleType:
    """Tests for Metasploit module type validation."""

    @pytest.mark.parametrize(
        "module_type",
        ["exploit", "auxiliary", "post", "payload", "encoder", "nop"],
    )
    def test_valid_types_pass(self, module_type: str) -> None:
        assert validate_module_type(module_type) is None

    def test_invalid_type_fails(self) -> None:
        err = validate_module_type("scanner")
        assert err is not None
        assert "Invalid module type" in err
        assert "exploit" in err


class TestClampLimit:
    """Tests for query limit clamping to [1, MAX_LIMIT]."""

    def test_below_min_clamped_to_one(self) -> None:
        assert clamp_limit(0) == 1
        assert clamp_limit(-50) == 1

    def test_above_max_clamped_to_max_limit(self) -> None:
        assert clamp_limit(MAX_LIMIT + 1) == MAX_LIMIT
        assert clamp_limit(99999) == MAX_LIMIT

    def test_in_range_unchanged(self) -> None:
        assert clamp_limit(1) == 1
        assert clamp_limit(100) == 100
        assert clamp_limit(MAX_LIMIT) == MAX_LIMIT
