"""Tests for console command target/module parsing in console_tools."""

from __future__ import annotations

from msf_harness.mcp.tools import console_tools as ct


def _triggers_exploit_gate(command: str) -> bool:
    """Mirror msf_console_execute exploit-gate condition."""
    modules = ct._extract_console_modules(command)
    return ct._console_has_exploit_verb(command) and ct._console_has_exploit_module(modules)


class TestExtractConsoleTargets:
    """Tests for _extract_console_targets."""

    def test_parses_set_rhosts(self) -> None:
        targets = ct._extract_console_targets("set RHOSTS 10.0.0.1")
        assert targets == ["10.0.0.1"]

    def test_parses_db_nmap_cidr(self) -> None:
        targets = ct._extract_console_targets("db_nmap 10.0.0.0/24")
        assert targets == ["10.0.0.0/24"]

    def test_handles_multiple_rhosts(self) -> None:
        command = "set RHOSTS 10.0.0.1,10.0.0.2\nset rhost 192.168.1.5"
        targets = ct._extract_console_targets(command)
        assert targets == ["10.0.0.1", "10.0.0.2", "192.168.1.5"]


class TestExtractConsoleModules:
    """Tests for _extract_console_modules."""

    def test_parses_exploit_module(self) -> None:
        command = "use exploit/windows/smb/ms17_010_eternalblue"
        modules = ct._extract_console_modules(command)
        assert modules == ["exploit/windows/smb/ms17_010_eternalblue"]

    def test_parses_auxiliary_module(self) -> None:
        command = "use auxiliary/scanner/smb/smb_version"
        modules = ct._extract_console_modules(command)
        assert modules == ["auxiliary/scanner/smb/smb_version"]


class TestConsoleExploitDetection:
    """Tests for exploit verb and module detection."""

    def test_console_has_exploit_verb_detects_exploit_and_run(self) -> None:
        assert ct._console_has_exploit_verb("exploit") is True
        assert ct._console_has_exploit_verb("run") is True
        assert ct._console_has_exploit_verb("set RHOSTS 10.0.0.1") is False

    def test_console_has_exploit_module_identifies_exploit_modules(self) -> None:
        assert ct._console_has_exploit_module(["exploit/windows/smb/ms17_010_eternalblue"]) is True
        assert ct._console_has_exploit_module(["auxiliary/scanner/smb/smb_version"]) is False


class TestExploitGateCombined:
    """Tests for combined exploit-gate triggering logic."""

    def test_exploit_module_with_exploit_verb_triggers_gate(self) -> None:
        command = "use exploit/windows/smb/ms17_010_eternalblue ; exploit"
        assert _triggers_exploit_gate(command) is True

    def test_auxiliary_module_with_run_does_not_trigger_gate(self) -> None:
        command = "use auxiliary/scanner/smb/smb_version ; run"
        assert _triggers_exploit_gate(command) is False
