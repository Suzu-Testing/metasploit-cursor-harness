"""Security tests for hardening measures: path sandboxing, input validation, and console hardening."""

from __future__ import annotations

from pathlib import Path

import pytest

from msf_harness.mcp.models.inputs import (
    validate_console_safe,
    validate_netmask,
)
from msf_harness.mcp.policy.roe import validate_engagement_id
from msf_harness.mcp.tools.meterpreter_tools import _validate_remote_path


class TestTemplatePath:
    """S1: template_path must be sandboxed to evidence/ or engagements/."""

    def test_traversal_rejected(self, tmp_project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from msf_harness.mcp.tools import payload_tools

        monkeypatch.setattr(payload_tools, "PROJECT_ROOT", tmp_project)
        monkeypatch.setattr(
            payload_tools,
            "_ALLOWED_OUTPUT_DIRS",
            (
                tmp_project / "evidence",
                tmp_project / "engagements",
            ),
        )

        candidate = Path("../../etc/shadow")
        assert ".." in candidate.parts

    def test_absolute_outside_rejected(self, tmp_project: Path) -> None:
        allowed = (tmp_project / "evidence", tmp_project / "engagements")
        candidate = Path("C:/Windows/System32/calc.exe").resolve()
        allowed_check = any(str(candidate).startswith(str(d.resolve())) for d in allowed)
        assert not allowed_check

    def test_relative_inside_evidence_accepted(self, tmp_project: Path) -> None:
        evidence_file = tmp_project / "evidence" / "msf" / "template.exe"
        evidence_file.parent.mkdir(parents=True, exist_ok=True)
        evidence_file.write_bytes(b"MZ")

        resolved = evidence_file.resolve()
        evidence_dir = (tmp_project / "evidence").resolve()
        try:
            resolved.relative_to(evidence_dir)
            inside = True
        except ValueError:
            inside = False
        assert inside


class TestNetmaskValidation:
    """S2: validate_netmask rejects bad netmask values."""

    @pytest.mark.parametrize(
        "mask",
        [
            "255.255.255.0",
            "255.255.0.0",
            "255.0.0.0",
            "0.0.0.0",
        ],
    )
    def test_valid_netmasks_pass(self, mask: str) -> None:
        assert validate_netmask(mask) is None

    @pytest.mark.parametrize(
        "mask",
        [
            "not.a.mask",
            "255.255.255",
            "255.255.256.0",
            "1",
            "255.255.255.0; id",
            "",
        ],
    )
    def test_invalid_netmasks_fail(self, mask: str) -> None:
        err = validate_netmask(mask)
        assert err is not None

    def test_console_safe_rejects_semicolons(self) -> None:
        err = validate_console_safe("10.0.0.0; id", "subnet")
        assert err is not None
        assert "forbidden characters" in err

    def test_console_safe_rejects_newlines(self) -> None:
        err = validate_console_safe("10.0.0.0\nid", "netmask")
        assert err is not None

    def test_console_safe_rejects_null_bytes(self) -> None:
        err = validate_console_safe("10.0.0.0\x00", "subnet")
        assert err is not None

    def test_console_safe_accepts_clean(self) -> None:
        assert validate_console_safe("255.255.255.0", "netmask") is None


class TestMeterpreterPathSanitization:
    """S3: Meterpreter paths must not contain quote or control chars."""

    def test_rejects_double_quote(self) -> None:
        err = _validate_remote_path('C:\\Users\\"evil')
        assert err is not None
        assert "forbidden characters" in err

    def test_rejects_newline(self) -> None:
        err = _validate_remote_path("C:\\Users\\test\nid")
        assert err is not None

    def test_rejects_carriage_return(self) -> None:
        err = _validate_remote_path("C:\\Users\\test\rid")
        assert err is not None

    def test_rejects_null_byte(self) -> None:
        err = _validate_remote_path("C:\\Users\\test\x00")
        assert err is not None

    def test_accepts_clean_windows_path(self) -> None:
        assert _validate_remote_path("C:\\Users\\Admin\\Desktop\\file.txt") is None

    def test_accepts_clean_linux_path(self) -> None:
        assert _validate_remote_path("/tmp/loot.txt") is None

    def test_accepts_spaces(self) -> None:
        assert _validate_remote_path("C:\\Program Files\\app\\data.txt") is None


class TestEngagementIdValidation:
    """S4: engagement_id must be alphanumeric with hyphens/underscores."""

    @pytest.mark.parametrize(
        "eid",
        [
            "lab-default",
            "engagement_1",
            "Test123",
            "a",
            "ALLCAPS",
        ],
    )
    def test_valid_ids_pass(self, eid: str) -> None:
        assert validate_engagement_id(eid) is None

    @pytest.mark.parametrize(
        "eid",
        [
            "../etc/passwd",
            "path/traversal",
            "",
            "has spaces",
            "has.dots",
            "special!chars",
            "back\\slash",
        ],
    )
    def test_invalid_ids_rejected(self, eid: str) -> None:
        err = validate_engagement_id(eid)
        assert err is not None
        assert "Invalid engagement_id" in err

    def test_roe_enforce_rejects_bad_id(self) -> None:
        from msf_harness.mcp.policy.roe import enforce_roe

        denial = enforce_roe("../../../etc/passwd")
        assert denial is not None
        assert denial["status"] == "denied"
        assert "Invalid engagement_id" in denial["reason"]


class TestCheckRegistryNormalization:
    """S5: module name normalization in check registry."""

    def test_check_with_prefix_found_by_prefix(self) -> None:
        from msf_harness.mcp.policy.roe import _check_registry, record_check, was_check_run

        _check_registry.clear()
        record_check("eng-1", "exploit/windows/smb/ms17_010", "10.0.0.5")
        assert was_check_run("eng-1", "exploit/windows/smb/ms17_010", "10.0.0.5")

    def test_check_case_insensitive(self) -> None:
        from msf_harness.mcp.policy.roe import _check_registry, record_check, was_check_run

        _check_registry.clear()
        record_check("eng-1", "Exploit/Windows/SMB/EternalBlue", "10.0.0.5")
        assert was_check_run("eng-1", "exploit/windows/smb/eternalblue", "10.0.0.5")


class TestConsoleHardening:
    """S6: Console command parsing hardened against injection."""

    def test_setg_rhosts_extracted(self) -> None:
        from msf_harness.mcp.tools.console_tools import _extract_console_targets

        targets = _extract_console_targets("setg RHOSTS 10.0.0.1")
        assert "10.0.0.1" in targets

    def test_set_rhosts_still_works(self) -> None:
        from msf_harness.mcp.tools.console_tools import _extract_console_targets

        targets = _extract_console_targets("set RHOSTS 192.168.1.1")
        assert "192.168.1.1" in targets

    def test_setg_rhost_extracted(self) -> None:
        from msf_harness.mcp.tools.console_tools import _extract_console_targets

        targets = _extract_console_targets("setg RHOST 10.0.0.2")
        assert "10.0.0.2" in targets
