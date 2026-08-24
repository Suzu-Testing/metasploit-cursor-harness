"""Tests for path validation helpers in workspace and payload tools."""

from __future__ import annotations

from pathlib import Path

import pytest

from msf_harness.mcp.tools import workspace_tools as ws


class TestValidateSafePath:
    """Tests for _validate_safe_path in workspace_tools."""

    def test_rejects_path_traversal(self, tmp_project: Path) -> None:
        result = ws._validate_safe_path("../../etc/passwd", ws._ALLOWED_IMPORT_DIRS)
        assert isinstance(result, str)
        assert "Path traversal not allowed" in result

    def test_rejects_absolute_path_outside_allowed_dirs(self, tmp_project: Path, tmp_path: Path) -> None:
        outside = tmp_path / "outside.xml"
        outside.write_text("<nmaprun/>", encoding="utf-8")
        result = ws._validate_safe_path(str(outside), ws._ALLOWED_IMPORT_DIRS)
        assert isinstance(result, str)
        assert "Path must be inside" in result

    def test_accepts_path_inside_evidence(self, tmp_project: Path) -> None:
        scan_file = tmp_project / "evidence" / "msf" / "scan.xml"
        scan_file.write_text("<nmaprun/>", encoding="utf-8")
        result = ws._validate_safe_path("evidence/msf/scan.xml", ws._ALLOWED_IMPORT_DIRS)
        assert isinstance(result, Path)
        assert result == scan_file.resolve()

    def test_accepts_path_inside_engagements(self, tmp_project: Path) -> None:
        scan_file = tmp_project / "engagements" / "test-eng" / "scan.nessus"
        scan_file.parent.mkdir(parents=True)
        scan_file.write_text("<NessusClientData_v2/>", encoding="utf-8")
        result = ws._validate_safe_path("engagements/test-eng/scan.nessus", ws._ALLOWED_IMPORT_DIRS)
        assert isinstance(result, Path)
        assert result == scan_file.resolve()


class TestAllowedImportExtensions:
    """Tests for _ALLOWED_IMPORT_EXTS allowlist."""

    @pytest.mark.parametrize("ext", [".exe", ".dll", ".bat", ".sh"])
    def test_rejects_unknown_extensions(self, ext: str) -> None:
        assert ext not in ws._ALLOWED_IMPORT_EXTS

    @pytest.mark.parametrize("ext", [".xml", ".nessus", ".csv", ".json", ".txt"])
    def test_accepts_known_extensions(self, ext: str) -> None:
        assert ext in ws._ALLOWED_IMPORT_EXTS


class TestSanitizeNmapArgs:
    """Tests for _sanitize_nmap_args flag allowlist."""

    def test_rejects_dangerous_flags(self) -> None:
        err = ws._sanitize_nmap_args("-sV ; id")
        assert err is not None
        assert "Disallowed nmap argument" in err

        err = ws._sanitize_nmap_args("-sV $(whoami)")
        assert err is not None
        assert "Disallowed nmap argument" in err

    def test_accepts_common_flags(self) -> None:
        assert ws._sanitize_nmap_args("-sV -sC") is None
        assert ws._sanitize_nmap_args("-sV -sC -p 80,443 10.0.0.0/24") is None
