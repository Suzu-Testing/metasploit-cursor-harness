"""Shared pytest fixtures for Metasploit Cursor Harness MCP tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from msf_harness.mcp.policy import roe as roe_module
from msf_harness.mcp.policy.roe import RoePolicy, clear_policy_cache, load_roe
from msf_harness.mcp.tools import workspace_tools as ws_tools

SCOPE_MASTER_CONTENT = """\
# Authorized lab networks
10.0.0.0/24
192.168.1.0/24

!10.0.0.1  # gateway
!192.168.1.254
"""

IN_SCOPE_DOMAINS_CONTENT = """\
# Global in-scope domains
lab.test
shared.example
"""

ROE_YAML_CONTENT = """\
engagement_id: test-engagement
authorized_cidrs:
  - 10.10.10.0/24
  - 172.16.0.0/24
excluded_ips:
  - 10.10.10.5
authorized_domains:
  - example.test
forbidden_module_prefixes:
  - auxiliary/dos/
require_check_before_exploit: true
max_sessions: 3
max_scan_cidr: 24
"""


@pytest.fixture
def roe_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """Create temp scope/engagement dirs and patch ROE module path constants."""
    clear_policy_cache()

    scope_dir = tmp_path / "scope"
    scope_dir.mkdir()
    engagements_dir = tmp_path / "engagements"
    engagements_dir.mkdir()

    scope_file = scope_dir / "scope-master.txt"
    scope_file.write_text(SCOPE_MASTER_CONTENT, encoding="utf-8")

    domains_file = scope_dir / "in-scope-domains.txt"
    domains_file.write_text(IN_SCOPE_DOMAINS_CONTENT, encoding="utf-8")

    engagement_dir = engagements_dir / "test-engagement"
    engagement_dir.mkdir()
    (engagement_dir / "roe.yaml").write_text(ROE_YAML_CONTENT, encoding="utf-8")

    monkeypatch.setattr(roe_module, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(roe_module, "SCOPE_FILE", scope_file)
    monkeypatch.setattr(roe_module, "ENGAGEMENTS_DIR", engagements_dir)

    yield {
        "root": tmp_path,
        "scope_dir": scope_dir,
        "scope_file": scope_file,
        "domains_file": domains_file,
        "engagements_dir": engagements_dir,
        "engagement_dir": engagement_dir,
        "engagement_id": "test-engagement",
    }

    clear_policy_cache()


@pytest.fixture(autouse=True)
def _clear_roe_cache() -> None:
    """Ensure each test starts with an empty ROE policy cache."""
    clear_policy_cache()
    yield
    clear_policy_cache()


@pytest.fixture
def loaded_policy(roe_paths: dict[str, Path]) -> RoePolicy:
    """Load a RoePolicy from the temporary engagement roe.yaml."""
    return load_roe(roe_paths["engagement_id"])


@pytest.fixture
def scope_only_policy(roe_paths: dict[str, Path]) -> RoePolicy:
    """Load a RoePolicy that falls back to scope-master.txt only."""
    return load_roe("no-engagement-yaml")


@pytest.fixture
def manual_policy() -> RoePolicy:
    """Construct a RoePolicy directly for unit tests that do not need disk I/O."""
    return RoePolicy(
        engagement_id="manual",
        authorized_cidrs=["10.0.0.0/24"],
        excluded_ips=["10.0.0.1"],
        forbidden_module_prefixes=["auxiliary/dos/"],
        require_check_before_exploit=True,
        max_sessions=5,
        authorized_domains=["example.test", "lab.test"],
        max_scan_cidr=24,
    )


@pytest.fixture
def mock_rpc_client() -> MagicMock:
    """Fake MsfRpcClient for unit tests."""
    client = MagicMock()
    client.sessions.list = {}
    client.jobs.list = {}
    client.call = MagicMock(return_value={})
    client.modules.use = MagicMock()
    client.modules.search = MagicMock(return_value=[])
    return client


@pytest.fixture
def tmp_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create a temp directory with evidence/msf/, engagements/, and scope/ layout."""
    evidence_dir = tmp_path / "evidence" / "msf"
    evidence_dir.mkdir(parents=True)
    (tmp_path / "engagements").mkdir(exist_ok=True)
    (tmp_path / "scope").mkdir(exist_ok=True)

    allowed_dirs = (tmp_path / "evidence", tmp_path / "engagements")
    monkeypatch.setattr(ws_tools, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(ws_tools, "_ALLOWED_IMPORT_DIRS", allowed_dirs)
    monkeypatch.setattr(roe_module, "PROJECT_ROOT", tmp_path)

    return tmp_path
