"""Test that all expected MCP tools are registered."""

import re
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1] / "msf_harness" / "mcp" / "tools"
EXPECTED_TOOL_COUNT = 54

TOOL_NAME_RE = re.compile(r'name="(msf_\w+)"')


def test_tool_count():
    """Every tool module must register exactly EXPECTED_TOOL_COUNT total tools."""
    names: set[str] = set()
    for py_file in sorted(TOOLS_DIR.glob("*.py")):
        if py_file.name.startswith("__"):
            continue
        text = py_file.read_text(encoding="utf-8")
        for m in TOOL_NAME_RE.finditer(text):
            names.add(m.group(1))

    assert len(names) == EXPECTED_TOOL_COUNT, (
        f"Expected {EXPECTED_TOOL_COUNT} tools, found {len(names)}: {sorted(names)}"
    )


def test_no_duplicate_tool_names():
    """Each tool name must be unique across all modules."""
    names: list[str] = []
    for py_file in sorted(TOOLS_DIR.glob("*.py")):
        if py_file.name.startswith("__"):
            continue
        text = py_file.read_text(encoding="utf-8")
        for m in TOOL_NAME_RE.finditer(text):
            names.append(m.group(1))

    seen: set[str] = set()
    dupes: list[str] = []
    for n in names:
        if n in seen:
            dupes.append(n)
        seen.add(n)

    assert not dupes, f"Duplicate tool names: {dupes}"
