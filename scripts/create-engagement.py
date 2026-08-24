#!/usr/bin/env python3
"""Create a new engagement from the engagements/_template/ scaffold."""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

NAME_PATTERN = re.compile(r"^[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*$")
VALID_TYPES = {"internal_ad", "web_app", "hybrid", "external", "mobile", "cloud"}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def validate_name(name: str) -> str | None:
    if not name:
        return "Engagement name is required."
    if not NAME_PATTERN.match(name):
        return (
            "Invalid name. Use alphanumeric characters and hyphens only "
            "(e.g. client-lab-2026)."
        )
    return None


def format_cidrs_block(cidrs: list[str]) -> str:
    lines = ["authorized_cidrs:"]
    for cidr in cidrs:
        lines.append(f'  - "{cidr}"')
    return "\n".join(lines)


def apply_placeholders(
    dest: Path,
    engagement_id: str,
    engagement_type: str,
    cidrs: list[str],
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    for path in dest.rglob("*"):
        if not path.is_file():
            continue

        text = path.read_text(encoding="utf-8")
        text = text.replace("{{ENGAGEMENT_ID}}", engagement_id)
        text = text.replace("{{engagement_id}}", engagement_id)
        text = text.replace("{{engagement_type}}", engagement_type)
        text = text.replace("{{created_at}}", now)

        if path.name == "roe.yaml":
            text = re.sub(
                r"^engagement_type: .*$",
                f"engagement_type: {engagement_type}",
                text,
                count=1,
                flags=re.MULTILINE,
            )
            if cidrs:
                text = re.sub(
                    r"authorized_cidrs:\n  - \"\{\{TARGET_CIDR\}\}\"",
                    format_cidrs_block(cidrs),
                    text,
                    count=1,
                )

        path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a new Metasploit Cursor Harness engagement."
    )
    parser.add_argument(
        "--name",
        required=True,
        help="Engagement ID (alphanumeric and hyphens only).",
    )
    parser.add_argument(
        "--type",
        default="internal_ad",
        choices=sorted(VALID_TYPES),
        help="Engagement type (default: internal_ad).",
    )
    parser.add_argument(
        "--cidrs",
        default="",
        help="Comma-separated authorized CIDRs (e.g. 10.10.0.0/24,192.168.1.0/24).",
    )
    args = parser.parse_args()

    name = args.name.strip()
    error = validate_name(name)
    if error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    root = repo_root()
    template_dir = root / "engagements" / "_template"
    dest_dir = root / "engagements" / name

    if not template_dir.is_dir():
        print(f"Error: Template not found at {template_dir}", file=sys.stderr)
        return 1

    if dest_dir.exists():
        print(f"Error: Engagement already exists: {dest_dir}", file=sys.stderr)
        return 1

    cidrs = [c.strip() for c in args.cidrs.split(",") if c.strip()]

    shutil.copytree(template_dir, dest_dir)
    apply_placeholders(dest_dir, name, args.type, cidrs)

    world_state_script = root / ".cursor" / "skills" / "pentest-workflow" / "scripts" / "world-state.py"
    if world_state_script.exists():
        try:
            subprocess.run(
                [sys.executable, str(world_state_script), "init", name],
                cwd=str(root),
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError:
            pass

    print(f"Created engagement: {dest_dir}")
    print()
    print("Next steps:")
    print(f"  1. Edit {dest_dir / 'roe.yaml'}")
    if not cidrs:
        print("     - Set authorized_cidrs (replace {{TARGET_CIDR}} placeholder)")
    print(f"  2. Define objectives in {dest_dir / 'objectives.yaml'}")
    print(f"  3. Run gate check:")
    print(f"     python .cursor/skills/pentest-workflow/scripts/gate-check.py {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
