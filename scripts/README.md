# Utility Scripts

## Core Scripts

| Script | Usage | Purpose |
|--------|-------|---------|
| `create-engagement.py` | `python scripts/create-engagement.py --name <name>` | Create a new engagement from the `_template/` scaffold |
| `start-msfrpcd.ps1` | `.\scripts\start-msfrpcd.ps1` | Start msfdb and msfrpcd in WSL using `.env` credentials |
| `validate-mcp.py` | `python scripts/validate-mcp.py` | Smoke test RPC connectivity and tool registration |
| `test-roe.py` | `python scripts/test-roe.py` | Validate ROE policy enforcement for the lab-default engagement |

## Lab Scripts

| Script | Usage | Purpose |
|--------|-------|---------|
| `reset-lab.ps1` | `.\scripts\reset-lab.ps1` | Clear lab engagement state, evidence, and logs |
| `start-lab-targets.ps1` | `.\scripts\start-lab-targets.ps1` | Start Docker lab target stack via docker-compose |

## Development Scripts

| Script | Usage | Purpose |
|--------|-------|---------|
| `dev/mvp-attack.py` | (unsupported) | Development exploit test against lab targets |
| `dev/mvp-irc-attack.py` | (unsupported) | Development IRC exploit test |
| `dev/attack-metasploitable2.py` | (unsupported) | Metasploitable2 chain test |

## Workflow Scripts (under .cursor/skills/)

| Script | Usage | Purpose |
|--------|-------|---------|
| `pentest-workflow/scripts/gate-check.py` | `python .cursor/skills/pentest-workflow/scripts/gate-check.py {engagement_id}` | Check gate/subgate status for an engagement |
| `pentest-workflow/scripts/complete-subgate.py` | `python .cursor/skills/pentest-workflow/scripts/complete-subgate.py {subgate_id}` | Mark a subgate as completed |
| `pentest-knowledge-base/scripts/generate-skills.py` | `python .cursor/skills/pentest-knowledge-base/scripts/generate-skills.py --list` | List all available skills |
