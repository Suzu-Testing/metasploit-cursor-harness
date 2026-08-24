# Engagement Workflow Catalogs

Phases, gates, and subgates for the Metasploit Cursor Harness.

## Structure

```
Phase (7 PTES-aligned)
  └── Gate (exit criteria)
        └── Subgate (atomic task)
              └── Skill (agent loads)
                    └── Agent (optional delegate)
```

## Files

| File | Content |
|------|---------|
| `phases.yaml` | Phase machine, gate criteria, skill/agent routing |
| `subgates-common.yaml` | Pre-engage, model, exploit, report subgates |
| `subgates-web-app.yaml` | OWASP WSTG subgates |
| `subgates-internal-ad.yaml` | MITRE ATT&CK internal/AD subgates |

## Per-engagement state

```
engagements/{id}/
  roe.yaml           # engagement_type, CIDRs, limits
  phase-state.yaml   # current_phase, completed_subgates
  objectives.yaml    # objectives with status
  targets.yaml       # prioritized targets (model phase)
```

## Commands

```powershell
python .cursor/skills/pentest-workflow/scripts/gate-check.py lab-default
python .cursor/skills/pentest-workflow/scripts/complete-subgate.py SG0.1-scope-verify --engagement lab-default
python .cursor/skills/pentest-workflow/scripts/gate-check.py lab-default --advance
```

## Framework basis

See `.cursor/skills/pentest-workflow/frameworks.md` for PTES, NIST, OWASP WSTG, ATT&CK, and Unified Kill Chain mapping.
