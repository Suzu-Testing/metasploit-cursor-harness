# Metasploit Cursor Harness - Agent Context

## Project Intent

This is an agentic penetration testing harness that bridges Cursor AI agents with the Metasploit Framework via MCP (Model Context Protocol). It provides structured, scope-enforced access to Metasploit RPC for reconnaissance, exploitation, session management, and post-exploitation.

## Architecture

- **MCP Server** (`msf_harness/mcp/`): Python FastMCP server exposing 54 tools over stdio
- **RPC Backend**: `msfrpcd` on 127.0.0.1:55553 via MessagePack RPC (WSL/Kali or native Linux)
- **Policy Layer** (`msf_harness/mcp/policy/roe.py`): Server-side CIDR/domain validation, module blocking, session limits, CIDR width caps, and check-before-exploit enforcement
- **Hooks** (`.cursor/hooks/`): PowerShell gates for scope enforcement, risk scoring, duplicate detection (world-state), and audit logging
- **Skills** (`.cursor/skills/`): 57 workflow playbooks for recon, exploitation, post-exploitation, and domain-specific testing
- **Subagents** (`.cursor/agents/`): Specialized agents for orchestration, recon, exploit chains, post-exploitation, and review

## Prerequisites

1. Python 3.10+ with `pip install -e ".[mcp]"`
2. Metasploit Framework installed (WSL/Kali or native Linux)
3. Start RPC: `./scripts/start-msfrpcd.sh` (Linux) or `.\scripts\start-msfrpcd.ps1` (Windows/WSL)
4. Set `MSF_USER` and `MSF_PASSWORD` in `.env` (copy from `.env.example`)

## MCP Tools (54 total)

### Read-Only Tools (no engagement_id required)
| Tool | Purpose |
|------|---------|
| `msf_status` | Check RPC connectivity and version |
| `msf_search_modules` | Search Metasploit module database |
| `msf_module_info` | Get detailed module information |
| `msf_module_options` | Get only configurable options for a module |
| `msf_list_modules` | List modules by type with optional filter |
| `msf_running_stats` | Get running module statistics (waiting/running/results) |
| `msf_host_info` | Query discovered hosts |
| `msf_service_info` | Query discovered services |
| `msf_vulnerability_info` | Query vulnerability records |
| `msf_note_info` | Query notes/annotations |
| `msf_credential_info` | Query harvested credentials |
| `msf_loot_info` | Query collected loot |
| `msf_list_active_sessions` | List current sessions |
| `msf_session_info` | Get detailed info for a single session |
| `msf_list_listeners` | List active handlers/jobs |
| `msf_job_info` | Get details about a specific running job |
| `msf_list_payloads` | Search available payloads |
| `msf_compatible_payloads` | List payloads compatible with a module |
| `msf_get_lab_network` | Get lab target configuration |
| `msf_list_workspaces` | List database workspaces |
| `msf_db_status` | Check database connectivity and driver info |
| `msf_console_list` | List active RPC console instances |
| `msf_route_list` | List active routes for pivoting |

### Action Tools (engagement_id required)
| Tool | Purpose |
|------|---------|
| `msf_module_check` | Run vulnerability check (safe probe) |
| `msf_module_results` | Query results of an async module job by UUID |
| `msf_run_exploit` | Execute exploit module (configurable timeout) |
| `msf_run_auxiliary_module` | Run auxiliary module (console default, run_as_job option) |
| `msf_run_post_module` | Run post-exploitation module (console default, run_as_job option) |
| `msf_send_session_command` | Execute command in session (up to 300s timeout) |
| `msf_session_run_script` | Run Meterpreter script via meterpreter_run_single |
| `msf_terminate_session` | Kill a session |
| `msf_wait_for_session` | Poll for new sessions |
| `msf_session_upgrade` | Upgrade shell to Meterpreter |
| `msf_session_sysinfo` | Get OS/arch/hostname from Meterpreter session |
| `msf_session_getuid` | Get current user identity from Meterpreter session |
| `msf_session_ps` | List running processes in Meterpreter session |
| `msf_session_download` | Download file from target to evidence/ |
| `msf_session_upload` | Upload file from evidence/ to target |
| `msf_start_listener` | Start multi/handler |
| `msf_stop_job` | Stop background job |
| `msf_cleanup_jobs` | Stop all background jobs to free ports |
| `msf_generate_payload` | Generate payload with encoder/badchars/nopsled/template |
| `msf_create_workspace` | Create database workspace |
| `msf_set_workspace` | Switch active workspace |
| `msf_delete_workspace` | Delete a workspace (cannot delete 'default') |
| `msf_db_import` | Import scan data (nmap XML, Nessus, etc.) |
| `msf_db_nmap` | Run nmap and auto-import results |
| `msf_console_execute` | Run raw msfconsole command via RPC |
| `msf_route_add` | Add route through session for pivoting |
| `msf_route_delete` | Remove a route |
| `msf_autoroute` | Auto-add routes via post/multi/manage/autoroute |
| `msf_report_host` | Manually report host to database |
| `msf_credential_add` | Store discovered credential in database |
| `msf_db_add_note` | Add note/annotation to database |

## Directory Map

| Path | Purpose |
|------|---------|
| `msf_harness/mcp/` | Python MCP server package |
| `msf_harness/mcp/tools/` | MCP tool implementations (12 modules) |
| `msf_harness/mcp/rpc/` | Metasploit RPC client with auto-reconnect |
| `msf_harness/mcp/policy/` | ROE enforcement (CIDR, domain, module, session, exploit-gate) |
| `scope/` | Authorized target CIDRs, domains, and metadata |
| `engagements/` | Per-engagement ROE configs and workflow state |
| `engagements/_template/` | Template for new engagements |
| `engagements/catalogs/` | Phase/subgate workflow definitions |
| `engagements/{id}/world-state.md` | Action log and gate/subgate status |
| `engagements/{id}/world-state.json` | Runtime session stats (hook-managed) |
| `evidence/msf/` | Captured evidence (gitignored) |
| `logs/` | Hook audit logs, command ledger, risk assessments, MCP server logs |
| `tests/` | Pytest test suite for ROE and input validation |
| `tests/hooks/` | PowerShell hook test suite (unit + gate integration tests) |
| `scripts/` | Utility scripts (create-engagement, start-msfrpcd, test-roe, test-hooks) |
| `.cursor/hooks/` | PowerShell Core safety gates (18 scripts: 10 triggered + 7 shared modules + hooks.json) |
| `.cursor/skills/` | Agent workflow playbooks (57 skills) |
| `.cursor/agents/` | Custom subagent definitions (5 agents) |
| `.cursor/rules/` | Always-on agent guidance (3 rules + AGENTS.md) |

## Hook Pipeline

| Event | Hooks | Purpose |
|-------|-------|---------|
| `sessionStart` | `session-context.ps1` | Inject scope/engagement context + hook health check |
| `beforeShell` | `risk-gate.ps1`, `scope-check.ps1`, `dangerous-command-gate.ps1`, `rate-limit-gate.ps1`, `world-state-gate.ps1` | Risk scoring, scope enforcement, destructive blocking, cooldown, duplicate detection |
| `beforeMCP` | `risk-gate.ps1`, `mcp-action-gate.ps1`, `rate-limit-gate.ps1`, `world-state-gate.ps1` | ROE + scope + domain + CIDR width + dangerous pattern enforcement, cooldown, duplicate detection |
| `afterShell/MCP` | `evidence-logger.ps1`, `mcp-evidence-logger.ps1`, `world-state-logger.ps1` | Audit trail, evidence files, world state updates (atomic locking) |
| `stop` | `stop-checklist.ps1` | Cleanup and risk summary |

### Shared Modules (not directly triggered)

| Module | Purpose |
|--------|---------|
| `scope-common.ps1` | CIDR matching, scope loading, exclusion/domain validation |
| `engagement-resolver.ps1` | Unified engagement ID resolution across all hooks |
| `input-parser.ps1` | Robust JSON input parsing with debug logging |
| `world-state-io.ps1` | Atomic read-merge-write with file locking |
| `world-state-common.ps1` | Python bridge for world-state.py |
| `risk-scoring.ps1` | Weighted risk scoring engine (shell + MCP) |
| `credential-filter.ps1` | Redacts passwords, hashes, tokens, and keys from evidence |

## ROE Enforcement (Server-Side)

The Python ROE layer enforces these checks on every action tool call:
- **Target scope**: IP must be in authorized CIDRs and not excluded
- **CIDR width**: Scan targets limited to `max_scan_cidr` (default /24)
- **Module blocking**: `auxiliary/dos/*` and custom prefixes forbidden
- **Session limit**: Capped at `max_sessions` (default 5); fails closed on RPC errors
- **Check before exploit**: When `require_check_before_exploit=true`, exploits are blocked unless a check was run
- **Domain authorization**: Validated against `authorized_domains` list

## Operating Rules

1. **Scope first**: Verify targets are in `scope/scope-master.txt` before any operation.
2. **MCP over shell**: Use MCP tools instead of raw `msfconsole` whenever possible.
3. **Check before exploit**: Always run `msf_module_check` before `msf_run_exploit`.
4. **Engagement ID**: All destructive tools require an `engagement_id` parameter.
5. **No DoS**: `auxiliary/dos/*` modules are blocked unconditionally.
6. **Evidence**: All MCP tool outputs auto-save to `evidence/msf/` via hooks.
7. **Windows commands**: Use `;` not `&&` for chaining. Use `wsl` prefix for Linux tools on Windows.
8. **Ask when uncertain**: If scope or authorization is unclear, stop and ask the user.
9. **Create engagements**: Use `python scripts/create-engagement.py --name <name>` for new engagements.
10. **Run tests**: Use `python -m pytest tests/ -v` for Python ROE tests, `pwsh -ExecutionPolicy Bypass -File scripts/test-hooks.ps1` for hook tests (120 tests).
11. **Health check**: Run `python scripts/doctor.py` to verify all prerequisites.
