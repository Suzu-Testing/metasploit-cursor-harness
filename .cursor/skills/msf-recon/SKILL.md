---
name: msf-recon
description: >-
  Reconnaissance workflow using Metasploit MCP read tools. Use when mapping
  targets, searching for exploit modules, correlating services with
  vulnerabilities, or querying the Metasploit database.
---

# Metasploit Reconnaissance

## When to Use
- Initial target mapping after network scan
- Searching Metasploit modules for specific CVEs or services
- Correlating Nexpose/nmap results with Metasploit module coverage
- Querying hosts, services, vulns, and credentials from msfdb

## Prerequisites
- Metasploit RPC running (check with `msf_status`)
- `msfdb` initialized with scan data (imported via `msf_db_import` or `msf_db_nmap`)
- Targets in `scope/scope-master.txt`

## Tool Inventory

**Read-only:** `msf_status`, `msf_host_info`, `msf_service_info`, `msf_vulnerability_info`, `msf_note_info`, `msf_credential_info`, `msf_loot_info`, `msf_search_modules`, `msf_module_info`, `msf_get_lab_network`, `msf_list_workspaces`

**Action (engagement_id required):** `msf_db_nmap`, `msf_db_import`, `msf_create_workspace`, `msf_set_workspace`, `msf_run_auxiliary_module`

## Workflow

### Step 1: Verify connectivity

**MSF MCP (preferred):**
```text
msf_status()
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'version; exit'"
```

### Step 2: Lab network and workspace setup

**MSF MCP (preferred):**
```text
msf_get_lab_network()
msf_list_workspaces()
msf_create_workspace(
  engagement_id="<id>",
  workspace_name="engagement-<id>"
)
msf_set_workspace(
  engagement_id="<id>",
  workspace_name="engagement-<id>"
)
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'workspace -a engagement-<id>; workspace engagement-<id>; exit'"
```

### Step 3: Network scan and import

Resolve scan ports deterministically:
1. `msf_get_lab_network()` -> use `port_map` keys as scan targets
2. Else use `engagements/{id}/targets.yaml` port list if defined
3. Else default: `-p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,5985,6667,8080,8443,9667`
4. Only use `-p-` (all ports) if the user explicitly requests a full port scan

**MSF MCP (preferred):**
```text
msf_db_nmap(
  engagement_id="<id>",
  targets="<target>",
  nmap_args="-sV --open -T4 -p <ports_from_above>"
)
```

**CLI fallback:**
```bash
nmap -sV --open -T4 -p <ports_from_above> <target> -oX evidence/msf/nmap-<target>.xml
```

**MSF MCP (import after nmap):**
```text
msf_db_import(
  engagement_id="<id>",
  file_path="evidence/msf/nmap-<target>.xml"
)
```

### Step 4: Import external scan data

**MSF MCP (preferred):**
```text
msf_db_import(
  engagement_id="<id>",
  file_path="evidence/msf/nessus-export.xml"
)
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'db_import evidence/msf/nessus-export.xml; exit'"
```

### Step 5: Map discovered hosts

**MSF MCP (preferred):**
```text
msf_host_info(
  workspace="engagement-<id>",
  only_up=true
)
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'workspace engagement-<id>; hosts -c address,os_name,os_flavor; exit'"
```

### Step 6: Enumerate services

**MSF MCP (preferred):**
```text
msf_service_info(
  workspace="engagement-<id>",
  only_up=true,
  ports="445"
)
msf_service_info(
  workspace="engagement-<id>",
  only_up=true,
  names="http"
)
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'workspace engagement-<id>; services -p 445; services -S http; exit'"
nmap -sV -p 445,80,443 <target>
```

### Step 7: Check known vulnerabilities

**MSF MCP (preferred):**
```text
msf_vulnerability_info(
  workspace="engagement-<id>",
  host="<target>"
)
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'workspace engagement-<id>; vulns -R <target>; exit'"
```

### Step 8: Search for exploit modules

**MSF MCP (preferred):**
```text
msf_search_modules(query="CVE-2017-0144")
msf_search_modules(query="smb remote code execution")
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'search CVE-2017-0144; search smb rce; exit'"
searchsploit eternalblue
```

### Step 9: Get module details

**MSF MCP (preferred):**
```text
msf_module_info(
  type="exploit",
  name="windows/smb/ms17_010_eternalblue"
)
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'info exploit/windows/smb/ms17_010_eternalblue; exit'"
```

### Step 10: Auxiliary service scanning

**MSF MCP (preferred):**
```text
msf_run_auxiliary_module(
  engagement_id="<id>",
  module_name="auxiliary/scanner/smb/smb_version",
  options={"RHOSTS": "<target>"}
)
msf_run_auxiliary_module(
  engagement_id="<id>",
  module_name="auxiliary/scanner/http/http_version",
  options={"RHOSTS": "<target>", "RPORT": 80}
)
```

**CLI fallback:**
```bash
nmap -sV --script smb-os-discovery -p 445 <target>
nmap -sV --script http-headers -p 80 <target>
```

### Step 11: Check credentials, loot, and notes

**MSF MCP (preferred):**
```text
msf_credential_info(workspace="engagement-<id>")
msf_loot_info(workspace="engagement-<id>")
msf_note_info(workspace="engagement-<id>")
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'workspace engagement-<id>; creds; loot; notes; exit'"
```

## Skill routing by service

For each discovered service, map to KB before module search:

1. Load `hacktricks-methodology` and find service in service-index
2. Web ports (80/443): `web-app-pentest`
3. AD ports (88, 389, 445): `internal-ad-pentest`
4. Cloud metadata/API: `cloud-pentest`
5. Docker/K8s/CI: `container-devops-pentest`
6. LLM/chat endpoints: `ai-llm-pentest`
7. Methodology/shells/pivoting: `methodology-cheatsheets`
8. Then run `msf_search_modules` with technique keywords

## Correlation pattern

For each host with open services:
1. Query `msf_service_info` filtered by host
2. Load the matching service skill (e.g. `smb-pentest` for port 445)
3. For each service, `msf_search_modules` by service name, version, or CVE
4. Cross-reference with `msf_vulnerability_info` for confirmed vulns
5. Document in `evidence/msf/recon-{host}-{date}.txt`

## Evidence paths
- `evidence/msf/hosts-{date}.txt`
- `evidence/msf/services-{date}.txt`
- `evidence/msf/module-search-{query}-{date}.txt`

## Related skills

- `msf-harness` - tool reference and engagement setup
- `msf-exploit-chain` - next step after recon identifies targets
- `hacktricks-methodology` - service-level enumeration playbooks
- `pentest-knowledge-base` - skill routing by scenario
- `database-pentest` - database service enumeration
- `web-app-pentest` - web service enumeration
