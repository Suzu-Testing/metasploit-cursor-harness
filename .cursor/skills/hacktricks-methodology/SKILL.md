---
name: hacktricks-methodology
description: >-
  Guides network and service penetration testing after port discovery. Provides
  port-to-skill routing, per-service quick reference, and general enumeration
  methodology for services with and without dedicated harness skills.
---

# Service Methodology

## When to Use

- A port or service was discovered (nmap, MSF scan, client intel).
- You need service-specific attack paths, not generic web vuln payloads (use `web-app-pentest` for OWASP testing).
- You need OS privesc checklists after shell access (route to OS skills).

## Workflow

```
Task Progress:
- [ ] Identify service/version from scan or msf_service_info
- [ ] Route to dedicated skill or per-port module table below
- [ ] Enumerate with safe scanners first
- [ ] Execute in-scope only with engagement_id
```

## Port-to-skill routing

| Port / service | Dedicated skill |
|----------------|-----------------|
| 445, 139 SMB | `smb-pentest` |
| 389, 636 LDAP | `ldap-pentest` |
| 88 Kerberos | `internal-ad-pentest` |
| 1433 MSSQL | `database-pentest` |
| 3389 RDP | `rdp-pentest` |
| 22 SSH | `ssh-pentest` |
| 21 FTP | `ftp-pentest` |
| 25, 587 SMTP | `smtp-pentest` |
| 53 DNS | `dns-pentest` |
| 161, 162 SNMP | `snmp-pentest` |
| 5900 VNC | `vnc-pentest` |
| 5985, 5986 WinRM | `winrm-pentest` |
| 2049 NFS | `nfs-pentest` |
| 23 Telnet | `telnet-pentest` |
| 11211 Memcache | `memcache-pentest` |
| 80, 443 HTTP | `web-app-pentest` (+ vuln skills) |
| 3306 MySQL | `database-pentest` |
| 5432 PostgreSQL | `database-pentest` |
| 6379 Redis | `database-pentest` |
| 27017 MongoDB | `database-pentest` |
| 9200 Elasticsearch | `database-pentest` |
| 2375, 2376 Docker API | `container-devops-pentest` |
| 6443, 10250 K8s | `container-devops-pentest` |

Post-shell routing: Windows -> `windows-pentest`, Linux -> `linux-pentest`, macOS -> `macos-pentest`, domain -> `internal-ad-pentest`.

## Per-port MSF module table

Each row: MSF MCP call (preferred) plus CLI fallback.

### SMB (445/139)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/smb/smb_version",
  engagement_id="<id>",
  options={"RHOSTS": "<target>"}
)
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/smb/smb_enumshares",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "SMBUser": "guest", "SMBPass": ""}
)
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/smb/smb_login",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "SMBUser": "admin", "SMBPass": "password"}
)
```

**CLI fallback:**

```bash
nmap --script smb-enum-shares,smb-os-discovery -p 445 <target>
crackmapexec smb <target> --shares
enum4linux -a <target>
```

### LDAP (389/636)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/ldap/ldap_login",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "DOMAIN": "domain.local", "USERNAME": "user", "PASSWORD": "password"}
)
msf_run_auxiliary_module(
  module_name="auxiliary/gather/ldap_query",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "DOMAIN": "domain.local", "USERNAME": "user", "PASSWORD": "password", "QUERY_FILTER": "(objectClass=user)"}
)
```

**CLI fallback:**

```bash
ldapsearch -x -H ldap://<target> -D "user@domain.local" -w pass -b "DC=domain,DC=local"
```

### Kerberos (88)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/gather/kerberos_enumusers",
  engagement_id="<id>",
  options={"RHOSTS": "<dc>", "DOMAIN": "domain.local", "USER_FILE": "/tmp/users.txt"}
)
msf_run_auxiliary_module(
  module_name="auxiliary/gather/kerberos_kerberoast",
  engagement_id="<id>",
  options={"RHOSTS": "<dc>", "DOMAIN": "domain.local", "USER": "user", "PASSWORD": "password"}
)
```

**CLI fallback:**

```bash
kerbrute userenum -d domain.local users.txt
impacket-GetUserSPNs domain.local/user:pass -request
```

### MSSQL (1433)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/mssql/mssql_ping",
  engagement_id="<id>",
  options={"RHOSTS": "<target>"}
)
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/mssql/mssql_login",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "USERNAME": "sa", "PASSWORD": "password"}
)
```

**CLI fallback:**

```bash
crackmapexec mssql <target> -u sa -p password
nmap --script ms-sql-info -p 1433 <target>
```

### RDP (3389)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/rdp/rdp_scanner",
  engagement_id="<id>",
  options={"RHOSTS": "<target>"}
)
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
  engagement_id="<id>",
  options={"RHOSTS": "<target>"}
)
```

**CLI fallback:**

```bash
nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info <target>
xfreerdp /u:user /p:pass /v:<target>
```

### SSH (22)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/ssh/ssh_version",
  engagement_id="<id>",
  options={"RHOSTS": "<target>"}
)
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/ssh/ssh_login",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "USERNAME": "root", "PASS_FILE": "/tmp/passwords.txt"}
)
```

**CLI fallback:**

```bash
ssh -o BatchMode=yes user@<target> id
nmap --script ssh-auth-methods -p 22 <target>
```

### FTP (21)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/ftp/ftp_version",
  engagement_id="<id>",
  options={"RHOSTS": "<target>"}
)
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/ftp/ftp_login",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "USERNAME": "anonymous", "PASSWORD": "anonymous@"}
)
```

**CLI fallback:**

```bash
nmap --script ftp-anon,ftp-syst -p 21 <target>
ftp <target>
```

### SMTP (25/587)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/smtp/smtp_version",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "RPORT": 25}
)
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/smtp/smtp_enum",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "RPORT": 25}
)
```

**CLI fallback:**

```bash
nmap --script smtp-commands,smtp-enum-users -p 25 <target>
smtp-user-enum -M VRFY -U users.txt -t <target>
```

### DNS (53)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/gather/enum_dns",
  engagement_id="<id>",
  options={"DOMAIN": "domain.local", "NAMESERVER": "<target>"}
)
```

**CLI fallback:**

```bash
dig axfr @<ns> domain.local
dnsenum domain.local
```

### SNMP (161)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/snmp/snmp_login",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "COMMUNITY": "public", "VERSION": "2c"}
)
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/snmp/snmp_enum",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "COMMUNITY": "public"}
)
```

**CLI fallback:**

```bash
onesixtyone -c community.txt <target>
snmpwalk -v2c -c public <target>
```

### WinRM (5985/5986)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/winrm/winrm_auth_methods",
  engagement_id="<id>",
  options={"RHOSTS": "<target>"}
)
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/winrm/winrm_login",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "USERNAME": "admin", "PASSWORD": "password"}
)
```

**CLI fallback:**

```bash
crackmapexec winrm <target> -u admin -p password
evil-winrm -i <target> -u admin -p password
```

### HTTP/HTTPS (80/443)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/http/http_version",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "RPORT": 443, "SSL": true}
)
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/http/dir_scanner",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "RPORT": 443, "SSL": true}
)
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/http/robots_txt",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "RPORT": 443, "SSL": true}
)
```

**CLI fallback:**

```bash
whatweb https://target
ffuf -u https://target/FUZZ -w common.txt
nuclei -u https://target
```

Route to `web-app-pentest` for OWASP methodology.

### MySQL / PostgreSQL / Redis / MongoDB

See `database-pentest` for full dual-track module table per engine.

### Docker API (2375)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/http/docker_version",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "RPORT": 2375}
)
```

**CLI fallback:**

```bash
curl http://<target>:2375/version
docker -H tcp://<target>:2375 ps
```

### Kubernetes (6443/10250)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/http/kubelet_healthz",
  engagement_id="<id>",
  options={"RHOSTS": "<node>", "RPORT": 10250}
)
```

**CLI fallback:**

```bash
curl -k https://<target>:6443/version
curl -k https://<node>:10250/pods
```

### NFS (2049)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/nfs/nfsmount",
  engagement_id="<id>",
  options={"RHOSTS": "<target>"}
)
msf_run_auxiliary_module(
  module_name="auxiliary/scanner/nfs/nfs_showmount",
  engagement_id="<id>",
  options={"RHOSTS": "<target>"}
)
```

**CLI fallback:**

```bash
showmount -e <target>
```

### Memcache (11211)

**MSF MCP (preferred):**

```text
msf_run_auxiliary_module(
  module_name="auxiliary/gather/memcached_extractor",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "RPORT": 11211}
)
```

**CLI fallback:**

```bash
echo "stats" | nc <target> 11211
```

## General enumeration

### Banner and version

**MSF MCP (preferred):**

```text
msf_service_info()
msf_host_info()
```

**CLI fallback:**

```bash
nmap -sV -sC -p <port> <target>
nc -nv <target> <port>
```

### Vulnerability correlation

**MSF MCP (preferred):**

```text
msf_search_modules(query="<service> <version>")
msf_vulnerability_info()
msf_module_check(
  module_name="exploit/...",
  engagement_id="<id>",
  module_type="exploit",
  options={"RHOSTS": "<target>"}
)
```

**CLI fallback:**

```bash
searchsploit <product> <version>
```

Always `msf_module_check` before exploits. Include `engagement_id`.

## Related skills

- All tier-2 service skills (`smb-pentest`, `ssh-pentest`, etc.)
- `web-app-pentest` - OWASP web methodology
- `internal-ad-pentest` - AD-wide attacks
- `database-pentest` - database engines
- `container-devops-pentest` - Docker/K8s/CI-CD
- `msf-recon` - MCP recon workflow
- `pivoting-pentest` - reach internal subnets after foothold
- `initial-access-pentest` - external attack surface before service testing
