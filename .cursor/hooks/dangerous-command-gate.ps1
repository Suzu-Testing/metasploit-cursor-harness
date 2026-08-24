# =============================================================================
# DANGEROUS COMMAND GATE
# Blocks or prompts for inherently dangerous shell commands that could cause
# denial of service, data destruction, or other irreversible harm regardless
# of whether the target is in scope.
# =============================================================================

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot "input-parser.ps1")
. (Join-Path $PSScriptRoot "scope-common.ps1")

$projectRoot = Get-ProjectRoot
$hookLogDir = Join-Path $projectRoot "logs"
if (-not (Test-Path $hookLogDir)) { New-Item -ItemType Directory -Path $hookLogDir -Force | Out-Null }
$hookLog = Join-Path $hookLogDir "hook-audit.log"

trap {
    try { Write-ParseDebug "dangerous-cmd-gate" "TRAP: $($_.Exception.Message)" } catch {}
    # Fail closed: deny on unhandled errors
    Write-Output '{ "permission": "deny", "user_message": "Dangerous command gate encountered an internal error (fail-closed).", "agent_message": "Hook internal error in dangerous-command-gate. Check logs/hook-debug.log." }'
    exit 0
}

function Write-HookDecision($decision, $reason, $cmd) {
    $ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    $cmdHash = Get-CommandHash -Command $cmd -Length 12
    $line = "$ts | hook=dangerous-cmd-gate | decision=$decision | reason=$reason | cmd_hash=$cmdHash"
    try { Add-Content -Path $hookLog -Value $line } catch {}
}

# --- Read and parse input ---
$rawInput = Read-HookStdin
$parsed = Parse-HookInput -RawInput $rawInput -HookName "dangerous-cmd-gate"

$command = $null
if ($parsed.Success) {
    $command = Extract-ShellCommand -ParsedData $parsed.ParsedData -HookName "dangerous-cmd-gate"
} else {
    $command = Extract-ShellCommand -RawInput $rawInput -HookName "dangerous-cmd-gate"
}

if (-not $command) {
    Write-Output '{ "permission": "allow" }'
    exit 0
}

# =============================================================================
# UNCONDITIONAL DENIALS - never allow these
# =============================================================================

$hardDenyPatterns = @(
    # DoS tools
    @{ pattern = '\bslowloris\b';    reason = "DoS tool: slowloris" },
    @{ pattern = '\bslowhttp\b';     reason = "DoS tool: slowhttptest" },
    @{ pattern = '\bgoldeneye\b';    reason = "DoS tool: GoldenEye" },
    @{ pattern = '\bxerxes\b';       reason = "DoS tool: Xerxes" },
    @{ pattern = '\bloic\b';         reason = "DoS tool: LOIC" },
    @{ pattern = '\bhoic\b';         reason = "DoS tool: HOIC" },
    @{ pattern = '\bhulk\b';         reason = "DoS tool: HULK" },
    @{ pattern = '\bhping\b';        reason = "DoS tool: hping" },
    @{ pattern = '\btorsloris\b';    reason = "DoS tool: torsloris" },
    @{ pattern = '\btorshammer\b';   reason = "DoS tool: torshammer" },
    @{ pattern = '\bsockstress\b';   reason = "DoS tool: sockstress" },
    @{ pattern = '\br-u-dead-yet\b'; reason = "DoS tool: R.U.D.Y." },
    # Destructive system commands
    @{ pattern = '\b(rm|del)\s+(-rf?\s+)?/';  reason = "Recursive delete on root" },
    @{ pattern = '\bformat\s+[a-zA-Z]:';      reason = "Disk format command" },
    @{ pattern = '\bdd\s+if=.*\bof=/dev/';     reason = "Raw disk write with dd" },
    @{ pattern = '\bshutdown\b';     reason = "System shutdown" },
    @{ pattern = '\breboot\b';       reason = "System reboot" },
    @{ pattern = '\bhalt\b';         reason = "System halt" },
    @{ pattern = '\bmkfs\b';         reason = "Filesystem format" },
    @{ pattern = '\bfdisk\b';        reason = "Disk partitioning" },
    # Wiper / ransomware patterns
    @{ pattern = '\bshred\s+.*-[a-z]*z';       reason = "Secure wipe with shred" },
    @{ pattern = '\bwipe\s+/dev/';              reason = "Device wipe command" },
    @{ pattern = '\bcryptsetup\s+luksErase\b';  reason = "LUKS encryption erase" },
    # Credential exfiltration to external
    @{ pattern = 'curl.*\b(pastebin|hastebin|0x0|transfer\.sh|webhook\.site)\b'; reason = "Data exfiltration to paste service" },
    @{ pattern = 'wget.*--post-file.*\b(pastebin|transfer\.sh)\b';              reason = "File exfiltration via wget" }
)

foreach ($rule in $hardDenyPatterns) {
    if ($command -match $rule.pattern) {
        Write-HookDecision "deny" $rule.reason $command
        $result = @{
            permission    = "deny"
            user_message  = "BLOCKED: $($rule.reason). This command is unconditionally forbidden."
            agent_message = "Command blocked by dangerous-command-gate: $($rule.reason). Do not attempt to bypass this restriction."
        } | ConvertTo-Json -Compress
        Write-Output $result
        exit 0
    }
}

# =============================================================================
# ASK PATTERNS - dangerous but sometimes legitimate, prompt user
# =============================================================================

$askPatterns = @(
    @{ pattern = '\bgit\s+push\s+.*--force\b';          reason = "Force push to git remote" },
    @{ pattern = '\bgit\s+push\s+-f\b';                 reason = "Force push to git remote" },
    @{ pattern = '\bgit\s+reset\s+--hard\b';             reason = "Hard git reset" },
    @{ pattern = '\bcredential.?spray\b';                reason = "Credential spraying detected" },
    @{ pattern = '(?:^|\s)-T\s*[45]\b';                   reason = "Aggressive nmap timing (T4/T5)" },
    @{ pattern = '\bmasscan\b.*--rate\s+\d{5,}';        reason = "High-rate masscan (potential DoS)" },
    @{ pattern = '(?:^|\s)-t\s+\d{3,}\b';               reason = "High thread count (potential DoS)" },
    @{ pattern = '(?:^|\s)--threads\s+\d{3,}\b';        reason = "High thread count (potential DoS)" },
    @{ pattern = '\b(wmic|psexec)\b.*\b/every:';         reason = "Scheduled task creation on remote" },
    @{ pattern = '\bnetsh\s+.*firewall.*disable\b';      reason = "Firewall disable command" },
    @{ pattern = '\biptables\s+.*-F\b';                  reason = "Firewall flush command" },
    @{ pattern = '\bufw\s+disable\b';                    reason = "UFW firewall disable" },
    @{ pattern = '\bsystemctl\s+stop\s+.*firewall';      reason = "Stopping firewall service" },
    @{ pattern = '\bsetenforce\s+0\b';                   reason = "Disabling SELinux" },
    @{ pattern = '\brm\s+.*\.bash_history';              reason = "Deleting shell history (anti-forensics)" },
    @{ pattern = '\b(history|shred).*\.log\b';           reason = "Log tampering detected" },
    @{ pattern = '\bkill\s+-9\s+1\b';                    reason = "Killing init/systemd (PID 1)" },
    @{ pattern = '\bchmod\s+777\s+/';                    reason = "World-writable root filesystem" },
    @{ pattern = '\bpasswd\s+root\b';                    reason = "Changing root password" },
    @{ pattern = '\buseradd\b.*-o\s.*-u\s*0';           reason = "Creating UID 0 backdoor user" }
)

foreach ($rule in $askPatterns) {
    if ($command -match $rule.pattern) {
        Write-HookDecision "ask" $rule.reason $command
        $result = @{
            permission    = "ask"
            user_message  = "CAUTION: $($rule.reason). Are you sure you want to proceed?"
            agent_message = "Command flagged by dangerous-command-gate: $($rule.reason). Ask the user before proceeding."
        } | ConvertTo-Json -Compress
        Write-Output $result
        exit 0
    }
}

# =============================================================================
# MSF CONSOLE EXECUTE - check for DoS modules in embedded MSF syntax
# =============================================================================
if ($command -match 'msf_console_execute|msfconsole') {
    if ($command -match 'auxiliary/dos/') {
        Write-HookDecision "deny" "dos_module_in_console" $command
        $result = @{
            permission    = "deny"
            user_message  = "BLOCKED: auxiliary/dos/* modules are unconditionally forbidden per ROE."
            agent_message = "DoS module detected in console command. auxiliary/dos/* modules are blocked."
        } | ConvertTo-Json -Compress
        Write-Output $result
        exit 0
    }
}

Write-HookDecision "allow" "not_dangerous" $command
Write-Output '{ "permission": "allow" }'
exit 0
