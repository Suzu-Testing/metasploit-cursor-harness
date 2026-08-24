# =============================================================================
# SHELL COMMAND LEDGER - Postflight hook
# Records every shell command with structured detail to command-ledger.jsonl
# and updates the world state with discoveries.
# =============================================================================

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot "input-parser.ps1")
. (Join-Path $PSScriptRoot "risk-scoring.ps1")
. (Join-Path $PSScriptRoot "engagement-resolver.ps1")
. (Join-Path $PSScriptRoot "scope-common.ps1")
. (Join-Path $PSScriptRoot "world-state-io.ps1")
. (Join-Path $PSScriptRoot "credential-filter.ps1")

$projectRoot = Get-ProjectRoot
$logDir = Join-Path $projectRoot "logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$ledgerFile = Join-Path $logDir "command-ledger.jsonl"

trap {
    try { Write-ParseDebug "evidence-logger" "TRAP: $($_.Exception.Message)" } catch {}
    Write-Output '{}'
    exit 0
}

# --- Read and parse input ---
$rawInput = Read-HookStdin
$parsed = Parse-HookInput -RawInput $rawInput -HookName "evidence-logger"

$command = $null
$exitCode = $null
$output = ""

if ($parsed.Success) {
    $command = Extract-ShellCommand -ParsedData $parsed.ParsedData -HookName "evidence-logger"
    $shellOutput = Extract-ShellOutput -ParsedData $parsed.ParsedData
    $output = $shellOutput.Output
    $exitCode = $shellOutput.ExitCode
} else {
    $command = Extract-ShellCommand -RawInput $rawInput -HookName "evidence-logger"
}

if (-not $command) {
    Write-Output '{}'
    exit 0
}

# --- Resolve engagement via unified resolver ---
$engagementId = Resolve-EngagementId -ProjectRoot $projectRoot

# --- Compute risk score ---
$risk = Get-CommandRiskScore $command

# --- Extract targets ---
$targets = Extract-IpsFromText $command

# --- Compute command hash ---
$cmdHash = Get-CommandHash -Command $command

# --- Redact credentials and truncate output for ledger ---
$outputForLog = Invoke-CredentialFilter -Text $output
if ($outputForLog.Length -gt 2000) {
    $outputForLog = $outputForLog.Substring(0, 1997) + "..."
}

# --- Build and write ledger entry ---
$ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
$entry = @{
    timestamp      = $ts
    type           = "shell"
    command        = $command
    command_hash   = $cmdHash
    exit_code      = $exitCode
    targets        = $targets
    risk_score     = $risk.Score
    risk_level     = $risk.Level
    tool_category  = $risk.Breakdown.tool_category.category
    engagement_id  = $engagementId
    output_preview = $outputForLog
} | ConvertTo-Json -Depth 5 -Compress

try { Add-Content -Path $ledgerFile -Value $entry } catch {}

# --- Update world state atomically (preserves ALL fields) ---
Update-WorldState -EngagementId $engagementId -ProjectRoot $projectRoot -Mutator {
    param($state)

    $state.session_stats.total_commands++
    $state.session_stats.total_shell_cmds++
    $state.session_stats.by_risk_level[$risk.Level]++

    # Recent commands
    $recentEntry = @{
        timestamp       = $ts
        type            = "shell"
        command_hash    = $cmdHash
        command_preview = if ($command.Length -gt 80) { $command.Substring(0, 77) + "..." } else { $command }
        exit_code       = $exitCode
        risk_score      = $risk.Score
        risk_level      = $risk.Level
        targets         = $targets
    }
    Add-RecentCommand -WorldState $state -Entry $recentEntry

    # Discovered targets
    Add-DiscoveredTargets -WorldState $state -Targets $targets
} | Out-Null

Write-Output '{}'
exit 0
