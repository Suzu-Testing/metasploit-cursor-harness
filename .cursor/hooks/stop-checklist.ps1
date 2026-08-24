# =============================================================================
# STOP CHECKLIST - Session end summary
# Reads world state and command ledger to provide a comprehensive end-of-session
# report including risk summary, active resources, and cleanup checklist.
# =============================================================================

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot "scope-common.ps1")
. (Join-Path $PSScriptRoot "engagement-resolver.ps1")

$projectRoot = Get-ProjectRoot
$ledgerFile = Join-Path $projectRoot "logs\command-ledger.jsonl"

trap {
    $fallback = @{
        agentMessage = "## Session End Report`n`nWARNING: stop-checklist hook encountered an error. Please manually verify:`n- All sessions are terminated`n- Evidence is saved`n- No handlers running"
    } | ConvertTo-Json -Compress
    Write-Output $fallback
    exit 0
}

$engagementId = Resolve-EngagementId -ProjectRoot $projectRoot
$worldStateFile = Get-WorldStateFilePath -EngagementId $engagementId -ProjectRoot $projectRoot

$totalCommands = 0
$totalMcp = 0
$totalShell = 0
$riskBreakdown = ""
$discoveredTargets = 0
$activeSessions = 0
$activeListeners = 0
$criticalActions = @()

# --- Read world state ---
if (Test-Path $worldStateFile) {
    try {
        $ws = Get-Content $worldStateFile -Raw | ConvertFrom-Json
        $totalCommands = if ($ws.session_stats.total_commands) { $ws.session_stats.total_commands } else { 0 }
        $totalMcp = if ($ws.session_stats.total_mcp_calls) { $ws.session_stats.total_mcp_calls } else { 0 }
        $totalShell = if ($ws.session_stats.total_shell_cmds) { $ws.session_stats.total_shell_cmds } else { 0 }
        $discoveredTargets = if ($ws.discovered_targets) { $ws.discovered_targets.Count } else { 0 }
        $activeSessions = if ($ws.active_sessions) { $ws.active_sessions.Count } else { 0 }
        $activeListeners = if ($ws.active_listeners) { $ws.active_listeners.Count } else { 0 }

        if ($ws.session_stats.by_risk_level) {
            $parts = @()
            foreach ($lvl in @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')) {
                $val = $ws.session_stats.by_risk_level.$lvl
                if ($null -ne $val -and [int]$val -gt 0) {
                    $parts += "$lvl`:$val"
                }
            }
            $riskBreakdown = $parts -join ', '
        }

        if ($ws.recent_commands) {
            $criticalActions = @($ws.recent_commands | Where-Object {
                $_.risk_level -eq "CRITICAL" -or $_.risk_level -eq "HIGH"
            })
        }
    } catch {}
}

# --- Count ledger entries ---
$ledgerCount = 0
if (Test-Path $ledgerFile) {
    try { $ledgerCount = (Get-Content $ledgerFile | Measure-Object).Count } catch {}
}

# --- Build critical actions section ---
$criticalSection = ""
if ($criticalActions.Count -gt 0) {
    $criticalSection = "`n**High/Critical risk actions this session:** $($criticalActions.Count)"
    foreach ($action in $criticalActions | Select-Object -First 5) {
        $desc = if ($action.command_preview) { $action.command_preview } elseif ($action.tool) { "MCP:$($action.tool)" } else { "unknown" }
        $criticalSection += "`n  - [$($action.risk_level) $($action.risk_score)/100] $desc"
    }
}

# --- Build warnings ---
$warnings = ""
if ($activeSessions -gt 0) {
    $warnings += "`n**WARNING:** $activeSessions active session(s) still open. Terminate or document before ending."
}
if ($activeListeners -gt 0) {
    $warnings += "`n**WARNING:** $activeListeners active listener(s) still running. Stop or document before ending."
}

$reminder = @"
## Session End Report

**Engagement:** $engagementId
**Total operations:** $totalCommands (MCP: $totalMcp + Shell: $totalShell) = $ledgerCount ledger entries
**Risk breakdown:** $riskBreakdown
**Discovered targets:** $discoveredTargets
**Active sessions:** $activeSessions
**Active listeners:** $activeListeners
$warnings
$criticalSection

### Before Ending, Verify:
- [ ] All active Metasploit sessions have been terminated or documented
- [ ] Evidence has been saved to evidence/msf/
- [ ] Findings have been documented in the engagement directory
- [ ] No handlers are left running unintentionally
- [ ] World state at engagements/$engagementId/world-state.json is accurate
- [ ] Command ledger at logs/command-ledger.jsonl has been reviewed for anomalies
"@

$response = @{
    "agentMessage" = $reminder
} | ConvertTo-Json -Compress

Write-Output $response
exit 0
