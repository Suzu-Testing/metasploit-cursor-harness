# =============================================================================
# SESSION CONTEXT - Injected at session start
# Provides the agent with scope, engagement, world state context, and hook
# health status.
# =============================================================================

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot "scope-common.ps1")
. (Join-Path $PSScriptRoot "engagement-resolver.ps1")

$projectRoot = Get-ProjectRoot

trap {
    # If we fail, still provide minimal context
    $fallback = @{
        agentMessage = "## Metasploit Cursor Harness - Session Context`n`nWARNING: session-context hook encountered an error. Hooks may not be fully functional. Check logs/hook-debug.log.`n`n### Safety Reminders`n- Verify scope before any action`n- Use MCP tools over shell commands`n- Do not proceed with out-of-scope targets"
    } | ConvertTo-Json -Compress
    Write-Output $fallback
    exit 0
}

# --- Hook health checks ---
$healthIssues = @()

$requiredHookFiles = @(
    "risk-gate.ps1", "risk-scoring.ps1",
    "mcp-action-gate.ps1", "scope-check.ps1",
    "dangerous-command-gate.ps1",
    "world-state-gate.ps1", "world-state-common.ps1", "world-state-logger.ps1",
    "mcp-evidence-logger.ps1", "evidence-logger.ps1",
    "stop-checklist.ps1",
    "scope-common.ps1", "engagement-resolver.ps1", "input-parser.ps1", "world-state-io.ps1",
    "rate-limit-gate.ps1"
)

foreach ($file in $requiredHookFiles) {
    $path = Join-Path $PSScriptRoot $file
    if (-not (Test-Path $path)) {
        $healthIssues += "Missing hook file: $file"
    }
}

# Check Python availability (needed for world-state.py)
try {
    $pythonVer = & python --version 2>&1
    if ($LASTEXITCODE -ne 0) { $healthIssues += "Python not available (world-state tracking disabled)" }
} catch {
    $healthIssues += "Python not available (world-state tracking disabled)"
}

# Check scope file
$scopeFile = Get-ScopeFile
if (-not (Test-Path $scopeFile)) {
    $healthIssues += "scope/scope-master.txt is MISSING - no scope enforcement possible"
} else {
    $scopeLines = Get-ScopeCIDRs
    if ($scopeLines.Count -eq 0) {
        $healthIssues += "scope/scope-master.txt is EMPTY - no authorized targets"
    }
}

# Check engagement directory writability
$engagementId = Resolve-EngagementId -ProjectRoot $projectRoot
$engDir = Join-Path $projectRoot "engagements\$engagementId"
if (-not (Test-Path $engDir)) {
    try {
        New-Item -ItemType Directory -Path $engDir -Force | Out-Null
    } catch {
        $healthIssues += "Cannot create engagement directory: engagements/$engagementId"
    }
}

# --- Load scope ---
$scopeLines = Get-ScopeCIDRs
$exclusions = Get-ScopeExclusions

# --- Load world state summary ---
$worldStateFile = Get-WorldStateFilePath -EngagementId $engagementId -ProjectRoot $projectRoot
$worldStateSummary = "No prior world state found."

if (Test-Path $worldStateFile) {
    try {
        $ws = Get-Content $worldStateFile -Raw | ConvertFrom-Json
        $totalCmds = if ($ws.session_stats.total_commands) { $ws.session_stats.total_commands } else { 0 }
        $totalMcp = if ($ws.session_stats.total_mcp_calls) { $ws.session_stats.total_mcp_calls } else { 0 }
        $totalShell = if ($ws.session_stats.total_shell_cmds) { $ws.session_stats.total_shell_cmds } else { 0 }
        $lastUpdate = if ($ws.last_updated) { $ws.last_updated } else { "unknown" }
        $targetCount = if ($ws.discovered_targets) { $ws.discovered_targets.Count } else { 0 }
        $sessionCount = if ($ws.active_sessions) { $ws.active_sessions.Count } else { 0 }
        $listenerCount = if ($ws.active_listeners) { $ws.active_listeners.Count } else { 0 }

        $riskSummary = ""
        if ($ws.session_stats.by_risk_level) {
            $parts = @()
            foreach ($lvl in @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')) {
                $val = $ws.session_stats.by_risk_level.$lvl
                if ($null -ne $val -and [int]$val -gt 0) {
                    $parts += "$lvl`:$val"
                }
            }
            if ($parts.Count -gt 0) { $riskSummary = " | Risk breakdown: $($parts -join ', ')" }
        }

        $worldStateSummary = @"
Last updated: $lastUpdate
Prior commands: $totalCmds total (MCP: $totalMcp, Shell: $totalShell)$riskSummary
Discovered targets: $targetCount | Active sessions: $sessionCount | Active listeners: $listenerCount
"@

        # Show recent high-risk commands
        $highRiskRecent = @()
        if ($ws.recent_commands) {
            $highRiskRecent = @($ws.recent_commands | Where-Object { $_.risk_level -eq "HIGH" -or $_.risk_level -eq "CRITICAL" } | Select-Object -First 3)
        }
        if ($highRiskRecent.Count -gt 0) {
            $worldStateSummary += "`nRecent high-risk actions:"
            foreach ($cmd in $highRiskRecent) {
                $preview = if ($cmd.command_preview) { $cmd.command_preview } elseif ($cmd.tool) { "MCP:$($cmd.tool)" } else { "unknown" }
                $worldStateSummary += "`n  - [$($cmd.risk_level) $($cmd.risk_score)/100] $preview ($($cmd.timestamp))"
            }
        }
    } catch {
        $worldStateSummary = "World state file exists but could not be parsed."
    }
}

# --- Build context message ---
$healthSection = ""
if ($healthIssues.Count -gt 0) {
    $healthSection = "`n### Hook Health Issues`n"
    foreach ($issue in $healthIssues) {
        $healthSection += "- WARNING: $issue`n"
    }
} else {
    $healthSection = "`n### Hook Health: All OK ($($requiredHookFiles.Count) scripts verified)`n"
}

$context = @"
## Metasploit Cursor Harness - Session Context

**Active engagement:** $engagementId
**Authorized scope:** $($scopeLines -join ', ')
**Exclusions:** $(if ($exclusions.Count -gt 0) { $exclusions -join ', ' } else { 'None' })
$healthSection
### World State
$worldStateSummary

### Safety Reminders
- All commands are risk-scored (0-100). CRITICAL (76+) requires your approval.
- Every shell command and MCP call is logged to logs/command-ledger.jsonl
- World state is tracked at engagements/$engagementId/world-state.json
- Targets must be within authorized CIDRs in scope/scope-master.txt
- IPs prefixed with ! in scope-master.txt are hard-excluded
- DoS modules (auxiliary/dos/*) are blocked unconditionally
- Run msf_module_check before msf_run_exploit
- Use MCP tools instead of raw msfconsole when possible
- Rate limiting is active: repeated identical actions will be flagged
"@

$response = @{
    "agentMessage" = $context
} | ConvertTo-Json -Compress

Write-Output $response
exit 0
