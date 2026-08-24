# =============================================================================
# MCP TOOL LEDGER - Postflight hook
# Records every MCP tool call with structured detail to command-ledger.jsonl
# and updates the world state. Also saves full results as evidence files.
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
$evidenceDir = Join-Path $projectRoot "evidence\msf"
if (-not (Test-Path $evidenceDir)) { New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null }

trap {
    $ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
    try { Write-ParseDebug "mcp-evidence-logger" "TRAP: $($_.Exception.Message)" } catch {}
    Write-Output '{}'
    exit 0
}

# --- Read and parse input ---
$rawInput = Read-HookStdin
$parsed = Parse-HookInput -RawInput $rawInput -HookName "mcp-evidence-logger"

$toolName = $null
$argsObj = $null
$argsJson = "{}"
$resultData = $null
$status = "completed"
$hasResult = $false

if ($parsed.Success) {
    $toolName = Extract-McpToolName -ParsedData $parsed.ParsedData -HookName "mcp-evidence-logger"
    $argsObj = Extract-McpArguments -ParsedData $parsed.ParsedData
    if ($argsObj) {
        try { $argsJson = ($argsObj | ConvertTo-Json -Depth 20 -Compress) } catch { $argsJson = "{}" }
    }
    $mcpResult = Extract-McpResult -ParsedData $parsed.ParsedData
    $status = $mcpResult.Status
    if ($mcpResult.Output) {
        $resultData = $mcpResult.Output
        $hasResult = $true
    }
    if ($parsed.ParsedData.result) {
        $resultData = $parsed.ParsedData.result
        $hasResult = $true
    }
} else {
    # Fallback: try regex extraction from raw input
    $toolName = Extract-McpToolName -RawInput $rawInput -HookName "mcp-evidence-logger"
}

if (-not $toolName) {
    Write-ParseDebug "mcp-evidence-logger" "NO_TOOL_NAME | parsed=$($parsed.Success) | reason=$($parsed.ErrorReason)"
    Write-Output '{}'
    exit 0
}

# --- Resolve engagement ---
$mcpEngId = Extract-EngagementIdFromMcpArgs -ArgsObject $argsObj
$engagementId = Resolve-EngagementId -McpEngagementArg $mcpEngId -ProjectRoot $projectRoot

# --- Compute risk score ---
$risk = Get-McpRiskScore $toolName $argsJson

# --- Extract targets ---
$targets = Extract-IpsFromText $argsJson

# --- Build result summary ---
$resultSummary = ""
if ($hasResult) {
    try {
        if ($resultData -is [string]) {
            $resultSummary = $resultData
        } else {
            $resultSummary = ($resultData | ConvertTo-Json -Depth 5 -Compress)
        }
    } catch {
        $resultSummary = [string]$resultData
    }
    if ($resultSummary.Length -gt 2000) {
        $resultSummary = $resultSummary.Substring(0, 1997) + "..."
    }
}

# --- Build and write ledger entry ---
$ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
$tsFile = Get-Date -Format "yyyyMMdd-HHmmss"

$entry = @{
    timestamp      = $ts
    type           = "mcp"
    tool           = $toolName
    arguments      = $argsJson
    status         = $status
    targets        = $targets
    risk_score     = $risk.Score
    risk_level     = $risk.Level
    tool_category  = $risk.Breakdown.tool_category.category
    engagement_id  = $engagementId
    result_preview = $resultSummary
} | ConvertTo-Json -Depth 5 -Compress

try { Add-Content -Path $ledgerFile -Value $entry } catch {}

# --- Save full evidence file for actionable tools ---
$actionableTools = @(
    'msf_run_exploit', 'msf_run_auxiliary_module', 'msf_run_post_module',
    'msf_module_check', 'msf_send_session_command',
    'msf_start_listener', 'msf_generate_payload',
    'msf_console_execute', 'msf_db_nmap', 'msf_db_import',
    'msf_session_upgrade', 'msf_wait_for_session', 'msf_cleanup_jobs',
    'msf_terminate_session', 'msf_stop_job',
    'msf_host_info', 'msf_service_info', 'msf_vulnerability_info',
    'msf_credential_info', 'msf_loot_info', 'msf_note_info',
    'msf_search_modules',
    'msf_session_sysinfo', 'msf_session_getuid', 'msf_session_ps',
    'msf_session_download', 'msf_session_upload', 'msf_session_info',
    'msf_session_run_script',
    'msf_route_list', 'msf_route_add', 'msf_route_delete', 'msf_autoroute',
    'msf_report_host', 'msf_credential_add', 'msf_db_add_note', 'msf_db_status',
    'msf_module_results', 'msf_job_info', 'msf_delete_workspace',
    'msf_create_workspace', 'msf_set_workspace'
)

if ($hasResult -and $toolName -in $actionableTools) {
    $evidenceFile = Join-Path $evidenceDir "$tsFile-$toolName.json"
    try {
        $evidenceEntry = @{
            timestamp     = $ts
            tool          = $toolName
            arguments     = $argsJson
            status        = $status
            risk_score    = $risk.Score
            risk_level    = $risk.Level
            engagement_id = $engagementId
            result        = $resultData
        } | ConvertTo-Json -Depth 15

        # Redact credentials before writing evidence
        $filterResult = Invoke-CredentialFilter -Text $evidenceEntry -ReturnStats
        $evidenceEntry = $filterResult.Text
        if ($filterResult.RedactionCount -gt 0) {
            $redactNote = "# REDACTED: $($filterResult.RedactionCount) credential(s) [$($filterResult.Types -join ', ')]"
            $evidenceEntry = $redactNote + "`n" + $evidenceEntry
        }

        Set-Content -Path $evidenceFile -Value $evidenceEntry -Encoding UTF8
    } catch {}
}

# --- Update world state atomically ---
$sessionChangeMsg = $null

Update-WorldState -EngagementId $engagementId -ProjectRoot $projectRoot -Mutator {
    param($state)

    $state.session_stats.total_mcp_calls++
    $state.session_stats.by_risk_level[$risk.Level]++

    if ($state.session_stats.by_mcp_tool.ContainsKey($toolName)) {
        $state.session_stats.by_mcp_tool[$toolName]++
    } else {
        $state.session_stats.by_mcp_tool[$toolName] = 1
    }

    # Recent commands
    $recentEntry = @{
        timestamp  = $ts
        type       = "mcp"
        tool       = $toolName
        status     = $status
        risk_score = $risk.Score
        risk_level = $risk.Level
        targets    = $targets
    }
    Add-RecentCommand -WorldState $state -Entry $recentEntry

    # Discovered targets
    Add-DiscoveredTargets -WorldState $state -Targets $targets

    # Session lifecycle: detect new sessions from exploit results
    if ($toolName -eq "msf_run_exploit" -and $hasResult -and $status -eq "completed") {
        try {
            $sessionResult = $resultData
            if ($sessionResult -is [string]) { $sessionResult = $sessionResult | ConvertFrom-Json -ErrorAction SilentlyContinue }
            if ($sessionResult.session_id -or $sessionResult.session) {
                $sessionId = if ($sessionResult.session_id) { $sessionResult.session_id } else { $sessionResult.session }
                $newSession = @{ id = $sessionId; opened_at = $ts; source_tool = $toolName; targets = $targets }
                $state.active_sessions = @($state.active_sessions) + @($newSession)
                $maxSessions = 5
                try {
                    $roeFile = Join-Path (Get-EngagementDir -EngagementId $engagementId -ProjectRoot $projectRoot) "roe.yaml"
                    if (Test-Path $roeFile) {
                        $roeRaw = Get-Content $roeFile -Raw -ErrorAction SilentlyContinue
                        if ($roeRaw -match 'max_sessions:\s*(\d+)') { $maxSessions = [int]$Matches[1] }
                    }
                } catch {}
                $remaining = $maxSessions - $state.active_sessions.Count
                $script:sessionChangeMsg = "Session $sessionId opened. Active: $($state.active_sessions.Count)/$maxSessions (remaining capacity: $remaining)."
            }
        } catch {}
    }

    # Session lifecycle: detect termination
    if ($toolName -eq "msf_terminate_session" -and $status -eq "completed") {
        try {
            $termId = $null
            if ($argsObj.session_id) { $termId = [string]$argsObj.session_id }
            elseif ($argsObj.id) { $termId = [string]$argsObj.id }
            if ($termId) {
                $state.active_sessions = @($state.active_sessions | Where-Object { [string]$_.id -ne $termId })
                $script:sessionChangeMsg = "Session $termId terminated. Active: $($state.active_sessions.Count) remaining."
            }
        } catch {}
    }

    # Update sessions/listeners from list operations
    if ($toolName -eq "msf_list_active_sessions" -and $hasResult -and $status -eq "completed") {
        try {
            $sData = $resultData
            if ($sData -is [string]) { $sData = $sData | ConvertFrom-Json -ErrorAction SilentlyContinue }
            if ($sData.sessions) { $state.active_sessions = @($sData.sessions) }
        } catch {}
    }

    if ($toolName -eq "msf_list_listeners" -and $hasResult -and $status -eq "completed") {
        try {
            $lData = $resultData
            if ($lData -is [string]) { $lData = $lData | ConvertFrom-Json -ErrorAction SilentlyContinue }
            if ($lData.listeners) { $state.active_listeners = @($lData.listeners) }
        } catch {}
    }
} | Out-Null

# --- Emit agent message for session changes ---
if ($sessionChangeMsg) {
    $response = @{
        agentMessage = $sessionChangeMsg
    } | ConvertTo-Json -Compress
    Write-Output $response
    exit 0
}

Write-Output '{}'
exit 0
