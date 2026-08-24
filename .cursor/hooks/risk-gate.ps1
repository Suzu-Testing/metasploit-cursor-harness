param(
    [ValidateSet("shell", "mcp")]
    [string]$Mode = "shell"
)

# =============================================================================
# RISK GATE - Preflight hook
# Computes a risk score for every shell command or MCP tool call.
# CRITICAL (76+) commands are escalated to the human operator.
# HIGH (51-75) get a prominent agent warning.
# All scores are logged to the risk-assessments ledger.
# =============================================================================

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot "input-parser.ps1")
. (Join-Path $PSScriptRoot "risk-scoring.ps1")
. (Join-Path $PSScriptRoot "scope-common.ps1")

$projectRoot = Get-ProjectRoot
$hookLogDir = Join-Path $projectRoot "logs"
if (-not (Test-Path $hookLogDir)) { New-Item -ItemType Directory -Path $hookLogDir -Force | Out-Null }
$riskLog = Join-Path $hookLogDir "risk-assessments.jsonl"

trap {
    try { Write-ParseDebug "risk-gate" "TRAP($Mode): $($_.Exception.Message)" } catch {}
    $trapResult = @{
        permission    = "deny"
        user_message  = "Risk gate encountered an internal error and is blocking this action as a safety precaution. Check logs/risk-assessments.jsonl for details."
        agent_message = "RISK GATE ERROR: The risk scoring hook failed. Action blocked (fail-closed). Error: $($_.Exception.Message)"
    } | ConvertTo-Json -Compress
    Write-Output $trapResult
    exit 0
}

# --- Read and parse input ---
$rawInput = Read-HookStdin
$parsed = Parse-HookInput -RawInput $rawInput -HookName "risk-gate"

$command = $null
$toolName = $null
$argsJson = "{}"

if ($Mode -eq "mcp") {
    if ($parsed.Success) {
        $toolName = Extract-McpToolName -ParsedData $parsed.ParsedData -HookName "risk-gate"
        $argsObj = Extract-McpArguments -ParsedData $parsed.ParsedData
        if ($argsObj) {
            try { $argsJson = ($argsObj | ConvertTo-Json -Depth 20 -Compress) } catch {}
        }
    } else {
        $toolName = Extract-McpToolName -RawInput $rawInput -HookName "risk-gate"
    }

    if (-not $toolName) {
        Write-Output '{ "permission": "allow" }'
        exit 0
    }

    $risk = Get-McpRiskScore $toolName $argsJson
    $subject = "MCP:$toolName"
} else {
    if ($parsed.Success) {
        $command = Extract-ShellCommand -ParsedData $parsed.ParsedData -HookName "risk-gate"
    } else {
        $command = Extract-ShellCommand -RawInput $rawInput -HookName "risk-gate"
    }

    if (-not $command) {
        Write-Output '{ "permission": "allow" }'
        exit 0
    }

    $risk = Get-CommandRiskScore $command
    $subject = $command
    if ($subject.Length -gt 120) {
        $subject = $subject.Substring(0, 117) + "..."
    }
}

# --- Log the risk assessment ---
$ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
$logEntry = @{
    timestamp  = $ts
    mode       = $Mode
    subject    = $subject
    risk_score = $risk.Score
    risk_level = $risk.Level
    escalated  = $risk.Escalate
    breakdown  = $risk.Breakdown
} | ConvertTo-Json -Depth 10 -Compress

try { Add-Content -Path $riskLog -Value $logEntry } catch {}

# --- Decide based on risk level ---
if ($risk.Escalate) {
    $breakdown = $risk.Breakdown
    $factors = @()
    if ($breakdown.tool_category.score -gt 0) {
        $factors += "tool=$($breakdown.tool_category.category)(+$($breakdown.tool_category.score))"
    }
    if ($breakdown.target_count.score -gt 0) {
        $factors += "targets=$($breakdown.target_count.count)(+$($breakdown.target_count.score))"
    }
    if ($breakdown.privilege.score -gt 0) {
        $factors += "privilege=$($breakdown.privilege.level)(+$($breakdown.privilege.score))"
    }
    if ($breakdown.destructive.score -gt 0) {
        $factors += "destructive=$($breakdown.destructive.level)(+$($breakdown.destructive.score))"
    }
    if ($breakdown.noise -and $breakdown.noise.score -gt 0) {
        $factors += "noise=$($breakdown.noise.level)(+$($breakdown.noise.score))"
    }
    $factorStr = $factors -join ", "

    $result = @{
        permission    = "ask"
        user_message  = "RISK ESCALATION [$($risk.Score)/100 CRITICAL]: This action requires human approval. Factors: $factorStr"
        agent_message = "RISK SCORE $($risk.Score)/100 (CRITICAL). This command exceeds the risk threshold and requires human-in-the-loop approval. Factors: $factorStr. Do NOT proceed without explicit user approval."
    } | ConvertTo-Json -Compress
    Write-Output $result
    exit 0
}

if ($risk.Level -eq "HIGH") {
    $label = Format-RiskLabel $risk.Score $risk.Level
    $result = @{
        permission    = "allow"
        agent_message = "RISK ASSESSMENT: $label. Proceed with caution. Ensure this action is justified by the engagement objectives."
    } | ConvertTo-Json -Compress
    Write-Output $result
    exit 0
}

if ($risk.Level -eq "MEDIUM") {
    $label = Format-RiskLabel $risk.Score $risk.Level
    $result = @{
        permission    = "allow"
        agent_message = "Risk: $label."
    } | ConvertTo-Json -Compress
    Write-Output $result
    exit 0
}

Write-Output '{ "permission": "allow" }'
exit 0
