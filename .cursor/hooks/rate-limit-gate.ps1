param(
    [ValidateSet("shell", "mcp")]
    [string]$Mode = "shell"
)

# =============================================================================
# RATE LIMIT GATE - Preflight cooldown enforcement
# Prevents rapid repetition of the same high-risk action against the same target.
# Reads the command ledger tail and blocks if an identical tool+target combination
# was executed within the cooldown period.
#
# Configurable:
#   Cooldown periods by risk level:
#     CRITICAL: 120 seconds
#     HIGH:      60 seconds
#     MEDIUM:    30 seconds
#     LOW:       no rate limiting
# =============================================================================

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot "input-parser.ps1")
. (Join-Path $PSScriptRoot "scope-common.ps1")
. (Join-Path $PSScriptRoot "risk-scoring.ps1")

$projectRoot = Get-ProjectRoot
$ledgerFile = Join-Path $projectRoot "logs\command-ledger.jsonl"

# Cooldown thresholds (seconds)
$cooldownCritical = 120
$cooldownHigh     = 60
$cooldownMedium   = 30

trap {
    try { Write-ParseDebug "rate-limit-gate" "TRAP($Mode): $($_.Exception.Message)" } catch {}
    Write-Output '{ "permission": "allow" }'
    exit 0
}

# --- Read and parse input ---
$rawInput = Read-HookStdin
$parsed = Parse-HookInput -RawInput $rawInput -HookName "rate-limit-gate"

$currentTool = $null
$currentTargets = @()
$currentRiskLevel = "LOW"

if ($Mode -eq "mcp") {
    if ($parsed.Success) {
        $currentTool = Extract-McpToolName -ParsedData $parsed.ParsedData -HookName "rate-limit-gate"
        $argsObj = Extract-McpArguments -ParsedData $parsed.ParsedData
        if ($argsObj) {
            try {
                $argsStr = ($argsObj | ConvertTo-Json -Depth 10 -Compress)
                $currentTargets = Extract-IpsFromText $argsStr
            } catch {}
        }
        if ($currentTool) {
            $argsJson = if ($argsStr) { $argsStr } else { "{}" }
            $risk = Get-McpRiskScore $currentTool $argsJson
            $currentRiskLevel = $risk.Level
        }
    } else {
        $currentTool = Extract-McpToolName -RawInput $rawInput -HookName "rate-limit-gate"
    }
} else {
    $command = $null
    if ($parsed.Success) {
        $command = Extract-ShellCommand -ParsedData $parsed.ParsedData -HookName "rate-limit-gate"
    } else {
        $command = Extract-ShellCommand -RawInput $rawInput -HookName "rate-limit-gate"
    }
    if ($command) {
        $currentTool = $command
        $currentTargets = Extract-IpsFromText $command
        $risk = Get-CommandRiskScore $command
        $currentRiskLevel = $risk.Level
    }
}

# Only rate-limit MEDIUM+ risk actions
if (-not $currentTool -or $currentRiskLevel -eq "LOW") {
    Write-Output '{ "permission": "allow" }'
    exit 0
}

# Determine cooldown period
$cooldownSeconds = switch ($currentRiskLevel) {
    "CRITICAL" { $cooldownCritical }
    "HIGH"     { $cooldownHigh }
    "MEDIUM"   { $cooldownMedium }
    default    { 0 }
}

if ($cooldownSeconds -eq 0) {
    Write-Output '{ "permission": "allow" }'
    exit 0
}

# --- Read recent ledger entries ---
if (-not (Test-Path $ledgerFile)) {
    Write-Output '{ "permission": "allow" }'
    exit 0
}

$now = Get-Date
$cutoff = $now.AddSeconds(-$cooldownSeconds)
$recentEntries = @()

try {
    # Read last 50 lines of ledger
    $lines = Get-Content $ledgerFile -Tail 50 -ErrorAction SilentlyContinue
    foreach ($line in $lines) {
        if (-not $line) { continue }
        try {
            $entry = $line | ConvertFrom-Json -ErrorAction SilentlyContinue
            if (-not $entry -or -not $entry.timestamp) { continue }

            $entryTime = [DateTime]::Parse($entry.timestamp)
            if ($entryTime -lt $cutoff) { continue }

            $recentEntries += $entry
        } catch { continue }
    }
} catch {
    Write-Output '{ "permission": "allow" }'
    exit 0
}

# --- Check for duplicate tool+target within cooldown ---
$currentTargetSet = ($currentTargets | Sort-Object) -join ","
$toolIdentifier = if ($Mode -eq "mcp") { $currentTool } else { Get-CommandHash -Command $currentTool -Length 16 }

foreach ($entry in $recentEntries) {
    $entryTool = $null
    $entryTargets = @()

    if ($entry.type -eq "mcp" -and $Mode -eq "mcp") {
        $entryTool = $entry.tool
        $entryTargets = @($entry.targets)
    } elseif ($entry.type -eq "shell" -and $Mode -eq "shell") {
        $entryTool = $entry.command_hash
        $entryTargets = @($entry.targets)
    } else { continue }

    $entryTargetSet = ($entryTargets | Sort-Object) -join ","

    # Match: same tool and same target set
    if ($entryTool -eq $toolIdentifier -and $entryTargetSet -eq $currentTargetSet -and $currentTargetSet -ne "") {
        $entryTime = [DateTime]::Parse($entry.timestamp)
        $elapsed = [int]($now - $entryTime).TotalSeconds
        $remaining = $cooldownSeconds - $elapsed

        $result = @{
            permission    = "ask"
            user_message  = "RATE LIMIT: This exact action (same tool + targets) was run ${elapsed}s ago. Cooldown: ${cooldownSeconds}s for $currentRiskLevel risk. Wait ${remaining}s or confirm to proceed."
            agent_message = "Rate limit triggered: identical $currentRiskLevel-risk action detected within cooldown window (${elapsed}s < ${cooldownSeconds}s). This prevents accidental exploitation loops. If intentional repetition is needed, ask the user to confirm."
        } | ConvertTo-Json -Compress
        Write-Output $result
        exit 0
    }
}

Write-Output '{ "permission": "allow" }'
exit 0
