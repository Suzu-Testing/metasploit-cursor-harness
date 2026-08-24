# =============================================================================
# WORLD-STATE-COMMON - Bridge between PowerShell hooks and world-state.py
# Provides helpers for base64 encoding, duplicate message formatting,
# and skip patterns for meta-commands.
# =============================================================================

function Get-WorldStateProjectRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

function Get-WorldStateScript {
    $root = Get-WorldStateProjectRoot
    return (Join-Path $root ".cursor\skills\pentest-workflow\scripts\world-state.py")
}

function ConvertTo-Base64Utf8([string]$Text) {
    if (-not $Text) { return "" }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    return [Convert]::ToBase64String($bytes)
}

function Invoke-WorldStatePython {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $script = Get-WorldStateScript
    if (-not (Test-Path $script)) {
        return $null
    }

    try {
        $output = & python $script @Arguments 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        return ($output | Out-String).Trim()
    } catch {
        return $null
    }
}

function Test-SkipWorldStateCommand([string]$Command) {
    if (-not $Command) { return $true }
    $normalized = $Command.ToLower()
    $skipPatterns = @(
        "world-state.py",
        "world-state-gate.ps1",
        "world-state-logger.ps1",
        "world-state-io.ps1",
        "hook-audit.log",
        "hook-debug.log",
        "rate-limit-gate.ps1"
    )
    foreach ($pattern in $skipPatterns) {
        if ($normalized -like "*$pattern*") { return $true }
    }
    return $false
}

function Format-WorldStateAgentMessage($checkResult, $kind) {
    if (-not $checkResult) { return $null }
    try {
        $parsed = $checkResult | ConvertFrom-Json
        if (-not $parsed.duplicate) { return $null }

        $prior = $parsed.prior
        $path = $parsed.world_state_path
        $when = $prior.recorded_at
        $status = $prior.status
        $summary = $prior.result_summary
        if ($summary.Length -gt 300) {
            $summary = $summary.Substring(0, 297) + "..."
        }

        return @"
WORLD STATE DUPLICATE CHECK ($kind):
This action appears to have already been run for engagement '$($parsed.engagement_id)'.
Read '$path' before repeating work.
Prior run: $when | status=$status
Prior result summary: $summary
If the prior result is still valid, skip re-execution and continue with the next pending subgate.
"@
    } catch {
        return $null
    }
}
