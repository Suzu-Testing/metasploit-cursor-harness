# =============================================================================
# INPUT-PARSER - Robust hook JSON input parsing with debug logging
# Handles various input formats from Cursor hook system:
#   - Standard JSON with { command, shell_command, cmd } for shell hooks
#   - Standard JSON with { toolName, tool, arguments, input } for MCP hooks
#   - Malformed JSON with prefix bytes (known Cursor issue)
#   - Plain text fallback for shell hooks
# =============================================================================

$script:_InputParserDebugLog = $null

function Get-DebugLogPath {
    if (-not $script:_InputParserDebugLog) {
        $root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
        $logDir = Join-Path $root "logs"
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        $script:_InputParserDebugLog = Join-Path $logDir "hook-debug.log"
    }
    return $script:_InputParserDebugLog
}

function Write-ParseDebug {
    param([string]$Hook, [string]$Message, [string]$RawPreview = "")
    try {
        $ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        $line = "$ts | $Hook | $Message"
        if ($RawPreview) { $line += " | raw=$RawPreview" }
        Add-Content -Path (Get-DebugLogPath) -Value $line
    } catch {}
}

function Read-HookStdin {
    $raw = ""
    try { $raw = [Console]::In.ReadToEnd() } catch { $raw = "" }
    return $raw
}

function Clean-JsonInput {
    param([string]$RawInput)
    if (-not $RawInput) { return $null }
    $trimmed = $RawInput.Trim()
    if (-not $trimmed) { return $null }

    # Handle known prefix bytes issue (e.g., "n++" prefix from Cursor)
    if ($trimmed -notmatch '^\s*[\{\[]') {
        $jsonStart = $trimmed.IndexOf('{')
        if ($jsonStart -gt 0) {
            $trimmed = $trimmed.Substring($jsonStart)
        } elseif ($trimmed -notmatch '^\s*[\{\[]') {
            return $null
        }
    }
    return $trimmed
}

function Parse-HookInput {
    param(
        [string]$RawInput,
        [string]$HookName = "unknown"
    )

    $result = @{
        Success     = $false
        RawInput    = $RawInput
        ParsedData  = $null
        ErrorReason = $null
    }

    if (-not $RawInput -or $RawInput.Trim().Length -eq 0) {
        $result.ErrorReason = "empty_input"
        return $result
    }

    $cleaned = Clean-JsonInput $RawInput
    if (-not $cleaned) {
        $result.ErrorReason = "no_json_found"
        $preview = if ($RawInput.Length -gt 200) { $RawInput.Substring(0, 200) } else { $RawInput }
        Write-ParseDebug $HookName "NO_JSON_FOUND" $preview
        return $result
    }

    try {
        $parsed = $cleaned | ConvertFrom-Json
        $result.Success = $true
        $result.ParsedData = $parsed
        return $result
    } catch {
        $result.ErrorReason = "json_parse_fail"
        $preview = if ($cleaned.Length -gt 200) { $cleaned.Substring(0, 200) } else { $cleaned }
        Write-ParseDebug $HookName "JSON_PARSE_FAIL | len=$($cleaned.Length)" $preview
    }

    # Regex fallback: will not fill ParsedData but callers can use Extract- functions
    $result.ErrorReason = "json_parse_fail_with_fallback"
    return $result
}

function Extract-ShellCommand {
    param(
        [string]$RawInput,
        $ParsedData = $null,
        [string]$HookName = "unknown"
    )

    # From parsed JSON
    if ($ParsedData) {
        if ($ParsedData.command) { return [string]$ParsedData.command }
        if ($ParsedData.shell_command) { return [string]$ParsedData.shell_command }
        if ($ParsedData.cmd) { return [string]$ParsedData.cmd }
    }

    if (-not $RawInput) { return $null }

    # Regex fallback for malformed JSON
    if ($RawInput -match '"command"\s*:\s*"((?:[^"\\]|\\.)*)"') {
        return ($Matches[1] -replace '\\(.)', '$1')
    }
    if ($RawInput -match '"shell_command"\s*:\s*"((?:[^"\\]|\\.)*)"') {
        return ($Matches[1] -replace '\\(.)', '$1')
    }
    if ($RawInput -match '"cmd"\s*:\s*"((?:[^"\\]|\\.)*)"') {
        return ($Matches[1] -replace '\\(.)', '$1')
    }

    # Plain text fallback (not JSON at all)
    if ($RawInput.Trim() -notmatch '^\s*\{') {
        return $RawInput.Trim()
    }

    return $null
}

function Extract-McpToolName {
    param(
        [string]$RawInput,
        $ParsedData = $null,
        [string]$HookName = "unknown"
    )

    if ($ParsedData) {
        if ($ParsedData.toolName) { return [string]$ParsedData.toolName }
        if ($ParsedData.tool) { return [string]$ParsedData.tool }
    }

    if (-not $RawInput) { return $null }

    # Regex fallback
    if ($RawInput -match '"toolName"\s*:\s*"([^"]+)"') { return $Matches[1] }
    if ($RawInput -match '"tool"\s*:\s*"([^"]+)"') { return $Matches[1] }

    return $null
}

function Extract-McpArguments {
    param(
        $ParsedData = $null
    )

    if (-not $ParsedData) { return $null }
    if ($ParsedData.arguments) { return $ParsedData.arguments }
    if ($ParsedData.input) { return $ParsedData.input }
    return $null
}

function Extract-McpResult {
    param($ParsedData = $null)

    $output = @{ Output = ""; Status = "completed" }
    if (-not $ParsedData) { return $output }

    if ($ParsedData.result) {
        $output.Output = $ParsedData.result
    }
    if ($ParsedData.output -and -not $output.Output) {
        $output.Output = $ParsedData.output
    }
    if ($ParsedData.error) {
        $output.Status = "failed"
        $output.Output = $ParsedData.error
    }
    return $output
}

function Extract-ShellOutput {
    param($ParsedData = $null)

    $result = @{ Output = ""; ExitCode = 0 }
    if (-not $ParsedData) { return $result }

    if ($null -ne $ParsedData.output) { $result.Output = [string]$ParsedData.output }
    elseif ($null -ne $ParsedData.stdout) { $result.Output = [string]$ParsedData.stdout }
    elseif ($null -ne $ParsedData.result) { $result.Output = [string]$ParsedData.result }

    if ($null -ne $ParsedData.exit_code) { $result.ExitCode = [int]$ParsedData.exit_code }
    elseif ($null -ne $ParsedData.exitCode) { $result.ExitCode = [int]$ParsedData.exitCode }

    return $result
}
