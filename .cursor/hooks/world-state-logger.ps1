param(
    [ValidateSet("shell", "mcp")]
    [string]$Mode = "shell"
)

# =============================================================================
# WORLD STATE LOGGER - Postflight world-state recording via Python bridge
# Records actions to world-state-index.json and world-state.md.
# =============================================================================

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot "input-parser.ps1")
. (Join-Path $PSScriptRoot "world-state-common.ps1")

trap {
    try { Write-ParseDebug "world-state-logger" "TRAP($Mode): $($_.Exception.Message)" } catch {}
    Write-Output '{}'
    exit 0
}

$rawInput = Read-HookStdin
$parsed = Parse-HookInput -RawInput $rawInput -HookName "world-state-logger"

if ($Mode -eq "mcp") {
    $toolName = $null
    $argsJson = "{}"
    $resultOutput = ""
    $status = "completed"

    if ($parsed.Success) {
        $toolName = Extract-McpToolName -ParsedData $parsed.ParsedData -HookName "world-state-logger"
        $argsObj = Extract-McpArguments -ParsedData $parsed.ParsedData
        if ($argsObj) {
            try { $argsJson = ($argsObj | ConvertTo-Json -Depth 20 -Compress) } catch {}
        }
        $mcpResult = Extract-McpResult -ParsedData $parsed.ParsedData
        $resultOutput = $mcpResult.Output
        $status = $mcpResult.Status
    } else {
        $toolName = Extract-McpToolName -RawInput $rawInput -HookName "world-state-logger"
    }

    if ($toolName -and $toolName -ne "unknown") {
        $resultStr = ""
        if ($resultOutput -is [string]) { $resultStr = $resultOutput }
        else { try { $resultStr = ($resultOutput | ConvertTo-Json -Depth 5 -Compress) } catch {} }
        $resultB64 = ConvertTo-Base64Utf8 $resultStr
        Invoke-WorldStatePython -Arguments @(
            "record-mcp",
            "--tool", $toolName,
            "--args-json", $argsJson,
            "--result-b64", $resultB64,
            "--status", $status
        ) | Out-Null
    }
} else {
    $command = $null
    $output = ""
    $exitCode = 0

    if ($parsed.Success) {
        $command = Extract-ShellCommand -ParsedData $parsed.ParsedData -HookName "world-state-logger"
        $shellOutput = Extract-ShellOutput -ParsedData $parsed.ParsedData
        $output = $shellOutput.Output
        $exitCode = $shellOutput.ExitCode
    } else {
        $command = Extract-ShellCommand -RawInput $rawInput -HookName "world-state-logger"
    }

    if ($command -and -not (Test-SkipWorldStateCommand $command)) {
        $commandB64 = ConvertTo-Base64Utf8 $command
        $outputB64 = ConvertTo-Base64Utf8 ([string]$output)
        Invoke-WorldStatePython -Arguments @(
            "record-shell",
            "--payload-b64", $commandB64,
            "--output-b64", $outputB64,
            "--exit-code", "$exitCode"
        ) | Out-Null
    }
}

Write-Output '{}'
exit 0
