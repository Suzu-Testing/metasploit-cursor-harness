param(
    [ValidateSet("shell", "mcp")]
    [string]$Mode = "shell"
)

# =============================================================================
# WORLD STATE GATE - Preflight duplicate detection
# Warns the agent if an action appears to have been run before.
# Never blocks execution (failClosed: false).
# =============================================================================

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot "input-parser.ps1")
. (Join-Path $PSScriptRoot "world-state-common.ps1")

trap {
    try { Write-ParseDebug "world-state-gate" "TRAP($Mode): $($_.Exception.Message)" } catch {}
    Write-Output '{ "permission": "allow" }'
    exit 0
}

$rawInput = Read-HookStdin
$parsed = Parse-HookInput -RawInput $rawInput -HookName "world-state-gate"

$agentMessage = $null

if ($Mode -eq "mcp") {
    $toolName = $null
    $argsJson = "{}"

    if ($parsed.Success) {
        $toolName = Extract-McpToolName -ParsedData $parsed.ParsedData -HookName "world-state-gate"
        $argsObj = Extract-McpArguments -ParsedData $parsed.ParsedData
        if ($argsObj) {
            try { $argsJson = ($argsObj | ConvertTo-Json -Depth 20 -Compress) } catch {}
        }
    } else {
        $toolName = Extract-McpToolName -RawInput $rawInput -HookName "world-state-gate"
    }

    if ($toolName -and $toolName -ne "unknown") {
        $checkJson = Invoke-WorldStatePython -Arguments @(
            "check",
            "--type", "mcp",
            "--tool", $toolName,
            "--args-json", $argsJson
        )
        $agentMessage = Format-WorldStateAgentMessage $checkJson "mcp"
    }
} else {
    $command = $null
    if ($parsed.Success) {
        $command = Extract-ShellCommand -ParsedData $parsed.ParsedData -HookName "world-state-gate"
    } else {
        $command = Extract-ShellCommand -RawInput $rawInput -HookName "world-state-gate"
    }

    if ($command -and -not (Test-SkipWorldStateCommand $command)) {
        $commandB64 = ConvertTo-Base64Utf8 $command
        $checkJson = Invoke-WorldStatePython -Arguments @(
            "check",
            "--type", "shell",
            "--payload-b64", $commandB64
        )
        $agentMessage = Format-WorldStateAgentMessage $checkJson "shell"
    }
}

if ($agentMessage) {
    $permission = "allow"
    if ($Mode -eq "mcp" -and $toolName -eq "msf_run_exploit") {
        $response = @{
            permission    = "ask"
            user_message  = "DUPLICATE EXPLOIT DETECTED: This exploit appears to have already been executed. Use msf_list_active_sessions to check for existing sessions. Approve to re-run."
            agent_message = $agentMessage
        } | ConvertTo-Json -Compress
        Write-Output $response
        exit 0
    }

    $response = @{
        permission    = $permission
        agent_message = $agentMessage
    } | ConvertTo-Json -Compress
    Write-Output $response
    exit 0
}

Write-Output '{ "permission": "allow" }'
exit 0
