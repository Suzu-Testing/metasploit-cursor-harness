# =============================================================================
# SHARED MODULE UNIT TESTS
# Tests scope-common, engagement-resolver, input-parser, world-state-io,
# and risk-scoring as isolated PowerShell modules.
# Run: powershell -ExecutionPolicy Bypass -File tests/hooks/Test-SharedModules.ps1
# =============================================================================

param(
    [switch]$Verbose
)

$ErrorActionPreference = 'Stop'
$script:TestCount = 0
$script:PassCount = 0
$script:FailCount = 0
$script:Failures = @()

$hooksDir = (Resolve-Path (Join-Path $PSScriptRoot "../../.cursor/hooks")).Path
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path

function Assert-Equal {
    param([string]$TestName, $Expected, $Actual)
    $script:TestCount++
    if ($Expected -eq $Actual) {
        $script:PassCount++
        if ($Verbose) { Write-Host "  PASS: $TestName" -ForegroundColor Green }
    } else {
        $script:FailCount++
        $script:Failures += "[$TestName] expected '$Expected', got '$Actual'"
        Write-Host "  FAIL: $TestName (expected '$Expected', got '$Actual')" -ForegroundColor Red
    }
}

function Assert-True {
    param([string]$TestName, [bool]$Condition)
    Assert-Equal $TestName $true $Condition
}

function Assert-False {
    param([string]$TestName, [bool]$Condition)
    Assert-Equal $TestName $false $Condition
}

function Assert-NotNull {
    param([string]$TestName, $Value)
    $script:TestCount++
    if ($null -ne $Value -and $Value -ne '') {
        $script:PassCount++
        if ($Verbose) { Write-Host "  PASS: $TestName" -ForegroundColor Green }
    } else {
        $script:FailCount++
        $script:Failures += "[$TestName] expected non-null/non-empty, got null/empty"
        Write-Host "  FAIL: $TestName (value was null/empty)" -ForegroundColor Red
    }
}

function Assert-Null {
    param([string]$TestName, $Value)
    $script:TestCount++
    if ($null -eq $Value -or $Value -eq '') {
        $script:PassCount++
        if ($Verbose) { Write-Host "  PASS: $TestName" -ForegroundColor Green }
    } else {
        $script:FailCount++
        $script:Failures += "[$TestName] expected null/empty, got '$Value'"
        Write-Host "  FAIL: $TestName (value was '$Value', expected null)" -ForegroundColor Red
    }
}

function Assert-GreaterThan {
    param([string]$TestName, [int]$Expected, [int]$Actual)
    $script:TestCount++
    if ($Actual -gt $Expected) {
        $script:PassCount++
        if ($Verbose) { Write-Host "  PASS: $TestName" -ForegroundColor Green }
    } else {
        $script:FailCount++
        $script:Failures += "[$TestName] expected > $Expected, got $Actual"
        Write-Host "  FAIL: $TestName (expected > $Expected, got $Actual)" -ForegroundColor Red
    }
}

Write-Host "`n=== Shared Module Unit Tests ===" -ForegroundColor Cyan
Write-Host "Project: $projectRoot"
Write-Host "Hooks:   $hooksDir`n"

# =============================================================================
# SCOPE-COMMON.PS1
# =============================================================================
Write-Host "--- scope-common.ps1 ---" -ForegroundColor Yellow
. (Join-Path $hooksDir "scope-common.ps1")

# Test-IpInCidr
Assert-True "IpInCidr: 10.10.0.20 in 10.10.0.0/24" (Test-IpInCidr "10.10.0.20" "10.10.0.0/24")
Assert-True "IpInCidr: 10.10.0.1 in 10.10.0.0/24" (Test-IpInCidr "10.10.0.1" "10.10.0.0/24")
Assert-False "IpInCidr: 10.10.1.1 not in 10.10.0.0/24" (Test-IpInCidr "10.10.1.1" "10.10.0.0/24")
Assert-True "IpInCidr: 192.168.1.50 in 192.168.0.0/16" (Test-IpInCidr "192.168.1.50" "192.168.0.0/16")
Assert-False "IpInCidr: 172.16.0.1 not in 10.0.0.0/8" (Test-IpInCidr "172.16.0.1" "10.0.0.0/8")
Assert-True "IpInCidr: single host /32" (Test-IpInCidr "10.10.0.5" "10.10.0.5/32")
Assert-False "IpInCidr: single host mismatch /32" (Test-IpInCidr "10.10.0.6" "10.10.0.5/32")

# Test-CidrWidth (returns @{Violation=$true/$false})
Assert-False "CidrWidth: /24 within /24 max" (Test-CidrWidth "10.10.0.0/24" 24).Violation
Assert-False "CidrWidth: /28 within /24 max" (Test-CidrWidth "10.10.0.0/28" 24).Violation
Assert-True "CidrWidth: /16 exceeds /24 max" (Test-CidrWidth "10.10.0.0/16" 24).Violation
Assert-False "CidrWidth: bare IP is /32" (Test-CidrWidth "10.10.0.20" 24).Violation
Assert-True "CidrWidth: /8 exceeds /24" (Test-CidrWidth "10.0.0.0/8" 24).Violation

# Extract-IpsFromText
$ips = Extract-IpsFromText "nmap -sV 10.10.0.20 10.10.0.30"
Assert-True "ExtractIPs: finds both IPs" ($ips.Count -ge 2)
$ips2 = Extract-IpsFromText "echo hello world"
Assert-True "ExtractIPs: no IPs in text" ($ips2.Count -eq 0)
$ips3 = Extract-IpsFromText "scan 192.168.1.1/24"
Assert-True "ExtractIPs: finds CIDR address" ($ips3.Count -ge 1)

# Extract-DomainsFromText
$domains = Extract-DomainsFromText "curl https://example.com/path"
Assert-True "ExtractDomains: finds example.com" ($domains -contains "example.com")
$domains2 = Extract-DomainsFromText "nmap 10.10.0.20"
Assert-True "ExtractDomains: no domain in IP-only" ($domains2.Count -eq 0)

# Get-CommandHash
$hash1 = Get-CommandHash "nmap -sV 10.10.0.20"
$hash2 = Get-CommandHash "nmap -sV 10.10.0.20"
$hash3 = Get-CommandHash "nmap -sV 10.10.0.30"
Assert-Equal "CommandHash: same command = same hash" $hash1 $hash2
Assert-True "CommandHash: different command = different hash" ($hash1 -ne $hash3)
Assert-NotNull "CommandHash: returns non-empty" $hash1

# Get-ScopeCIDRs
$cidrs = Get-ScopeCIDRs
Assert-True "GetScopeCIDRs: returns at least one CIDR" ($cidrs.Count -ge 1)

# Test-IpInScope
Assert-True "IpInScope: 10.10.0.20 is in scope" (Test-IpInScope "10.10.0.20")

# =============================================================================
# ENGAGEMENT-RESOLVER.PS1
# =============================================================================
Write-Host "`n--- engagement-resolver.ps1 ---" -ForegroundColor Yellow
. (Join-Path $hooksDir "engagement-resolver.ps1")

# Resolve-EngagementId with explicit arg
$resolved = Resolve-EngagementId -McpEngagementArg "lab-default"
Assert-Equal "EngResolver: explicit lab-default" "lab-default" $resolved

# Resolve-EngagementId fallback (no arg)
$resolved2 = Resolve-EngagementId
Assert-NotNull "EngResolver: fallback when no arg" $resolved2

# Get-EngagementDir
$engDir = Get-EngagementDir "lab-default"
Assert-True "EngResolver: dir path ends with lab-default" ($engDir -like "*lab-default")

# Extract-EngagementIdFromMcpArgs
$extracted = Extract-EngagementIdFromMcpArgs '{"engagement_id":"my-eng","options":{}}'
Assert-Equal "ExtractEngId: from JSON" "my-eng" $extracted

$extractedNull = Extract-EngagementIdFromMcpArgs '{"options":{}}'
Assert-Null "ExtractEngId: missing = null" $extractedNull

# =============================================================================
# INPUT-PARSER.PS1
# =============================================================================
Write-Host "`n--- input-parser.ps1 ---" -ForegroundColor Yellow
. (Join-Path $hooksDir "input-parser.ps1")

# Parse-HookInput with well-formed JSON
$parseResult = Parse-HookInput -RawInput '{"toolName":"msf_search_modules","arguments":{"query":"test"}}'
Assert-True "InputParser: parses valid JSON" $parseResult.Success
Assert-NotNull "InputParser: has ParsedData" $parseResult.ParsedData
Assert-Equal "InputParser: toolName from parsed" "msf_search_modules" $parseResult.ParsedData.toolName

# Parse-HookInput with malformed JSON
$parsedBad = Parse-HookInput -RawInput 'not json at all'
Assert-False "InputParser: malformed fails" $parsedBad.Success
Assert-Null "InputParser: malformed has no data" $parsedBad.ParsedData

# Parse-HookInput with empty string
$parsedEmpty = Parse-HookInput -RawInput ''
Assert-False "InputParser: empty fails" $parsedEmpty.Success

# Extract-ShellCommand (from raw + parsed)
$shellParse = Parse-HookInput -RawInput '{"command":"ls -la"}'
$cmd = Extract-ShellCommand -RawInput '{"command":"ls -la"}' -ParsedData $shellParse.ParsedData
Assert-Equal "InputParser: shell command" "ls -la" $cmd

# Extract-McpToolName (from raw + parsed)
$mcpParse = Parse-HookInput -RawInput '{"toolName":"msf_run_exploit","arguments":{}}'
$tool = Extract-McpToolName -RawInput '{"toolName":"msf_run_exploit","arguments":{}}' -ParsedData $mcpParse.ParsedData
Assert-Equal "InputParser: MCP tool name" "msf_run_exploit" $tool

# Extract-McpToolName fallback from raw text (no parsed data)
$toolFallback = Extract-McpToolName -RawInput '{"toolName":"msf_db_nmap","arguments":{}}'
Assert-Equal "InputParser: MCP tool fallback" "msf_db_nmap" $toolFallback

# Extract-McpArguments (from parsed)
$nmapParse = Parse-HookInput -RawInput '{"toolName":"msf_db_nmap","arguments":{"targets":"10.10.0.0/24","options":"-sV"}}'
$mcpArgs = Extract-McpArguments -ParsedData $nmapParse.ParsedData
Assert-NotNull "InputParser: MCP args" $mcpArgs
Assert-Equal "InputParser: MCP args targets" "10.10.0.0/24" $mcpArgs.targets

# Extract-McpResult
$resultParse = Parse-HookInput -RawInput '{"toolName":"test","result":{"sessions":[1,2]}}'
$resultObj = Extract-McpResult -ParsedData $resultParse.ParsedData
Assert-NotNull "InputParser: MCP result" $resultObj
Assert-Equal "InputParser: MCP result status" "completed" $resultObj.Status

# Extract-ShellOutput
$shellOutParse = Parse-HookInput -RawInput '{"command":"echo hi","output":"hi","exit_code":0}'
$shellOut = Extract-ShellOutput -ParsedData $shellOutParse.ParsedData
Assert-Equal "InputParser: shell output text" "hi" $shellOut.Output
Assert-Equal "InputParser: shell exit code" 0 $shellOut.ExitCode

# =============================================================================
# RISK-SCORING.PS1
# =============================================================================
Write-Host "`n--- risk-scoring.ps1 ---" -ForegroundColor Yellow
. (Join-Path $hooksDir "risk-scoring.ps1")

# MCP risk scoring
$riskLow = Get-McpRiskScore "msf_search_modules" '{"query":"test"}'
Assert-True "RiskScore: search = LOW" ($riskLow.Level -eq "LOW")
Assert-True "RiskScore: search score < 20" ($riskLow.Score -lt 20)

$riskExploit = Get-McpRiskScore "msf_run_exploit" '{"module_path":"exploit/windows/smb/ms17","options":{"RHOSTS":"10.10.0.20"}}'
Assert-True "RiskScore: exploit = HIGH or CRITICAL" ($riskExploit.Level -eq "HIGH" -or $riskExploit.Level -eq "CRITICAL")
Assert-GreaterThan "RiskScore: exploit score > 30" 30 $riskExploit.Score

$riskMultiTarget = Get-McpRiskScore "msf_run_exploit" '{"options":{"RHOSTS":"10.10.0.20 10.10.0.30 10.10.0.40 10.10.0.50"}}'
Assert-GreaterThan "RiskScore: multi-target > single" 30 $riskMultiTarget.Score

# Shell risk scoring (uses Get-CommandRiskScore)
$shellRiskLow = Get-CommandRiskScore "git status"
Assert-True "ShellRisk: git status = LOW" ($shellRiskLow.Level -eq "LOW")

$shellRiskHigh = Get-CommandRiskScore "msfconsole -x 'use exploit/windows/smb/ms17; exploit'"
Assert-True "ShellRisk: msfconsole exploit = HIGH+" ($shellRiskHigh.Level -ne "LOW")

# Breakdown fields
Assert-NotNull "RiskScore: has breakdown" $riskExploit.Breakdown
Assert-NotNull "RiskScore: has tool_category" $riskExploit.Breakdown.tool_category
Assert-NotNull "RiskScore: has noise" $riskExploit.Breakdown.noise

# Escalate flag
Assert-False "RiskScore: low search not escalated" $riskLow.Escalate

# =============================================================================
# WORLD-STATE-IO.PS1
# =============================================================================
Write-Host "`n--- world-state-io.ps1 ---" -ForegroundColor Yellow
. (Join-Path $hooksDir "world-state-io.ps1")

# Use a temp file for testing atomic writes
$testWsFile = Join-Path $env:TEMP "test-world-state-$(Get-Random).json"

try {
    # Test Read-WorldState with non-existent file returns default structure
    $defaultState = Read-WorldState -FilePath $testWsFile
    Assert-Equal "WorldStateIO: default total_commands" 0 $defaultState.session_stats.total_commands
    Assert-Equal "WorldStateIO: default total_mcp_calls" 0 $defaultState.session_stats.total_mcp_calls
    Assert-Equal "WorldStateIO: default total_shell_cmds" 0 $defaultState.session_stats.total_shell_cmds
    Assert-True "WorldStateIO: default has recent_commands array" ($null -ne $defaultState.recent_commands)
    Assert-True "WorldStateIO: default has active_sessions array" ($null -ne $defaultState.active_sessions)

    # Test Write-WorldStateAtomic
    $defaultState.session_stats.total_commands = 5
    $defaultState.session_stats.total_mcp_calls = 3
    $defaultState.session_stats.total_shell_cmds = 2
    $writeResult = Write-WorldStateAtomic -FilePath $testWsFile -WorldState $defaultState
    Assert-True "WorldStateIO: atomic write succeeds" $writeResult

    # Read it back
    $readBack = Read-WorldState -FilePath $testWsFile
    Assert-Equal "WorldStateIO: read total_commands" 5 $readBack.session_stats.total_commands
    Assert-Equal "WorldStateIO: read total_mcp_calls" 3 $readBack.session_stats.total_mcp_calls
    Assert-Equal "WorldStateIO: read total_shell_cmds" 2 $readBack.session_stats.total_shell_cmds

    # Test Write preserves other fields
    $readBack.active_sessions = @("session-1", "session-2")
    $readBack.session_stats.total_commands = 10
    Write-WorldStateAtomic -FilePath $testWsFile -WorldState $readBack | Out-Null

    $readBack2 = Read-WorldState -FilePath $testWsFile
    Assert-Equal "WorldStateIO: sessions preserved" 2 $readBack2.active_sessions.Count
    Assert-Equal "WorldStateIO: incremented total" 10 $readBack2.session_stats.total_commands
    Assert-Equal "WorldStateIO: mcp_calls still 3" 3 $readBack2.session_stats.total_mcp_calls

    # Test Add-RecentCommand
    $ws = Read-WorldState -FilePath $testWsFile
    Add-RecentCommand -WorldState $ws -Entry @{ tool = "msf_search_modules"; target = "10.10.0.20"; timestamp = (Get-Date).ToString() }
    Write-WorldStateAtomic -FilePath $testWsFile -WorldState $ws | Out-Null

    $withCmd = Read-WorldState -FilePath $testWsFile
    Assert-True "WorldStateIO: recent_commands has entry" ($withCmd.recent_commands.Count -ge 1)

    # Test Add-DiscoveredTargets
    $ws2 = Read-WorldState -FilePath $testWsFile
    Add-DiscoveredTargets -WorldState $ws2 -Targets @("10.10.0.50", "10.10.0.60")
    Assert-True "WorldStateIO: targets added" ($ws2.discovered_targets.Count -ge 2)

    # Test deduplication
    Add-DiscoveredTargets -WorldState $ws2 -Targets @("10.10.0.50", "10.10.0.70")
    Assert-True "WorldStateIO: dedup targets" ($ws2.discovered_targets.Count -eq 3)

    # Test ignores loopback
    Add-DiscoveredTargets -WorldState $ws2 -Targets @("127.0.0.1", "0.0.0.0")
    Assert-True "WorldStateIO: ignores loopback" ($ws2.discovered_targets.Count -eq 3)

} finally {
    if (Test-Path $testWsFile) { Remove-Item $testWsFile -Force }
}

# =============================================================================
# CREDENTIAL-FILTER.PS1
# =============================================================================
Write-Host "`n--- credential-filter.ps1 ---" -ForegroundColor Yellow
. (Join-Path $hooksDir "credential-filter.ps1")

# NTLM hash redaction
$ntlmInput = "Found hash: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
$ntlmResult = Invoke-CredentialFilter -Text $ntlmInput
Assert-True "CredFilter: NTLM hash redacted" ($ntlmResult -match 'NTLM_HASH_REDACTED')
Assert-False "CredFilter: NTLM hash gone" ($ntlmResult -match 'aad3b435b51404ee')

# Unix shadow hash
$shadowInput = 'root:$6$rounds=5000$saltsalt$hashhashhashhashhash:18000:0:99999:7:::'
$shadowResult = Invoke-CredentialFilter -Text $shadowInput
Assert-True "CredFilter: Unix hash redacted" ($shadowResult -match 'UNIX_HASH_REDACTED')

# Password assignment
$passInput = 'PASSWORD=MyS3cretP@ss database=prod'
$passResult = Invoke-CredentialFilter -Text $passInput
Assert-True "CredFilter: password redacted" ($passResult -match 'PASSWORD_REDACTED')
Assert-False "CredFilter: password value gone" ($passResult -match 'MyS3cretP@ss')

# AWS key
$awsInput = 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE'
$awsResult = Invoke-CredentialFilter -Text $awsInput
Assert-True "CredFilter: AWS key redacted" ($awsResult -match 'AWS_KEY_REDACTED')

# Bearer token
$bearerInput = 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw'
$bearerResult = Invoke-CredentialFilter -Text $bearerInput
Assert-True "CredFilter: Bearer token redacted" ($bearerResult -match 'TOKEN_REDACTED')

# API key
$apiInput = 'x-api-key: sk_test_1234567890abcdef1234567890abcdef'
$apiResult = Invoke-CredentialFilter -Text $apiInput
Assert-True "CredFilter: API key redacted" ($apiResult -match 'API_KEY_REDACTED')

# SAM dump hash (NTLM pattern may fire first, either way the hash is gone)
$samInput = 'Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::'
$samResult = Invoke-CredentialFilter -Text $samInput
Assert-True "CredFilter: SAM hash redacted" ($samResult -match 'REDACTED')

# Clean text should pass through unchanged
$cleanInput = "22/tcp open ssh OpenSSH 7.6p1 Ubuntu"
$cleanResult = Invoke-CredentialFilter -Text $cleanInput
Assert-Equal "CredFilter: clean text unchanged" $cleanInput $cleanResult

# Test-ContainsCredentials
Assert-True "CredFilter: detects NTLM" (Test-ContainsCredentials $ntlmInput)
Assert-False "CredFilter: clean is safe" (Test-ContainsCredentials $cleanInput)

# ReturnStats mode
$statsResult = Invoke-CredentialFilter -Text $ntlmInput -ReturnStats
Assert-True "CredFilter: stats count > 0" ($statsResult.RedactionCount -gt 0)
Assert-True "CredFilter: stats has type" ($statsResult.Types.Count -gt 0)

# Empty/null handling
$emptyResult = Invoke-CredentialFilter -Text ""
Assert-Equal "CredFilter: empty returns empty" "" $emptyResult

# Kerberoasting hash
$kerbInput = '$krb5tgs$23$*user$DOMAIN.COM$spn*$abc123456789'
$kerbResult = Invoke-CredentialFilter -Text $kerbInput
Assert-True "CredFilter: Kerberos hash redacted" ($kerbResult -match 'KERBEROS_HASH_REDACTED')

# =============================================================================
# SUMMARY
# =============================================================================
Write-Host "`n=== RESULTS ===" -ForegroundColor Cyan
Write-Host "Total: $($script:TestCount) | Pass: $($script:PassCount) | Fail: $($script:FailCount)"

if ($script:FailCount -gt 0) {
    Write-Host "`nFailures:" -ForegroundColor Red
    foreach ($f in $script:Failures) {
        Write-Host "  - $f" -ForegroundColor Red
    }
    exit 1
} else {
    Write-Host "`nAll tests passed!" -ForegroundColor Green
    exit 0
}
