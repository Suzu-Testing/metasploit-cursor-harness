# =============================================================================
# MCP ACTION GATE - Preflight scope enforcement for MCP tool calls
# Validates targets (IPs, domains, CIDRs) against scope files.
# Also blocks forbidden module patterns and dangerous console commands.
# =============================================================================

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot "input-parser.ps1")
. (Join-Path $PSScriptRoot "scope-common.ps1")
. (Join-Path $PSScriptRoot "engagement-resolver.ps1")

$projectRoot = Get-ProjectRoot
$hookLogDir = Join-Path $projectRoot "logs"
if (-not (Test-Path $hookLogDir)) { New-Item -ItemType Directory -Path $hookLogDir -Force | Out-Null }
$hookLog = Join-Path $hookLogDir "hook-audit.log"

trap {
    try { Write-ParseDebug "mcp-action-gate" "TRAP: $($_.Exception.Message)" } catch {}
    # Fail closed: deny on unhandled errors
    Write-Output '{ "permission": "deny", "user_message": "MCP action gate encountered an internal error (fail-closed).", "agent_message": "Hook internal error. Retry or check logs/hook-debug.log." }'
    exit 0
}

function Write-HookDecision($decision, $reason, $tool) {
    $ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    $line = "$ts | hook=mcp-action-gate | decision=$decision | reason=$reason | tool=$tool"
    try { Add-Content -Path $hookLog -Value $line } catch {}
}

# --- Read and parse input ---
$rawInput = Read-HookStdin
$parsed = Parse-HookInput -RawInput $rawInput -HookName "mcp-action-gate"

$toolName = "unknown"
$targets = @()
$domains = @()
$argsObj = $null

if ($parsed.Success) {
    $toolName = Extract-McpToolName -ParsedData $parsed.ParsedData -HookName "mcp-action-gate"
    if (-not $toolName) { $toolName = "unknown" }
    $argsObj = Extract-McpArguments -ParsedData $parsed.ParsedData
} else {
    $toolName = Extract-McpToolName -RawInput $rawInput -HookName "mcp-action-gate"
    if (-not $toolName) { $toolName = "unknown" }
    Write-HookDecision "deny" "json_parse_fail" $toolName
    Write-Output '{ "permission": "deny", "user_message": "MCP action gate: failed to parse hook input JSON. Denying as a safety precaution (fail-closed).", "agent_message": "Hook input could not be parsed. Ensure the MCP call has valid JSON arguments." }'
    exit 0
}

# --- Extract targets from MCP arguments ---
if ($argsObj) {
    # IP targets from various argument fields
    $rhosts = $null
    if ($argsObj.options -and $argsObj.options.RHOSTS) { $rhosts = $argsObj.options.RHOSTS }
    elseif ($argsObj.options -and $argsObj.options.rhosts) { $rhosts = $argsObj.options.rhosts }
    elseif ($argsObj.RHOSTS) { $rhosts = $argsObj.RHOSTS }
    elseif ($argsObj.target) { $rhosts = $argsObj.target }
    elseif ($argsObj.targets) { $rhosts = $argsObj.targets }
    elseif ($argsObj.host) { $rhosts = $argsObj.host }
    elseif ($argsObj.subnet) { $rhosts = $argsObj.subnet }
    elseif ($argsObj.lhost) { $rhosts = $argsObj.lhost }
    if ($rhosts) {
        $targets = @($rhosts -split '[,\s]' | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() })
    }

    # Extract IPs from command field (msf_console_execute)
    if ($targets.Count -eq 0 -and $argsObj.command) {
        $targets = Extract-IpsFromText $argsObj.command
    }

    # Extract IPs from any remaining args as JSON
    if ($targets.Count -eq 0) {
        try {
            $argsStr = ($argsObj | ConvertTo-Json -Depth 10 -Compress)
            $targets = Extract-IpsFromText $argsStr
        } catch {}
    }

    # Extract domains from arguments
    try {
        $argsStr = if ($argsStr) { $argsStr } else { ($argsObj | ConvertTo-Json -Depth 10 -Compress) }
        $domains = Extract-DomainsFromText $argsStr
    } catch {}
}

# =============================================================================
# DANGEROUS PATTERN CHECKS (MCP equivalent of dangerous-command-gate)
# =============================================================================

# Check for forbidden module paths in any argument
$forbiddenModulePrefixes = @("auxiliary/dos/")
$moduleField = $null
if ($argsObj.module_path) { $moduleField = $argsObj.module_path }
elseif ($argsObj.module) { $moduleField = $argsObj.module }

if ($moduleField) {
    foreach ($prefix in $forbiddenModulePrefixes) {
        if ($moduleField -like "$prefix*") {
            Write-HookDecision "deny" "forbidden_module:$moduleField" $toolName
            $msg = @{
                permission    = "deny"
                user_message  = "BLOCKED: Module '$moduleField' is unconditionally forbidden (DoS module)."
                agent_message = "Module $moduleField blocked by ROE. DoS modules (auxiliary/dos/*) are never allowed."
            } | ConvertTo-Json -Compress
            Write-Output $msg
            exit 0
        }
    }
}

# Check msf_console_execute command field for dangerous patterns
if ($toolName -eq "msf_console_execute" -and $argsObj.command) {
    $consoleCmd = [string]$argsObj.command

    # Block DoS modules via console
    if ($consoleCmd -match 'auxiliary/dos/') {
        Write-HookDecision "deny" "console_dos_module" $toolName
        $msg = @{
            permission    = "deny"
            user_message  = "BLOCKED: Console command references a DoS module (auxiliary/dos/*)."
            agent_message = "DoS modules are unconditionally forbidden. Use MCP tools with non-DoS modules instead."
        } | ConvertTo-Json -Compress
        Write-Output $msg
        exit 0
    }

    # Block direct shell commands that bypass scope (e.g., system calls)
    $dangerousConsolePatterns = @(
        @{ pattern = '\bsystem\s*\('; reason = "system() call in console command" },
        @{ pattern = '\b(rm|del)\s+(-rf?\s+)?/'; reason = "Recursive delete in console" },
        @{ pattern = '\bshutdown\b'; reason = "Shutdown command in console" }
    )
    foreach ($rule in $dangerousConsolePatterns) {
        if ($consoleCmd -match $rule.pattern) {
            Write-HookDecision "deny" $rule.reason $toolName
            $msg = @{
                permission    = "deny"
                user_message  = "BLOCKED: Console command contains dangerous pattern: $($rule.reason)"
                agent_message = "Dangerous pattern detected in msf_console_execute command. $($rule.reason). Use specific MCP tools instead."
            } | ConvertTo-Json -Compress
            Write-Output $msg
            exit 0
        }
    }
}

# =============================================================================
# SCOPE CHECKS - IPs
# =============================================================================

if ($targets.Count -eq 0 -and $domains.Count -eq 0) {
    Write-HookDecision "allow" "no_targets_extracted" $toolName
    Write-Output '{ "permission": "allow" }'
    exit 0
}

$cidrs = Get-ScopeCIDRs
$exclusions = Get-ScopeExclusions

if ($cidrs.Count -eq 0) {
    Write-HookDecision "deny" "no_scope_file" $toolName
    $msg = '{ "permission": "deny", "user_message": "SCOPE FILE EMPTY: No authorized CIDRs in scope/scope-master.txt. Add targets before using destructive tools.", "agent_message": "The scope file has no authorized CIDRs. Add target ranges to scope/scope-master.txt." }'
    Write-Output $msg
    exit 0
}

foreach ($target in $targets) {
    $t = $target.Trim()
    if (-not $t) { continue }
    if ($t -in @("127.0.0.1", "0.0.0.0")) { continue }

    # Check for CIDR width violations
    if ($t -match '/') {
        $engId = Resolve-EngagementId -ProjectRoot $projectRoot
        $maxCidr = Get-MaxScanCidr -EngagementId $engId
        $widthCheck = Test-CidrWidth -Target $t -MaxPrefix $maxCidr
        if ($widthCheck.Violation) {
            Write-HookDecision "deny" "broad_cidr:$t" $toolName
            $msg = @{
                permission    = "deny"
                user_message  = "BLOCKED: $($widthCheck.Message)"
                agent_message = "CIDR $t is broader than max /$maxCidr. Use narrower ranges from scope/scope-master.txt."
            } | ConvertTo-Json -Compress
            Write-Output $msg
            exit 0
        }
    }

    # Validate IP is not a CIDR notation for individual check
    $ipToCheck = $t -replace '/\d+$', ''
    if ($ipToCheck -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { continue }

    # Check exclusion first
    if (Test-IpExcluded -Ip $ipToCheck -Exclusions $exclusions) {
        Write-HookDecision "deny" "excluded:$ipToCheck" $toolName
        $msg = @{
            permission    = "deny"
            user_message  = "EXCLUDED TARGET: $ipToCheck is on the exclusion list in scope/scope-master.txt."
            agent_message = "Target $ipToCheck is explicitly excluded. Do not target this IP under any circumstances."
        } | ConvertTo-Json -Compress
        Write-Output $msg
        exit 0
    }

    # Check scope
    if (-not (Test-IpInScope -Ip $ipToCheck -CIDRs $cidrs)) {
        Write-HookDecision "deny" "out_of_scope:$ipToCheck" $toolName
        $msg = @{
            permission    = "deny"
            user_message  = "TARGET OUT OF SCOPE: $ipToCheck is not in authorized CIDRs. Check scope/scope-master.txt."
            agent_message = "Target $ipToCheck is outside authorized scope. Do not proceed with this target."
        } | ConvertTo-Json -Compress
        Write-Output $msg
        exit 0
    }
}

# =============================================================================
# SCOPE CHECKS - Domains
# =============================================================================

$scopeDomains = Get-ScopeDomains

foreach ($domain in $domains) {
    if (-not $domain) { continue }
    # Skip common safe/test domains
    $safeDomains = @('localhost', 'example.com', 'example.org', 'test.com', 'test.local')
    $isSafe = $false
    foreach ($safe in $safeDomains) {
        if ($domain -eq $safe -or $domain.EndsWith(".$safe")) { $isSafe = $true; break }
    }
    if ($isSafe) { continue }

    # Check against authorized domains
    if (-not (Test-DomainInScope -Domain $domain -AuthorizedDomains $scopeDomains)) {
        # Try DNS resolution as fallback
        $resolvedInScope = $false
        try {
            $resolved = Resolve-DnsName -Name $domain -Type A -DnsOnly -ErrorAction Stop | Where-Object { $_.QueryType -eq 'A' }
            foreach ($record in $resolved) {
                if (Test-IpInScope -Ip $record.IPAddress -CIDRs $cidrs) {
                    $resolvedInScope = $true
                    break
                }
            }
        } catch {}

        if (-not $resolvedInScope) {
            Write-HookDecision "deny" "domain_out_of_scope:$domain" $toolName
            $msg = @{
                permission    = "deny"
                user_message  = "DOMAIN OUT OF SCOPE: '$domain' is not in authorized domains. Check scope/in-scope-domains.txt."
                agent_message = "Domain $domain is not authorized. Add it to scope/in-scope-domains.txt or engagement ROE authorized_domains."
            } | ConvertTo-Json -Compress
            Write-Output $msg
            exit 0
        }
    }
}

Write-HookDecision "allow" "in_scope" $toolName
Write-Output '{ "permission": "allow" }'
exit 0
