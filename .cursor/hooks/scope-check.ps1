# =============================================================================
# SCOPE CHECK HOOK
# Validates shell commands against scope/scope-master.txt, scope/in-scope-domains.txt,
# and scope exclusions before allowing execution.
#
# Enforcement layers:
#   1. Extracts IPs and hostnames from the command
#   2. Validates IPs against authorized CIDRs and exclusion list
#   3. Validates hostnames against domain list + DNS resolution to scope IPs
#   4. Blocks broad CIDRs (wider than max_scan_cidr) and target-file flags (-iL)
#   5. Logs every decision to logs/hook-audit.log
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
    try { Write-ParseDebug "scope-check" "TRAP: $($_.Exception.Message)" } catch {}
    # Fail closed: deny on unhandled errors in scope checking
    Write-Output '{ "permission": "deny", "user_message": "Scope check encountered an internal error (fail-closed).", "agent_message": "Hook internal error in scope-check. Check logs/hook-debug.log." }'
    exit 0
}

# --- Audit logging ---
function Write-HookDecision($decision, $reason, $cmd) {
    $ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    $cmdHash = Get-CommandHash -Command $cmd -Length 12
    $line = "$ts | hook=scope-check | decision=$decision | reason=$reason | cmd_hash=$cmdHash"
    try { Add-Content -Path $hookLog -Value $line } catch {}
}

# --- Read and parse input ---
$rawInput = Read-HookStdin
$parsed = Parse-HookInput -RawInput $rawInput -HookName "scope-check"

$command = $null
if ($parsed.Success) {
    $command = Extract-ShellCommand -ParsedData $parsed.ParsedData -HookName "scope-check"
} else {
    $command = Extract-ShellCommand -RawInput $rawInput -HookName "scope-check"
}

if (-not $command) {
    Write-HookDecision "allow" "no_command_parsed" "N/A"
    Write-Output '{ "permission": "allow" }'
    exit 0
}

# =============================================================================
# LOAD SCOPE FILES
# =============================================================================

$scopeFile = Get-ScopeFile
$domainFile = Get-DomainFile

if (-not (Test-Path $scopeFile)) {
    Write-HookDecision "deny" "scope_file_missing" $command
    Write-Output '{ "permission": "deny", "user_message": "SCOPE FILE MISSING: scope/scope-master.txt not found. Cannot verify scope.", "agent_message": "The scope file scope/scope-master.txt is missing. Create it before running commands." }'
    exit 0
}

$scopeEntries = Get-ScopeCIDRs
$exclusions = Get-ScopeExclusions

if ($scopeEntries.Count -eq 0) {
    Write-HookDecision "deny" "scope_file_empty" $command
    Write-Output '{ "permission": "deny", "user_message": "SCOPE FILE EMPTY: No CIDRs in scope/scope-master.txt.", "agent_message": "scope/scope-master.txt has no authorized targets. Add CIDRs or IPs before running network commands." }'
    exit 0
}

$scopeDomains = Get-ScopeDomains

# =============================================================================
# ALLOWLISTS - things that look like targets but aren't
# =============================================================================

$toolNameAllowlist = @(
    'testssl.sh', 'ssh-audit', 'nikto.pl', 'feroxbuster', 'gobuster',
    'enum4linux.pl', 'smtp-user-enum.pl', 'ike-scan', 'dnsrecon.py',
    'wpscan', 'nuclei', 'httpx', 'subfinder', 'amass', 'eyewitness',
    'crackmapexec', 'impacket', 'responder', 'bloodhound', 'sharphound'
)

$safeTestDomains = @(
    'example.com', 'example.org', 'example.net',
    'test.com', 'test.org', 'test.net',
    'google.com', 'google.org',
    'evil.com', 'attacker.com',
    'localhost', 'test.local', 'nxdomain.invalid'
)

$dnsChaosNames = @(
    'version.bind', 'hostname.bind', 'authors.bind',
    'version.server', 'hostname.server', 'id.server'
)

$execExtensions = '\.(exe|sh|pl|py|rb|ps1|psm1|bat|cmd|msi|jar|vbs|js|cgi|bin|elf|out|appimage|deb|rpm|txt|csv|json|yaml|yml|md|log)$'

# =============================================================================
# LOCAL-ONLY COMMAND DETECTION
# =============================================================================

function Test-IsLocalDevCommand($cmd) {
    if ($cmd -match '(?:^|[;&\s])python(\s+(-c|-m)|\s+\S+\.py|\s+scripts/)') { return $true }
    if ($cmd -match 'python\s+-c\s') { return $true }
    if ($cmd -match '(?:^|[;&\s])py(\s|$|-)') { return $true }
    if ($cmd -match '(?:^|[;&\s])(pip|npm|node|pytest)(\s|$)') { return $true }
    if ($cmd -match '(gate-check|test-roe|search-kb|complete-subgate|world-state|mvp-|msf-integration)\.py') { return $true }
    if ($cmd -match '(?:^|[;&\s])scope-check\.ps1|mcp-action-gate\.ps1|mcp-evidence-logger\.ps1') { return $true }
    if ($cmd -match 'msf_harness[\\/]mcp[\\/]|enforce_roe|validate_target|load_roe|Test-IpInScope') { return $true }
    return $false
}

if (Test-IsLocalDevCommand $command) {
    Write-HookDecision "allow" "local_dev_command" $command
    Write-Output '{ "permission": "allow" }'
    exit 0
}

# Well-known reference IPs
$referenceIPs = @(
    '127.0.0.1', '0.0.0.0', '255.255.255.255',
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
    '1.2.3.4', '192.0.2.1', '198.51.100.1', '203.0.113.1'
)

# Code-like tokens that look like hostnames
$codeLikeHostnamePattern = '^(mod|self|os|sys|json|yaml|client|c|mod\.|\.join|print|import|from|def|class|return|for|in|if|else|elif|while|try|except|with|as|not|and|or|true|false|null|none)\.'

function Test-LooksLikeRealHostname($hostname) {
    if (-not $hostname) { return $false }
    if ($hostname -match '[\\''"\(\)\[\]{}]|\\n|\\t') { return $false }
    if ($hostname -match $codeLikeHostnamePattern) { return $false }
    $parts = $hostname.Split('.')
    if ($parts.Count -lt 2) { return $false }
    $tld = $parts[$parts.Count - 1]
    if ($tld -notmatch '^[a-z]{2,24}$') { return $false }
    $fakeTlds = @(
        'payloads', 'payload', 'options', 'runoptions', 'modules', 'module',
        'join', 'split', 'strip', 'lower', 'upper', 'format', 'append',
        'extend', 'items', 'keys', 'values', 'get', 'set', 'call', 'execute',
        'client', 'server', 'path', 'file', 'read', 'write', 'load', 'dump',
        'list', 'dict', 'str', 'int', 'float', 'bool', 'type', 'name',
        'groups', 'match', 'search', 'find', 'replace', 'encode', 'decode',
        'py', 'pyc', 'pyo', 'whl', 'egg', 'cfg', 'ini', 'toml', 'lock'
    )
    if ($tld -in $fakeTlds) { return $false }
    foreach ($part in $parts) {
        if ($part -match '^\d+$') { return $false }
        if ($part.Length -lt 1) { return $false }
    }
    return $true
}

# =============================================================================
# PASSIVE COMMAND DETECTION
# =============================================================================

$passivePatterns = @(
    '^\s*whois\b',
    '^\s*wsl\s+whois\b',
    '^\s*searchsploit\b',
    '^\s*wsl\s+searchsploit\b',
    '^\s*(type|more|dir|cd|pwd|Write-Host|Write-Output|Get-Content|Get-ChildItem|Get-Item|Test-Path|New-Item|Copy-Item|Move-Item|Rename-Item|Remove-Item)\b',
    '^\s*git\b',
    '^\s*mkdir\b',
    '^\s*jq\b',
    '^\s*wsl\s+jq\b',
    '^\s*wsl\s+(cat|grep|awk|sed|sort|uniq|wc|head|tail|less|find|ls|chmod|chown)\b',
    '^\s*(echo|Write-)\s',
    '^\s*head\s',
    '^\s*tail\s',
    '^\s*rg\s',
    '^\s*Select-String\b'
)

# =============================================================================
# NETWORK INTENT DETECTION
# =============================================================================

$networkIntentPatterns = @(
    '(?:^|[;&\|\s])(nmap|masscan|rustscan|naabu|unicornscan)\b',
    '(?:^|[;&\|\s])(nikto|feroxbuster|gobuster|ffuf|dirb|dirsearch|wpscan|nuclei|httpx|eyewitness|whatweb)\b',
    '(?:^|[;&\|\s])(msfconsole|msfvenom)\b', 'metasploit\b',
    '(?:^|[;&\|\s])(curl|wget|ssh|nc|ncat|netcat|telnet|socat|proxychains)\b',
    '(?:^|[;&\|\s])ftp\s', '(?:^|[;&\|\s])ftp\b',
    '(?:^|[;&\|\s])(hydra|medusa|patator|crackmapexec|ncrack|hashcat|john)\b',
    'impacket\b', 'secretsdump\b', 'psexec\b', 'wmiexec\b', 'smbexec\b',
    'atexec\b', 'dcomexec\b', 'getTGT\b', 'getST\b', 'GetNPUsers\b',
    'GetUserSPNs\b', 'bloodhound\b', 'ldapsearch\b', 'rpcclient\b',
    'smbclient\b', 'smbmap\b', 'enum4linux\b',
    '(?:^|[;&\|\s])(sqlmap|mssqlclient|mysql|psql)\b',
    '(?:^|[;&\|\s])dig\s', '(?:^|[;&\|\s])nslookup\b', '(?:^|[;&\|\s])host\s',
    'dnsrecon\b', 'dnsenum\b',
    'testssl\b', 'sslscan\b', 'openssl\s+s_client',
    'onesixtyone\b', 'snmpwalk\b', 'snmpget\b', 'snmp-check\b',
    'smtp-user-enum\b', 'swaks\b',
    'ike-scan\b', 'ssh-audit\b',
    'requests\.(get|post|put|delete)', 'urllib', '-connect\b', '--url\b',
    '-u\s+https?://', 'Invoke-WebRequest\b', 'Invoke-RestMethod\b',
    'Test-NetConnection\b', 'Test-Connection\b',
    'netexec\b', 'cme\b', 'nxc\b'
)

$hasNetworkIntent = $false
foreach ($nip in $networkIntentPatterns) {
    if ($command -match $nip) {
        $hasNetworkIntent = $true
        break
    }
}

if (-not $hasNetworkIntent) {
    foreach ($pat in $passivePatterns) {
        if ($command -match $pat) {
            Write-HookDecision "allow" "passive_command" $command
            Write-Output '{ "permission": "allow" }'
            exit 0
        }
    }
}

# =============================================================================
# EXTRACT TARGETS FROM COMMAND
# =============================================================================

# --- Extract IPv4 addresses ---
$ipPattern = '\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
$foundIPs = @([regex]::Matches($command, $ipPattern) | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)

if (-not $hasNetworkIntent) {
    $foundIPs = @($foundIPs | Where-Object { $_ -notin $referenceIPs })
}

# --- Extract hostnames/FQDNs ---
$foundHostnames = @()

# From URLs
$urlPattern = 'https?://([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)'
$urlMatches = [regex]::Matches($command, $urlPattern)
foreach ($m in $urlMatches) {
    $extracted = $m.Groups[1].Value.ToLower()
    if ($extracted -match '^\d+\.\d+\.\d+\.\d+$') { continue }
    $foundHostnames += $extracted
}

# From common tool flags
$flagHostPattern = '(?:-[uhH]|--url|--host|--target|-connect|-server)\s+(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)'
$flagMatches = [regex]::Matches($command, $flagHostPattern)
foreach ($m in $flagMatches) {
    $foundHostnames += $m.Groups[1].Value.ToLower()
}

# From DNS @server notation
$dnsAtPattern = '@\s*([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)'
$dnsMatches = [regex]::Matches($command, $dnsAtPattern)
foreach ($m in $dnsMatches) {
    $foundHostnames += $m.Groups[1].Value.ToLower()
}

# Bare hostname tokens when network intent is detected
if ($hasNetworkIntent) {
    $tokens = $command -split '\s+'
    foreach ($tok in $tokens) {
        $clean = $tok -replace '[\[\]{}()"''\\]', '' -replace ':(\d+)$', '' -replace '/$', ''
        $clean = $clean -replace '^https?://', ''
        if ($clean -match '^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$') {
            if ($clean -notmatch '^\d+\.\d+\.\d+\.\d+$') {
                $foundHostnames += $clean.ToLower()
            }
        }
    }
}

# Deduplicate and filter
$foundHostnames = @($foundHostnames | Select-Object -Unique | Where-Object {
    $_ -and $_.Length -gt 3 -and
    (Test-LooksLikeRealHostname $_) -and
    ($_ -notin $toolNameAllowlist) -and
    ($_ -notin $safeTestDomains) -and
    ($_ -notin $dnsChaosNames) -and
    ($_ -notmatch '^\d+\.\d+\.\d+\.\d+$') -and
    ($_ -notmatch $execExtensions)
})

# =============================================================================
# SPECIAL CASE: target file flags (-iL for nmap, etc.)
# =============================================================================

if ($command -match '-iL\s+(\S+)') {
    $targetFile = $Matches[1]
    Write-HookDecision "ask" "target_file_iL" $command
    $result = @{
        permission    = "ask"
        user_message  = "SCOPE CHECK: Command uses target file '$targetFile'. Verify all IPs/hosts in that file are in scope before allowing."
        agent_message = "The command references a target file via -iL. Manually verify its contents are in scope."
    } | ConvertTo-Json -Compress
    Write-Output $result
    exit 0
}

# =============================================================================
# SPECIAL CASE: broad CIDR notation
# =============================================================================

$engagementId = Resolve-EngagementId -ProjectRoot $projectRoot
$maxScanCidr = Get-MaxScanCidr -EngagementId $engagementId

if ($command -match '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/(\d{1,2})\b') {
    $prefix = [int]$Matches[1]
    if ($prefix -lt $maxScanCidr) {
        Write-HookDecision "deny" "broad_cidr:/$prefix" $command
        $result = @{
            permission    = "deny"
            user_message  = "BLOCKED: CIDR /$prefix is broader than the maximum allowed /$maxScanCidr. Use specific IPs or narrower ranges."
            agent_message = "CIDR notation broader than /$maxScanCidr is prohibited. Specify individual IPs from scope/scope-master.txt."
        } | ConvertTo-Json -Compress
        Write-Output $result
        exit 0
    }
}

# No identifiable targets
if ($foundIPs.Count -eq 0 -and $foundHostnames.Count -eq 0) {
    Write-HookDecision "allow" "no_target_identified" $command
    Write-Output '{ "permission": "allow" }'
    exit 0
}

# =============================================================================
# VALIDATE IPs
# =============================================================================

$localIPs = @("127.0.0.1", "0.0.0.0")
$outOfScopeIPs = @()
$excludedIPs = @()

foreach ($ip in $foundIPs) {
    if ($ip -in $localIPs) { continue }

    # Validate octets
    $octets = $ip.Split('.')
    $valid = $true
    foreach ($o in $octets) {
        if ([int]$o -gt 255) { $valid = $false; break }
    }
    if (-not $valid) { continue }

    if (Test-IpExcluded -Ip $ip -Exclusions $exclusions) {
        $excludedIPs += $ip
        continue
    }

    if (-not (Test-IpInScope -Ip $ip -CIDRs $scopeEntries)) {
        $outOfScopeIPs += $ip
    }
}

# =============================================================================
# VALIDATE HOSTNAMES
# =============================================================================

$outOfScopeHostnames = @()

foreach ($hostname in $foundHostnames) {
    # Skip safe test domains (including subdomains)
    $isSafe = $false
    foreach ($safeDomain in $safeTestDomains) {
        if ($hostname -eq $safeDomain -or $hostname.EndsWith(".$safeDomain")) {
            $isSafe = $true
            break
        }
    }
    if ($isSafe) { continue }

    # Check against in-scope domain list
    if (Test-DomainInScope -Domain $hostname -AuthorizedDomains $scopeDomains) { continue }

    # Try DNS resolution and check if resolved IP is in scope
    try {
        $resolved = Resolve-DnsName -Name $hostname -Type A -DnsOnly -ErrorAction Stop | Where-Object { $_.QueryType -eq 'A' }
        $resolvedInScope = $false
        foreach ($record in $resolved) {
            if (Test-IpInScope -Ip $record.IPAddress -CIDRs $scopeEntries) {
                $resolvedInScope = $true
                break
            }
        }
        if ($resolvedInScope) { continue }
    } catch { }

    $outOfScopeHostnames += $hostname
}

# =============================================================================
# BUILD RESPONSE
# =============================================================================

if ($excludedIPs.Count -gt 0) {
    $detail = "Excluded IP(s): $($excludedIPs -join ', ')"
    Write-HookDecision "deny" "excluded:$detail" $command
    $result = @{
        permission    = "deny"
        user_message  = "EXCLUDED TARGET: $detail. These IPs are explicitly excluded in scope/scope-master.txt (prefixed with !)."
        agent_message = "Target(s) $detail are on the exclusion list. Do not target these IPs under any circumstances."
    } | ConvertTo-Json -Compress
    Write-Output $result
    exit 0
}

if ($outOfScopeIPs.Count -gt 0 -or $outOfScopeHostnames.Count -gt 0) {
    $parts = @()
    if ($outOfScopeIPs.Count -gt 0) { $parts += "IP(s): $($outOfScopeIPs -join ', ')" }
    if ($outOfScopeHostnames.Count -gt 0) { $parts += "Hostname(s): $($outOfScopeHostnames -join ', ')" }
    $detail = $parts -join '; '
    Write-HookDecision "ask" "out_of_scope:$detail" $command
    $result = @{
        permission    = "ask"
        user_message  = "SCOPE VIOLATION: Out-of-scope targets detected: $detail. Check scope/scope-master.txt and scope/in-scope-domains.txt."
        agent_message = "Hook flagged out-of-scope targets: $detail. Verify authorization before proceeding."
    } | ConvertTo-Json -Compress
    Write-Output $result
    exit 0
}

Write-HookDecision "allow" "in_scope" $command
Write-Output '{ "permission": "allow" }'
exit 0
