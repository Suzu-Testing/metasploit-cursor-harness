# =============================================================================
# SCOPE-COMMON - Shared scope validation module
# Provides CIDR matching, scope loading, exclusion checks, and domain validation
# used by scope-check.ps1, mcp-action-gate.ps1, and other enforcement hooks.
# =============================================================================

function Get-ProjectRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

function Get-ScopeFile {
    return (Join-Path (Get-ProjectRoot) "scope\scope-master.txt")
}

function Get-DomainFile {
    return (Join-Path (Get-ProjectRoot) "scope\in-scope-domains.txt")
}

function Get-ScopeCIDRs {
    $scopeFile = Get-ScopeFile
    $cidrs = @()
    if (Test-Path $scopeFile) {
        Get-Content $scopeFile | ForEach-Object {
            $line = $_.Trim()
            if ($line -and $line -notmatch '^\s*#' -and $line -notmatch '^\s*!') {
                $entry = ($line -replace '\s*#.*$', '').Trim()
                if ($entry) { $cidrs += $entry }
            }
        }
    }
    return $cidrs
}

function Get-ScopeExclusions {
    $scopeFile = Get-ScopeFile
    $excluded = @()
    if (Test-Path $scopeFile) {
        Get-Content $scopeFile | Where-Object { $_ -match '^\s*!' } | ForEach-Object {
            $ip = ($_ -replace '^\s*!', '' -replace '\s*#.*$', '').Trim()
            if ($ip) { $excluded += $ip }
        }
    }
    return $excluded
}

function Get-ScopeDomains {
    $domainFile = Get-DomainFile
    $domains = @()
    if (Test-Path $domainFile) {
        Get-Content $domainFile | ForEach-Object {
            $line = ($_ -replace '\s*#.*$', '').Trim().ToLower()
            if ($line -and $line -match '^[a-z]') { $domains += $line }
        }
    }
    return $domains
}

function Test-IpInCidr {
    param([string]$Ip, [string]$Cidr)
    try {
        if ($Cidr -match '/') {
            $parts = $Cidr -split '/'
            $netAddr = [System.Net.IPAddress]::Parse($parts[0])
            $maskLen = [int]$parts[1]
            $targetAddr = [System.Net.IPAddress]::Parse($Ip)
            $netBytes = $netAddr.GetAddressBytes()
            $targetBytes = $targetAddr.GetAddressBytes()
            [Array]::Reverse($netBytes)
            [Array]::Reverse($targetBytes)
            $netInt = [BitConverter]::ToUInt32($netBytes, 0)
            $targetInt = [BitConverter]::ToUInt32($targetBytes, 0)
            $mask = ([uint32]::MaxValue) -shl (32 - $maskLen)
            return (($netInt -band $mask) -eq ($targetInt -band $mask))
        } else {
            return ($Ip -eq $Cidr.Trim())
        }
    } catch { return $false }
}

function Test-IpInScope {
    param(
        [string]$Ip,
        [string[]]$CIDRs = $null
    )
    if (-not $CIDRs) { $CIDRs = Get-ScopeCIDRs }
    if (-not $CIDRs -or $CIDRs.Count -eq 0) { return $false }
    foreach ($cidr in $CIDRs) {
        if (Test-IpInCidr -Ip $Ip -Cidr $cidr) { return $true }
    }
    return $false
}

function Test-IpExcluded {
    param(
        [string]$Ip,
        [string[]]$Exclusions = $null
    )
    if (-not $Exclusions) { $Exclusions = Get-ScopeExclusions }
    foreach ($excl in $Exclusions) {
        if ($Ip.Trim() -eq $excl.Trim()) { return $true }
    }
    return $false
}

function Test-DomainInScope {
    param(
        [string]$Domain,
        [string[]]$AuthorizedDomains = $null
    )
    if (-not $AuthorizedDomains) { $AuthorizedDomains = Get-ScopeDomains }
    if (-not $AuthorizedDomains -or $AuthorizedDomains.Count -eq 0) { return $false }
    $domainLower = $Domain.Trim().ToLower()
    foreach ($auth in $AuthorizedDomains) {
        if ($domainLower -eq $auth -or $domainLower.EndsWith(".$auth")) {
            return $true
        }
    }
    return $false
}

function Test-CidrWidth {
    param(
        [string]$Target,
        [int]$MaxPrefix = 24
    )
    if ($Target -match '/(\d{1,2})$') {
        $prefix = [int]$Matches[1]
        if ($prefix -lt $MaxPrefix) {
            return @{
                Violation = $true
                Prefix = $prefix
                MaxPrefix = $MaxPrefix
                Message = "CIDR /$prefix is broader than the allowed max /$MaxPrefix. Narrow the scan target."
            }
        }
    }
    return @{ Violation = $false }
}

function Get-MaxScanCidr {
    param([string]$EngagementId = $null)
    $maxScanCidr = 24
    $root = Get-ProjectRoot
    if (-not $EngagementId) { return $maxScanCidr }
    $roeYaml = Join-Path $root "engagements\$EngagementId\roe.yaml"
    if (Test-Path $roeYaml) {
        $content = Get-Content $roeYaml -Raw -ErrorAction SilentlyContinue
        if ($content -match 'max_scan_cidr:\s*(\d+)') {
            $maxScanCidr = [int]$Matches[1]
        }
    }
    return $maxScanCidr
}

function Extract-IpsFromText {
    param([string]$Text)
    $ipPattern = '\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    return @([regex]::Matches($Text, $ipPattern) | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
}

function Extract-DomainsFromText {
    param([string]$Text)
    $domains = @()
    $urlPattern = 'https?://([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)'
    $urlMatches = [regex]::Matches($Text, $urlPattern)
    foreach ($m in $urlMatches) {
        $extracted = $m.Groups[1].Value.ToLower()
        if ($extracted -notmatch '^\d+\.\d+\.\d+\.\d+$') {
            $domains += $extracted
        }
    }
    $flagPattern = '(?:--?(?:host|target|domain|url|vhost|server))\s+(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)'
    $flagMatches = [regex]::Matches($Text, $flagPattern)
    foreach ($m in $flagMatches) {
        $extracted = $m.Groups[1].Value.ToLower()
        if ($extracted -notmatch '^\d+\.\d+\.\d+\.\d+$') {
            $domains += $extracted
        }
    }
    return @($domains | Select-Object -Unique)
}

function Get-CommandHash {
    param([string]$Command, [int]$Length = 16)
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Command)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hb = $sha.ComputeHash($bytes)
        $full = ($hb | ForEach-Object { $_.ToString("x2") }) -join ''
        return $full.Substring(0, [Math]::Min($Length, $full.Length))
    } catch { return "err" }
}
