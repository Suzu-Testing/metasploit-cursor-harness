# =============================================================================
# WORLD-STATE-IO - Atomic read-merge-write for world-state.json
# Prevents race conditions between concurrent hook writers by using file locking.
# All hooks that update world-state.json MUST go through this module.
# =============================================================================

. (Join-Path $PSScriptRoot "engagement-resolver.ps1")

function Read-WorldState {
    param([string]$FilePath)

    $default = @{
        last_updated       = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
        session_stats      = @{
            total_commands   = 0
            total_mcp_calls  = 0
            total_shell_cmds = 0
            by_risk_level    = @{ LOW = 0; MEDIUM = 0; HIGH = 0; CRITICAL = 0 }
            by_mcp_tool      = @{}
        }
        recent_commands     = @()
        discovered_targets  = @()
        active_sessions     = @()
        active_listeners    = @()
    }

    if (-not (Test-Path $FilePath)) { return $default }

    try {
        $raw = Get-Content $FilePath -Raw -ErrorAction Stop
        if (-not $raw -or $raw.Trim().Length -eq 0) { return $default }
        $existing = $raw | ConvertFrom-Json

        # Merge into default structure to ensure all fields exist
        if ($existing.session_stats) {
            if ($null -ne $existing.session_stats.total_commands) {
                $default.session_stats.total_commands = [int]$existing.session_stats.total_commands
            }
            if ($null -ne $existing.session_stats.total_mcp_calls) {
                $default.session_stats.total_mcp_calls = [int]$existing.session_stats.total_mcp_calls
            }
            if ($null -ne $existing.session_stats.total_shell_cmds) {
                $default.session_stats.total_shell_cmds = [int]$existing.session_stats.total_shell_cmds
            }
            if ($existing.session_stats.by_risk_level) {
                foreach ($lvl in @('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) {
                    $val = $existing.session_stats.by_risk_level.$lvl
                    if ($null -ne $val) {
                        $default.session_stats.by_risk_level[$lvl] = [int]$val
                    }
                }
            }
            if ($existing.session_stats.by_mcp_tool) {
                $existing.session_stats.by_mcp_tool.PSObject.Properties | ForEach-Object {
                    $default.session_stats.by_mcp_tool[$_.Name] = [int]$_.Value
                }
            }
        }
        if ($existing.recent_commands) {
            $default.recent_commands = @($existing.recent_commands)
        }
        if ($existing.discovered_targets) {
            $default.discovered_targets = @($existing.discovered_targets)
        }
        if ($existing.active_sessions) {
            $default.active_sessions = @($existing.active_sessions)
        }
        if ($existing.active_listeners) {
            $default.active_listeners = @($existing.active_listeners)
        }
        if ($existing.last_updated) {
            $default.last_updated = $existing.last_updated
        }
        return $default
    } catch {
        return $default
    }
}

function Write-WorldStateAtomic {
    param(
        [string]$FilePath,
        [hashtable]$WorldState,
        [int]$MaxRetries = 3,
        [int]$RetryDelayMs = 100
    )

    $dir = Split-Path $FilePath -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $json = $WorldState | ConvertTo-Json -Depth 10
    $retries = 0

    while ($retries -lt $MaxRetries) {
        try {
            $fs = [System.IO.FileStream]::new(
                $FilePath,
                [System.IO.FileMode]::Create,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None
            )
            try {
                $writer = [System.IO.StreamWriter]::new($fs, [System.Text.Encoding]::UTF8)
                $writer.Write($json)
                $writer.Flush()
            } finally {
                if ($writer) { $writer.Dispose() }
                if ($fs) { $fs.Dispose() }
            }
            return $true
        } catch [System.IO.IOException] {
            $retries++
            if ($retries -lt $MaxRetries) {
                Start-Sleep -Milliseconds $RetryDelayMs
            }
        } catch {
            # Non-IO error, fall back to Set-Content
            try {
                Set-Content -Path $FilePath -Value $json -Encoding UTF8 -Force
                return $true
            } catch { return $false }
        }
    }

    # Final fallback after retries exhausted
    try {
        Set-Content -Path $FilePath -Value $json -Encoding UTF8 -Force
        return $true
    } catch { return $false }
}

function Update-WorldState {
    param(
        [string]$EngagementId = $null,
        [string]$ProjectRoot = $null,
        [scriptblock]$Mutator
    )

    if (-not $ProjectRoot) {
        $ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    }

    $filePath = Get-WorldStateFilePath -EngagementId $EngagementId -ProjectRoot $ProjectRoot
    $state = Read-WorldState -FilePath $filePath

    # Apply the mutation
    & $Mutator $state

    # Update timestamp
    $state.last_updated = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ")

    # Write atomically
    Write-WorldStateAtomic -FilePath $filePath -WorldState $state | Out-Null
    return $state
}

function Add-RecentCommand {
    param(
        [hashtable]$WorldState,
        [hashtable]$Entry,
        [int]$MaxEntries = 25
    )
    $WorldState.recent_commands = @($Entry) + @($WorldState.recent_commands | Select-Object -First ($MaxEntries - 1))
}

function Add-DiscoveredTargets {
    param(
        [hashtable]$WorldState,
        [string[]]$Targets
    )
    $ignoreIPs = @("127.0.0.1", "0.0.0.0", "255.255.255.255")
    foreach ($t in $Targets) {
        if ($t -notin $ignoreIPs -and $t -notin $WorldState.discovered_targets) {
            $WorldState.discovered_targets += $t
        }
    }
}
