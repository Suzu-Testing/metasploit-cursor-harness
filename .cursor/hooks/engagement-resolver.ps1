# =============================================================================
# ENGAGEMENT-RESOLVER - Unified engagement ID resolution
# Single source of truth for determining the active engagement across all hooks.
#
# Resolution priority:
#   1. Explicit MCP argument (engagement_id from tool args)
#   2. Environment variable ($env:MSF_ENGAGEMENT_ID)
#   3. Most recently modified engagement directory (excludes _template, catalogs)
#   4. Fallback: "lab-default"
# =============================================================================

function Resolve-EngagementId {
    param(
        [string]$McpEngagementArg = $null,
        [string]$ProjectRoot = $null
    )

    if (-not $ProjectRoot) {
        $ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    }

    $engagementsDir = Join-Path $ProjectRoot "engagements"

    # Priority 1: Explicit MCP argument
    if ($McpEngagementArg -and $McpEngagementArg -ne "catalogs" -and $McpEngagementArg -ne "_template") {
        $engPath = Join-Path $engagementsDir $McpEngagementArg
        if (Test-Path $engPath) {
            return $McpEngagementArg
        }
    }

    # Priority 2: Environment variable
    if ($env:MSF_ENGAGEMENT_ID) {
        $engPath = Join-Path $engagementsDir $env:MSF_ENGAGEMENT_ID
        if (Test-Path $engPath) {
            return $env:MSF_ENGAGEMENT_ID
        }
    }

    # Priority 3: Most recently modified engagement directory
    try {
        $latest = Get-ChildItem -Path $engagementsDir -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne "_template" -and $_.Name -ne "catalogs" } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($latest) {
            return $latest.Name
        }
    } catch {}

    # Priority 4: Fallback
    return "lab-default"
}

function Get-EngagementDir {
    param(
        [string]$EngagementId = $null,
        [string]$ProjectRoot = $null
    )
    if (-not $ProjectRoot) {
        $ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    }
    if (-not $EngagementId) {
        $EngagementId = Resolve-EngagementId -ProjectRoot $ProjectRoot
    }
    $dir = Join-Path $ProjectRoot "engagements\$EngagementId"
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    return $dir
}

function Get-WorldStateFilePath {
    param(
        [string]$EngagementId = $null,
        [string]$ProjectRoot = $null
    )
    $engDir = Get-EngagementDir -EngagementId $EngagementId -ProjectRoot $ProjectRoot
    return (Join-Path $engDir "world-state.json")
}

function Extract-EngagementIdFromMcpArgs {
    param($ArgsObject)
    if (-not $ArgsObject) { return $null }
    try {
        if ($ArgsObject -is [string]) {
            $parsed = $ArgsObject | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($parsed.engagement_id) { return [string]$parsed.engagement_id }
        } elseif ($ArgsObject.engagement_id) {
            return [string]$ArgsObject.engagement_id
        }
    } catch {}
    return $null
}
