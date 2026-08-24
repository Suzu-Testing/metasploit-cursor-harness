# =============================================================================
# HOOK SYSTEM INTEGRATION TEST
# Runs both unit tests (shared modules) and gate tests (full hook piping).
# This is the single entry point for validating the entire hook system.
#
# Usage:
#   pwsh -ExecutionPolicy Bypass -File scripts/test-hooks.ps1
#   pwsh -ExecutionPolicy Bypass -File scripts/test-hooks.ps1 -Verbose
#   pwsh -ExecutionPolicy Bypass -File scripts/test-hooks.ps1 -Suite unit
#   pwsh -ExecutionPolicy Bypass -File scripts/test-hooks.ps1 -Suite gate
# =============================================================================

param(
    [ValidateSet("all", "unit", "gate")]
    [string]$Suite = "all",
    [switch]$Verbose
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testDir = Join-Path $projectRoot "tests\hooks"
$hooksDir = Join-Path $projectRoot ".cursor\hooks"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  METASPLOIT CURSOR HARNESS - Hook Tests" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Project: $projectRoot"
Write-Host "Hooks:   $hooksDir"
Write-Host "Suite:   $Suite"
Write-Host ""

# --- Pre-flight: check all hook files exist ---
Write-Host "--- Pre-flight checks ---" -ForegroundColor Yellow
$requiredHooks = @(
    "scope-common.ps1", "engagement-resolver.ps1", "input-parser.ps1",
    "world-state-io.ps1", "risk-scoring.ps1", "credential-filter.ps1",
    "scope-check.ps1", "mcp-action-gate.ps1", "dangerous-command-gate.ps1",
    "risk-gate.ps1", "rate-limit-gate.ps1", "world-state-gate.ps1",
    "evidence-logger.ps1", "mcp-evidence-logger.ps1", "world-state-logger.ps1",
    "session-context.ps1", "stop-checklist.ps1", "world-state-common.ps1"
)
$missingHooks = @()
foreach ($hook in $requiredHooks) {
    if (-not (Test-Path (Join-Path $hooksDir $hook))) {
        $missingHooks += $hook
    }
}
if ($missingHooks.Count -gt 0) {
    Write-Host "  FAIL: Missing hook files:" -ForegroundColor Red
    foreach ($m in $missingHooks) { Write-Host "    - $m" -ForegroundColor Red }
    exit 1
}
Write-Host "  All $($requiredHooks.Count) hook files present." -ForegroundColor Green

# Check hooks.json (lives at .cursor/hooks.json, not inside hooks/ subfolder)
$hooksJson = Join-Path $projectRoot ".cursor\hooks.json"
if (-not (Test-Path $hooksJson)) {
    Write-Host "  FAIL: hooks.json not found" -ForegroundColor Red
    exit 1
}
try {
    Get-Content $hooksJson -Raw | ConvertFrom-Json | Out-Null
    Write-Host "  hooks.json is valid JSON." -ForegroundColor Green
} catch {
    Write-Host "  FAIL: hooks.json is invalid JSON" -ForegroundColor Red
    exit 1
}

# Check scope file
$scopeFile = Join-Path $projectRoot "scope\scope-master.txt"
if (-not (Test-Path $scopeFile)) {
    Write-Host "  WARNING: scope/scope-master.txt not found (gate tests may fail)" -ForegroundColor Yellow
} else {
    $scopeLines = (Get-Content $scopeFile | Where-Object { $_ -and $_ -notmatch '^\s*#' }).Count
    Write-Host "  Scope file: $scopeLines entries." -ForegroundColor Green
}

# Check engagement directory
$engDir = Join-Path $projectRoot "engagements\lab-default"
if (-not (Test-Path $engDir)) {
    Write-Host "  WARNING: engagements/lab-default not found" -ForegroundColor Yellow
} else {
    Write-Host "  Default engagement present." -ForegroundColor Green
}

Write-Host ""

# --- Syntax validation for all hooks ---
Write-Host "--- Syntax validation ---" -ForegroundColor Yellow
$syntaxErrors = 0
foreach ($hook in $requiredHooks) {
    $hookPath = Join-Path $hooksDir $hook
    $parseResult = & powershell -ExecutionPolicy Bypass -Command "
        `$null = [System.Management.Automation.Language.Parser]::ParseFile('$hookPath', [ref]`$null, [ref]`$null)
        if (`$?) { 'OK' } else { 'FAIL' }
    " 2>&1
    $parseStr = ($parseResult | Out-String).Trim()
    if ($parseStr -ne "OK") {
        Write-Host "  SYNTAX ERROR: $hook" -ForegroundColor Red
        $syntaxErrors++
    }
}
if ($syntaxErrors -eq 0) {
    Write-Host "  All $($requiredHooks.Count) hooks pass syntax check." -ForegroundColor Green
} else {
    Write-Host "  $syntaxErrors hook(s) have syntax errors!" -ForegroundColor Red
    exit 1
}
Write-Host ""

# --- Run test suites ---
$totalPass = 0
$totalFail = 0

if ($Suite -eq "all" -or $Suite -eq "unit") {
    Write-Host "--- Shared Module Unit Tests ---" -ForegroundColor Yellow
    $unitArgs = @("-ExecutionPolicy", "Bypass", "-File", (Join-Path $testDir "Test-SharedModules.ps1"))
    if ($Verbose) { $unitArgs += "-Verbose" }
    & powershell @unitArgs
    if ($LASTEXITCODE -ne 0) { $totalFail++ } else { $totalPass++ }
    Write-Host ""
}

if ($Suite -eq "all" -or $Suite -eq "gate") {
    Write-Host "--- Hook Gate Integration Tests ---" -ForegroundColor Yellow
    $gateArgs = @("-ExecutionPolicy", "Bypass", "-File", (Join-Path $testDir "Test-HookGates.ps1"))
    if ($Verbose) { $gateArgs += "-Verbose" }
    & powershell @gateArgs
    if ($LASTEXITCODE -ne 0) { $totalFail++ } else { $totalPass++ }
    Write-Host ""
}

# --- Summary ---
Write-Host "============================================" -ForegroundColor Cyan
if ($totalFail -eq 0) {
    Write-Host "  ALL SUITES PASSED" -ForegroundColor Green
} else {
    Write-Host "  $totalFail SUITE(S) FAILED" -ForegroundColor Red
}
Write-Host "============================================" -ForegroundColor Cyan

exit $totalFail
