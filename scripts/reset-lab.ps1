# Reset lab engagement state for a clean demo.
# Usage: .\scripts\reset-lab.ps1 [-EngagementId lab-default]

param(
    [string]$EngagementId = "lab-default"
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot

Write-Host "Resetting engagement: $EngagementId" -ForegroundColor Cyan

$engDir = Join-Path $projectRoot "engagements\$EngagementId"
if (-not (Test-Path $engDir)) {
    Write-Host "Engagement directory not found: $engDir" -ForegroundColor Red
    exit 1
}

$filesToRemove = @(
    "world-state.json",
    "world-state-index.json",
    "world-state.md",
    "lhost.yaml"
)

foreach ($f in $filesToRemove) {
    $fp = Join-Path $engDir $f
    if (Test-Path $fp) {
        Remove-Item $fp -Force
        Write-Host "  Removed: engagements\$EngagementId\$f" -ForegroundColor Yellow
    }
}

$evidenceDir = Join-Path $projectRoot "evidence\msf"
if (Test-Path $evidenceDir) {
    $evidenceFiles = Get-ChildItem -Path $evidenceDir -File | Where-Object { $_.Name -ne "README.md" }
    $count = $evidenceFiles.Count
    if ($count -gt 0) {
        $evidenceFiles | Remove-Item -Force
        Write-Host "  Removed $count evidence file(s) from evidence\msf\" -ForegroundColor Yellow
    }
}

$logsDir = Join-Path $projectRoot "logs"
if (Test-Path $logsDir) {
    $logFiles = Get-ChildItem -Path $logsDir -File
    $count = $logFiles.Count
    if ($count -gt 0) {
        $logFiles | Remove-Item -Force
        Write-Host "  Removed $count log file(s) from logs\" -ForegroundColor Yellow
    }
}

Write-Host "`nReset complete. Ready for clean demo." -ForegroundColor Green
