<#
.SYNOPSIS
  One-command bootstrap for Metasploit Cursor Harness.
.DESCRIPTION
  Checks prerequisites, installs Python dependencies, configures .env and
  .cursor/mcp.json, starts msfrpcd, and validates the full setup.
  Run this once after cloning the repo.
.EXAMPLE
  .\scripts\bootstrap.ps1
#>

$ErrorActionPreference = 'Continue'
$ProjectRoot = Split-Path -Parent $PSScriptRoot

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Metasploit Cursor Harness - Bootstrap"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$failed = @()

# --- Check Python ---
Write-Host "[1/7] Checking Python..." -ForegroundColor Yellow
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    $failed += "Python 3.10+ not found. Install from https://python.org"
    Write-Host "  FAIL: Python not found" -ForegroundColor Red
} else {
    $pyVer = python --version 2>&1
    Write-Host "  OK: $pyVer" -ForegroundColor Green
}

# --- Check PowerShell 7 ---
Write-Host "[2/7] Checking PowerShell Core (pwsh)..." -ForegroundColor Yellow
$pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
if (-not $pwsh) {
    $failed += "PowerShell 7+ (pwsh) required for hooks. Install: winget install Microsoft.PowerShell"
    Write-Host "  FAIL: pwsh not found" -ForegroundColor Red
} else {
    $pwshVer = pwsh --version 2>&1
    Write-Host "  OK: $pwshVer" -ForegroundColor Green
}

# --- Check WSL ---
Write-Host "[3/7] Checking WSL..." -ForegroundColor Yellow
$wslCheck = Get-Command wsl -ErrorAction SilentlyContinue
if (-not $wslCheck) {
    $failed += "WSL not found. Install: wsl --install -d kali-linux"
    Write-Host "  FAIL: WSL not available" -ForegroundColor Red
} else {
    $distros = wsl --list --quiet 2>&1
    Write-Host "  OK: WSL available" -ForegroundColor Green
}

# --- Install Python dependencies ---
Write-Host "[4/7] Installing Python dependencies..." -ForegroundColor Yellow
Push-Location $ProjectRoot
try {
    $result = pip install -e ".[mcp]" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  OK: Dependencies installed" -ForegroundColor Green
    } else {
        $failed += "pip install failed. Check Python environment."
        Write-Host "  FAIL: pip install returned error" -ForegroundColor Red
    }
} finally {
    Pop-Location
}

# --- Configure .env ---
Write-Host "[5/7] Configuring .env..." -ForegroundColor Yellow
$envFile = Join-Path $ProjectRoot '.env'
$envExample = Join-Path $ProjectRoot '.env.example'
if (Test-Path $envFile) {
    Write-Host "  OK: .env already exists" -ForegroundColor Green
} else {
    Copy-Item $envExample $envFile
    Write-Host "  Created .env from .env.example" -ForegroundColor Green
    Write-Host ""
    Write-Host "  IMPORTANT: Set your msfrpcd password in .env" -ForegroundColor Magenta
    Write-Host "  Edit: $envFile" -ForegroundColor Magenta
    Write-Host "  Set MSF_PASSWORD to the password you'll use for msfrpcd" -ForegroundColor Magenta
    Write-Host ""
    $newPass = Read-Host "  Enter MSF_PASSWORD (or press Enter to set later)"
    if ($newPass) {
        $content = Get-Content $envFile -Raw
        $content = $content -replace 'MSF_PASSWORD=changeme', "MSF_PASSWORD=$newPass"
        Set-Content $envFile $content -NoNewline
        Write-Host "  Password set in .env" -ForegroundColor Green
    } else {
        $failed += "MSF_PASSWORD not set in .env. Edit it before starting msfrpcd."
    }
}

# --- Configure .cursor/mcp.json ---
Write-Host "[6/7] Configuring .cursor/mcp.json..." -ForegroundColor Yellow
$mcpJson = Join-Path $ProjectRoot '.cursor\mcp.json'
$mcpExample = Join-Path $ProjectRoot '.cursor\mcp.json.example'
if (Test-Path $mcpJson) {
    Write-Host "  OK: .cursor/mcp.json already exists" -ForegroundColor Green
} else {
    $escapedPath = $ProjectRoot -replace '\\', '/'
    $mcpContent = @"
{
  "mcpServers": {
    "msf-harness": {
      "command": "python",
      "args": ["-m", "msf_harness.mcp.server"],
      "cwd": "$escapedPath",
      "env": {
        "PYTHONPATH": "$escapedPath",
        "MSF_HOST": "127.0.0.1",
        "MSF_PORT": "55553",
        "MSF_SSL": "false",
        "MSF_USER": "msf"
      }
    }
  }
}
"@
    Set-Content $mcpJson $mcpContent -Encoding UTF8
    Write-Host "  Created .cursor/mcp.json with paths:" -ForegroundColor Green
    Write-Host "    cwd: $escapedPath" -ForegroundColor DarkGray
}

# --- Create logs directory ---
$logsDir = Join-Path $ProjectRoot 'logs'
if (-not (Test-Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir | Out-Null
}

# --- Run doctor ---
Write-Host "[7/7] Running health check..." -ForegroundColor Yellow
Write-Host ""
python (Join-Path $ProjectRoot 'scripts\doctor.py')

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan

if ($failed.Count -gt 0) {
    Write-Host "  Setup completed with issues:" -ForegroundColor Yellow
    Write-Host ""
    foreach ($f in $failed) {
        Write-Host "  - $f" -ForegroundColor Red
    }
} else {
    Write-Host "  Setup complete!" -ForegroundColor Green
}

Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Cyan
Write-Host "    1. Start msfrpcd:       .\scripts\start-msfrpcd.ps1"
Write-Host "    2. Start lab targets:   .\scripts\start-lab-targets.ps1"
Write-Host "    3. Enable MCP server:   Cursor > Settings > MCP > toggle msf-harness ON"
Write-Host "    4. Verify in chat:      msf_status"
Write-Host ""
Write-Host "  Full workflow demo:       python scripts\demo-workflow.py"
Write-Host "==========================================" -ForegroundColor Cyan
