<#
.SYNOPSIS
  Start msfdb and msfrpcd in WSL using credentials from .env
.DESCRIPTION
  Reads MSF_USER and MSF_PASSWORD from the project .env file,
  starts the Metasploit database, then launches msfrpcd on 127.0.0.1:55553.
  Verifies the port is listening before exiting.
#>

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot

# Parse .env
$envFile = Join-Path $projectRoot '.env'
if (-not (Test-Path $envFile)) {
    Write-Error ".env file not found at $envFile. Copy .env.example and fill in credentials."
    exit 1
}

$envVars = @{}
Get-Content $envFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith('#') -and $line.Contains('=')) {
        $parts = $line -split '=', 2
        $envVars[$parts[0].Trim()] = $parts[1].Trim().Trim('"').Trim("'")
    }
}

$user = $envVars['MSF_USER']
$pass = $envVars['MSF_PASSWORD']
$rpcHost = if ($envVars['MSF_HOST']) { $envVars['MSF_HOST'] } else { '127.0.0.1' }
$port = if ($envVars['MSF_PORT']) { $envVars['MSF_PORT'] } else { '55553' }

if (-not $user -or -not $pass) {
    Write-Error "MSF_USER and MSF_PASSWORD must be set in .env"
    exit 1
}

Write-Host "Starting msfdb..."
wsl -e bash -lc "sudo msfdb start 2>&1"

Write-Host "Checking for existing msfrpcd on port $port..."
$existing = wsl -e bash -lc "ss -tlnp 2>/dev/null | grep $port"
if ($existing) {
    Write-Host "msfrpcd already listening on $port"
} else {
    Write-Host "Starting msfrpcd (user=$user, host=$rpcHost, port=$port, no SSL)..."
    wsl -e bash -lc "msfrpcd -U $user -P $pass -S -a $rpcHost -p $port 2>&1"
    Start-Sleep -Seconds 3
}

$check = wsl -e bash -lc "ss -tlnp 2>/dev/null | grep $port"
if ($check) {
    Write-Host "msfrpcd is listening on ${rpcHost}:${port}"
} else {
    Write-Error "msfrpcd failed to start on ${rpcHost}:${port}"
    exit 1
}
