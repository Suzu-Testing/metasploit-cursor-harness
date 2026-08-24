# Pull and start vulnerable Docker lab targets for Metasploit harness testing.
# Metasploitable2 is managed separately (already running as container "metasploitable2").

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$ComposeFile = Join-Path $ProjectRoot "lab\docker-compose.yml"

Write-Host "=== Metasploit Lab Targets ===" -ForegroundColor Cyan
Write-Host "Project: $ProjectRoot"
Write-Host ""

# Check Docker
try {
    docker info | Out-Null
} catch {
    Write-Error "Docker is not running. Start Docker Desktop and retry."
    exit 1
}

# Metasploitable2 status
Write-Host "--- Metasploitable2 ---" -ForegroundColor Yellow
$ms2 = docker ps -a --filter "name=metasploitable2" --format "{{.Names}}|{{.Status}}|{{.Image}}"
if ($ms2) {
    Write-Host "  $ms2"
} else {
    Write-Host "  Not found. Pull and start with:" -ForegroundColor DarkYellow
    Write-Host '  docker run -d --name metasploitable2 --restart unless-stopped \'
    Write-Host '    -p 9021:21 -p 9022:22 -p 9023:23 -p 9025:25 -p 9080:80 \'
    Write-Host '    -p 9139:139 -p 9445:445 -p 9099:1099 -p 9524:1524 -p 9121:2121 \'
    Write-Host '    -p 9306:3306 -p 9632:3632 -p 9432:5432 -p 9900:5900 \'
    Write-Host '    -p 6200:6200 -p 9667:6667 -p 9787:8787 \'
    Write-Host '    tleemcjr/metasploitable2:latest'
}

Write-Host ""
Write-Host "--- Pulling lab images ---" -ForegroundColor Yellow
docker compose -f $ComposeFile pull

Write-Host ""
Write-Host "--- Starting lab stack ---" -ForegroundColor Yellow
docker compose -f $ComposeFile up -d

Write-Host ""
Write-Host "--- Running containers ---" -ForegroundColor Green
docker ps --filter "name=lab-" --filter "name=metasploitable2" --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"

Write-Host ""
Write-Host "=== Access from WSL (RHOST=10.255.255.254) ===" -ForegroundColor Cyan
Write-Host "  Metasploitable2 FTP:    10.255.255.254:9021  (vsftpd backdoor)"
Write-Host "  Metasploitable2 HTTP:   10.255.255.254:9080"
Write-Host "  Metasploitable2 SMB:    10.255.255.254:9445"
Write-Host "  Metasploitable2 IRC:    10.255.255.254:9667  (UnrealIRCd backdoor)"
Write-Host "  DVWA:                   10.255.255.254:9100  (login: admin / password)"
Write-Host "  Tomcat 8.5.19:          10.255.255.254:9101  (CVE-2017-12615)"
Write-Host "  Struts2 2.3.31:         10.255.255.254:9102  (CVE-2017-5638 S2-045)"
Write-Host "  WordPress 4.6:          10.255.255.254:9103"
Write-Host "  Redis 4.0.14:           10.255.255.254:9137  (no auth)"
Write-Host "  Samba 4.6.3:            10.255.255.254:9145  (CVE-2017-7494 SambaCry)"
Write-Host ""
Write-Host "Run msf_get_lab_network MCP tool for full port map." -ForegroundColor DarkGray
