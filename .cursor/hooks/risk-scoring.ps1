# =============================================================================
# RISK SCORING ENGINE
# Shared module for computing risk scores on shell commands and MCP tool calls.
#
# Risk score: 0-100, composed of weighted factors:
#   Tool category   (0-35) - what kind of tool is being used
#   Target count    (0-15) - how many targets are involved
#   Privilege impact(0-20) - what privilege level is implied
#   Destructive pot.(0-20) - can it modify/destroy data or services
#   Stealth/noise   (0-10) - how detectable is this action
#
# Thresholds:
#   0-25   LOW      - allow, log normally
#   26-50  MEDIUM   - allow, log with risk level
#   51-75  HIGH     - allow, agent warned prominently
#   76-100 CRITICAL - escalate to human operator (ask permission)
# =============================================================================

$RISK_THRESHOLD_LOW      = 25
$RISK_THRESHOLD_MEDIUM   = 50
$RISK_THRESHOLD_HIGH     = 75
$RISK_THRESHOLD_CRITICAL = 76  # >= this triggers escalation

# =============================================================================
# TOOL CLASSIFICATION TABLES
# =============================================================================

$ToolCategories = @{
    # --- Exploitation (35) ---
    exploit = @(
        'msfconsole', 'msfvenom', 'metasploit',
        'psexec', 'wmiexec', 'smbexec', 'atexec', 'dcomexec',
        'eternalblue', 'shellshock', 'log4shell'
    )
    # --- Credential attacks (30) ---
    credential = @(
        'hydra', 'medusa', 'patator', 'ncrack',
        'hashcat', 'john',
        'secretsdump', 'getTGT', 'getST', 'GetNPUsers', 'GetUserSPNs',
        'mimikatz', 'pypykatz', 'kerbrute',
        'crackmapexec', 'netexec', 'cme', 'nxc',
        'responder'
    )
    # --- Session/post-exploitation (25) ---
    session = @(
        'meterpreter', 'msf_send_session_command', 'msf_run_post_module',
        'msf_terminate_session'
    )
    # --- Active scanning (15) ---
    scanning = @(
        'nmap', 'masscan', 'rustscan', 'naabu', 'unicornscan',
        'nikto', 'sqlmap', 'wpscan', 'nuclei',
        'feroxbuster', 'gobuster', 'ffuf', 'dirb', 'dirsearch',
        'testssl', 'sslscan',
        'eyewitness', 'whatweb', 'httpx'
    )
    # --- Enumeration (10) ---
    enumeration = @(
        'enum4linux', 'ldapsearch', 'rpcclient',
        'smbclient', 'smbmap',
        'snmpwalk', 'snmpget', 'snmp-check', 'onesixtyone',
        'smtp-user-enum', 'dnsrecon', 'dnsenum',
        'ssh-audit', 'ike-scan',
        'bloodhound', 'sharphound'
    )
    # --- Network utilities (8) ---
    network_util = @(
        'curl', 'wget', 'ssh', 'nc', 'ncat', 'netcat',
        'telnet', 'ftp', 'socat', 'proxychains',
        'swaks', 'openssl'
    )
    # --- Database clients (10) ---
    database = @(
        'mssqlclient', 'mysql', 'psql'
    )
}

$ToolCategoryScores = @{
    exploit      = 35
    credential   = 30
    session      = 25
    scanning     = 15
    database     = 10
    enumeration  = 10
    network_util = 8
}

# --- MCP tool risk mapping ---
$McpToolScores = @{
    msf_run_exploit           = 40
    msf_console_execute       = 35
    msf_run_post_module       = 25
    msf_send_session_command  = 25
    msf_generate_payload      = 30
    msf_session_upgrade       = 25
    msf_start_listener        = 20
    msf_run_auxiliary_module  = 15
    msf_db_nmap               = 15
    msf_db_import             = 10
    msf_terminate_session     = 10
    msf_wait_for_session      = 5
    msf_stop_job              = 5
    msf_cleanup_jobs          = 5
    msf_module_check          = 10
    msf_create_workspace      = 3
    msf_set_workspace         = 3
    msf_search_modules        = 3
    msf_module_info           = 2
    msf_host_info             = 2
    msf_service_info          = 2
    msf_vulnerability_info    = 2
    msf_note_info             = 2
    msf_credential_info       = 3
    msf_loot_info             = 2
    msf_list_active_sessions  = 2
    msf_list_listeners        = 2
    msf_list_payloads         = 3
    msf_list_workspaces       = 1
    msf_compatible_payloads   = 2
    msf_get_lab_network       = 0
    msf_console_list          = 1
    msf_status                = 0
    # Meterpreter ops
    msf_session_sysinfo       = 5
    msf_session_getuid        = 5
    msf_session_ps            = 5
    msf_session_download      = 15
    msf_session_upload        = 25
    # Route/pivot
    msf_route_list            = 2
    msf_route_add             = 15
    msf_route_delete          = 5
    msf_autoroute             = 15
    # Database write
    msf_report_host           = 5
    msf_credential_add        = 10
    msf_db_add_note           = 5
    msf_db_status             = 1
    # Module query
    msf_module_options        = 2
    msf_module_results        = 5
    msf_running_stats         = 1
    msf_list_modules          = 2
    # Extended session/handler/workspace
    msf_session_info          = 2
    msf_session_run_script    = 20
    msf_job_info              = 2
    msf_delete_workspace      = 5
}

# --- Privilege escalation indicators ---
$PrivilegeIndicators = @{
    system = @('-p windows/meterpreter', 'getsystem', 'SYSTEM', 'NT AUTHORITY',
               'exploit/windows/local', 'post/multi/recon/local_exploit_suggester',
               'post/windows/escalate', '--admin', 'sudo ', 'root',
               'eternalblue', 'ms17_010', 'ms08_067', 'exploit/windows/smb',
               'exploit/linux/', 'reverse_tcp', 'reverse_https',
               'meterpreter/')
    admin  = @('Administrator', 'admin', '-U Administrator', 'ADMIN\$',
               'post/windows/manage', 'enable_rdp', 'run_as',
               'psexec', 'wmiexec', 'smbexec', 'atexec')
}

# --- Destructive potential indicators ---
$DestructiveIndicators = @{
    high   = @('rm ', 'del ', 'format ', 'drop ', 'DELETE FROM', 'truncate',
               'wipe', 'destroy', 'kill', 'disable', 'modify',
               'write', 'upload', 'deploy', 'inject', 'implant',
               'exploit/', '; exploit', ';exploit', '-x "', 'msfvenom')
    medium = @('config', 'change', 'update', 'alter', 'create',
               'add_user', 'enable_rdp', 'firewall', 'registry')
}

# --- Noise/stealth indicators ---
$NoiseIndicators = @{
    very_high = @('-sS', '-sT', '-sU', '-p-', '-p 1-65535', '--top-ports',
                  '-A ', '-T4', '-T5', '--script', 'brute', 'fuzz')
    high      = @('-sV', '-sC', '--version-all', '-O ', 'vuln',
                  'discovery', 'spray', '--batch')
    medium    = @('-Pn', '-sn', '--open', '--min-rate', '--max-rate')
}

# =============================================================================
# SCORING FUNCTIONS
# =============================================================================

function Get-ToolCategoryScore([string]$Command) {
    $normalized = $Command.ToLower()
    foreach ($category in @('exploit', 'credential', 'session', 'scanning', 'database', 'enumeration', 'network_util')) {
        foreach ($tool in $ToolCategories[$category]) {
            if ($normalized -match "\b$([regex]::Escape($tool))\b") {
                return @{
                    Score = $ToolCategoryScores[$category]
                    Category = $category
                    MatchedTool = $tool
                }
            }
        }
    }
    return @{ Score = 0; Category = "passive"; MatchedTool = $null }
}

function Get-McpToolCategoryScore([string]$ToolName) {
    $score = 0
    if ($McpToolScores.ContainsKey($ToolName)) {
        $score = $McpToolScores[$ToolName]
    }
    $category = "passive"
    if ($score -ge 30) { $category = "exploit" }
    elseif ($score -ge 20) { $category = "session" }
    elseif ($score -ge 10) { $category = "scanning" }
    elseif ($score -ge 3) { $category = "enumeration" }
    return @{ Score = $score; Category = $category; MatchedTool = $ToolName }
}

function Get-TargetCountScore([string]$Command) {
    $ipPattern = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    $ips = @([regex]::Matches($Command, $ipPattern) | ForEach-Object { $_.Value } | Select-Object -Unique)
    $count = $ips.Count
    if ($count -ge 10) { return @{ Score = 15; Count = $count } }
    if ($count -ge 6)  { return @{ Score = 10; Count = $count } }
    if ($count -ge 2)  { return @{ Score = 5;  Count = $count } }
    return @{ Score = 0; Count = $count }
}

function Get-PrivilegeScore([string]$Command) {
    $normalized = $Command.ToLower()
    foreach ($indicator in $PrivilegeIndicators['system']) {
        if ($normalized -match [regex]::Escape($indicator.ToLower())) {
            return @{ Score = 20; Level = "system"; Indicator = $indicator }
        }
    }
    foreach ($indicator in $PrivilegeIndicators['admin']) {
        if ($normalized -match [regex]::Escape($indicator.ToLower())) {
            return @{ Score = 15; Level = "admin"; Indicator = $indicator }
        }
    }
    return @{ Score = 0; Level = "none"; Indicator = $null }
}

function Get-DestructiveScore([string]$Command) {
    $normalized = $Command.ToLower()
    foreach ($indicator in $DestructiveIndicators['high']) {
        if ($normalized -match "\b$([regex]::Escape($indicator.ToLower()))") {
            return @{ Score = 20; Level = "high"; Indicator = $indicator }
        }
    }
    foreach ($indicator in $DestructiveIndicators['medium']) {
        if ($normalized -match "\b$([regex]::Escape($indicator.ToLower()))") {
            return @{ Score = 10; Level = "medium"; Indicator = $indicator }
        }
    }
    return @{ Score = 0; Level = "none"; Indicator = $null }
}

function Get-NoiseScore([string]$Command) {
    $normalized = $Command.ToLower()
    foreach ($indicator in $NoiseIndicators['very_high']) {
        if ($normalized -match [regex]::Escape($indicator.ToLower())) {
            return @{ Score = 10; Level = "very_high"; Indicator = $indicator }
        }
    }
    foreach ($indicator in $NoiseIndicators['high']) {
        if ($normalized -match [regex]::Escape($indicator.ToLower())) {
            return @{ Score = 7; Level = "high"; Indicator = $indicator }
        }
    }
    foreach ($indicator in $NoiseIndicators['medium']) {
        if ($normalized -match [regex]::Escape($indicator.ToLower())) {
            return @{ Score = 4; Level = "medium"; Indicator = $indicator }
        }
    }
    return @{ Score = 0; Level = "low"; Indicator = $null }
}

# =============================================================================
# MAIN SCORING FUNCTION
# =============================================================================

function Get-CommandRiskScore([string]$Command) {
    $toolResult      = Get-ToolCategoryScore $Command
    $targetResult    = Get-TargetCountScore $Command
    $privResult      = Get-PrivilegeScore $Command
    $destructResult  = Get-DestructiveScore $Command
    $noiseResult     = Get-NoiseScore $Command

    $totalScore = [Math]::Min(100, (
        $toolResult.Score +
        $targetResult.Score +
        $privResult.Score +
        $destructResult.Score +
        $noiseResult.Score
    ))

    $level = "LOW"
    if ($totalScore -ge $RISK_THRESHOLD_CRITICAL) { $level = "CRITICAL" }
    elseif ($totalScore -gt $RISK_THRESHOLD_MEDIUM) { $level = "HIGH" }
    elseif ($totalScore -gt $RISK_THRESHOLD_LOW) { $level = "MEDIUM" }

    return @{
        Score = $totalScore
        Level = $level
        Escalate = ($totalScore -ge $RISK_THRESHOLD_CRITICAL)
        Breakdown = @{
            tool_category = @{
                score = $toolResult.Score
                category = $toolResult.Category
                matched = $toolResult.MatchedTool
            }
            target_count = @{
                score = $targetResult.Score
                count = $targetResult.Count
            }
            privilege = @{
                score = $privResult.Score
                level = $privResult.Level
                indicator = $privResult.Indicator
            }
            destructive = @{
                score = $destructResult.Score
                level = $destructResult.Level
                indicator = $destructResult.Indicator
            }
            noise = @{
                score = $noiseResult.Score
                level = $noiseResult.Level
                indicator = $noiseResult.Indicator
            }
        }
    }
}

function Get-McpRiskScore([string]$ToolName, [string]$ArgsJson) {
    $toolResult = Get-McpToolCategoryScore $ToolName
    $targetResult = Get-TargetCountScore $ArgsJson
    $privResult = Get-PrivilegeScore $ArgsJson
    $destructResult = Get-DestructiveScore $ArgsJson
    $noiseResult = Get-NoiseScore $ArgsJson

    $totalScore = [Math]::Min(100, (
        $toolResult.Score +
        $targetResult.Score +
        $privResult.Score +
        $destructResult.Score +
        $noiseResult.Score
    ))

    $level = "LOW"
    if ($totalScore -ge $RISK_THRESHOLD_CRITICAL) { $level = "CRITICAL" }
    elseif ($totalScore -gt $RISK_THRESHOLD_MEDIUM) { $level = "HIGH" }
    elseif ($totalScore -gt $RISK_THRESHOLD_LOW) { $level = "MEDIUM" }

    return @{
        Score = $totalScore
        Level = $level
        Escalate = ($totalScore -ge $RISK_THRESHOLD_CRITICAL)
        Breakdown = @{
            tool_category = @{
                score = $toolResult.Score
                category = $toolResult.Category
                matched = $toolResult.MatchedTool
            }
            target_count = @{
                score = $targetResult.Score
                count = $targetResult.Count
            }
            privilege = @{
                score = $privResult.Score
                level = $privResult.Level
                indicator = $privResult.Indicator
            }
            destructive = @{
                score = $destructResult.Score
                level = $destructResult.Level
                indicator = $destructResult.Indicator
            }
            noise = @{
                score = $noiseResult.Score
                level = $noiseResult.Level
                indicator = $noiseResult.Indicator
            }
        }
    }
}

function Format-RiskLabel([int]$Score, [string]$Level) {
    switch ($Level) {
        "CRITICAL" { return "CRITICAL ($Score/100)" }
        "HIGH"     { return "HIGH ($Score/100)" }
        "MEDIUM"   { return "MEDIUM ($Score/100)" }
        default    { return "LOW ($Score/100)" }
    }
}
