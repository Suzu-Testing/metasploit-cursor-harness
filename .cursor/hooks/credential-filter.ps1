# =============================================================================
# CREDENTIAL-FILTER - Redacts sensitive credential data from evidence output
# Prevents passwords, hashes, tokens, and keys from being written to evidence
# files in cleartext. Called by evidence-logger and mcp-evidence-logger.
#
# Usage: $redacted = Invoke-CredentialFilter -Text $rawOutput
# =============================================================================

$script:CredentialPatterns = @(
    # NTLM hashes (LM:NT format)
    @{ Pattern = '([a-fA-F0-9]{32}:[a-fA-F0-9]{32})'; Replacement = '[NTLM_HASH_REDACTED]'; Name = 'NTLM' }

    # NTLMv2 challenge-response (long hex after username)
    @{ Pattern = '([A-Za-z0-9_\-\\]+::\S+:[a-fA-F0-9]{16,})'; Replacement = '[NTLMv2_RESPONSE_REDACTED]'; Name = 'NTLMv2' }

    # Unix shadow file hashes ($1$, $5$, $6$, $y$, $2a$, $2b$)
    @{ Pattern = '(\$(?:1|2[aby]?|5|6|y)\$[^\s:]{8,}\$[^\s:]+)'; Replacement = '[UNIX_HASH_REDACTED]'; Name = 'UnixHash' }

    # AWS Access Keys
    @{ Pattern = '(AKIA[0-9A-Z]{16})'; Replacement = '[AWS_KEY_REDACTED]'; Name = 'AWSKey' }

    # AWS Secret Keys (40-char base64-ish after known prefixes)
    @{ Pattern = '(?i)(aws_secret_access_key|secret_?key)\s*[=:]\s*([A-Za-z0-9/+=]{40})'; Replacement = '$1=[AWS_SECRET_REDACTED]'; Name = 'AWSSecret' }

    # Generic password assignments (PASSWORD=..., password: ..., -p ...)
    @{ Pattern = '(?i)(password|passwd|pwd|pass)\s*[=:]\s*[''"]?([^\s''"]{4,})[''"]?'; Replacement = '$1=[PASSWORD_REDACTED]'; Name = 'PasswordAssign' }

    # MSF creds format: password => value
    @{ Pattern = '(?i)(password)\s*=>\s*([^\s,}]+)'; Replacement = '$1 => [REDACTED]'; Name = 'MsfCred' }

    # Private key blocks
    @{ Pattern = '(-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----)[\s\S]*?(-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----)'; Replacement = '[PRIVATE_KEY_REDACTED]'; Name = 'PrivateKey' }

    # Bearer tokens
    @{ Pattern = '(?i)(Bearer\s+)([A-Za-z0-9\-._~+/]+=*)'; Replacement = '$1[TOKEN_REDACTED]'; Name = 'Bearer' }

    # API key patterns (api_key=, apikey:, x-api-key:)
    @{ Pattern = '(?i)(api[_-]?key|x-api-key)\s*[=:]\s*[''"]?([A-Za-z0-9\-._]{16,})[''"]?'; Replacement = '$1=[API_KEY_REDACTED]'; Name = 'ApiKey' }

    # Kerberos tickets (base64 kirbi)
    @{ Pattern = '(doI[A-Za-z0-9+/=]{100,})'; Replacement = '[KERBEROS_TICKET_REDACTED]'; Name = 'Kerberos' }

    # Session tokens / cookies with sensitive names
    @{ Pattern = '(?i)(session_?token|session_?id|auth_?token|csrf_?token|jwt)\s*[=:]\s*([A-Za-z0-9\-._~+/]{20,})'; Replacement = '$1=[SESSION_REDACTED]'; Name = 'SessionToken' }

    # SAM dump hashes (username:RID:LMHash:NTHash:::)
    @{ Pattern = '([^\s:]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::)'; Replacement = '[SAM_HASH_REDACTED]'; Name = 'SAMDump' }

    # Kerberoasting hashes ($krb5tgs$)
    @{ Pattern = '(\$krb5tgs\$[^\s]+)'; Replacement = '[KERBEROS_HASH_REDACTED]'; Name = 'Kerberoast' }

    # AS-REP roasting hashes ($krb5asrep$)
    @{ Pattern = '(\$krb5asrep\$[^\s]+)'; Replacement = '[ASREP_HASH_REDACTED]'; Name = 'ASREPRoast' }
)

function Invoke-CredentialFilter {
    param(
        [string]$Text,
        [switch]$ReturnStats
    )

    if (-not $Text -or $Text.Length -eq 0) {
        if ($ReturnStats) { return @{ Text = ""; RedactionCount = 0; Types = @() } }
        return ""
    }

    $redactionCount = 0
    $typesFound = @()
    $result = $Text

    foreach ($rule in $script:CredentialPatterns) {
        $matches = [regex]::Matches($result, $rule.Pattern)
        if ($matches.Count -gt 0) {
            $redactionCount += $matches.Count
            $typesFound += $rule.Name
            $result = [regex]::Replace($result, $rule.Pattern, $rule.Replacement)
        }
    }

    if ($ReturnStats) {
        return @{
            Text = $result
            RedactionCount = $redactionCount
            Types = $typesFound
        }
    }
    return $result
}

function Test-ContainsCredentials {
    param([string]$Text)

    if (-not $Text -or $Text.Length -eq 0) { return $false }

    foreach ($rule in $script:CredentialPatterns) {
        if ($Text -match $rule.Pattern) { return $true }
    }
    return $false
}
