# Security Policy

## Authorized Use Only

This tool is designed exclusively for authorized penetration testing and security research. Use it only on systems you have explicit written permission to test. Unauthorized access to computer systems is illegal.

## Vulnerability Reporting

If you discover a security vulnerability in this harness (such as an ROE bypass, scope enforcement failure, or command injection), please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Report via [GitHub Security Advisories](https://github.com/Suzu-Testing/metasploit-cursor-harness/security/advisories/new) or email security@suzulabs.com
3. Include steps to reproduce and potential impact

We aim to acknowledge reports within 48 hours and issue fixes within 7 days for critical issues.

## Security Architecture

The harness enforces safety through multiple layers:

| Layer | Mechanism | Scope |
|-------|-----------|-------|
| Server-side ROE | `msf_harness/mcp/policy/roe.py` | CIDR validation, domain auth, module blocking, session limits, exploit gates |
| Console parsing | `msf_harness/mcp/tools/console_tools.py` | Extract and validate targets/modules from raw msfconsole commands |
| File restrictions | `workspace_tools.py`, `payload_tools.py` | Restrict imports/exports to `evidence/` and `engagements/` |
| Input sanitization | `rpc/console.py` | Option key validation, quote escaping for console commands |
| Cursor hooks | `.cursor/hooks/` | Scope gates, risk scoring, evidence logging |

## Secret Handling

- **Never commit** `.env` files, Metasploit passwords, or API keys
- The `.gitignore` excludes `.env`, `logs/`, `evidence/`, and engagement-specific files
- `MSF_PASSWORD` should be set as an environment variable or in a local `.env` file
- Review `git diff --staged` before every commit to verify no secrets are included

## Scope Enforcement

- All targets must be listed in `scope/scope-master.txt`
- IPs prefixed with `!` are hard-excluded and cannot be targeted
- Domains must be in `scope/in-scope-domains.txt` or the engagement's `authorized_domains`
- CIDR scan width is capped per engagement ROE (default /24)
- `auxiliary/dos/*` modules are unconditionally blocked
- `msf_console_execute` parses commands for targets and modules before execution

## Known Limitations

- Console command parsing uses regex-based extraction; complex msfconsole scripting may bypass target detection
- The harness trusts msfrpcd responses; a compromised RPC daemon could return misleading data
- Hook enforcement depends on Cursor's hook execution; direct MCP calls outside Cursor bypass hooks
