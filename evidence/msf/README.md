# Evidence Directory

This directory stores MCP tool outputs and pentest artifacts captured during engagements.

## Naming Convention

| Pattern | Source | Example |
|---------|--------|---------|
| `{timestamp}-{tool}.json` | MCP evidence hook (auto) | `20260727-151805-msf_search_modules.json` |
| `{timestamp}-payload-{name}.{format}` | `msf_generate_payload` (auto) | `20260727-152000-payload-linux_x86_shell_reverse_tcp.raw` |
| `recon-{host}-{date}.json` | msf-recon workflow (manual) | `recon-10.10.0.20-20260727.json` |
| `review-{module}-{date}.json` | G4 reviewer gate (manual) | `review-vsftpd-20260727.json` |

## Security

All files in this directory are gitignored by default. Do not commit pentest evidence to version control.
Engagement-specific evidence should be archived and delivered per the engagement's reporting requirements.
