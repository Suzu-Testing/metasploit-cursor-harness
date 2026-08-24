# Scope Files

This directory defines which targets the harness is authorized to interact with. Scope is enforced at three layers: Python ROE (server-side), Cursor hooks (pre-call), and engagement ROE YAML.

## Files

### `scope-master.txt`

Global scope file. One CIDR or IP per line.

```
# Authorized networks
10.10.10.0/24
192.168.1.0/24

# Exclusions (prefix with !)
!10.10.10.1   # gateway, do not touch
```

- Lines starting with `#` are comments
- Lines starting with `!` are exclusions (always denied even if in an authorized CIDR)
- Empty lines are ignored
- Supports individual IPs (`10.10.10.5`) and CIDRs (`10.10.10.0/24`)

### `in-scope-domains.txt`

Authorized domains for domain-based operations. One domain per line. Subdomains are automatically included.

```
example.com        # also matches sub.example.com
lab.local
```

If this file is empty or missing, domain operations are **denied by default** (fail-closed).

### `scope-details.yaml` (optional)

Extended target metadata for the lab environment. Not required for harness operation.

## Relationship to Engagement ROE

Each engagement (`engagements/<id>/roe.yaml`) can define its own `authorized_cidrs` and `authorized_domains`. These are checked **in addition to** the global scope files. A target must be in scope in both the global file and the engagement ROE.

## For New Users

If you're bringing your own targets (HTB, THM, OSCP), edit `scope-master.txt` with your target ranges. See [docs/BYO-TARGETS.md](../docs/BYO-TARGETS.md) for examples.

The shipped `scope-master.txt` contains example lab ranges. Replace them with your authorized targets before testing.
