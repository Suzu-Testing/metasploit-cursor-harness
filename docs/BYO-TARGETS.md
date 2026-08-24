# Bring Your Own Targets

Use this guide when testing against HackTheBox, TryHackMe, OSCP/PWK labs, local VMs, or client networks instead of the built-in Docker lab (`lab-default`).

Scope is enforced in three places that must agree:

| Layer | File |
|-------|------|
| Global scope | `scope/scope-master.txt` |
| Domains | `scope/in-scope-domains.txt` |
| Engagement ROE | `engagements/<id>/roe.yaml` |

Every destructive MCP call requires an `engagement_id`. Create one engagement per lab platform or client.

## Quick Start

```powershell
# 1. Edit scope/scope-master.txt and scope/in-scope-domains.txt
# 2. Create engagement
python scripts/create-engagement.py --name htb-platform --cidrs 10.129.0.0/16
# 3. Edit engagements/htb-platform/roe.yaml
# 4. Gate check
python .cursor/skills/pentest-workflow/scripts/gate-check.py htb-platform
# 5. Verify: msf_status, then ping target from WSL
```

---

## MSF vs VPN Placement

| Component | Location |
|-----------|----------|
| Cursor + MCP | Windows |
| `msfrpcd` | WSL/Kali on `127.0.0.1:55553` |
| HTB/THM VPN | Windows or WSL |

**VPN routing is the #1 failure.** WSL2 does not inherit Windows VPN routes. Fix options:

1. **Run VPN inside WSL** (recommended)
2. **WSL mirrored networking** (Win 11 23H2+): `networkingMode=mirrored` in `.wslconfig`
3. **Native Kali VM** with VPN + MSF; point MCP RPC at the VM

**LHOST:** Use your `tun0` IP (e.g. `10.10.14.5`), not WSL `eth0`. Confirm with `ip addr show tun0`.

---

## Scope Format

`scope/scope-master.txt`:

```
10.129.123.45/32        # single host
10.129.0.0/16           # range
!10.129.50.1            # exclusion
```

`scope/in-scope-domains.txt` (subdomains inherit):

```
machine.htb
app.client.com
```

---

## 1. HackTheBox

IPs: `10.10.10.0/24` (legacy) or `10.129.0.0/16` (current). VPN on `tun0` gives you `10.10.14.x` or `10.129.x.x`.

**Scope strategy:** `/32` per active box (tightest), `/16` for regular use, or `/24` if you know the subnet.

**scope-master.txt:**

```
10.129.0.0/16
!10.10.14.0/24
```

**in-scope-domains.txt:** `# machine-name.htb` (add when spawned)

**Create engagement:**

```powershell
python scripts/create-engagement.py --name htb-labyrinth --cidrs 10.129.123.45/32
python scripts/create-engagement.py --name htb-platform --cidrs 10.129.0.0/16
```

**roe.yaml:** `max_sessions: 3`, `max_scan_cidr: 24` (blocks scanning all of /16). Scan `/32` or `/24`, not `/16`.

**Gotchas:** Spawn box before scanning. WSL needs VPN-in-WSL or mirrored mode. HTB ToS prohibits broad scanning.

---

## 2. TryHackMe

Same VPN mechanics as HTB. IPs are room-specific, commonly `10.10.x.x` or `10.200.x.x` (check room banner).

**scope-master.txt:** `10.10.45.0/24` (adjust to room range)

**Create engagement:**

```powershell
python scripts/create-engagement.py --name thm-basic-pentesting --cidrs 10.10.45.0/24
```

**roe.yaml:** Template defaults work. `max_scan_cidr: 24` fits room-sized subnets.

**Gotchas:** Read room banner for exact range. Use local WSL MSF, not THM's browser AttackBox. Redeployed rooms may get new IPs.

---

## 3. OSCP / PWK Labs

Multi-subnet labs with pivoting (`192.168.49-51.0/24`, `192.168.102.0/24`, etc.).

**scope-master.txt:**

```
192.168.49.0/24
192.168.50.0/24
192.168.51.0/24
192.168.102.0/24
!192.168.49.1
```

**Create engagement:**

```powershell
python scripts/create-engagement.py --name oscp-lab --cidrs 192.168.49.0/24,192.168.50.0/24,192.168.51.0/24,192.168.102.0/24
```

**roe.yaml:** `max_sessions: 5`, `max_scan_cidr: 24`. Add pivoted subnets to scope before routing.

**Pivoting:** `msf_route_add` / `msf_autoroute` after internal compromise. Each subnet must be in `scope-master.txt` and `authorized_cidrs`. Scan one `/24` at a time.

**Gotchas:** Lab reset changes IPs. Session limit enforced at 5; kill stale sessions. Keep `max_scan_cidr` at 24.

---

## 4. Custom VMs (VulnHub, Local Lab)

| Layout | Access |
|--------|--------|
| Bridged | Direct to VM LAN IP |
| Host-only | Add hypervisor subnet to scope |
| NAT | Usually blocked; use bridged |

**scope-master.txt:**

```
192.168.56.101/32
192.168.56.0/24
```

**Create engagement:**

```powershell
python scripts/create-engagement.py --name vulnhub-vulnix --cidrs 192.168.56.101/32
```

**roe.yaml:** Defaults fine. Add `authorized_domains: [vuln.local]` if using local DNS.

**Gotchas:** Docker-on-Windows targets need `10.255.255.254` from WSL (see `docs/LAB.md`). Test LHOST with a listener first. Snapshot VMs before exploits.

---

## 5. External / Real Engagements

Tightest scope. Use `--type external`.

**scope-master.txt:**

```
203.0.113.50/32
203.0.113.51/32
!203.0.113.1
```

**in-scope-domains.txt:** `app.client.com`, `api.client.com`

**Create engagement:**

```powershell
python scripts/create-engagement.py --name client-acme-2026 --type external --cidrs 203.0.113.50/32,203.0.113.51/32
```

**roe.yaml (strict):**

```yaml
engagement_type: external
max_sessions: 2
max_scan_cidr: 32
require_check_before_exploit: true
credential_spray_approval_required: true
authorized_domains: [app.client.com]
excluded_ips: [203.0.113.1]
forbidden_module_prefixes: [auxiliary/dos/]
```

**Gotchas:** Out-of-scope is hard-blocked. No CDN ranges. Evidence in `evidence/msf/` may contain client data.

---

## ROE Reference

| Field | Template | lab-default | Notes |
|-------|----------|-------------|-------|
| `max_sessions` | 5 | 5 | Concurrent session cap |
| `max_scan_cidr` | 24 | 29 | Min prefix for scans; 24 = up to /24, 32 = single IP only |
| `require_check_before_exploit` | true | true | Run `msf_module_check` first |

---

## Common Gotchas

1. IP must be in both `scope-master.txt` and `roe.yaml` `authorized_cidrs`
2. Action tools require `engagement_id`
3. WSL must route to target (VPN placement)
4. Scans broader than `max_scan_cidr` are rejected
5. `require_check_before_exploit` blocks exploits without prior check
6. Create new engagement when switching platforms
7. Domains need both `in-scope-domains.txt` and `authorized_domains`

---

## Related Docs

- [SETUP.md](SETUP.md) - WSL, RPC, MCP
- [LAB.md](LAB.md) - Docker Metasploitable2 lab
- `engagements/_template/roe.yaml` - Full template
