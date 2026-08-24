# Setup Guide

Detailed instructions for setting up the Metasploit Cursor Harness on Windows with WSL.

## Requirements

- **Windows 10/11** with WSL2
- **Python 3.10+** (Windows or WSL)
- **Cursor IDE** with MCP support
- **Metasploit Framework** installed in WSL/Kali Linux
- **PostgreSQL** (bundled with Metasploit's `msfdb`)

## Step 1: Install WSL and Kali Linux

If you don't have WSL set up:

```powershell
wsl --install -d kali-linux
```

Inside Kali, install Metasploit:

```bash
sudo apt update
sudo apt install metasploit-framework -y
```

## Step 2: Clone the Harness

```powershell
git clone https://github.com/Suzu-Testing/metasploit-cursor-harness.git
cd metasploit-cursor-harness
```

## Step 3: Install Python Dependencies

```powershell
pip install -e ".[mcp]"
```

This installs:
- `pymetasploit3` for RPC communication
- `mcp[cli]` (FastMCP) for the MCP server
- `pyyaml` for configuration parsing

For development:

```powershell
pip install -e ".[mcp,dev]"
```

## Step 4: Configure Environment

```powershell
copy .env.example .env
```

Edit `.env` and set at minimum:

```
MSF_PASSWORD=your_msfrpcd_password
```

Optional variables:

```
MSF_HOST=127.0.0.1
MSF_PORT=55553
MSF_USER=msf
MSF_SSL=false
MSF_LOG_LEVEL=INFO
```

## Step 5: Start Metasploit RPC

Option A: Use the provided script:

```powershell
.\scripts\start-msfrpcd.ps1
```

Option B: Manual start:

```powershell
wsl -e bash -lc "msfdb start; msfrpcd -U msf -P your_password -S -a 127.0.0.1 -p 55553"
```

The `-S` flag disables SSL (required for `MSF_SSL=false`). The daemon binds to `127.0.0.1:55553`.

## Step 6: Configure Cursor MCP

**Option A: Run the bootstrap script** (handles this automatically):

```powershell
.\scripts\bootstrap.ps1
```

**Option B: Manual setup:**

```powershell
copy .cursor\mcp.json.example .cursor\mcp.json
```

Edit `.cursor/mcp.json` to set **absolute** paths for `cwd` and `PYTHONPATH` (Cursor resolves these relative to its own binary, not the workspace, so absolute paths are required):

```json
{
  "mcpServers": {
    "msf-harness": {
      "command": "python",
      "args": ["-m", "msf_harness.mcp.server"],
      "cwd": "C:/path/to/metasploit-cursor-harness",
      "env": {
        "PYTHONPATH": "C:/path/to/metasploit-cursor-harness",
        "MSF_HOST": "127.0.0.1",
        "MSF_PORT": "55553",
        "MSF_SSL": "false",
        "MSF_USER": "msf"
      }
    }
  }
}
```

Replace `C:/path/to/metasploit-cursor-harness` with your actual clone path (use forward slashes).

The MCP server reads `MSF_PASSWORD` from the project-root `.env` file at startup, so it does not need to be in `mcp.json`.

Then in Cursor: **Settings > MCP** and toggle **msf-harness** on.

## Step 7: Define Scope

Add authorized targets to `scope/scope-master.txt`:

```
# Lab target (Docker Metasploitable2)
10.255.255.254/32

# Exclusions (prefix with !)
!192.168.1.1
```

Add authorized domains to `scope/in-scope-domains.txt`:

```
# Authorized domains
example.lab
target.local
```

## Step 8: Create an Engagement

```powershell
python scripts/create-engagement.py --name my-engagement
```

This creates `engagements/my-engagement/` with a `roe.yaml` from the template.

## Step 9: Verify

Use `msf_status` in Cursor to verify the connection:

```
msf_status()
```

You should see Metasploit version info and session count.

## Safety Hooks Pipeline

The harness includes an 18-script PowerShell safety pipeline that loads automatically when you open the project in Cursor. These hooks are configured in `.cursor/hooks.json` and enforce defense-in-depth alongside the Python ROE layer.

### Hook Events

| Event | Hooks | Purpose |
|-------|-------|---------|
| `sessionStart` | `session-context.ps1` | Inject scope/engagement context into new sessions |
| `beforeShell` | `risk-gate.ps1`, `scope-check.ps1`, `dangerous-command-gate.ps1`, `world-state-gate.ps1` | Risk scoring, scope enforcement, destructive command blocking, duplicate detection |
| `beforeMCP` | `risk-gate.ps1`, `mcp-action-gate.ps1`, `world-state-gate.ps1` | ROE + scope enforcement for MCP tool calls, duplicate detection |
| `afterShell/MCP` | `evidence-logger.ps1`, `mcp-evidence-logger.ps1`, `world-state-logger.ps1` | Audit trail, evidence files, world state updates |
| `stop` | `stop-checklist.ps1` | Cleanup and risk summary |

### How It Works

1. **Before every MCP tool call**, `mcp-action-gate.ps1` extracts target IPs from tool arguments and validates them against `scope/scope-master.txt`
2. **Risk scoring** (`risk-scoring.ps1`) assigns a risk level to each operation and can prompt for confirmation on high-risk actions
3. **After each call**, `mcp-evidence-logger.ps1` saves tool results to `evidence/msf/` and updates the command ledger
4. **World state tracking** prevents duplicate operations via `world-state-gate.ps1`

### Relationship to Python ROE

The hooks provide a secondary enforcement layer. The Python ROE in `msf_harness/mcp/policy/roe.py` is the primary gate and runs server-side on every action tool call. The hooks add:
- Shell command scope enforcement (Python ROE only covers MCP tools)
- Risk scoring and interactive confirmation prompts
- Automated evidence capture and audit logging
- World-state tracking for duplicate detection

Both layers must pass for an operation to proceed.

## Troubleshooting

### "Cannot connect to msfrpcd"

1. Verify msfrpcd is running: `wsl -e bash -lc "ss -tlnp | grep 55553"`
2. Check firewall rules
3. Verify password matches between `.env` and `msfrpcd` startup

### "MSF_PASSWORD is not set"

Set the password in `.env` or as an environment variable.

### Module operations fail

Ensure `msfdb` is running: `wsl -e bash -lc "msfdb start"`

### MCP server doesn't appear in Cursor

1. Confirm `.cursor/mcp.json` has correct absolute paths
2. Restart Cursor
3. Check MCP server logs in the Cursor output panel
