# Cursor Hook System

The hook system provides multi-layered safety enforcement for all shell and MCP tool executions in the harness. Every action goes through preflight gates before execution and postflight loggers after completion.

## Architecture

```
                  +------------------+
  stdin (JSON) -->| Preflight Gates  |--> { permission: allow|deny|ask }
                  +------------------+
                          |
            +---------+---+---+---------+
            |         |       |         |
        scope-    mcp-action  risk-   rate-limit
        check     gate        gate    gate
            |         |       |         |
            +----+----+---+---+---------+
                 |            |
                 v            v
          +------------+ +---------+
          | Execution  | | Blocked |
          +------------+ +---------+
                 |
                 v
          +------------------+
          | Postflight Hooks |--> evidence files, ledger, world-state
          +------------------+
```

## Hook Files (18)

### Shared Modules (6)
| File | Purpose |
|------|---------|
| `scope-common.ps1` | CIDR math, scope parsing, IP/domain validation, command hashing |
| `engagement-resolver.ps1` | Unified engagement ID resolution (MCP arg > env > latest > fallback) |
| `input-parser.ps1` | Robust JSON input parsing with regex fallback for malformed input |
| `world-state-io.ps1` | Atomic read-merge-write for world-state.json with file locking |
| `risk-scoring.ps1` | Risk calculation for shell commands and MCP tools (0-100 scale) |
| `credential-filter.ps1` | Redacts passwords, hashes, tokens, and keys from evidence output |

### Preflight Gates (6)
| File | Trigger | Decision |
|------|---------|----------|
| `scope-check.ps1` | beforeShell | Validates IPs/domains are in authorized CIDRs |
| `mcp-action-gate.ps1` | beforeMCP | Validates targets, CIDR width, module paths, domains |
| `dangerous-command-gate.ps1` | beforeShell | Blocks DoS tools, wipers, exfiltration; asks for risky ops |
| `risk-gate.ps1` | beforeShell/MCP | Scores risk 0-100, warns on HIGH, blocks CRITICAL |
| `rate-limit-gate.ps1` | beforeShell/MCP | Cooldown for repeated high-risk identical actions |
| `world-state-gate.ps1` | beforeShell/MCP | Detects duplicate actions already performed |

### Postflight Loggers (3)
| File | Trigger | Purpose |
|------|---------|---------|
| `evidence-logger.ps1` | afterShell | Records shell commands to ledger, updates world state |
| `mcp-evidence-logger.ps1` | afterMCP | Records MCP calls to ledger, saves evidence, tracks sessions |
| `world-state-logger.ps1` | afterShell/MCP | Writes actions to world-state.md via Python bridge |

### Session Lifecycle (2)
| File | Trigger | Purpose |
|------|---------|---------|
| `session-context.ps1` | sessionStart | Loads scope/engagement context, runs health checks |
| `stop-checklist.ps1` | stop | End-of-session summary and cleanup |

### Legacy/Bridge (1)
| File | Purpose |
|------|---------|
| `world-state-common.ps1` | Helper functions for world-state Python script bridge |

## Hook Input/Output Protocol

All hooks receive JSON on stdin and must output JSON to stdout.

### Preflight (beforeShell/beforeMCP)

**Input:**
```json
{
  "command": "nmap -sV 10.10.0.20",
  "toolName": "msf_run_exploit",
  "arguments": { "module_path": "...", "options": { "RHOSTS": "..." } }
}
```

**Output (one of):**
```json
{"permission": "allow"}
{"permission": "deny", "user_message": "...", "agent_message": "..."}
{"permission": "ask", "user_message": "...", "agent_message": "..."}
```

### Postflight (afterShell/afterMCP)

**Input:**
```json
{
  "command": "...",
  "exit_code": 0,
  "output": "...",
  "toolName": "...",
  "arguments": {...},
  "result": {...}
}
```

**Output:** `{}` (empty object, no permission required)

## Error Handling

All hooks use `$ErrorActionPreference = 'Stop'` with a `trap` block. On unhandled errors:
- Preflight gates **fail closed** (output `{"permission":"deny"}`)
- Postflight loggers **fail open** (output `{}`, errors logged but not blocking)

## Testing

Run the full hook test suite:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/test-hooks.ps1
```

Run with verbose output:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/test-hooks.ps1 -Verbose
```

Run only unit tests (shared modules):
```powershell
powershell -ExecutionPolicy Bypass -File scripts/test-hooks.ps1 -Suite unit
```

Run only gate tests (full hook piping):
```powershell
powershell -ExecutionPolicy Bypass -File scripts/test-hooks.ps1 -Suite gate
```

## Adding a New Hook

1. Create the `.ps1` file in `.cursor/hooks/`
2. Import shared modules at the top (scope-common, input-parser, etc.)
3. Use `$ErrorActionPreference = 'Stop'` with a `trap` block
4. Register in `.cursor/hooks.json` with appropriate matchers
5. Add the hook to `session-context.ps1` health check list
6. Add test cases to `tests/hooks/Test-HookGates.ps1`
7. Update this README

## Adding Risk Scoring for a New MCP Tool

1. Add the tool name and score to `$McpToolScores` in `risk-scoring.ps1`
2. Add it to `$actionableTools` in `mcp-evidence-logger.ps1` if it should save evidence
3. Add matchers in `hooks.json` for beforeMCP/afterMCP if needed
4. Run `scripts/test-hooks.ps1` to verify

## Credential Filter

Evidence files are automatically filtered for sensitive data before writing:
- NTLM hashes (LM:NT format)
- Unix shadow hashes ($1$, $5$, $6$, etc.)
- AWS access/secret keys
- Bearer tokens and API keys
- Private key blocks
- SAM dump hashes
- Kerberos tickets and hashes
- Generic password assignments

To test: `Invoke-CredentialFilter -Text $output -ReturnStats`
