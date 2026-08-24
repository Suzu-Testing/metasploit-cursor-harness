# Contributing

Thank you for your interest in contributing to the Metasploit Cursor Harness.

## Development Setup

1. Clone the repository and install with dev dependencies:

```bash
git clone https://github.com/Suzu-Testing/metasploit-cursor-harness.git
cd metasploit-cursor-harness
pip install -e ".[mcp,dev]"
```

2. Verify the test suite passes:

```bash
python -m pytest tests/ -v
```

3. (Optional) Start msfrpcd for integration testing -- see [docs/SETUP.md](docs/SETUP.md).

## Project Structure

- `msf_harness/mcp/tools/` -- MCP tool implementations (one file per tool group)
- `msf_harness/mcp/rpc/` -- RPC client, console engine, module execution
- `msf_harness/mcp/policy/` -- ROE enforcement
- `msf_harness/mcp/models/` -- Input validation, output formatting
- `.cursor/hooks/` -- PowerShell safety gates
- `.cursor/skills/` -- Agent playbooks
- `tests/` -- Unit tests

## Pull Request Guidelines

1. **Tests**: Add tests for any new ROE logic or input validation. Run `pytest` before submitting.
2. **Tool count**: If you add or remove an MCP tool, update `README.md`, `AGENTS.md`, and the tool count assertion test.
3. **ROE**: Any new action tool must call `enforce_roe()` with appropriate parameters.
4. **Hooks**: New action tools need entries in `risk-scoring.ps1` (`$McpToolScores`) and `mcp-evidence-logger.ps1` (`$actionableTools`).
5. **asyncio**: All blocking RPC calls must be wrapped in `run_in_thread()` to avoid stalling the event loop.
6. **No secrets**: Never commit passwords, API keys, or engagement evidence. Check `.gitignore` coverage.

## Code Style

- Python: follow existing patterns (type hints, logging, structured error returns)
- PowerShell hooks: `$ErrorActionPreference = 'Stop'` with `trap` blocks, JSON input/output
- All hooks must import shared modules (`scope-common.ps1`, `input-parser.ps1`, etc.)
- Avoid comments that just narrate what code does

## Testing

### Python unit tests (no msfrpcd needed)

```bash
python -m pytest tests/ -v
```

### Hook tests (PowerShell, no msfrpcd needed)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/test-hooks.ps1
```

This runs:
- Pre-flight checks (file existence, syntax validation)
- Shared module unit tests (85 tests: scope-common, engagement-resolver, input-parser, risk-scoring, world-state-io, credential-filter)
- Gate integration tests (35 tests: all preflight/postflight hooks with fixture JSON)

Run only unit or gate suites:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/test-hooks.ps1 -Suite unit
powershell -ExecutionPolicy Bypass -File scripts/test-hooks.ps1 -Suite gate
```

### MCP validation (requires msfrpcd)

```bash
python scripts/validate-mcp.py
```

### ROE validation

```bash
python scripts/test-roe.py
```

## Hook Development

See `.cursor/hooks/README.md` for the full hook architecture guide, including:
- Hook input/output protocol
- Error handling patterns
- How to add new hooks
- How to extend risk scoring
- Credential filter configuration

## Reporting Issues

- Include your Python version, Metasploit version, and OS
- For MCP errors, include the tool name, arguments, and full error response
- For hook issues, include relevant lines from `logs/hook-audit.log`

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
