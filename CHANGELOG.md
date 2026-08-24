# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-27

### Added

- **MCP Server** with 54 tools covering reconnaissance, exploitation, post-exploitation, session management, routing, database operations, and payload generation
- **ROE enforcement layer** with CIDR validation, domain authorization, module blocking, session limits, CIDR width caps, and check-before-exploit gating
- **Thread-safe check registry** with TTL-based expiration for tracking vulnerability checks
- **Console-first execution** for exploit, auxiliary, and post modules with structured output parsing
- **18 Cursor hook scripts** for scope validation, risk scoring, duplicate detection, evidence logging, world state tracking, and credential redaction
- **57 agent skills** covering pentest workflow, recon, exploitation, post-exploitation, and domain-specific testing (web, AD, cloud, containers, service-level, vuln-class)
- **5 custom subagents** for orchestration, recon, exploit chains, post-exploitation, and review
- **Input validation** across all tool handlers (IP, port, workspace, module type, path traversal, command injection)
- **Meterpreter tools** for sysinfo, getuid, process listing, file download/upload with path sandboxing
- **Route management tools** for pivot subnet routing through compromised sessions
- **Database write tools** for host reporting, credential storage, and note annotations
- **269 automated tests** at 46% code coverage with CI enforcement
- **CI pipeline** with multi-Python testing (3.10-3.12), Windows runner, ruff linting/formatting, pip-audit, and bandit scanning
- **Engagement workflow** with PTES-aligned phases, gates, and subgates
- **Cross-platform support**: Windows + WSL, native Linux/Kali, macOS (experimental)
- **Health check script** (`scripts/doctor.py`) for prerequisite validation
- **Linux start script** (`scripts/start-msfrpcd.sh`) for native Kali/Linux
- **BYO targets guide** (`docs/BYO-TARGETS.md`) for HTB, THM, OSCP, and custom target setups
