"""Metasploit Cursor Harness MCP Server.

Exposes Metasploit Framework functionality as MCP tools for Cursor agent
integration. Includes read-only recon tools (msfmcpd-compatible) and
ROE-gated action tools for exploitation, session management, and payloads.

Runs over stdio transport for local Cursor use:
    python -m msf_harness.mcp.server
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

LOG_DIR = Path(__file__).resolve().parents[2] / "logs"
LOG_DIR.mkdir(exist_ok=True)


def _configure_logging() -> None:
    """Set up structured file logging for the MCP server process."""
    log_file = LOG_DIR / "mcp-server.log"
    handler = logging.FileHandler(str(log_file), encoding="utf-8")
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    root = logging.getLogger("msf_harness")
    root.setLevel(os.environ.get("MSF_LOG_LEVEL", "INFO").upper())
    root.addHandler(handler)


_configure_logging()

mcp = FastMCP("msf-harness", json_response=True)


def _register_all_tools() -> None:
    from msf_harness.mcp.tools import (
        console_tools,
        db_tools,
        handler_tools,
        lab_tools,
        meterpreter_tools,
        module_query_tools,
        module_tools,
        payload_tools,
        read_tools,
        route_tools,
        session_tools,
        workspace_tools,
    )

    read_tools.register(mcp)
    module_tools.register(mcp)
    module_query_tools.register(mcp)
    session_tools.register(mcp)
    handler_tools.register(mcp)
    payload_tools.register(mcp)
    lab_tools.register(mcp)
    workspace_tools.register(mcp)
    console_tools.register(mcp)
    meterpreter_tools.register(mcp)
    route_tools.register(mcp)
    db_tools.register(mcp)


_register_all_tools()


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
