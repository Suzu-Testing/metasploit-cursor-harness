"""Metasploit RPC client wrapping pymetasploit3 with lazy connect and reconnect."""

from __future__ import annotations

import asyncio
import functools
import logging
import threading
from collections.abc import Callable
from typing import Any, TypeVar

from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcError

from msf_harness.mcp.config import get_config

logger = logging.getLogger("msf_harness.rpc")

T = TypeVar("T")


class RpcConnectionError(Exception):
    """Raised when the Metasploit RPC server is unreachable."""


_client: MsfRpcClient | None = None
_lock = threading.Lock()


def get_rpc() -> MsfRpcClient:
    """Return a connected MsfRpcClient, creating one lazily on first call."""
    global _client
    if _client is not None:
        return _client

    with _lock:
        if _client is not None:
            return _client

        cfg = get_config()
        if not cfg.password:
            raise RpcConnectionError(
                "MSF_PASSWORD is not set. Export it or add it to .env before starting the MCP server."
            )
        try:
            logger.info("Connecting to msfrpcd at %s", cfg.uri)
            _client = MsfRpcClient(
                cfg.password,
                username=cfg.user,
                server=cfg.host,
                port=cfg.port,
                ssl=cfg.ssl,
            )
            logger.info("Connected to msfrpcd at %s", cfg.uri)
        except Exception as exc:
            logger.error("Failed to connect to msfrpcd at %s: %s", cfg.uri, exc)
            import sys

            if sys.platform == "win32":
                hint = f'Start it in WSL: wsl -e bash -lc "msfdb start; msfrpcd -U {cfg.user} -P <password> -S -a {cfg.host} -p {cfg.port}"'
            else:
                hint = (
                    f"Start it with: msfdb start && msfrpcd -U {cfg.user} -P <password> -S -a {cfg.host} -p {cfg.port}"
                )
            raise RpcConnectionError(
                f"Cannot connect to msfrpcd at {cfg.uri}. {hint}\nUnderlying error: {exc}"
            ) from exc
        return _client


def reset_client() -> None:
    """Drop the cached client so the next call reconnects."""
    global _client
    with _lock:
        _client = None
    logger.info("RPC client cache cleared; next call will reconnect")


def safe_rpc_call(method: str, args: list | None = None) -> Any:
    """Call an RPC method with automatic reconnect on transient failure.

    Uses client.call() for raw RPC method invocation, retrying once
    after resetting the connection on network/protocol errors.
    """
    client = get_rpc()
    call_args = args or []
    try:
        return client.call(method, call_args)
    except (MsfRpcError, ConnectionError, OSError) as exc:
        logger.warning("RPC call %s failed (%s), reconnecting and retrying", method, exc)
        reset_client()
        client = get_rpc()
        return client.call(method, call_args)


async def run_in_thread(fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run a blocking function in a thread to avoid stalling the event loop."""
    return await asyncio.to_thread(functools.partial(fn, *args, **kwargs))
