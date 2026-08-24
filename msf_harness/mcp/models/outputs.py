"""Structured response helpers for MCP tool outputs."""

from __future__ import annotations

from typing import Any


def ok(data: Any, *, message: str | None = None) -> dict:
    result: dict[str, Any] = {"status": "ok"}
    if message:
        result["message"] = message
    result["data"] = data
    return result


def error(reason: str, *, code: str = "error", data: Any = None) -> dict:
    result: dict[str, Any] = {"status": code, "reason": reason}
    if data is not None:
        result["data"] = data
    return result


def denied(reason: str, *, engagement_id: str | None = None) -> dict:
    result = {"status": "denied", "reason": reason}
    if engagement_id:
        result["engagement_id"] = engagement_id
    return result


def paginated(items: list, total: int, limit: int, offset: int) -> dict:
    return {
        "status": "ok",
        "data": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }
