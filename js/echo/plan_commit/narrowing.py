"""Monotonic mid-turn write/egress narrowing. Pure functions; zero model calls."""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import replace
from typing import Any, Final

from js.orin.sinks import (
    SINK_FS_WRITE,
    SINK_MEMORY_WRITE,
    SINK_NETWORK_EGRESS,
    SINK_SPAWN,
    sinks_for_tool,
)
from js.orin.taint import BOT_PEER, INBOX_CONTENT, WEB_CONTENT, source_taint_for_tool

# WEB_CONTENT | INBOX_CONTENT | BOT_PEER. TOOL_RESULT alone must not narrow:
# a trusted file_read is not an injection.
DIRTY_MIDTURN: Final[int] = WEB_CONTENT | INBOX_CONTENT | BOT_PEER
_INJECTION_DIRTY: Final[int] = DIRTY_MIDTURN

WRITE_EGRESS_SINKS: Final[int] = (
    SINK_FS_WRITE | SINK_SPAWN | SINK_NETWORK_EGRESS | SINK_MEMORY_WRITE
)

_write_egress_blocked: ContextVar[bool] = ContextVar(
    "echo_midturn_write_egress_blocked",
    default=False,
)


def injection_dirty_bits() -> int:
    """Bits that trigger remaining-iteration write/egress narrowing."""

    return _INJECTION_DIRTY


def messages_have_injection_dirty(messages: list[Any]) -> bool:
    """True when any live message carries a mid-turn injection dirty bit."""

    mask = _INJECTION_DIRTY
    return any(int(getattr(message, "taint", 0) or 0) & mask for message in messages)


def restore_checkpoint_tool_taint(messages: list[Any]) -> list[Any]:
    """Recover source taint that ``AgentState.to_dict`` does not persist."""

    restored: list[Any] = []
    for message in messages:
        taint = int(getattr(message, "taint", 0) or 0)
        name = str(getattr(message, "name", "") or "")
        if getattr(message, "role", "") == "tool" and taint == 0 and name:
            restored.append(replace(message, taint=source_taint_for_tool(name)))
        else:
            restored.append(message)
    return restored


def is_write_or_egress_tool(tool_name: str) -> bool:
    return bool(sinks_for_tool(tool_name) & WRITE_EGRESS_SINKS)


def filter_write_egress_schema(
    tools_schema: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Drop write/spawn/egress tools from the advertised schema."""

    return [
        schema
        for schema in tools_schema
        if not is_write_or_egress_tool(str(schema.get("function", {}).get("name", "")))
    ]


def write_egress_blocked() -> bool:
    return bool(_write_egress_blocked.get())


def set_write_egress_blocked(value: bool) -> Token[bool]:
    return _write_egress_blocked.set(bool(value))


def reset_write_egress_blocked(token: Token[bool]) -> None:
    _write_egress_blocked.reset(token)


def deny_write_egress_if_blocked(tool_name: str) -> None:
    """Hard deny remaining-iteration write/egress after mid-turn dirty bits."""

    if write_egress_blocked() and is_write_or_egress_tool(tool_name):
        raise PermissionError("mid-turn dirty context forbids write/egress tools")
