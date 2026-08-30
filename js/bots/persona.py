"""SOUL binding and stable-prefix helpers for a named bot turn."""

from __future__ import annotations

import contextvars
import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from js.bots.identity import soul_digest

_binding: contextvars.ContextVar[BotTurnBinding | None] = contextvars.ContextVar(
    "bots_turn_binding",
    default=None,
)
_ask_depth: contextvars.ContextVar[int] = contextvars.ContextVar("bots_ask_depth", default=0)


@dataclass(frozen=True, slots=True)
class BotTurnBinding:
    bot_id: str
    soul_text: str
    persona_appendix: str
    room_id: str = ""
    memory_session: str = ""
    prefix_id: str = ""
    frozen_tools: tuple[dict[str, Any], ...] | None = None
    ask_depth: int = 0


def soul_digest_of(soul_text: str) -> str:
    return soul_digest(soul_text)


def compute_prefix_id(bot_id: str, soul_text: str, tools: list[dict[str, Any]] | None) -> str:
    from js.models.usage import tools_schema_digest

    raw = f"{bot_id}|{soul_digest(soul_text)}|{tools_schema_digest(tools)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


_VOLATILE_HEADING = "## Volatile Context"


def strip_volatile_tail(content: str) -> str:
    """Drop the current-turn volatile tail so it cannot enter room history."""

    if not isinstance(content, str) or not content:
        return content
    index = content.find(_VOLATILE_HEADING)
    if index < 0:
        return content
    return content[:index].rstrip()


def render_soul_block(soul_text: str, persona_appendix: str) -> str:
    appendix = f"\n{persona_appendix}" if persona_appendix.strip() else ""
    return f"\n## SOUL\n{soul_text.strip()}{appendix}"


def current_bot_binding() -> BotTurnBinding | None:
    return _binding.get()


def current_ask_depth() -> int:
    return int(_ask_depth.get())


@contextmanager
def bind_bot_turn(binding: BotTurnBinding) -> Iterator[BotTurnBinding]:
    token = _binding.set(binding)
    depth_token = _ask_depth.set(binding.ask_depth)
    try:
        yield binding
    finally:
        _ask_depth.reset(depth_token)
        _binding.reset(token)


def last_assistant_text(state: Any) -> str:
    messages = getattr(state, "messages", None) or []
    for message in reversed(list(messages)):
        if getattr(message, "role", "") != "assistant":
            continue
        content = getattr(message, "content", "")
        if isinstance(content, str) and content.strip():
            return content.strip()
    return ""


def apply_bots_cache_hooks(
    converted: list[dict[str, Any]],
    kwargs: dict[str, Any],
    *,
    transport_type: str,
) -> None:
    """Attach provider prefix-cache breakpoints for Bots and generic Echo."""

    prefix_id = ""
    binding = current_bot_binding()
    if binding is not None and binding.prefix_id:
        prefix_id = binding.prefix_id
    else:
        from js.echo.turn_loop.schema_freeze import current_turn_prefix_id

        prefix_id = current_turn_prefix_id()
    if not prefix_id:
        return
    kwargs["prompt_cache_key"] = prefix_id[:64]
    if transport_type != "anthropic":
        return
    for message in converted:
        if message.get("role") != "system":
            continue
        content = message.get("content")
        if isinstance(content, str):
            message["content"] = [
                {
                    "type": "text",
                    "text": content,
                    "cache_control": {"type": "ephemeral"},
                }
            ]
        break
