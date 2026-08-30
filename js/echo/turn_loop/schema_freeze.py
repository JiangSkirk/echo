"""Session-level advertised tool-schema freeze (P0-3).

Trusted CLI: first turn sets the set; later turns may only append (no reorder,
no delete). Untrusted surfaces (gateway): freeze ⊆ static allowlist, never grow,
later turns may shrink.
"""

from __future__ import annotations

import hashlib
from contextvars import ContextVar, Token
from typing import Any

from js.echo.plan_commit.activation import gateway_tool_allowlist
from js.models.usage import tools_schema_digest

_turn_prefix_id: ContextVar[str] = ContextVar("echo_turn_prefix_id", default="")


def current_turn_prefix_id() -> str:
    return _turn_prefix_id.get()


def set_turn_prefix_id(value: str) -> Token[str]:
    return _turn_prefix_id.set(value)


def reset_turn_prefix_id(token: Token[str]) -> None:
    _turn_prefix_id.reset(token)


def schema_freeze_untrusted(*, channel: str) -> bool:
    return channel.startswith("gateway:")


def freeze_store_key(*, owner_key_hash: str, session_id: str) -> str:
    return f"{owner_key_hash}:{session_id}"


def schema_freeze_store(agent: Any) -> dict[str, tuple[str, ...]]:
    store = getattr(agent, "_echo_schema_freeze", None)
    if not isinstance(store, dict):
        store = {}
        agent._echo_schema_freeze = store
    return store


def prefix_material_hash(system: str, schemas: list[dict[str, Any]] | None) -> str:
    """Hash cacheable prefix: system text + frozen schema. Memory must not appear."""

    digest = tools_schema_digest(schemas)
    return hashlib.sha256(f"{system}\n{digest}".encode()).hexdigest()


def apply_session_schema_freeze(
    *,
    store: dict[str, tuple[str, ...]],
    key: str,
    full_schemas: list[dict[str, Any]],
    adaptive: list[dict[str, Any]],
    untrusted: bool,
    allowlist: frozenset[str],
) -> list[dict[str, Any]]:
    """Return the session-frozen advertised schema and persist the name tuple."""

    by_name: dict[str, dict[str, Any]] = {}
    for schema in full_schemas:
        name = str(schema.get("function", {}).get("name", ""))
        if name and name not in by_name:
            by_name[name] = schema
    adaptive_names = tuple(
        str(schema.get("function", {}).get("name", ""))
        for schema in adaptive
        if str(schema.get("function", {}).get("name", ""))
    )
    previous = store.get(key)
    if untrusted:
        allowed = tuple(name for name in adaptive_names if name in allowlist)
        if previous is None:
            frozen = allowed
        else:
            frozen = tuple(name for name in previous if name in allowed)
    elif previous is None:
        frozen = adaptive_names
    else:
        extra = tuple(name for name in adaptive_names if name not in previous)
        frozen = previous + extra
    store[key] = frozen
    return [by_name[name] for name in frozen if name in by_name]


def freeze_advertised_schema(
    agent: Any,
    *,
    full_schemas: list[dict[str, Any]],
    adaptive: list[dict[str, Any]],
    channel: str,
    session_id: str,
    owner_key_hash: str,
) -> list[dict[str, Any]]:
    settings = getattr(agent, "settings", None)
    return apply_session_schema_freeze(
        store=schema_freeze_store(agent),
        key=freeze_store_key(owner_key_hash=owner_key_hash, session_id=session_id),
        full_schemas=full_schemas,
        adaptive=adaptive,
        untrusted=schema_freeze_untrusted(channel=channel),
        allowlist=gateway_tool_allowlist(settings),
    )
