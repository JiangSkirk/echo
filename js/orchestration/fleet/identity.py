"""Fleet event identity and shared constants."""

from __future__ import annotations

import contextvars
import re
from contextlib import contextmanager
from typing import Any

_FLEET_OWNER: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "echo_fleet_owner", default=None
)
_FLEET_SESSION: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "echo_fleet_session", default=None
)
_FLEET_REQUEST: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "echo_fleet_request", default=None
)
_FLEET_TURN: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "echo_fleet_turn", default=None
)
_FLEET_PRODUCT: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "echo_fleet_product", default=None
)
_SAFE_FLEET_SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_SAFE_FLEET_ROLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
_FLEET_MODES = frozenset({"auto", "debate", "sequential", "manager"})
_MAX_FLEET_TASK_CHARS = 20_000
_MAX_FLEET_SUBTASK_CHARS = 2_000
_LOCAL_FLEET_OWNER = "fleet-local"
_MAX_FLEET_RUNTIME_ID_CHARS = 128

def _validate_fleet_request_or_turn_id(value: Any, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > _MAX_FLEET_RUNTIME_ID_CHARS
    ):
        raise ValueError(f"invalid Fleet {field_name}")
    return value


def validate_fleet_event_identity(
    request_id: Any,
    turn_id: Any,
    session_id: Any,
) -> tuple[str, str, str]:
    """Validate and preserve the exact public identity of one Fleet run."""
    request = _validate_fleet_request_or_turn_id(request_id, "request_id")
    turn = _validate_fleet_request_or_turn_id(turn_id, "turn_id")
    if not isinstance(session_id, str) or not _SAFE_FLEET_SESSION_RE.fullmatch(session_id):
        raise ValueError("invalid Fleet session_id")
    return request, turn, session_id


@contextmanager
def bind_fleet_event_identity(
    request_id: str,
    turn_id: str,
    session_id: str,
) -> Any:
    """Bind an authoritative Fleet event identity for the current async context."""
    request, turn, session = validate_fleet_event_identity(
        request_id,
        turn_id,
        session_id,
    )
    inherited = (_FLEET_REQUEST.get(), _FLEET_TURN.get(), _FLEET_SESSION.get())
    if any(value is not None for value in inherited) and inherited != (
        request,
        turn,
        session,
    ):
        raise PermissionError("Fleet event identity cannot override its parent context")
    request_token = _FLEET_REQUEST.set(request)
    turn_token = _FLEET_TURN.set(turn)
    session_token = _FLEET_SESSION.set(session)
    try:
        yield
    finally:
        _FLEET_SESSION.reset(session_token)
        _FLEET_TURN.reset(turn_token)
        _FLEET_REQUEST.reset(request_token)


def _current_fleet_event_identity() -> tuple[str, str, str]:
    identity = (_FLEET_REQUEST.get(), _FLEET_TURN.get(), _FLEET_SESSION.get())
    if any(value is None for value in identity):
        raise RuntimeError("Fleet event identity context is required")
    return validate_fleet_event_identity(*identity)

