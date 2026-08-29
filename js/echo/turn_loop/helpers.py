"""Shared module-level helpers used by :class:`EchoTurnLoop`."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

_CAPSULE_DROP_DRIFT_CONFIDENCE = 0.75


def _valid_tool_call_id(value: Any) -> str | None:
    """Return an opaque provider ID only when it is a non-blank string."""
    if not isinstance(value, str) or not value.strip():
        return None
    return value


def _redact_provider_value(
    value: Any,
    *,
    redact: Callable[[str, str], str],
    source: str,
) -> Any:
    """Copy provider-owned structured output while redacting every string value."""
    if isinstance(value, str):
        return redact(value, source)
    if isinstance(value, list):
        return [_redact_provider_value(item, redact=redact, source=source) for item in value]
    if isinstance(value, dict):
        return {
            key: _redact_provider_value(item, redact=redact, source=source)
            for key, item in value.items()
        }
    return value
