"""Validate provider / model / session identifiers used across Web surfaces."""

from __future__ import annotations

import re
import unicodedata

# Common model IDs look like ``gpt-4o``, ``claude-3-5-sonnet``, ``qwen2.5:14b``,
# or ``provider/model``. Reject control chars, quotes, and HTML/JS metacharacters.
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_MAX_ID_LEN = 192


class InvalidRuntimeIdError(ValueError):
    """Raised when a provider/model/session id fails validation."""


def validate_runtime_id(value: str, *, label: str = "id") -> str:
    """Return a normalized safe runtime id or raise ``InvalidRuntimeIdError``."""
    if not isinstance(value, str):
        raise InvalidRuntimeIdError(f"{label} must be a string")
    normalized = unicodedata.normalize("NFC", value).strip()
    if not normalized:
        raise InvalidRuntimeIdError(f"{label} must not be empty")
    if len(normalized) > _MAX_ID_LEN:
        raise InvalidRuntimeIdError(f"{label} exceeds {_MAX_ID_LEN} characters")
    if any(unicodedata.category(ch).startswith("C") for ch in normalized):
        raise InvalidRuntimeIdError(f"{label} contains control characters")
    if any(ch in normalized for ch in "\"'<>`\\\n\r\t"):
        raise InvalidRuntimeIdError(f"{label} contains forbidden characters")
    if not _ID_RE.fullmatch(normalized):
        raise InvalidRuntimeIdError(f"{label} has an invalid format")
    return normalized


def validate_model_ref(value: str) -> str:
    """Validate ``model`` or ``provider/model`` identifiers."""
    return validate_runtime_id(value, label="model id")


def validate_provider_name(value: str) -> str:
    if not isinstance(value, str):
        raise InvalidRuntimeIdError("provider name must be a string")
    normalized = unicodedata.normalize("NFC", value).strip()
    if not normalized:
        raise InvalidRuntimeIdError("provider name must not be empty")
    if len(normalized) > 64:
        raise InvalidRuntimeIdError("provider name exceeds 64 characters")
    if any(unicodedata.category(ch).startswith("C") for ch in normalized):
        raise InvalidRuntimeIdError("provider name contains control characters")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", normalized) is None:
        raise InvalidRuntimeIdError("provider name has an invalid format")
    return normalized


def validate_session_id(value: str) -> str:
    return validate_runtime_id(value, label="session id")


def coerce_optional_session_id(value: object) -> str | None:
    """Return validated session id, ``None`` for empty, or raise ``InvalidRuntimeIdError``."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidRuntimeIdError("session id must be a string")
    if not value.strip():
        return None
    return validate_session_id(value)
