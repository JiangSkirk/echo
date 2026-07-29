"""Strict JSON loader for release-evidence validation.

All release/gate validators that compare, hash, or verify signatures over JSON
MUST use this module instead of bare ``json.loads``. Fail-closed on duplicate
keys, non-finite numbers, out-of-range integers, and decode/overflow/recursion
errors.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from pathlib import Path
from typing import Any

# Versioned release-evidence integer contract: signed 64-bit.
MAX_STRICT_JSON_INT = 2**63 - 1
MIN_STRICT_JSON_INT = -(2**63)


class StrictJSONError(ValueError):
    """Raised when evidence JSON fails strict parsing rules."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise StrictJSONError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def _parse_constant(text: str) -> object:
    raise StrictJSONError(f"non-finite JSON constant forbidden: {text}")


def _parse_float(text: str) -> float:
    try:
        value = float(text)
    except (ValueError, OverflowError) as exc:
        raise StrictJSONError(f"non-finite JSON number forbidden: {text}") from exc
    if not math.isfinite(value):
        raise StrictJSONError(f"non-finite JSON number forbidden: {text}")
    return value


def _parse_int(text: str) -> int:
    try:
        value = int(text)
    except (ValueError, OverflowError) as exc:
        raise StrictJSONError(f"JSON integer forbidden: {text}") from exc
    if value < MIN_STRICT_JSON_INT or value > MAX_STRICT_JSON_INT:
        raise StrictJSONError(f"JSON integer out of signed-64-bit range: {text}")
    return value


def is_strict_json_int(value: object) -> bool:
    """True only for non-bool ints within the signed 64-bit evidence contract."""
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return MIN_STRICT_JSON_INT <= value <= MAX_STRICT_JSON_INT


_MAX_JSON_DEPTH = 64


def _assert_depth(value: object, *, depth: int = 0) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise StrictJSONError("JSON nesting too deep")
    if isinstance(value, dict):
        for child in value.values():
            _assert_depth(child, depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            _assert_depth(child, depth=depth + 1)


def _assert_int_bounds(value: object) -> None:
    """Walk the value tree and reject out-of-range ints (defense in depth)."""
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if value < MIN_STRICT_JSON_INT or value > MAX_STRICT_JSON_INT:
            raise StrictJSONError("JSON integer out of signed-64-bit range")
        return
    if isinstance(value, dict):
        for child in value.values():
            _assert_int_bounds(child)
    elif isinstance(value, list):
        for child in value:
            _assert_int_bounds(child)


def strict_loads(text: str) -> object:
    """Parse a single JSON value with release-evidence fail-closed rules."""
    if text.startswith("\ufeff"):
        raise StrictJSONError("BOM prefix forbidden in evidence JSON")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_parse_constant,
            parse_float=_parse_float,
            parse_int=_parse_int,
        )
    except StrictJSONError:
        raise
    except RecursionError as exc:
        raise StrictJSONError("JSON nesting too deep") from exc
    except OverflowError as exc:
        raise StrictJSONError("JSON numeric overflow") from exc
    except json.JSONDecodeError as exc:
        raise StrictJSONError(f"JSON decode failed: {exc.msg}") from exc
    except UnicodeDecodeError as exc:
        raise StrictJSONError("JSON unicode decode failed") from exc
    except ValueError as exc:
        raise StrictJSONError(f"JSON value error: {exc}") from exc
    _assert_depth(value)
    _assert_int_bounds(value)
    return value


def strict_load_bytes(data: bytes) -> object:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictJSONError("JSON unicode decode failed") from exc
    return strict_loads(text)


def strict_load_path(path: Path) -> object:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise StrictJSONError(f"JSON file unreadable: {path}") from exc
    return strict_load_bytes(data)


def strict_load_object(path: Path) -> dict[str, Any]:
    """Load JSON and require a top-level object (dict)."""
    value = strict_load_path(path)
    if not isinstance(value, dict):
        raise StrictJSONError("JSON root must be an object")
    return value


def strict_load_object_bytes(data: bytes) -> dict[str, Any]:
    value = strict_load_bytes(data)
    if not isinstance(value, dict):
        raise StrictJSONError("JSON root must be an object")
    return value


def canonical_json_text(payload: Mapping[str, object]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def require_finite(value: object, *, field: str) -> float:
    """Coerce a JSON number and reject bool/non-finite/out-of-range values."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise StrictJSONError(f"{field} must be a finite number")
    if isinstance(value, int) and not is_strict_json_int(value):
        raise StrictJSONError(f"{field} integer out of signed-64-bit range")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise StrictJSONError(f"{field} must be a finite number") from exc
    if not math.isfinite(number):
        raise StrictJSONError(f"{field} must be a finite number")
    return number
