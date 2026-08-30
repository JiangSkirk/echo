"""Isolated value extraction: one disable_tools model call, never a tool loop."""

from __future__ import annotations

import json
import re
from typing import Any, Final

from js.echo.plan_commit.assembler import AssemblyError

EXTRACT_INSTRUCTIONS: Final[str] = (
    'Extract one JSON object {"value": <extracted>} for the requested field. '
    "Do not call tools. Do not invent file writes, shell, or URLs. "
    'If the value is not present, output {"value": null}.'
)

_FENCE_RE: Final[re.Pattern[str]] = re.compile(
    r"```(?:json)?\s*(\{.*\})\s*```",
    re.DOTALL,
)


def parse_extracted_value(text: str, slot_name: str) -> Any:
    """Parse an isolated extract response. Fail closed on junk."""

    if not isinstance(text, str) or not text.strip():
        raise AssemblyError(f"extract for {slot_name} is empty")
    payload = _load_object(text)
    if not isinstance(payload, dict):
        raise AssemblyError(f"extract for {slot_name} is not an object")
    if "value" in payload:
        return payload["value"]
    if slot_name in payload:
        return payload[slot_name]
    raise AssemblyError(f"extract for {slot_name} missing value")


def _load_object(text: str) -> Any:
    stripped = text.strip()
    fenced = _FENCE_RE.search(stripped)
    candidate = fenced.group(1) if fenced is not None else stripped
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(stripped[start : end + 1])
            except json.JSONDecodeError as exc:
                raise AssemblyError("extract is not valid JSON") from exc
        raise AssemblyError("extract is not valid JSON") from None
