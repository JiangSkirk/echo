"""Assemble and redact streamed tool-call deltas."""

from __future__ import annotations

from typing import Any


def _merge_stream_tool_call(
    parts: dict[int | str, dict[str, Any]],
    delta: dict[str, Any],
) -> None:
    raw_key = delta.get("index")
    key: int | str = (
        raw_key if isinstance(raw_key, int | str) else f"\0stream-fallback-{len(parts)}"
    )
    if raw_key is None:
        call_id = delta.get("id")
        key = call_id if isinstance(call_id, str) and call_id else key
    entry = parts.setdefault(key, {"name": "", "arguments": ""})
    if "id" in delta:
        entry["id"] = delta["id"]
    if delta.get("name"):
        entry["name"] = str(delta["name"])
    if delta.get("arguments_delta") is not None:
        entry["arguments"] = str(entry.get("arguments", "")) + str(delta["arguments_delta"])


def _stream_tool_call_key(
    delta: dict[str, Any],
    parts: dict[int | str, dict[str, Any]],
) -> int | str:
    raw_key = delta.get("index")
    if isinstance(raw_key, int | str):
        return raw_key
    call_id = delta.get("id")
    if isinstance(call_id, str) and call_id:
        return call_id
    return f"\0stream-fallback-{len(parts)}"


def _stream_tool_call_has_payload(delta: dict[str, Any]) -> bool:
    return any(key != "index" and value is not None and value != "" for key, value in delta.items())


def _redact_stream_tool_call(tool_call: dict[str, Any], secrets: Any) -> dict[str, Any]:
    def _redact(value: Any) -> Any:
        if isinstance(value, str):
            return secrets.detect_and_redact(value, "stream_tool_call")
        if isinstance(value, dict):
            return {str(key): _redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [_redact(item) for item in value]
        return value

    redacted = _redact(tool_call)
    return redacted if isinstance(redacted, dict) else {}


def _assembled_stream_tool_calls(
    parts: dict[int | str, dict[str, Any]],
) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    numeric_keys = sorted(key for key in parts if isinstance(key, int))
    fallback_keys: list[str] = [key for key in parts if not isinstance(key, int)]
    ordered_keys: list[int | str] = [*numeric_keys, *fallback_keys]
    for key in ordered_keys:
        entry = parts[key]
        name = str(entry.get("name") or "")
        if not name:
            continue
        call = {
            "type": "function",
            "function": {
                "name": name,
                "arguments": str(entry.get("arguments") or "{}"),
            },
        }
        if "id" in entry:
            call["id"] = entry["id"]
        calls.append(call)
    return calls
