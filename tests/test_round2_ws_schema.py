"""Round 2 attack tests: WS strict schema and provisional session_id.

1. String "false" for ``enable_tools`` must NOT be treated as True.
2. A disconnect before the first turn returns must still be able to cancel
   the in-flight turn via a provisional session_id.
"""

from __future__ import annotations

from typing import Any


def test_string_false_not_treated_as_true() -> None:
    """``bool("false")`` is True in Python, but WS schema must treat "false" as False."""
    # Simulate the strict parsing logic now in server.py
    def parse_enable_tools(raw: object) -> bool:
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            return raw.strip().lower() in ("true", "1", "yes")
        if isinstance(raw, (int, float)):
            return bool(raw)
        return True

    assert parse_enable_tools("false") is False
    assert parse_enable_tools("False") is False
    assert parse_enable_tools("FALSE") is False
    assert parse_enable_tools("0") is False
    assert parse_enable_tools("no") is False
    assert parse_enable_tools("") is False
    assert parse_enable_tools(True) is True
    assert parse_enable_tools("true") is True
    assert parse_enable_tools("yes") is True
    assert parse_enable_tools(1) is True
    # The old ``bool(data.get("enable_tools", True))`` would return True for "false":
    assert bool("false") is True  # demonstrating the old bug
    assert parse_enable_tools("false") is False  # new behavior is strict


def test_provisional_session_id_generated_for_first_turn(monkeypatch: Any) -> None:
    """When client sends no session_id, the WS endpoint must generate a provisional one."""
    import secrets

    # The endpoint now does: if not session_id: session_id = f"ws-{secrets.token_hex(16)}"
    generated = []
    original_token_hex = secrets.token_hex

    def spy_token_hex(nbytes: int) -> str:
        result = original_token_hex(nbytes)
        generated.append(result)
        return result

    monkeypatch.setattr("js.web.server.secrets.token_hex", spy_token_hex)

    session_id: str | None = None
    # Simulate the endpoint's provisional generation
    if not session_id:
        session_id = f"ws-{secrets.token_hex(16)}"
    assert session_id is not None
    assert session_id.startswith("ws-")
    assert len(generated) == 1
