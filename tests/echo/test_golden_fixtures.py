"""Echo golden fixture replay tests.

Reads ``tests/echo/golden/*.json`` and asserts the contracts the Echo kernel
must honour at T9 cutover:

* Every fixture is present and field-order-stable.
* Each fixture has the README-mandated top-level keys
  ``scenario / kind / input / expected / mock / notes`` in that order.
* Deterministic constants (session_id ``00000000-0000-0000-0000-000000000001``,
  token counts, costs) are pinned.
* ``api_chat`` fixtures carry an HTTP status, a body, and no WS frames.
* ``ws`` fixtures carry frames_out (or close_code for handshake failure) and
  no HTTP body.

These tests are intentionally pure-Python — they do NOT spin up the legacy
engine, NOT call the recorder, NOT touch the network. The recorder is the
source of truth for HOW fixtures are written; these tests are the gate that
keeps the on-disk artefacts well-formed.

If a fixture file drifts (extra/missing field, reordered keys, wrong type),
this test fails immediately. Re-record with ``.venv/bin/python -m
scripts.record_echo_golden`` and re-commit.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

_GOLDEN_DIR = Path(__file__).resolve().parent / "golden"

# Fixed contract — keep in lockstep with tests/echo/golden/README.md and
# scripts/record_echo_golden.py.
_FIXED_SESSION_ID = "00000000-0000-0000-0000-000000000001"
_FIXTURE_FIELDS = ("scenario", "kind", "input", "expected", "mock", "notes")

# T1's "10 must-record" list. Every name here must exist as a .json file.
_REQUIRED_API_CHAT = (
    "api_chat_success",
    "api_chat_empty",
    "api_chat_413",
    "api_chat_auth_required",
    "api_chat_provider_error",
)
_REQUIRED_WS = (
    "ws_ping",
    "ws_message",
    "ws_stream_success",
    "ws_stream_error",
    "ws_auth_fail",
)
_REQUIRED_FIXTURES = _REQUIRED_API_CHAT + _REQUIRED_WS


def _load(name: str) -> dict[str, Any]:
    path = _GOLDEN_DIR / f"{name}.json"
    if not path.is_file():
        pytest.fail(f"Golden fixture missing: {path.relative_to(_GOLDEN_DIR.parent.parent)}")
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Structural / field-order tests
# ---------------------------------------------------------------------------


def test_golden_dir_exists() -> None:
    """``tests/echo/golden/`` must be a real directory tracked next to this file."""
    assert _GOLDEN_DIR.is_dir(), f"missing directory: {_GOLDEN_DIR}"


def test_all_required_fixtures_present() -> None:
    """All 10 T1 fixtures must exist on disk."""
    missing = [name for name in _REQUIRED_FIXTURES if not (_GOLDEN_DIR / f"{name}.json").is_file()]
    assert not missing, f"missing fixtures: {missing}"


@pytest.mark.parametrize("name", _REQUIRED_FIXTURES)
def test_fixture_field_order(name: str) -> None:
    """Top-level keys must appear in the README-defined order, no extras."""
    raw = (_GOLDEN_DIR / f"{name}.json").read_text(encoding="utf-8")
    # json.loads preserves insertion order in Python 3.7+, so the key order
    # we get back matches the order they were written.
    data = json.loads(raw)
    assert tuple(data.keys()) == _FIXTURE_FIELDS, (
        f"{name}: expected key order {_FIXTURE_FIELDS!r}, got {tuple(data.keys())!r}"
    )


@pytest.mark.parametrize("name", _REQUIRED_FIXTURES)
def test_scenario_field_matches_filename(name: str) -> None:
    """``scenario`` field must equal the filename stem."""
    data = _load(name)
    assert data["scenario"] == name


@pytest.mark.parametrize("name", _REQUIRED_FIXTURES)
def test_kind_field_valid(name: str) -> None:
    """``kind`` must be ``api_chat`` or ``ws``."""
    data = _load(name)
    assert data["kind"] in {"api_chat", "ws"}
    if name.startswith("api_chat_"):
        assert data["kind"] == "api_chat"
    elif name.startswith("ws_"):
        assert data["kind"] == "ws"


# ---------------------------------------------------------------------------
# /api/chat contract assertions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", _REQUIRED_API_CHAT)
def test_api_chat_input_shape(name: str) -> None:
    """``api_chat`` fixtures must have method='POST', path='/api/chat'."""
    data = _load(name)
    inp = data["input"]
    assert inp["method"] == "POST"
    assert inp["path"] == "/api/chat"
    assert isinstance(inp["headers"], dict)
    assert isinstance(inp["body"], dict)
    assert inp["frames_in"] == []  # api_chat doesn't use frames


@pytest.mark.parametrize("name", _REQUIRED_API_CHAT)
def test_api_chat_expected_has_status(name: str) -> None:
    """Every api_chat fixture must record a numeric HTTP status."""
    data = _load(name)
    expected = data["expected"]
    assert isinstance(expected["status"], int)
    assert 100 <= expected["status"] <= 599
    assert expected["frames_out"] == []


def test_api_chat_success_pinned() -> None:
    """``api_chat_success`` must carry the deterministic happy-path body."""
    data = _load("api_chat_success")
    assert data["expected"]["status"] == 200
    body = data["expected"]["body"]
    assert body["response"] == "Hi there"
    assert body["session_id"] == _FIXED_SESSION_ID
    assert body["turns"] == 1
    assert body["tokens"] == {"input": 10, "output": 5}
    assert body["status"] == "completed"
    # cost is rounded to 6 decimals server-side
    assert body["cost"] == pytest.approx(0.000123, rel=0, abs=1e-6)


def test_api_chat_empty_returns_200_empty_response() -> None:
    """``api_chat_empty`` is the empty-message happy path."""
    data = _load("api_chat_empty")
    assert data["expected"]["status"] == 200
    body = data["expected"]["body"]
    assert body["response"] == ""
    assert body["tokens"] == {"input": 0, "output": 0}


def test_api_chat_413_rejects_oversized() -> None:
    """Payload above 256 KiB returns 413 and ``agent.run`` is never invoked."""
    data = _load("api_chat_413")
    assert data["expected"]["status"] == 413
    # Body marker so the test recorder doesn't have to embed 260 KiB inline.
    marker = data["input"]["body"].get("_oversized_payload")
    assert marker == {"char": "A", "repeat": 260 * 1024}


def test_api_chat_auth_required_403() -> None:
    """No Origin + no X-API-Key triggers the CSRF guard with 403."""
    data = _load("api_chat_auth_required")
    assert data["expected"]["status"] == 403
    assert data["input"]["headers"] == {}


def test_api_chat_provider_error_500_humanized() -> None:
    """Provider error → 500 + humanized Chinese detail; never leaks 'boom'."""
    data = _load("api_chat_provider_error")
    assert data["expected"]["status"] == 500
    body = data["expected"]["body"]
    detail = body.get("detail", "")
    assert isinstance(detail, str)
    assert "boom" not in detail
    # Generic Chinese fallback or one of the recognised buckets.
    assert "出错" in detail or "请稍后" in detail or "出错了" in detail


# ---------------------------------------------------------------------------
# /ws contract assertions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", _REQUIRED_WS)
def test_ws_input_shape(name: str) -> None:
    """``ws`` fixtures must have method=None, path='/ws', frames_in present."""
    data = _load(name)
    inp = data["input"]
    assert inp["method"] is None
    assert inp["path"] == "/ws"
    assert isinstance(inp["frames_in"], list)
    assert inp["body"] is None


@pytest.mark.parametrize("name", _REQUIRED_WS)
def test_ws_expected_has_frames_or_close_code(name: str) -> None:
    """Every ws fixture must record either frames_out (≥1) or a close_code."""
    data = _load(name)
    expected = data["expected"]
    assert expected["status"] == 101  # WS switching protocols
    assert expected["body"] is None
    frames = expected.get("frames_out", [])
    close_code = expected.get("close_code")
    assert isinstance(frames, list)
    # ws_auth_fail closes before any frame; others must have frames.
    if name == "ws_auth_fail":
        assert close_code == 1008
    else:
        assert frames, f"{name}: frames_out is empty but no close_code recorded"


def test_ws_ping_round_trip() -> None:
    """``ws_ping`` → one pong frame."""
    data = _load("ws_ping")
    frames = data["expected"]["frames_out"]
    assert frames == [{"type": "pong"}]


def test_ws_message_status_then_response() -> None:
    """``ws_message`` → status + response, in that order."""
    data = _load("ws_message")
    frames = data["expected"]["frames_out"]
    assert len(frames) == 2
    assert frames[0]["type"] == "status"
    assert frames[0]["content"] == "thinking..."
    assert frames[1]["type"] == "response"
    assert frames[1]["content"] == "Hi there"
    assert frames[1]["session_id"] == _FIXED_SESSION_ID


def test_ws_stream_success_frame_order() -> None:
    """``ws_stream_success`` → status / token×3 / usage / done in order."""
    data = _load("ws_stream_success")
    frames = data["expected"]["frames_out"]
    types = [f["type"] for f in frames]
    assert types == ["status", "token", "token", "token", "usage", "done"]
    # Token payloads must reassemble to "Hello"
    tokens = "".join(f["content"] for f in frames if f["type"] == "token")
    assert tokens == "Hello"
    done = frames[-1]
    assert done["session_id"] == _FIXED_SESSION_ID
    assert done["status"] == "completed"


def test_ws_stream_error_status_then_error() -> None:
    """``ws_stream_error`` → status + error, never leaks raw provider text."""
    data = _load("ws_stream_error")
    frames = data["expected"]["frames_out"]
    types = [f["type"] for f in frames]
    assert types == ["status", "error"]
    err = frames[1]
    assert err["session_id"] == _FIXED_SESSION_ID
    # humanize_error translates 'rate limit' → friendly Chinese; raw English
    # must not leak.
    assert "rate limit" not in err["content"].lower()
    assert (
        "请稍后" in err["content"] or "繁忙" in err["content"] or "请求过于频繁" in err["content"]
    )


def test_ws_auth_fail_close_code_1008() -> None:
    """Handshake failure closes with code 1008."""
    data = _load("ws_auth_fail")
    expected = data["expected"]
    assert expected["close_code"] == 1008
    assert expected["frames_out"] == []
    assert data["mock"].get("api_key_required") is True


# ---------------------------------------------------------------------------
# Cross-fixture invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", _REQUIRED_FIXTURES)
def test_no_session_id_drift(name: str) -> None:
    """Any session_id appearing in a fixture must be the fixed UUID.

    Real engine reruns produce random UUIDs — if a recorder change leaks
    one through, every byte-comparison after this test passes would be
    permanently broken.
    """
    raw = (_GOLDEN_DIR / f"{name}.json").read_text(encoding="utf-8")
    for line in raw.splitlines():
        if '"session_id"' in line and "null" not in line:
            # crude but adequate — every session_id string in any of our
            # fixtures must equal the fixed UUID.
            assert _FIXED_SESSION_ID in line, (
                f"{name}: non-fixed session_id detected: {line.strip()}"
            )
