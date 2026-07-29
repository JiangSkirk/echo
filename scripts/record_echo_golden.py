"""Deterministic Echo golden fixture recorder.

Records the legacy engine's ``/api/chat`` and ``/ws`` byte-for-byte responses
into ``tests/echo/golden/*.json``. Echo kernel (``js/echo/``) must reproduce
these fixtures verbatim at T9 cutover.

Usage::

    .venv/bin/python -m scripts.record_echo_golden            # rec all
    .venv/bin/python -m scripts.record_echo_golden api_chat_success
    .venv/bin/python -m scripts.record_echo_golden ws_ping ws_message

Output layout::

    tests/echo/golden/
        api_chat_success.json
        api_chat_empty.json
        api_chat_413.json
        api_chat_auth_required.json
        api_chat_provider_error.json
        ws_message.json
        ws_stream_success.json
        ws_stream_error.json
        ws_ping.json
        ws_auth_fail.json

Determinism rules:

* Mock provider (no real network).
* ``agent.run`` replaced with ``AsyncMock`` returning a deterministic state.
* All timestamps fixed at epoch ``1700000000`` (``2023-11-14T22:13:20Z``).
* All session IDs fixed at ``00000000-0000-0000-0000-000000000001``.
* Frame counters start at 1.

Running the recorder twice with the same code produces byte-identical files —
``git diff`` after a re-run must be empty.

The recorder is **read-only** with respect to the legacy engine: it never
edits ``js/web/``, ``js/agent/``, or any other production source. It only
patches them at call time via ``unittest.mock``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

# Repo root anchor — the recorder must work even when invoked from elsewhere.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_GOLDEN_DIR = _REPO_ROOT / "tests" / "echo" / "golden"

# Deterministic constants — keep in lockstep with tests/echo/golden/README.md.
_FIXED_SESSION_ID = "00000000-0000-0000-0000-000000000001"
_FIXED_EPOCH = 1700000000  # 2023-11-14T22:13:20Z

# Field-order template enforced on every fixture file (README §"JSON Schema").
_FIXTURE_FIELDS = ("scenario", "kind", "input", "expected", "mock", "notes")


# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------


def _dump_fixture(scenario: str, payload: dict[str, Any]) -> Path:
    """Write a fixture to ``tests/echo/golden/<scenario>.json``.

    Enforces the README's field order (``scenario / kind / input / expected /
    mock / notes``) so the on-disk JSON is stable across recorder reruns.
    """
    ordered: dict[str, Any] = {}
    for field in _FIXTURE_FIELDS:
        if field not in payload:
            raise ValueError(f"Fixture {scenario} missing field: {field}")
        ordered[field] = payload[field]
    extra = set(payload) - set(_FIXTURE_FIELDS)
    if extra:
        raise ValueError(f"Fixture {scenario} has unexpected fields: {sorted(extra)}")

    _GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    path = _GOLDEN_DIR / f"{scenario}.json"
    serialised = json.dumps(ordered, indent=2, ensure_ascii=False, sort_keys=False)
    path.write_text(serialised + "\n", encoding="utf-8")
    return path


def _make_chat_app() -> Any:
    """Build a minimal FastAPI app with the chat router and auth disabled.

    Mirrors ``tests/web/test_chat_router.py::_make_app`` exactly so the
    fixture recording path is identical to the existing legacy-engine test
    template.
    """
    from fastapi import FastAPI

    from js.config import JSSettings, SecurityConfig
    from js.web.routers.chat import router as chat_router

    app = FastAPI()
    app.include_router(chat_router)
    _settings = JSSettings(
        workspace=Path("/tmp/echo_golden"),
        state_dir=Path("/tmp/echo_golden"),
        security=SecurityConfig(api_key_required=False),
    )
    patch("js.web.server._settings", _settings).start()
    patch("js.web.deps._stats_store", None).start()
    return app


def _build_mock_state(
    *,
    session_id: str = _FIXED_SESSION_ID,
    turn_count: int = 1,
    input_tokens: int = 10,
    output_tokens: int = 5,
    status: str = "completed",
    assistant_text: str = "Hi there",
    model: str | None = None,
    cost: float = 0.000123,
    error_message: str | None = None,
    compression_stats: dict[str, Any] | None = None,
) -> MagicMock:
    """Construct a deterministic AgentState mock.

    All free-form numeric/string fields default to fixed values listed in
    ``tests/echo/golden/README.md``'s "Dynamic-field policy" table. The
    factory is intentionally narrow: every fixture in this recorder
    overrides only the fields its scenario requires.
    """
    state = MagicMock()
    state.session_id = session_id
    state.turn_count = turn_count
    state.total_tokens = {"input": input_tokens, "output": output_tokens}
    state.status = status
    state.cost_estimate = cost
    state.model = model
    state.error_message = error_message
    state.compression_stats = compression_stats or {}
    if assistant_text:
        state.messages = [
            MagicMock(role="user", content=""),
            MagicMock(role="assistant", content=assistant_text),
        ]
    else:
        state.messages = []
    return state


def _normalise_response_headers(headers: Any) -> dict[str, str]:
    """Return only the response headers the golden contract cares about.

    The full set varies by Starlette/uvicorn build and is not contractual.
    We keep ``content-type`` (semantic) and ``content-length`` (size).
    """
    keep = {"content-type", "content-length"}
    return {k.lower(): v for k, v in headers.items() if k.lower() in keep}


# ---------------------------------------------------------------------------
# /api/chat fixture recorders
# ---------------------------------------------------------------------------


def record_api_chat_success() -> Path:
    """Successful single-turn chat (no tools)."""
    from fastapi.testclient import TestClient

    app = _make_chat_app()
    state = _build_mock_state(assistant_text="Hi there", model="mock-model")
    agent = MagicMock()
    agent.run = AsyncMock(return_value=state)
    agent.router.get_model_config.return_value = None

    body_in = {"message": "hello", "session_id": _FIXED_SESSION_ID}
    client = TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost"},
    )
    with patch("js.web.routers.chat.get_agent", return_value=agent):
        resp = client.post("/api/chat", json=body_in)

    payload = {
        "scenario": "api_chat_success",
        "kind": "api_chat",
        "input": {
            "method": "POST",
            "path": "/api/chat",
            "headers": {"Origin": "http://localhost"},
            "body": body_in,
            "frames_in": [],
        },
        "expected": {
            "status": resp.status_code,
            "headers": _normalise_response_headers(resp.headers),
            "body": resp.json(),
            "frames_out": [],
        },
        "mock": {
            "provider": "scripted",
            "scripted_chunks": [{"role": "assistant", "content": "Hi there"}],
        },
        "notes": "single-turn happy path; assistant text fixed; auth disabled.",
    }
    return _dump_fixture("api_chat_success", payload)


def record_api_chat_empty() -> Path:
    """Empty ``message`` field still yields a 200 with empty response."""
    from fastapi.testclient import TestClient

    app = _make_chat_app()
    state = _build_mock_state(
        assistant_text="",
        input_tokens=0,
        output_tokens=0,
        cost=0.0,
    )
    agent = MagicMock()
    agent.run = AsyncMock(return_value=state)
    agent.router.get_model_config.return_value = None

    body_in = {"message": ""}
    client = TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost"},
    )
    with patch("js.web.routers.chat.get_agent", return_value=agent):
        resp = client.post("/api/chat", json=body_in)

    payload = {
        "scenario": "api_chat_empty",
        "kind": "api_chat",
        "input": {
            "method": "POST",
            "path": "/api/chat",
            "headers": {"Origin": "http://localhost"},
            "body": body_in,
            "frames_in": [],
        },
        "expected": {
            "status": resp.status_code,
            "headers": _normalise_response_headers(resp.headers),
            "body": resp.json(),
            "frames_out": [],
        },
        "mock": {
            "provider": "scripted",
            "scripted_chunks": [],
        },
        "notes": "empty message still yields 200; matches tests/web/test_chat_router.py::test_chat_empty_message.",
    }
    return _dump_fixture("api_chat_empty", payload)


def record_api_chat_413() -> Path:
    """Payload above 256 KiB → HTTPException(413)."""
    from fastapi.testclient import TestClient

    app = _make_chat_app()
    agent = MagicMock()
    agent.run = AsyncMock()  # must not be called

    # Build a deterministic > 256 KiB string. 260*1024 'A' chars far exceeds the limit.
    big = "A" * (260 * 1024)
    body_in = {"message": big}

    client = TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost"},
    )
    with patch("js.web.routers.chat.get_agent", return_value=agent):
        resp = client.post("/api/chat", json=body_in)

    payload = {
        "scenario": "api_chat_413",
        "kind": "api_chat",
        "input": {
            "method": "POST",
            "path": "/api/chat",
            # Body too large to dump verbatim — store the marker + length
            # instead. Test replays by reconstructing ``"A" * length``.
            "headers": {"Origin": "http://localhost"},
            "body": {"_oversized_payload": {"char": "A", "repeat": len(big)}},
            "frames_in": [],
        },
        "expected": {
            "status": resp.status_code,
            "headers": _normalise_response_headers(resp.headers),
            "body": resp.json(),
            "frames_out": [],
        },
        "mock": {
            "provider": "scripted",
            "scripted_chunks": [],
        },
        "notes": "payload > 256 KiB rejected with HTTPException(413); agent.run not invoked.",
    }
    return _dump_fixture("api_chat_413", payload)


def record_api_chat_auth_required() -> Path:
    """No Origin + no API key → ``check_origin`` rejects with 403."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from js.config import JSSettings, SecurityConfig
    from js.web.routers.chat import router as chat_router

    app = FastAPI()
    app.include_router(chat_router)
    _settings = JSSettings(
        workspace=Path("/tmp/echo_golden"),
        state_dir=Path("/tmp/echo_golden"),
        security=SecurityConfig(api_key_required=False),
    )
    patch("js.web.server._settings", _settings).start()
    patch("js.web.deps._stats_store", None).start()

    agent = MagicMock()
    agent.run = AsyncMock()  # must not be called

    body_in = {"message": "hello"}
    # No Origin header + no X-API-Key → check_origin raises 403.
    client = TestClient(app, base_url="http://localhost")
    with patch("js.web.routers.chat.get_agent", return_value=agent):
        resp = client.post("/api/chat", json=body_in)

    payload = {
        "scenario": "api_chat_auth_required",
        "kind": "api_chat",
        "input": {
            "method": "POST",
            "path": "/api/chat",
            "headers": {},  # no Origin → check_origin will reject
            "body": body_in,
            "frames_in": [],
        },
        "expected": {
            "status": resp.status_code,
            "headers": _normalise_response_headers(resp.headers),
            "body": resp.json(),
            "frames_out": [],
        },
        "mock": {
            "provider": "scripted",
            "scripted_chunks": [],
        },
        "notes": "no Origin + no X-API-Key → check_origin rejects with 403; mimics browser pre-auth state.",
    }
    return _dump_fixture("api_chat_auth_required", payload)


def record_api_chat_provider_error() -> Path:
    """Agent raises non-HTTPException → 500 with humanized Chinese detail."""
    from fastapi.testclient import TestClient

    app = _make_chat_app()
    agent = MagicMock()
    agent.run = AsyncMock(side_effect=RuntimeError("boom"))

    body_in = {"message": "hello"}
    client = TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost"},
    )
    with patch("js.web.routers.chat.get_agent", return_value=agent):
        resp = client.post("/api/chat", json=body_in)

    payload = {
        "scenario": "api_chat_provider_error",
        "kind": "api_chat",
        "input": {
            "method": "POST",
            "path": "/api/chat",
            "headers": {"Origin": "http://localhost"},
            "body": body_in,
            "frames_in": [],
        },
        "expected": {
            "status": resp.status_code,
            "headers": _normalise_response_headers(resp.headers),
            "body": resp.json(),
            "frames_out": [],
        },
        "mock": {
            "provider": "scripted",
            "scripted_chunks": [],
            "raise": "RuntimeError('boom')",
        },
        "notes": "agent.run raises RuntimeError → humanize_error wraps to 500 with generic Chinese detail; never leaks 'boom'.",
    }
    return _dump_fixture("api_chat_provider_error", payload)


# ---------------------------------------------------------------------------
# /ws fixture recorders
# ---------------------------------------------------------------------------


def _build_ws_app() -> Any:
    """Build the full FastAPI app (with /ws) WITH the production lifespan stubbed.

    ``js.web.server.create_app`` wires every router and the WebSocket handlers.
    The real lifespan instantiates a full ``JSAgent`` (reading state from disk,
    starting background tasks, etc.), which is far too heavy and side-effect-
    heavy for a deterministic recorder. We replace it with a no-op async
    context manager just for the lifetime of ``create_app()``.

    We also pin ``JS_ALLOWED_ORIGINS=http://localhost`` so the WebSocket
    handler's ``check_origin`` accepts the TestClient's WS upgrade — the WS
    upgrade path doesn't auto-fill a Host header the way the HTTP TestClient
    does, so without an explicit allowlist the legacy CSRF guard rejects it.
    """
    import os
    from collections.abc import AsyncIterator
    from contextlib import asynccontextmanager

    os.environ["JS_ALLOWED_ORIGINS"] = "http://localhost"
    # The auth module caches the parsed origin allowlist on first call.
    # Reset it so our env override takes effect on every fresh recorder run.
    import js.web.auth as _auth_mod

    _auth_mod._ALLOWED_ORIGINS = None

    @asynccontextmanager
    async def _noop_lifespan(_app: Any) -> AsyncIterator[None]:
        yield

    with patch("js.web.server.lifespan", _noop_lifespan):
        from js.web.server import create_app

        app = create_app()
    return app


def _patch_ws_globals(agent: MagicMock, *, api_key_required: bool = False) -> list[Any]:
    """Patch the module-level globals the WS handler reads.

    Returns the started patcher objects so the caller can ``stop()`` them.
    The /ws handler resolves ``get_agent()`` (from ``js.web.server``) and
    ``_settings`` (also module-level). Auth-optional + Origin localhost
    is the legacy single-user dev default.
    """
    from js.config import JSSettings, SecurityConfig

    settings = JSSettings(
        workspace=Path("/tmp/echo_golden_ws"),
        state_dir=Path("/tmp/echo_golden_ws"),
        security=SecurityConfig(api_key_required=api_key_required),
    )
    agent.settings = settings
    if not hasattr(agent, "_dream_scheduler") or agent._dream_scheduler is None:
        agent._dream_scheduler = MagicMock()

    patchers = [
        patch("js.web.server._settings", settings),
        patch("js.web.server._agent", agent),
        patch("js.web.server.get_agent", return_value=agent),
        patch("js.web.deps._settings", settings),
        patch("js.web.deps._agent", agent),
    ]
    for p in patchers:
        p.start()
    return patchers


def _stop_patchers(patchers: list[Any]) -> None:
    for p in patchers:
        try:
            p.stop()
        except RuntimeError:
            pass  # patcher already stopped (e.g. context-manager teardown)


def record_ws_ping() -> Path:
    """Client sends ``{type:"ping"}``, server replies ``{type:"pong"}``."""
    from fastapi.testclient import TestClient

    app = _build_ws_app()
    agent = MagicMock()
    agent.run = AsyncMock()
    agent.router.get_model_config.return_value = None

    patchers = _patch_ws_globals(agent)
    try:
        client = TestClient(
            app,
            base_url="http://localhost",
            headers={"Origin": "http://localhost"},
        )
        frames_in = [{"type": "ping"}]
        frames_out: list[dict[str, Any]] = []
        with client.websocket_connect("/ws", headers={"Origin": "http://localhost"}) as ws:
            ws.send_json(frames_in[0])
            frames_out.append(ws.receive_json())
    finally:
        _stop_patchers(patchers)

    payload = {
        "scenario": "ws_ping",
        "kind": "ws",
        "input": {
            "method": None,
            "path": "/ws",
            "headers": {"Origin": "http://localhost"},
            "body": None,
            "frames_in": frames_in,
        },
        "expected": {
            "status": 101,  # WebSocket switching protocols
            "headers": {},
            "body": None,
            "frames_out": frames_out,
        },
        "mock": {
            "provider": "scripted",
            "scripted_chunks": [],
        },
        "notes": "heartbeat round-trip; agent.run never called.",
    }
    return _dump_fixture("ws_ping", payload)


def record_ws_message() -> Path:
    """Client sends ``{type:"message", content:"hi"}``; server replies 1× status + 1× response."""
    from fastapi.testclient import TestClient

    app = _build_ws_app()
    state = _build_mock_state(assistant_text="Hi there", model="mock-model")
    agent = MagicMock()
    agent.run = AsyncMock(return_value=state)
    agent.router.get_model_config.return_value = None

    patchers = _patch_ws_globals(agent)
    try:
        client = TestClient(
            app,
            base_url="http://localhost",
            headers={"Origin": "http://localhost"},
        )
        frames_in = [{"type": "message", "content": "hi", "session_id": _FIXED_SESSION_ID}]
        frames_out: list[dict[str, Any]] = []
        with client.websocket_connect("/ws", headers={"Origin": "http://localhost"}) as ws:
            ws.send_json(frames_in[0])
            # Expect: 1× status, 1× response
            frames_out.append(ws.receive_json())
            frames_out.append(ws.receive_json())
    finally:
        _stop_patchers(patchers)

    payload = {
        "scenario": "ws_message",
        "kind": "ws",
        "input": {
            "method": None,
            "path": "/ws",
            "headers": {"Origin": "http://localhost"},
            "body": None,
            "frames_in": frames_in,
        },
        "expected": {
            "status": 101,
            "headers": {},
            "body": None,
            "frames_out": frames_out,
        },
        "mock": {
            "provider": "scripted",
            "scripted_chunks": [{"role": "assistant", "content": "Hi there"}],
        },
        "notes": "single-frame message → status('thinking...') + response(assistant_msg).",
    }
    return _dump_fixture("ws_message", payload)


def record_ws_stream_success() -> Path:
    """Streaming turn → status / token×N / usage / done frames."""
    from fastapi.testclient import TestClient

    app = _build_ws_app()
    state = _build_mock_state(assistant_text="Hello", model="mock-model")
    agent = MagicMock()
    agent.router.get_model_config.return_value = None

    chunks = ["He", "ll", "o"]

    async def fake_run(
        user_msg: str,
        *,
        session_id: str | None = None,
        model: str | None = None,
        attachments: list[Any] | None = None,
        stream_callback: Any = None,
        event_callback: Any = None,
    ) -> Any:
        for chunk in chunks:
            if stream_callback is not None:
                await stream_callback(chunk)
        if event_callback is not None:
            await event_callback(
                {
                    "kind": "usage",
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                }
            )
        return state

    agent.run = AsyncMock(side_effect=fake_run)
    agent._dream_scheduler = MagicMock()

    patchers = _patch_ws_globals(agent)
    try:
        client = TestClient(
            app,
            base_url="http://localhost",
            headers={"Origin": "http://localhost"},
        )
        frames_in = [{"type": "stream", "content": "hi", "session_id": _FIXED_SESSION_ID}]
        frames_out: list[dict[str, Any]] = []
        with client.websocket_connect("/ws", headers={"Origin": "http://localhost"}) as ws:
            ws.send_json(frames_in[0])
            # Expect: status, token×3, usage, done
            for _ in range(6):
                frames_out.append(ws.receive_json())
    finally:
        _stop_patchers(patchers)

    payload = {
        "scenario": "ws_stream_success",
        "kind": "ws",
        "input": {
            "method": None,
            "path": "/ws",
            "headers": {"Origin": "http://localhost"},
            "body": None,
            "frames_in": frames_in,
        },
        "expected": {
            "status": 101,
            "headers": {},
            "body": None,
            "frames_out": frames_out,
        },
        "mock": {
            "provider": "scripted",
            "scripted_chunks": chunks,
        },
        "notes": "token streaming via stream_callback; usage via event_callback; done frame at end.",
    }
    return _dump_fixture("ws_stream_success", payload)


def record_ws_stream_error() -> Path:
    """Streaming turn where state.status == 'error' → status + error frame."""
    from fastapi.testclient import TestClient

    app = _build_ws_app()
    state = _build_mock_state(
        assistant_text="",
        status="error",
        error_message="rate limit exceeded",
        input_tokens=0,
        output_tokens=0,
        cost=0.0,
        model="mock-model",
    )
    agent = MagicMock()
    agent.router.get_model_config.return_value = None

    async def fake_run(
        user_msg: str,
        *,
        session_id: str | None = None,
        model: str | None = None,
        attachments: list[Any] | None = None,
        stream_callback: Any = None,
        event_callback: Any = None,
    ) -> Any:
        # No tokens emitted before the error — pure error path.
        return state

    agent.run = AsyncMock(side_effect=fake_run)
    agent._dream_scheduler = MagicMock()

    patchers = _patch_ws_globals(agent)
    try:
        client = TestClient(
            app,
            base_url="http://localhost",
            headers={"Origin": "http://localhost"},
        )
        frames_in = [{"type": "stream", "content": "hi", "session_id": _FIXED_SESSION_ID}]
        frames_out: list[dict[str, Any]] = []
        with client.websocket_connect("/ws", headers={"Origin": "http://localhost"}) as ws:
            ws.send_json(frames_in[0])
            # Expect: status, error
            frames_out.append(ws.receive_json())
            frames_out.append(ws.receive_json())
    finally:
        _stop_patchers(patchers)

    payload = {
        "scenario": "ws_stream_error",
        "kind": "ws",
        "input": {
            "method": None,
            "path": "/ws",
            "headers": {"Origin": "http://localhost"},
            "body": None,
            "frames_in": frames_in,
        },
        "expected": {
            "status": 101,
            "headers": {},
            "body": None,
            "frames_out": frames_out,
        },
        "mock": {
            "provider": "scripted",
            "scripted_chunks": [],
            "state_status": "error",
            "state_error_message": "rate limit exceeded",
        },
        "notes": "state.status='error' → status('streaming...') + error frame with humanized Chinese detail.",
    }
    return _dump_fixture("ws_stream_error", payload)


def record_ws_auth_fail() -> Path:
    """WS handshake rejected when ``api_key_required`` and key missing.

    Captures the close-code path (1008 Authentication failed). The
    TestClient surfaces this as a ``WebSocketDisconnect`` exception during
    handshake or first receive.
    """
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    app = _build_ws_app()
    agent = MagicMock()
    agent.run = AsyncMock()
    agent.router.get_model_config.return_value = None

    patchers = _patch_ws_globals(agent, api_key_required=True)

    close_code: int | None = None
    close_reason: str | None = None
    try:
        client = TestClient(
            app,
            base_url="http://localhost",
            headers={"Origin": "http://localhost"},
        )
        try:
            with client.websocket_connect("/ws", headers={"Origin": "http://localhost"}) as ws:
                # Server should close immediately. Reading either raises
                # WebSocketDisconnect or yields no frames.
                ws.receive_json()
        except WebSocketDisconnect as exc:
            close_code = exc.code
            close_reason = getattr(exc, "reason", None)
    finally:
        _stop_patchers(patchers)

    payload = {
        "scenario": "ws_auth_fail",
        "kind": "ws",
        "input": {
            "method": None,
            "path": "/ws",
            "headers": {"Origin": "http://localhost"},
            "body": None,
            "frames_in": [],
        },
        "expected": {
            "status": 101,
            "headers": {},
            "body": None,
            "frames_out": [],
            "close_code": close_code,
            "close_reason": close_reason,
        },
        "mock": {
            "provider": "scripted",
            "scripted_chunks": [],
            "api_key_required": True,
        },
        "notes": "api_key_required=True but no key cookie/header/query → server closes with code 1008.",
    }
    return _dump_fixture("ws_auth_fail", payload)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


_RECORDERS: dict[str, Any] = {
    "api_chat_success": record_api_chat_success,
    "api_chat_empty": record_api_chat_empty,
    "api_chat_413": record_api_chat_413,
    "api_chat_auth_required": record_api_chat_auth_required,
    "api_chat_provider_error": record_api_chat_provider_error,
    "ws_ping": record_ws_ping,
    "ws_message": record_ws_message,
    "ws_stream_success": record_ws_stream_success,
    "ws_stream_error": record_ws_stream_error,
    "ws_auth_fail": record_ws_auth_fail,
}


def _run(scenarios: Iterable[str]) -> int:
    written: list[Path] = []
    failed: list[tuple[str, str]] = []
    for name in scenarios:
        recorder = _RECORDERS.get(name)
        if recorder is None:
            failed.append((name, f"unknown scenario: {name}"))
            continue
        try:
            path = recorder()
            written.append(path)
            print(f"[ok] {name} -> {path.relative_to(_REPO_ROOT)}")
        except Exception as exc:  # noqa: BLE001 - top-level CLI surface
            failed.append((name, repr(exc)))
            print(f"[FAIL] {name}: {exc!r}", file=sys.stderr)
    if failed:
        print(f"\n{len(failed)} fixture(s) failed:", file=sys.stderr)
        for name, err in failed:
            print(f"  - {name}: {err}", file=sys.stderr)
        return 1
    print(f"\nWrote {len(written)} fixture file(s) to {_GOLDEN_DIR.relative_to(_REPO_ROOT)}/")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Record Echo golden fixtures for /api/chat and /ws.",
    )
    parser.add_argument(
        "scenarios",
        nargs="*",
        help=(f"Scenario names to record (default: all). Choices: {', '.join(sorted(_RECORDERS))}"),
    )
    args = parser.parse_args(argv)
    scenarios = args.scenarios or sorted(_RECORDERS)
    return _run(scenarios)


if __name__ == "__main__":
    raise SystemExit(main())
