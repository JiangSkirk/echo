"""F-13 e2e: WS ``type=stream`` must not leak provider secrets anywhere."""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch
from urllib.parse import quote, quote_plus

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from js.agent import JSAgent
from js.config import JSSettings, ModelConfig, ModelProviderConfig, SecurityConfig
from js.models.providers import OpenAICompatibleProvider
from js.models.stream_events import StreamEvent
from js.web.auth import AuthManager
from js.web.runtime_context import WebRuntime, bind_web_runtime

_SECRET = "xYz-NOT_A_SK_PREFIX_9876543210!@#"
_MODEL = ModelConfig(id="leak-model", name="Leak Model", context_window=4096)


def _leaky_message(secret: str = _SECRET) -> str:
    return (
        f"Client error '401' for url "
        f"'https://generativelanguage.googleapis.com/v1beta/models?key={secret}' "
        f"For more information check: detail={secret}"
    )


def _assert_secret_absent(secret: str, *values: Any) -> None:
    encoded = quote(secret, safe="")
    plus = quote_plus(secret)
    mixed_hex = "%61%2f%62"  # sample triplet pattern — must not appear verbatim for / in secrets
    for value in values:
        text = value if isinstance(value, str) else repr(value)
        assert secret not in text
        assert encoded not in text
        assert plus not in text
        assert encoded.upper() not in text
        assert plus.upper() not in text
        if "/" in secret:
            assert mixed_hex.lower() not in text.lower() or "****" in text


class _Circuit:
    async def can_execute(self) -> bool:
        return True

    async def record_success(self) -> None:
        return None

    async def record_failure(self) -> None:
        return None

    async def execute(self, coro: Any) -> Any:
        return await coro


def _leaky_stream_provider(secret: str = _SECRET) -> OpenAICompatibleProvider:
    provider = object.__new__(OpenAICompatibleProvider)
    provider.config = ModelProviderConfig(
        name="gemini-like",
        base_url="https://generativelanguage.googleapis.com/v1beta",
        api_key=secret,
        auth_adapter="query_param",
        query_param_name="key",
        default_model="leak-model",
        models=[_MODEL],
    )
    provider._is_local = False
    provider._last_stream_usage = None
    provider._stream_options_supported = True
    provider.circuit = _Circuit()

    async def leaky_stream_events(**_kwargs: Any) -> AsyncIterator[StreamEvent]:
        yield StreamEvent(
            kind="error",
            error=_leaky_message(secret),
            model="leak-model",
            meta={
                "retryable": False,
                "completion_tokens": 7,
                "api_key": secret,
                "raw_url": f"https://example.test?key={quote(secret, safe='')}",
                "diagnostic": _leaky_message(secret),
            },
        )

    provider.chat_stream_events = leaky_stream_events  # type: ignore[method-assign]
    provider.chat = AsyncMock(side_effect=RuntimeError(_leaky_message(secret)))
    provider.health_check = AsyncMock(return_value=True)
    provider.close = AsyncMock(return_value=None)
    return provider


def _build_app(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("JS_ALLOWED_ORIGINS", "http://localhost")
    import js.web.auth as auth_mod

    monkeypatch.setattr(auth_mod, "_ALLOWED_ORIGINS", None)

    @asynccontextmanager
    async def _noop_lifespan(_app: Any) -> AsyncIterator[None]:
        yield

    with patch("js.web.server.lifespan", _noop_lifespan):
        from js.web.server import create_app

        return create_app()


@pytest.mark.asyncio
async def test_ws_type_stream_scrubs_secrets_in_all_sinks(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
        echo_engine="on",
        max_turns=1,
    )
    (tmp_path / "workspace").mkdir(parents=True, exist_ok=True)
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)

    agent = JSAgent(settings)
    provider = _leaky_stream_provider()
    agent.router._providers = {"gemini-like": provider}
    agent.router._model_map = {
        "leak-model": ("gemini-like", _MODEL),
        "gemini-like/leak-model": ("gemini-like", _MODEL),
    }
    agent.router._routing_cache.clear()

    app = _build_app(monkeypatch)
    bind_web_runtime(
        app,
        WebRuntime(agent=agent, settings=settings, stats_store=None),
    )
    with (
        patch("js.web.server._settings", settings),
        patch("js.web.server._agent", agent),
        patch("js.web.server.get_agent", lambda: agent),
        patch("js.web.deps._agent", agent),
        patch("js.web.deps._settings", settings),
    ):
        user_key = AuthManager(settings.state_dir).create_key("ws-scrub", role="user")
        client = TestClient(
            app,
            base_url="http://localhost",
            headers={"Origin": "http://localhost", "X-API-Key": user_key},
        )
        ws_frames: list[str] = []
        with (
            caplog.at_level(logging.DEBUG),
            client.websocket_connect("/ws") as ws,
        ):
            ws.send_json(
                {
                    "type": "stream",
                    "content": "hello",
                    "session_id": "sess-f13-stream-e2e",
                    "model": "leak-model",
                }
            )
            deadline = time.time() + 8.0
            while time.time() < deadline:
                try:
                    msg = ws.receive_json()
                except WebSocketDisconnect:
                    break
                ws_frames.append(repr(msg))
                if msg.get("type") in {"error", "done", "result", "stream_diagnostic"}:
                    if msg.get("type") == "result":
                        break
                    if msg.get("type") in {"error", "done"} and msg.get("terminal"):
                        break
                    if msg.get("type") == "stream_diagnostic":
                        # Keep reading until terminal frame.
                        continue

    await agent.close()

    state_repr = ""
    for record in caplog.records:
        if "Run complete" in record.getMessage() or "error" in record.getMessage().lower():
            state_repr += repr(getattr(record, "extra", {}))

    sinks = [
        caplog.text,
        *ws_frames,
        state_repr,
    ]
    for sink in sinks:
        _assert_secret_absent(_SECRET, sink)

    diagnostic_frames = [f for f in ws_frames if "stream_diagnostic" in f]
    assert diagnostic_frames, "expected stream_diagnostic frame from provider error"
    for frame in diagnostic_frames:
        _assert_secret_absent(_SECRET, frame)

    assert any("error" in f or "stream_diagnostic" in f for f in ws_frames)
