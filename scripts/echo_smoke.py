#!/usr/bin/env python3
"""Local Echo smoke test.

This script is intentionally self-contained and deterministic. It does not
contact a real LLM provider. Instead it drives the real FastAPI `/api/chat`
router through a real `JSAgent` instance wired to a fake provider, then checks
that `/ws` still preserves its basic ping contract.

It is a convenience gate for local operators:

    JS_ECHO_ENGINE=on  .venv/bin/python scripts/echo_smoke.py

The script exercises the Echo-only runtime. Removed rollout values such as
`off` and `shadow` are rejected by configuration instead of being smoked.
"""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from js.agent import JSAgent
from js.config import JSSettings, ModelConfig, SecurityConfig
from js.echo.context_runtime import (
    get_context_runtime_snapshot_for_tests,
    reset_context_runtime_for_tests,
)
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter
from js.web.routers.chat import router as chat_router


class EchoSmokeError(RuntimeError):
    """Human-readable smoke failure."""


class _Provider(ModelProvider):
    def __init__(self) -> None:
        self.calls: list[tuple[list[ChatMessage], list[dict[str, Any]] | None]] = []

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.calls.append((messages, tools))
        return ChatResponse(
            content="echo smoke ok",
            tool_calls=[],
            model="mock",
            usage={"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14},
            finish_reason="stop",
        )

    def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        async def _gen() -> AsyncIterator[str]:
            yield "echo smoke ok"

        return _gen()

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


class _Router(ModelRouter):
    def __init__(self, provider: _Provider, *, permit_verifier: Any) -> None:
        self.settings = JSSettings()
        model = ModelConfig(id="mock", name="Mock", provider="mock")
        self._providers: dict[str, ModelProvider] = {"mock": provider}
        self._model_map: dict[str, tuple[str, ModelConfig]] = {
            "mock": ("mock", model),
            "mock/mock": ("mock", model),
        }
        self._permit_verifier = permit_verifier

    async def select_model(
        self, task_complexity: str = "medium", preferred: str | None = None
    ) -> Any:
        from js.models.router import RoutingDecision

        return RoutingDecision(
            provider=self._providers["mock"],
            model="mock",
            provider_name="mock",
            reason="mock",
        )

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        before_model_call: Callable[..., Any] | None = None,
        after_model_call: Callable[..., Any] | None = None,
        permit_grant: Callable[..., Any] | None = None,
    ) -> ChatResponse:
        if before_model_call is None or after_model_call is None or permit_grant is None:
            raise RuntimeError("Echo smoke router requires model callbacks and permit grant")
        decision = await self.select_model(preferred=model)
        self._consume_model_permit(permit_grant, decision, messages, tools)
        context = await before_model_call(decision, messages, tools)
        response: ChatResponse | None = None
        error: BaseException | None = None
        try:
            response = await decision.provider.chat(
                messages=messages,
                model=decision.model,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return response
        except BaseException as exc:  # noqa: BLE001 - finalize exact failure
            error = exc
            response = None
            raise
        finally:
            await after_model_call(context, response, error)


def _settings(base: Path) -> JSSettings:
    return JSSettings(
        workspace=base / "workspace",
        state_dir=base / "state",
        max_turns=3,
        security=SecurityConfig(api_key_required=False),
    )


def _check_api_chat(mode: str, base: Path) -> None:
    os.environ["JS_ECHO_ENGINE"] = mode
    reset_context_runtime_for_tests()
    provider = _Provider()
    settings = _settings(base / f"chat-{mode}")
    agent = JSAgent(settings)
    agent.router = _Router(provider, permit_verifier=agent._model_permit_issuer)

    # F-01 semantics: anonymous requests are read-only guests even when
    # api_key_required=false; mutating endpoints require explicit credentials.
    from js.web.auth import AuthManager

    admin_key = AuthManager(settings.state_dir).ensure_bootstrap_admin_key()
    if not admin_key:
        raise EchoSmokeError("Echo smoke could not create a bootstrap admin key")

    app = FastAPI()
    app.include_router(chat_router)
    with (
        patch("js.web.server._settings", settings),
        patch("js.web.deps._settings", settings),
        patch("js.web.routers.chat.get_agent", return_value=agent),
        patch("js.web.routers.chat.get_stats_store", return_value=None),
    ):
        client = TestClient(
            app,
            base_url="http://localhost",
            headers={"Origin": "http://localhost"},
        )
        resp = client.post(
            "/api/chat",
            json={"message": "run echo smoke", "session_id": f"echo-smoke-{mode}"},
            headers={"x-api-key": admin_key},
        )

    if resp.status_code != 200:
        raise EchoSmokeError(f"/api/chat failed in {mode}: HTTP {resp.status_code} {resp.text}")
    data = resp.json()
    if data.get("response") != "echo smoke ok":
        raise EchoSmokeError(f"/api/chat wrong response in {mode}: {data!r}")
    if len(provider.calls) != 1:
        raise EchoSmokeError(f"/api/chat provider call count in {mode}: {len(provider.calls)}")

    snapshot = get_context_runtime_snapshot_for_tests()
    if snapshot.observation_count != 1 or snapshot.last_observation is None:
        raise EchoSmokeError("Echo mode did not record context metrics")
    if snapshot.last_observation.mode != mode:
        raise EchoSmokeError(
            f"{mode} mode recorded wrong observation mode: "
            f"{snapshot.last_observation.mode!r}"
        )
    if snapshot.last_observation.naive_tokens <= 0:
        raise EchoSmokeError("Echo mode recorded empty prompt metrics")


def _make_ws_agent() -> MagicMock:
    agent = MagicMock()
    agent.router.get_model_config.return_value = None
    agent._dream_scheduler = MagicMock()
    agent.run = AsyncMock()
    return agent


def _check_ws_ping(mode: str, base: Path) -> None:
    os.environ["JS_ECHO_ENGINE"] = mode
    os.environ["JS_ALLOWED_ORIGINS"] = "http://localhost"

    import js.web.auth as auth_mod

    auth_mod._ALLOWED_ORIGINS = None

    @asynccontextmanager
    async def _noop_lifespan(_app: Any) -> AsyncIterator[None]:
        yield

    with patch("js.web.server.lifespan", _noop_lifespan):
        from js.web.server import create_app

        app = create_app()

    settings = _settings(base / f"ws-{mode}")
    agent = _make_ws_agent()
    agent.settings = settings
    with (
        patch("js.web.server._settings", settings),
        patch("js.web.server._agent", agent),
        patch("js.web.server.get_agent", return_value=agent),
        patch("js.web.deps._settings", settings),
        patch("js.web.deps._agent", agent),
    ):
        client = TestClient(
            app,
            base_url="http://localhost",
            headers={"Origin": "http://localhost"},
        )
        with client.websocket_connect("/ws", headers={"Origin": "http://localhost"}) as ws:
            ws.send_json({"type": "ping"})
            frame = ws.receive_json()

    if frame != {"type": "pong"}:
        raise EchoSmokeError(f"/ws ping wrong frame in {mode}: {frame!r}")


def run_smoke() -> None:
    incoming = os.environ.get("JS_ECHO_ENGINE", "<unset>")
    print(f"Echo smoke starting; incoming JS_ECHO_ENGINE={incoming}")
    with tempfile.TemporaryDirectory(prefix="echo-smoke-") as tmp:
        base = Path(tmp)
        mode = "on"
        _check_api_chat(mode, base)
        _check_ws_ping(mode, base)
        print("PASS on: /api/chat + /ws")
    print("Echo smoke passed for Echo on")


def main() -> int:
    try:
        run_smoke()
    except EchoSmokeError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
