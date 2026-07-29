"""Round 1 attack tests: ModelRouter stream-events callback bypass.

``chat_stream_events()`` must not accept arbitrary callback pairs.  The gate
is now an unforgeable single-use permit (P0-1 fix); these tests verify forged
callers are rejected and genuine runtime permits are accepted.
"""

from __future__ import annotations

import pathlib
from collections.abc import AsyncGenerator
from typing import Any

import pytest

from js.config import JSSettings, ModelConfig
from js.models.permit import ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter
from js.models.stream_events import StreamEvent


class _StubStreamProvider(ModelProvider):
    def __init__(self, name: str = "stub") -> None:
        self.name = name

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:  # pragma: no cover - not exercised in stream tests
        return ChatResponse(
            content="stub",
            tool_calls=[],
            model=model,
            usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            finish_reason="stop",
        )

    def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> Any:
        raise NotImplementedError

    async def chat_stream_events(
        self,
        *,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncGenerator[StreamEvent, None]:
        yield StreamEvent(kind="text_delta", text="hello")
        yield StreamEvent(kind="done", finish_reason="stop")

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        return None


def _router_with_stub() -> tuple[ModelRouter, ModelPermitIssuer]:
    settings = JSSettings(workspace=pathlib.Path("/tmp/x"), providers=[])
    issuer = ModelPermitIssuer()
    router = ModelRouter(settings, permit_verifier=issuer)
    router.add_provider(
        "stub",
        _StubStreamProvider(),
        [ModelConfig(id="m1", name="m1", provider="stub")],
    )
    return router, issuer


def _grant(issuer: ModelPermitIssuer):
    def grant(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        return issuer.issue(
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
            owner_key_hash="owner",
            session_id="session",
            run_id="run",
        )

    return grant


@pytest.mark.asyncio
async def test_chat_stream_events_rejects_forged_callbacks() -> None:
    """A forged callback pair without a runtime permit must NOT be accepted."""
    router, _issuer = _router_with_stub()

    async def _forged_before(*_a: Any, **_kw: Any) -> Any:
        return None

    async def _forged_after(*_a: Any, **_kw: Any) -> None:
        return None

    assert not hasattr(router, "bind_echo_callbacks")
    with pytest.raises(RuntimeError, match="permit_grant"):
        async for _ in router.chat_stream_events(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_forged_before,
            after_model_call=_forged_after,
        ):
            pass


@pytest.mark.asyncio
async def test_chat_stream_events_rejects_missing_callbacks() -> None:
    """Calling stream with None callbacks must fail closed."""
    router, _issuer = _router_with_stub()

    with pytest.raises(RuntimeError):
        async for _ in router.chat_stream_events(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=None,
            after_model_call=None,
        ):
            pass


@pytest.mark.asyncio
async def test_chat_stream_events_accepts_runtime_permit() -> None:
    """The runtime-issued permit authorizes streaming through the gate."""
    router, issuer = _router_with_stub()

    async def _real_before(*_a: Any, **_kw: Any) -> Any:
        return None

    async def _real_after(*_a: Any, **_kw: Any) -> None:
        return None

    events = []
    async for ev in router.chat_stream_events(
        messages=[ChatMessage(role="user", content="hi")],
        model="stub/m1",
        before_model_call=_real_before,
        after_model_call=_real_after,
        permit_grant=_grant(issuer),
    ):
        events.append(ev)
    kinds = [e.kind for e in events]
    assert "text_delta" in kinds
    assert "done" in kinds
