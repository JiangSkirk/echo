from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any

import pytest

from js.config import JSSettings, ModelConfig
from js.models.permit import ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter
from js.models.stream_events import StreamEvent


class _StreamingProvider(ModelProvider):
    def __init__(self) -> None:
        self.stream_calls = 0
        self.chat_calls = 0
        self.event_calls = 0

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.chat_calls += 1
        return ChatResponse(
            content="ok",
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
    ) -> AsyncIterator[str]:
        async def _gen() -> AsyncIterator[str]:
            self.stream_calls += 1
            yield "hello"

        return _gen()

    async def chat_stream_events(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[StreamEvent]:
        self.event_calls += 1
        yield StreamEvent(kind="text_delta", text="hello")
        yield StreamEvent(kind="done", finish_reason="stop")

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


class _ScriptedStreamingProvider(_StreamingProvider):
    def __init__(
        self,
        events: list[StreamEvent],
        *,
        exception: BaseException | None = None,
        block_after_events: bool = False,
    ) -> None:
        super().__init__()
        self.events = events
        self.exception = exception
        self.block_after_events = block_after_events
        self.max_tokens: list[int | None] = []

    async def chat_stream_events(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[StreamEvent]:
        del messages, model, tools, temperature
        self.event_calls += 1
        self.max_tokens.append(max_tokens)
        for event in self.events:
            yield event
        if self.block_after_events:
            await asyncio.Event().wait()
        if self.exception is not None:
            raise self.exception


def _router(provider: _StreamingProvider) -> ModelRouter:
    router = ModelRouter(JSSettings(providers=[]), permit_verifier=ModelPermitIssuer())
    router.add_provider("mock", provider, [ModelConfig(id="mock-model", name="mock")])
    return router


def _router_with_fallback(
    primary: _StreamingProvider,
    backup: _StreamingProvider,
) -> ModelRouter:
    router = ModelRouter(JSSettings(providers=[]), permit_verifier=ModelPermitIssuer())
    router.add_provider("primary", primary, [ModelConfig(id="primary-model", name="primary")])
    router.add_provider("backup", backup, [ModelConfig(id="backup-model", name="backup")])
    return router


def _grant(router: ModelRouter) -> Any:
    """Issue a fresh single-use permit per provider attempt, like the runtime."""
    issuer = router._permit_verifier
    assert isinstance(issuer, ModelPermitIssuer)

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


def _hooks(router: ModelRouter | None = None) -> tuple[
    Any,
    Any,
    list[tuple[str, ChatResponse | None, BaseException | None]],
]:
    finalizations: list[tuple[str, ChatResponse | None, BaseException | None]] = []

    async def _before(decision: Any, *_args: Any) -> str:
        return str(decision.provider_name)

    async def _after(
        context: str,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        finalizations.append((context, response, error))

    if router is not None:
        assert not hasattr(router, "bind_echo_callbacks")

    return _before, _after, finalizations


@pytest.mark.asyncio
async def test_chat_stream_echo_on_fails_closed_to_gated_event_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    provider = _StreamingProvider()
    router = _router(provider)

    with pytest.raises(RuntimeError, match="chat_stream_events"):
        async for _token in router.chat_stream([ChatMessage(role="user", content="hi")]):
            pass

    assert provider.stream_calls == 0


@pytest.mark.asyncio
async def test_chat_stream_events_still_runs_provider_before_after_gates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    provider = _StreamingProvider()
    router = _router(provider)
    calls: list[str] = []

    async def _before(*_args: Any) -> str:
        calls.append("before")
        return "ctx"

    async def _after(context: Any, response: ChatResponse | None, error: BaseException | None) -> None:
        calls.append(f"after:{context}:{response.content if response else None}:{error}")

    router_grant = _grant(router)
    events = [
        event.kind
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            before_model_call=_before,
            after_model_call=_after,
            permit_grant=router_grant,
        )
    ]

    assert events == ["text_delta", "done"]
    assert calls == ["before", "after:ctx:hello:None"]


@pytest.mark.asyncio
async def test_each_stream_reconnect_gets_a_fresh_echo_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _ReconnectProvider(_StreamingProvider):
        def __init__(self) -> None:
            super().__init__()
            self.config = SimpleNamespace(max_retries=3)

        async def chat_stream_events(self, **_kwargs: Any) -> AsyncIterator[StreamEvent]:
            self.event_calls += 1
            if self.event_calls < 3:
                yield StreamEvent(
                    kind="error",
                    error="temporary stream transport failure",
                    meta={"retryable": True},
                )
                return
            yield StreamEvent(kind="text_delta", text="recovered")
            yield StreamEvent(kind="done", finish_reason="stop")

    async def no_wait(_delay: float) -> None:
        return None

    provider = _ReconnectProvider()
    router = _router(provider)
    monkeypatch.setattr("js.models.router.asyncio.sleep", no_wait)
    admissions = 0
    finalizations: list[tuple[str, ChatResponse | None, BaseException | None]] = []

    async def before(*_args: Any) -> str:
        nonlocal admissions
        admissions += 1
        return f"ctx-{admissions}"

    async def after(
        context: str,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        finalizations.append((context, response, error))

    output = [
        event
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model="mock/mock-model",
            before_model_call=before,
            after_model_call=after,
            permit_grant=_grant(router),
        )
    ]

    assert [event.kind for event in output] == ["text_delta", "done"]
    assert provider.event_calls == 3
    assert admissions == 3
    assert [item[0] for item in finalizations] == ["ctx-1", "ctx-2", "ctx-3"]
    assert all(item[2] is not None for item in finalizations[:2])
    assert finalizations[2][1] is not None and finalizations[2][2] is None


@pytest.mark.asyncio
async def test_chat_stream_events_finalize_when_consumer_closes_early() -> None:
    provider = _ScriptedStreamingProvider(
        [
            StreamEvent(
                kind="usage",
                usage={"prompt_tokens": 7, "completion_tokens": 4, "total_tokens": 11},
            ),
            StreamEvent(kind="text_delta", text="hello"),
        ],
        block_after_events=True,
    )
    router = _router(provider)
    finalizations: list[tuple[Any, ChatResponse | None, BaseException | None]] = []

    async def _before(*_args: Any) -> str:
        return "ctx"

    async def _after(
        context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        finalizations.append((context, response, error))

    stream = router.chat_stream_events(
        [ChatMessage(role="user", content="hi")],
        before_model_call=_before,
        after_model_call=_after,
        permit_grant=_grant(router),
    )
    assert (await anext(stream)).kind == "usage"
    first = await anext(stream)
    await stream.aclose()

    assert first.kind == "text_delta"
    assert len(finalizations) == 1
    assert finalizations[0][0] == "ctx"
    assert finalizations[0][1] is None
    assert isinstance(finalizations[0][2], RuntimeError)
    assert "closed early" in str(finalizations[0][2]).lower()
    assert getattr(finalizations[0][2], "completion_tokens", None) == 4
    assert getattr(finalizations[0][2], "token_source", None) == "provider_actual"
    assert getattr(finalizations[0][2], "provider_reported_completion_tokens", None) == 4


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("terminal", "message"),
    [
        (StreamEvent(kind="error", error="provider failed"), "provider failed"),
        (RuntimeError("provider exploded"), "provider exploded"),
    ],
)
async def test_partial_text_failure_finalizes_once_without_fallback(
    terminal: StreamEvent | BaseException,
    message: str,
) -> None:
    events = [
        StreamEvent(kind="text_delta", text="partial"),
        StreamEvent(
            kind="usage",
            usage={"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12},
        ),
    ]
    exception = terminal if isinstance(terminal, BaseException) else None
    if isinstance(terminal, StreamEvent):
        events.append(terminal)
    primary = _ScriptedStreamingProvider(events, exception=exception)
    backup = _ScriptedStreamingProvider(
        [
            StreamEvent(kind="text_delta", text="duplicate"),
            StreamEvent(kind="done", finish_reason="stop"),
        ]
    )
    router = _router_with_fallback(primary, backup)
    before, after, finalizations = _hooks(router)

    if exception is None:
        output = [
            event
            async for event in router.chat_stream_events(
                [ChatMessage(role="user", content="hi")],
                before_model_call=before,
                after_model_call=after,
                permit_grant=_grant(router),
            )
        ]
        assert [event.kind for event in output] == ["text_delta", "usage", "error"]
    else:
        with pytest.raises(RuntimeError, match=message):
            async for _event in router.chat_stream_events(
                [ChatMessage(role="user", content="hi")],
                before_model_call=before,
                after_model_call=after,
                permit_grant=_grant(router),
            ):
                pass

    assert backup.event_calls == 0
    assert len(finalizations) == 1
    context, response, error = finalizations[0]
    assert context == "primary"
    assert response is None
    assert error is not None and message in str(error)
    assert getattr(error, "completion_tokens", None) == 5
    assert getattr(error, "assistant_text", None) == "partial"
    assert getattr(error, "token_source", None) == "provider_actual"
    assert getattr(error, "provider_reported_completion_tokens", None) == 5
    assert getattr(error, "provider_reported_total_tokens", None) == 12


@pytest.mark.asyncio
@pytest.mark.parametrize("primary_events", [[], [StreamEvent(kind="error", error="failed")]])
async def test_zero_text_failure_can_fallback(primary_events: list[StreamEvent]) -> None:
    primary = _ScriptedStreamingProvider(primary_events)
    backup = _ScriptedStreamingProvider(
        [
            StreamEvent(kind="text_delta", text="backup"),
            StreamEvent(kind="done", finish_reason="stop"),
        ]
    )
    router = _router_with_fallback(primary, backup)
    before, after, finalizations = _hooks(router)

    output = [
        event
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            before_model_call=before,
            after_model_call=after,
            permit_grant=_grant(router),
        )
    ]

    assert [event.kind for event in output] == ["text_delta", "done"]
    assert backup.event_calls == 1
    assert [item[0] for item in finalizations] == ["primary", "backup"]
    assert finalizations[0][1] is None
    assert finalizations[0][2] is not None
    assert finalizations[1][1] is not None
    assert finalizations[1][2] is None


@pytest.mark.asyncio
async def test_zero_text_exception_can_fallback() -> None:
    primary = _ScriptedStreamingProvider([], exception=RuntimeError("failed before output"))
    backup = _ScriptedStreamingProvider(
        [
            StreamEvent(kind="text_delta", text="backup"),
            StreamEvent(kind="done", finish_reason="stop"),
        ]
    )
    router = _router_with_fallback(primary, backup)
    before, after, finalizations = _hooks(router)

    output = [
        event
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            before_model_call=before,
            after_model_call=after,
            permit_grant=_grant(router),
        )
    ]

    assert [event.kind for event in output] == ["text_delta", "done"]
    assert backup.event_calls == 1
    assert [item[0] for item in finalizations] == ["primary", "backup"]


@pytest.mark.asyncio
async def test_provider_usage_failure_reduces_fallback_max_tokens() -> None:
    primary = _ScriptedStreamingProvider(
        [
            StreamEvent(
                kind="usage",
                usage={"prompt_tokens": 9, "completion_tokens": 3, "total_tokens": 12},
            ),
            StreamEvent(kind="error", error="failed after reasoning"),
        ]
    )
    backup = _ScriptedStreamingProvider(
        [
            StreamEvent(kind="text_delta", text="ok"),
            StreamEvent(kind="done", finish_reason="stop"),
        ]
    )
    router = _router_with_fallback(primary, backup)
    before, after, finalizations = _hooks(router)

    output = [
        event
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            max_tokens=5,
            before_model_call=before,
            after_model_call=after,
            permit_grant=_grant(router),
        )
    ]

    assert [event.kind for event in output] == ["usage", "text_delta", "done"]
    assert primary.max_tokens == [5]
    assert backup.max_tokens == [2]
    primary_error = finalizations[0][2]
    assert primary_error is not None
    assert getattr(primary_error, "completion_tokens", None) == 3
    assert getattr(primary_error, "token_source", None) == "provider_actual"
    assert getattr(primary_error, "provider_reported_completion_tokens", None) == 3


@pytest.mark.asyncio
async def test_partial_failure_does_not_label_text_estimate_as_provider_actual() -> None:
    provider = _ScriptedStreamingProvider(
        [
            StreamEvent(kind="text_delta", text="abcdefgh"),
            StreamEvent(
                kind="usage",
                usage={"prompt_tokens": 6, "completion_tokens": 1, "total_tokens": 7},
            ),
            StreamEvent(kind="error", error="failed"),
        ]
    )
    router = _router(provider)
    before, after, finalizations = _hooks(router)

    output = [
        event
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            before_model_call=before,
            after_model_call=after,
            permit_grant=_grant(router),
        )
    ]

    assert [event.kind for event in output] == ["text_delta", "usage", "error"]
    error = finalizations[0][2]
    assert error is not None
    assert getattr(error, "completion_tokens", None) == 2
    assert getattr(error, "token_source", None) == "estimated"
    assert getattr(error, "provider_reported_completion_tokens", None) == 1
    assert output[-1].meta["provider_reported_completion_tokens"] == 1


@pytest.mark.asyncio
async def test_natural_end_after_text_is_terminal_error_without_fallback() -> None:
    primary = _ScriptedStreamingProvider(
        [
            StreamEvent(kind="text_delta", text="partial"),
            StreamEvent(
                kind="usage",
                usage={"prompt_tokens": 6, "completion_tokens": 4, "total_tokens": 10},
            ),
        ]
    )
    backup = _ScriptedStreamingProvider(
        [StreamEvent(kind="text_delta", text="duplicate"), StreamEvent(kind="done")]
    )
    router = _router_with_fallback(primary, backup)
    before, after, finalizations = _hooks(router)

    output = [
        event
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            before_model_call=before,
            after_model_call=after,
            permit_grant=_grant(router),
        )
    ]

    assert [event.kind for event in output] == ["text_delta", "usage", "error"]
    assert "without done" in output[-1].error.lower()
    assert backup.event_calls == 0
    assert len(finalizations) == 1
    assert finalizations[0][1] is None
    assert getattr(finalizations[0][2], "completion_tokens", None) == 4
    assert getattr(finalizations[0][2], "token_source", None) == "provider_actual"
    assert output[-1].meta["completion_tokens"] == 4
    assert output[-1].meta["token_source"] == "provider_actual"
    assert output[-1].meta["provider_reported_completion_tokens"] == 4


@pytest.mark.asyncio
async def test_after_callback_exception_does_not_refinalize_or_fallback() -> None:
    primary = _ScriptedStreamingProvider(
        [StreamEvent(kind="text_delta", text="ok"), StreamEvent(kind="done")]
    )
    backup = _ScriptedStreamingProvider([StreamEvent(kind="done")])
    router = _router_with_fallback(primary, backup)
    calls = 0

    async def _before(*_args: Any) -> str:
        return "ctx"

    async def _after(*_args: Any) -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("after failed")

    with pytest.raises(RuntimeError, match="after failed"):
        async for _event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            before_model_call=_before,
            after_model_call=_after,
            permit_grant=_grant(router),
        ):
            pass

    assert calls == 1
    assert backup.event_calls == 0


@pytest.mark.asyncio
async def test_stream_cancellation_finalizes_partial_output_once() -> None:
    provider = _ScriptedStreamingProvider(
        [
            StreamEvent(
                kind="usage",
                usage={"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12},
            ),
            StreamEvent(kind="text_delta", text="partial"),
        ],
        block_after_events=True,
    )
    router = _router(provider)
    before, after, finalizations = _hooks(router)
    stream = router.chat_stream_events(
        [ChatMessage(role="user", content="hi")],
        before_model_call=before,
        after_model_call=after,
        permit_grant=_grant(router),
    )

    assert (await anext(stream)).kind == "usage"
    assert (await anext(stream)).text == "partial"
    pending = asyncio.create_task(anext(stream))
    await asyncio.sleep(0)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending

    assert len(finalizations) == 1
    assert isinstance(finalizations[0][2], asyncio.CancelledError)
    assert getattr(finalizations[0][2], "completion_tokens", None) == 4
    assert getattr(finalizations[0][2], "token_source", None) == "provider_actual"
    assert getattr(finalizations[0][2], "provider_reported_completion_tokens", None) == 4


@pytest.mark.asyncio
async def test_stream_cancellation_surfaces_finalization_failure() -> None:
    provider = _ScriptedStreamingProvider(
        [StreamEvent(kind="text_delta", text="partial")],
        block_after_events=True,
    )
    router = _router(provider)

    async def before(*_args: Any) -> str:
        return "ctx"

    async def failing_after(*_args: Any) -> None:
        raise OSError("journal unavailable")

    stream = router.chat_stream_events(
        [ChatMessage(role="user", content="hi")],
        before_model_call=before,
        after_model_call=failing_after,
        permit_grant=_grant(router),
    )
    assert (await anext(stream)).text == "partial"
    pending = asyncio.create_task(anext(stream))
    await asyncio.sleep(0)
    pending.cancel("cancel stream")

    with pytest.raises(OSError, match="journal unavailable"):
        await pending


@pytest.mark.asyncio
async def test_chat_cancellation_surfaces_finalization_failure() -> None:
    provider = _StreamingProvider()
    router = _router(provider)
    entered = asyncio.Event()

    async def blocking_chat(*_args: Any, **_kwargs: Any) -> ChatResponse:
        entered.set()
        await asyncio.Event().wait()
        raise AssertionError("provider should have been cancelled")

    provider.chat = blocking_chat  # type: ignore[method-assign]

    async def before(*_args: Any) -> str:
        return "ctx"

    async def failing_after(*_args: Any) -> None:
        raise OSError("journal unavailable")

    pending = asyncio.create_task(
        router.chat(
            [ChatMessage(role="user", content="hi")],
            before_model_call=before,
            after_model_call=failing_after,
            permit_grant=_grant(router),
        )
    )
    await entered.wait()
    pending.cancel("cancel chat")

    with pytest.raises(OSError, match="journal unavailable"):
        await pending


@pytest.mark.asyncio
async def test_chat_echo_on_requires_model_gate_callbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    provider = _StreamingProvider()
    router = _router(provider)

    with pytest.raises(RuntimeError, match="before_model_call"):
        await router.chat([ChatMessage(role="user", content="hi")])

    assert provider.chat_calls == 0


@pytest.mark.asyncio
async def test_chat_stream_events_echo_on_requires_model_gate_callbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    provider = _StreamingProvider()
    router = _router(provider)

    with pytest.raises(RuntimeError, match="before_model_call"):
        async for _event in router.chat_stream_events([ChatMessage(role="user", content="hi")]):
            pass

    assert provider.event_calls == 0
