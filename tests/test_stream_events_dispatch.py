"""Tests for the PR-4.3 WebSocket realtime channel wiring.

Scope: verify that ``EchoTurnLoop._get_response`` consumes the PR-4.2
``chat_stream_events()`` feed and dispatches the structured event kinds to
``event_callback`` correctly, while ``stream_callback`` keeps receiving
plain text-delta tokens (legacy contract). This is the seam the WebSocket
handler in ``js/web/server.py`` plugs into; covering it here proves the
channel works without spinning up an HTTP server.

Coverage:

* ``text_delta`` goes to ``stream_callback`` (NOT ``event_callback``).
* ``thinking_delta`` → event_callback with ``{kind:"thinking_delta", text}``.
* ``tool_call_delta`` → event_callback with secret-bearing fields redacted.
* ``usage`` event from the stream is forwarded AND used as the authoritative
  usage source for the returned ChatResponse (provider-cached
  ``_last_stream_usage`` is the fallback, heuristic is the last resort).
* Secrets are redacted in both text and thinking deltas via
  ``agent.secrets.detect_and_redact``.
* An ``event_callback`` that raises does NOT abort the stream — the
  legacy text-only path keeps producing tokens.
* When the stream emits an ``error`` event the executor surfaces it
  upward as a RuntimeError (so the existing agent error path records it).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.echo.context_tokenizer import BoundTokenCounter, TokenCounter
from js.echo.durable_thread import EchoDurableExecutor
from js.echo.turn_context import RuntimeContext, reset_runtime_context, set_runtime_context
from js.echo.turn_loop import EchoTurnLoop
from js.echo.turn_runtime import EchoRuntime
from js.models.permit import ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse
from js.models.stream_events import StreamEvent
from js.security.secrets import SecretManager

_TEST_DURABLE_EXECUTOR = EchoDurableExecutor(
    max_claim_pending=8,
    max_finish_pending=8,
    claim_workers=2,
    finish_workers=2,
    thread_name_prefix="echo-stream-event-test",
)

_TEST_TOKEN_UNIT_ID = "test:stream-events/token-unit:v1"


@pytest.fixture(scope="module", autouse=True)
def _close_test_durable_executor() -> Iterator[None]:
    yield
    _TEST_DURABLE_EXECUTOR.shutdown(wait=True)


class _FakeProvider:
    """Minimal provider yielding a scripted StreamEvent sequence."""

    def __init__(self, events: list[StreamEvent]) -> None:
        self._events = events
        self.seen_tools: list[dict[str, Any]] | None = None
        # The real OpenAICompatibleProvider exposes a cached usage dict here;
        # leaving it as None forces the executor to rely on the in-stream
        # usage event when present (the PR-4.3 preferred path).
        self._last_stream_usage: dict[str, int] | None = None

    async def chat_stream_events(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[StreamEvent]:
        self.seen_tools = tools
        for ev in self._events:
            yield ev


class _FakeRouter:
    """Minimal gated router matching the production Echo stream contract."""

    def __init__(self, provider: _FakeProvider) -> None:
        self.provider = provider
        self._permit_verifier = ModelPermitIssuer()

    async def chat_stream_events(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        temperature: float = 0.7,
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int | None = None,
        before_model_call: Any = None,
        after_model_call: Any = None,
        permit_grant: Any = None,
    ) -> AsyncIterator[StreamEvent]:
        del max_tokens
        decision = SimpleNamespace(
            provider=self.provider,
            model=model or "m1",
            provider_name="fake",
        )
        # Match the production gate: a fresh single-use permit per attempt.
        assert permit_grant is not None
        self._permit_verifier.verify_and_consume(
            permit_grant(decision, messages, tools),
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
        )
        context = await before_model_call(decision, messages, tools)
        text_parts: list[str] = []
        usage: dict[str, int] = {}
        finalized = False
        try:
            async for event in self.provider.chat_stream_events(
                messages=messages,
                model=decision.model,
                tools=tools,
                temperature=temperature,
            ):
                event.model = event.model or decision.model
                event.provider = event.provider or decision.provider_name
                if event.kind == "text_delta" and event.text:
                    text_parts.append(event.text)
                elif event.kind == "usage" and event.usage:
                    usage = dict(event.usage)
                elif event.kind == "error":
                    await after_model_call(
                        context,
                        None,
                        RuntimeError(event.error or "stream error"),
                    )
                    finalized = True
                    yield event
                    return
                yield event
                if event.kind == "done":
                    await after_model_call(
                        context,
                        _stream_response(decision.model, text_parts, usage, event.finish_reason),
                        None,
                    )
                    finalized = True
                    return
            await after_model_call(
                context,
                _stream_response(decision.model, text_parts, usage, "stop"),
                None,
            )
            finalized = True
        except Exception as exc:
            if not finalized:
                await after_model_call(context, None, exc)
            raise


def _stream_response(
    model: str,
    text_parts: list[str],
    usage: dict[str, int],
    finish_reason: str | None,
) -> ChatResponse:
    return ChatResponse(
        content="".join(text_parts),
        tool_calls=[],
        model=model,
        usage=usage,
        finish_reason=finish_reason or "stop",
    )


class _FakeSecrets:
    """Pass-through secret manager that records every redaction call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.replacements: dict[str, str] = {}

    def detect_and_redact(self, text: str, kind: str) -> str:
        self.calls.append((kind, text))
        for needle, mask in self.replacements.items():
            text = text.replace(needle, mask)
        return text


class _FakeEchoSafetyService:
    def __init__(self) -> None:
        self.authorized: list[dict[str, Any]] = []
        self.finished: list[dict[str, Any]] = []

    def authorize_model_call(self, **kwargs: Any) -> SimpleNamespace:
        self.authorized.append(kwargs)
        return SimpleNamespace(run_id=kwargs.get("run_id"))

    def finish_chat_turn(self, context: Any, **kwargs: Any) -> None:
        self.finished.append({"context": context, **kwargs})


def _make_executor(
    events: list[StreamEvent],
    *,
    stream_callback: Any,
    event_callback: Any,
    secrets: _FakeSecrets | None = None,
) -> tuple[EchoTurnLoop, _FakeProvider, _FakeSecrets]:
    """Build a EchoTurnLoop wired to fakes; _get_response will run.

    The constructor needs an ``AgentBase`` — we feed in a SimpleNamespace
    matching only the attributes ``_get_response`` actually touches:
    ``router.select_model``, ``secrets.detect_and_redact``, ``logger``.
    """
    provider = _FakeProvider(events)
    secrets_obj = secrets or _FakeSecrets()

    fake_agent = SimpleNamespace(
        router=_FakeRouter(provider),
        secrets=secrets_obj,
        settings=SimpleNamespace(
            echo_engine="on",
            product_id="js-agent",
            workspace=Path.cwd(),
            state_dir=Path.cwd(),
            echo_budget=SimpleNamespace(
                max_prompt_tokens=200_000,
                max_completion_tokens=32_768,
                max_tool_calls=32,
                max_journal_appends=128,
                max_elapsed_ms=900_000,
            ),
        ),
        echo_safety_service=_FakeEchoSafetyService(),
        _echo_durable_executor=_TEST_DURABLE_EXECUTOR,
        logger=SimpleNamespace(
            warning=lambda *a, **kw: None,
            info=lambda *a, **kw: None,
            error=lambda *a, **kw: None,
        ),
    )
    fake_agent.echo_runtime = EchoRuntime(fake_agent)
    set_runtime_context(
        fake_agent.echo_runtime.build_context(
            channel="test-stream",
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
            role="test",
            profile="default",
            capabilities=(),
        )
    )
    executor = EchoTurnLoop(
        agent=fake_agent,
        user_input="hi",
        session_id="session-a",
        model=None,
        attachments=None,
        resume_state=None,
        stream_callback=stream_callback,
        progress_callback=None,
        event_callback=event_callback,
    )
    executor.run_id = "run-a"
    executor.owner_key_hash = "owner-a"
    return executor, provider, secrets_obj


@pytest.mark.asyncio
class TestStreamEventDispatch:
    @pytest.fixture(autouse=True)
    def _bind_echo_context(self, tmp_path: Path) -> Iterator[None]:
        workspace = (tmp_path / "workspace").resolve()
        state_dir = (tmp_path / "state").resolve()
        workspace.mkdir(parents=True)
        state_dir.mkdir(parents=True)
        token = set_runtime_context(
            RuntimeContext(
                product_id="js-agent",
                channel="test-stream",
                owner_key_hash="owner-a",
                session_id="session-a",
                run_id="run-a",
                role="test",
                profile="default",
                capabilities=(),
                workspace=workspace,
                state_dir=state_dir,
                fs_roots=(workspace, state_dir),
            )
        )
        try:
            yield
        finally:
            reset_runtime_context(token)

    async def test_disable_tools_skips_tool_schema_for_streaming_runs(self) -> None:
        class _Compressor:
            def __init__(self) -> None:
                self.seen_tools: Any = "not-called"
                self.seen_token_counter: TokenCounter | None = None
                self.seen_token_unit_id: str | None = None

            async def compress(
                self,
                messages: list[ChatMessage],
                tools: list[dict[str, Any]] | None = None,
                token_counter: TokenCounter | None = None,
            ) -> Any:
                self.seen_tools = tools
                self.seen_token_counter = token_counter
                assert token_counter is not None
                self.seen_token_unit_id = token_counter.token_unit_id
                return SimpleNamespace(
                    messages=messages,
                    level=SimpleNamespace(value="none"),
                    original_tokens=0,
                    compressed_tokens=0,
                    token_unit_id=token_counter.token_unit_id,
                    identifiers_found=[],
                )

        class _Agent:
            def __init__(self) -> None:
                self.tool_schema_calls = 0
                self.router = SimpleNamespace(get_model_config=lambda _model: None)
                self.compressor = _Compressor()
                self._current_allowed_tools: set[str] = set()
                self._token_counter = BoundTokenCounter(
                    count=lambda payload: len(payload),
                    token_unit_id=_TEST_TOKEN_UNIT_ID,
                )

            def _get_tools_schema(self, _model: str | None) -> list[dict[str, Any]]:
                self.tool_schema_calls += 1
                return [{"function": {"name": "shell"}}]

            def _token_counter_for_model(self, _model: str | None) -> TokenCounter:
                return self._token_counter

        agent = _Agent()
        executor = EchoTurnLoop.__new__(EchoTurnLoop)
        executor.agent = agent  # type: ignore[attr-defined]
        executor.model = None  # type: ignore[attr-defined]
        executor.state = SimpleNamespace(
            messages=[ChatMessage(role="user", content="hi")],
            turn_count=1,
            compression_stats={},
        )  # type: ignore[assignment]
        executor.session_id = "stream-session"  # type: ignore[attr-defined]
        executor.run_id = "run-1"  # type: ignore[attr-defined]
        executor.owner_key_hash = None  # type: ignore[attr-defined]
        executor.disable_tools = True  # type: ignore[attr-defined]
        executor.lease_tool_allowlist = None  # type: ignore[attr-defined]
        executor.allowed_tools = {"stale"}  # type: ignore[attr-defined]

        tools_schema, messages = await executor._compress()

        assert messages == executor.state.messages
        assert tools_schema is None
        assert agent.tool_schema_calls == 0
        assert agent.compressor.seen_tools is None
        assert agent.compressor.seen_token_unit_id == _TEST_TOKEN_UNIT_ID
        assert executor.state.compression_stats["compression"]["token_unit_id"] == (
            _TEST_TOKEN_UNIT_ID
        )
        assert executor._prompt_token_counter is agent._token_counter
        assert executor.allowed_tools == set()

    async def test_text_deltas_only_hit_stream_callback(self) -> None:
        tokens: list[str] = []
        events_seen: list[dict[str, Any]] = []

        async def on_token(t: str) -> None:
            tokens.append(t)

        async def on_event(p: dict[str, Any]) -> None:
            events_seen.append(p)

        executor, _, _ = _make_executor(
            [
                StreamEvent(kind="text_delta", text="hello "),
                StreamEvent(kind="text_delta", text="world"),
            ],
            stream_callback=on_token,
            event_callback=on_event,
        )

        resp = await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=None,
        )

        # Text deltas reach the legacy text callback.
        assert tokens == ["hello ", "world"]
        # event_callback was given nothing for plain text deltas.
        assert events_seen == []
        # ChatResponse content is the concatenated text.
        assert resp.content == "hello world"

    async def test_router_stream_events_without_gate_signature_is_rejected(self) -> None:
        tokens: list[str] = []

        async def on_token(t: str) -> None:
            tokens.append(t)

        class _RouterNoGate:
            _permit_verifier = ModelPermitIssuer()

            async def select_model(self, preferred: Any = None) -> Any:
                return SimpleNamespace(provider=self, model=preferred or "m1", provider_name="fake")

            async def chat_stream_events(
                self,
                messages: list[ChatMessage],
                model: str,
                tools: list[dict[str, Any]] | None = None,
                temperature: float = 0.7,
                max_tokens: int | None = None,
            ) -> AsyncIterator[StreamEvent]:
                yield StreamEvent(kind="text_delta", text="manual")
                yield StreamEvent(kind="done", finish_reason="stop")

        executor, _, _ = _make_executor(
            [],
            stream_callback=on_token,
            event_callback=None,
        )
        executor.agent.router = _RouterNoGate()  # type: ignore[attr-defined]

        with pytest.raises(TypeError, match="before_model_call"):
            await executor._get_response(
                compressed_messages=[ChatMessage(role="user", content="hi")],
                tools_schema=None,
            )

        assert tokens == []

    async def test_thinking_delta_routed_to_event_callback(self) -> None:
        tokens: list[str] = []
        events_seen: list[dict[str, Any]] = []

        async def on_token(t: str) -> None:
            tokens.append(t)

        async def on_event(p: dict[str, Any]) -> None:
            events_seen.append(p)

        executor, _, _ = _make_executor(
            [
                StreamEvent(kind="thinking_delta", text="reasoning step"),
                StreamEvent(kind="text_delta", text="answer"),
            ],
            stream_callback=on_token,
            event_callback=on_event,
        )

        await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=None,
        )

        # Thinking does NOT contaminate the text token stream.
        assert tokens == ["answer"]
        # Security buffering may coalesce provider chunk boundaries, but the
        # complete thinking text still reaches only the structured channel.
        assert all(event["kind"] == "thinking_delta" for event in events_seen)
        assert "".join(str(event["text"]) for event in events_seen) == "reasoning step"

    async def test_tool_call_delta_redacts_arguments_before_forwarding(self) -> None:
        events_seen: list[dict[str, Any]] = []

        async def on_token(_: str) -> None:
            pass

        async def on_event(p: dict[str, Any]) -> None:
            events_seen.append(p)

        tc_payload = {
            "index": 0,
            "id": "call_xyz",
            "name": "lookup",
            "arguments_delta": '{"token":"sk-live-secret"',
        }
        secrets = _FakeSecrets()
        secrets.replacements["sk-live-secret"] = "[REDACTED]"
        executor, _, _ = _make_executor(
            [StreamEvent(kind="tool_call_delta", tool_call=tc_payload)],
            stream_callback=on_token,
            event_callback=on_event,
            secrets=secrets,
        )

        await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=None,
        )
        assert events_seen == [
            {
                "kind": "tool_call_delta",
                "tool_call": {
                    "index": 0,
                    "id": "call_xyz",
                    "name": "lookup",
                    "arguments_delta": '{"token":"[REDACTED]"',
                },
            }
        ]

    async def test_tool_call_delta_assembles_chatresponse_tool_call(self) -> None:
        async def on_token(_: str) -> None:
            pass

        async def on_event(_: dict[str, Any]) -> None:
            pass

        executor, _, _ = _make_executor(
            [
                StreamEvent(
                    kind="tool_call_delta",
                    tool_call={
                        "index": 0,
                        "id": "call_lookup",
                        "name": "lookup",
                        "arguments_delta": '{"q"',
                    },
                ),
                StreamEvent(
                    kind="tool_call_delta",
                    tool_call={
                        "index": 0,
                        "arguments_delta": ':"x"}',
                    },
                ),
                StreamEvent(kind="done", finish_reason="tool_calls"),
            ],
            stream_callback=on_token,
            event_callback=on_event,
        )

        resp = await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=[{"type": "function", "function": {"name": "lookup"}}],
        )

        assert resp.finish_reason == "tool_calls"
        assert resp.tool_calls == [
            {
                "id": "call_lookup",
                "type": "function",
                "function": {"name": "lookup", "arguments": '{"q":"x"}'},
            }
        ]

    async def test_stream_tool_call_assembly_preserves_malformed_raw_ids(self) -> None:
        async def on_token(_: str) -> None:
            pass

        executor, _, _ = _make_executor(
            [
                StreamEvent(
                    kind="tool_call_delta",
                    tool_call={
                        "index": 0,
                        "id": 7,
                        "name": "lookup",
                        "arguments_delta": "{}",
                    },
                ),
                StreamEvent(
                    kind="tool_call_delta",
                    tool_call={
                        "index": 1,
                        "id": None,
                        "name": "lookup",
                        "arguments_delta": "{}",
                    },
                ),
                StreamEvent(
                    kind="tool_call_delta",
                    tool_call={
                        "index": 2,
                        "id": "",
                        "name": "lookup",
                        "arguments_delta": "{}",
                    },
                ),
                StreamEvent(
                    kind="tool_call_delta",
                    tool_call={
                        "index": 3,
                        "name": "lookup",
                        "arguments_delta": "{}",
                    },
                ),
                StreamEvent(kind="done", finish_reason="tool_calls"),
            ],
            stream_callback=on_token,
            event_callback=None,
        )

        response = await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=[{"type": "function", "function": {"name": "lookup"}}],
        )

        assert [call.get("id") for call in response.tool_calls] == [7, None, "", None]
        assert "id" not in response.tool_calls[3]

    async def test_stream_tool_call_assembly_sorts_numeric_indices_numerically(self) -> None:
        async def on_token(_: str) -> None:
            pass

        expected_ids = [f"call-{index}" for index in range(12)]
        executor, _, _ = _make_executor(
            [
                StreamEvent(
                    kind="tool_call_delta",
                    tool_call={
                        "index": index,
                        "id": call_id,
                        "name": "shell",
                        "arguments_delta": "{}",
                    },
                )
                for index, call_id in enumerate(expected_ids)
            ],
            stream_callback=on_token,
            event_callback=None,
        )

        response = await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=[{"type": "function", "function": {"name": "shell"}}],
        )

        assert [call["id"] for call in response.tool_calls] == expected_ids

    async def test_stream_tool_call_assembly_keeps_nonnumeric_insertion_order(self) -> None:
        async def on_token(_: str) -> None:
            pass

        expected_ids = ["call-b", "call-a", "call-c"]
        executor, _, _ = _make_executor(
            [
                StreamEvent(
                    kind="tool_call_delta",
                    tool_call={
                        "id": call_id,
                        "name": "lookup",
                        "arguments_delta": "{}",
                    },
                )
                for call_id in expected_ids
            ],
            stream_callback=on_token,
            event_callback=None,
        )

        response = await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=[{"type": "function", "function": {"name": "lookup"}}],
        )

        assert [call["id"] for call in response.tool_calls] == expected_ids

    async def test_nested_tool_call_delta_does_not_crash_stream_dispatch(self) -> None:
        events_seen: list[dict[str, Any]] = []

        async def on_token(_: str) -> None:
            pass

        async def on_event(payload: dict[str, Any]) -> None:
            events_seen.append(payload)

        executor, _, _ = _make_executor(
            [
                StreamEvent(
                    kind="tool_call_delta",
                    tool_call={
                        "index": 0,
                        "function": {"name": "lookup", "arguments": "{}"},
                    },
                )
            ],
            stream_callback=on_token,
            event_callback=on_event,
        )

        await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=[{"type": "function", "function": {"name": "lookup"}}],
        )

        assert events_seen == [
            {
                "kind": "tool_call_delta",
                "tool_call": {
                    "index": 0,
                    "function": {"name": "lookup", "arguments": "{}"},
                },
            }
        ]

    async def test_structured_stream_keeps_tools_schema_when_tools_are_enabled(self) -> None:
        tokens: list[str] = []
        events_seen: list[dict[str, Any]] = []

        async def on_token(t: str) -> None:
            tokens.append(t)

        async def on_event(p: dict[str, Any]) -> None:
            events_seen.append(p)

        tool_schema = [{"type": "function", "function": {"name": "lookup"}}]
        executor, provider, _ = _make_executor(
            [
                StreamEvent(kind="thinking_delta", text="choose tool"),
                StreamEvent(
                    kind="tool_call_delta",
                    tool_call={"id": "call_1", "name": "lookup", "arguments_delta": "{}"},
                ),
                StreamEvent(kind="text_delta", text="answer"),
            ],
            stream_callback=on_token,
            event_callback=on_event,
        )

        resp = await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=tool_schema,
        )

        assert provider.seen_tools == tool_schema
        assert tokens == ["answer"]
        assert resp.content == "answer"
        assert events_seen == [
            {"kind": "thinking_delta", "text": "choose tool"},
            {
                "kind": "tool_call_delta",
                "tool_call": {"id": "call_1", "name": "lookup", "arguments_delta": "{}"},
            },
        ]

    async def test_usage_event_is_authoritative_for_chatresponse(self) -> None:
        events_seen: list[dict[str, Any]] = []

        async def on_token(_: str) -> None:
            pass

        async def on_event(p: dict[str, Any]) -> None:
            events_seen.append(p)

        executor, _, _ = _make_executor(
            [
                StreamEvent(kind="text_delta", text="x"),
                StreamEvent(
                    kind="usage",
                    usage={
                        "prompt_tokens": 11,
                        "completion_tokens": 22,
                        "total_tokens": 40,
                        "cached_tokens": 5,
                    },
                ),
            ],
            stream_callback=on_token,
            event_callback=on_event,
        )

        resp = await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=None,
        )
        # The usage event was forwarded.
        assert events_seen[-1]["kind"] == "usage"
        assert events_seen[-1]["usage"]["completion_tokens"] == 22
        # And it became the authoritative usage in ChatResponse — not the
        # heuristic fallback that would have produced a much smaller number.
        assert resp.usage["uncached_input"] == 6
        assert resp.usage["cache_read"] == 5
        assert resp.usage["input_total"] == 11
        assert resp.usage["output"] == 22
        assert resp.usage_source == "provider_actual"

    async def test_missing_stream_usage_is_explicitly_estimated(self) -> None:
        async def on_token(_: str) -> None:
            pass

        executor, _, _ = _make_executor(
            [StreamEvent(kind="text_delta", text="estimated response")],
            stream_callback=on_token,
            event_callback=None,
        )

        resp = await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=None,
        )

        assert resp.usage["input_total"] == 0
        assert resp.usage["completion_tokens"] > 0
        assert resp.usage_source == "estimated"

    async def test_secrets_redaction_runs_on_text_and_thinking(self) -> None:
        # The fake secrets replaces "sk-LEAK" everywhere it sees it.
        secrets = _FakeSecrets()
        secrets.replacements = {"sk-LEAK": "[REDACTED]"}

        tokens: list[str] = []
        events: list[dict[str, Any]] = []

        async def on_token(t: str) -> None:
            tokens.append(t)

        async def on_event(p: dict[str, Any]) -> None:
            events.append(p)

        executor, _, _ = _make_executor(
            [
                StreamEvent(kind="thinking_delta", text="thinking sk-LEAK here"),
                StreamEvent(kind="text_delta", text="answer sk-LEAK end"),
            ],
            stream_callback=on_token,
            event_callback=on_event,
            secrets=secrets,
        )

        await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=None,
        )

        # Both channels are scrubbed.
        assert tokens == ["answer [REDACTED] end"]
        assert events == [{"kind": "thinking_delta", "text": "thinking [REDACTED] here"}]

    async def test_text_secret_split_across_chunks_never_reaches_callback(
        self, tmp_path: Path
    ) -> None:
        secret = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
        tokens: list[str] = []

        async def on_token(token: str) -> None:
            tokens.append(token)

        executor, _, _ = _make_executor(
            [
                StreamEvent(kind="text_delta", text="prefix sk-ABCDEFGHIJ"),
                StreamEvent(kind="text_delta", text="KLMNOPQRSTUVWXYZ123456 suffix"),
            ],
            stream_callback=on_token,
            event_callback=None,
            secrets=SecretManager(tmp_path / "text-secrets"),
        )

        response = await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=None,
        )

        delivered = "".join(tokens)
        assert secret not in delivered
        assert "[REDACTED:openai_key]" in delivered
        assert secret not in response.content

    async def test_thinking_secret_split_across_chunks_never_reaches_event_callback(
        self, tmp_path: Path
    ) -> None:
        secret = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
        events: list[dict[str, Any]] = []

        async def on_token(_: str) -> None:
            pass

        async def on_event(payload: dict[str, Any]) -> None:
            events.append(payload)

        executor, _, _ = _make_executor(
            [
                StreamEvent(kind="thinking_delta", text="inspect sk-ABCDEFGHIJ"),
                StreamEvent(kind="thinking_delta", text="KLMNOPQRSTUVWXYZ123456 safely"),
            ],
            stream_callback=on_token,
            event_callback=on_event,
            secrets=SecretManager(tmp_path / "thinking-secrets"),
        )

        await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=None,
        )

        delivered = "".join(
            str(event.get("text", "")) for event in events if event.get("kind") == "thinking_delta"
        )
        assert secret not in delivered
        assert "[REDACTED:openai_key]" in delivered

    async def test_tool_argument_secret_split_across_chunks_is_redacted_before_dispatch(
        self, tmp_path: Path
    ) -> None:
        secret = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
        events: list[dict[str, Any]] = []

        async def on_token(_: str) -> None:
            pass

        async def on_event(payload: dict[str, Any]) -> None:
            events.append(payload)

        executor, _, _ = _make_executor(
            [
                StreamEvent(
                    kind="tool_call_delta",
                    tool_call={
                        "index": 0,
                        "id": "call_secret",
                        "name": "lookup",
                        "arguments_delta": '{"token":"sk-ABCDEFGHIJ',
                    },
                ),
                StreamEvent(
                    kind="tool_call_delta",
                    tool_call={
                        "index": 0,
                        "arguments_delta": 'KLMNOPQRSTUVWXYZ123456"}',
                    },
                ),
            ],
            stream_callback=on_token,
            event_callback=on_event,
            secrets=SecretManager(tmp_path / "tool-secrets"),
        )

        response = await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=[{"type": "function", "function": {"name": "lookup"}}],
        )

        delivered = repr(events)
        assert secret not in delivered
        assert "[REDACTED:openai_key]" in delivered
        assert secret not in repr(response.tool_calls)

    async def test_failing_event_callback_does_not_abort_stream(self) -> None:
        tokens: list[str] = []

        async def on_token(t: str) -> None:
            tokens.append(t)

        async def on_event(_: dict[str, Any]) -> None:
            raise RuntimeError("websocket dropped frame")

        executor, _, _ = _make_executor(
            [
                StreamEvent(kind="thinking_delta", text="t"),
                StreamEvent(kind="text_delta", text="a"),
                StreamEvent(kind="text_delta", text="b"),
            ],
            stream_callback=on_token,
            event_callback=on_event,
        )

        resp = await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=None,
        )
        # Text tokens still flow even though the event_callback exploded.
        assert "".join(tokens) == "ab"
        assert resp.content == "ab"

    async def test_error_event_raises_to_outer_loop(self) -> None:
        events_seen: list[dict[str, Any]] = []

        async def on_token(_: str) -> None:
            pass

        async def on_event(p: dict[str, Any]) -> None:
            events_seen.append(p)

        executor, _, _ = _make_executor(
            [
                StreamEvent(kind="text_delta", text="partial"),
                StreamEvent(kind="error", error="upstream rate-limited"),
            ],
            stream_callback=on_token,
            event_callback=on_event,
        )

        with pytest.raises(RuntimeError, match="upstream rate-limited"):
            await executor._get_response(
                compressed_messages=[ChatMessage(role="user", content="hi")],
                tools_schema=None,
            )

        # The error event was still surfaced to the side-channel BEFORE the
        # exception propagated, so the WS layer can render a banner before
        # the higher-level error frame.
        assert any(
            e.get("kind") == "error" and "rate-limited" in (e.get("error") or "")
            for e in events_seen
        )

    async def test_error_event_redacts_secret_before_callback_and_exception(self) -> None:
        events_seen: list[dict[str, Any]] = []
        secret = "sk-test12345678901234567890ABCDEFGH"
        secrets = _FakeSecrets()
        secrets.replacements[secret] = "[REDACTED:openai_key]"

        async def on_token(_: str) -> None:
            pass

        async def on_event(payload: dict[str, Any]) -> None:
            events_seen.append(payload)

        executor, _, _ = _make_executor(
            [StreamEvent(kind="error", error=f"provider diagnostic {secret}")],
            stream_callback=on_token,
            event_callback=on_event,
            secrets=secrets,
        )

        with pytest.raises(RuntimeError) as raised:
            await executor._get_response(
                compressed_messages=[ChatMessage(role="user", content="hi")],
                tools_schema=None,
            )

        delivered = repr(events_seen)
        assert secret not in delivered
        assert secret not in str(raised.value)
        assert secret not in repr(executor.agent.echo_safety_service.finished)
        assert "[REDACTED:openai_key]" in delivered
        assert "[REDACTED:openai_key]" in str(raised.value)

    async def test_no_event_callback_means_no_disruption(self) -> None:
        # Backward-compat: callers that don't opt into event_callback see
        # exactly the old behaviour — text tokens flow, thinking is dropped
        # at the boundary (it never went anywhere in the legacy code path).
        tokens: list[str] = []

        async def on_token(t: str) -> None:
            tokens.append(t)

        executor, _, _ = _make_executor(
            [
                StreamEvent(kind="thinking_delta", text="ignored"),
                StreamEvent(kind="text_delta", text="hi"),
            ],
            stream_callback=on_token,
            event_callback=None,
        )

        resp = await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=None,
        )
        assert tokens == ["hi"]
        assert resp.content == "hi"
