"""Tests for the PR-4.3 WebSocket realtime channel wiring.

Scope: verify that ``TurnExecutor._get_response`` consumes the PR-4.2
``chat_stream_events()`` feed and dispatches the structured event kinds to
``event_callback`` correctly, while ``stream_callback`` keeps receiving
plain text-delta tokens (legacy contract). This is the seam the WebSocket
handler in ``js/web/server.py`` plugs into; covering it here proves the
channel works without spinning up an HTTP server.

Coverage:

* ``text_delta`` goes to ``stream_callback`` (NOT ``event_callback``).
* ``thinking_delta`` → event_callback with ``{kind:"thinking_delta", text}``.
* ``tool_call_delta`` → event_callback with the tool_call payload intact.
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

from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any

import pytest

from js.agent.runner import TurnExecutor
from js.models.providers import ChatMessage
from js.models.stream_events import StreamEvent


class _FakeProvider:
    """Minimal provider yielding a scripted StreamEvent sequence."""

    def __init__(self, events: list[StreamEvent]) -> None:
        self._events = events
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
        for ev in self._events:
            yield ev


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


def _make_executor(
    events: list[StreamEvent],
    *,
    stream_callback: Any,
    event_callback: Any,
    secrets: _FakeSecrets | None = None,
) -> tuple[TurnExecutor, _FakeProvider, _FakeSecrets]:
    """Build a TurnExecutor wired to fakes; _get_response will run.

    The constructor needs an ``AgentBase`` — we feed in a SimpleNamespace
    matching only the attributes ``_get_response`` actually touches:
    ``router.select_model``, ``secrets.detect_and_redact``, ``logger``.
    """
    provider = _FakeProvider(events)
    secrets_obj = secrets or _FakeSecrets()

    async def _select(preferred: Any = None) -> Any:
        return SimpleNamespace(provider=provider, model="m1", provider_name="fake")

    fake_agent = SimpleNamespace(
        router=SimpleNamespace(select_model=_select),
        secrets=secrets_obj,
        logger=SimpleNamespace(
            warning=lambda *a, **kw: None,
            info=lambda *a, **kw: None,
            error=lambda *a, **kw: None,
        ),
    )
    # Bypass __init__ — we only need attributes _get_response reads.
    executor = TurnExecutor.__new__(TurnExecutor)
    executor.agent = fake_agent  # type: ignore[attr-defined]
    executor.model = None  # type: ignore[attr-defined]
    executor.stream_callback = stream_callback  # type: ignore[attr-defined]
    executor.event_callback = event_callback  # type: ignore[attr-defined]
    return executor, provider, secrets_obj


@pytest.mark.asyncio
class TestStreamEventDispatch:
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
        # Thinking delta surfaced as a structured event.
        assert events_seen == [{"kind": "thinking_delta", "text": "reasoning step"}]

    async def test_tool_call_delta_forwarded_intact(self) -> None:
        events_seen: list[dict[str, Any]] = []

        async def on_token(_: str) -> None:
            pass

        async def on_event(p: dict[str, Any]) -> None:
            events_seen.append(p)

        tc_payload = {
            "index": 0,
            "id": "call_xyz",
            "name": "lookup",
            "arguments_delta": '{"q":"x"',
        }
        executor, _, _ = _make_executor(
            [StreamEvent(kind="tool_call_delta", tool_call=tc_payload)],
            stream_callback=on_token,
            event_callback=on_event,
        )

        await executor._get_response(
            compressed_messages=[ChatMessage(role="user", content="hi")],
            tools_schema=None,
        )
        assert events_seen == [{"kind": "tool_call_delta", "tool_call": tc_payload}]

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
                        "total_tokens": 33,
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
        assert resp.usage == {
            "prompt_tokens": 11,
            "completion_tokens": 22,
            "total_tokens": 33,
            "cached_tokens": 5,
        }

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
        assert tokens == ["a", "b"]
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
