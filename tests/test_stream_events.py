"""Tests for ``js/models/stream_events.py`` and the structured event hooks.

Covers:

* ``StreamEvent.to_dict`` produces a stable JSON-safe payload, omitting empty
  optional fields.
* OpenAI chunk parser:
    - ``delta.content`` → text_delta
    - ``delta.reasoning_content`` and ``delta.thinking`` → thinking_delta
    - ``delta.tool_calls`` with partial fragments → tool_call_delta
    - ``chunk.usage`` (final summary chunk) → usage
    - ``choices[0].finish_reason`` → done
* Anthropic SSE parser (dict-based events):
    - message_start → usage
    - content_block_delta(text_delta) → text_delta
    - content_block_delta(thinking_delta) → thinking_delta
    - content_block_start(tool_use) + input_json_delta → tool_call_delta
    - message_delta + message_stop → done
    - error event → error
* Provider integration: the default ``ModelProvider.chat_stream_events`` wraps
  a child's ``chat_stream`` correctly (text fragments become text_delta,
  followed by a single ``done``); raised exceptions surface as ``error``.
* No real network or SDK is touched — providers are stubbed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import pytest

from js.models.providers import ChatMessage, ModelProvider
from js.models.stream_events import (
    StreamEvent,
    parse_anthropic_event,
    parse_openai_chunk,
    text_to_events,
)

# ---------------------------------------------------------------------------
# StreamEvent.to_dict
# ---------------------------------------------------------------------------


class TestStreamEventSerialisation:
    def test_text_delta_serialises_minimally(self) -> None:
        ev = StreamEvent(kind="text_delta", text="hi")
        d = ev.to_dict()
        assert d == {"kind": "text_delta", "text": "hi"}

    def test_done_with_finish_reason_carries_only_set_fields(self) -> None:
        ev = StreamEvent(kind="done", finish_reason="stop", provider="openai")
        d = ev.to_dict()
        # No empty text / tool_call / usage / error keys leak into the dict.
        assert d == {"kind": "done", "finish_reason": "stop", "provider": "openai"}

    def test_usage_event(self) -> None:
        ev = StreamEvent(
            kind="usage",
            usage={
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
                "cached_tokens": 2,
            },
        )
        d = ev.to_dict()
        assert d["usage"]["cached_tokens"] == 2
        assert d["kind"] == "usage"


# ---------------------------------------------------------------------------
# OpenAI chunk → events
# ---------------------------------------------------------------------------


@dataclass
class _OAIDelta:
    content: str | None = None
    reasoning_content: str | None = None
    thinking: str | None = None
    tool_calls: list[Any] | None = None


@dataclass
class _OAIChoice:
    delta: _OAIDelta | None = None
    finish_reason: str | None = None


@dataclass
class _OAIUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    prompt_tokens_details: Any = None


@dataclass
class _OAIToolFn:
    name: str | None = None
    arguments: str | None = None


@dataclass
class _OAIToolCall:
    index: int = 0
    id: str | None = None
    function: _OAIToolFn | None = None


@dataclass
class _OAIChunk:
    choices: list[_OAIChoice]
    usage: _OAIUsage | None = None


class TestParseOpenAIChunk:
    def test_text_delta(self) -> None:
        chunk = _OAIChunk(choices=[_OAIChoice(delta=_OAIDelta(content="hello "))])
        events = parse_openai_chunk(chunk)
        assert len(events) == 1
        assert events[0].kind == "text_delta"
        assert events[0].text == "hello "

    def test_reasoning_content_becomes_thinking_delta(self) -> None:
        # DeepSeek-R1 / Kimi K2 Thinking style.
        chunk = _OAIChunk(choices=[_OAIChoice(delta=_OAIDelta(reasoning_content="let me think"))])
        events = parse_openai_chunk(chunk)
        assert [e.kind for e in events] == ["thinking_delta"]
        assert events[0].text == "let me think"

    def test_thinking_field_alias(self) -> None:
        # QwQ / some GLM variants use plain `thinking` attribute.
        chunk = _OAIChunk(choices=[_OAIChoice(delta=_OAIDelta(thinking="step 1"))])
        events = parse_openai_chunk(chunk)
        assert events[0].kind == "thinking_delta"
        assert events[0].text == "step 1"

    def test_thinking_before_text_in_same_chunk(self) -> None:
        chunk = _OAIChunk(
            choices=[_OAIChoice(delta=_OAIDelta(reasoning_content="think", content="answer"))]
        )
        events = parse_openai_chunk(chunk)
        kinds = [e.kind for e in events]
        # Order matters: thinking must precede text so the UI can render the
        # reasoning panel before the visible answer.
        assert kinds == ["thinking_delta", "text_delta"]

    def test_tool_call_delta(self) -> None:
        chunk = _OAIChunk(
            choices=[
                _OAIChoice(
                    delta=_OAIDelta(
                        tool_calls=[
                            _OAIToolCall(
                                index=0,
                                id="call_abc",
                                function=_OAIToolFn(name="lookup", arguments='{"q": "x"'),
                            )
                        ]
                    )
                )
            ]
        )
        events = parse_openai_chunk(chunk)
        assert len(events) == 1
        ev = events[0]
        assert ev.kind == "tool_call_delta"
        assert ev.tool_call == {
            "index": 0,
            "id": "call_abc",
            "name": "lookup",
            "arguments_delta": '{"q": "x"',
        }

    def test_finish_reason_emits_done(self) -> None:
        chunk = _OAIChunk(choices=[_OAIChoice(delta=_OAIDelta(), finish_reason="stop")])
        events = parse_openai_chunk(chunk)
        assert [e.kind for e in events] == ["done"]
        assert events[0].finish_reason == "stop"

    def test_usage_chunk_no_choices(self) -> None:
        usage = _OAIUsage(prompt_tokens=12, completion_tokens=34, total_tokens=46)
        chunk = _OAIChunk(choices=[], usage=usage)
        events = parse_openai_chunk(chunk)
        assert len(events) == 1
        assert events[0].kind == "usage"
        assert events[0].usage == {
            "prompt_tokens": 12,
            "completion_tokens": 34,
            "total_tokens": 46,
            "cached_tokens": 0,
        }

    def test_empty_chunk_returns_no_events(self) -> None:
        # Keepalive / empty deltas must not produce events.
        chunk = _OAIChunk(choices=[_OAIChoice(delta=_OAIDelta())])
        assert parse_openai_chunk(chunk) == []


# ---------------------------------------------------------------------------
# Anthropic SSE → events
# ---------------------------------------------------------------------------


class TestParseAnthropicEvent:
    def test_message_start_yields_usage(self) -> None:
        events = parse_anthropic_event(
            {
                "type": "message_start",
                "message": {"usage": {"input_tokens": 7, "output_tokens": 0}},
            }
        )
        assert [e.kind for e in events] == ["usage"]
        assert events[0].usage == {
            "prompt_tokens": 7,
            "completion_tokens": 0,
            "total_tokens": 7,
            "cached_tokens": 0,
        }

    def test_text_delta(self) -> None:
        events = parse_anthropic_event(
            {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Hi"}}
        )
        assert [(e.kind, e.text) for e in events] == [("text_delta", "Hi")]

    def test_thinking_delta(self) -> None:
        events = parse_anthropic_event(
            {
                "type": "content_block_delta",
                "delta": {"type": "thinking_delta", "thinking": "let me consider"},
            }
        )
        assert [(e.kind, e.text) for e in events] == [("thinking_delta", "let me consider")]

    def test_tool_use_block_start_and_input_json_delta(self) -> None:
        start = parse_anthropic_event(
            {
                "type": "content_block_start",
                "index": 1,
                "content_block": {"type": "tool_use", "id": "toolu_x", "name": "search"},
            }
        )
        delta = parse_anthropic_event(
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": '{"q":"'},
            }
        )
        assert start[0].kind == "tool_call_delta"
        assert start[0].tool_call == {"index": 1, "id": "toolu_x", "name": "search"}
        assert delta[0].kind == "tool_call_delta"
        assert delta[0].tool_call == {"arguments_delta": '{"q":"', "index": 1}

    def test_message_delta_with_stop_reason_emits_usage_and_done(self) -> None:
        events = parse_anthropic_event(
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn"},
                "usage": {"input_tokens": 10, "output_tokens": 22},
            }
        )
        kinds = [e.kind for e in events]
        assert kinds == ["usage", "done"]
        done = events[1]
        assert done.finish_reason == "end_turn"

    def test_message_stop_emits_done(self) -> None:
        events = parse_anthropic_event({"type": "message_stop"})
        assert [e.kind for e in events] == ["done"]

    def test_error_event(self) -> None:
        events = parse_anthropic_event({"type": "error", "error": {"message": "rate limited"}})
        assert events[0].kind == "error"
        assert events[0].error == "rate limited"

    def test_unknown_event_returns_empty(self) -> None:
        assert parse_anthropic_event({"type": "ping"}) == []
        assert parse_anthropic_event(None) == []


# ---------------------------------------------------------------------------
# text_to_events
# ---------------------------------------------------------------------------


class TestTextToEvents:
    def test_non_empty_returns_text_delta(self) -> None:
        events = text_to_events("chunk")
        assert [(e.kind, e.text) for e in events] == [("text_delta", "chunk")]

    def test_empty_returns_no_events(self) -> None:
        assert text_to_events("") == []
        assert text_to_events(None) == []


# ---------------------------------------------------------------------------
# Default ModelProvider.chat_stream_events wraps legacy chat_stream()
# ---------------------------------------------------------------------------


class _ScriptedProvider(ModelProvider):
    """Minimal ModelProvider that yields a scripted text sequence (or raises)."""

    def __init__(self, tokens: list[str], raise_at: int | None = None) -> None:
        self._tokens = tokens
        self._raise_at = raise_at

    async def chat(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - unused
        raise NotImplementedError

    async def chat_stream(  # type: ignore[override]
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        for i, t in enumerate(self._tokens):
            if self._raise_at is not None and i == self._raise_at:
                raise RuntimeError("provider exploded mid-stream")
            yield t

    async def health_check(self) -> bool:  # pragma: no cover - unused
        return True

    async def close(self) -> None:  # pragma: no cover - unused
        return None


@pytest.mark.asyncio
class TestDefaultChatStreamEvents:
    async def test_text_tokens_become_text_deltas_then_done(self) -> None:
        p = _ScriptedProvider(["he", "llo"])
        events: list[StreamEvent] = []
        async for ev in p.chat_stream_events(messages=[], model="m1"):
            events.append(ev)

        kinds = [e.kind for e in events]
        assert kinds == ["text_delta", "text_delta", "done"]
        assert [e.text for e in events[:2]] == ["he", "llo"]
        assert events[-1].finish_reason == "stop"
        # Model id should propagate so the consumer can attribute the event.
        assert all(e.model == "m1" for e in events)

    async def test_empty_token_is_skipped(self) -> None:
        p = _ScriptedProvider(["", "x", ""])
        events: list[StreamEvent] = []
        async for ev in p.chat_stream_events(messages=[], model="m1"):
            events.append(ev)
        kinds = [e.kind for e in events]
        # Only the "x" token produces a delta; trailing/leading empties are no-ops.
        assert kinds == ["text_delta", "done"]
        assert events[0].text == "x"

    async def test_exception_becomes_error_event(self) -> None:
        p = _ScriptedProvider(["a", "b"], raise_at=1)
        events: list[StreamEvent] = []
        async for ev in p.chat_stream_events(messages=[], model="m1"):
            events.append(ev)
        # First "a" makes it out; then the runtime error fires before "b".
        assert events[0].kind == "text_delta"
        assert events[-1].kind == "error"
        assert "provider exploded" in events[-1].error
