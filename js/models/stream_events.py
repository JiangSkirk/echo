"""Structured streaming events shared by all provider transports.

OpenAI Chat Completions, Anthropic Messages, Bedrock Converse, and even local
LM-Studio/Ollama all expose roughly the same set of "things happening during a
stream": text deltas, reasoning/thinking deltas, tool-call deltas, a final
usage report, normal completion, and errors. Each protocol expresses those in
its own frame shape — this module turns them into a single normalised event
type so the web layer (PR-4.3), the fleet observability layer (PR-4.4), and
the agent loop can consume one feed regardless of which provider produced it.

A ``StreamEvent`` is intentionally a small dataclass instead of a Pydantic
model: it lives on the hot path (one per delta) and is throwaway. It is JSON
serialisable via ``to_dict()`` for the websocket push path.

Public API
----------

* ``StreamEvent`` — single event record.
* ``EventKind`` — one of ``text_delta`` / ``thinking_delta`` / ``tool_call_delta``
  / ``usage`` / ``done`` / ``error``.
* ``parse_openai_chunk(chunk)`` — OpenAI SDK chunk → list[StreamEvent].
* ``parse_anthropic_event(event)`` — Anthropic SSE event → list[StreamEvent].
* ``text_to_events(text)`` — wrap a plain string as a single text_delta.

The OpenAI parser also handles reasoning content surfaced by DeepSeek-R1,
QwQ, GLM-Zero, and other reasoner models that put it under
``delta.reasoning_content`` or ``delta.thinking``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

EventKind = Literal[
    "text_delta",
    "thinking_delta",
    "tool_call_delta",
    "usage",
    "done",
    "error",
]


@dataclass
class StreamEvent:
    """One structured event in a model stream.

    Fields are populated based on ``kind``:

    * ``text_delta`` / ``thinking_delta`` — ``text`` carries the chunk string.
    * ``tool_call_delta`` — ``tool_call`` carries ``{index, id?, name?,
      arguments_delta?}``; the full tool call is assembled by the consumer
      across multiple events.
    * ``usage`` — ``usage`` carries ``{prompt_tokens, completion_tokens,
      total_tokens, cached_tokens}``.
    * ``done`` — terminal success marker (carries optional ``finish_reason``).
    * ``error`` — terminal failure marker (carries ``error`` string).

    The fields not used by a particular kind are left as default. Consumers
    must NOT rely on absent fields — always check ``kind`` first.
    """

    kind: EventKind
    text: str = ""
    tool_call: dict[str, Any] | None = None
    usage: dict[str, int] | None = None
    finish_reason: str | None = None
    error: str = ""
    # Provider name & model id are filled in at the router/provider boundary
    # so the web/fleet layers can attribute each event without bookkeeping.
    provider: str = ""
    model: str = ""
    # Free-form bag for provider-specific extras the consumer may want.
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable form for transport over websocket / SSE."""
        out: dict[str, Any] = {"kind": self.kind}
        if self.text:
            out["text"] = self.text
        if self.tool_call is not None:
            out["tool_call"] = self.tool_call
        if self.usage is not None:
            out["usage"] = self.usage
        if self.finish_reason:
            out["finish_reason"] = self.finish_reason
        if self.error:
            out["error"] = self.error
        if self.provider:
            out["provider"] = self.provider
        if self.model:
            out["model"] = self.model
        if self.meta:
            out["meta"] = self.meta
        return out


# ---------------------------------------------------------------------------
# OpenAI-compatible chunk → events
# ---------------------------------------------------------------------------


def parse_openai_chunk(chunk: Any) -> list[StreamEvent]:
    """Translate one OpenAI-style SDK chunk into zero or more StreamEvents.

    Handles:
    * ``delta.content`` → ``text_delta``
    * ``delta.reasoning_content`` / ``delta.thinking`` / ``delta.reasoning``
      → ``thinking_delta`` (DeepSeek-R1, QwQ, GLM-Zero, Kimi K2-Thinking)
    * ``delta.tool_calls`` → one ``tool_call_delta`` per partial tool call
    * ``chunk.usage`` (final summary chunk) → ``usage``
    * ``choices[0].finish_reason`` (non-null) → ``done`` event

    Empty / keepalive chunks return an empty list so the caller can ``yield
    from`` without filtering.
    """
    events: list[StreamEvent] = []

    # Some providers emit a final chunk with usage but no choices.
    usage = getattr(chunk, "usage", None)
    if usage is not None:
        from js.models.usage import map_openai_usage

        events.append(
            StreamEvent(
                kind="usage",
                usage=map_openai_usage(usage).to_usage_dict(),
            )
        )

    choices = getattr(chunk, "choices", None) or []
    if not choices:
        return events

    choice = choices[0]
    delta = getattr(choice, "delta", None)
    finish_reason = getattr(choice, "finish_reason", None)

    if delta is not None:
        # Thinking content first — it usually arrives before normal text in
        # DeepSeek-R1 / QwQ-style models.
        thinking_text = (
            getattr(delta, "reasoning_content", None)
            or getattr(delta, "thinking", None)
            or getattr(delta, "reasoning", None)
        )
        if thinking_text:
            events.append(StreamEvent(kind="thinking_delta", text=str(thinking_text)))

        content = getattr(delta, "content", None)
        if content:
            events.append(StreamEvent(kind="text_delta", text=str(content)))

        tool_calls = getattr(delta, "tool_calls", None) or []
        for tc in tool_calls:
            payload = _tool_call_delta_payload(tc)
            if payload:
                events.append(StreamEvent(kind="tool_call_delta", tool_call=payload))

    if finish_reason:
        events.append(StreamEvent(kind="done", finish_reason=str(finish_reason)))

    return events


def _tool_call_delta_payload(tc: Any) -> dict[str, Any]:
    """Normalise an OpenAI-style partial tool call into a stable dict."""
    payload: dict[str, Any] = {}
    idx = getattr(tc, "index", None)
    if idx is not None:
        payload["index"] = int(idx)
    tc_id = getattr(tc, "id", None)
    if tc_id:
        payload["id"] = tc_id
    fn = getattr(tc, "function", None)
    if fn is not None:
        name = getattr(fn, "name", None)
        if name:
            payload["name"] = name
        args = getattr(fn, "arguments", None)
        if args is not None:
            # OpenAI streams arguments as concatenated JSON-string fragments.
            # The consumer assembles the full payload, so we carry the delta.
            payload["arguments_delta"] = args
    return payload


def _extract_cached_tokens(usage: Any) -> int:
    """Pull cached-token count from common usage shapes (OpenAI / DeepSeek)."""
    if usage is None:
        return 0
    details = getattr(usage, "prompt_tokens_details", None)
    if details is not None:
        return int(getattr(details, "cached_tokens", 0) or 0)
    ds = getattr(usage, "prompt_cache_hit_tokens", None)
    if ds is not None:
        return int(ds or 0)
    return 0


# ---------------------------------------------------------------------------
# Anthropic SSE event → events
# ---------------------------------------------------------------------------


def parse_anthropic_event(event: Any) -> list[StreamEvent]:
    """Translate one Anthropic Messages-API SSE event into StreamEvents.

    Anthropic's stream protocol emits typed events:

    * ``message_start`` — carries initial input_tokens (we surface as usage).
    * ``content_block_start`` — declares a new block (text / tool_use / thinking).
    * ``content_block_delta`` — text_delta / input_json_delta / thinking_delta.
    * ``content_block_stop`` — block finished.
    * ``message_delta`` — updated stop_reason and final output_tokens.
    * ``message_stop`` — overall completion (we surface as done).
    * ``error`` — terminal failure.

    We accept both SDK ``Event`` objects (attribute access) and raw dicts
    (SSE-decoded JSON) to keep this parser usable from tests + production.
    """
    et = _get(event, "type")
    if not et:
        return []

    if et == "content_block_delta":
        delta = _get(event, "delta") or {}
        dt = _get(delta, "type")
        if dt == "text_delta":
            text = _get(delta, "text") or ""
            return [StreamEvent(kind="text_delta", text=str(text))] if text else []
        if dt == "thinking_delta":
            text = _get(delta, "thinking") or ""
            return [StreamEvent(kind="thinking_delta", text=str(text))] if text else []
        if dt == "input_json_delta":
            # Tool-use argument fragments.
            partial = _get(delta, "partial_json") or ""
            index = _get(event, "index")
            payload: dict[str, Any] = {"arguments_delta": partial}
            if index is not None:
                payload["index"] = int(index)
            return [StreamEvent(kind="tool_call_delta", tool_call=payload)]
        return []

    if et == "content_block_start":
        block = _get(event, "content_block") or {}
        if _get(block, "type") == "tool_use":
            index = _get(event, "index")
            payload = {"id": _get(block, "id") or "", "name": _get(block, "name") or ""}
            if index is not None:
                payload["index"] = int(index)
            return [StreamEvent(kind="tool_call_delta", tool_call=payload)]
        return []

    if et == "message_start":
        msg = _get(event, "message") or {}
        usage = _get(msg, "usage") or {}
        if usage:
            from js.models.usage import map_anthropic_usage

            return [
                StreamEvent(
                    kind="usage",
                    usage=map_anthropic_usage(usage).to_usage_dict(),
                )
            ]
        return []

    if et == "message_delta":
        usage = _get(event, "usage") or {}
        delta = _get(event, "delta") or {}
        out: list[StreamEvent] = []
        if usage:
            from js.models.usage import map_anthropic_usage

            out.append(
                StreamEvent(
                    kind="usage",
                    usage=map_anthropic_usage(usage).to_usage_dict(),
                )
            )
        stop_reason = _get(delta, "stop_reason")
        if stop_reason:
            out.append(StreamEvent(kind="done", finish_reason=str(stop_reason)))
        return out

    if et == "message_stop":
        return [StreamEvent(kind="done", finish_reason="stop")]

    if et == "error":
        err = _get(event, "error") or {}
        msg = _get(err, "message") or "anthropic stream error"
        return [StreamEvent(kind="error", error=str(msg))]

    return []


def _get(obj: Any, key: str) -> Any:
    """Attribute-or-dict access shim. Returns None when missing."""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


# ---------------------------------------------------------------------------
# Plain text → events (fallback bridge for legacy chat_stream)
# ---------------------------------------------------------------------------


def text_to_events(text: str | None) -> list[StreamEvent]:
    """Wrap a non-empty text chunk as a single ``text_delta`` event."""
    if not text:
        return []
    return [StreamEvent(kind="text_delta", text=text)]


__all__ = [
    "EventKind",
    "StreamEvent",
    "parse_anthropic_event",
    "parse_openai_chunk",
    "text_to_events",
]
