"""Transport ABC: protocol adapters for multi-provider support.

Hermes v0.14 introduced a Transport ABC that separates format conversion
and HTTP transport from the core agent loop. JS Agent adopts the same
pattern so that OpenAI ChatCompletions, Anthropic Messages API,
OpenAI Responses API, and AWS Bedrock Converse can coexist.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from js.models.providers import ChatMessage, ChatResponse
from js.utils.log import get_logger

logger = get_logger("js.models.transports")


@dataclass
class TransportRequest:
    """Normalised request regardless of downstream protocol."""

    model: str
    messages: list[ChatMessage]
    tools: list[dict[str, Any]] | None = None
    temperature: float = 0.7
    max_tokens: int | None = None
    stream: bool = False


class BaseTransport(ABC):
    """Abstract transport: converts normalised requests ↔ provider-native format."""

    name: str = "base"

    @abstractmethod
    def convert_request(self, req: TransportRequest) -> dict[str, Any]:
        """Turn a normalised request into the provider's native payload."""
        ...

    @abstractmethod
    def parse_response(self, raw: Any) -> ChatResponse:
        """Parse a provider-native response into ChatResponse."""
        ...

    @abstractmethod
    def parse_stream_chunk(self, chunk: Any) -> str | None:
        """Extract token text from a streaming chunk. Return None for non-content chunks."""
        ...

    @abstractmethod
    def extract_usage(self, raw: Any) -> dict[str, int]:
        """Extract token usage from a response or final stream chunk."""
        ...


class ChatCompletionsTransport(BaseTransport):
    """OpenAI Chat Completions API (default)."""

    name = "chat_completions"

    def convert_request(self, req: TransportRequest) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": req.model,
            "messages": _messages_to_openai(req.messages),
            "temperature": req.temperature,
            "stream": req.stream,
        }
        if req.tools:
            payload["tools"] = req.tools
            payload["tool_choice"] = "auto"
        if req.max_tokens:
            payload["max_tokens"] = req.max_tokens
        if req.stream:
            payload["stream_options"] = {"include_usage": True}
        return payload

    def parse_response(self, raw: Any) -> ChatResponse:
        choice = raw.choices[0]
        msg = choice.message
        tool_calls: list[dict[str, Any]] = []
        if msg.tool_calls:
            for tc in msg.tool_calls:
                tool_calls.append({
                    "id": tc.id,
                    "type": tc.type,
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                })
        usage = raw.usage
        return ChatResponse(
            content=msg.content or "",
            tool_calls=tool_calls,
            model=raw.model,
            usage={
                "prompt_tokens": usage.prompt_tokens if usage else 0,
                "completion_tokens": usage.completion_tokens if usage else 0,
                "total_tokens": usage.total_tokens if usage else 0,
                "cached_tokens": _extract_cached_tokens(usage),
            },
            finish_reason=choice.finish_reason or "stop",
            reasoning_content=getattr(msg, "reasoning_content", "") or "",
            usage_source="provider_actual" if usage else "unavailable",
        )

    def parse_stream_chunk(self, chunk: Any) -> str | None:
        if chunk.choices and chunk.choices[0].delta.content:
            text: str = chunk.choices[0].delta.content
            return text
        return None

    def extract_usage(self, raw: Any) -> dict[str, int]:
        usage = getattr(raw, "usage", None)
        if not usage:
            return {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "cached_tokens": 0}
        return {
            "prompt_tokens": usage.prompt_tokens or 0,
            "completion_tokens": usage.completion_tokens or 0,
            "total_tokens": usage.total_tokens or 0,
            "cached_tokens": _extract_cached_tokens(usage),
        }


class AnthropicTransport(BaseTransport):
    """Anthropic Messages API transport adapter.

    Converts OpenAI-style messages/tools into Anthropic's native format.
    Requires the ``anthropic`` package to be installed.
    """

    name = "anthropic"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key
        try:
            import anthropic as _anthropic  # type: ignore[import-not-found]
            self._client_cls = _anthropic.AsyncAnthropic
        except ImportError:
            self._client_cls = None  # type: ignore[assignment]

    def convert_request(self, req: TransportRequest) -> dict[str, Any]:
        """Convert OpenAI-style messages to Anthropic Messages format."""
        system_text: str | None = None
        native_messages: list[dict[str, Any]] = []
        for m in req.messages:
            if m.role == "system":
                system_text = m.content if isinstance(m.content, str) else str(m.content)
                continue
            native_messages.append(_openai_msg_to_anthropic(m))
        payload: dict[str, Any] = {
            "model": req.model,
            "messages": native_messages,
            "max_tokens": req.max_tokens or 4096,
            "temperature": req.temperature,
            "stream": req.stream,
        }
        if system_text:
            payload["system"] = system_text
        if req.tools:
            payload["tools"] = [_openai_tool_to_anthropic(t) for t in req.tools]
        return payload

    def parse_response(self, raw: Any) -> ChatResponse:
        content_text = ""
        tool_calls: list[dict[str, Any]] = []
        reasoning = ""
        for block in raw.content:
            btype = getattr(block, "type", "")
            if btype == "text":
                content_text += getattr(block, "text", "")
            elif btype == "tool_use":
                tool_calls.append({
                    "id": getattr(block, "id", ""),
                    "type": "function",
                    "function": {
                        "name": getattr(block, "name", ""),
                        "arguments": json.dumps(getattr(block, "input", {})),
                    },
                })
            elif btype == "thinking":
                reasoning += getattr(block, "thinking", "")
        usage = raw.usage
        cached = getattr(usage, "cache_read_input_tokens", 0) if usage else 0
        return ChatResponse(
            content=content_text,
            tool_calls=tool_calls,
            model=raw.model,
            usage={
                "prompt_tokens": usage.input_tokens if usage else 0,
                "completion_tokens": usage.output_tokens if usage else 0,
                "total_tokens": (usage.input_tokens + usage.output_tokens) if usage else 0,
                "cached_tokens": cached,
            },
            finish_reason="stop",
            reasoning_content=reasoning,
            usage_source="provider_actual" if usage else "unavailable",
        )

    def parse_stream_chunk(self, chunk: Any) -> str | None:
        delta = getattr(chunk, "delta", None)
        if delta:
            text: str | None = getattr(delta, "text", None)
            if text is not None:
                return text
        return None

    def extract_usage(self, raw: Any) -> dict[str, int]:
        usage = getattr(raw, "usage", None)
        if not usage:
            return {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "cached_tokens": 0}
        cached = getattr(usage, "cache_read_input_tokens", 0) or 0
        return {
            "prompt_tokens": usage.input_tokens or 0,
            "completion_tokens": usage.output_tokens or 0,
            "total_tokens": (usage.input_tokens + usage.output_tokens) if usage else 0,
            "cached_tokens": cached,
        }


class BedrockTransport(BaseTransport):
    """AWS Bedrock Converse API transport adapter.

    Converts normalised requests to Bedrock Converse format.
    Requires ``boto3`` to be installed.
    """

    name = "bedrock"

    def __init__(self, region: str = "us-east-1") -> None:
        self.region = region
        try:
            import boto3  # type: ignore[import-not-found]
            self._boto3 = boto3
        except ImportError:
            self._boto3 = None  # type: ignore[assignment]

    def convert_request(self, req: TransportRequest) -> dict[str, Any]:
        """Convert to Bedrock Converse format."""
        system_texts: list[dict[str, Any]] = []
        native_messages: list[dict[str, Any]] = []
        for m in req.messages:
            if m.role == "system":
                system_texts.append({"text": m.content if isinstance(m.content, str) else str(m.content)})
                continue
            native_messages.append(_openai_msg_to_bedrock(m))
        payload: dict[str, Any] = {
            "modelId": req.model,
            "messages": native_messages,
            "inferenceConfig": {"temperature": req.temperature},
        }
        if system_texts:
            payload["system"] = system_texts
        if req.tools:
            payload["toolConfig"] = {
                "tools": [_openai_tool_to_bedrock(t) for t in req.tools],
            }
        if req.max_tokens:
            payload["inferenceConfig"]["maxTokens"] = req.max_tokens
        return payload

    def parse_response(self, raw: Any) -> ChatResponse:
        output = raw.get("output", {})
        message = output.get("message", {})
        content_text = ""
        tool_calls: list[dict[str, Any]] = []
        for block in message.get("content", []):
            if "text" in block:
                content_text += block["text"]
            elif "toolUse" in block:
                tu = block["toolUse"]
                tool_calls.append({
                    "id": tu.get("toolUseId", ""),
                    "type": "function",
                    "function": {
                        "name": tu.get("name", ""),
                        "arguments": json.dumps(tu.get("input", {})),
                    },
                })
        usage = raw.get("usage", {})
        return ChatResponse(
            content=content_text,
            tool_calls=tool_calls,
            model="",
            usage={
                "prompt_tokens": usage.get("inputTokens", 0),
                "completion_tokens": usage.get("outputTokens", 0),
                "total_tokens": usage.get("totalTokens", 0),
                "cached_tokens": 0,
            },
            finish_reason="stop",
            reasoning_content="",
            usage_source="provider_actual" if usage else "unavailable",
        )

    def parse_stream_chunk(self, chunk: Any) -> str | None:
        delta = chunk.get("delta", {})
        return delta.get("text") or None

    def extract_usage(self, raw: Any) -> dict[str, int]:
        usage = raw.get("usage", {})
        return {
            "prompt_tokens": usage.get("inputTokens", 0),
            "completion_tokens": usage.get("outputTokens", 0),
            "total_tokens": usage.get("totalTokens", 0),
            "cached_tokens": 0,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _messages_to_openai(messages: list[ChatMessage]) -> list[dict[str, Any]]:
    """Serialise ChatMessage list to OpenAI native dicts."""
    out: list[dict[str, Any]] = []
    for m in messages:
        msg: dict[str, Any] = {"role": m.role}
        if isinstance(m.content, list):
            msg["content"] = m.content
        else:
            msg["content"] = m.content
        if m.tool_calls:
            msg["tool_calls"] = m.tool_calls
        if m.tool_call_id:
            msg["tool_call_id"] = m.tool_call_id
        if m.reasoning_content:
            msg["reasoning_content"] = m.reasoning_content
        out.append(msg)
    return out


def _extract_cached_tokens(usage: Any) -> int:
    if not usage:
        return 0
    # OpenAI format
    details = getattr(usage, "prompt_tokens_details", None)
    if details:
        return getattr(details, "cached_tokens", 0) or 0
    # DeepSeek format
    ds_cached = getattr(usage, "prompt_cache_hit_tokens", None)
    if ds_cached is not None:
        return ds_cached or 0
    return 0


def _openai_msg_to_anthropic(m: ChatMessage) -> dict[str, Any]:
    """Convert a single ChatMessage to Anthropic message format."""
    role = "user" if m.role in ("user", "tool") else "assistant"
    content: Any = m.content
    if m.role == "tool":
        content = [
            {
                "type": "tool_result",
                "tool_use_id": m.tool_call_id or "",
                "content": m.content if isinstance(m.content, str) else str(m.content),
            }
        ]
    elif m.tool_calls:
        content = []
        if m.content:
            content.append({"type": "text", "text": m.content})
        for tc in m.tool_calls:
            content.append({
                "type": "tool_use",
                "id": tc.get("id", ""),
                "name": tc.get("function", {}).get("name", ""),
                "input": json.loads(tc.get("function", {}).get("arguments", "{}")),
            })
    return {"role": role, "content": content}


def _openai_tool_to_anthropic(tool: dict[str, Any]) -> dict[str, Any]:
    """Convert OpenAI function tool schema to Anthropic tool schema."""
    func = tool.get("function", tool)
    return {
        "name": func.get("name", ""),
        "description": func.get("description", ""),
        "input_schema": func.get("parameters", {"type": "object"}),
    }


def _openai_msg_to_bedrock(m: ChatMessage) -> dict[str, Any]:
    """Convert a single ChatMessage to Bedrock Converse message format."""
    role = "user" if m.role in ("user", "tool") else "assistant"
    content: list[dict[str, Any]] = []
    if m.role == "tool":
        content.append({
            "toolResult": {
                "toolUseId": m.tool_call_id or "",
                "content": [{"text": m.content if isinstance(m.content, str) else str(m.content)}],
            }
        })
    elif m.tool_calls:
        if m.content:
            content.append({"text": m.content})
        for tc in m.tool_calls:
            content.append({
                "toolUse": {
                    "toolUseId": tc.get("id", ""),
                    "name": tc.get("function", {}).get("name", ""),
                    "input": json.loads(tc.get("function", {}).get("arguments", "{}")),
                }
            })
    else:
        content.append({"text": m.content if isinstance(m.content, str) else str(m.content)})
    return {"role": role, "content": content}


def _openai_tool_to_bedrock(tool: dict[str, Any]) -> dict[str, Any]:
    """Convert OpenAI function tool schema to Bedrock tool schema."""
    func = tool.get("function", tool)
    return {
        "toolSpec": {
            "name": func.get("name", ""),
            "description": func.get("description", ""),
            "inputSchema": {"json": func.get("parameters", {"type": "object"})},
        }
    }


# ---------------------------------------------------------------------------
# Transport registry
# ---------------------------------------------------------------------------

_TRANSPORT_REGISTRY: dict[str, type[BaseTransport]] = {
    "chat_completions": ChatCompletionsTransport,
    "anthropic": AnthropicTransport,
    "bedrock": BedrockTransport,
}


def get_transport(name: str, **kwargs: Any) -> BaseTransport:
    """Factory: instantiate a transport by name."""
    cls = _TRANSPORT_REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"Unknown transport '{name}'. Available: {list(_TRANSPORT_REGISTRY.keys())}")
    return cls(**kwargs)


def list_transports() -> list[str]:
    """Return available transport names."""
    return list(_TRANSPORT_REGISTRY.keys())


import json  # noqa: E402 — imported at end to avoid circular issues during module load
