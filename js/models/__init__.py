"""Model management: providers, routing, and context handling."""

from js.models.capability import (
    ProbeResult,
    SafeProviderError,
    infer_capabilities_from_id,
    probe_provider,
    raise_safe_provider_error,
    redact_api_key,
    safe_provider_error,
    sanitize_provider_error,
)
from js.models.providers import ModelProvider, OpenAICompatibleProvider
from js.models.router import ModelRouter
from js.models.stream_events import (
    EventKind,
    StreamEvent,
    parse_anthropic_event,
    parse_openai_chunk,
    text_to_events,
)

__all__ = [
    "EventKind",
    "ModelProvider",
    "ModelRouter",
    "OpenAICompatibleProvider",
    "ProbeResult",
    "SafeProviderError",
    "StreamEvent",
    "infer_capabilities_from_id",
    "parse_anthropic_event",
    "parse_openai_chunk",
    "probe_provider",
    "raise_safe_provider_error",
    "redact_api_key",
    "safe_provider_error",
    "sanitize_provider_error",
    "text_to_events",
]
