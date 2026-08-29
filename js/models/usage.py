"""Exclusive provider usage buckets. Ledger truth is never cached/prompt."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Final, Literal

UsageSource = Literal["provider_actual", "estimated", "unavailable", "tokenizer"]

USAGE_SOURCE_PROVIDER: Final[UsageSource] = "provider_actual"
USAGE_SOURCE_ESTIMATED: Final[UsageSource] = "estimated"
USAGE_SOURCE_UNAVAILABLE: Final[UsageSource] = "unavailable"
USAGE_SOURCE_TOKENIZER: Final[UsageSource] = "tokenizer"

CACHE_READ_RATE: Final[float] = 0.10
CACHE_WRITE_RATE: Final[float] = 1.25


def _as_int(value: Any) -> int:
    if isinstance(value, bool) or value is None:
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _get(obj: Any, name: str, default: int = 0) -> int:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return _as_int(obj.get(name, default))
    return _as_int(getattr(obj, name, default))


@dataclass(frozen=True, slots=True)
class ExclusiveUsageBuckets:
    uncached_input: int = 0
    cache_read: int = 0
    cache_write: int = 0
    output: int = 0
    reasoning: int = 0
    usage_source: UsageSource = USAGE_SOURCE_UNAVAILABLE
    prefix_id: str = ""

    @property
    def input_total(self) -> int:
        return self.uncached_input + self.cache_read + self.cache_write

    @property
    def hit_rate(self) -> float:
        total = self.input_total
        return (self.cache_read / total) if total else 0.0

    def to_usage_dict(self) -> dict[str, int]:
        """Integer usage payload. ``prompt_tokens`` is inclusive input_total."""

        return {
            "prompt_tokens": self.input_total,
            "completion_tokens": self.output,
            "total_tokens": self.input_total + self.output,
            "cached_tokens": self.cache_read,
            "uncached_input": self.uncached_input,
            "cache_read": self.cache_read,
            "cache_write": self.cache_write,
            "output": self.output,
            "reasoning": self.reasoning,
            "input_total": self.input_total,
        }


def merge_usage_dicts(
    current: dict[str, int] | None,
    incoming: dict[str, int],
) -> dict[str, int]:
    """Merge disjoint stream usage frames. Later output-only frames must not wipe input."""

    if current is None:
        return dict(incoming)
    merged = dict(current)
    for key, value in incoming.items():
        if isinstance(value, bool) or not isinstance(value, int):
            continue
        prior = merged.get(key, 0)
        prior_int = prior if isinstance(prior, int) and not isinstance(prior, bool) else 0
        merged[key] = max(prior_int, value)
    return merged


def coerce_usage_source(value: str) -> UsageSource:
    if value == "provider_actual":
        return "provider_actual"
    if value == "estimated":
        return "estimated"
    if value == "unavailable":
        return "unavailable"
    if value == "tokenizer":
        return "tokenizer"
    return USAGE_SOURCE_UNAVAILABLE


def empty_usage(*, source: UsageSource = USAGE_SOURCE_UNAVAILABLE) -> ExclusiveUsageBuckets:
    return ExclusiveUsageBuckets(usage_source=source)


def hit_rate(buckets: ExclusiveUsageBuckets) -> float:
    return buckets.hit_rate


def relative_bucket_error(internal: int, provider: int) -> float:
    """|internal − provider| / max(provider, 1)."""

    return abs(int(internal) - int(provider)) / max(int(provider), 1)


def prefix_cache_id(*, bot_id: str, soul_digest: str, tools_digest: str) -> str:
    material = f"{bot_id}|{soul_digest}|{tools_digest}".encode()
    return hashlib.sha256(material).hexdigest()


def tools_schema_digest(schemas: list[dict[str, Any]] | None) -> str:
    import json

    payload = json.dumps(sorted_tools_schema(schemas or []), separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sorted_tools_schema(schemas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic tools JSON: name sort, object keys sorted recursively."""

    def _sort(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: _sort(value[key]) for key in sorted(value)}
        if isinstance(value, list):
            return [_sort(item) for item in value]
        return value

    ordered = [_sort(schema) for schema in schemas]
    return sorted(ordered, key=lambda item: str(item.get("function", {}).get("name") or ""))


def cost_from_buckets(
    buckets: ExclusiveUsageBuckets,
    *,
    cost_input: float,
    cost_output: float,
) -> float:
    """Price exclusive buckets. Anthropic prompt is uncached; do not subtract read twice."""

    return (
        buckets.uncached_input * cost_input
        + buckets.cache_read * cost_input * CACHE_READ_RATE
        + buckets.cache_write * cost_input * CACHE_WRITE_RATE
        + buckets.output * cost_output
    )


def buckets_from_usage_dict(
    usage: dict[str, Any] | None,
    *,
    source: UsageSource = USAGE_SOURCE_PROVIDER,
    family: str = "openai_inclusive",
) -> ExclusiveUsageBuckets:
    if not usage:
        return empty_usage(source=USAGE_SOURCE_UNAVAILABLE)
    if "uncached_input" in usage or "cache_read" in usage:
        return ExclusiveUsageBuckets(
            uncached_input=_as_int(usage.get("uncached_input")),
            cache_read=_as_int(usage.get("cache_read", usage.get("cached_tokens"))),
            cache_write=_as_int(usage.get("cache_write")),
            output=_as_int(usage.get("output", usage.get("completion_tokens"))),
            reasoning=_as_int(usage.get("reasoning")),
            usage_source=source,
            prefix_id=str(usage.get("prefix_id") or ""),
        )
    if family == "anthropic_exclusive":
        return map_anthropic_usage(usage, source=source)
    return map_openai_usage(usage, source=source)


def map_openai_usage(
    usage: Any, *, source: UsageSource = USAGE_SOURCE_PROVIDER
) -> ExclusiveUsageBuckets:
    """OpenAI-shaped usage: ``prompt_tokens`` includes cache_read."""

    if usage is None:
        return empty_usage(source=USAGE_SOURCE_UNAVAILABLE)
    prompt = _get(usage, "prompt_tokens")
    output = _get(usage, "completion_tokens")
    details = (
        getattr(usage, "prompt_tokens_details", None)
        if not isinstance(usage, dict)
        else usage.get("prompt_tokens_details")
    )
    cache_read = (
        _get(details, "cached_tokens") if details is not None else _get(usage, "cached_tokens")
    )
    if cache_read == 0:
        cache_read = _get(usage, "prompt_cache_hit_tokens")
    cache_write = _get(details, "cache_write_tokens") if details is not None else 0
    if cache_write == 0:
        cache_write = _get(usage, "cache_creation_input_tokens")
    completion_details = (
        getattr(usage, "completion_tokens_details", None)
        if not isinstance(usage, dict)
        else usage.get("completion_tokens_details")
    )
    reasoning = (
        _get(completion_details, "reasoning_tokens") if completion_details is not None else 0
    )
    uncached = max(prompt - cache_read - cache_write, 0)
    return ExclusiveUsageBuckets(
        uncached_input=uncached,
        cache_read=cache_read,
        cache_write=cache_write,
        output=output,
        reasoning=reasoning,
        usage_source=source
        if prompt or output or cache_read or cache_write
        else USAGE_SOURCE_UNAVAILABLE,
    )


def map_anthropic_usage(
    usage: Any, *, source: UsageSource = USAGE_SOURCE_PROVIDER
) -> ExclusiveUsageBuckets:
    """Anthropic-shaped usage: ``input_tokens`` excludes cache read/write."""

    if usage is None:
        return empty_usage(source=USAGE_SOURCE_UNAVAILABLE)
    uncached = _get(usage, "input_tokens")
    cache_read = _get(usage, "cache_read_input_tokens")
    cache_write = _get(usage, "cache_creation_input_tokens")
    output = _get(usage, "output_tokens")
    if output == 0:
        output = _get(usage, "completion_tokens")
    reasoning = _get(usage, "reasoning_tokens")
    return ExclusiveUsageBuckets(
        uncached_input=uncached,
        cache_read=cache_read,
        cache_write=cache_write,
        output=output,
        reasoning=reasoning,
        usage_source=source
        if (uncached or cache_read or cache_write or output)
        else USAGE_SOURCE_UNAVAILABLE,
    )


def map_bedrock_usage(
    usage: Any, *, source: UsageSource = USAGE_SOURCE_PROVIDER
) -> ExclusiveUsageBuckets:
    if not usage:
        return empty_usage(source=USAGE_SOURCE_UNAVAILABLE)
    if isinstance(usage, dict):
        uncached = _as_int(usage.get("inputTokens", usage.get("prompt_tokens")))
        output = _as_int(usage.get("outputTokens", usage.get("completion_tokens")))
        cache_read = _as_int(usage.get("cacheReadInputTokens", usage.get("cached_tokens")))
        cache_write = _as_int(usage.get("cacheWriteInputTokens", usage.get("cache_write")))
    else:
        uncached = _get(usage, "inputTokens")
        output = _get(usage, "outputTokens")
        cache_read = _get(usage, "cacheReadInputTokens")
        cache_write = _get(usage, "cacheWriteInputTokens")
    return ExclusiveUsageBuckets(
        uncached_input=uncached,
        cache_read=cache_read,
        cache_write=cache_write,
        output=output,
        usage_source=source
        if (uncached or output or cache_read or cache_write)
        else USAGE_SOURCE_UNAVAILABLE,
    )


def warmup_hit_rate(
    samples: list[ExclusiveUsageBuckets],
    *,
    exclude_first_write: bool = True,
) -> float:
    """Hit rate after dropping the first cache-write sample (warmup / post-TTL)."""

    usable = list(samples)
    if exclude_first_write:
        for index, sample in enumerate(usable):
            if sample.cache_write > 0 and sample.cache_read == 0:
                usable = usable[index + 1 :]
                break
    read = sum(item.cache_read for item in usable)
    total = sum(item.input_total for item in usable)
    return (read / total) if total else 0.0


__all__ = [
    "CACHE_READ_RATE",
    "CACHE_WRITE_RATE",
    "ExclusiveUsageBuckets",
    "USAGE_SOURCE_ESTIMATED",
    "USAGE_SOURCE_PROVIDER",
    "USAGE_SOURCE_TOKENIZER",
    "USAGE_SOURCE_UNAVAILABLE",
    "UsageSource",
    "buckets_from_usage_dict",
    "coerce_usage_source",
    "cost_from_buckets",
    "empty_usage",
    "hit_rate",
    "map_anthropic_usage",
    "map_bedrock_usage",
    "map_openai_usage",
    "merge_usage_dicts",
    "prefix_cache_id",
    "relative_bucket_error",
    "sorted_tools_schema",
    "tools_schema_digest",
    "warmup_hit_rate",
]
