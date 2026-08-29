"""Exclusive usage buckets: OpenAI inclusive prompt vs Anthropic three-part input."""

from __future__ import annotations

from types import SimpleNamespace

from js.models.usage import (
    ExclusiveUsageBuckets,
    cost_from_buckets,
    map_anthropic_usage,
    map_openai_usage,
    merge_usage_dicts,
    relative_bucket_error,
    warmup_hit_rate,
)
from js.web.stats_store import TokenStatsStore


def test_openai_inclusive_prompt_maps_without_double_count() -> None:
    usage = SimpleNamespace(
        prompt_tokens=1000,
        completion_tokens=40,
        total_tokens=1040,
        prompt_tokens_details=SimpleNamespace(cached_tokens=800),
    )
    buckets = map_openai_usage(usage)
    assert buckets.uncached_input == 200
    assert buckets.cache_read == 800
    assert buckets.cache_write == 0
    assert buckets.input_total == 1000
    assert buckets.output == 40
    assert relative_bucket_error(buckets.input_total, 1000) <= 0.02
    assert relative_bucket_error(buckets.cache_read, 800) == 0.0
    assert abs(buckets.hit_rate - 0.8) < 1e-9


def test_anthropic_three_component_input_matches_openai_hit_rate() -> None:
    usage = SimpleNamespace(
        input_tokens=200,
        cache_read_input_tokens=800,
        cache_creation_input_tokens=50,
        output_tokens=40,
    )
    buckets = map_anthropic_usage(usage)
    assert buckets.uncached_input == 200
    assert buckets.cache_read == 800
    assert buckets.cache_write == 50
    assert buckets.input_total == 1050
    assert buckets.output == 40
    assert relative_bucket_error(buckets.uncached_input, 200) == 0.0
    assert relative_bucket_error(buckets.cache_read, 800) == 0.0
    assert relative_bucket_error(buckets.cache_write, 50) == 0.0
    openai_like = map_openai_usage(
        SimpleNamespace(
            prompt_tokens=1000,
            completion_tokens=40,
            prompt_tokens_details=SimpleNamespace(cached_tokens=800),
        )
    )
    # Same read/uncached pair produces the same hit-rate formula even though
    # Anthropic also reported a write. Writes sit in the denominator only.
    assert openai_like.cache_read / openai_like.input_total == 0.8
    assert buckets.cache_read / buckets.input_total == 800 / 1050


def test_hit_rate_never_uses_cached_over_prompt(tmp_path) -> None:
    store = TokenStatsStore(tmp_path)
    store.record(
        "claude",
        "anthropic",
        prompt_tokens=200,
        completion_tokens=10,
        cached_tokens=800,
        uncached_input=200,
        cache_read=800,
        cache_write=0,
        output=10,
        input_total=1000,
        usage_source="provider_actual",
    )
    summary = store.get_summary(days=30)
    # Old formula cached/prompt would be 800/200 = 400%. Exclusive denom is 1000.
    assert summary["cache_rate"] == 80.0
    assert summary["total_prompt_tokens"] == 1000
    assert summary["total_cached_tokens"] == 800


def test_anthropic_cost_does_not_subtract_read_from_already_uncached_prompt() -> None:
    buckets = ExclusiveUsageBuckets(
        uncached_input=200,
        cache_read=800,
        cache_write=0,
        output=10,
        usage_source="provider_actual",
    )
    cost = cost_from_buckets(buckets, cost_input=0.001, cost_output=0.002)
    assert cost == 200 * 0.001 + 800 * 0.001 * 0.10 + 10 * 0.002


def test_warmup_excludes_first_write() -> None:
    samples = [
        ExclusiveUsageBuckets(uncached_input=20, cache_write=980, output=5),
        ExclusiveUsageBuckets(uncached_input=20, cache_read=980, output=5),
        ExclusiveUsageBuckets(uncached_input=20, cache_read=980, output=5),
    ]
    rate = warmup_hit_rate(samples)
    assert rate >= 0.96
    assert rate == 1960 / 2000


def test_stream_usage_frames_merge_disjoint_buckets() -> None:
    start = map_anthropic_usage(
        {
            "input_tokens": 200,
            "cache_read_input_tokens": 800,
            "cache_creation_input_tokens": 50,
            "output_tokens": 0,
        }
    ).to_usage_dict()
    delta = map_anthropic_usage({"input_tokens": 0, "output_tokens": 40}).to_usage_dict()
    merged = merge_usage_dicts(start, delta)
    assert merged["uncached_input"] == 200
    assert merged["cache_read"] == 800
    assert merged["cache_write"] == 50
    assert merged["output"] == 40
    assert merged["input_total"] == 1050
