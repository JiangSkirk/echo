"""Prefix-cache hit-rate helpers. Exclusive buckets only; warmup excluded."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from js.models.usage import USAGE_SOURCE_PROVIDER, ExclusiveUsageBuckets

HIT_RATE_TARGET = 0.96


def _warmup_totals(
    rows: Iterable[ExclusiveUsageBuckets | dict[str, Any]],
) -> tuple[int, int]:
    read = 0
    denom = 0
    saw_first_write = False
    for raw in rows:
        if isinstance(raw, ExclusiveUsageBuckets):
            if raw.usage_source != USAGE_SOURCE_PROVIDER:
                continue
            write = raw.cache_write
            cache_read = raw.cache_read
            total = raw.input_total
        else:
            if str(raw.get("usage_source") or "") != USAGE_SOURCE_PROVIDER:
                continue
            if raw.get("exclude_from_hit_rate"):
                continue
            write = int(raw.get("cache_write") or 0)
            cache_read = int(raw.get("cache_read") or 0)
            total = int(
                raw.get("input_total") or (int(raw.get("uncached_input") or 0) + cache_read + write)
            )
        if not saw_first_write and write > 0 and cache_read == 0:
            saw_first_write = True
            continue
        saw_first_write = True
        read += cache_read
        denom += total
    return read, denom


def warmup_excluded_hit_rate(rows: Iterable[ExclusiveUsageBuckets | dict[str, Any]]) -> float:
    """``cache_read / input_total`` after dropping the first write of a prefix.

    TTL-expiry first turns should be marked ``exclude_from_hit_rate`` by the
    caller (or appear as a later write-only row) and are also skipped.
    """

    read, denom = _warmup_totals(rows)
    if denom <= 0:
        return 0.0
    return read / denom


def warmup_excluded_hit_rate_or_none(
    rows: Iterable[ExclusiveUsageBuckets | dict[str, Any]],
) -> float | None:
    """Same as ``warmup_excluded_hit_rate``, or ``None`` when nothing counted."""

    read, denom = _warmup_totals(rows)
    if denom <= 0:
        return None
    return read / denom


def note_hit_rate(rate: float | None, *, bot_id: str, prefix_id: str) -> None:
    """Publish the latest warmup-excluded rate; alarm under 96%."""

    if rate is None:
        return
    from js.utils.log import get_logger
    from js.utils.metrics import get_metrics

    metrics = get_metrics()
    metrics.bots_prefix_hit_rate.set(rate)
    if rate >= HIT_RATE_TARGET:
        return
    get_logger("js.bots.prefix").warning(
        "bots prefix hit rate below target",
        extra={
            "bot_id": bot_id,
            "prefix_id": prefix_id,
            "hit_rate": rate,
            "layer": "stable_prefix",
        },
    )
    metrics.bots_prefix_hit_below_target_total.labels(reason="below_96").inc()
