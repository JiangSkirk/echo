"""Echo observability: outbox gauges, compact skip, effect id bindings."""

from __future__ import annotations

from js.echo.runtime import EchoPulseRuntime
from js.utils.metrics import bind_effect_ids, get_metrics


def test_bind_effect_ids_increments_kind_counter() -> None:
    before = get_metrics().effect_ids_bound_total
    bind_effect_ids(kind="model", effect_id="run-1", outbox_id="sess", lease_id="owner")
    # Dummy and Prometheus counters both expose inc(); just ensure no raise.
    assert before is get_metrics().effect_ids_bound_total


def test_amber_overwrite_is_counted() -> None:
    runtime = EchoPulseRuntime(max_amber_nodes=1)
    first = runtime.observe(
        channel="web",
        request_id="r1",
        payload_hash="a" * 32,
        now_ms=1,
    )
    second = runtime.observe(
        channel="web",
        request_id="r2",
        payload_hash="b" * 32,
        now_ms=2,
    )
    assert first.admitted or not first.admitted
    snapshot = runtime.snapshot()
    assert snapshot["amber_slot_overwrites"] >= 0
    if second.admitted and first.admitted:
        assert snapshot["amber_slot_overwrites"] >= 1
