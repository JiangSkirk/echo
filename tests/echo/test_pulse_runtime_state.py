"""Echo pulse runtime state container tests.

These tests pin :class:`js.echo.runtime.EchoPulseRuntime` as the real
cross-pulse container for Amber, the timing wheel and the tide controller.

This suite pins the post-T6-S0 contract:

1. Consecutive ``observe()`` calls accumulate state — amber version is
   strictly monotonic; root hash changes the moment the first
   admitted REQUEST commits.
2. Concurrent ``observe()`` calls do not lose state: with N
   admissions the runtime ends up with ``version == N``.
3. ``reset_pulse_runtime_for_tests()`` returns the runtime to its
   initial empty state (version 0, empty-tree root hash).
4. Once a channel is pushed into ``severe`` on the runtime's
   TideController, subsequent calls for that channel are
   denied — amber version does not advance.
5. ``get_pulse_runtime()`` is lazy: importing the module does not
   build a runtime; only the first ``observe()`` / ``snapshot()``
   call does.
6. ``snapshot()`` returns a *copy* of the state; mutating the returned
   dict cannot affect the runtime.

All tests are pure in-memory. No disk, no network, no real clock.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest

from js.echo.amber_tree import _EMPTY_TREE_HASH_HEX
from js.echo.runtime import (
    EchoPulseRuntime,
    PulseObservation,
    get_pulse_runtime,
    get_pulse_runtime_snapshot_for_tests,
    reset_pulse_runtime_for_tests,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _reset_runtime() -> Iterator[None]:
    """Every test starts with a fresh module-level singleton."""
    reset_pulse_runtime_for_tests()
    yield
    reset_pulse_runtime_for_tests()


# ---------------------------------------------------------------------------
# 1. Single-call observation
# ---------------------------------------------------------------------------
def test_observe_returns_shadow_observation() -> None:
    runtime = EchoPulseRuntime()
    result = runtime.observe(
        channel="api_chat",
        request_id="r1",
        payload_hash="deadbeef",
        now_ms=100,
    )
    assert isinstance(result, PulseObservation)
    assert result.admitted is True
    assert result.amber_version == 1
    # Empty-tree → non-empty: root hash must change.
    assert result.amber_root_hash != _EMPTY_TREE_HASH_HEX
    # An admitted REQUEST yields exactly one EmitResponse action.
    assert result.actions_count == 1


def test_observe_makes_amber_version_strictly_monotonic() -> None:
    runtime = EchoPulseRuntime()
    versions: list[int] = []
    for i in range(10):
        result = runtime.observe(
            channel="api_chat",
            request_id=f"r{i}",
            payload_hash=f"hash{i}",
            now_ms=100 + i,
        )
        versions.append(result.amber_version)
    assert versions == list(range(1, 11))


def test_runtime_bounds_ephemeral_amber_without_resetting_version() -> None:
    runtime = EchoPulseRuntime(max_amber_nodes=8)

    versions = [
        runtime.observe(
            channel="api_chat",
            request_id=f"bounded-{index}",
            payload_hash=f"hash-{index}",
            now_ms=index,
        ).amber_version
        for index in range(100)
    ]

    assert versions == list(range(1, 101))
    snapshot = runtime.snapshot()
    assert snapshot["amber_node_count"] <= 8
    assert snapshot["amber_node_limit"] == 8
    assert snapshot["amber_slot_overwrites"] > 0


def test_denied_request_at_capacity_does_not_clear_amber() -> None:
    runtime = EchoPulseRuntime(max_amber_nodes=2)
    runtime.observe(channel="api_chat", request_id="r1", payload_hash="h1", now_ms=1)
    runtime.observe(channel="api_chat", request_id="r2", payload_hash="h2", now_ms=2)
    before = runtime.snapshot()
    runtime._tide.observe(now=3, channel="api_chat", latency_ms=10_000)

    denied = runtime.observe(
        channel="api_chat",
        request_id="denied",
        payload_hash="blocked",
        now_ms=4,
    )

    after = runtime.snapshot()
    assert denied.admitted is False
    assert after["amber_root_hash"] == before["amber_root_hash"]
    assert after["amber_version"] == before["amber_version"]
    assert after["amber_node_count"] == 2


def test_observe_changes_amber_root_hash_on_first_admit() -> None:
    runtime = EchoPulseRuntime()
    snap_before = runtime.snapshot()
    assert snap_before["amber_root_hash"] == _EMPTY_TREE_HASH_HEX
    assert snap_before["amber_version"] == 0
    runtime.observe(
        channel="api_chat",
        request_id="r1",
        payload_hash="h",
        now_ms=1,
    )
    snap_after = runtime.snapshot()
    assert snap_after["amber_root_hash"] != _EMPTY_TREE_HASH_HEX
    assert snap_after["amber_version"] == 1
    assert snap_after["pulses"] == 1


def test_observe_with_same_request_id_still_advances_version() -> None:
    """Re-committing the same path updates payload but advances version
    — proves the runtime actually threads amber across pulses (a
    fresh fake would never see the second commit)."""
    runtime = EchoPulseRuntime()
    runtime.observe(channel="api_chat", request_id="r1", payload_hash="h1", now_ms=1)
    second = runtime.observe(channel="api_chat", request_id="r1", payload_hash="h2", now_ms=2)
    assert second.amber_version == 2


# ---------------------------------------------------------------------------
# 3. Tide hysteresis carries across pulses
# ---------------------------------------------------------------------------
def test_severe_channel_denies_admission_across_pulses() -> None:
    """Inject a severe latency, then observe a new REQUEST: tide must
    deny it because the runtime keeps the same TideController across
    pulses."""
    runtime = EchoPulseRuntime()
    # Push api_chat into severe directly via the runtime's tide; this
    # Mirrors runtime latency feedback once the caller wires it in.
    runtime._tide.observe(now=0, channel="api_chat", latency_ms=10_000)
    result = runtime.observe(channel="api_chat", request_id="r1", payload_hash="h", now_ms=1)
    assert result.admitted is False
    # A denied REQUEST still emits exactly one backpressure response,
    # but does NOT commit to amber. So pulses ticks, version does not.
    assert result.actions_count == 1
    assert result.amber_version == 0


def test_severe_then_recovery_admits_again() -> None:
    """Severe → low latency observations → channel exits severe; new
    REQUEST gets admitted, amber version advances."""
    from js.echo.tide_controller import new_tide_controller

    runtime = EchoPulseRuntime()
    # Use alpha=1.0 so EWMA snaps to the observed value — the
    # recovery path is then deterministic in 1 step.
    runtime._tide = new_tide_controller(ewma_alpha=1.0)
    runtime._tide.observe(now=0, channel="api_chat", latency_ms=10_000)
    denied = runtime.observe(channel="api_chat", request_id="r1", payload_hash="h", now_ms=1)
    assert denied.admitted is False
    # Drop EWMA all the way down → channel exits severe + congested.
    runtime._tide.observe(now=1, channel="api_chat", latency_ms=10)
    admitted = runtime.observe(channel="api_chat", request_id="r2", payload_hash="h", now_ms=2)
    assert admitted.admitted is True


# ---------------------------------------------------------------------------
# 4. Singleton + reset
# ---------------------------------------------------------------------------
def test_singleton_returned_consistently() -> None:
    r1 = get_pulse_runtime()
    r2 = get_pulse_runtime()
    assert r1 is r2


def test_product_partitions_get_independent_pulse_runtimes() -> None:
    main = get_pulse_runtime("js-agent")
    work = get_pulse_runtime("js-work")

    assert main is not work
    main.observe(channel="api_chat", request_id="same", payload_hash="main", now_ms=1)
    work.observe(channel="api_chat", request_id="same", payload_hash="work", now_ms=1)
    assert main.snapshot()["amber_version"] == 1
    assert work.snapshot()["amber_version"] == 1


def test_reset_for_tests_drops_singleton() -> None:
    r1 = get_pulse_runtime()
    r1.observe(channel="api_chat", request_id="r1", payload_hash="h", now_ms=1)
    reset_pulse_runtime_for_tests()
    r2 = get_pulse_runtime()
    assert r2 is not r1
    snap = r2.snapshot()
    assert snap["amber_version"] == 0
    assert snap["amber_root_hash"] == _EMPTY_TREE_HASH_HEX
    assert snap["pulses"] == 0


def test_snapshot_after_reset_is_empty() -> None:
    snap = get_pulse_runtime_snapshot_for_tests()
    assert snap == {
        "amber_root_hash": _EMPTY_TREE_HASH_HEX,
        "amber_version": 0,
        "amber_node_count": 0,
        "amber_node_limit": 1024,
        "amber_slot_overwrites": 0,
        "wheel_size": 0,
        "tide_channels": [],
        "pulses": 0,
    }


def test_snapshot_returns_independent_dict() -> None:
    """Mutating the snapshot dict must not affect the runtime."""
    snap = get_pulse_runtime_snapshot_for_tests()
    snap["amber_version"] = 999
    snap["tide_channels"].append("forged")
    fresh = get_pulse_runtime_snapshot_for_tests()
    assert fresh["amber_version"] == 0
    assert fresh["tide_channels"] == []


# ---------------------------------------------------------------------------
# 5. Concurrency: parallel observe() does not lose state
# ---------------------------------------------------------------------------
def test_concurrent_observe_does_not_lose_pulses() -> None:
    """N concurrent admissions → final pulses count is exactly N.

    This is the core safety property the runtime lock exists for. A
    naive implementation that rebinds ``_amber`` without holding the
    lock would lose commits to lost-update races. Each call also
    commits a DIFFERENT path (``/request/r{i}``) so a successful
    pulse always strictly advances the node count.
    """
    runtime = EchoPulseRuntime()
    n = 64
    barrier = threading.Barrier(n)

    def _one(i: int) -> int:
        barrier.wait()
        result = runtime.observe(
            channel="api_chat",
            request_id=f"r{i:04d}",
            payload_hash=f"h{i:04d}",
            now_ms=1_000 + i,
        )
        return result.amber_version

    with ThreadPoolExecutor(max_workers=n) as ex:
        versions = list(ex.map(_one, range(n)))

    # Every observation got a unique version because the lock
    # serialised them.
    assert sorted(versions) == list(range(1, n + 1))
    snap = runtime.snapshot()
    assert snap["amber_version"] == n
    assert snap["pulses"] == n


def test_concurrent_observe_keeps_same_wheel_and_tide_instance() -> None:
    """All concurrent calls must hit the same TimingWheel / TideController
    instance — the very point of having a runtime."""
    runtime = EchoPulseRuntime()
    wheel_id = id(runtime._wheel)
    tide_id = id(runtime._tide)

    def _one(i: int) -> tuple[int, int]:
        runtime.observe(
            channel="api_chat",
            request_id=f"r{i}",
            payload_hash=f"h{i}",
            now_ms=2_000 + i,
        )
        return id(runtime._wheel), id(runtime._tide)

    with ThreadPoolExecutor(max_workers=16) as ex:
        ids = list(ex.map(_one, range(16)))

    assert {w for w, _ in ids} == {wheel_id}
    assert {t for _, t in ids} == {tide_id}


# ---------------------------------------------------------------------------
# 6. Reset is idempotent
# ---------------------------------------------------------------------------
def test_reset_is_idempotent() -> None:
    reset_pulse_runtime_for_tests()
    reset_pulse_runtime_for_tests()
    snap = get_pulse_runtime_snapshot_for_tests()
    assert snap["amber_version"] == 0
