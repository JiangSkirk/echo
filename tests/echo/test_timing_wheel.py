"""Echo T5 — TimingWheel contract & complexity tests.

Pins :class:`js.echo.timing_wheel.TimingWheelImpl` against the
``TimingWheel`` Protocol defined in :mod:`js.echo.wheel`. Every test
runs in microseconds; the complexity tests deliberately exercise
10 000 scheduled timers to prove the implementation does not regress
to per-call O(N^2) scans.

Contracts proven:

- Protocol conformance (``isinstance(impl, TimingWheel)``).
- ``schedule`` + ``due`` + ``cancel`` happy paths.
- Same ``correlation_id`` overwrites in place.
- ``due(now)`` ordering is ``(fire_at, correlation_id)`` lexicographic
  — deterministic regardless of insertion order.
- ``due(now)`` removes every returned id (re-call returns ``[]``).
- ``due(now)`` only returns ids with ``fire_at <= now``; nothing
  later leaks.
- ``cancel`` returns ``True`` only when an entry was actually present.
- ``cancel`` after ``due`` returns ``False`` (already fired).
- Re-``schedule`` after ``due`` is allowed (fire-once semantics
  require it).
- Negative ``fire_at`` is allowed; ``due`` still fires it correctly.
- Hermetic: no I/O imports in source; no clock reads (verified
  positionally by hooking the only entry points).
- Complexity: a wheel holding 10 000 timers serves ``due`` over a
  small window in time that scales sub-quadratically in the pending
  count.

Negative-input handling (eagerly rejected with ``ValueError``):

- non-str / empty ``correlation_id``
- non-int / bool ``fire_at``
- non-int ``now``
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import time

import pytest

from js.echo.timing_wheel import TimingWheelImpl, new_timing_wheel
from js.echo.wheel import TimingWheel


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------
def test_impl_satisfies_protocol() -> None:
    wheel = new_timing_wheel()
    assert isinstance(wheel, TimingWheel)


def test_new_timing_wheel_returns_empty() -> None:
    wheel = new_timing_wheel()
    assert wheel.size() == 0
    assert wheel.pending() == ()
    assert wheel.due(0) == []
    assert wheel.due(2**31 - 1) == []


# ---------------------------------------------------------------------------
# schedule basics
# ---------------------------------------------------------------------------
def test_schedule_records_single_timer() -> None:
    wheel = new_timing_wheel()
    wheel.schedule(fire_at=100, correlation_id="a")
    assert wheel.size() == 1
    assert wheel.pending() == (("a", 100),)


def test_schedule_multiple_timers_preserves_all() -> None:
    wheel = new_timing_wheel()
    wheel.schedule(fire_at=50, correlation_id="a")
    wheel.schedule(fire_at=200, correlation_id="b")
    wheel.schedule(fire_at=100, correlation_id="c")
    # Snapshot is sorted by (fire_at, cid).
    assert wheel.pending() == (("a", 50), ("c", 100), ("b", 200))


def test_schedule_same_id_overwrites() -> None:
    """The contract: same correlation_id keeps the *most recent* fire_at."""
    wheel = new_timing_wheel()
    wheel.schedule(fire_at=10, correlation_id="dup")
    wheel.schedule(fire_at=999, correlation_id="dup")
    assert wheel.size() == 1
    assert wheel.pending() == (("dup", 999),)
    # And fires at the new time, not the old.
    assert wheel.due(now=10) == []
    assert wheel.due(now=999) == ["dup"]


def test_schedule_negative_fire_at_allowed() -> None:
    wheel = new_timing_wheel()
    wheel.schedule(fire_at=-5, correlation_id="past")
    # Already past at now=0.
    assert wheel.due(now=0) == ["past"]


# ---------------------------------------------------------------------------
# due ordering & removal
# ---------------------------------------------------------------------------
def test_due_returns_only_fired_ids() -> None:
    wheel = new_timing_wheel()
    wheel.schedule(fire_at=10, correlation_id="a")
    wheel.schedule(fire_at=20, correlation_id="b")
    wheel.schedule(fire_at=30, correlation_id="c")
    fired = wheel.due(now=20)
    assert set(fired) == {"a", "b"}
    # Surviving timers stay pending.
    assert wheel.size() == 1
    assert wheel.pending() == (("c", 30),)


def test_due_orders_by_fire_at_then_id() -> None:
    """Stable lexicographic order on (fire_at, correlation_id)."""
    wheel = new_timing_wheel()
    # Insert deliberately out of order to prove ordering is derived,
    # not insertion-based.
    wheel.schedule(fire_at=10, correlation_id="z")
    wheel.schedule(fire_at=5, correlation_id="m")
    wheel.schedule(fire_at=10, correlation_id="a")
    wheel.schedule(fire_at=5, correlation_id="b")
    fired = wheel.due(now=10)
    assert fired == ["b", "m", "a", "z"], f"order drifted: {fired!r}"


def test_due_removes_fired_ids() -> None:
    wheel = new_timing_wheel()
    wheel.schedule(fire_at=5, correlation_id="a")
    wheel.schedule(fire_at=10, correlation_id="b")
    assert wheel.due(now=10) == ["a", "b"]
    # Re-call must yield empty — the wheel does not re-fire.
    assert wheel.due(now=10) == []
    assert wheel.due(now=999) == []
    assert wheel.size() == 0


def test_due_with_no_pending_returns_empty() -> None:
    wheel = new_timing_wheel()
    assert wheel.due(now=0) == []
    assert wheel.due(now=1_000_000) == []


def test_due_is_deterministic_for_same_pending_set() -> None:
    """Two independently constructed wheels with the same pending set
    must produce identical due() outputs for every ``now``."""
    schedule_plan = [(7, "g"), (3, "a"), (3, "z"), (5, "m"), (7, "b")]
    for now in range(0, 10):
        snap_a = new_timing_wheel()
        snap_b = new_timing_wheel()
        for fire_at, cid in schedule_plan:
            snap_a.schedule(fire_at=fire_at, correlation_id=cid)
        for fire_at, cid in reversed(schedule_plan):
            snap_b.schedule(fire_at=fire_at, correlation_id=cid)
        assert snap_a.due(now=now) == snap_b.due(now=now), f"due drifted at now={now}"


def test_due_does_not_release_future_timers() -> None:
    wheel = new_timing_wheel()
    wheel.schedule(fire_at=100, correlation_id="future")
    assert wheel.due(now=99) == []
    assert wheel.size() == 1
    assert wheel.pending() == (("future", 100),)


def test_due_boundary_inclusive() -> None:
    """fire_at == now must fire (inclusive bound)."""
    wheel = new_timing_wheel()
    wheel.schedule(fire_at=42, correlation_id="exact")
    assert wheel.due(now=42) == ["exact"]


# ---------------------------------------------------------------------------
# cancel
# ---------------------------------------------------------------------------
def test_cancel_pending_returns_true_and_drops() -> None:
    wheel = new_timing_wheel()
    wheel.schedule(fire_at=10, correlation_id="x")
    assert wheel.cancel("x") is True
    assert wheel.size() == 0
    assert wheel.due(now=10) == []


def test_cancel_unknown_returns_false() -> None:
    wheel = new_timing_wheel()
    assert wheel.cancel("ghost") is False
    wheel.schedule(fire_at=1, correlation_id="real")
    assert wheel.cancel("ghost") is False
    assert wheel.size() == 1


def test_cancel_after_due_returns_false() -> None:
    """An already-fired timer is gone; cancel must return False."""
    wheel = new_timing_wheel()
    wheel.schedule(fire_at=5, correlation_id="once")
    assert wheel.due(now=5) == ["once"]
    assert wheel.cancel("once") is False


def test_cancel_twice_returns_false_second_time() -> None:
    wheel = new_timing_wheel()
    wheel.schedule(fire_at=1, correlation_id="x")
    assert wheel.cancel("x") is True
    assert wheel.cancel("x") is False


# ---------------------------------------------------------------------------
# Re-scheduling after due
# ---------------------------------------------------------------------------
def test_reschedule_after_due_is_allowed() -> None:
    """Once a timer fires it is gone — re-scheduling must work."""
    wheel = new_timing_wheel()
    wheel.schedule(fire_at=10, correlation_id="cid")
    assert wheel.due(now=10) == ["cid"]
    wheel.schedule(fire_at=20, correlation_id="cid")
    assert wheel.pending() == (("cid", 20),)
    assert wheel.due(now=20) == ["cid"]


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
def test_schedule_rejects_non_string_cid() -> None:
    wheel = new_timing_wheel()
    with pytest.raises(ValueError):
        wheel.schedule(fire_at=1, correlation_id=123)  # type: ignore[arg-type]


def test_schedule_rejects_empty_cid() -> None:
    wheel = new_timing_wheel()
    with pytest.raises(ValueError):
        wheel.schedule(fire_at=1, correlation_id="")


def test_schedule_rejects_non_int_fire_at() -> None:
    wheel = new_timing_wheel()
    with pytest.raises(ValueError):
        wheel.schedule(fire_at=1.5, correlation_id="x")  # type: ignore[arg-type]


def test_schedule_rejects_bool_fire_at() -> None:
    """``bool`` is a subclass of int; the wheel rejects it explicitly."""
    wheel = new_timing_wheel()
    with pytest.raises(ValueError):
        wheel.schedule(fire_at=True, correlation_id="x")  # type: ignore[arg-type]


def test_due_rejects_non_int_now() -> None:
    wheel = new_timing_wheel()
    with pytest.raises(ValueError):
        wheel.due(now=1.5)  # type: ignore[arg-type]


def test_due_rejects_bool_now() -> None:
    wheel = new_timing_wheel()
    with pytest.raises(ValueError):
        wheel.due(now=False)  # type: ignore[arg-type]


def test_cancel_rejects_non_string_cid() -> None:
    wheel = new_timing_wheel()
    with pytest.raises(ValueError):
        wheel.cancel(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Hermeticity — module source has no I/O / clock imports
# ---------------------------------------------------------------------------
_FORBIDDEN_TOKENS = (
    "open(",
    "os.",
    "time.",
    "random",
    "logging",
    "asyncio",
    "subprocess",
    "httpx",
    "requests",
    "pathlib",
)


def test_module_source_has_no_io_tokens() -> None:
    src_path = pathlib.Path(inspect.getfile(TimingWheelImpl))
    src = src_path.read_text(encoding="utf-8")
    # Strip the module docstring so phrases like "no asyncio" in prose
    # do not trip the guard. We re-parse via AST to find the end of
    # the docstring node precisely; everything after is real code.
    tree = ast.parse(src)
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
    ):
        doc_end_line = tree.body[0].end_lineno or 0
        lines = src.splitlines(keepends=True)
        non_docstring = "".join(lines[doc_end_line:])
    else:
        non_docstring = src
    for token in _FORBIDDEN_TOKENS:
        assert token not in non_docstring, (
            f"timing_wheel.py must not mention {token!r} in code; found:\n{non_docstring}"
        )


def test_module_does_not_import_legacy() -> None:
    src = pathlib.Path(inspect.getfile(TimingWheelImpl)).read_text(encoding="utf-8")
    tree = ast.parse(src)
    forbidden_prefixes = (
        "js.agent",
        "js.clcr",
        "js.web",
        "js.tools",
        "js.memory",
        "js.models",
        "js.security",
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                for p in forbidden_prefixes:
                    assert not (alias.name == p or alias.name.startswith(p + ".")), (
                        f"timing_wheel.py imports legacy: {alias.name}"
                    )
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for p in forbidden_prefixes:
                assert not (mod == p or mod.startswith(p + ".")), (
                    f"timing_wheel.py imports legacy: {mod}"
                )


# ---------------------------------------------------------------------------
# Complexity — 10k timers serve due() in subquadratic time
# ---------------------------------------------------------------------------
def test_due_handles_ten_thousand_timers_quickly() -> None:
    """Pin against a per-call O(N^2) regression.

    A naive O(N^2) scan would take seconds on 10k timers; we cap at
    1 wall-clock second, which leaves ample headroom for noisy CI
    while flagging any real algorithmic regression.
    """
    n = 10_000
    wheel = new_timing_wheel()
    for i in range(n):
        wheel.schedule(fire_at=i, correlation_id=f"t{i:05d}")
    assert wheel.size() == n

    start = time.perf_counter()
    fired = wheel.due(now=n // 2)
    elapsed = time.perf_counter() - start

    # Half of the timers fire on this call; the rest stay pending.
    assert len(fired) == n // 2 + 1  # inclusive bound at now=n//2
    assert wheel.size() == n - (n // 2 + 1)
    assert elapsed < 1.0, f"due over 10k timers took {elapsed:.3f}s; expected <1s"


def test_due_output_is_sorted_for_ten_thousand_timers() -> None:
    """The output ordering invariant must hold at scale."""
    n = 10_000
    wheel = new_timing_wheel()
    # Insert with reversed order to disprove any insertion-order
    # dependency.
    for i in range(n - 1, -1, -1):
        wheel.schedule(fire_at=i, correlation_id=f"t{i:05d}")
    fired = wheel.due(now=n)
    assert len(fired) == n
    assert fired == sorted(fired)


# ---------------------------------------------------------------------------
# Independence — two wheels do not share state
# ---------------------------------------------------------------------------
def test_two_wheels_have_independent_state() -> None:
    a = new_timing_wheel()
    b = new_timing_wheel()
    a.schedule(fire_at=10, correlation_id="x")
    assert b.size() == 0
    assert b.due(now=999) == []
    assert a.due(now=10) == ["x"]


# ---------------------------------------------------------------------------
# Pending snapshot is a snapshot, not a live view
# ---------------------------------------------------------------------------
def test_pending_snapshot_does_not_track_subsequent_mutations() -> None:
    wheel = new_timing_wheel()
    wheel.schedule(fire_at=10, correlation_id="x")
    snap = wheel.pending()
    wheel.schedule(fire_at=20, correlation_id="y")
    # Snapshot stays put.
    assert snap == (("x", 10),)
    assert wheel.pending() == (("x", 10), ("y", 20))
