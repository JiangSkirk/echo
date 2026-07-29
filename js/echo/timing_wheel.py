"""Echo T5 — TimingWheel implementation.

Real, deterministic, zero-I/O backing for the
:class:`js.echo.wheel.TimingWheel` Protocol. The wheel never reads the
real clock; ``now`` is always handed in by the caller (``pulse()`` for
the kernel, tests directly otherwise).

Semantics (frozen by ``tests/echo/test_timing_wheel.py``):

- ``schedule(fire_at, correlation_id)``
    Register or **overwrite** the future firing time for
    ``correlation_id``. Two schedules with the same id keep only the
    most recent ``fire_at``. O(1) amortised.

- ``due(now)``
    Return every ``correlation_id`` whose stored ``fire_at`` is
    ``<= now``, in **stable lexicographic order** of the pair
    ``(fire_at, correlation_id)``, and remove every returned id from
    the pending set. Re-scheduling a returned id after ``due`` is
    fully supported. O(P log P) on a single call where ``P`` is the
    number of pending timers — *not* the number of timers ever
    scheduled. The wheel never iterates timers it already fired.

- ``cancel(correlation_id)``
    Remove ``correlation_id`` from the pending set if present.
    Returns ``True`` iff a pending entry was actually removed. O(1).

Determinism guarantees:

- ``due(now)`` ordering is a pure function of the pending set; no
  insertion-order dependency.
- A fresh :class:`TimingWheelImpl` produced by :func:`new_timing_wheel`
  has the same observable behaviour as any other empty wheel
  (``pending() == ()``, ``due(any_now) == []``).

Hermetic guarantees:

- No imports outside the standard library typing surface.
- No filesystem, network, clock, logging, randomness, asyncio or
  subprocess. The module is safe to import inside ``pulse()``.

The implementation deliberately stays small. A 32-bucket "real" hashed
wheel would be premature optimisation: at the Echo kernel's tick
granularity the pending set is bounded by the in-flight ``Resonate``
actions, which T6 will additionally cap via the ledger. The dict-based
representation gives exact semantics today and leaves the door open
for a hashed-wheel substitution behind the same Protocol.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TimingWheelImpl:
    """Pure-dict implementation of :class:`js.echo.wheel.TimingWheel`.

    Internal state:

    - ``_pending`` maps ``correlation_id`` to its scheduled ``fire_at``.
      The mapping is the single source of truth — there is no
      secondary ordered structure; ordering is derived on demand by
      :meth:`due` and :meth:`pending`. Duplicate ``correlation_id``
      schedules overwrite in place: the dict slot is reassigned, no
      stale entry remains. This is the explicit T5 contract.

    The dataclass is **mutable on purpose** — ``pulse()`` is a pure
    function over the kernel state graph, but the wheel itself is a
    mutable Protocol implementation threaded through Echo's runtime layer.
    The mutation surface is restricted to the three Protocol methods plus
    :meth:`pending` (test-only view).
    """

    _pending: dict[str, int] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Protocol surface
    # ------------------------------------------------------------------
    def schedule(self, fire_at: int, correlation_id: str) -> None:
        """Register / overwrite a timer for ``correlation_id``.

        Inputs are validated eagerly so a misuse fails loudly at the
        call site rather than corrupting the pending set:

        - ``correlation_id`` must be a non-empty ``str``.
        - ``fire_at`` must be an ``int`` (``bool`` is rejected because
          it is technically a subclass of ``int``).

        Negative ``fire_at`` is allowed and means "already past, fire
        on the next ``due(now)`` with ``now >= fire_at``". Tests rely
        on this to seed already-due timers.
        """
        if not isinstance(correlation_id, str):
            raise ValueError(
                f"TimingWheel.schedule: correlation_id must be str, "
                f"got {type(correlation_id).__name__}"
            )
        if not correlation_id:
            raise ValueError("TimingWheel.schedule: correlation_id must be non-empty")
        if isinstance(fire_at, bool) or not isinstance(fire_at, int):
            raise ValueError(
                f"TimingWheel.schedule: fire_at must be int, got {type(fire_at).__name__}"
            )
        # Plain dict assignment is the single mutation point. Same key
        # → in-place overwrite. The T5 contract pins this verbatim.
        self._pending[correlation_id] = fire_at

    def due(self, now: int) -> list[str]:
        """Return every id with ``fire_at <= now`` and pop it.

        Stable order: sort by ``(fire_at, correlation_id)``. Two ids
        with the same ``fire_at`` resolve to lexicographic order on
        the correlation id itself. The same input set always produces
        the same output sequence — this is what the kernel relies on
        for replay determinism.

        Inputs are validated for type but not for sign — a negative
        ``now`` is meaningful (no timers have fired yet against a
        post-init clock that was wound backwards) and the contract
        tests exercise that path.
        """
        if isinstance(now, bool) or not isinstance(now, int):
            raise ValueError(f"TimingWheel.due: now must be int, got {type(now).__name__}")

        # Collect (fire_at, id) for everything that has fired. A
        # single pass over the dict is O(P); the secondary sort is
        # O(D log D) where D is the number of due ids — never more
        # than P. Both bounds are documented in the module docstring.
        fired: list[tuple[int, str]] = [
            (fire_at, cid) for cid, fire_at in self._pending.items() if fire_at <= now
        ]
        fired.sort()
        for _, cid in fired:
            # ``pop`` rather than ``del`` so a concurrent mutation
            # would surface as a KeyError, not a silent skip. The
            # wheel is single-threaded by design (it lives on the
            # pulse() call stack) but defensive deletion is cheap.
            self._pending.pop(cid, None)
        return [cid for _, cid in fired]

    def cancel(self, correlation_id: str) -> bool:
        """Drop a pending timer if any.

        Returns ``True`` iff a pending entry was actually removed.
        Cancelling an id that was never scheduled, or one that was
        already returned by :meth:`due`, returns ``False`` — these
        are not errors.
        """
        if not isinstance(correlation_id, str):
            raise ValueError(
                f"TimingWheel.cancel: correlation_id must be str, "
                f"got {type(correlation_id).__name__}"
            )
        return self._pending.pop(correlation_id, None) is not None

    # ------------------------------------------------------------------
    # Test-only inspection. Not part of the Protocol; tests rely on it
    # to assert internal state without mutating it.
    # ------------------------------------------------------------------
    def pending(self) -> tuple[tuple[str, int], ...]:
        """Return a stable snapshot of pending ``(id, fire_at)`` pairs.

        Ordering: by ``(fire_at, correlation_id)`` — the same scheme
        :meth:`due` uses, so a test can compare ``pending()`` against
        the next ``due(now)`` output without re-sorting.
        """
        items = sorted(self._pending.items(), key=lambda kv: (kv[1], kv[0]))
        return tuple((cid, fire_at) for cid, fire_at in items)

    def size(self) -> int:
        """Number of timers still pending. O(1)."""
        return len(self._pending)


def new_timing_wheel() -> TimingWheelImpl:
    """Build a fresh empty :class:`TimingWheelImpl`.

    Tests use this factory rather than the dataclass constructor so
    the internal state surface can change later without rippling
    through every test file.
    """
    return TimingWheelImpl()


__all__ = [
    "TimingWheelImpl",
    "new_timing_wheel",
]
