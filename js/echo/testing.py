"""Echo pure-in-memory test fakes.

This module supplies trivial, fully observable stand-ins for the AmberTree
/ TimingWheel / TideController Protocols defined in :mod:`js.echo.amber`,
:mod:`js.echo.wheel`, and :mod:`js.echo.tide`. They exist for one reason:
contract tests need a deterministic, hermetic substrate that proves the kernel
uses collaborators only through the published Echo protocols.

Design constraints (these are gates, not aspirations):

- **No I/O.** Not files, not the clock, not the network, not logging.
- **No hidden mutation of inputs.** The fakes report what was *asked* of them
  via per-instance call counters and keep structural behavior deliberately
  simple.
- **No legacy imports.** Everything is built from stdlib + ``js.echo.*``
  Protocol surfaces.
- **Hand-out-only.** Fakes are constructed via ``new_*`` factories so
  tests don't accidentally share instances and assume per-test isolation.

These fakes are intentionally minimal: the goal is to make the contract-level
invariants of ``pulse()`` checkable, not to model the full AmberTree,
TimingWheel, or TideController semantics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Self

from js.echo.amber import AmberTree, ContextView, Delta, NodeStatus, ReadyIndex
from js.echo.tide import TideController
from js.echo.types import Budget
from js.echo.wheel import TimingWheel


# ---------------------------------------------------------------------------
# FakeClock — deterministic, injected-only time source
# ---------------------------------------------------------------------------
@dataclass
class FakeClock:
    """A clock that returns whatever the test gives it.

    The kernel never reads a clock directly; callers always inject ``now``
    explicitly. ``FakeClock`` is for *tests* that need a stable
    monotonic-ish time value, and for asserting that ``pulse()`` did not
    call ``now()`` itself (it can't — the fake has no hook into
    :mod:`js.echo.core`).
    """

    current: int = 0
    reads: int = 0

    def now(self) -> int:
        """Return the current frozen time. Counted via ``reads``."""
        self.reads += 1
        return self.current

    def advance(self, delta: int) -> int:
        """Move the clock forward by ``delta`` and return the new value."""
        if delta < 0:
            raise ValueError(f"FakeClock cannot run backwards: delta={delta}")
        self.current += delta
        return self.current


# ---------------------------------------------------------------------------
# FakeReadyIndex / FakeContextView — companions for FakeAmberTree
# ---------------------------------------------------------------------------
@dataclass
class FakeReadyIndex:
    """Static ready-index whose ``topk`` is a pure prefix slice."""

    paths: tuple[str, ...] = ()
    topk_calls: int = 0

    def topk(self, n: int) -> list[str]:
        self.topk_calls += 1
        if n < 0:
            raise ValueError(f"topk: n must be >= 0, got {n}")
        return list(self.paths[:n])


@dataclass
class FakeContextView:
    """Static context view; the digest is what the test wrote in."""

    digest_value: bytes = b""

    @property
    def digest(self) -> bytes:
        return self.digest_value


# ---------------------------------------------------------------------------
# FakeAmberTree — no-op CoW substrate
# ---------------------------------------------------------------------------
@dataclass
class FakeAmberTree:
    """A minimal :class:`AmberTree` Protocol implementation.

    Every CoW method returns ``self`` and increments a private counter. Tests
    can assert collaborator calls without constructing a full HAMT.
    """

    root_hash_value: str = "h0"
    ready_paths: tuple[str, ...] = ()
    context_digest: bytes = b""
    delta_payload: bytes = b""

    commit_checked_calls: int = 0
    mark_calls: int = 0
    ready_index_calls: int = 0
    context_view_calls: int = 0
    delta_since_last_calls: int = 0

    @property
    def root_hash(self) -> str:
        return self.root_hash_value

    def commit_checked(self, path: str, payload: bytes) -> Self:
        self.commit_checked_calls += 1
        # No structural change at the fake level; identity-preserving by design.
        return self

    def mark(self, path: str, status: NodeStatus) -> Self:
        self.mark_calls += 1
        return self

    def ready_index(self) -> ReadyIndex:
        self.ready_index_calls += 1
        return FakeReadyIndex(paths=self.ready_paths)

    def context_view(self, path: str) -> ContextView:
        self.context_view_calls += 1
        return FakeContextView(digest_value=self.context_digest)

    def delta_since_last(self) -> Delta:
        self.delta_since_last_calls += 1
        return Delta(from_version=0, to_version=0, payload=self.delta_payload)


# ---------------------------------------------------------------------------
# FakeTimingWheel — observable Protocol implementation
# ---------------------------------------------------------------------------
@dataclass
class FakeTimingWheel:
    """A timing wheel that records every call but fires nothing.

    The fake is observable enough to test scheduler contract calls without
    pulling in a real wheel: each method increments a per-instance counter.
    ``due()`` returns an empty list by default; tests that need due timers can
    subclass or replace this fake.
    """

    schedule_calls: list[tuple[int, str]] = field(default_factory=list)
    due_calls: list[int] = field(default_factory=list)
    cancel_calls: list[str] = field(default_factory=list)

    def schedule(self, fire_at: int, correlation_id: str) -> None:
        self.schedule_calls.append((fire_at, correlation_id))

    def due(self, now: int) -> list[str]:
        self.due_calls.append(now)
        return []

    def cancel(self, correlation_id: str) -> bool:
        self.cancel_calls.append(correlation_id)
        return False


# ---------------------------------------------------------------------------
# FakeTideController — observable Protocol implementation
# ---------------------------------------------------------------------------
@dataclass
class FakeTideController:
    """A tide controller that admits everything and records every call.

    Like :class:`FakeTimingWheel`, the goal is *observability* of method
    invocations, not policy fidelity. The default budget is intentionally
    permissive (all positive) so tests do not fail because of a zero budget
    unless that is what they are specifically exercising.
    """

    admit_default: bool = True
    default_budget: Budget = field(
        default_factory=lambda: Budget(tokens=1_000, wall_ms=1_000, depth=8)
    )

    admit_calls: list[tuple[int, str]] = field(default_factory=list)
    budget_calls: list[str] = field(default_factory=list)
    observe_calls: list[tuple[int, str, int]] = field(default_factory=list)

    def admit(self, now: int, channel: str) -> bool:
        self.admit_calls.append((now, channel))
        return self.admit_default

    def budget_for(self, channel: str) -> Budget:
        self.budget_calls.append(channel)
        return self.default_budget

    def observe(self, now: int, channel: str, latency_ms: int) -> None:
        self.observe_calls.append((now, channel, latency_ms))


# ---------------------------------------------------------------------------
# Factories — preferred constructor surface for tests
# ---------------------------------------------------------------------------
def new_fake_amber(
    *,
    root_hash: str = "h0",
    ready_paths: tuple[str, ...] = (),
    context_digest: bytes = b"",
    delta_payload: bytes = b"",
) -> FakeAmberTree:
    """Build a fresh :class:`FakeAmberTree` (no shared state across tests)."""
    return FakeAmberTree(
        root_hash_value=root_hash,
        ready_paths=ready_paths,
        context_digest=context_digest,
        delta_payload=delta_payload,
    )


def new_fake_wheel() -> FakeTimingWheel:
    """Build a fresh :class:`FakeTimingWheel`."""
    return FakeTimingWheel()


def new_fake_tide(
    *,
    admit_default: bool = True,
    budget: Budget | None = None,
) -> FakeTideController:
    """Build a fresh :class:`FakeTideController`."""
    if budget is None:
        return FakeTideController(admit_default=admit_default)
    return FakeTideController(admit_default=admit_default, default_budget=budget)


def new_fake_clock(*, current: int = 0) -> FakeClock:
    """Build a fresh :class:`FakeClock` starting at ``current``."""
    return FakeClock(current=current)


__all__ = [
    "FakeAmberTree",
    "FakeClock",
    "FakeContextView",
    "FakeReadyIndex",
    "FakeTideController",
    "FakeTimingWheel",
    "new_fake_amber",
    "new_fake_clock",
    "new_fake_tide",
    "new_fake_wheel",
]


# ---------------------------------------------------------------------------
# Type-only assertions (Protocol conformance)
# ---------------------------------------------------------------------------
# Static check: each fake structurally satisfies its Protocol. mypy's
# structural typing accepts these because every Protocol method on
# AmberTree / TimingWheel / TideController is implemented above with a
# matching signature. Runtime conformance (via ``isinstance(..., Protocol)``)
# is asserted in tests/echo/test_pulse_purity.py.
_: AmberTree = FakeAmberTree()
__: TimingWheel = FakeTimingWheel()
___: TideController = FakeTideController()
