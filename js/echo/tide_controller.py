"""Echo T5 — TideController implementation.

Real, deterministic, zero-I/O backing for the
:class:`js.echo.tide.TideController` Protocol. ``admit`` /
``budget_for`` / ``observe`` are pure with respect to wall-clock —
the controller never reads the real time; ``now`` is always injected
by the caller.

Policy (frozen by ``tests/echo/test_tide_controller.py``):

- **Per-channel isolation.** Every channel keeps its own state
  vector — latency EWMA, congestion mode, last-update timestamp.
  Observing latency on channel A never changes the budget or
  admission for channel B. The kernel feeds latency back through
  :meth:`observe` after each unit of work; everything else is
  derived from that single signal.

- **Three states with hysteresis.**

  - ``normal``    — EWMA below ``exit_low_ms``; ``admit`` returns
    ``True``; ``budget_for`` returns the baseline budget.
  - ``congested`` — EWMA in ``[exit_low_ms, severe_ms)`` after first
    crossing ``enter_high_ms``; ``admit`` still returns ``True`` —
    the kernel reduces work via the shrunk budget, not by dropping
    requests. ``budget_for`` returns a smaller budget (half tokens,
    half wall_ms, half depth, with a minimum floor of 1 on each).
  - ``severe``    — EWMA >= ``severe_ms``; ``admit`` returns
    ``False`` for new requests on that channel until the next
    ``observe`` brings EWMA back down. This is the only state in
    which admission is denied — and it is denied **per-channel**
    only.

  Hysteresis is built in by separating ``enter_high_ms`` (lower
  threshold to enter ``congested``) from ``exit_low_ms`` (must drop
  below this to leave ``congested``). A single slow request followed
  by fast ones cannot flap the controller back and forth.

- **Safety stays put.** :class:`js.echo.types.Budget` carries only
  ``tokens / wall_ms / depth`` — three *capacity* knobs. There is
  no sandbox, auth or guard field on Budget for ``TideController``
  to weaken; congestion shrinks capacity only. The
  ``test_tide_controller.py::test_congestion_does_not_change_budget_field_set``
  contract pins this invariant.

- **Determinism.** With identical observed-latency history, two
  controllers produce identical admission decisions and identical
  budgets for every channel. There is no randomness, no clock, no
  shared global state.

Hermetic guarantees: no filesystem / network / clock / logging /
randomness / asyncio / subprocess. Safe to import inside ``pulse()``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from js.echo.types import Budget

# ---------------------------------------------------------------------------
# Default policy constants. These are deliberately picked to be obviously
# wider than any single request's measured latency in shadow mode so the
# controller stays in ``normal`` unless real downstream latency is actually
# pathological.
# ---------------------------------------------------------------------------
# EWMA smoothing factor. Higher = more responsive, lower = smoother.
# 0.3 is a conservative middle ground — three slow samples in a row
# pull the EWMA up by ~66% of the gap, fast enough to react within a
# handful of pulses without overshooting on a single outlier.
DEFAULT_EWMA_ALPHA: float = 0.3

# Latency thresholds in milliseconds.
DEFAULT_ENTER_HIGH_MS: int = 500
DEFAULT_EXIT_LOW_MS: int = 200
DEFAULT_SEVERE_MS: int = 2_000

# Baseline budget used when a channel is in ``normal`` state. Tight
# enough to be a meaningful ceiling; wide enough that ``congested``
# halving still leaves a workable budget.
DEFAULT_BASELINE_BUDGET: Budget = Budget(tokens=1_000, wall_ms=1_000, depth=8)


# ---------------------------------------------------------------------------
# Channel state
# ---------------------------------------------------------------------------
@dataclass
class _ChannelState:
    """Mutable per-channel observation state.

    All fields are derived from the ``observe`` history. Nothing is
    read from the real clock; ``last_seen_now`` is whatever the
    caller has handed in — it is exposed for tests, not consumed by
    the controller's own logic.
    """

    ewma_latency_ms: float = 0.0
    is_congested: bool = False
    is_severe: bool = False
    observe_count: int = 0
    last_seen_now: int = 0


@dataclass
class TideControllerImpl:
    """In-memory deterministic :class:`js.echo.tide.TideController`.

    The controller is configurable for tests (so we can exercise the
    hysteresis with smaller thresholds) but production callers should
    use :func:`new_tide_controller` with no arguments, which pins
    every knob to the module-level defaults.
    """

    baseline_budget: Budget = DEFAULT_BASELINE_BUDGET
    enter_high_ms: int = DEFAULT_ENTER_HIGH_MS
    exit_low_ms: int = DEFAULT_EXIT_LOW_MS
    severe_ms: int = DEFAULT_SEVERE_MS
    ewma_alpha: float = DEFAULT_EWMA_ALPHA

    _channels: dict[str, _ChannelState] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Threshold sanity. Catches misconfiguration at construction
        # time rather than letting it cause stuck congestion later.
        if not (0 < self.exit_low_ms < self.enter_high_ms < self.severe_ms):
            raise ValueError(
                "TideController thresholds must satisfy "
                "0 < exit_low_ms < enter_high_ms < severe_ms; "
                f"got exit_low_ms={self.exit_low_ms}, "
                f"enter_high_ms={self.enter_high_ms}, "
                f"severe_ms={self.severe_ms}"
            )
        if not (0.0 < self.ewma_alpha <= 1.0):
            raise ValueError(f"TideController.ewma_alpha must be in (0, 1]; got {self.ewma_alpha}")
        if (
            self.baseline_budget.tokens <= 0
            or self.baseline_budget.wall_ms <= 0
            or self.baseline_budget.depth <= 0
        ):
            raise ValueError(
                "TideController.baseline_budget must have strictly positive "
                f"tokens/wall_ms/depth; got {self.baseline_budget!r}"
            )

    # ------------------------------------------------------------------
    # Protocol surface
    # ------------------------------------------------------------------
    def admit(self, now: int, channel: str) -> bool:
        """Return False iff the named channel is currently in ``severe``.

        ``now`` is accepted for Protocol parity; the controller does
        not use it for admission. State is purely a function of the
        observed latency history for that channel.
        """
        self._validate_now(now)
        self._validate_channel(channel)
        state = self._channels.get(channel)
        if state is None:
            # Unknown channel → no history → fully admitted with
            # baseline budget. The first observation creates the
            # state lazily.
            return True
        return not state.is_severe

    def budget_for(self, channel: str) -> Budget:
        """Return the current budget for ``channel``.

        - Unknown / ``normal`` channels: baseline budget.
        - ``congested`` channels: capacity knobs halved (floored to 1).
        - ``severe`` channels: same shrunk budget as ``congested`` —
          the budget itself does not vanish; admission is what gates
          new work. The shrunk budget still applies to whatever the
          caller chooses to do in-flight on that channel.

        Field set is invariant. Only the three capacity knobs
        (``tokens / wall_ms / depth``) ever change; no safety knob
        is added or removed because :class:`Budget` does not carry
        one.
        """
        self._validate_channel(channel)
        state = self._channels.get(channel)
        if state is None or not (state.is_congested or state.is_severe):
            return self.baseline_budget
        return _halve_budget(self.baseline_budget)

    def observe(self, now: int, channel: str, latency_ms: int) -> None:
        """Feed an observed latency back into the controller.

        The EWMA is updated in place; state transitions are evaluated
        immediately so subsequent ``admit`` / ``budget_for`` calls
        see the new mode. State transitions are hysteretic:

        - ``normal``    → ``congested`` when EWMA >= ``enter_high_ms``
        - ``congested`` → ``normal``    when EWMA <  ``exit_low_ms``
        - any           → ``severe``    when EWMA >= ``severe_ms``
        - ``severe``    → ``congested`` when EWMA <  ``severe_ms``
                                       (and still >= ``exit_low_ms``)
        """
        self._validate_now(now)
        self._validate_channel(channel)
        if isinstance(latency_ms, bool) or not isinstance(latency_ms, int):
            raise ValueError(
                f"TideController.observe: latency_ms must be int, got {type(latency_ms).__name__}"
            )
        if latency_ms < 0:
            raise ValueError(f"TideController.observe: latency_ms must be >= 0; got {latency_ms}")

        state = self._channels.get(channel)
        if state is None:
            state = _ChannelState()
            self._channels[channel] = state

        # EWMA. On the very first observation, the EWMA snaps to the
        # observed value — there is no prior smoothing to anchor to.
        if state.observe_count == 0:
            state.ewma_latency_ms = float(latency_ms)
        else:
            state.ewma_latency_ms = (
                self.ewma_alpha * float(latency_ms)
                + (1.0 - self.ewma_alpha) * state.ewma_latency_ms
            )
        state.observe_count += 1
        state.last_seen_now = now

        # State transitions. Order matters — severe is checked first
        # so a single observation that lifts EWMA past severe always
        # marks the channel severe even if it was previously normal.
        ewma = state.ewma_latency_ms
        if ewma >= self.severe_ms:
            state.is_severe = True
            state.is_congested = True
        elif state.is_severe:
            # Leaving severe — still considered congested until EWMA
            # drops below exit_low_ms.
            state.is_severe = False
            state.is_congested = True
            if ewma < self.exit_low_ms:
                state.is_congested = False
        elif state.is_congested:
            # Hysteretic exit — must dip below the low threshold.
            if ewma < self.exit_low_ms:
                state.is_congested = False
        else:
            # Normal → congested only on crossing the high threshold.
            if ewma >= self.enter_high_ms:
                state.is_congested = True

    # ------------------------------------------------------------------
    # Test-only introspection (not part of the Protocol).
    # ------------------------------------------------------------------
    def channel_state(self, channel: str) -> _ChannelState | None:
        """Return a *snapshot* copy of a channel's state, or None."""
        state = self._channels.get(channel)
        if state is None:
            return None
        # Return a shallow copy so tests cannot mutate live state via
        # this hook.
        return _ChannelState(
            ewma_latency_ms=state.ewma_latency_ms,
            is_congested=state.is_congested,
            is_severe=state.is_severe,
            observe_count=state.observe_count,
            last_seen_now=state.last_seen_now,
        )

    def known_channels(self) -> tuple[str, ...]:
        """Return all channels with observed history, sorted."""
        return tuple(sorted(self._channels.keys()))

    # ------------------------------------------------------------------
    # Internal validation
    # ------------------------------------------------------------------
    @staticmethod
    def _validate_now(now: int) -> None:
        if isinstance(now, bool) or not isinstance(now, int):
            raise ValueError(f"TideController: now must be int, got {type(now).__name__}")

    @staticmethod
    def _validate_channel(channel: str) -> None:
        if not isinstance(channel, str):
            raise ValueError(f"TideController: channel must be str, got {type(channel).__name__}")
        if not channel:
            raise ValueError("TideController: channel must be non-empty")


def _halve_budget(budget: Budget) -> Budget:
    """Return a Budget with each capacity knob halved (min floor 1).

    The floor guarantees a congested channel still has a workable
    budget — a kernel that asks for "half of 1 token" otherwise gets
    a zero-token budget and stops working entirely. Zero would mean
    "everything dropped"; that decision belongs to ``admit``, not to
    ``budget_for``.
    """
    return Budget(
        tokens=max(1, budget.tokens // 2),
        wall_ms=max(1, budget.wall_ms // 2),
        depth=max(1, budget.depth // 2),
    )


def new_tide_controller(
    *,
    baseline_budget: Budget | None = None,
    enter_high_ms: int | None = None,
    exit_low_ms: int | None = None,
    severe_ms: int | None = None,
    ewma_alpha: float | None = None,
) -> TideControllerImpl:
    """Build a fresh :class:`TideControllerImpl`.

    All knobs are optional; omitted ones fall back to the module-level
    defaults. Tests use this factory rather than the dataclass
    constructor so that the policy surface can evolve without
    rippling test files.
    """
    return TideControllerImpl(
        baseline_budget=baseline_budget or DEFAULT_BASELINE_BUDGET,
        enter_high_ms=enter_high_ms if enter_high_ms is not None else DEFAULT_ENTER_HIGH_MS,
        exit_low_ms=exit_low_ms if exit_low_ms is not None else DEFAULT_EXIT_LOW_MS,
        severe_ms=severe_ms if severe_ms is not None else DEFAULT_SEVERE_MS,
        ewma_alpha=ewma_alpha if ewma_alpha is not None else DEFAULT_EWMA_ALPHA,
    )


__all__ = [
    "DEFAULT_BASELINE_BUDGET",
    "DEFAULT_ENTER_HIGH_MS",
    "DEFAULT_EWMA_ALPHA",
    "DEFAULT_EXIT_LOW_MS",
    "DEFAULT_SEVERE_MS",
    "TideControllerImpl",
    "new_tide_controller",
]
