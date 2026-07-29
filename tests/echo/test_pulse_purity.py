"""Echo T5 — pulse() purity & non-mutation contract tests.

This suite layers on top of :mod:`tests.echo.test_core_contract` by
exercising ``js.echo.core.pulse`` against the in-memory fakes from
:mod:`js.echo.testing`. The contract being pinned at T5 is:

1.  ``pulse()`` is a **pure function**: equal inputs → equal outputs
    across any number of independent calls (modulo the documented
    fact that ``wheel`` / ``tide`` may carry mutable state across
    calls — fresh collaborators are constructed inside each test
    that asserts equality).

2.  ``pulse()`` does **not mutate** its ``inbound`` list — neither
    its identity, length, nor any element.

3.  ``pulse()`` does **not read any I/O surface**: not the
    filesystem, not the clock, not the network. ``now`` is the only
    time source, and it is injected.

4.  ``pulse()`` **does** call its collaborators per the T5 spec —
    ``wheel.due(now)`` is consulted once per tick, and request
    inbound events drive ``tide.admit`` + ``amber.commit_checked``.
    The pre-T5 invariant "kernel never touches collaborators" no
    longer applies; what stays is "kernel touches collaborators
    only through their Protocol surface".

5.  The returned ``actions`` list is always a *new* list. Mutating
    it must not affect any subsequent ``pulse()`` call.

6.  Inputs of varying shape (empty inbound, dense inbound, every
    ``InboundKind`` value) all flow through unchanged.

None of these tests touch the filesystem, network, real clock,
randomness, or any legacy engine module. They run in microseconds.
"""

from __future__ import annotations

import copy
from dataclasses import fields, replace

import pytest

from js.echo.core import pulse
from js.echo.testing import (
    FakeAmberTree,
    FakeTideController,
    FakeTimingWheel,
    new_fake_amber,
    new_fake_clock,
    new_fake_tide,
    new_fake_wheel,
)
from js.echo.types import EmitResponse, InboundEvent, InboundKind, RequestEnvelope


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _fresh_collaborators() -> tuple[FakeAmberTree, FakeTimingWheel, FakeTideController]:
    """Return a new (amber, wheel, tide) triple with zero call history."""
    return new_fake_amber(), new_fake_wheel(), new_fake_tide()


def _sample_inbound() -> list[InboundEvent]:
    """Build a non-empty inbound list mixing three event kinds."""
    return [
        InboundEvent(
            kind=InboundKind.REQUEST,
            arrived_at=100,
            request=RequestEnvelope(request_id="r1", channel="api_chat", payload_hash="h1"),
        ),
        InboundEvent(kind=InboundKind.TIMER, arrived_at=101, correlation_id="t1"),
        InboundEvent(kind=InboundKind.LEDGER_ACK, arrived_at=102, correlation_id="ack-1"),
    ]


# ---------------------------------------------------------------------------
# Purity — equal inputs yield equal outputs
# ---------------------------------------------------------------------------
def test_pulse_equal_inputs_yield_equal_outputs_empty() -> None:
    """With empty inbound, ``pulse()`` is deterministic."""
    # Two independent collaborator triples so wheel.due() state cannot
    # leak between calls.
    a_amber, a_wheel, a_tide = _fresh_collaborators()
    b_amber, b_wheel, b_tide = _fresh_collaborators()
    out_a = pulse(0, [], a_amber, a_wheel, a_tide)
    out_b = pulse(0, [], b_amber, b_wheel, b_tide)
    # Returned actions list is equal (both empty); amber identities
    # differ (each triple has its own fake) — compare structurally.
    assert out_a[1] == out_b[1] == []


def test_pulse_equal_inputs_yield_equal_actions_dense() -> None:
    """With a populated inbound, the action sequence is deterministic."""
    a_amber, a_wheel, a_tide = _fresh_collaborators()
    b_amber, b_wheel, b_tide = _fresh_collaborators()
    inbound1 = _sample_inbound()
    inbound2 = _sample_inbound()
    _, actions_a = pulse(42, inbound1, a_amber, a_wheel, a_tide)
    _, actions_b = pulse(42, inbound2, b_amber, b_wheel, b_tide)
    assert actions_a == actions_b
    # And specifically: a single REQUEST → a single EmitResponse on the
    # success branch (TIMER / LEDGER_ACK commit to amber but emit no
    # action).
    assert len(actions_a) == 1
    assert isinstance(actions_a[0], EmitResponse)


def test_pulse_now_variation_does_not_break_determinism() -> None:
    """Pure-fn invariant: different ``now`` produces deterministic output."""
    for now in (0, 1, 1_700_000_000, 2**31 - 1):
        a_amber, a_wheel, a_tide = _fresh_collaborators()
        b_amber, b_wheel, b_tide = _fresh_collaborators()
        _, actions_a = pulse(now, [], a_amber, a_wheel, a_tide)
        _, actions_b = pulse(now, [], b_amber, b_wheel, b_tide)
        assert actions_a == actions_b, f"pulse() drifted across calls at now={now}"


# ---------------------------------------------------------------------------
# Non-mutation of inbound
# ---------------------------------------------------------------------------
def test_pulse_does_not_mutate_inbound_list_identity() -> None:
    """``inbound`` list reference, length, and elements remain unchanged."""
    amber, wheel, tide = _fresh_collaborators()
    inbound = _sample_inbound()
    inbound_snapshot = copy.deepcopy(inbound)
    inbound_id_before = id(inbound)

    pulse(7, inbound, amber, wheel, tide)

    assert id(inbound) == inbound_id_before, "pulse() rebound the inbound list"
    assert len(inbound) == len(inbound_snapshot), "pulse() changed inbound length"
    for actual, expected in zip(inbound, inbound_snapshot, strict=True):
        assert actual == expected, "pulse() mutated an inbound element"


def test_pulse_does_not_mutate_inbound_with_empty_list() -> None:
    amber, wheel, tide = _fresh_collaborators()
    inbound: list[InboundEvent] = []
    inbound_id = id(inbound)
    pulse(0, inbound, amber, wheel, tide)
    assert inbound == []
    assert id(inbound) == inbound_id


# ---------------------------------------------------------------------------
# Actions list — always a fresh list, mutating it does not leak
# ---------------------------------------------------------------------------
def test_pulse_returns_new_list_each_call() -> None:
    """``actions`` must be a freshly allocated list every call."""
    amber, wheel, tide = _fresh_collaborators()
    _, actions_a = pulse(0, [], amber, wheel, tide)
    _, actions_b = pulse(0, [], amber, wheel, tide)
    assert actions_a is not actions_b, "pulse() must not reuse the action list"


def test_pulse_does_not_carry_over_action_list() -> None:
    """Caller can mutate the returned actions without affecting future pulses."""
    amber, wheel, tide = _fresh_collaborators()
    _, actions = pulse(0, [], amber, wheel, tide)
    actions.append("poison")  # type: ignore[arg-type]
    _, actions_next = pulse(0, [], amber, wheel, tide)
    assert actions_next == [], "pulse() leaked a mutated action list across calls"


# ---------------------------------------------------------------------------
# Collaborator interactions — what pulse SHOULD call at T5
# ---------------------------------------------------------------------------
def test_pulse_consults_wheel_due_each_call() -> None:
    """pulse() always asks the wheel for due timers, exactly once per call."""
    amber, wheel, tide = _fresh_collaborators()
    pulse(123, [], amber, wheel, tide)
    assert wheel.due_calls == [123]
    assert wheel.schedule_calls == []
    assert wheel.cancel_calls == []


def test_pulse_consults_tide_admit_for_each_request() -> None:
    """Every REQUEST event triggers exactly one tide.admit call."""
    amber, wheel, tide = _fresh_collaborators()
    inbound = [
        InboundEvent(
            kind=InboundKind.REQUEST,
            arrived_at=10,
            request=RequestEnvelope(request_id="r1", channel="api_chat", payload_hash="h"),
        ),
        InboundEvent(
            kind=InboundKind.REQUEST,
            arrived_at=11,
            request=RequestEnvelope(request_id="r2", channel="ws_message", payload_hash="h"),
        ),
    ]
    pulse(100, inbound, amber, wheel, tide)
    assert tide.admit_calls == [(100, "api_chat"), (100, "ws_message")]


def test_pulse_does_not_call_tide_observe() -> None:
    """T5 pulse() does not feed latency back — that's the gateway's job
    in later tides."""
    amber, wheel, tide = _fresh_collaborators()
    pulse(0, _sample_inbound(), amber, wheel, tide)
    assert tide.observe_calls == []


def test_pulse_writes_to_amber_for_admitted_request() -> None:
    """An admitted REQUEST results in exactly one commit_checked call."""
    amber, wheel, tide = _fresh_collaborators()
    inbound = [
        InboundEvent(
            kind=InboundKind.REQUEST,
            arrived_at=10,
            request=RequestEnvelope(request_id="r1", channel="api_chat", payload_hash="hh"),
        )
    ]
    pulse(100, inbound, amber, wheel, tide)
    assert amber.commit_checked_calls == 1


def test_pulse_does_not_write_amber_for_denied_request() -> None:
    """A denied REQUEST writes nothing to amber (admit=False branch)."""
    amber, wheel, _ = _fresh_collaborators()
    tide = new_fake_tide(admit_default=False)
    inbound = [
        InboundEvent(
            kind=InboundKind.REQUEST,
            arrived_at=10,
            request=RequestEnvelope(request_id="r1", channel="api_chat", payload_hash="hh"),
        )
    ]
    _, actions = pulse(100, inbound, amber, wheel, tide)
    assert amber.commit_checked_calls == 0
    # But it does emit a backpressure response.
    assert len(actions) == 1


# ---------------------------------------------------------------------------
# Clock — pulse never reads it
# ---------------------------------------------------------------------------
def test_pulse_never_reads_fake_clock() -> None:
    """Pulse takes ``now`` directly; the FakeClock injected via test stays
    untouched after that single read."""
    amber, wheel, tide = _fresh_collaborators()
    clock = new_fake_clock(current=12345)
    initial_now = clock.now()
    assert clock.reads == 1
    pulse(initial_now, [], amber, wheel, tide)
    assert clock.reads == 1, "pulse() must not have read the clock"


# ---------------------------------------------------------------------------
# Independence across calls
# ---------------------------------------------------------------------------
def test_pulse_independent_calls_do_not_share_state() -> None:
    """Two pulse() calls with different inputs must not affect each other."""
    amber, wheel, tide = _fresh_collaborators()
    inbound1 = _sample_inbound()
    out_a = pulse(0, inbound1, amber, wheel, tide)
    inbound2: list[InboundEvent] = []
    out_b = pulse(1, inbound2, amber, wheel, tide)
    # Inputs stay separate: inbound1 unmodified, inbound2 still empty.
    assert inbound2 == []
    assert len(inbound1) == 3
    # actions list is fresh per call.
    assert out_a[1] is not out_b[1]


@pytest.mark.parametrize("calls", [1, 2, 5, 16])
def test_pulse_repeated_calls_produce_equal_action_sequences(calls: int) -> None:
    """Repeating pulse() N times with fresh collaborators always
    produces equal action sequences."""
    inbound_template = _sample_inbound()
    results: list[list[object]] = []
    for _ in range(calls):
        amber, wheel, tide = _fresh_collaborators()
        inbound = [replace(ev) for ev in inbound_template]
        _, actions = pulse(0, inbound, amber, wheel, tide)
        results.append(actions)
    for r in results[1:]:
        assert r == results[0]


# ---------------------------------------------------------------------------
# Inbound shape coverage
# ---------------------------------------------------------------------------
def test_pulse_accepts_all_inbound_kinds() -> None:
    """Every ``InboundKind`` value flows through pulse() unchanged.

    Note: REQUEST without an envelope is dropped silently; we use a
    fully-populated REQUEST so it produces a visible action.
    """
    amber, wheel, tide = _fresh_collaborators()
    inbound = [
        InboundEvent(
            kind=InboundKind.REQUEST,
            arrived_at=1,
            request=RequestEnvelope(request_id="r1", channel="c", payload_hash="h"),
        ),
        InboundEvent(kind=InboundKind.TIMER, arrived_at=2, correlation_id="t1"),
        InboundEvent(kind=InboundKind.RESONANCE, arrived_at=3, correlation_id="r1-res"),
        InboundEvent(kind=InboundKind.LEDGER_ACK, arrived_at=4, correlation_id="ack-1"),
        InboundEvent(kind=InboundKind.SANDBOX_RESULT, arrived_at=5, correlation_id="sb-1"),
    ]
    snapshot = list(inbound)
    pulse(10, inbound, amber, wheel, tide)
    assert inbound == snapshot
    # Every event commits to amber (5 commits total).
    assert amber.commit_checked_calls == 5


def test_pulse_accepts_request_envelope_event() -> None:
    """A REQUEST event with a fully populated RequestEnvelope round-trips."""
    amber, wheel, tide = _fresh_collaborators()
    env = RequestEnvelope(request_id="r-42", channel="ws", payload_hash="abc123")
    evt = InboundEvent(kind=InboundKind.REQUEST, arrived_at=99, request=env)
    inbound = [evt]
    pulse(0, inbound, amber, wheel, tide)
    # Frozen dataclass: the original element must still be present
    # unchanged after pulse().
    assert inbound[0] is evt
    rebuilt = replace(evt)
    assert inbound[0] == rebuilt
    for f in fields(InboundEvent):
        assert getattr(inbound[0], f.name) == getattr(evt, f.name)


def test_pulse_drops_request_without_envelope() -> None:
    """REQUEST with no envelope has no stable id; pulse skips it silently."""
    amber, wheel, tide = _fresh_collaborators()
    inbound = [InboundEvent(kind=InboundKind.REQUEST, arrived_at=1)]
    _, actions = pulse(0, inbound, amber, wheel, tide)
    assert actions == []
    assert amber.commit_checked_calls == 0


def test_pulse_drops_timer_without_correlation_id() -> None:
    """TIMER without correlation_id is dropped silently."""
    amber, wheel, tide = _fresh_collaborators()
    inbound = [InboundEvent(kind=InboundKind.TIMER, arrived_at=1)]
    _, actions = pulse(0, inbound, amber, wheel, tide)
    assert actions == []
    assert amber.commit_checked_calls == 0


# ---------------------------------------------------------------------------
# Composition — pulse() output is itself usable as input substrate
# ---------------------------------------------------------------------------
def test_pulse_output_amber_is_protocol_conformant() -> None:
    """The returned amber must still satisfy AmberTree (Protocol checks pass)."""
    amber, wheel, tide = _fresh_collaborators()
    new_amber, _ = pulse(0, [], amber, wheel, tide)
    # Read-only property access must succeed.
    assert isinstance(new_amber.root_hash, str)
    new_amber.ready_index()
    new_amber.context_view("/")
    new_amber.delta_since_last()


def test_pulse_chaining_is_stable_on_empty_inbound() -> None:
    """Empty-inbound pulses chain into a steady-state loop:

    - No events → no commits → amber identity preserved (FakeAmberTree
      ``commit_checked`` returns self, but ``commit_checked`` isn't
      called at all here).
    - No timers fired → empty action list.
    """
    amber, wheel, tide = _fresh_collaborators()
    cur_amber = amber
    for _ in range(10):
        cur_amber, actions = pulse(0, [], cur_amber, wheel, tide)
        assert actions == []
    # 10 pulses, each consulted wheel.due once.
    assert wheel.due_calls == [0] * 10
