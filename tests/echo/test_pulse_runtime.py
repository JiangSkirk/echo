"""Echo T5 — pulse() minimal runtime behavioural tests.

Exercises the actual T5 semantics — admission, AmberTree commits,
EmitResponse production, wheel firing — against both the in-memory
fakes from :mod:`js.echo.testing` and the real implementations from
:mod:`js.echo.amber_tree` / :mod:`js.echo.timing_wheel` /
:mod:`js.echo.tide_controller`. Purity / non-mutation invariants
live in :mod:`tests.echo.test_pulse_purity`; this file is about
"does pulse() actually do what the spec says".

What this file pins:

- Admitted REQUEST → ``EmitResponse`` with ``admit:ok`` metadata +
  one commit at ``/request/{request_id}``.
- Denied REQUEST → ``EmitResponse`` with the backpressure metadata,
  no commit.
- TIMER, RESONANCE, LEDGER_ACK, SANDBOX_RESULT each commit to a
  kind-specific path and emit no action.
- ``wheel.due(now)`` is drained at the top of every pulse; each due
  id produces one ``EmitResponse(channel="timer")`` + one
  ``/wheel/due/{cid}`` commit.
- Stable ordering: inbound events sorted by
  ``(arrived_at, id, kind)`` — the action sequence is invariant
  under input shuffling.
- Real-implementation smoke: wiring pulse() to the production
  :class:`AmberTreeImpl` + :class:`TimingWheelImpl` +
  :class:`TideControllerImpl` works end-to-end without any I/O.
"""

from __future__ import annotations

from js.echo.amber_tree import new_amber_tree
from js.echo.core import pulse
from js.echo.testing import (
    new_fake_amber,
    new_fake_tide,
    new_fake_wheel,
)
from js.echo.tide_controller import new_tide_controller
from js.echo.timing_wheel import new_timing_wheel
from js.echo.types import (
    EmitResponse,
    InboundEvent,
    InboundKind,
    RequestEnvelope,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_request(rid: str, channel: str = "api_chat", payload: str = "h") -> InboundEvent:
    return InboundEvent(
        kind=InboundKind.REQUEST,
        arrived_at=10,
        request=RequestEnvelope(request_id=rid, channel=channel, payload_hash=payload),
    )


# ---------------------------------------------------------------------------
# REQUEST — admitted vs denied
# ---------------------------------------------------------------------------
def test_admitted_request_emits_response_and_commits() -> None:
    amber = new_fake_amber()
    wheel = new_fake_wheel()
    tide = new_fake_tide()  # admit_default=True
    ev = _make_request("r1", channel="api_chat", payload="hh")
    new_amber, actions = pulse(100, [ev], amber, wheel, tide)
    assert len(actions) == 1
    action = actions[0]
    assert isinstance(action, EmitResponse)
    assert action.request_id == "r1"
    assert action.channel == "api_chat"
    assert action.payload_hash == "hh"
    assert action.metadata == (("admit", "ok"),)
    assert amber.commit_checked_calls == 1
    assert tide.admit_calls == [(100, "api_chat")]
    # FakeAmberTree.commit_checked returns self → identity preserved.
    assert new_amber is amber


def test_denied_request_emits_backpressure_and_no_commit() -> None:
    amber = new_fake_amber()
    wheel = new_fake_wheel()
    tide = new_fake_tide(admit_default=False)
    ev = _make_request("r1")
    _, actions = pulse(100, [ev], amber, wheel, tide)
    assert len(actions) == 1
    action = actions[0]
    assert isinstance(action, EmitResponse)
    assert action.request_id == "r1"
    assert action.metadata == (("admit", "drop"), ("reason", "backpressure"))
    assert amber.commit_checked_calls == 0


# ---------------------------------------------------------------------------
# Non-request inbound kinds → commit only, no action
# ---------------------------------------------------------------------------
def test_timer_event_commits_and_emits_nothing() -> None:
    amber = new_fake_amber()
    wheel = new_fake_wheel()
    tide = new_fake_tide()
    ev = InboundEvent(kind=InboundKind.TIMER, arrived_at=5, correlation_id="t1")
    _, actions = pulse(10, [ev], amber, wheel, tide)
    assert actions == []
    assert amber.commit_checked_calls == 1


def test_resonance_event_commits_and_emits_nothing() -> None:
    amber = new_fake_amber()
    wheel = new_fake_wheel()
    tide = new_fake_tide()
    ev = InboundEvent(kind=InboundKind.RESONANCE, arrived_at=5, correlation_id="reso-1")
    _, actions = pulse(10, [ev], amber, wheel, tide)
    assert actions == []
    assert amber.commit_checked_calls == 1


def test_ledger_ack_event_commits_and_emits_nothing() -> None:
    amber = new_fake_amber()
    wheel = new_fake_wheel()
    tide = new_fake_tide()
    ev = InboundEvent(kind=InboundKind.LEDGER_ACK, arrived_at=5, correlation_id="ack-1")
    _, actions = pulse(10, [ev], amber, wheel, tide)
    assert actions == []
    assert amber.commit_checked_calls == 1


def test_sandbox_result_event_commits_and_emits_nothing() -> None:
    amber = new_fake_amber()
    wheel = new_fake_wheel()
    tide = new_fake_tide()
    ev = InboundEvent(kind=InboundKind.SANDBOX_RESULT, arrived_at=5, correlation_id="sb-1")
    _, actions = pulse(10, [ev], amber, wheel, tide)
    assert actions == []
    assert amber.commit_checked_calls == 1


# ---------------------------------------------------------------------------
# wheel.due drives synthetic timer responses
# ---------------------------------------------------------------------------
def test_wheel_due_fires_emit_response_per_cid() -> None:
    """Real wheel + fake amber/tide.

    The wheel has two pre-scheduled timers; pulse() drains them all
    at the top of the tick.
    """
    amber = new_fake_amber()
    wheel = new_timing_wheel()
    tide = new_fake_tide()
    wheel.schedule(fire_at=1, correlation_id="a")
    wheel.schedule(fire_at=2, correlation_id="b")
    _, actions = pulse(now=10, inbound=[], amber=amber, wheel=wheel, tide=tide)
    assert len(actions) == 2
    cids = [a.request_id for a in actions if isinstance(a, EmitResponse)]
    assert cids == ["a", "b"]
    # Each wheel firing is its own commit at /wheel/due/{cid}.
    assert amber.commit_checked_calls == 2
    # And the wheel is now empty.
    assert wheel.size() == 0


def test_wheel_due_uses_synthetic_timer_channel() -> None:
    amber = new_fake_amber()
    wheel = new_timing_wheel()
    tide = new_fake_tide()
    wheel.schedule(fire_at=0, correlation_id="x")
    _, actions = pulse(now=1, inbound=[], amber=amber, wheel=wheel, tide=tide)
    assert len(actions) == 1
    action = actions[0]
    assert isinstance(action, EmitResponse)
    assert action.channel == "timer"
    assert action.metadata == (("source", "wheel"),)


def test_pulse_does_not_block_on_future_wheel_timers() -> None:
    amber = new_fake_amber()
    wheel = new_timing_wheel()
    tide = new_fake_tide()
    wheel.schedule(fire_at=1_000, correlation_id="late")
    _, actions = pulse(now=1, inbound=[], amber=amber, wheel=wheel, tide=tide)
    assert actions == []
    assert wheel.size() == 1


# ---------------------------------------------------------------------------
# Stable ordering — the action sequence is invariant under input shuffling
# ---------------------------------------------------------------------------
def test_inbound_order_does_not_affect_action_sequence() -> None:
    """Two pulses fed the same events in different orders produce the
    same action list."""
    events = [
        _make_request("r2"),  # arrived_at=10
        InboundEvent(kind=InboundKind.TIMER, arrived_at=5, correlation_id="t1"),
        _make_request("r1"),  # arrived_at=10
    ]

    amber_a = new_fake_amber()
    wheel_a = new_fake_wheel()
    tide_a = new_fake_tide()
    _, actions_a = pulse(99, events, amber_a, wheel_a, tide_a)

    amber_b = new_fake_amber()
    wheel_b = new_fake_wheel()
    tide_b = new_fake_tide()
    _, actions_b = pulse(99, list(reversed(events)), amber_b, wheel_b, tide_b)

    assert actions_a == actions_b


def test_stable_order_for_requests_with_same_arrived_at() -> None:
    """Ties on arrived_at break by request_id lexicographically."""
    e_z = _make_request("z")
    e_a = _make_request("a")
    e_m = _make_request("m")
    amber = new_fake_amber()
    wheel = new_fake_wheel()
    tide = new_fake_tide()
    _, actions = pulse(now=99, inbound=[e_z, e_a, e_m], amber=amber, wheel=wheel, tide=tide)
    rids = [a.request_id for a in actions if isinstance(a, EmitResponse)]
    assert rids == ["a", "m", "z"]


def test_pulse_orders_actions_wheel_first_then_inbound() -> None:
    """Wheel-fired actions always come BEFORE inbound responses.

    This is the spec ordering: timers that came due at this tick are
    drained before the kernel admits new inbound work. Tests pin
    this so the gateway / ledger never see an inverted sequence.
    """
    amber = new_fake_amber()
    wheel = new_timing_wheel()
    tide = new_fake_tide()
    wheel.schedule(fire_at=0, correlation_id="wheel-first")
    inbound = [_make_request("inbound-second")]
    _, actions = pulse(now=10, inbound=inbound, amber=amber, wheel=wheel, tide=tide)
    assert len(actions) == 2
    assert isinstance(actions[0], EmitResponse)
    assert isinstance(actions[1], EmitResponse)
    assert actions[0].request_id == "wheel-first"
    assert actions[1].request_id == "inbound-second"


# ---------------------------------------------------------------------------
# Real-implementation smoke — wire AmberTreeImpl + TimingWheelImpl + TideControllerImpl
# ---------------------------------------------------------------------------
def test_real_collaborators_smoke_admitted_request() -> None:
    """End-to-end with the real production fakes: pulse() works."""
    amber = new_amber_tree()
    wheel = new_timing_wheel()
    tide = new_tide_controller()
    ev = _make_request("r1", channel="api_chat", payload="abc")
    new_amber, actions = pulse(now=100, inbound=[ev], amber=amber, wheel=wheel, tide=tide)
    # AmberTree CoW: a new tree is returned, not the same instance.
    assert new_amber is not amber
    # Exactly one action emitted.
    assert len(actions) == 1
    action = actions[0]
    assert isinstance(action, EmitResponse)
    assert action.metadata == (("admit", "ok"),)
    # The /request/r1 path is now present in the new amber tree.
    assert new_amber.get("/request/r1") is not None  # type: ignore[attr-defined]


def test_real_collaborators_smoke_severe_channel_denied() -> None:
    """A channel pushed into ``severe`` denies admission via real tide."""
    amber = new_amber_tree()
    wheel = new_timing_wheel()
    tide = new_tide_controller(enter_high_ms=500, exit_low_ms=200, severe_ms=2000, ewma_alpha=1.0)
    # Push api_chat into severe.
    tide.observe(now=0, channel="api_chat", latency_ms=3000)
    ev = _make_request("r1", channel="api_chat", payload="abc")
    new_amber, actions = pulse(now=100, inbound=[ev], amber=amber, wheel=wheel, tide=tide)
    # No commit → amber identity preserved.
    assert new_amber is amber
    # Backpressure response only.
    assert len(actions) == 1
    action = actions[0]
    assert isinstance(action, EmitResponse)
    assert action.metadata == (("admit", "drop"), ("reason", "backpressure"))


def test_real_collaborators_wheel_due_drains() -> None:
    """Real wheel + real amber + real tide: a scheduled timer fires."""
    amber = new_amber_tree()
    wheel = new_timing_wheel()
    tide = new_tide_controller()
    wheel.schedule(fire_at=5, correlation_id="cid-1")
    new_amber, actions = pulse(now=10, inbound=[], amber=amber, wheel=wheel, tide=tide)
    assert len(actions) == 1
    assert wheel.size() == 0
    # The wheel-fired commit landed in the new tree.
    assert new_amber.get("/wheel/due/cid-1") is not None  # type: ignore[attr-defined]
    assert new_amber is not amber


# ---------------------------------------------------------------------------
# Empty inbound + empty wheel = no actions, no commits
# ---------------------------------------------------------------------------
def test_pulse_on_empty_state_is_steady() -> None:
    amber = new_amber_tree()
    wheel = new_timing_wheel()
    tide = new_tide_controller()
    new_amber, actions = pulse(now=0, inbound=[], amber=amber, wheel=wheel, tide=tide)
    assert actions == []
    # No commits → amber identity preserved (CoW: no derive).
    assert new_amber is amber


# ---------------------------------------------------------------------------
# Mixed inbound: admitted + denied + timer in same pulse
# ---------------------------------------------------------------------------
def test_mixed_inbound_produces_expected_action_set() -> None:
    amber = new_fake_amber()
    wheel = new_fake_wheel()

    # Custom tide that denies channel "b" but admits everything else.
    class _PartialTide:
        def admit(self, now: int, channel: str) -> bool:
            return channel != "b"

        def budget_for(self, channel: str):  # noqa: ANN001 - not used here
            raise NotImplementedError

        def observe(self, now: int, channel: str, latency_ms: int) -> None:
            raise NotImplementedError

    tide = _PartialTide()
    inbound = [
        _make_request("r-a", channel="a"),
        _make_request("r-b", channel="b"),
        InboundEvent(kind=InboundKind.TIMER, arrived_at=20, correlation_id="t1"),
    ]
    _, actions = pulse(now=100, inbound=inbound, amber=amber, wheel=wheel, tide=tide)  # type: ignore[arg-type]
    # Two requests → two EmitResponses (one admit:ok, one backpressure).
    # The timer commits to amber but emits no action.
    assert len(actions) == 2
    a_responses = {a.request_id: a for a in actions if isinstance(a, EmitResponse)}
    assert a_responses["r-a"].metadata == (("admit", "ok"),)
    assert a_responses["r-b"].metadata == (("admit", "drop"), ("reason", "backpressure"))
    # commit_checked: r-a (admitted) + timer t1 = 2 calls. r-b denied.
    assert amber.commit_checked_calls == 2
