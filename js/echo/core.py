"""Echo pulse kernel integration.

Pulse() runs one kernel tick. The T5 implementation is the first time
the kernel actually *uses* its collaborators — admission via
``tide``, scheduling via ``wheel``, commits via ``amber`` — while
staying a strict pure function over the parameters.

Contract (repeated here for the implementer's benefit):

- Signature: ``pulse(now, inbound, amber, wheel,
  tide) -> tuple[AmberTree, list[Action]]``.
- Pure function: equal inputs (including the collaborator state)
  produce equal outputs across any number of calls.
- No I/O: no filesystem, no network, no clock read, no logging, no
  asyncio, no subprocess, no randomness. ``now`` is the only time
  source; the caller injects it.
- No mutation of the caller's ``inbound`` list. The kernel sorts a
  private copy before processing.
- ``amber`` returns as either the same object (no commits this
  tick) or a CoW-derived successor (one or more commits). Either
  way it satisfies the ``AmberTree`` Protocol.
- ``actions`` is always a freshly allocated list, even when empty.
- ``wheel`` and ``tide`` may be mutated through their Protocol
  surfaces (``wheel.due`` pops, ``tide.observe`` updates state);
  no other mutation is permitted.

Behaviour (T5 minimal):

1. Drain ``wheel.due(now)`` first — every fired correlation id
   becomes a ``/wheel/due/{cid}`` commit + an :class:`EmitResponse`
   on the synthetic ``"timer"`` channel.

2. Process ``inbound`` in stable order
   ``(arrived_at, correlation_id_or_request_id, kind.value)`` so a
   pulse fed the same multiset of events always produces the same
   action sequence.

3. For each event:

   - **REQUEST**: consult ``tide.admit(now, request.channel)``.
     - Admitted → commit ``/request/{request_id}`` payload =
       ``request.payload_hash`` bytes; emit success response.
     - Denied → no commit; emit a backpressure response.
   - **TIMER**: commit ``/timer/{cid}`` so the timer firing is
     observable in the AmberTree audit trail.
   - **RESONANCE**: commit ``/resonance/{cid}`` for the same reason.
   - **LEDGER_ACK**: commit ``/ledger_ack/{cid}``.
   - **SANDBOX_RESULT**: commit ``/sandbox/{cid}``.
   - Events with no usable id (no ``correlation_id`` and no
     ``request.request_id``) are skipped silently — there is no
     stable path to commit them under.

What pulse() does NOT do at T5 (deferred):

- Touch any real LLM / Ledger / Sandbox.
- Issue ``CommitFrame`` / ``Exec`` actions (those land at T6 / T7).
- Read the real clock — ever. ``now`` is the injected time.
- Cancel or schedule timers from ``inbound`` (no ``Resonate`` is
  emitted in this milestone; the wheel only fires what was already
  scheduled externally).

Test pin:
- ``tests/echo/test_pulse_runtime.py`` exercises the full event
  table and the stable-order guarantee.
- ``tests/echo/test_pulse_purity.py`` re-pins the purity / non-mutation
  / freshly-allocated-list invariants under the new behavioural
  envelope.
- ``tests/echo/test_core_contract.py`` continues to pin the
  signature freeze and the no-legacy-imports / no-I/O guards.
"""

from __future__ import annotations

from js.echo.amber import AmberTree
from js.echo.tide import TideController
from js.echo.types import (
    Action,
    EmitResponse,
    InboundEvent,
    InboundKind,
)
from js.echo.wheel import TimingWheel

# Channel name pulse() uses when it manufactures a synthetic response
# for a wheel-fired timer. Keeping this as a module-level constant so
# tests can refer to it by name rather than re-typing a string.
_SYNTH_TIMER_CHANNEL: str = "timer"

# Metadata keys for response provenance. Kept as plain string
# constants so they show up verbatim in the AmberTree audit and in
# test assertions.
_META_ADMIT_OK = (("admit", "ok"),)
_META_BACKPRESSURE_DROP = (("admit", "drop"), ("reason", "backpressure"))
_META_SOURCE_WHEEL = (("source", "wheel"),)


def pulse(
    now: int,
    inbound: list[InboundEvent],
    amber: AmberTree,
    wheel: TimingWheel,
    tide: TideController,
) -> tuple[AmberTree, list[Action]]:
    """Run one kernel tick. See module docstring for the full contract."""
    # ------------------------------------------------------------------
    # 0. Local mutable surfaces. The actions list is always freshly
    #    allocated (purity guard #4). The amber reference may rebind
    #    as we commit; we never write to the caller's list.
    # ------------------------------------------------------------------
    actions: list[Action] = []
    current_amber: AmberTree = amber

    # ------------------------------------------------------------------
    # 1. Fire any timers that came due before this tick. The wheel
    #    returns ids in (fire_at, cid) lexicographic order; we keep
    #    that order through the emitted actions and the AmberTree
    #    writes so replay stays bit-stable.
    # ------------------------------------------------------------------
    fired_cids = wheel.due(now)
    for cid in fired_cids:
        path = f"/wheel/due/{cid}"
        payload = f"fire_at<={now}:cid={cid}".encode()
        current_amber = current_amber.commit_checked(path, payload)
        actions.append(
            EmitResponse(
                request_id=cid,
                channel=_SYNTH_TIMER_CHANNEL,
                payload_hash=cid,
                metadata=_META_SOURCE_WHEEL,
            )
        )

    # ------------------------------------------------------------------
    # 2. Stable inbound ordering. We sort a copy — the caller's list
    #    stays exactly as it was passed in (purity guard #2).
    # ------------------------------------------------------------------
    ordered = sorted(inbound, key=_event_sort_key)

    # ------------------------------------------------------------------
    # 3. Process each event. Every branch either commits to amber or
    #    emits an action (or both). The empty branch — no usable id —
    #    is a deliberate skip; pulse cannot fabricate a stable path
    #    for a malformed event.
    # ------------------------------------------------------------------
    for event in ordered:
        kind = event.kind
        if kind is InboundKind.REQUEST:
            request = event.request
            if request is None:
                # A REQUEST without an envelope has no stable id /
                # channel; drop silently.
                continue
            admitted = tide.admit(now, request.channel)
            if not admitted:
                actions.append(
                    EmitResponse(
                        request_id=request.request_id,
                        channel=request.channel,
                        payload_hash=request.payload_hash,
                        metadata=_META_BACKPRESSURE_DROP,
                    )
                )
                continue
            path = f"/request/{request.state_key}"
            payload = request.payload_hash.encode("utf-8")
            current_amber = current_amber.commit_checked(path, payload)
            actions.append(
                EmitResponse(
                    request_id=request.request_id,
                    channel=request.channel,
                    payload_hash=request.payload_hash,
                    metadata=_META_ADMIT_OK,
                )
            )
        elif kind is InboundKind.TIMER:
            corr_timer: str | None = event.correlation_id
            if corr_timer is None:
                continue
            path = f"/timer/{corr_timer}"
            payload = f"timer:{corr_timer}@{event.arrived_at}".encode()
            current_amber = current_amber.commit_checked(path, payload)
        elif kind is InboundKind.RESONANCE:
            corr_reso: str | None = event.correlation_id
            if corr_reso is None:
                continue
            path = f"/resonance/{corr_reso}"
            payload = f"resonance:{corr_reso}@{event.arrived_at}".encode()
            current_amber = current_amber.commit_checked(path, payload)
        elif kind is InboundKind.LEDGER_ACK:
            corr_ack: str | None = event.correlation_id
            if corr_ack is None:
                continue
            path = f"/ledger_ack/{corr_ack}"
            payload = f"ledger_ack:{corr_ack}@{event.arrived_at}".encode()
            current_amber = current_amber.commit_checked(path, payload)
        elif kind is InboundKind.SANDBOX_RESULT:
            corr_sb: str | None = event.correlation_id
            if corr_sb is None:
                continue
            path = f"/sandbox/{corr_sb}"
            payload = f"sandbox_result:{corr_sb}@{event.arrived_at}".encode()
            current_amber = current_amber.commit_checked(path, payload)
        # No else: InboundKind is a StrEnum and the five branches
        # above are exhaustive. mypy would catch a new variant.

    return current_amber, actions


def _event_sort_key(event: InboundEvent) -> tuple[int, str, str]:
    """Stable sort key for an inbound event.

    Two events with the same ``arrived_at`` are tie-broken by the
    correlation/request id (whichever is present) and then by the
    kind value. The ids are strings; ties on all three are vanishingly
    rare and resolve to the natural string ordering.
    """
    # Resolve the secondary key from whichever id the event carries.
    secondary: str
    if event.request is not None:
        secondary = event.request.request_id
    elif event.correlation_id is not None:
        secondary = event.correlation_id
    else:
        secondary = ""
    return (event.arrived_at, secondary, event.kind.value)


__all__ = ["pulse"]
