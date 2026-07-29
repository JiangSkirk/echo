"""Process-local Echo pulse runtime.

This module owns the in-memory collaborators used by Echo's deterministic
``pulse()`` loop: one Amber tree, one timing wheel and one tide controller.
Each ``observe()`` call converts a request summary into an inbound event,
runs one pulse, then keeps the successor Amber tree for the next call.

The runtime is intentionally small and dependency-light. It does not call
models, tools, web handlers, network APIs, or persistent storage. Durable
authorization and recovery belong exclusively to ``EchoSafetyService`` and
``FileEchoLedger``.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, cast

from js.echo.amber_tree import AmberTreeImpl, new_amber_tree
from js.echo.core import pulse
from js.echo.tide_controller import TideControllerImpl, new_tide_controller
from js.echo.timing_wheel import TimingWheelImpl, new_timing_wheel
from js.echo.types import InboundEvent, InboundKind, RequestEnvelope

_DEFAULT_MAX_AMBER_NODES = 1024


@dataclass(frozen=True)
class PulseObservation:
    """Result returned by :meth:`EchoPulseRuntime.observe`.

    Carries just enough information for callers/tests to assert on the
    kernel's response. The full ``actions`` list and the new
    amber object itself are intentionally not exposed — the runtime
    is the single owner of those.
    """

    amber_root_hash: str
    amber_version: int
    actions_count: int
    admitted: bool


class EchoPulseRuntime:
    """Process-local container for the real Echo collaborators.

    A single instance is held by the module-level singleton (see
    :func:`get_pulse_runtime`). Every public method takes the runtime's
    ``RLock`` for the duration of one pulse, so concurrent invocations
    serialise rather than racing the amber rebind.

    The lock is intentionally an ``RLock`` rather than a ``Lock`` —
    the snapshot helper re-enters under the same lock for a
    consistent read.
    """

    __slots__ = (
        "_amber",
        "_wheel",
        "_tide",
        "_lock",
        "_pulses",
        "_max_amber_nodes",
        "_amber_slot_overwrites",
    )

    def __init__(
        self,
        *,
        max_amber_nodes: int = _DEFAULT_MAX_AMBER_NODES,
    ) -> None:
        if isinstance(max_amber_nodes, bool) or not isinstance(max_amber_nodes, int):
            raise ValueError("max_amber_nodes must be a positive integer")
        if max_amber_nodes < 1:
            raise ValueError("max_amber_nodes must be a positive integer")
        self._amber: AmberTreeImpl = new_amber_tree()
        self._wheel: TimingWheelImpl = new_timing_wheel()
        self._tide: TideControllerImpl = new_tide_controller()
        self._lock: threading.RLock = threading.RLock()
        self._pulses: int = 0
        self._max_amber_nodes = max_amber_nodes
        self._amber_slot_overwrites = 0

    # ------------------------------------------------------------------
    # Public observe
    # ------------------------------------------------------------------
    def observe(
        self,
        *,
        channel: str,
        request_id: str,
        payload_hash: str,
        now_ms: int,
        owner_key_hash: str = "local-user",
        session_id: str = "",
        source: str | None = None,
    ) -> PulseObservation:
        """Run one real ``pulse()`` against the runtime's collaborators.

        Builds an ``InboundEvent`` of kind ``REQUEST``, feeds it to
        ``pulse()``, and rebinds ``_amber`` to the returned successor.
        ``_wheel`` and ``_tide`` remain the same instance — the kernel
        is allowed to mutate them through the Protocol surface, and
        keeping the identity is what gives the runtime its cross-pulse
        memory.

        The lock window covers the full pulse so a concurrent call
        can never observe a partial state (e.g. amber rebound but
        ``_pulses`` not yet bumped). ``payload_hash`` is passed in
        already-hashed because hashing belongs at the request boundary;
        the runtime stays a pure value sink.
        """
        if not payload_hash or len(payload_hash) > 256:
            raise ValueError("payload_hash must contain at most 256 characters")
        with self._lock:
            state_key = f"slot-{self._pulses % self._max_amber_nodes:08x}"
            state_path = f"/request/{state_key}"
            overwrites_slot = self._amber.get(state_path) is not None
            envelope = RequestEnvelope(
                request_id=request_id,
                channel=channel,
                payload_hash=payload_hash,
                envelope_id=request_id,
                owner_key_hash=owner_key_hash,
                session_id=session_id,
                run_id=request_id,
                source=source or ("websocket" if channel.startswith("ws_") else "web"),
                request_hash=payload_hash,
                idempotency_key=request_id,
                created_at=now_ms,
                auth_role="local-user",
                state_key=state_key,
            )
            event = InboundEvent(
                kind=InboundKind.REQUEST,
                arrived_at=now_ms,
                request=envelope,
            )
            new_amber, actions = pulse(
                now_ms,
                [event],
                self._amber,
                self._wheel,
                self._tide,
            )
            # Identity-aware rebind: the kernel returns the same amber
            # reference when no commit happened (denied request). A
            # genuine commit returns a CoW successor. ``pulse()``
            # declares its return as ``AmberTree`` (the Protocol), but
            # at runtime it is always the same concrete class we
            # handed in — :class:`AmberTreeImpl` exposes ``version``
            # / ``snapshot()``-friendly state we need below.
            new_amber_impl = cast("AmberTreeImpl", new_amber)
            self._amber = new_amber_impl
            self._pulses += 1
            # ``admitted`` mirrors the kernel: a commit means the
            # request was admitted by the tide. A denied request still
            # produces exactly one EmitResponse (backpressure metadata),
            # but no commit. We look at ``actions`` to classify so the
            # caller does not have to repeat the tide query.
            admitted = any(getattr(a, "metadata", None) == (("admit", "ok"),) for a in actions)
            if admitted and overwrites_slot:
                self._amber_slot_overwrites += 1
            return PulseObservation(
                amber_root_hash=new_amber_impl.root_hash,
                amber_version=new_amber_impl.version,
                actions_count=len(actions),
                admitted=admitted,
            )

    # ------------------------------------------------------------------
    # Read-only snapshot for tests
    # ------------------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        """Return a flat dict view of the runtime state.

        Used by :func:`get_pulse_runtime_snapshot_for_tests`. Holds
        the runtime lock so the snapshot is a consistent point-in-time
        read. The returned dict is a fresh allocation; mutating it
        cannot affect the runtime.

        The pulse runtime exposes no persistence state. Durable health belongs
        to the authoritative Echo safety service.
        """
        with self._lock:
            return {
                "amber_root_hash": self._amber.root_hash,
                "amber_version": self._amber.version,
                "amber_node_count": self._amber.node_count,
                "amber_node_limit": self._max_amber_nodes,
                "amber_slot_overwrites": self._amber_slot_overwrites,
                "wheel_size": self._wheel.size(),
                "tide_channels": list(self._tide.known_channels()),
                "pulses": self._pulses,
            }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
# Production access goes through ``get_pulse_runtime()``. The singleton
# is constructed lazily on first use so importing this module from a
# test that explicitly does NOT want a runtime (e.g. a unit test for the
# class itself) does not implicitly create state. The construction
# itself is guarded by ``_singleton_lock`` so two concurrent first-time
# callers cannot end up with two runtimes.
_singletons: dict[str, EchoPulseRuntime] = {}
_singleton_lock = threading.Lock()


def get_pulse_runtime(partition_id: str = "default") -> EchoPulseRuntime:
    """Return the process-local Echo pulse runtime, building it lazily.

    Safe to call from any thread. The construction is double-checked
    under ``_singleton_lock`` so concurrent first-time callers cannot
    race two runtimes into existence.

    The singleton is process-local admission state only. Persistent records are
    written by the authoritative Echo safety service at effect boundaries.
    """
    if not partition_id:
        raise ValueError("partition_id must be non-empty")
    with _singleton_lock:
        runtime = _singletons.get(partition_id)
        if runtime is None:
            runtime = EchoPulseRuntime()
            _singletons[partition_id] = runtime
        return runtime


# ---------------------------------------------------------------------------
# Test-only helpers — production code MUST NOT call these
# ---------------------------------------------------------------------------
def reset_pulse_runtime_for_tests() -> None:
    """Drop the module-level singleton.

    The next :func:`get_pulse_runtime` call will build a fresh
    runtime with an empty AmberTree, an empty TimingWheel, and a
    TideController with no observed channels. Used by test fixtures
    to guarantee isolation between tests.

    **Production code MUST NOT call this.** The ``_for_tests`` suffix
    is the contractual marker; a code reviewer should reject any
    production caller of this function on sight.
    """
    with _singleton_lock:
        _singletons.clear()


def get_pulse_runtime_snapshot_for_tests() -> dict[str, Any]:
    """Return a flat snapshot dict of the current runtime state.

    Keys:

    - ``amber_root_hash`` (str)
    - ``amber_version`` (int)
    - ``wheel_size`` (int) — pending timer count
    - ``tide_channels`` (list[str]) — channels with observed history
    - ``pulses`` (int) — total ``observe()`` calls completed
    Returns a snapshot dict, never a live reference to runtime state.
    If the singleton has not been built yet (post-reset), this still
    triggers a build, so the test can immediately assert on the
    initial state.

    **Production code MUST NOT call this.**
    """
    return get_pulse_runtime().snapshot()


__all__ = [
    "EchoPulseRuntime",
    "PulseObservation",
    "get_pulse_runtime",
    "get_pulse_runtime_snapshot_for_tests",
    "reset_pulse_runtime_for_tests",
]
