"""Echo 2.0 Service Provider Interfaces (SPI).

Five Protocols mark the only legitimate boundary between the pure kernel and
the outside world. Each method body is ``...`` because this module defines
interfaces only; concrete adapters live at explicit Echo edges.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from js.echo.types import (
    Action,
    CapabilityLease,
    InboundEvent,
    PulseFrame,
    RequestEnvelope,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


@runtime_checkable
class InboundDriver(Protocol):
    """Pulls inbound events from a transport (HTTP, queue, timer)."""

    def drain(self, now: int) -> list[InboundEvent]:
        """Return the inbound events ready to be handed to ``pulse()``."""
        ...

    def acknowledge(self, event: InboundEvent) -> None:
        """Mark an event as consumed by the kernel."""
        ...


@runtime_checkable
class OutboundDriver(Protocol):
    """Dispatches kernel-produced actions to the outside world."""

    def dispatch(self, action: Action) -> None:
        """Hand off one kernel action for side-effecting execution."""
        ...

    def respond(self, envelope: RequestEnvelope, payload_hash: str) -> None:
        """Send a response payload (referenced by hash) back to a caller."""
        ...


@runtime_checkable
class LedgerStore(Protocol):
    """Append-only frame ledger used for audit and replay (Echo spec §7)."""

    def append(self, frame: PulseFrame) -> int:
        """Append a committed pulse frame; return its monotonic frame_seq.

        Must be idempotent on retry; the returned int is the stored seq.
        """
        ...

    def frames(self) -> Iterator[PulseFrame]:
        """Iterate all committed frames in seq order, oldest first.

        Used by crash recovery to replay the ledger. Must not block on new
        appends; this is a snapshot of what's already durable.
        """
        ...

    def flock(self) -> bool:
        """Acquire the single-leader file lock.

        Returns True iff this process now holds the lock. Used as fencing
        against split-brain on restart. Implementers must keep the lock
        held for the lifetime of the kernel process.
        """
        ...


@runtime_checkable
class Sandbox(Protocol):
    """Capability-leased side-effect host."""

    def grant(
        self,
        tool_name: str,
        resource_scope: str,
        now: int,
    ) -> CapabilityLease:
        """Issue a fresh capability lease bounded by policy.

        Inputs mirror Echo spec §4 ``CapabilityLease`` fields: ``tool_name``
        identifies the capability, ``resource_scope`` declares the resource
        boundary the caller is asking for. ``now`` is the injected clock.
        Concrete lease shaping (budget, fs_roots, network_policy, nonce,
        expiry, MAC) is the implementer's responsibility in later tides.
        """
        ...

    def execute(self, lease: CapabilityLease, arguments_hash: str) -> str:
        """Run the leased capability and return a result payload hash."""
        ...


@runtime_checkable
class Store(Protocol):
    """Keyed snapshot store for AmberTree segments (versioned).

    The kernel itself does not mutate via this Protocol; adapters use it to
    page state in and out across pulses.
    """

    def load(self, key: str) -> bytes | None:
        """Return the latest blob for ``key`` (``None`` if absent)."""
        ...

    def save(self, key: str, blob: bytes, *, version: int) -> int:
        """Persist ``blob`` at ``version`` and return the stored version."""
        ...


__all__ = [
    "InboundDriver",
    "LedgerStore",
    "OutboundDriver",
    "Sandbox",
    "Store",
]
