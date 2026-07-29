"""Echo 2.0 frozen value types.

All data carriers are immutable ``@dataclass(frozen=True)``. They model the
*shape* of inbound events and outbound actions; behaviour stays out of this
module. Anything that touches the world (I/O, clocks, randomness) lives behind
SPI Protocols in :mod:`js.echo.spi` and is injected at the edges.

Action variants are exposed as sibling frozen dataclasses (``Exec``,
``Resonate``, ``CommitFrame``, ``EmitResponse``). ``Action`` is a public
type alias that unions them; switch on ``isinstance`` at the call site.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


# ---------------------------------------------------------------------------
# Inbound side
# ---------------------------------------------------------------------------
class InboundKind(StrEnum):
    """Coarse classification of an inbound event."""

    REQUEST = "request"
    TIMER = "timer"
    RESONANCE = "resonance"
    LEDGER_ACK = "ledger_ack"
    SANDBOX_RESULT = "sandbox_result"


@dataclass(frozen=True)
class RequestEnvelope:
    """Opaque request payload entering the kernel.

    ``request_id`` / ``channel`` / ``payload_hash`` remain first for stable
    serialization. The additional identity fields carry
    owner/session/run/source/idempotency/auth role into the kernel.
    """

    request_id: str
    channel: str
    payload_hash: str
    envelope_id: str = ""
    owner_key_hash: str = "local-user"
    session_id: str = ""
    run_id: str = ""
    source: str = "test"
    request_hash: str = ""
    idempotency_key: str = ""
    created_at: int = 0
    auth_role: str = "local-user"
    state_key: str = ""

    def __post_init__(self) -> None:
        if not self.envelope_id:
            object.__setattr__(self, "envelope_id", self.request_id)
        if not self.request_hash:
            object.__setattr__(self, "request_hash", self.payload_hash)
        if not self.idempotency_key:
            object.__setattr__(self, "idempotency_key", self.request_id)
        if not self.state_key:
            object.__setattr__(self, "state_key", self.request_id)


@dataclass(frozen=True)
class InboundEvent:
    """One discrete event handed to ``pulse()`` on a tick."""

    kind: InboundKind
    arrived_at: int
    request: RequestEnvelope | None = None
    correlation_id: str | None = None


# ---------------------------------------------------------------------------
# Budget & capability lease
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Budget:
    """Token / latency / wall-clock budget attached to a unit of work."""

    tokens: int
    wall_ms: int
    depth: int


@dataclass(frozen=True)
class CapabilityLease:
    """A capability lease as defined in Echo spec §4.

    Pinned to the spec's 15-field shape. ``args_schema`` stays a string
    reference / hash; the concrete schema is registered elsewhere
    in later tides. ``parent_lease_id`` is ``None`` for top-level leases.
    """

    lease_id: str
    owner_key_hash: str
    run_id: str
    tool_name: str
    args_schema: str
    resource_scope: str
    fs_roots: tuple[str, ...]
    network_policy: str
    max_bytes: int
    max_duration_ms: int
    max_invocations: int
    nonce: str
    expires_at: int
    parent_lease_id: str | None
    mac: bytes
    product_id: str = ""
    session_id: str = ""
    network_hosts: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Pulse frame (snapshot of one kernel tick)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PulseFrame:
    """Snapshot of one ``pulse()`` invocation as defined in Echo spec §4.

    The frame is what the ledger commits and what audits replay against.
    ``delta`` is the serialized AmberTree delta payload; ``mac`` and
    ``crc32`` cover authenticity and integrity respectively.
    """

    frame_seq: int
    root_hash: str
    delta: bytes
    prev_frame_hash: str
    mac: bytes
    crc32: int


# ---------------------------------------------------------------------------
# Outbound action variants
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Exec:
    """Request the sandbox to execute a capability under a lease."""

    lease: CapabilityLease
    arguments_hash: str


@dataclass(frozen=True)
class Resonate:
    """Schedule a future inbound event onto the timing wheel."""

    fire_at: int
    correlation_id: str


@dataclass(frozen=True)
class CommitFrame:
    """Commit a pulse frame to the ledger."""

    frame: PulseFrame


@dataclass(frozen=True)
class EmitResponse:
    """Emit a response back to an inbound channel."""

    request_id: str
    channel: str
    payload_hash: str
    metadata: tuple[tuple[str, str], ...] = field(default_factory=tuple)


Action = Exec | Resonate | CommitFrame | EmitResponse
"""Public union of the four Echo action variants."""


__all__ = [
    "Action",
    "Budget",
    "CapabilityLease",
    "CommitFrame",
    "EmitResponse",
    "Exec",
    "InboundEvent",
    "InboundKind",
    "PulseFrame",
    "RequestEnvelope",
    "Resonate",
]
