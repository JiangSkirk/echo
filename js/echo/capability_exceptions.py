"""Capability lease denial hierarchy and consume receipt."""

from __future__ import annotations

from dataclasses import dataclass


class LeaseDenied(Exception):  # noqa: N818  # Plan-mandated public API name; "Denied" reads as the policy verb, not an error suffix.
    """Base class for any lease-related authority denial."""


class LeaseMacInvalid(LeaseDenied):
    """The lease's MAC did not match the canonical recomputed MAC."""


class LeaseExpired(LeaseDenied):
    """``now`` is strictly greater than ``lease.expires_at``."""


class LeaseNonceReplay(LeaseDenied):
    """The lease's nonce is unknown, already exhausted, or bound to another lease."""


class LeaseRevoked(LeaseDenied):
    """The lease (or one of its ancestors) has been revoked."""


class LeaseExhausted(LeaseDenied):
    """The lease has no remaining invocation slots."""


class LeaseOwnerMismatch(LeaseDenied):
    """``lease.owner_key_hash`` did not match the expected owner."""


class LeaseScopeMismatch(LeaseDenied):
    """``lease.resource_scope`` did not match the expected scope."""


class LeaseToolMismatch(LeaseDenied):
    """``lease.tool_name`` did not match the expected tool."""


class LeaseUnknownTool(LeaseDenied):
    """The tool referenced by a lease is unknown to the policy layer."""


class LeaseParentMissing(LeaseDenied):
    """A lease was issued with a ``parent_lease_id`` that is not registered."""


class LeaseContextMismatch(LeaseDenied):
    """A signed execution context did not match the stored lease record."""


class LeaseBindingMismatch(LeaseDenied):
    """A parent/child lease crossed its product, owner, or session binding."""


class EchoAnchorUnavailable(LeaseDenied):
    """The Echo anchor authority is unavailable for consume verification."""


# ---------------------------------------------------------------------------
# Durable consume receipt (R4A-B1)
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class LeaseConsumeReceipt:
    """Durable proof of a single-use lease consumption.

    The ``ledger_record_hash`` is the domain-separated SHA-256 of the
    consume record written to the persistent lease ledger.  It is used
    as the Echo anchor binding to detect valid-prefix rollback of the
    lease ledger alone.
    """

    lease_id: str
    nonce: str
    consumed_at: int
    ledger_seq: int
    ledger_record_hash: str

