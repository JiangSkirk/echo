"""Echo T7 — CapabilityLease policy + HMAC-SHA-256 verification.

This module owns the issuance, MAC computation, verification, single-use
consumption, and eager revocation of :class:`~js.echo.types.CapabilityLease`
records as defined in Echo spec §4.

Notes
-----
* T7 default authority is in-memory; callers may opt into a local JSONL
  lease ledger for cross-restart issue/consume/revoke replay.
* Module never reads env vars; ``mac_key`` must be injected at construction.
* Module never calls gateway / runtime / ``pulse()``; it is a pure policy
  oracle with no I/O side effects.
* Eager revocation: ``revoke(lease_id)`` marks ``lease_id`` plus all
  descendants in one BFS pass.

The canonical MAC pre-image laid out in :func:`_canonical_lease_payload`
embeds its domain prefix directly so callers receive bytes that are already
domain-separated from the authoritative durable journal contract.

T7.1 hardening: ``LeaseAuthority.consume()`` now validates the lease's
MAC against the authority's stored canonical record before mutating any
nonce state; the ``mac_key`` public property has been removed so the
HMAC key never leaks across the authority boundary.
"""

from __future__ import annotations

import dataclasses
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from js.echo.types import CapabilityLease

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------
DEFAULT_NETWORK_POLICY: Final[str] = "deny"
"""Default network policy attached to a lease when the caller omits one."""

LEASE_MAC_DOMAIN: Final[bytes] = b"echo-capability-lease-v1:"
"""Domain separator prefixed to every lease MAC pre-image."""

TOOL_CONTEXT_MAC_DOMAIN: Final[bytes] = b"echo-tool-execution-context-v1:"
"""Domain separator for signed registry execution contexts."""


# ---------------------------------------------------------------------------
# Exception family
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Canonical encoding primitives (capability-permit domain only)
# ---------------------------------------------------------------------------
def _enc_u64_be(value: int) -> bytes:
    """Encode an unsigned 64-bit integer in big-endian byte order."""

    return int(value).to_bytes(8, "big", signed=False)


def _enc_u32_be(value: int) -> bytes:
    """Encode an unsigned 32-bit integer in big-endian byte order."""

    return int(value).to_bytes(4, "big", signed=False)


def _enc_str(text: str) -> bytes:
    """Encode a UTF-8 string as a length-prefixed byte sequence."""

    payload = text.encode("utf-8")
    return _enc_u32_be(len(payload)) + payload


def _enc_tuple_str(items: tuple[str, ...]) -> bytes:
    """Encode a tuple of strings as a length-prefixed sequence of length-prefixed UTF-8 strings."""

    parts = [_enc_u32_be(len(items))]
    parts.extend(_enc_str(item) for item in items)
    return b"".join(parts)


def _enc_opt_str(value: str | None) -> bytes:
    """Encode an optional string as ``\\x00`` (None) or ``\\x01`` + length-prefixed UTF-8."""

    if value is None:
        return b"\x00"
    return b"\x01" + _enc_str(value)


def _canonical_lease_payload(lease: CapabilityLease) -> bytes:
    """Return the canonical, domain-separated MAC pre-image for ``lease``.

    The lease's ``mac`` field is *not* part of the pre-image: only the
    other 14 fields participate, in the order documented in Echo spec §4.
    The returned bytes already include the
    :data:`LEASE_MAC_DOMAIN` prefix; callers should feed them directly
    into HMAC.
    """

    return b"".join(
        (
            LEASE_MAC_DOMAIN,
            _enc_str(lease.lease_id),
            _enc_str(lease.product_id),
            _enc_str(lease.owner_key_hash),
            _enc_str(lease.session_id),
            _enc_str(lease.run_id),
            _enc_str(lease.tool_name),
            _enc_str(lease.args_schema),
            _enc_str(lease.resource_scope),
            _enc_tuple_str(lease.fs_roots),
            _enc_str(lease.network_policy),
            _enc_tuple_str(lease.network_hosts),
            _enc_u64_be(lease.max_bytes),
            _enc_u64_be(lease.max_duration_ms),
            _enc_u32_be(lease.max_invocations),
            _enc_str(lease.nonce),
            _enc_u64_be(lease.expires_at),
            _enc_opt_str(lease.parent_lease_id),
        )
    )


def _tool_context_payload(context: Any) -> bytes:
    """Canonical payload for an Echo tool execution context."""

    fs_roots = tuple(str(item) for item in getattr(context, "fs_roots", ()))
    return b"".join(
        (
            TOOL_CONTEXT_MAC_DOMAIN,
            _enc_str(str(getattr(context, "product_id", ""))),
            _enc_str(str(getattr(context, "owner_key_hash", ""))),
            _enc_str(str(getattr(context, "session_id", ""))),
            _enc_str(str(getattr(context, "run_id", ""))),
            _enc_str(str(getattr(context, "profile", ""))),
            _enc_str(str(getattr(context, "tool_name", ""))),
            _enc_str(str(getattr(context, "args_hash", ""))),
            _enc_str(str(getattr(context, "resource_scope", ""))),
            _enc_tuple_str(fs_roots),
            _enc_str(str(getattr(context, "network_policy", ""))),
            _enc_tuple_str(tuple(str(item) for item in getattr(context, "network_hosts", ()))),
            _enc_u64_be(int(getattr(context, "max_bytes", 0))),
            _enc_u64_be(int(getattr(context, "max_duration_ms", 0))),
            _enc_str(str(getattr(context, "lease_id", ""))),
            _enc_str(str(getattr(context, "lease_mac", ""))),
        )
    )


def sign_tool_execution_context(
    context: Any,
    *,
    lease: CapabilityLease,
    authority: LeaseAuthority | None = None,
    now: int | None = None,
) -> Any:
    """Return ``context`` with an Echo registry signature attached."""

    if authority is None:
        raise ValueError("Echo tool context signing requires a lease authority")

    if getattr(context, "owner_key_hash", "") != lease.owner_key_hash:
        raise LeaseContextMismatch("context owner_key_hash does not match lease")
    if getattr(context, "product_id", "") != lease.product_id:
        raise LeaseContextMismatch("context product_id does not match lease")
    if getattr(context, "session_id", "") != lease.session_id:
        raise LeaseContextMismatch("context session_id does not match lease")
    if getattr(context, "run_id", "") != lease.run_id:
        raise LeaseContextMismatch("context run_id does not match lease")
    if getattr(context, "tool_name", "") != lease.tool_name:
        raise LeaseContextMismatch("context tool_name does not match lease")
    if getattr(context, "args_hash", "") != lease.args_schema:
        raise LeaseContextMismatch("context args_hash does not match lease")
    if getattr(context, "resource_scope", "") != lease.resource_scope:
        raise LeaseContextMismatch("context resource_scope does not match lease")
    if tuple(getattr(context, "fs_roots", ())) != tuple(lease.fs_roots):
        raise LeaseContextMismatch("context fs_roots do not match lease")
    if getattr(context, "network_policy", "") != lease.network_policy:
        raise LeaseContextMismatch("context network_policy does not match lease")
    if tuple(getattr(context, "network_hosts", ())) != tuple(lease.network_hosts):
        raise LeaseContextMismatch("context network_hosts do not match lease")
    if int(getattr(context, "max_bytes", -1)) != int(lease.max_bytes):
        raise LeaseContextMismatch("context max_bytes does not match lease")
    if int(getattr(context, "max_duration_ms", -1)) != int(lease.max_duration_ms):
        raise LeaseContextMismatch("context max_duration_ms does not match lease")
    if authority is not None:
        authority.verify_execution_context(
            lease_id=lease.lease_id,
            lease_mac=lease.mac.hex(),
            product_id=lease.product_id,
            owner_key_hash=lease.owner_key_hash,
            session_id=lease.session_id,
            run_id=lease.run_id,
            tool_name=lease.tool_name,
            args_schema=lease.args_schema,
            resource_scope=lease.resource_scope,
            fs_roots=lease.fs_roots,
            network_policy=lease.network_policy,
            network_hosts=lease.network_hosts,
            max_bytes=lease.max_bytes,
            max_duration_ms=lease.max_duration_ms,
            now=now if now is not None else int(authority._now()),
        )
    signed = dataclasses.replace(
        context,
        lease_id=lease.lease_id,
        lease_mac=lease.mac.hex(),
        signature="",
    )
    mac = hmac.new(
        authority._context_signing_key(),
        _tool_context_payload(signed),
        hashlib.sha256,
    ).hexdigest()
    return dataclasses.replace(signed, signature=f"authority-hmac-sha256:{mac}")


def compute_lease_mac(mac_key: bytes, lease: CapabilityLease) -> bytes:
    """Compute the HMAC-SHA-256 MAC tag for ``lease`` under ``mac_key``.

    The lease's own ``mac`` field is ignored; only the 14 non-MAC fields
    contribute to the pre-image (see :func:`_canonical_lease_payload`).
    Returns 32 raw bytes.
    """

    digest = hmac.new(mac_key, digestmod=hashlib.sha256)
    digest.update(_canonical_lease_payload(lease))
    return digest.digest()


# ---------------------------------------------------------------------------
# Internal nonce bookkeeping
# ---------------------------------------------------------------------------
@dataclass
class _NonceState:
    """Single-use nonce state owned by :class:`LeaseAuthority`."""

    lease_id: str
    invocations_remaining: int


# ---------------------------------------------------------------------------
# Authority
# ---------------------------------------------------------------------------
class LeaseAuthority:
    """Authority that issues, verifies, consumes, and revokes leases.

    All public methods serialize through an internal reentrant lock so the
    authority is safe to share across threads. When ``ledger_path`` is set,
    nonce and revocation state is durably serialized across processes.
    """

    __slots__ = (
        "_mac_key",
        "_now",
        "_lock",
        "_issued",
        "_nonces",
        "_revoked",
        "_parents",
        "_children",
        "_ledger_path",
        "_ledger_prev_hash",
        "_ledger_seq",
        "_ledger_lock_depth",
    )

    def __init__(
        self,
        *,
        mac_key: bytes,
        now_fn: Callable[[], int],
        ledger_path: Path | None = None,
    ) -> None:
        """Construct an authority with an injected MAC key and clock.

        Parameters
        ----------
        mac_key:
            HMAC key, must be at least 16 bytes of entropy. Defensively
            copied; the caller's buffer is not retained.
        now_fn:
            Monotonic-ish wall-clock source returning integer milliseconds.
        """

        if not isinstance(mac_key, (bytes, bytearray)):
            raise ValueError("mac_key must be bytes")
        if len(mac_key) < 16:
            raise ValueError("mac_key must be at least 16 bytes")
        if not callable(now_fn):
            raise TypeError("now_fn must be callable")

        self._mac_key: bytes = bytes(mac_key)
        self._now: Callable[[], int] = now_fn
        self._lock = threading.RLock()
        self._issued: dict[str, CapabilityLease] = {}
        self._nonces: dict[str, _NonceState] = {}
        self._revoked: set[str] = set()
        self._parents: dict[str, str | None] = {}
        self._children: dict[str, set[str]] = {}
        self._ledger_path = ledger_path
        self._ledger_prev_hash = "sha256:" + "0" * 64
        self._ledger_seq = 0
        self._ledger_lock_depth = 0
        if self._ledger_path is not None:
            with self._ledger_transaction():
                pass

    # -- issuance ----------------------------------------------------------
    def issue(
        self,
        *,
        owner_key_hash: str,
        run_id: str,
        tool_name: str,
        args_schema: str,
        resource_scope: str,
        max_bytes: int,
        max_duration_ms: int,
        ttl_ms: int,
        fs_roots: tuple[str, ...] = (),
        network_policy: str = DEFAULT_NETWORK_POLICY,
        max_invocations: int = 1,
        parent_lease_id: str | None = None,
        product_id: str = "",
        session_id: str = "",
        network_hosts: tuple[str, ...] = (),
    ) -> CapabilityLease:
        """Issue a fresh :class:`CapabilityLease` and register its bookkeeping.

        Raises
        ------
        ValueError
            If any numeric bound is out of range.
        LeaseParentMissing
            If ``parent_lease_id`` is set but not registered.
        LeaseRevoked
            If ``parent_lease_id`` is registered but already revoked.
        """

        if max_invocations < 1:
            raise ValueError("max_invocations must be >= 1")
        if max_bytes < 0:
            raise ValueError("max_bytes must be >= 0")
        if max_duration_ms < 0:
            raise ValueError("max_duration_ms must be >= 0")
        if ttl_ms <= 0:
            raise ValueError("ttl_ms must be > 0")

        with self._lock, self._ledger_transaction():
            if parent_lease_id is not None:
                if parent_lease_id not in self._issued:
                    raise LeaseParentMissing(f"parent lease {parent_lease_id!r} is not registered")
                if parent_lease_id in self._revoked:
                    raise LeaseRevoked(f"parent lease {parent_lease_id!r} is revoked")
                parent = self._issued[parent_lease_id]
                owner_matches = len(parent.owner_key_hash) == len(owner_key_hash) and hmac.compare_digest(
                    parent.owner_key_hash.encode("utf-8"),
                    owner_key_hash.encode("utf-8"),
                )
                if (
                    parent.product_id != product_id
                    or not owner_matches
                    or parent.session_id != session_id
                ):
                    raise LeaseBindingMismatch(
                        "child lease must inherit parent product_id, owner_key_hash, and session_id"
                    )

            # Allocate a fresh lease_id (single retry on collision — 128-bit
            # space makes a third hit astronomically unlikely).
            lease_id = secrets.token_hex(16)
            if lease_id in self._issued:
                lease_id = secrets.token_hex(16)

            # Allocate a fresh nonce that is not already pending.
            nonce = secrets.token_hex(16)
            if nonce in self._nonces:
                nonce = secrets.token_hex(16)

            expires_at = int(self._now()) + int(ttl_ms)

            template = CapabilityLease(
                lease_id=lease_id,
                owner_key_hash=owner_key_hash,
                run_id=run_id,
                tool_name=tool_name,
                args_schema=args_schema,
                resource_scope=resource_scope,
                fs_roots=tuple(fs_roots),
                network_policy=network_policy,
                max_bytes=int(max_bytes),
                max_duration_ms=int(max_duration_ms),
                max_invocations=int(max_invocations),
                nonce=nonce,
                expires_at=expires_at,
                parent_lease_id=parent_lease_id,
                mac=b"",
                product_id=product_id,
                session_id=session_id,
                network_hosts=tuple(network_hosts),
            )
            mac = compute_lease_mac(self._mac_key, template)
            lease = dataclasses.replace(template, mac=mac)

            self._issued[lease_id] = lease
            self._nonces[nonce] = _NonceState(
                lease_id=lease_id,
                invocations_remaining=int(max_invocations),
            )
            self._parents[lease_id] = parent_lease_id
            self._children.setdefault(lease_id, set())
            if parent_lease_id is not None:
                self._children.setdefault(parent_lease_id, set()).add(lease_id)

            self._append_ledger_record(
                "issue",
                {
                    "lease": _lease_to_payload(lease),
                },
            )
            return lease

    # -- canonical lookup --------------------------------------------------
    def _canonical_check(self, presented: CapabilityLease) -> CapabilityLease:
        """Return the authority's stored canonical lease for ``presented``.

        Fail-closed guard shared by :meth:`consume`. Performs the
        following checks without mutating any state:

        1. ``presented.lease_id`` is registered in ``self._issued``
           (else :class:`LeaseNonceReplay` — we cannot distinguish a
           never-issued id from a long-since-purged one without leaking
           lease provenance).
        2. Stored canonical record MAC self-check (T7.2): the MAC
           recomputed over the stored lease matches the MAC recorded on
           the stored lease itself (else :class:`LeaseMacInvalid`).
        3. The MAC recomputed over ``presented`` matches the MAC on
           ``presented`` itself (else :class:`LeaseMacInvalid`).
        4. The MAC on ``presented`` matches the MAC recorded on the
           stored canonical lease (else :class:`LeaseMacInvalid`).

        Returning the stored lease lets callers read ``expires_at`` /
        ``max_invocations`` / etc. from the authority's record rather
        than trusting the (possibly tampered) ``presented`` object.

        This method is intentionally not part of the public API; it is
        for internal use by methods that mutate state and therefore must
        validate the caller's lease end-to-end before doing so.

        The stored-record self-check (step 2) catches in-process
        tampering of ``self._issued`` entries (e.g. an attacker that
        mutates the stored lease's ``expires_at`` after issuance without
        recomputing the MAC), which would otherwise be invisible to a
        presented-only MAC check.
        """

        with self._lock:
            stored = self._issued.get(presented.lease_id)
            if stored is None:
                raise LeaseNonceReplay("lease is not registered with this authority")
            stored_template = dataclasses.replace(stored, mac=b"")
            stored_expected_mac = compute_lease_mac(self._mac_key, stored_template)
            if not hmac.compare_digest(stored_expected_mac, stored.mac):
                raise LeaseMacInvalid("authority record MAC self-check failed")
            expected_template = dataclasses.replace(presented, mac=b"")
            expected_mac = compute_lease_mac(self._mac_key, expected_template)
            if not hmac.compare_digest(expected_mac, presented.mac):
                raise LeaseMacInvalid("lease MAC failed constant-time check")
            if not hmac.compare_digest(stored.mac, presented.mac):
                raise LeaseMacInvalid("lease MAC does not bind to authority record")
            return stored

    # -- verification ------------------------------------------------------
    def verify(
        self,
        lease: CapabilityLease,
        *,
        expected_owner: str,
        expected_tool: str,
        expected_scope: str,
        now: int,
    ) -> None:
        """Verify ``lease`` is currently authoritative for the given context.

        The checks fire in the documented order; the first failure raises
        and wins. On success this method returns ``None`` and does not
        mutate any state.
        """

        with self._lock, self._ledger_transaction():
            expected_template = dataclasses.replace(lease, mac=b"")
            expected_mac = compute_lease_mac(self._mac_key, expected_template)
            if not hmac.compare_digest(expected_mac, lease.mac):
                raise LeaseMacInvalid("lease MAC failed constant-time check")

            if now > lease.expires_at:
                raise LeaseExpired(f"lease {lease.lease_id!r} expired at {lease.expires_at}")

            if lease.lease_id in self._revoked:
                raise LeaseRevoked(f"lease {lease.lease_id!r} is revoked")

            owner_ok = len(lease.owner_key_hash) == len(expected_owner) and hmac.compare_digest(
                lease.owner_key_hash.encode("utf-8"),
                expected_owner.encode("utf-8"),
            )
            if not owner_ok:
                raise LeaseOwnerMismatch("lease owner_key_hash does not match expected owner")

            if lease.tool_name != expected_tool:
                raise LeaseToolMismatch("lease tool_name does not match expected tool")

            if lease.resource_scope != expected_scope:
                raise LeaseScopeMismatch("lease resource_scope does not match expected scope")

    def _validate_bound_locked(
        self,
        lease: CapabilityLease,
        *,
        expected_product_id: str,
        expected_owner: str,
        expected_session: str,
        expected_run: str,
        expected_tool: str,
        expected_args_schema: str,
        expected_resource_scope: str,
        expected_fs_roots: tuple[str, ...],
        expected_network_policy: str,
        expected_network_hosts: tuple[str, ...],
        expected_max_bytes: int,
        expected_max_duration_ms: int,
        now: int,
        require_single_use: bool,
    ) -> tuple[CapabilityLease, _NonceState]:
        """Validate a complete expected binding while the authority transaction is held."""

        if type(lease) is not CapabilityLease:
            raise LeaseBindingMismatch("bound consume requires an exact CapabilityLease")
        if type(expected_fs_roots) is not tuple or type(expected_network_hosts) is not tuple:
            raise LeaseBindingMismatch("bound lease tuple fields must be immutable")
        if any(type(item) is not str for item in (*expected_fs_roots, *expected_network_hosts)):
            raise LeaseBindingMismatch("bound lease tuple values must be text")
        if type(now) is not int or type(expected_max_bytes) is not int or type(expected_max_duration_ms) is not int:
            raise LeaseBindingMismatch("bound lease numeric expectations must be integers")

        stored = self._canonical_check(lease)
        if stored.lease_id in self._revoked:
            raise LeaseRevoked(f"lease {stored.lease_id!r} is revoked")
        if now > stored.expires_at:
            raise LeaseExpired(f"lease {stored.lease_id!r} expired at {stored.expires_at}")
        owner_ok = len(stored.owner_key_hash) == len(expected_owner) and hmac.compare_digest(
            stored.owner_key_hash.encode("utf-8"),
            expected_owner.encode("utf-8"),
        )
        checks = (
            ("product_id", stored.product_id == expected_product_id),
            ("owner_key_hash", owner_ok),
            ("session_id", stored.session_id == expected_session),
            ("run_id", stored.run_id == expected_run),
            ("tool_name", stored.tool_name == expected_tool),
            ("args_schema", stored.args_schema == expected_args_schema),
            ("resource_scope", stored.resource_scope == expected_resource_scope),
            ("fs_roots", tuple(stored.fs_roots) == expected_fs_roots),
            ("network_policy", stored.network_policy == expected_network_policy),
            ("network_hosts", tuple(stored.network_hosts) == expected_network_hosts),
            ("max_bytes", stored.max_bytes == expected_max_bytes),
            ("max_duration_ms", stored.max_duration_ms == expected_max_duration_ms),
            ("max_invocations", not require_single_use or stored.max_invocations == 1),
        )
        for field, matches in checks:
            if not matches:
                raise LeaseBindingMismatch(f"lease {field} does not match expected binding")

        state = self._nonces.get(stored.nonce)
        if state is None:
            raise LeaseNonceReplay("lease nonce is unknown or already exhausted")
        if state.lease_id != stored.lease_id:
            raise LeaseNonceReplay("lease nonce does not bind to the presented lease_id")
        if state.invocations_remaining <= 0:
            raise LeaseExhausted(f"lease {stored.lease_id!r} has no invocations remaining")
        return stored, state

    def verify_bound(
        self,
        lease: CapabilityLease,
        *,
        expected_product_id: str,
        expected_owner: str,
        expected_session: str,
        expected_run: str,
        expected_tool: str,
        expected_args_schema: str,
        expected_resource_scope: str,
        expected_fs_roots: tuple[str, ...],
        expected_network_policy: str,
        expected_network_hosts: tuple[str, ...],
        expected_max_bytes: int,
        expected_max_duration_ms: int,
        now: int,
        require_single_use: bool = True,
    ) -> None:
        """Perform the complete connector binding preflight without consuming."""

        with self._lock, self._ledger_transaction():
            self._validate_bound_locked(
                lease,
                expected_product_id=expected_product_id,
                expected_owner=expected_owner,
                expected_session=expected_session,
                expected_run=expected_run,
                expected_tool=expected_tool,
                expected_args_schema=expected_args_schema,
                expected_resource_scope=expected_resource_scope,
                expected_fs_roots=expected_fs_roots,
                expected_network_policy=expected_network_policy,
                expected_network_hosts=expected_network_hosts,
                expected_max_bytes=expected_max_bytes,
                expected_max_duration_ms=expected_max_duration_ms,
                now=now,
                require_single_use=require_single_use,
            )

    def consume_bound(
        self,
        lease: CapabilityLease,
        *,
        expected_product_id: str,
        expected_owner: str,
        expected_session: str,
        expected_run: str,
        expected_tool: str,
        expected_args_schema: str,
        expected_resource_scope: str,
        expected_fs_roots: tuple[str, ...],
        expected_network_policy: str,
        expected_network_hosts: tuple[str, ...],
        expected_max_bytes: int,
        expected_max_duration_ms: int,
        now: int,
        require_single_use: bool = True,
    ) -> LeaseConsumeReceipt:
        """Validate and durably consume one exact lease in one transaction.

        Returns a :class:`LeaseConsumeReceipt` containing the durable
        ledger record hash, which callers should bind to an Echo anchor
        for valid-prefix rollback detection.
        """

        with self._lock, self._ledger_transaction():
            stored, state = self._validate_bound_locked(
                lease,
                expected_product_id=expected_product_id,
                expected_owner=expected_owner,
                expected_session=expected_session,
                expected_run=expected_run,
                expected_tool=expected_tool,
                expected_args_schema=expected_args_schema,
                expected_resource_scope=expected_resource_scope,
                expected_fs_roots=expected_fs_roots,
                expected_network_policy=expected_network_policy,
                expected_network_hosts=expected_network_hosts,
                expected_max_bytes=expected_max_bytes,
                expected_max_duration_ms=expected_max_duration_ms,
                now=now,
                require_single_use=require_single_use,
            )
            state.invocations_remaining -= 1
            if state.invocations_remaining == 0 and stored.max_invocations == 1:
                del self._nonces[stored.nonce]
            seq = self._ledger_seq
            record_hash = self._append_ledger_record(
                "consume",
                {
                    "lease_id": stored.lease_id,
                    "nonce": stored.nonce,
                    "remaining": max(state.invocations_remaining, 0),
                },
            )
            return LeaseConsumeReceipt(
                lease_id=stored.lease_id,
                nonce=stored.nonce,
                consumed_at=now,
                ledger_seq=seq,
                ledger_record_hash=record_hash,
            )

    def verify_consume_anchor(
        self,
        lease_id: str,
        nonce: str,
        *,
        echo_lookup: Callable[[str, str], str | None],
    ) -> bool:
        """Check whether the Echo authority has a durable consume anchor.

        When the lease ledger's final consume line is deleted (valid-prefix
        rollback), the remaining prefix is self-consistent and the nonce
        appears unconsumed.  This method queries the Echo authority to
        detect such rollback.

        Returns ``True`` if the Echo anchor confirms the lease was consumed.
        Raises :class:`EchoAnchorUnavailable` if the Echo authority is
        unavailable (fail closed).
        """

        try:
            anchor_hash = echo_lookup(lease_id, nonce)
        except Exception as exc:
            raise EchoAnchorUnavailable(
                "echo anchor authority is unavailable"
            ) from exc
        return anchor_hash is not None

    # -- consumption -------------------------------------------------------
    def consume(self, lease: CapabilityLease, *, now: int) -> None:
        """Atomically consume one invocation slot of ``lease``.

        T7.1: validates the lease's MAC against the authority's stored
        canonical record **before** mutating any nonce / invocation
        state. ``expires_at`` / ``max_invocations`` are read from the
        stored lease, not from the caller-supplied ``lease`` object.
        Any tampered field that survives the MAC check would still have
        a recomputed MAC matching the authority's key — i.e. forgery is
        constrained to a constant-time-distinguishable HMAC collision.

        Order of checks (first failure wins; no state mutation before
        every check has passed):

        1. ``_canonical_check`` — registered + MAC valid (else
           :class:`LeaseNonceReplay` / :class:`LeaseMacInvalid`);
        2. ``stored.lease_id in self._revoked`` →
           :class:`LeaseRevoked`;
        3. ``now > stored.expires_at`` → :class:`LeaseExpired` (read
           from the stored record, not the presented one);
        4. ``_nonces[stored.nonce]`` exists and binds to
           ``stored.lease_id`` (else :class:`LeaseNonceReplay`);
        5. invocation slot remains (else :class:`LeaseExhausted`).

        Two distinct exhaustion semantics, by design:

        * ``stored.max_invocations == 1`` (single-use nonce): the nonce
          is forgotten the moment its only slot is consumed. A second
          ``consume()`` therefore raises :class:`LeaseNonceReplay` —
          there is no ledger to distinguish "your nonce never existed"
          from "you already used your nonce".
        * ``stored.max_invocations > 1`` (multi-use lease): the nonce
          state is retained even after the last slot is consumed so the
          next ``consume()`` can raise :class:`LeaseExhausted` and tell
          the caller specifically that the budget is gone — not that
          the nonce was forged.
        """

        with self._lock, self._ledger_transaction():
            stored = self._canonical_check(lease)

            if stored.lease_id in self._revoked:
                raise LeaseRevoked(f"lease {stored.lease_id!r} is revoked")
            if now > stored.expires_at:
                raise LeaseExpired(f"lease {stored.lease_id!r} expired at {stored.expires_at}")

            state = self._nonces.get(stored.nonce)
            if state is None:
                raise LeaseNonceReplay("lease nonce is unknown or already exhausted")
            if state.lease_id != stored.lease_id:
                raise LeaseNonceReplay("lease nonce does not bind to the presented lease_id")
            if state.invocations_remaining <= 0:
                raise LeaseExhausted(f"lease {stored.lease_id!r} has no invocations remaining")

            state.invocations_remaining -= 1
            if state.invocations_remaining == 0 and stored.max_invocations == 1:
                del self._nonces[stored.nonce]
            self._append_ledger_record(
                "consume",
                {
                    "lease_id": stored.lease_id,
                    "nonce": stored.nonce,
                    "remaining": max(state.invocations_remaining, 0),
                },
            )

    def verify_execution_context(
        self,
        *,
        lease_id: str,
        lease_mac: str,
        product_id: str,
        owner_key_hash: str,
        session_id: str,
        run_id: str,
        tool_name: str,
        args_schema: str,
        resource_scope: str,
        fs_roots: tuple[str, ...],
        network_policy: str,
        network_hosts: tuple[str, ...],
        max_bytes: int,
        max_duration_ms: int,
        now: int,
    ) -> None:
        """Verify a registry execution context against the stored lease record."""

        with self._lock, self._ledger_transaction():
            stored = self._issued.get(lease_id)
            if stored is None:
                raise LeaseNonceReplay("execution context lease is unknown")
            if not hmac.compare_digest(stored.mac.hex(), lease_mac):
                raise LeaseMacInvalid("execution context lease MAC mismatch")
            if now > stored.expires_at:
                raise LeaseExpired(f"lease {lease_id!r} expired at {stored.expires_at}")
            if stored.lease_id in self._revoked:
                raise LeaseRevoked(f"lease {lease_id!r} is revoked")
            checks = {
                "product_id": stored.product_id == product_id,
                "owner_key_hash": (
                    len(stored.owner_key_hash) == len(owner_key_hash)
                    and hmac.compare_digest(
                        stored.owner_key_hash.encode("utf-8"),
                        owner_key_hash.encode("utf-8"),
                    )
                ),
                "session_id": stored.session_id == session_id,
                "run_id": stored.run_id == run_id,
                "tool_name": stored.tool_name == tool_name,
                "args_schema": stored.args_schema == args_schema,
                "resource_scope": stored.resource_scope == resource_scope,
                "fs_roots": tuple(stored.fs_roots) == tuple(fs_roots),
                "network_policy": stored.network_policy == network_policy,
                "network_hosts": tuple(stored.network_hosts) == tuple(network_hosts),
                "max_bytes": int(stored.max_bytes) == int(max_bytes),
                "max_duration_ms": int(stored.max_duration_ms) == int(max_duration_ms),
            }
            for field, ok in checks.items():
                if not ok:
                    raise LeaseContextMismatch(f"execution context {field} does not match lease")

    def consume_execution_context(self, context: Any, *, now: int) -> None:
        """Verify a signed registry context and atomically consume its lease."""

        signature = str(getattr(context, "signature", ""))
        if not signature.startswith("authority-hmac-sha256:"):
            raise LeaseContextMismatch("execution context authority signature missing")
        unsigned = dataclasses.replace(context, signature="")
        expected = hmac.new(
            self._context_signing_key(),
            _tool_context_payload(unsigned),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, f"authority-hmac-sha256:{expected}"):
            raise LeaseContextMismatch("execution context authority signature invalid")

        with self._lock, self._ledger_transaction():
            self.verify_execution_context(
                lease_id=str(getattr(context, "lease_id", "")),
                lease_mac=str(getattr(context, "lease_mac", "")),
                product_id=str(getattr(context, "product_id", "")),
                owner_key_hash=str(getattr(context, "owner_key_hash", "")),
                session_id=str(getattr(context, "session_id", "")),
                run_id=str(getattr(context, "run_id", "")),
                tool_name=str(getattr(context, "tool_name", "")),
                args_schema=str(getattr(context, "args_hash", "")),
                resource_scope=str(getattr(context, "resource_scope", "")),
                fs_roots=tuple(getattr(context, "fs_roots", ())),
                network_policy=str(getattr(context, "network_policy", "")),
                network_hosts=tuple(getattr(context, "network_hosts", ())),
                max_bytes=int(getattr(context, "max_bytes", 0)),
                max_duration_ms=int(getattr(context, "max_duration_ms", 0)),
                now=now,
            )
            stored = self._issued[str(getattr(context, "lease_id", ""))]
            self.consume(stored, now=now)

    def _context_signing_key(self) -> bytes:
        """Derive a stable context key without exposing the lease MAC key."""

        return hmac.new(
            self._mac_key,
            b"echo-tool-execution-context-key-v1",
            hashlib.sha256,
        ).digest()

    # -- revocation --------------------------------------------------------
    @staticmethod
    def _shares_binding(left: CapabilityLease, right: CapabilityLease) -> bool:
        return (
            left.product_id == right.product_id
            and len(left.owner_key_hash) == len(right.owner_key_hash)
            and hmac.compare_digest(
                left.owner_key_hash.encode("utf-8"),
                right.owner_key_hash.encode("utf-8"),
            )
            and left.session_id == right.session_id
        )

    def _validate_ancestor_chain(self, root_id: str) -> None:
        """Fail closed when a selected root has a missing, cyclic, or cross-bound ancestor."""

        root = self._issued.get(root_id)
        if root is None:
            raise LeaseBindingMismatch(f"selected lease {root_id!r} is missing from authority ledger")
        current_id = root_id
        seen = {root_id}
        while True:
            if current_id not in self._parents:
                raise LeaseBindingMismatch(
                    f"lease {current_id!r} is missing its recorded parent binding"
                )
            parent_id = self._parents[current_id]
            if parent_id is None:
                return
            if parent_id in seen:
                raise LeaseBindingMismatch("lease ancestor chain contains a cycle")
            parent = self._issued.get(parent_id)
            if parent is None:
                raise LeaseBindingMismatch(
                    f"lease ancestor {parent_id!r} is missing from authority ledger"
                )
            if not self._shares_binding(root, parent):
                raise LeaseBindingMismatch(
                    "lease ancestor crosses product_id, owner_key_hash, or session_id"
                )
            seen.add(parent_id)
            current_id = parent_id

    def _descendant_closure(self, roots: tuple[str, ...]) -> tuple[str, ...]:
        """Return a binding-safe descendant closure without mutating state."""

        queue = list(roots)
        ordered: list[str] = []
        seen: set[str] = set()
        while queue:
            current_id = queue.pop(0)
            if current_id in seen:
                continue
            current = self._issued.get(current_id)
            if current is None:
                raise LeaseBindingMismatch(
                    f"lease descendant {current_id!r} is missing from authority ledger"
                )
            seen.add(current_id)
            ordered.append(current_id)
            for child_id in sorted(self._children.get(current_id, set())):
                child = self._issued.get(child_id)
                if child is None:
                    raise LeaseBindingMismatch(
                        f"lease descendant {child_id!r} is missing from authority ledger"
                    )
                if not self._shares_binding(current, child):
                    raise LeaseBindingMismatch(
                        "lease descendant crosses product_id, owner_key_hash, or session_id"
                    )
                queue.append(child_id)
        return tuple(ordered)

    def revoke(self, lease_id: str) -> None:
        """Mark ``lease_id`` and every descendant as revoked.

        Idempotent: unknown ``lease_id``s are silently ignored, and
        re-revoking an already-revoked lease is a no-op. Descendants are
        discovered eagerly via BFS through the recorded parent/child
        edges captured at issuance time.
        """

        with self._lock, self._ledger_transaction():
            if lease_id not in self._issued:
                return
            targets = self._descendant_closure((lease_id,))
            for current in targets:
                if current in self._revoked:
                    continue
                self._revoked.add(current)
                self._append_ledger_record("revoke", {"lease_id": current})

    def revoke_for_session(
        self,
        *,
        owner_key_hash: str,
        session_id: str,
    ) -> tuple[str, ...]:
        """Atomically revoke leases bound to one verified owner/session.

        Used by AppShell Personal↔Work switch so departing-product leases cannot
        be replayed after the client rebinds. Returns the revoked lease ids.
        """
        if not isinstance(owner_key_hash, str) or not owner_key_hash.strip():
            raise ValueError("owner_key_hash must be a non-empty string")
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be a non-empty string")
        with self._lock, self._ledger_transaction():
            roots = tuple(
                lease_id
                for lease_id, lease in self._issued.items()
                if lease.session_id == session_id
                and len(lease.owner_key_hash) == len(owner_key_hash)
                and hmac.compare_digest(
                    lease.owner_key_hash.encode("utf-8"),
                    owner_key_hash.encode("utf-8"),
                )
                and lease_id not in self._revoked
            )
            for root_id in roots:
                self._validate_ancestor_chain(root_id)
            targets = self._descendant_closure(roots)
            revoked: list[str] = []
            for lease_id in targets:
                if lease_id in self._revoked:
                    continue
                self._revoked.add(lease_id)
                self._append_ledger_record("revoke", {"lease_id": lease_id})
                revoked.append(lease_id)
            return tuple(revoked)

    def active_session_ids_for_owner(self, *, owner_key_hash: str) -> tuple[str, ...]:
        """Snapshot sessions with unrevoked leases for one verified owner."""
        if not isinstance(owner_key_hash, str) or not owner_key_hash.strip():
            raise ValueError("owner_key_hash must be a non-empty string")
        with self._lock, self._ledger_transaction():
            sessions = {
                lease.session_id
                for lease_id, lease in self._issued.items()
                if lease_id not in self._revoked
                and len(lease.owner_key_hash) == len(owner_key_hash)
                and hmac.compare_digest(
                    lease.owner_key_hash.encode("utf-8"),
                    owner_key_hash.encode("utf-8"),
                )
            }
        return tuple(sorted(sessions))

    def is_revoked(self, lease_id: str) -> bool:
        """Return ``True`` iff ``lease_id`` is currently marked revoked."""

        with self._lock, self._ledger_transaction():
            return lease_id in self._revoked

    def known_lease_ids(self) -> frozenset[str]:
        """Test helper: snapshot of every lease_id ever issued by this authority."""

        with self._lock, self._ledger_transaction():
            return frozenset(self._issued.keys())

    def _append_ledger_record(self, event_type: str, payload: dict[str, object]) -> str:
        """Append a record and return its ``record_hash``."""
        if self._ledger_path is None:
            # In-memory mode: compute a synthetic hash for receipt binding
            base = {
                "seq": self._ledger_seq,
                "event_type": event_type,
                "payload": payload,
                "prev_hash": self._ledger_prev_hash,
            }
            record_hash = _ledger_hash(base)
            self._ledger_prev_hash = record_hash
            self._ledger_seq += 1
            return record_hash
        self._ledger_path.parent.mkdir(parents=True, exist_ok=True)
        was_missing = not self._ledger_path.exists()
        base = {
            "seq": self._ledger_seq,
            "event_type": event_type,
            "payload": payload,
            "prev_hash": self._ledger_prev_hash,
        }
        record_hash = _ledger_hash(base)
        record = {
            **base,
            "record_hash": record_hash,
            "mac": _ledger_mac(self._mac_key, {**base, "record_hash": record_hash}),
        }
        with self._ledger_path.open("a", encoding="utf-8") as handle:
            os.chmod(self._ledger_path, 0o600)
            handle.write(_stable_json(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        if was_missing:
            directory_fd = os.open(self._ledger_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        self._ledger_prev_hash = record_hash
        self._ledger_seq += 1
        return record_hash

    @contextmanager
    def _ledger_transaction(self) -> Iterator[None]:
        """Serialize a state mutation across every process sharing the ledger."""

        if self._ledger_path is None:
            yield
            return
        if self._ledger_lock_depth > 0:
            self._ledger_lock_depth += 1
            try:
                yield
            finally:
                self._ledger_lock_depth -= 1
            return

        self._ledger_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self._ledger_path.with_suffix(self._ledger_path.suffix + ".lock")
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        os.fchmod(lock_fd, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            self._ledger_lock_depth = 1
            self._reload_ledger()
            yield
        finally:
            self._ledger_lock_depth = 0
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    def _reload_ledger(self) -> None:
        if self._ledger_path is None:
            return
        self._issued.clear()
        self._nonces.clear()
        self._revoked.clear()
        self._parents.clear()
        self._children.clear()
        self._ledger_prev_hash = "sha256:" + "0" * 64
        self._ledger_seq = 0
        self._load_ledger(self._ledger_path)

    def _load_ledger(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                os.fchmod(fd, 0o600)
                os.fsync(fd)
            finally:
                os.close(fd)
            return
        expected_seq = 0
        expected_prev = "sha256:" + "0" * 64
        raw_lines = path.read_bytes().splitlines(keepends=True)
        offset = 0
        for index, raw_line in enumerate(raw_lines):
            line_start = offset
            offset += len(raw_line)
            if not raw_line.strip():
                continue
            try:
                row = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                is_incomplete_eof = (
                    expected_seq > 0
                    and index == len(raw_lines) - 1
                    and not raw_line.endswith((b"\n", b"\r"))
                )
                if is_incomplete_eof:
                    self._isolate_ledger_tail(path, clean_offset=line_start)
                    break
                raise
            try:
                base = {
                    "seq": int(row["seq"]),
                    "event_type": str(row["event_type"]),
                    "payload": row["payload"],
                    "prev_hash": str(row["prev_hash"]),
                }
                if base["seq"] != expected_seq:
                    raise ValueError("lease ledger seq gap")
                if base["prev_hash"] != expected_prev:
                    raise ValueError("lease ledger prev_hash mismatch")
                record_hash = _ledger_hash(base)
                if row.get("record_hash") != record_hash:
                    raise ValueError("lease ledger record_hash mismatch")
                expected_mac = _ledger_mac(self._mac_key, {**base, "record_hash": record_hash})
                if not hmac.compare_digest(str(row.get("mac", "")), expected_mac):
                    raise ValueError("lease ledger MAC mismatch")
                self._apply_ledger_record(str(base["event_type"]), row["payload"])
            except (KeyError, TypeError, ValueError):
                raise
            expected_seq += 1
            expected_prev = record_hash
        self._ledger_seq = expected_seq
        self._ledger_prev_hash = expected_prev

    @staticmethod
    def _isolate_ledger_tail(path: Path, *, clean_offset: int) -> None:
        with path.open("rb+") as handle:
            handle.seek(clean_offset)
            tail = handle.read()
            if not tail:
                return
            corrupt_path = path.with_suffix(path.suffix + ".corrupt")
            fd = os.open(corrupt_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            try:
                os.fchmod(fd, 0o600)
                os.write(fd, tail)
                os.fsync(fd)
            finally:
                os.close(fd)
            handle.seek(clean_offset)
            handle.truncate()
            handle.flush()
            os.fsync(handle.fileno())

    def _apply_ledger_record(self, event_type: str, payload: object) -> None:
        if not isinstance(payload, dict):
            raise ValueError("lease ledger payload must be an object")
        if event_type == "issue":
            lease_payload = payload.get("lease")
            if not isinstance(lease_payload, dict):
                raise ValueError("lease issue record missing lease")
            lease = _lease_from_payload(lease_payload)
            self._issued[lease.lease_id] = lease
            self._nonces[lease.nonce] = _NonceState(
                lease_id=lease.lease_id,
                invocations_remaining=lease.max_invocations,
            )
            self._parents[lease.lease_id] = lease.parent_lease_id
            self._children.setdefault(lease.lease_id, set())
            if lease.parent_lease_id is not None:
                self._children.setdefault(lease.parent_lease_id, set()).add(lease.lease_id)
        elif event_type == "consume":
            lease_id = str(payload["lease_id"])
            lease = self._issued[lease_id]
            remaining = int(payload.get("remaining", 0))
            if remaining <= 0 and lease.max_invocations == 1:
                self._nonces.pop(lease.nonce, None)
            else:
                self._nonces[lease.nonce] = _NonceState(
                    lease_id=lease.lease_id,
                    invocations_remaining=remaining,
                )
        elif event_type == "revoke":
            self._revoked.add(str(payload["lease_id"]))
        else:
            raise ValueError(f"unknown lease ledger event_type {event_type!r}")


def _stable_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _ledger_hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()


def _ledger_mac(mac_key: bytes, value: object) -> str:
    digest = hmac.new(mac_key, digestmod=hashlib.sha256)
    digest.update(b"echo-capability-lease-ledger-v1:")
    digest.update(_stable_json(value).encode("utf-8"))
    return digest.hexdigest()


def _lease_to_payload(lease: CapabilityLease) -> dict[str, object]:
    return {
        "lease_id": lease.lease_id,
        "product_id": lease.product_id,
        "owner_key_hash": lease.owner_key_hash,
        "session_id": lease.session_id,
        "run_id": lease.run_id,
        "tool_name": lease.tool_name,
        "args_schema": lease.args_schema,
        "resource_scope": lease.resource_scope,
        "fs_roots": list(lease.fs_roots),
        "network_policy": lease.network_policy,
        "network_hosts": list(lease.network_hosts),
        "max_bytes": lease.max_bytes,
        "max_duration_ms": lease.max_duration_ms,
        "max_invocations": lease.max_invocations,
        "nonce": lease.nonce,
        "expires_at": lease.expires_at,
        "parent_lease_id": lease.parent_lease_id,
        "mac": lease.mac.hex(),
    }


def _payload_int(payload: dict[str, object], key: str) -> int:
    value = payload[key]
    if isinstance(value, int | str):
        return int(value)
    raise ValueError(f"lease payload field {key!r} must be int-compatible")


def _payload_fs_roots(payload: dict[str, object]) -> tuple[str, ...]:
    value = payload.get("fs_roots", ())
    if not isinstance(value, (list, tuple)):
        raise ValueError("lease payload field 'fs_roots' must be a list")
    return tuple(str(item) for item in value)


def _payload_network_hosts(payload: dict[str, object]) -> tuple[str, ...]:
    value = payload.get("network_hosts", ())
    if not isinstance(value, (list, tuple)):
        raise ValueError("lease payload field 'network_hosts' must be a list")
    return tuple(str(item) for item in value)


def _lease_from_payload(payload: dict[str, object]) -> CapabilityLease:
    return CapabilityLease(
        lease_id=str(payload["lease_id"]),
        product_id=str(payload.get("product_id", "")),
        owner_key_hash=str(payload["owner_key_hash"]),
        session_id=str(payload.get("session_id", "")),
        run_id=str(payload["run_id"]),
        tool_name=str(payload["tool_name"]),
        args_schema=str(payload["args_schema"]),
        resource_scope=str(payload["resource_scope"]),
        fs_roots=_payload_fs_roots(payload),
        network_policy=str(payload["network_policy"]),
        network_hosts=_payload_network_hosts(payload),
        max_bytes=_payload_int(payload, "max_bytes"),
        max_duration_ms=_payload_int(payload, "max_duration_ms"),
        max_invocations=_payload_int(payload, "max_invocations"),
        nonce=str(payload["nonce"]),
        expires_at=_payload_int(payload, "expires_at"),
        parent_lease_id=(
            str(payload["parent_lease_id"]) if payload.get("parent_lease_id") is not None else None
        ),
        mac=bytes.fromhex(str(payload["mac"])),
    )


__all__ = [
    "LeaseDenied",
    "LeaseMacInvalid",
    "LeaseExpired",
    "LeaseNonceReplay",
    "LeaseRevoked",
    "LeaseExhausted",
    "LeaseOwnerMismatch",
    "LeaseScopeMismatch",
    "LeaseToolMismatch",
    "LeaseUnknownTool",
    "LeaseParentMissing",
    "LeaseContextMismatch",
    "LeaseBindingMismatch",
    "LeaseAuthority",
    "compute_lease_mac",
    "sign_tool_execution_context",
    "DEFAULT_NETWORK_POLICY",
    "LEASE_MAC_DOMAIN",
    "TOOL_CONTEXT_MAC_DOMAIN",
]
