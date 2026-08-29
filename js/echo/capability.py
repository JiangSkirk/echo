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
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.echo.capability_constants import (
    DEFAULT_CLEARANCE,
    DEFAULT_NETWORK_POLICY,
    DEFAULT_SANDBOX_PROFILE,
    DEFAULT_TAINT_FLOOR,
    DEFAULT_TAINT_SINK,
    LEASE_MAC_DOMAIN,
    LEASE_MAC_PREFIX,
    LEASE_MAC_PREFIX_V2,
    TOOL_CONTEXT_MAC_DOMAIN,
)
from js.echo.capability_encoding import (
    _canonical_lease_payload as _canonical_lease_payload,
)
from js.echo.capability_encoding import (
    _lease_v2_fields_nondefault,
    _tool_context_payload,
    compute_lease_mac,
    lease_mac_tag,
)
from js.echo.capability_exceptions import (
    EchoAnchorUnavailable,
    LeaseBindingMismatch,
    LeaseContextMismatch,
    LeaseDenied,
    LeaseExhausted,
    LeaseExpired,
    LeaseMacInvalid,
    LeaseNonceReplay,
    LeaseOwnerMismatch,
    LeaseParentMissing,
    LeaseRevoked,
    LeaseScopeMismatch,
    LeaseToolMismatch,
    LeaseUnknownTool,
)
from js.echo.capability_exceptions import (
    LeaseConsumeReceipt as LeaseConsumeReceipt,
)
from js.echo.types import CapabilityLease


def sign_tool_execution_context(
    context: Any,
    *,
    lease: CapabilityLease,
    authority: Any = None,
    now: int | None = None,
) -> Any:
    """Return ``context`` with an Echo registry signature attached.

    ``authority`` may be the in-process :class:`LeaseAuthority` (which
    holds the MAC key and signs locally) or an Orin IPC handle exposing
    ``sign_execution_context(context, lease, now)`` — the handle path
    never touches a local key: the signature was produced by orind at
    issue time. Any other object fails closed.
    """

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
    signed = dataclasses.replace(
        context,
        lease_id=lease.lease_id,
        lease_mac=lease.mac.hex(),
        signature="",
    )
    remote_sign = getattr(authority, "sign_execution_context", None)
    if callable(remote_sign) and type(authority) is not LeaseAuthority:
        # Orin IPC handle: the signature was produced by orind at issue
        # time; the main process holds no MAC key to sign locally.
        effective_now = now if now is not None else int(time.time() * 1000)
        signature = remote_sign(signed, lease, effective_now)
        return dataclasses.replace(signed, signature=str(signature))
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
    mac = hmac.new(
        authority._context_signing_key(),
        _tool_context_payload(signed),
        hashlib.sha256,
    ).hexdigest()
    return dataclasses.replace(signed, signature=f"authority-hmac-sha256:{mac}")


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
        "_ledger_disk_fp",
        "_ledger_full_reloads",
        "_compact_skip_reason",
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
        self._ledger_disk_fp: tuple[int, int, int] | None = None
        self._ledger_full_reloads = 0
        self._compact_skip_reason = "never"
        if self._ledger_path is not None:
            with self._ledger_transaction():
                pass
            self._verify_local_tip_seal()

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
        taint_floor: int = DEFAULT_TAINT_FLOOR,
        taint_sink: int = DEFAULT_TAINT_SINK,
        sandbox_profile: int = DEFAULT_SANDBOX_PROFILE,
        clearance: int = DEFAULT_CLEARANCE,
    ) -> CapabilityLease:
        """Issue a fresh :class:`CapabilityLease` and register its bookkeeping.

        The Orin v2 extension kwargs (``taint_floor`` / ``taint_sink`` /
        ``sandbox_profile`` / ``clearance``) default to the D-appendix-D.2
        values; all-default keeps the legacy MAC pre-image byte-for-byte.

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
                owner_matches = len(parent.owner_key_hash) == len(
                    owner_key_hash
                ) and hmac.compare_digest(
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
                taint_floor=int(taint_floor),
                taint_sink=int(taint_sink),
                sandbox_profile=int(sandbox_profile),
                clearance=int(clearance),
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
        if (
            type(now) is not int
            or type(expected_max_bytes) is not int
            or type(expected_max_duration_ms) is not int
        ):
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
            raise EchoAnchorUnavailable("echo anchor authority is unavailable") from exc
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
            raise LeaseBindingMismatch(
                f"selected lease {root_id!r} is missing from authority ledger"
            )
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

    def compact(self) -> str:
        """Snapshot lease state and retain only a replay tail.

        The Echo turn journal already has ``Journal.compact()``; this is the
        lease-ledger counterpart. Snapshot hash is written into the local
        tip seal. This is not an external anchor.
        """

        with self._lock, self._ledger_transaction():
            snapshot_hash = self._compact_locked()
            self._compact_skip_reason = ""
            return snapshot_hash

    def ledger_stats(self) -> dict[str, int | str]:
        """Read-only lease-ledger counters for governor scheduling and metrics."""

        with self._lock:
            path = self._ledger_path
            size = 0
            if path is not None and path.exists():
                try:
                    size = int(path.stat().st_size)
                except OSError:
                    size = 0
            return {
                "records": int(self._ledger_seq),
                "bytes": size,
                "full_reloads": int(self._ledger_full_reloads),
                "tip": str(self._ledger_prev_hash),
                "compact_skip_reason": str(self._compact_skip_reason),
            }

    def maybe_compact(
        self,
        *,
        trigger_records: int = 512,
        trigger_bytes: int = 256 * 1024,
        trigger_full_reloads: int = 8,
    ) -> str | None:
        """Compact when any configured threshold is crossed. Return skip reason via stats."""

        if trigger_records < 1 or trigger_bytes < 1 or trigger_full_reloads < 1:
            raise ValueError("lease compact triggers must be >= 1")
        with self._lock, self._ledger_transaction():
            if self._ledger_path is None:
                self._compact_skip_reason = "no_ledger_path"
                return None
            try:
                size = int(self._ledger_path.stat().st_size) if self._ledger_path.exists() else 0
            except OSError:
                self._compact_skip_reason = "stat_failed"
                return None
            if (
                self._ledger_seq < trigger_records
                and size < trigger_bytes
                and self._ledger_full_reloads < trigger_full_reloads
            ):
                self._compact_skip_reason = "below_threshold"
                return None
            snapshot_hash = self._compact_locked()
            self._compact_skip_reason = ""
            return snapshot_hash

    def _snapshot_path(self) -> Path | None:
        if self._ledger_path is None:
            return None
        return self._ledger_path.with_name(self._ledger_path.name + ".snapshot")

    def _build_snapshot(self) -> dict[str, object]:
        children = {parent: sorted(child_ids) for parent, child_ids in self._children.items()}
        return {
            "version": 1,
            "seq": self._ledger_seq,
            "prev_hash": self._ledger_prev_hash,
            "issued": [_lease_to_payload(lease) for lease in self._issued.values()],
            "nonces": [
                {
                    "nonce": nonce,
                    "lease_id": state.lease_id,
                    "invocations_remaining": state.invocations_remaining,
                }
                for nonce, state in self._nonces.items()
            ],
            "revoked": sorted(self._revoked),
            "parents": dict(self._parents),
            "children": children,
        }

    def _apply_snapshot(self, snapshot: dict[str, object]) -> None:
        issued_rows = snapshot.get("issued")
        if not isinstance(issued_rows, list):
            raise ValueError("lease snapshot issued must be a list")
        issued: dict[str, CapabilityLease] = {}
        for row in issued_rows:
            if not isinstance(row, dict):
                raise ValueError("lease snapshot issued entry must be an object")
            lease = _lease_from_payload(row)
            issued[lease.lease_id] = lease
        self._issued = issued
        nonce_rows = snapshot.get("nonces")
        if not isinstance(nonce_rows, list):
            raise ValueError("lease snapshot nonces must be a list")
        self._nonces = {}
        for row in nonce_rows:
            if not isinstance(row, dict):
                raise ValueError("lease snapshot nonce must be an object")
            self._nonces[str(row["nonce"])] = _NonceState(
                lease_id=str(row["lease_id"]),
                invocations_remaining=int(row["invocations_remaining"]),
            )
        revoked = snapshot.get("revoked")
        if not isinstance(revoked, list):
            raise ValueError("lease snapshot revoked must be a list")
        self._revoked = {str(item) for item in revoked}
        parents = snapshot.get("parents")
        if not isinstance(parents, dict):
            raise ValueError("lease snapshot parents must be an object")
        self._parents = {
            str(lease_id): (None if parent is None else str(parent))
            for lease_id, parent in parents.items()
        }
        children = snapshot.get("children")
        if not isinstance(children, dict):
            raise ValueError("lease snapshot children must be an object")
        self._children = {
            str(parent): {str(child) for child in (child_ids or [])}
            for parent, child_ids in children.items()
        }
        self._ledger_seq = int(str(snapshot["seq"]))
        self._ledger_prev_hash = str(snapshot["prev_hash"])

    def _load_snapshot(self, path: Path) -> None:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("lease snapshot is not an object")
        snapshot = raw.get("snapshot")
        record_hash = raw.get("record_hash")
        mac = raw.get("mac")
        if not isinstance(snapshot, dict):
            raise ValueError("lease snapshot payload missing")
        expected_hash = _ledger_hash(snapshot)
        if record_hash != expected_hash:
            raise ValueError("lease snapshot hash mismatch")
        expected_mac = _ledger_mac(
            self._mac_key, {"snapshot": snapshot, "record_hash": record_hash}
        )
        if not hmac.compare_digest(str(mac or ""), expected_mac):
            raise ValueError("lease snapshot MAC mismatch")
        self._apply_snapshot(snapshot)

    def _write_snapshot(self, snapshot: dict[str, object]) -> str:
        path = self._snapshot_path()
        if path is None:
            raise ValueError("lease compaction requires a ledger_path")
        record_hash = _ledger_hash(snapshot)
        record = {
            "snapshot": snapshot,
            "record_hash": record_hash,
            "mac": _ledger_mac(self._mac_key, {"snapshot": snapshot, "record_hash": record_hash}),
        }
        encoded = _stable_json(record) + "\n"
        temp_path = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
        fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, path)
            os.chmod(path, 0o600)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
        return str(record_hash)

    def _compact_locked(self) -> str:
        if self._ledger_path is None:
            raise ValueError("lease compaction requires a ledger_path")
        snapshot = self._build_snapshot()
        snapshot_hash = self._write_snapshot(snapshot)
        fd = os.open(self._ledger_path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.ftruncate(fd, 0)
            os.fsync(fd)
        finally:
            os.close(fd)
        self._capture_ledger_fp()
        from js.echo.ledger.tip_seal import bump_seal, seal_path_for

        bump_seal(
            seal_path_for(self._ledger_path),
            self._mac_key,
            new_tip=self._ledger_prev_hash,
            lease_snapshot_hash=snapshot_hash,
        )
        return snapshot_hash

    def _refresh_local_tip_seal_if_present(self) -> None:
        if self._ledger_path is None:
            return
        from js.echo.ledger.tip_seal import load_seal, refresh_seal_tip, seal_path_for

        path = seal_path_for(self._ledger_path)
        if load_seal(path, self._mac_key) is None:
            return
        snapshot_path = self._snapshot_path()
        snapshot_hash = ""
        if snapshot_path is not None and snapshot_path.exists():
            snapshot_hash = str(
                json.loads(snapshot_path.read_text(encoding="utf-8")).get("record_hash") or ""
            )
        refresh_seal_tip(
            path,
            self._mac_key,
            new_tip=self._ledger_prev_hash,
            lease_snapshot_hash=snapshot_hash,
        )

    def _verify_local_tip_seal(self) -> None:
        if self._ledger_path is None:
            return
        from js.echo.ledger.tip_seal import load_seal, seal_path_for, verify_current_tip

        path = seal_path_for(self._ledger_path)
        sealed = load_seal(path, self._mac_key)
        if sealed is None:
            return
        snapshot_path = self._snapshot_path()
        snapshot_hash = ""
        if snapshot_path is not None and snapshot_path.exists():
            raw = json.loads(snapshot_path.read_text(encoding="utf-8"))
            snapshot_hash = str(raw.get("record_hash") or "")
        if sealed.lease_snapshot_hash and snapshot_hash != sealed.lease_snapshot_hash:
            raise ValueError("local tip seal rejected a lease snapshot mismatch")
        ancestors = [self._ledger_prev_hash, "sha256:" + "0" * 64]
        if snapshot_path is not None and snapshot_path.exists():
            ancestors.append(
                str(
                    json.loads(snapshot_path.read_text(encoding="utf-8"))
                    .get("snapshot", {})
                    .get("prev_hash")
                    or ""
                )
            )
        verify_current_tip(
            sealed=sealed,
            current_tip=self._ledger_prev_hash,
            known_tips=tuple(item for item in ancestors if item),
        )

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
        self._capture_ledger_fp()
        self._refresh_local_tip_seal_if_present()
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

    def _ledger_stat_fp(self) -> tuple[int, int, int] | None:
        path = self._ledger_path
        if path is None:
            return None
        try:
            st = os.lstat(path)
        except OSError:
            return None
        return (int(st.st_ino), int(st.st_size), int(st.st_mtime_ns))

    def _capture_ledger_fp(self) -> None:
        self._ledger_disk_fp = self._ledger_stat_fp()

    def _reload_ledger(self) -> None:
        if self._ledger_path is None:
            return
        current = self._ledger_stat_fp()
        cached = self._ledger_disk_fp
        if current is not None and cached is not None and current == cached:
            return
        if (
            current is not None
            and cached is not None
            and current[0] == cached[0]
            and current[1] > cached[1]
            and self._apply_ledger_tail(start_offset=cached[1])
        ):
            self._capture_ledger_fp()
            return
        self._full_reload_ledger()

    def _full_reload_ledger(self) -> None:
        self._ledger_full_reloads += 1
        self._issued.clear()
        self._nonces.clear()
        self._revoked.clear()
        self._parents.clear()
        self._children.clear()
        self._ledger_prev_hash = "sha256:" + "0" * 64
        self._ledger_seq = 0
        if self._ledger_path is None:
            return
        self._load_ledger(self._ledger_path)
        self._capture_ledger_fp()

    def _apply_ledger_tail(self, *, start_offset: int) -> bool:
        path = self._ledger_path
        if path is None or start_offset < 0 or not path.exists():
            return False
        try:
            with path.open("rb") as handle:
                if start_offset > 0:
                    handle.seek(start_offset - 1)
                    if handle.read(1) != b"\n":
                        return False
                handle.seek(start_offset)
                raw = handle.read()
        except OSError:
            return False
        if not raw:
            return True
        try:
            seq, prev = self._ingest_ledger_lines(
                path,
                raw.splitlines(keepends=True),
                expected_seq=self._ledger_seq,
                expected_prev=self._ledger_prev_hash,
                start_file_offset=start_offset,
            )
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        self._ledger_seq = seq
        self._ledger_prev_hash = prev
        return True

    def _load_ledger(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path = self._snapshot_path()
        if snapshot_path is not None and snapshot_path.exists():
            self._load_snapshot(snapshot_path)
            if not path.exists():
                fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
                try:
                    os.fchmod(fd, 0o600)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                return
            seq, prev = self._ingest_ledger_lines(
                path,
                path.read_bytes().splitlines(keepends=True),
                expected_seq=self._ledger_seq,
                expected_prev=self._ledger_prev_hash,
                start_file_offset=0,
            )
            self._ledger_seq = seq
            self._ledger_prev_hash = prev
            return
        if not path.exists():
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                os.fchmod(fd, 0o600)
                os.fsync(fd)
            finally:
                os.close(fd)
            return
        seq, prev = self._ingest_ledger_lines(
            path,
            path.read_bytes().splitlines(keepends=True),
            expected_seq=0,
            expected_prev="sha256:" + "0" * 64,
            start_file_offset=0,
        )
        self._ledger_seq = seq
        self._ledger_prev_hash = prev

    def _ingest_ledger_lines(
        self,
        path: Path,
        raw_lines: list[bytes],
        *,
        expected_seq: int,
        expected_prev: str,
        start_file_offset: int,
    ) -> tuple[int, str]:
        offset = start_file_offset
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
        return expected_seq, expected_prev

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


def is_lease_authority_handle(obj: object) -> bool:
    """Return True for the in-process authority or a remote consume handle.

    ``orind`` holds the MAC key, so the main-process IPC adapter cannot be
    ``LeaseAuthority`` itself. Accept the exact in-process class, or any
    other object that exposes ``verify_bound`` and ``consume_bound``.

    ``LeaseAuthority`` subclasses are rejected: they can override
    verification while still looking like the TCB class.
    """

    if type(obj) is LeaseAuthority:
        return True
    if isinstance(obj, LeaseAuthority):
        return False
    return callable(getattr(obj, "verify_bound", None)) and callable(
        getattr(obj, "consume_bound", None)
    )


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
    payload: dict[str, object] = {
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
    # Orin v2 extension: serialize only when non-default so default-field
    # leases produce ledger records byte-identical to pre-Orin ones.
    if _lease_v2_fields_nondefault(lease):
        payload["taint_floor"] = lease.taint_floor
        payload["taint_sink"] = lease.taint_sink
        payload["sandbox_profile"] = lease.sandbox_profile
        payload["clearance"] = lease.clearance
    return payload


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
        taint_floor=_payload_int(payload, "taint_floor")
        if "taint_floor" in payload
        else DEFAULT_TAINT_FLOOR,
        taint_sink=_payload_int(payload, "taint_sink")
        if "taint_sink" in payload
        else DEFAULT_TAINT_SINK,
        sandbox_profile=(
            _payload_int(payload, "sandbox_profile")
            if "sandbox_profile" in payload
            else DEFAULT_SANDBOX_PROFILE
        ),
        clearance=_payload_int(payload, "clearance")
        if "clearance" in payload
        else DEFAULT_CLEARANCE,
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
    "LeaseConsumeReceipt",
    "LeaseAuthority",
    "is_lease_authority_handle",
    "compute_lease_mac",
    "sign_tool_execution_context",
    "DEFAULT_NETWORK_POLICY",
    "DEFAULT_CLEARANCE",
    "DEFAULT_SANDBOX_PROFILE",
    "DEFAULT_TAINT_FLOOR",
    "DEFAULT_TAINT_SINK",
    "LEASE_MAC_DOMAIN",
    "LEASE_MAC_PREFIX",
    "LEASE_MAC_PREFIX_V2",
    "TOOL_CONTEXT_MAC_DOMAIN",
    "lease_mac_tag",
]
