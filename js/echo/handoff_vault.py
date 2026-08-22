"""Trusted server-run provenance vault for R1 Batch2-B v6.

Pure leaf module: no I/O, no filesystem, no network, no env.
The only external dependencies are ``hashlib``, ``hmac``, ``secrets``,
``threading``, ``uuid``, ``base64`` and the existing ``mode_contract`` types.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import uuid
from dataclasses import dataclass
from typing import Final, cast

from js.echo.mode_contract import (
    AppMode,
    ClientTaskRequestV1,
    ResolvedTaskAuthorityV1,
    TaskRef,
)
from js.echo.primitives import canonical_json_bytes

# ruff: noqa: TC006

HANDOFF_VAULT_MAC_DOMAIN: Final = b"js-agent:handoff-vault:v1\0"

_UINT64_MAX: Final = 2**64 - 1
_MAX_REFERENCE_RETRIES: Final = 64
_VALID_STATES: Final = frozenset({"reserved", "committed", "taken", "cancelled"})


class HandoffVaultError(Exception):
    """Single public error for all vault failures."""


def _vault_error(code: str) -> HandoffVaultError:
    return HandoffVaultError(code)


def _validate_mac_key(key: object) -> bytes:
    if type(key) is not bytes or len(key) < 32:
        raise _vault_error("invalid_mac_key")
    return key


def _compute_mac(mac_key: bytes, record: object) -> bytes:
    key = _validate_mac_key(mac_key)
    payload = cast("dict[str, object]", record)
    return hmac.new(
        HANDOFF_VAULT_MAC_DOMAIN + key,
        canonical_json_bytes(payload),
        hashlib.sha256,
    ).digest()


def _record_mac_payload(
    *,
    reference: str,
    run_id: str,
    mode: AppMode,
    owner: str,
    session: str,
    workspace: str | None,
    state: str,
    expires_at_ns: int,
) -> dict[str, object]:
    return {
        "reference": reference,
        "run_id": run_id,
        "mode": mode.value,
        "owner": owner,
        "session": session,
        "workspace": workspace,
        "state": state,
        "expires_at_ns": expires_at_ns,
    }


@dataclass(frozen=True, slots=True, init=False)
class TaskBindingV1:
    mode: AppMode
    owner: str
    session: str
    workspace: str | None

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("TaskBindingV1 cannot be subclassed")

    def __init__(
        self,
        *,
        mode: AppMode,
        owner: str,
        session: str,
        workspace: str | None,
    ) -> None:
        from js.echo.mode_contract import (
            _OWNER_RE,
            _SESSION_RUN_RE,
            _validate_identity,
            _validate_workspace,
        )

        if type(mode) is not AppMode:
            raise _vault_error("invalid_request")
        validated_owner = _validate_identity(
            cast("object", owner), field="owner", pattern=_OWNER_RE, max_chars=192
        )
        validated_session = _validate_identity(
            cast("object", session), field="session", pattern=_SESSION_RUN_RE, max_chars=192
        )
        validated_workspace = _validate_workspace(cast("object", workspace), mode=mode)
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "owner", validated_owner)
        object.__setattr__(self, "session", validated_session)
        object.__setattr__(self, "workspace", validated_workspace)


@dataclass(frozen=True, slots=True, init=False)
class HandoffRecordV1:
    reference: str
    run_id: str
    binding: TaskBindingV1
    state: str
    expires_at_ns: int
    mac: bytes

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("HandoffRecordV1 cannot be subclassed")

    def __init__(
        self,
        *,
        reference: str,
        run_id: str,
        binding: TaskBindingV1,
        state: str,
        expires_at_ns: int,
        mac: bytes,
    ) -> None:
        if type(reference) is not str or not reference:
            raise _vault_error("unknown_reference")
        if type(run_id) is not str or not run_id:
            raise _vault_error("unknown_reference")
        if type(binding) is not TaskBindingV1:
            raise _vault_error("invalid_request")
        if type(state) is not str or state not in _VALID_STATES:
            raise _vault_error("unknown_state")
        if type(expires_at_ns) is not int or expires_at_ns < 0:
            raise _vault_error("invalid_clock")
        if type(mac) is not bytes or len(mac) != 32:
            raise _vault_error("mac_mismatch")
        object.__setattr__(self, "reference", reference)
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "binding", binding)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "expires_at_ns", expires_at_ns)
        object.__setattr__(self, "mac", mac)


@dataclass(frozen=True, slots=True, init=False)
class HandoffTokenV1:
    reference: str
    run_id: str

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("HandoffTokenV1 cannot be subclassed")

    def __init__(self, *, reference: str, run_id: str) -> None:
        if type(reference) is not str or not reference:
            raise _vault_error("invalid_token")
        if type(run_id) is not str or not run_id:
            raise _vault_error("invalid_token")
        object.__setattr__(self, "reference", reference)
        object.__setattr__(self, "run_id", run_id)


class HandoffVaultV1:
    """Internal trusted-run provenance vault."""

    __slots__ = ("_mac_key", "_clock", "_max_entries", "_reserve_ttl_ns",
                 "_commit_ttl_ns", "_entries", "_lock",
                 "_reference_factory", "_build_record_override")

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("HandoffVaultV1 cannot be subclassed")

    def __init__(
        self,
        *,
        mac_key: bytes,
        clock: object,
        max_entries: int,
        reserve_ttl_ns: int,
        commit_ttl_ns: int,
    ) -> None:
        key = _validate_mac_key(mac_key)
        if not callable(clock):
            raise _vault_error("invalid_clock")
        if type(max_entries) is not int or max_entries <= 0:
            raise _vault_error("invalid_request")
        if type(reserve_ttl_ns) is not int or reserve_ttl_ns <= 0 or reserve_ttl_ns > _UINT64_MAX:
            raise _vault_error("invalid_request")
        if type(commit_ttl_ns) is not int or commit_ttl_ns <= 0 or commit_ttl_ns > _UINT64_MAX:
            raise _vault_error("invalid_request")
        self._mac_key = key
        self._clock = cast("object", clock)
        self._max_entries = max_entries
        self._reserve_ttl_ns = reserve_ttl_ns
        self._commit_ttl_ns = commit_ttl_ns
        self._entries: dict[str, HandoffRecordV1] = {}
        self._lock = threading.RLock()
        self._reference_factory: object = None
        self._build_record_override: object = None

    def _now_ns(self) -> int:
        result = self._clock()  # type: ignore[operator]
        if type(result) is not int or result < 0 or result > _UINT64_MAX:
            raise _vault_error("invalid_clock")
        return result

    def _purge_expired_locked(self, now_ns: int) -> None:
        """Two-phase purge: validate all entries first, then delete expired ones.

        Phase 1 (validation): iterate a snapshot of entries. For each, verify
        that the key is a string and the value is an exact HandoffRecordV1
        with valid state and types. If any entry is unknown/forged, raise
        HandoffVaultError without modifying ``_entries``.

        Phase 2 (mutation): collect expired references and delete them.
        """
        to_remove: list[str] = []
        for key, value in tuple(self._entries.items()):
            if type(key) is not str or not key:
                raise _vault_error("unknown_state")
            if type(value) is not HandoffRecordV1:
                raise _vault_error("unknown_state")
            if type(value.state) is not str or value.state not in _VALID_STATES:
                raise _vault_error("unknown_state")
            if type(value.expires_at_ns) is not int:
                raise _vault_error("unknown_state")
            if value.expires_at_ns <= now_ns:
                to_remove.append(key)
        for key in to_remove:
            del self._entries[key]

    def _new_reference(self) -> str:
        if self._reference_factory is not None:
            return str(self._reference_factory())  # type: ignore[operator]
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")

    def _new_run_id(self) -> str:
        return str(uuid.uuid4())

    def _build_record(
        self,
        *,
        reference: str,
        run_id: str,
        binding: TaskBindingV1,
        state: str,
        expires_at_ns: int,
    ) -> HandoffRecordV1:
        if self._build_record_override is not None:
            return cast(
                "HandoffRecordV1",
                self._build_record_override(  # type: ignore[operator]
                    reference=reference,
                    run_id=run_id,
                    binding=binding,
                    state=state,
                    expires_at_ns=expires_at_ns,
                ),
            )
        payload = _record_mac_payload(
            reference=reference,
            run_id=run_id,
            mode=binding.mode,
            owner=binding.owner,
            session=binding.session,
            workspace=binding.workspace,
            state=state,
            expires_at_ns=expires_at_ns,
        )
        mac = _compute_mac(self._mac_key, payload)
        return HandoffRecordV1(
            reference=reference,
            run_id=run_id,
            binding=binding,
            state=state,
            expires_at_ns=expires_at_ns,
            mac=mac,
        )

    def _reserve_and_commit(self, binding: TaskBindingV1) -> tuple[str, str]:
        """Atomically reserve and commit in a single publish.

        All validation, reference generation, MAC computation, and record
        construction happen under the lock. The committed record is stored
        in ``_entries`` as the final step. If any exception occurs before
        that final assignment, ``_entries`` is unchanged.

        Post-publish orphan (exception between assignment and token return)
        is a bounded committed orphan cleaned by TTL.
        """
        now_ns = self._now_ns()
        if now_ns > _UINT64_MAX - self._commit_ttl_ns:
            raise _vault_error("invalid_clock")
        expires_at_ns = now_ns + self._commit_ttl_ns
        with self._lock:
            self._purge_expired_locked(now_ns)
            if len(self._entries) >= self._max_entries:
                raise _vault_error("vault_full")
            reference = self._new_reference()
            retries = 0
            while reference in self._entries:
                retries += 1
                if retries >= _MAX_REFERENCE_RETRIES:
                    raise _vault_error("reference_collision")
                reference = self._new_reference()
            run_id = self._new_run_id()
            committed_record = self._build_record(
                reference=reference,
                run_id=run_id,
                binding=binding,
                state="committed",
                expires_at_ns=expires_at_ns,
            )
            # Single publish: this is the only mutation of _entries
            self._entries[reference] = committed_record
            return reference, run_id

    def _take(self, reference: str, run_id: str) -> HandoffRecordV1:
        """Consume a committed record, verifying both reference and run_id.

        Semantics:
        - Record exists and is committed and not expired -> return and delete.
        - Record exists but expired -> delete and raise ``expired``.
        - Record exists but wrong state -> raise ``unknown_state``.
        - Record does not exist -> raise ``unknown_reference``.
        - run_id mismatch -> raise ``unknown_reference`` (no detail leak).

        The target record is checked for expiry BEFORE the general purge runs,
        so that an expired target returns ``expired`` rather than
        ``unknown_reference``.
        """
        now_ns = self._now_ns()
        with self._lock:
            record = self._entries.get(reference)
            if record is not None and record.run_id != run_id:
                raise _vault_error("unknown_reference")
            if record is not None and now_ns >= record.expires_at_ns:
                del self._entries[reference]
                raise _vault_error("expired")
            self._purge_expired_locked(now_ns)
            if record is None:
                raise _vault_error("unknown_reference")
            if record.state != "committed":
                raise _vault_error("unknown_state")
            payload = _record_mac_payload(
                reference=record.reference,
                run_id=record.run_id,
                mode=record.binding.mode,
                owner=record.binding.owner,
                session=record.binding.session,
                workspace=record.binding.workspace,
                state=record.state,
                expires_at_ns=record.expires_at_ns,
            )
            expected_mac = _compute_mac(self._mac_key, payload)
            if not hmac.compare_digest(expected_mac, record.mac):
                del self._entries[reference]
                raise _vault_error("mac_mismatch")
            del self._entries[reference]
            return record

    # -- Internal test/recovery interfaces (not for normal issue path) --

    def _reserve(self, binding: TaskBindingV1) -> tuple[str, str]:
        """Internal test/recovery interface. Not used by normal issue path."""
        now_ns = self._now_ns()
        if now_ns > _UINT64_MAX - self._reserve_ttl_ns:
            raise _vault_error("invalid_clock")
        expires_at_ns = now_ns + self._reserve_ttl_ns
        with self._lock:
            self._purge_expired_locked(now_ns)
            if len(self._entries) >= self._max_entries:
                raise _vault_error("vault_full")
            reference = self._new_reference()
            retries = 0
            while reference in self._entries:
                retries += 1
                if retries >= _MAX_REFERENCE_RETRIES:
                    raise _vault_error("reference_collision")
                reference = self._new_reference()
            run_id = self._new_run_id()
            record = self._build_record(
                reference=reference,
                run_id=run_id,
                binding=binding,
                state="reserved",
                expires_at_ns=expires_at_ns,
            )
            self._entries[reference] = record
            return reference, run_id

    def _commit(self, reference: str, binding: TaskBindingV1, run_id: str) -> None:
        """Internal test/recovery interface. Not used by normal issue path."""
        now_ns = self._now_ns()
        if now_ns > _UINT64_MAX - self._commit_ttl_ns:
            raise _vault_error("invalid_clock")
        expires_at_ns = now_ns + self._commit_ttl_ns
        with self._lock:
            self._purge_expired_locked(now_ns)
            record = self._entries.get(reference)
            if record is None:
                raise _vault_error("unknown_reference")
            if record.state != "reserved":
                raise _vault_error("unknown_state")
            new_record = self._build_record(
                reference=reference,
                run_id=run_id,
                binding=binding,
                state="committed",
                expires_at_ns=expires_at_ns,
            )
            self._entries[reference] = new_record


def issue_server_run_v1(
    *,
    request: ClientTaskRequestV1,
    authority: ResolvedTaskAuthorityV1,
    vault: HandoffVaultV1,
) -> HandoffTokenV1:
    if type(request) is not ClientTaskRequestV1:
        raise _vault_error("invalid_request")
    if type(authority) is not ResolvedTaskAuthorityV1:
        raise _vault_error("invalid_authority")
    if type(vault) is not HandoffVaultV1:
        raise _vault_error("invalid_vault")
    if request.mode is not authority.mode:
        raise _vault_error("mode_conflict")
    if request.session is not None and request.session != authority.session:
        raise _vault_error("session_conflict")
    if request.workspace != authority.workspace:
        raise _vault_error("workspace_conflict")
    binding = TaskBindingV1(
        mode=authority.mode,
        owner=authority.mode_runtime_owner,
        session=authority.session,
        workspace=authority.workspace,
    )
    reference, run_id = vault._reserve_and_commit(binding)
    return HandoffTokenV1(reference=reference, run_id=run_id)


def consume_handoff_token_v1(
    *,
    token: HandoffTokenV1,
    vault: HandoffVaultV1,
) -> TaskRef:
    if type(token) is not HandoffTokenV1:
        raise _vault_error("invalid_token")
    if type(vault) is not HandoffVaultV1:
        raise _vault_error("invalid_vault")
    record = vault._take(token.reference, token.run_id)
    return TaskRef(
        mode=record.binding.mode,
        owner=record.binding.owner,
        session=record.binding.session,
        run=record.run_id,
        workspace=record.binding.workspace,
    )
