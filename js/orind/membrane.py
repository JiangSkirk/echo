"""Durable commit membrane for irreversible Stage-B effects.

The membrane deliberately persists only authority metadata (identifiers,
digests, destination handles, counters, and reconciliation state).  Effect
packages and effect content remain on the authenticated Cell socket and are
never copied into this database.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, cast
from uuid import uuid4

from js.orin.draft import CommitPermit
from js.orin.protocol import RATE_LIMIT_BURST, RATE_LIMIT_PER_SECOND, SERVER_QUEUE_DEPTH
from js.orind.private_paths import (
    PrivatePathError,
    PrivateSQLiteGuard,
    install_sqlite_guard,
    prepare_private_sqlite,
)
from js.orind.store import OrinStore

_BUSY_TIMEOUT_MS: Final[int] = 5_000
_PERMIT_TTL_MS: Final[int] = 60_000
_SIDE_EFFECT_CLASSES: Final[frozenset[str]] = frozenset({"R0", "R1", "R2", "R3"})
_SAFE_RESULT_BYTES: Final[int] = 16 * 1024
_ADMISSION_SCOPE_CAP: Final[int] = SERVER_QUEUE_DEPTH * 4

type _AdmissionScope = tuple[str, str]
type _AdmissionScopes = tuple[
    _AdmissionScope,
    _AdmissionScope,
    _AdmissionScope,
    _AdmissionScope,
]


class MembraneError(RuntimeError):
    """Base class for fail-closed membrane errors."""


class MembraneDisabled(MembraneError):  # noqa: N818 - public protocol name
    """Raised when strong commit semantics are disabled."""


class OperationConflict(MembraneError):  # noqa: N818 - public protocol name
    """Raised when an operation or active draft identity is reused."""


class OperationNotFound(MembraneError):  # noqa: N818 - public protocol name
    """Raised when an operation id is unknown."""


class InvalidTransition(MembraneError):  # noqa: N818 - public protocol name
    """Raised when an operation attempts an illegal state edge."""


class BudgetExhausted(MembraneError):  # noqa: N818 - public protocol name
    """Raised when reserving the operation would exceed its owner budget."""


class ExportPassUnavailable(MembraneError):  # noqa: N818 - public protocol name
    """Raised when no live, exact ExportPass can authorize an egress."""


class ExactApprovalUnavailable(MembraneError):  # noqa: N818 - public protocol name
    """Raised when no live exact approval can authorize a Personal file commit."""


class AdmissionBackpressure(MembraneError):  # noqa: N818 - public protocol name
    """Raised when a membrane authority key exceeds its rate or queue bound."""

    def __init__(self, reason: str, *, retry_after_ms: int = 0) -> None:
        super().__init__(reason)
        self.reason = reason
        self.retry_after_ms = retry_after_ms


class CommitState(StrEnum):
    PROPOSED = "PROPOSED"
    DENIED = "DENIED"
    PREFLIGHTED = "PREFLIGHTED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    PREPARED = "PREPARED"
    COMMITTING = "COMMITTING"
    COMMITTED = "COMMITTED"
    UNKNOWN_COMMIT = "UNKNOWN_COMMIT"
    RECEIPTED = "RECEIPTED"


@dataclass(frozen=True, slots=True)
class OperationSpec:
    """Content-free authority identity for one commit attempt."""

    operation_id: str
    draft_id: str
    task_id: str
    owner_key_hash: str
    session_id: str
    effect_type: str
    executor_id: str
    side_effect_class: str
    canonical_effect_hash: str
    witness_id: str
    intent_id: str
    profile: str
    destinations: tuple[str, ...]
    bytes_out: int
    idempotency_key: str
    directory_handle_id: str = ""

    def __post_init__(self) -> None:
        bounded = {
            "operation_id": self.operation_id,
            "draft_id": self.draft_id,
            "task_id": self.task_id,
            "owner_key_hash": self.owner_key_hash,
            "session_id": self.session_id,
            "effect_type": self.effect_type,
            "executor_id": self.executor_id,
            "side_effect_class": self.side_effect_class,
            "witness_id": self.witness_id,
            "intent_id": self.intent_id,
            "profile": self.profile,
            "idempotency_key": self.idempotency_key,
        }
        for name, value in bounded.items():
            if not isinstance(value, str) or not value or len(value) > 512:
                raise ValueError(f"{name} must be a bounded non-empty string")
        prefixes = {
            "operation_id": (self.operation_id, "operation:"),
            "draft_id": (self.draft_id, "draft:"),
            "witness_id": (self.witness_id, "state:"),
            "intent_id": (self.intent_id, "intent:"),
        }
        for name, (value, prefix) in prefixes.items():
            if not value.startswith(prefix):
                raise ValueError(f"{name} must start with {prefix!r}")
        if not self.executor_id.startswith(("cell.", "cell:")):
            raise ValueError("executor_id must name a Cell")
        if self.side_effect_class not in _SIDE_EFFECT_CLASSES:
            raise ValueError("side_effect_class must be one of R0, R1, R2, or R3")
        _validate_sha256(self.owner_key_hash, "owner_key_hash")
        _validate_sha256(self.canonical_effect_hash, "canonical_effect_hash")
        if isinstance(self.bytes_out, bool) or not isinstance(self.bytes_out, int):
            raise ValueError("bytes_out must be an integer")
        if self.bytes_out < 0:
            raise ValueError("bytes_out must be non-negative")
        if not isinstance(self.destinations, tuple):
            raise ValueError("destinations must be a tuple")
        if len(self.destinations) > 32:
            raise ValueError("destinations must contain at most 32 handles")
        if any(
            not isinstance(destination, str)
            or not destination
            or len(destination) > 512
            for destination in self.destinations
        ):
            raise ValueError("destinations must be bounded non-empty strings")
        if len(set(self.destinations)) != len(self.destinations):
            raise ValueError("destinations must not contain duplicates")
        if tuple(sorted(self.destinations)) != self.destinations:
            raise ValueError("destinations must use canonical sorted order")
        if self.directory_handle_id and not _is_directory_handle_id(
            self.directory_handle_id
        ):
            raise ValueError("directory_handle_id must be a canonical DirectoryHandle id")


@dataclass(frozen=True, slots=True)
class OperationSnapshot:
    """Durable, content-free view of one membrane operation."""

    operation_id: str
    draft_id: str
    task_id: str
    owner_key_hash: str
    session_id: str
    effect_type: str
    executor_id: str
    side_effect_class: str
    canonical_effect_hash: str
    witness_id: str
    intent_id: str
    profile: str
    destinations: tuple[str, ...]
    bytes_out: int
    idempotency_key: str
    directory_handle_id: str
    state: CommitState
    permit_id: str = ""
    permit_sequence: int = 0
    permit_not_before_ms: int = 0
    permit_expires_at_ms: int = 0
    budget_sequence: int = 0
    attempt_count: int = 0
    export_pass_id: str = ""
    export_pass_claimed: bool = False
    exact_approval_id: str = ""
    exact_approval_claimed: bool = False
    remote_operation_id: str = ""
    receipt_id: str = ""
    safe_result_digest: str = ""
    last_error: str = ""
    reconciliation_status: str = ""
    created_at_ms: int = 0
    updated_at_ms: int = 0
    _safe_result_json: str = field(default="{}", repr=False)

    @property
    def safe_result(self) -> dict[str, Any]:
        """Return a fresh copy of the strictly bounded replay projection."""

        raw = json.loads(self._safe_result_json)
        if not isinstance(raw, dict):
            raise MembraneError("stored safe result is invalid")
        return cast("dict[str, Any]", raw)

    def to_commit_permit(self) -> CommitPermit:
        """Reconstruct the exact Cell-only permit persisted for this attempt."""

        if self.state not in {
            CommitState.PREPARED,
            CommitState.COMMITTING,
            CommitState.UNKNOWN_COMMIT,
            CommitState.COMMITTED,
            CommitState.RECEIPTED,
        }:
            raise InvalidTransition("operation has no commit permit")
        if not self.permit_id or self.permit_sequence < 1:
            raise InvalidTransition("operation has no durable commit permit")
        return CommitPermit(
            permit_id=self.permit_id,
            intent_id=self.intent_id,
            draft_id=self.draft_id,
            state_witness_id=self.witness_id,
            executor_id=self.executor_id,
            canonical_effect_hash=self.canonical_effect_hash,
            idempotency_key=self.idempotency_key,
            sequence=self.permit_sequence,
            not_before_ms=self.permit_not_before_ms,
            expires_at_ms=self.permit_expires_at_ms,
        )


@dataclass(frozen=True, slots=True)
class AdmissionTicket:
    """Opaque, one-use accounting ticket returned by :meth:`admit`."""

    ticket_id: str
    owner_key_hash: str
    session_id: str
    task_id: str
    side_effect_class: str


@dataclass(slots=True)
class _AdmissionState:
    tokens: float
    last_refill: float
    outstanding: int = 0


_MEMBRANE_SCHEMA: Final[str] = """
CREATE TABLE IF NOT EXISTS commit_operations (
    ordinal INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL UNIQUE,
    draft_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    owner_key_hash TEXT NOT NULL,
    session_id TEXT NOT NULL,
    effect_type TEXT NOT NULL,
    executor_id TEXT NOT NULL,
    side_effect_class TEXT NOT NULL,
    canonical_effect_hash TEXT NOT NULL,
    witness_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    profile TEXT NOT NULL,
    destinations_json TEXT NOT NULL,
    bytes_out INTEGER NOT NULL,
    idempotency_key TEXT NOT NULL,
    directory_handle_id TEXT NOT NULL DEFAULT '',
    spec_fingerprint TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'PROPOSED', 'DENIED', 'PREFLIGHTED', 'APPROVAL_PENDING',
        'PREPARED', 'COMMITTING', 'COMMITTED', 'UNKNOWN_COMMIT', 'RECEIPTED'
    )),
    permit_id TEXT NOT NULL DEFAULT '',
    permit_sequence INTEGER NOT NULL DEFAULT 0,
    permit_not_before_ms INTEGER NOT NULL DEFAULT 0,
    permit_expires_at_ms INTEGER NOT NULL DEFAULT 0,
    budget_sequence INTEGER NOT NULL DEFAULT 0,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    export_pass_id TEXT NOT NULL DEFAULT '',
    export_pass_claimed INTEGER NOT NULL DEFAULT 0 CHECK (export_pass_claimed IN (0, 1)),
    exact_approval_id TEXT NOT NULL DEFAULT '',
    exact_approval_claimed INTEGER NOT NULL DEFAULT 0 CHECK (exact_approval_claimed IN (0, 1)),
    remote_operation_id TEXT NOT NULL DEFAULT '',
    receipt_id TEXT NOT NULL DEFAULT '',
    safe_result_json TEXT NOT NULL DEFAULT '{}',
    safe_result_digest TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    reconciliation_status TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_commit_operations_draft
ON commit_operations(draft_id, ordinal);
CREATE INDEX IF NOT EXISTS idx_commit_operations_state
ON commit_operations(state, ordinal);
CREATE UNIQUE INDEX IF NOT EXISTS idx_commit_operations_active_draft
ON commit_operations(draft_id)
WHERE state NOT IN ('DENIED', 'RECEIPTED');
"""


class CommitMembrane:
    """Single SQLite transaction boundary for Stage-B irreversible effects."""

    def __init__(
        self,
        db_path: Path,
        *,
        enabled: bool = True,
        strict_paths: bool = False,
        now_fn: Callable[[], int] | None = None,
        monotonic_fn: Callable[[], float] | None = None,
    ) -> None:
        self.enabled = bool(enabled)
        self.strong_commit_guarantees = self.enabled
        self.supports_unknown_commit = self.enabled
        self._db_path = Path(db_path)
        self._now_fn = now_fn or (lambda: int(time.time() * 1000))
        self._monotonic_fn = monotonic_fn or time.monotonic
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._path_guard: PrivateSQLiteGuard | None = None
        self._admission_states: dict[_AdmissionScope, _AdmissionState] = {}
        self._admission_tickets: dict[str, _AdmissionScopes] = {}
        self._admission_outstanding = 0
        if not self.enabled:
            return

        # Bootstrap the existing Orin tables on the exact same database.  The
        # temporary store connection is closed before the membrane opens its
        # FULL-synchronous authority connection.
        store = OrinStore(self._db_path, strict_paths=strict_paths)
        store.close()
        if strict_paths:
            self._path_guard = prepare_private_sqlite(self._db_path)
        connection = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
            isolation_level=None,
        )
        if self._path_guard is not None:
            self._path_guard.verify()
            install_sqlite_guard(connection, self._path_guard)
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript(_MEMBRANE_SCHEMA)
        _ensure_operation_columns(connection)
        restart_now = self._now_fn()
        if (
            isinstance(restart_now, bool)
            or not isinstance(restart_now, int)
            or restart_now <= 0
        ):
            connection.close()
            raise ValueError("now_fn must return a positive integer millisecond timestamp")
        # Once the authority process has restarted, an old COMMITTING row is
        # necessarily ambiguous: dispatch may have happened before the crash.
        # Persist UNKNOWN before exposing the membrane to callers so no code
        # can mistake it for a safe-to-retry PREPARED operation.
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "UPDATE commit_operations SET state = ?,"
                " last_error = CASE WHEN last_error = '' THEN ? ELSE last_error END,"
                " updated_at_ms = ? WHERE state = ?",
                (
                    CommitState.UNKNOWN_COMMIT.value,
                    "authority restarted while commit was in flight",
                    restart_now,
                    CommitState.COMMITTING.value,
                ),
            )
        except BaseException:
            connection.rollback()
            connection.close()
            raise
        else:
            connection.commit()
        if self._path_guard is not None:
            self._path_guard.verify()
        self._conn = connection

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
            self._admission_tickets.clear()
            self._admission_states.clear()
            self._admission_outstanding = 0

    def admit(self, spec: OperationSpec) -> AdmissionTicket:
        """Non-blockingly admit one operation under its full authority key.

        Admission is process-local by design: durable authorization remains in
        SQLite, while this layer bounds instantaneous work without persisting
        requests or effect content.  Callers must release the returned ticket
        in a ``finally`` block.
        """

        self._require_enabled()
        if not isinstance(spec, OperationSpec):
            raise TypeError("spec must be an OperationSpec")
        scopes = _admission_scopes(spec)
        with self._lock:
            self._connection()
            if self._admission_outstanding >= SERVER_QUEUE_DEPTH:
                raise AdmissionBackpressure("membrane queue is full")
            now = self._monotonic()
            self._prune_admission_states(now)
            missing = sum(scope not in self._admission_states for scope in scopes)
            if len(self._admission_states) + missing > _ADMISSION_SCOPE_CAP:
                raise AdmissionBackpressure("membrane admission scope registry is full")

            states: list[_AdmissionState] = []
            for scope in scopes:
                state = self._admission_states.get(scope)
                if state is None:
                    state = _AdmissionState(
                        tokens=float(RATE_LIMIT_BURST),
                        last_refill=now,
                    )
                    self._admission_states[scope] = state
                elapsed = max(0.0, now - state.last_refill)
                state.tokens = min(
                    float(RATE_LIMIT_BURST),
                    state.tokens + elapsed * float(RATE_LIMIT_PER_SECOND),
                )
                state.last_refill = now
                states.append(state)

            # All four scopes must pass before any token or outstanding count
            # is consumed.  This prevents a failing owner bucket from draining
            # otherwise-valid session/task/class buckets.
            exhausted = [state for state in states if state.tokens < 1.0]
            if exhausted:
                deficit = max(1.0 - state.tokens for state in exhausted)
                retry_after_ms = max(
                    1,
                    int((deficit / float(RATE_LIMIT_PER_SECOND)) * 1_000) + 1,
                )
                raise AdmissionBackpressure(
                    "membrane rate limit exhausted",
                    retry_after_ms=retry_after_ms,
                )
            for state in states:
                state.tokens -= 1.0
                state.outstanding += 1
            self._admission_outstanding += 1
            ticket = AdmissionTicket(
                ticket_id=f"admission:{uuid4().hex}",
                owner_key_hash=spec.owner_key_hash,
                session_id=spec.session_id,
                task_id=spec.task_id,
                side_effect_class=spec.side_effect_class,
            )
            self._admission_tickets[ticket.ticket_id] = scopes
            return ticket

    def release(self, ticket: AdmissionTicket) -> bool:
        """Release an admission ticket once; duplicate/fabricated releases are inert."""

        if not isinstance(ticket, AdmissionTicket):
            raise TypeError("ticket must be an AdmissionTicket")
        with self._lock:
            scopes = self._admission_tickets.get(ticket.ticket_id)
            expected = _admission_scopes_from_values(
                owner_key_hash=ticket.owner_key_hash,
                session_id=ticket.session_id,
                task_id=ticket.task_id,
                side_effect_class=ticket.side_effect_class,
            )
            if scopes is None or scopes != expected:
                return False
            states = [self._admission_states.get(scope) for scope in scopes]
            if (
                self._admission_outstanding < 1
                or any(state is None or state.outstanding < 1 for state in states)
            ):
                raise MembraneError("admission accounting is inconsistent")
            self._admission_tickets.pop(ticket.ticket_id, None)
            for state in states:
                assert state is not None
                state.outstanding -= 1
            self._admission_outstanding -= 1
            return True

    def _prune_admission_states(self, now: float) -> None:
        stale: list[_AdmissionScope] = []
        for scope, state in self._admission_states.items():
            if state.outstanding:
                continue
            elapsed = max(0.0, now - state.last_refill)
            refilled = min(
                float(RATE_LIMIT_BURST),
                state.tokens + elapsed * float(RATE_LIMIT_PER_SECOND),
            )
            if refilled >= float(RATE_LIMIT_BURST):
                stale.append(scope)
        for scope in stale:
            self._admission_states.pop(scope, None)

    def propose(self, spec: OperationSpec) -> OperationSnapshot:
        self._require_enabled()
        if not isinstance(spec, OperationSpec):
            raise TypeError("spec must be an OperationSpec")
        fingerprint = _spec_fingerprint(spec)
        now_ms = self._now()
        try:
            with self._transaction() as connection:
                existing = connection.execute(
                    "SELECT * FROM commit_operations WHERE operation_id = ?",
                    (spec.operation_id,),
                ).fetchone()
                if existing is not None:
                    if str(existing["spec_fingerprint"]) != fingerprint:
                        raise OperationConflict("operation_id is bound to different authority")
                    return _snapshot(existing)

                active = connection.execute(
                    "SELECT operation_id FROM commit_operations"
                    " WHERE draft_id = ? AND state NOT IN ('DENIED', 'RECEIPTED')"
                    " ORDER BY ordinal DESC LIMIT 1",
                    (spec.draft_id,),
                ).fetchone()
                if active is not None:
                    raise OperationConflict(
                        f"draft already has an active operation {str(active['operation_id'])!r}"
                    )
                connection.execute(
                    """
                    INSERT INTO commit_operations (
                        operation_id, draft_id, task_id, owner_key_hash, session_id,
                        effect_type, executor_id, side_effect_class,
                        canonical_effect_hash, witness_id, intent_id, profile,
                        destinations_json, bytes_out, idempotency_key, directory_handle_id,
                        spec_fingerprint, state, created_at_ms, updated_at_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        spec.operation_id,
                        spec.draft_id,
                        spec.task_id,
                        spec.owner_key_hash,
                        spec.session_id,
                        spec.effect_type,
                        spec.executor_id,
                        spec.side_effect_class,
                        spec.canonical_effect_hash,
                        spec.witness_id,
                        spec.intent_id,
                        spec.profile,
                        _destinations_json(spec.destinations),
                        spec.bytes_out,
                        spec.idempotency_key,
                        spec.directory_handle_id,
                        fingerprint,
                        CommitState.PROPOSED.value,
                        now_ms,
                        now_ms,
                    ),
                )
                row = self._row(connection, spec.operation_id)
                return _snapshot(row)
        except sqlite3.IntegrityError as exc:
            raise OperationConflict("operation identity conflicts with durable state") from exc

    def get(self, operation_id: str) -> OperationSnapshot:
        self._require_enabled()
        with self._lock:
            row = self._connection().execute(
                "SELECT * FROM commit_operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if row is None:
                raise OperationNotFound(f"unknown operation {operation_id!r}")
            return _snapshot(row)

    def operation_for_draft(self, draft_id: str) -> OperationSnapshot | None:
        self._require_enabled()
        with self._lock:
            row = self._connection().execute(
                "SELECT * FROM commit_operations WHERE draft_id = ?"
                " ORDER BY ordinal DESC LIMIT 1",
                (draft_id,),
            ).fetchone()
            return None if row is None else _snapshot(row)

    def operations_for_draft(self, draft_id: str) -> list[OperationSnapshot]:
        self._require_enabled()
        with self._lock:
            rows = self._connection().execute(
                "SELECT * FROM commit_operations WHERE draft_id = ? ORDER BY ordinal",
                (draft_id,),
            ).fetchall()
            return [_snapshot(row) for row in rows]

    def operations_in_states(
        self,
        states: tuple[CommitState, ...] | list[CommitState] | frozenset[CommitState],
        *,
        executor_id: str | None = None,
    ) -> list[OperationSnapshot]:
        """Enumerate durable recovery work without exposing effect packages."""

        self._require_enabled()
        if not isinstance(states, (tuple, list, frozenset)):
            raise TypeError("states must be a finite CommitState collection")
        if any(not isinstance(state, CommitState) for state in states):
            raise TypeError("states must contain only CommitState values")
        unique_states = tuple(sorted({state.value for state in states}))
        if not unique_states:
            return []
        if executor_id is not None:
            _validate_bounded_text(executor_id, "executor_id", maximum=512)
            if not executor_id.startswith(("cell.", "cell:")):
                raise ValueError("executor_id must name a Cell")
        placeholders = ",".join("?" for _ in unique_states)
        sql = f"SELECT * FROM commit_operations WHERE state IN ({placeholders})"
        params: tuple[Any, ...] = unique_states
        if executor_id is not None:
            sql += " AND executor_id = ?"
            params += (executor_id,)
        sql += " ORDER BY ordinal"
        with self._lock:
            rows = self._connection().execute(sql, params).fetchall()
            return [_snapshot(row) for row in rows]

    def transition(
        self,
        operation_id: str,
        target: CommitState,
        *,
        receipt_id: str = "",
        remote_operation_id: str = "",
        safe_result: dict[str, Any] | None = None,
    ) -> OperationSnapshot:
        self._require_enabled()
        if not isinstance(target, CommitState):
            raise TypeError("target must be a CommitState")
        now_ms = self._now()
        with self._transaction() as connection:
            row = self._row(connection, operation_id)
            source = CommitState(str(row["state"]))
            generic_edges = {
                CommitState.PROPOSED: {CommitState.DENIED, CommitState.PREFLIGHTED},
                CommitState.PREFLIGHTED: {CommitState.APPROVAL_PENDING},
                CommitState.APPROVAL_PENDING: {CommitState.DENIED},
                CommitState.COMMITTING: {CommitState.COMMITTED},
                CommitState.COMMITTED: {CommitState.RECEIPTED},
            }
            if target not in generic_edges.get(source, set()):
                raise InvalidTransition(f"illegal membrane transition {source} -> {target}")
            if target is CommitState.RECEIPTED:
                _validate_identifier(receipt_id, "receipt_id", prefix="receipt:")
            elif receipt_id:
                raise InvalidTransition("receipt_id is valid only for RECEIPTED")
            result_json = str(row["safe_result_json"])
            result_digest = str(row["safe_result_digest"])
            durable_remote_id = str(row["remote_operation_id"])
            if target is CommitState.COMMITTED:
                result_json, result_digest, durable_remote_id = _normalize_safe_result(
                    str(row["effect_type"]),
                    safe_result,
                    remote_operation_id=remote_operation_id,
                )
            elif safe_result is not None or remote_operation_id:
                raise InvalidTransition(
                    "remote_operation_id and safe_result are valid only for COMMITTED"
                )
            connection.execute(
                "UPDATE commit_operations SET state = ?, receipt_id = ?,"
                " remote_operation_id = ?, safe_result_json = ?, safe_result_digest = ?,"
                " updated_at_ms = ? WHERE operation_id = ?",
                (
                    target.value,
                    receipt_id,
                    durable_remote_id,
                    result_json,
                    result_digest,
                    now_ms,
                    operation_id,
                ),
            )
            return _snapshot(self._row(connection, operation_id))

    def prepare(
        self,
        operation_id: str,
        *,
        max_invocations: int,
        max_bytes_out: int,
        export_pass_id: str | None,
        require_personal_pass: bool,
        exact_approval_id: str | None = None,
        require_personal_exact: bool = False,
        now_ms: int | None = None,
    ) -> OperationSnapshot:
        """Atomically validate authority, reserve budget, and mint one permit."""

        self._require_enabled()
        _validate_budget_limits(max_invocations, max_bytes_out)
        effective_now = self._now() if now_ms is None else now_ms
        if isinstance(effective_now, bool) or not isinstance(effective_now, int) or effective_now <= 0:
            raise ValueError("now_ms must be a positive integer")
        if not isinstance(require_personal_pass, bool):
            raise ValueError("require_personal_pass must be a boolean")
        if not isinstance(require_personal_exact, bool):
            raise ValueError("require_personal_exact must be a boolean")
        exact_id = exact_approval_id or ""
        if exact_id:
            _validate_identifier(exact_id, "exact_approval_id", prefix="exact:")
        if require_personal_pass and require_personal_exact:
            raise ValueError("one operation cannot require export and exact file authority")

        with self._transaction() as connection:
            row = self._row(connection, operation_id)
            source = CommitState(str(row["state"]))
            if source is CommitState.PREPARED:
                return _snapshot(row)
            if source not in {CommitState.PREFLIGHTED, CommitState.APPROVAL_PENDING}:
                raise InvalidTransition(f"cannot prepare operation from {source}")
            bytes_out = int(row["bytes_out"])
            budget = connection.execute(
                "SELECT invocations, bytes_out, sequence FROM effect_budget_usage"
                " WHERE task_id = ?",
                (str(row["task_id"]),),
            ).fetchone()
            invocations = 0 if budget is None else int(budget["invocations"])
            used_bytes = 0 if budget is None else int(budget["bytes_out"])
            previous_sequence = 0 if budget is None else int(budget["sequence"])
            if invocations + 1 > max_invocations or used_bytes + bytes_out > max_bytes_out:
                raise BudgetExhausted("effect budget exhausted")

            destinations = _destinations_from_json(str(row["destinations_json"]))
            must_have_pass = bool(destinations) or require_personal_pass
            pass_id = export_pass_id or ""
            if str(row["effect_type"]) == "file.commit" and (
                destinations or pass_id or require_personal_pass
            ):
                raise ExportPassUnavailable("file.commit must not bind an ExportPass")
            if (
                str(row["profile"]) == "personal"
                and str(row["effect_type"]) == "file.commit"
                and not require_personal_exact
            ):
                raise ExactApprovalUnavailable(
                    "Personal file.commit requires an exact commit approval"
                )
            pass_row: sqlite3.Row | None = None
            if must_have_pass:
                if not pass_id:
                    raise ExportPassUnavailable("an exact ExportPass is required")
                pass_row = self._exact_export_pass(
                    connection,
                    pass_id=pass_id,
                    operation=row,
                    destinations=destinations,
                    now_ms=effective_now,
                )
                profile = str(row["profile"])
                expected_standing = profile == "work"
                if profile not in {"personal", "work"}:
                    raise ExportPassUnavailable("egress profile cannot consume an ExportPass")
                if str(pass_row["profile"]) != profile or bool(pass_row["standing"]) != (
                    expected_standing
                ):
                    raise ExportPassUnavailable("ExportPass profile or standing mode mismatch")
            elif pass_id:
                raise ExportPassUnavailable("non-egress operation must not bind an ExportPass")

            exact_row: sqlite3.Row | None = None
            if require_personal_exact:
                if not exact_id:
                    raise ExactApprovalUnavailable("an exact commit approval is required")
                if (
                    str(row["profile"]) != "personal"
                    or str(row["effect_type"]) != "file.commit"
                    or str(row["executor_id"]) != "cell.file"
                    or destinations
                    or pass_id
                ):
                    raise ExactApprovalUnavailable(
                        "exact commit approval is limited to non-egress Personal cell.file"
                    )
                directory_handle_id = str(row["directory_handle_id"])
                if not directory_handle_id.startswith("dirh:"):
                    raise ExactApprovalUnavailable(
                        "Personal file operation has no DirectoryHandle binding"
                    )
                exact_row = self._exact_commit_approval(
                    connection,
                    approval_id=exact_id,
                    operation=row,
                    now_ms=effective_now,
                )
            elif exact_id:
                raise ExactApprovalUnavailable(
                    "operation must not bind an exact commit approval"
                )

            next_sequence = previous_sequence + 1
            connection.execute(
                "INSERT INTO effect_budget_usage(task_id, invocations, bytes_out, sequence)"
                " VALUES (?, ?, ?, ?)"
                " ON CONFLICT(task_id) DO UPDATE SET"
                " invocations = excluded.invocations, bytes_out = excluded.bytes_out,"
                " sequence = excluded.sequence",
                (str(row["task_id"]), invocations + 1, used_bytes + bytes_out, next_sequence),
            )

            profile = str(row["profile"])
            if pass_row is not None and profile == "personal":
                claimed = connection.execute(
                    "UPDATE export_passes SET revoked = 1, claimed_at_ms = ?"
                    " WHERE pass_id = ? AND revoked = 0 AND profile = 'personal'"
                    " AND standing = 0",
                    (effective_now, pass_id),
                )
                if claimed.rowcount != 1:
                    raise ExportPassUnavailable("Personal ExportPass is no longer available")

            if exact_row is not None:
                claimed_exact = connection.execute(
                    "UPDATE exact_commit_approvals SET claimed_at_ms = ?"
                    " WHERE approval_id = ? AND task_id = ? AND draft_id = ?"
                    " AND witness_id = ? AND canonical_effect_hash = ?"
                    " AND directory_handle_id = ? AND claimed_at_ms = 0"
                    " AND expires_at_ms > ?",
                    (
                        effective_now,
                        exact_id,
                        str(row["task_id"]),
                        str(row["draft_id"]),
                        str(row["witness_id"]),
                        str(row["canonical_effect_hash"]),
                        str(row["directory_handle_id"]),
                        effective_now,
                    ),
                )
                if claimed_exact.rowcount != 1:
                    raise ExactApprovalUnavailable(
                        "Personal exact commit approval is no longer available"
                    )

            permit_id = f"permit:{uuid4().hex}"
            connection.execute(
                "UPDATE commit_operations SET state = ?, permit_id = ?,"
                " permit_sequence = ?, permit_not_before_ms = ?,"
                " permit_expires_at_ms = ?, budget_sequence = ?, export_pass_id = ?,"
                " export_pass_claimed = ?, exact_approval_id = ?,"
                " exact_approval_claimed = ?, reconciliation_status = '', updated_at_ms = ?"
                " WHERE operation_id = ?",
                (
                    CommitState.PREPARED.value,
                    permit_id,
                    next_sequence,
                    effective_now,
                    effective_now + _PERMIT_TTL_MS,
                    next_sequence,
                    pass_id,
                    int(pass_row is not None and profile == "personal"),
                    exact_id,
                    int(exact_row is not None),
                    effective_now,
                    operation_id,
                ),
            )
            return _snapshot(self._row(connection, operation_id))

    def rotate_prepared_permit(
        self,
        operation_id: str,
        *,
        expected_permit_id: str,
        expected_intent_id: str,
        expected_witness_id: str,
        expected_export_pass_id: str | None,
        expected_exact_approval_id: str | None = None,
        now_ms: int | None = None,
    ) -> OperationSnapshot:
        """CAS-rotate a PREPARED permit without reserving budget twice.

        The caller must first revalidate the current Intent, witness and (for
        Work egress) standing ExportPass.  Requiring those exact durable ids,
        plus the old permit id, prevents a stale recovery task from rotating a
        different authority snapshot.  A Personal pass is not queried again:
        its durable claim is part of the original PREPARED transaction.
        """

        self._require_enabled()
        _validate_identifier(expected_permit_id, "expected_permit_id", prefix="permit:")
        _validate_identifier(expected_intent_id, "expected_intent_id", prefix="intent:")
        _validate_identifier(expected_witness_id, "expected_witness_id", prefix="state:")
        expected_pass_id = expected_export_pass_id or ""
        if expected_pass_id:
            _validate_identifier(
                expected_pass_id,
                "expected_export_pass_id",
                prefix="export:",
            )
        expected_exact_id = expected_exact_approval_id or ""
        if expected_exact_id:
            _validate_identifier(
                expected_exact_id,
                "expected_exact_approval_id",
                prefix="exact:",
            )
        effective_now = self._now() if now_ms is None else now_ms
        if isinstance(effective_now, bool) or not isinstance(effective_now, int):
            raise ValueError("now_ms must be a positive integer")
        if effective_now <= 0:
            raise ValueError("now_ms must be a positive integer")

        with self._transaction() as connection:
            row = self._row(connection, operation_id)
            source = CommitState(str(row["state"]))
            if source is not CommitState.PREPARED:
                raise InvalidTransition(f"cannot rotate a permit from {source}")
            expected_binding = (
                expected_permit_id,
                expected_intent_id,
                expected_witness_id,
                expected_pass_id,
                expected_exact_id,
            )
            stored_binding = (
                str(row["permit_id"]),
                str(row["intent_id"]),
                str(row["witness_id"]),
                str(row["export_pass_id"]),
                str(row["exact_approval_id"]),
            )
            if expected_binding != stored_binding:
                raise OperationConflict("prepared permit authority changed before rotation")
            budget = connection.execute(
                "SELECT sequence FROM effect_budget_usage WHERE task_id = ?",
                (str(row["task_id"]),),
            ).fetchone()
            if budget is None or int(row["budget_sequence"]) < 1:
                raise InvalidTransition("operation has no durable budget reservation")
            next_sequence = int(budget["sequence"]) + 1
            connection.execute(
                "UPDATE effect_budget_usage SET sequence = ? WHERE task_id = ?",
                (next_sequence, str(row["task_id"])),
            )
            connection.execute(
                "UPDATE commit_operations SET permit_id = ?, permit_sequence = ?,"
                " permit_not_before_ms = ?, permit_expires_at_ms = ?,"
                " reconciliation_status = 'rotated', updated_at_ms = ?"
                " WHERE operation_id = ?",
                (
                    f"permit:{uuid4().hex}",
                    next_sequence,
                    effective_now,
                    effective_now + _PERMIT_TTL_MS,
                    effective_now,
                    operation_id,
                ),
            )
            return _snapshot(self._row(connection, operation_id))

    def begin_commit(self, operation_id: str) -> OperationSnapshot:
        self._require_enabled()
        now_ms = self._now()
        with self._transaction() as connection:
            row = self._row(connection, operation_id)
            source = CommitState(str(row["state"]))
            if source is not CommitState.PREPARED:
                raise InvalidTransition(f"cannot begin commit from {source}")
            requires_exact_recheck = bool(
                str(row["profile"]) == "personal"
                and str(row["effect_type"]) == "file.commit"
                and str(row["exact_approval_id"])
                and bool(row["exact_approval_claimed"])
            )
            if requires_exact_recheck and not _operation_has_current_witness(
                connection,
                row,
                now_ms=now_ms,
            ):
                raise OperationConflict(
                    "prepared witness is no longer current at the commit boundary"
                )
            connection.execute(
                "UPDATE commit_operations SET state = ?, attempt_count = attempt_count + 1,"
                " reconciliation_status = '', updated_at_ms = ? WHERE operation_id = ?",
                (CommitState.COMMITTING.value, now_ms, operation_id),
            )
            return _snapshot(self._row(connection, operation_id))

    def mark_ambiguous(self, operation_id: str, error: str) -> OperationSnapshot:
        self._require_enabled()
        _validate_bounded_text(error, "error", maximum=2_048)
        now_ms = self._now()
        with self._transaction() as connection:
            row = self._row(connection, operation_id)
            source = CommitState(str(row["state"]))
            if source is not CommitState.COMMITTING:
                raise InvalidTransition(f"cannot mark ambiguity from {source}")
            connection.execute(
                "UPDATE commit_operations SET state = ?, last_error = ?,"
                " reconciliation_status = '', updated_at_ms = ? WHERE operation_id = ?",
                (CommitState.UNKNOWN_COMMIT.value, error, now_ms, operation_id),
            )
            return _snapshot(self._row(connection, operation_id))

    def reconcile(
        self,
        operation_id: str,
        outcome: str,
        *,
        remote_operation_id: str = "",
        safe_result: dict[str, Any] | None = None,
    ) -> OperationSnapshot:
        """Apply authoritative Cell reconciliation; never retry an unknown blindly."""

        self._require_enabled()
        if outcome not in {"committed", "absent", "unknown"}:
            raise ValueError("reconciliation outcome must be committed, absent, or unknown")
        if remote_operation_id:
            _validate_bounded_text(remote_operation_id, "remote_operation_id", maximum=512)
        if outcome != "committed" and (remote_operation_id or safe_result is not None):
            raise ValueError("only committed reconciliation can carry result metadata")
        now_ms = self._now()
        with self._transaction() as connection:
            row = self._row(connection, operation_id)
            source = CommitState(str(row["state"]))
            # A repeated reconciliation response must not mint another permit
            # or move counters a second time.
            if source is CommitState.PREPARED and str(row["reconciliation_status"]) == "absent":
                if outcome == "absent":
                    return _snapshot(row)
                raise InvalidTransition("operation was already reconciled absent")
            if source is CommitState.COMMITTED and str(row["reconciliation_status"]) == "committed":
                if outcome == "committed":
                    result_json, result_digest, durable_remote_id = _normalize_safe_result(
                        str(row["effect_type"]),
                        safe_result,
                        remote_operation_id=remote_operation_id,
                    )
                    if safe_result is not None and (
                        result_json != str(row["safe_result_json"])
                        or result_digest != str(row["safe_result_digest"])
                    ):
                        raise OperationConflict("reconciled safe result changed on replay")
                    if remote_operation_id and durable_remote_id != str(
                        row["remote_operation_id"]
                    ):
                        raise OperationConflict("reconciled remote operation changed on replay")
                    return _snapshot(row)
                raise InvalidTransition("operation was already reconciled committed")
            if source is not CommitState.UNKNOWN_COMMIT:
                raise InvalidTransition(f"cannot reconcile operation from {source}")

            if outcome == "unknown":
                connection.execute(
                    "UPDATE commit_operations SET reconciliation_status = 'unknown',"
                    " updated_at_ms = ? WHERE operation_id = ?",
                    (now_ms, operation_id),
                )
                return _snapshot(self._row(connection, operation_id))
            if outcome == "committed":
                result_json, result_digest, durable_remote_id = _normalize_safe_result(
                    str(row["effect_type"]),
                    safe_result,
                    remote_operation_id=remote_operation_id,
                )
                connection.execute(
                    "UPDATE commit_operations SET state = ?, remote_operation_id = ?,"
                    " safe_result_json = ?, safe_result_digest = ?,"
                    " reconciliation_status = 'committed', updated_at_ms = ?"
                    " WHERE operation_id = ?",
                    (
                        CommitState.COMMITTED.value,
                        durable_remote_id,
                        result_json,
                        result_digest,
                        now_ms,
                        operation_id,
                    ),
                )
                return _snapshot(self._row(connection, operation_id))

            budget = connection.execute(
                "SELECT sequence FROM effect_budget_usage WHERE task_id = ?",
                (str(row["task_id"]),),
            ).fetchone()
            if budget is None or int(row["budget_sequence"]) < 1:
                raise InvalidTransition("operation has no durable budget reservation")
            next_sequence = int(budget["sequence"]) + 1
            connection.execute(
                "UPDATE effect_budget_usage SET sequence = ? WHERE task_id = ?",
                (next_sequence, str(row["task_id"])),
            )
            connection.execute(
                "UPDATE commit_operations SET state = ?, permit_id = ?,"
                " permit_sequence = ?, permit_not_before_ms = ?,"
                " permit_expires_at_ms = ?, reconciliation_status = 'absent',"
                " updated_at_ms = ? WHERE operation_id = ?",
                (
                    CommitState.PREPARED.value,
                    f"permit:{uuid4().hex}",
                    next_sequence,
                    now_ms,
                    now_ms + _PERMIT_TTL_MS,
                    now_ms,
                    operation_id,
                ),
            )
            return _snapshot(self._row(connection, operation_id))

    def _exact_export_pass(
        self,
        connection: sqlite3.Connection,
        *,
        pass_id: str,
        operation: sqlite3.Row,
        destinations: tuple[str, ...],
        now_ms: int,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT pass_id, task_id, payload_hash, destinations_json, witness_id,"
            " expires_at_ms, revoked, profile, standing, claimed_at_ms"
            " FROM export_passes WHERE pass_id = ? AND task_id = ? AND payload_hash = ?"
            " AND destinations_json = ? AND witness_id = ? AND revoked = 0"
            " AND expires_at_ms > ?",
            (
                pass_id,
                str(operation["task_id"]),
                str(operation["canonical_effect_hash"]),
                _destinations_json(destinations),
                str(operation["witness_id"]),
                now_ms,
            ),
        ).fetchone()
        if row is None:
            raise ExportPassUnavailable("no live ExportPass matches task/hash/dest/witness")
        return cast("sqlite3.Row", row)

    def _exact_commit_approval(
        self,
        connection: sqlite3.Connection,
        *,
        approval_id: str,
        operation: sqlite3.Row,
        now_ms: int,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT approval.approval_id, approval.task_id, approval.draft_id,"
            " approval.witness_id, approval.canonical_effect_hash,"
            " approval.directory_handle_id, approval.expires_at_ms,"
            " approval.claimed_at_ms"
            " FROM exact_commit_approvals AS approval"
            " JOIN state_witnesses AS witness"
            " ON witness.witness_id = approval.witness_id"
            " AND witness.draft_id = approval.draft_id"
            " AND witness.canonical_effect_hash = approval.canonical_effect_hash"
            " JOIN effect_drafts AS draft ON draft.draft_id = approval.draft_id"
            " AND draft.task_id = approval.task_id"
            " AND draft.canonical_effect_hash = approval.canonical_effect_hash"
            " WHERE approval.approval_id = ? AND approval.task_id = ?"
            " AND approval.draft_id = ? AND approval.witness_id = ?"
            " AND approval.canonical_effect_hash = ?"
            " AND approval.directory_handle_id = ? AND approval.claimed_at_ms = 0"
            " AND approval.expires_at_ms > ? AND witness.is_current = 1"
            " AND witness.executor_id = 'cell.file' AND witness.expires_at_ms > ?"
            " AND draft.executor_id = 'cell.file' AND draft.expires_at_ms > ?",
            (
                approval_id,
                str(operation["task_id"]),
                str(operation["draft_id"]),
                str(operation["witness_id"]),
                str(operation["canonical_effect_hash"]),
                str(operation["directory_handle_id"]),
                now_ms,
                now_ms,
                now_ms,
            ),
        ).fetchone()
        if row is None:
            raise ExactApprovalUnavailable(
                "no live exact approval matches task/draft/witness/hash/directory"
            )
        return cast("sqlite3.Row", row)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            connection = self._connection()
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()

    def _row(self, connection: sqlite3.Connection, operation_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM commit_operations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise OperationNotFound(f"unknown operation {operation_id!r}")
        return cast("sqlite3.Row", row)

    def _connection(self) -> sqlite3.Connection:
        if self._conn is None:
            if not self.enabled:
                raise MembraneDisabled("commit membrane is disabled")
            raise MembraneError("commit membrane is closed")
        if self._path_guard is not None:
            try:
                self._path_guard.raise_if_violated()
                self._path_guard.verify()
            except PrivatePathError as exc:
                raise MembraneError("private membrane database path changed") from exc
        return self._conn

    def _require_enabled(self) -> None:
        if not self.enabled:
            raise MembraneDisabled("commit membrane is disabled")
        self._connection()

    def _now(self) -> int:
        value = self._now_fn()
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError("now_fn must return a positive integer millisecond timestamp")
        return value

    def _monotonic(self) -> float:
        value = self._monotonic_fn()
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise ValueError("monotonic_fn must return a non-negative number")
        return float(value)


def _snapshot(row: sqlite3.Row) -> OperationSnapshot:
    stored_result_json = str(row["safe_result_json"])
    try:
        parsed_result = json.loads(stored_result_json)
    except json.JSONDecodeError as exc:
        raise MembraneError("stored safe result is invalid") from exc
    if not isinstance(parsed_result, dict):
        raise MembraneError("stored safe result is invalid")
    canonical_result, expected_digest, expected_remote_id = _normalize_safe_result(
        str(row["effect_type"]),
        cast("dict[str, Any]", parsed_result),
        remote_operation_id=str(row["remote_operation_id"]),
    )
    if (
        canonical_result != stored_result_json
        or expected_digest != str(row["safe_result_digest"])
        or expected_remote_id != str(row["remote_operation_id"])
    ):
        raise MembraneError("stored safe result integrity check failed")
    return OperationSnapshot(
        operation_id=str(row["operation_id"]),
        draft_id=str(row["draft_id"]),
        task_id=str(row["task_id"]),
        owner_key_hash=str(row["owner_key_hash"]),
        session_id=str(row["session_id"]),
        effect_type=str(row["effect_type"]),
        executor_id=str(row["executor_id"]),
        side_effect_class=str(row["side_effect_class"]),
        canonical_effect_hash=str(row["canonical_effect_hash"]),
        witness_id=str(row["witness_id"]),
        intent_id=str(row["intent_id"]),
        profile=str(row["profile"]),
        destinations=_destinations_from_json(str(row["destinations_json"])),
        bytes_out=int(row["bytes_out"]),
        idempotency_key=str(row["idempotency_key"]),
        directory_handle_id=str(row["directory_handle_id"]),
        state=CommitState(str(row["state"])),
        permit_id=str(row["permit_id"]),
        permit_sequence=int(row["permit_sequence"]),
        permit_not_before_ms=int(row["permit_not_before_ms"]),
        permit_expires_at_ms=int(row["permit_expires_at_ms"]),
        budget_sequence=int(row["budget_sequence"]),
        attempt_count=int(row["attempt_count"]),
        export_pass_id=str(row["export_pass_id"]),
        export_pass_claimed=bool(row["export_pass_claimed"]),
        exact_approval_id=str(row["exact_approval_id"]),
        exact_approval_claimed=bool(row["exact_approval_claimed"]),
        remote_operation_id=str(row["remote_operation_id"]),
        receipt_id=str(row["receipt_id"]),
        safe_result_digest=str(row["safe_result_digest"]),
        last_error=str(row["last_error"]),
        reconciliation_status=str(row["reconciliation_status"]),
        created_at_ms=int(row["created_at_ms"]),
        updated_at_ms=int(row["updated_at_ms"]),
        _safe_result_json=stored_result_json,
    )


def _ensure_operation_columns(connection: sqlite3.Connection) -> None:
    """Forward-only migration for databases created by an earlier WP10 build."""

    connection.execute("BEGIN IMMEDIATE")
    try:
        columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(commit_operations)")
        }
        additions = {
            "directory_handle_id": "TEXT NOT NULL DEFAULT ''",
            "export_pass_claimed": "INTEGER NOT NULL DEFAULT 0",
            "exact_approval_id": "TEXT NOT NULL DEFAULT ''",
            "exact_approval_claimed": "INTEGER NOT NULL DEFAULT 0",
            "safe_result_json": "TEXT NOT NULL DEFAULT '{}'",
            "safe_result_digest": "TEXT NOT NULL DEFAULT ''",
        }
        for name, declaration in additions.items():
            if name not in columns:
                connection.execute(
                    f"ALTER TABLE commit_operations ADD COLUMN {name} {declaration}"
                )
        _backfill_file_directory_handles(connection)
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def _backfill_file_directory_handles(connection: sqlite3.Connection) -> None:
    """Recover a legacy File operation binding only from its immutable draft.

    Rows whose old fingerprint, draft identity, or canonical effect hash cannot
    be proven are deliberately left blank so later authorization fails closed.
    """

    from js.orin.draft import draft_from_dict
    from js.orind.kernel import canonical_effect_hash_of

    rows = connection.execute(
        "SELECT * FROM commit_operations"
        " WHERE effect_type = 'file.commit' AND directory_handle_id = ''"
    ).fetchall()
    expected_record_fields = {
        "draft",
        "draft_id",
        "task_id",
        "effect_type",
        "executor_id",
        "canonical_effect_hash",
        "context_taint",
        "arg_taint",
        "clearance",
        "created_at_ms",
        "expires_at_ms",
    }
    for row in rows:
        try:
            legacy_spec = _operation_spec_from_row(row, directory_handle_id="")
            legacy_fingerprint = _spec_fingerprint(legacy_spec)
            if legacy_fingerprint != str(row["spec_fingerprint"]):
                continue
            draft_row = connection.execute(
                "SELECT payload_json FROM effect_drafts WHERE draft_id = ?",
                (str(row["draft_id"]),),
            ).fetchone()
            if draft_row is None:
                continue
            record = json.loads(str(draft_row[0]))
            if not isinstance(record, dict) or set(record) != expected_record_fields:
                continue
            raw_draft = record.get("draft")
            if not isinstance(raw_draft, dict):
                continue
            draft = draft_from_dict(raw_draft)
            if (
                draft.draft_id != str(row["draft_id"])
                or draft.task_id != str(row["task_id"])
                or draft.effect_type != "file.commit"
                or record.get("draft_id") != draft.draft_id
                or record.get("task_id") != draft.task_id
                or record.get("effect_type") != draft.effect_type
                or record.get("executor_id") != "cell.file"
                or str(row["executor_id"]) != "cell.file"
                or record.get("canonical_effect_hash")
                != str(row["canonical_effect_hash"])
                or canonical_effect_hash_of(draft) != str(row["canonical_effect_hash"])
                or set(draft.arguments) != {"directory_handle", "changes"}
            ):
                continue
            directory_handle_id = draft.arguments.get("directory_handle")
            if not _is_directory_handle_id(directory_handle_id):
                continue
            assert isinstance(directory_handle_id, str)
            migrated_spec = _operation_spec_from_row(
                row,
                directory_handle_id=directory_handle_id,
            )
            migrated_fingerprint = _spec_fingerprint(migrated_spec)
            connection.execute(
                "UPDATE commit_operations SET directory_handle_id = ?,"
                " spec_fingerprint = ? WHERE operation_id = ?"
                " AND directory_handle_id = '' AND spec_fingerprint = ?",
                (
                    directory_handle_id,
                    migrated_fingerprint,
                    str(row["operation_id"]),
                    legacy_fingerprint,
                ),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue


def _operation_spec_from_row(
    row: sqlite3.Row,
    *,
    directory_handle_id: str,
) -> OperationSpec:
    return OperationSpec(
        operation_id=str(row["operation_id"]),
        draft_id=str(row["draft_id"]),
        task_id=str(row["task_id"]),
        owner_key_hash=str(row["owner_key_hash"]),
        session_id=str(row["session_id"]),
        effect_type=str(row["effect_type"]),
        executor_id=str(row["executor_id"]),
        side_effect_class=str(row["side_effect_class"]),
        canonical_effect_hash=str(row["canonical_effect_hash"]),
        witness_id=str(row["witness_id"]),
        intent_id=str(row["intent_id"]),
        profile=str(row["profile"]),
        destinations=_destinations_from_json(str(row["destinations_json"])),
        bytes_out=int(row["bytes_out"]),
        idempotency_key=str(row["idempotency_key"]),
        directory_handle_id=directory_handle_id,
    )


def _operation_has_current_witness(
    connection: sqlite3.Connection,
    operation: sqlite3.Row,
    *,
    now_ms: int,
) -> bool:
    row = connection.execute(
        "SELECT 1 FROM state_witnesses AS witness"
        " JOIN effect_drafts AS draft ON draft.draft_id = witness.draft_id"
        " AND draft.canonical_effect_hash = witness.canonical_effect_hash"
        " WHERE witness.witness_id = ? AND witness.draft_id = ?"
        " AND witness.executor_id = ? AND witness.canonical_effect_hash = ?"
        " AND witness.is_current = 1 AND witness.expires_at_ms > ?"
        " AND draft.task_id = ? AND draft.executor_id = ?"
        " AND draft.expires_at_ms > ?",
        (
            str(operation["witness_id"]),
            str(operation["draft_id"]),
            str(operation["executor_id"]),
            str(operation["canonical_effect_hash"]),
            now_ms,
            str(operation["task_id"]),
            str(operation["executor_id"]),
            now_ms,
        ),
    ).fetchone()
    return row is not None


def _normalize_safe_result(
    effect_type: str,
    safe_result: dict[str, Any] | None,
    *,
    remote_operation_id: str,
) -> tuple[str, str, str]:
    """Validate the small replay projection and return JSON, digest, remote id."""

    if remote_operation_id:
        _validate_bounded_text(remote_operation_id, "remote_operation_id", maximum=512)
    if safe_result is None:
        return ("{}", "", remote_operation_id)
    if not isinstance(safe_result, dict):
        raise ValueError("safe_result must be an object")
    common = {"status", "remote_operation_id", "duplicate"}
    effect_fields = {
        "email.send_exact": {"recipients", "bytes_out"},
        "file.commit": {"files", "bytes_written", "diff_hash", "overwrites"},
    }
    allowed = common | effect_fields.get(effect_type, set())
    unknown = set(safe_result) - allowed
    if unknown:
        raise ValueError(f"unsafe result fields are not persistable: {sorted(unknown)!r}")
    if safe_result and effect_type not in effect_fields:
        raise ValueError("safe result persistence is limited to Connector and File effects")

    normalized: dict[str, Any] = {}
    for key, value in safe_result.items():
        if key == "status":
            if value not in {"COMMITTED", "RECONCILED_COMMITTED"}:
                raise ValueError("safe result status is not a committed state")
            normalized[key] = value
        elif key == "remote_operation_id":
            _validate_bounded_text(value, key, maximum=512)
            if remote_operation_id and value != remote_operation_id:
                raise OperationConflict("remote operation id disagrees with safe result")
            remote_operation_id = value
            normalized[key] = value
        elif key == "duplicate":
            if not isinstance(value, bool):
                raise ValueError("safe result duplicate must be a boolean")
            normalized[key] = value
        elif key in {"recipients", "bytes_out", "bytes_written"}:
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << 63:
                raise ValueError(f"safe result {key} must be a non-negative integer")
            normalized[key] = value
        elif key == "diff_hash":
            if not isinstance(value, str):
                raise ValueError("safe result diff_hash must be a string")
            _validate_sha256(value, "safe result diff_hash")
            normalized[key] = value
        elif key in {"files", "overwrites"}:
            if not isinstance(value, list) or len(value) > 128:
                raise ValueError(f"safe result {key} must be a bounded list")
            paths: list[str] = []
            for path in value:
                if (
                    not isinstance(path, str)
                    or not path
                    or len(path) > 1_024
                    or path.startswith(("/", "\\"))
                    or "\x00" in path
                    or any(part in {"", ".", ".."} for part in path.replace("\\", "/").split("/"))
                ):
                    raise ValueError(f"safe result {key} contains an unsafe relative path")
                paths.append(path)
            normalized[key] = paths
        else:  # pragma: no cover - set validation above makes this unreachable
            raise ValueError(f"safe result field {key!r} is unsupported")
    raw = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    encoded = raw.encode("utf-8")
    if len(encoded) > _SAFE_RESULT_BYTES:
        raise ValueError("safe result projection exceeds its persistence bound")
    digest = "sha256:" + hashlib.sha256(encoded).hexdigest() if normalized else ""
    return (raw, digest, remote_operation_id)


def _spec_fingerprint(spec: OperationSpec) -> str:
    payload = {
        "operation_id": spec.operation_id,
        "draft_id": spec.draft_id,
        "task_id": spec.task_id,
        "owner_key_hash": spec.owner_key_hash,
        "session_id": spec.session_id,
        "effect_type": spec.effect_type,
        "executor_id": spec.executor_id,
        "side_effect_class": spec.side_effect_class,
        "canonical_effect_hash": spec.canonical_effect_hash,
        "witness_id": spec.witness_id,
        "intent_id": spec.intent_id,
        "profile": spec.profile,
        "destinations": list(spec.destinations),
        "bytes_out": spec.bytes_out,
        "idempotency_key": spec.idempotency_key,
    }
    if spec.directory_handle_id:
        payload["directory_handle_id"] = spec.directory_handle_id
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _admission_scopes(spec: OperationSpec) -> _AdmissionScopes:
    return _admission_scopes_from_values(
        owner_key_hash=spec.owner_key_hash,
        session_id=spec.session_id,
        task_id=spec.task_id,
        side_effect_class=spec.side_effect_class,
    )


def _admission_scopes_from_values(
    *,
    owner_key_hash: str,
    session_id: str,
    task_id: str,
    side_effect_class: str,
) -> _AdmissionScopes:
    return (
        ("owner", owner_key_hash),
        ("session", session_id),
        ("task", task_id),
        ("effect_class", side_effect_class),
    )


def _destinations_json(destinations: tuple[str, ...]) -> str:
    return json.dumps(list(destinations), sort_keys=True, separators=(",", ":"))


def _destinations_from_json(raw: str) -> tuple[str, ...]:
    value = json.loads(raw)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise MembraneError("stored destinations are invalid")
    result = tuple(value)
    if tuple(sorted(result)) != result or len(set(result)) != len(result):
        raise MembraneError("stored destinations are not canonical")
    return result


def _validate_sha256(value: str, name: str) -> None:
    if (
        len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ValueError(f"{name} must be sha256:<64 lowercase hex>")


def _validate_bounded_text(value: str, name: str, *, maximum: int) -> None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{name} must be a bounded non-empty string")


def _validate_identifier(value: str, name: str, *, prefix: str) -> None:
    _validate_bounded_text(value, name, maximum=512)
    if not value.startswith(prefix):
        raise ValueError(f"{name} must start with {prefix!r}")


def _is_directory_handle_id(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    prefix, separator, token = value.partition(":")
    return bool(
        prefix == "dirh"
        and separator
        and token
        and len(token) <= 200
        and all(character.isalnum() or character in "-_." for character in token)
    )


def _validate_budget_limits(max_invocations: int, max_bytes_out: int) -> None:
    values = (max_invocations, max_bytes_out)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        raise ValueError("budget limits must be integers")
    if any(value < 0 for value in values):
        raise ValueError("budget limits must be non-negative")


__all__ = [
    "AdmissionBackpressure",
    "AdmissionTicket",
    "BudgetExhausted",
    "CommitMembrane",
    "CommitState",
    "ExactApprovalUnavailable",
    "ExportPassUnavailable",
    "InvalidTransition",
    "MembraneDisabled",
    "MembraneError",
    "OperationConflict",
    "OperationNotFound",
    "OperationSnapshot",
    "OperationSpec",
]
