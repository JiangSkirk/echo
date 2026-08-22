"""Parent-owned AppShell identity and browser-session persistence."""

from __future__ import annotations

import contextvars
import hashlib
import json
import secrets
import sqlite3
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal

from js.utils.db import db_connection

APPSHELL_SESSION_COOKIE = "js_appshell_session"
APPSHELL_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
APPSHELL_ACTIVE_OPERATION_LIMIT = 256
APPSHELL_SCOPE_MANAGED = "appshell_managed"
APPSHELL_SCOPE_PRINCIPAL = "appshell_principal"

AppShellMode = Literal["personal", "work"]


class AppShellSessionError(RuntimeError):
    """Base class for parent AppShell session failures."""


class AppShellSessionConflictError(AppShellSessionError):
    """The stored active mode no longer matches the caller's expectation."""


class AppShellOperationLimitError(AppShellSessionError):
    """The parent session already owns the maximum active operations."""


@dataclass(frozen=True)
class AppShellPrincipalV1:
    """The only identity accepted by children while parent-managed."""

    owner: str
    session: str
    active_mode: AppShellMode
    mode_roles: Mapping[str, str]
    workspace: str | None
    expires_at: float
    epoch: int = 0

    def auth_context(self) -> dict[str, Any]:
        role = self.mode_roles.get(self.active_mode)
        if not isinstance(role, str) or not role:
            raise PermissionError(f"principal has no {self.active_mode} role")
        return {
            "name": "appshell",
            "role": role,
            "key_hash": self.owner,
            "appshell_session": self.session,
            "appshell_mode": self.active_mode,
            "workspace_handle": self.workspace,
            "appshell_epoch": self.epoch,
        }

    def public_dict(self) -> dict[str, Any]:
        """Return the browser-safe shape; the physical owner hash stays server-side."""
        return {
            "schema": type(self).__name__,
            "session": self.session,
            "active_mode": self.active_mode,
            "mode_roles": dict(self.mode_roles),
            "workspace": self.workspace,
            "expires_at": self.expires_at,
            "epoch": self.epoch,
        }

    def epoch_binding(self) -> AppShellEpochBindingV1:
        """Freeze the trusted parent identity used by one admitted child request."""
        return AppShellEpochBindingV1(
            owner=self.owner,
            session=self.session,
            active_mode=self.active_mode,
            workspace=self.workspace,
            epoch=self.epoch,
        )


@dataclass(frozen=True)
class AppShellEpochBindingV1:
    """Immutable AppShell authority captured at child-request admission."""

    owner: str
    session: str
    active_mode: AppShellMode
    workspace: str | None
    epoch: int


@dataclass(frozen=True)
class AppShellOperationV1:
    """One authoritative old-epoch operation held until its real lifecycle ends."""

    operation_id: str
    binding: AppShellEpochBindingV1
    operation_kind: str
    started_at: float


_current_epoch_binding: contextvars.ContextVar[AppShellEpochBindingV1 | None] = (
    contextvars.ContextVar("appshell_epoch_binding", default=None)
)


def current_appshell_epoch_binding() -> AppShellEpochBindingV1 | None:
    return _current_epoch_binding.get(None)


def set_current_appshell_epoch_binding(
    binding: AppShellEpochBindingV1,
) -> contextvars.Token[AppShellEpochBindingV1 | None]:
    return _current_epoch_binding.set(binding)


def reset_current_appshell_epoch_binding(
    token: contextvars.Token[AppShellEpochBindingV1 | None],
) -> None:
    _current_epoch_binding.reset(token)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _add_column_if_missing(
    connection: sqlite3.Connection,
    *,
    table: str,
    column: str,
    definition: str,
) -> None:
    columns = {
        str(row[1])
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }
    if column in columns:
        return
    try:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    except sqlite3.OperationalError as exc:
        if str(exc).casefold() == f"duplicate column name: {column}".casefold():
            return
        raise


class AppShellSessionStore:
    """Persist opaque parent sessions without storing plaintext cookie tokens."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        with db_connection(self._db_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS appshell_sessions (
                    token_hash TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    session TEXT NOT NULL UNIQUE,
                    active_mode TEXT NOT NULL,
                    mode_roles_json TEXT NOT NULL,
                    workspace TEXT,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    epoch INTEGER NOT NULL DEFAULT 0,
                    admission_open INTEGER NOT NULL DEFAULT 1,
                    issuer TEXT,
                    generation TEXT
                )
                """
            )
            _add_column_if_missing(
                connection,
                table="appshell_sessions",
                column="epoch",
                definition="INTEGER NOT NULL DEFAULT 0",
            )
            _add_column_if_missing(
                connection,
                table="appshell_sessions",
                column="admission_open",
                definition="INTEGER NOT NULL DEFAULT 1",
            )
            _add_column_if_missing(
                connection,
                table="appshell_sessions",
                column="issuer",
                definition="TEXT",
            )
            _add_column_if_missing(
                connection,
                table="appshell_sessions",
                column="generation",
                definition="TEXT",
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_appshell_sessions_expiry "
                "ON appshell_sessions(expires_at)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_appshell_sessions_issuer "
                "ON appshell_sessions(issuer)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS appshell_operations (
                    operation_id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    session TEXT NOT NULL,
                    active_mode TEXT NOT NULL,
                    workspace TEXT,
                    epoch INTEGER NOT NULL,
                    operation_kind TEXT NOT NULL,
                    started_at REAL NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_appshell_operations_epoch "
                "ON appshell_operations(session, epoch)"
            )
            connection.execute(
                "DELETE FROM appshell_operations AS operation "
                "WHERE NOT EXISTS ("
                "SELECT 1 FROM appshell_sessions AS session "
                "WHERE session.session = operation.session)"
            )
            connection.commit()

    @staticmethod
    def _from_row(row: tuple[Any, ...]) -> AppShellPrincipalV1:
        owner, session, active_mode, roles_json, workspace, expires_at = row[:6]
        epoch = int(row[6]) if len(row) > 6 else 0
        roles = json.loads(str(roles_json))
        if active_mode not in {"personal", "work"} or not isinstance(roles, dict):
            raise AppShellSessionError("stored AppShell principal is invalid")
        normalized_roles = {
            str(mode): str(role)
            for mode, role in roles.items()
            if mode in {"personal", "work"} and isinstance(role, str) and role
        }
        return AppShellPrincipalV1(
            owner=str(owner),
            session=str(session),
            active_mode=active_mode,
            mode_roles=normalized_roles,
            workspace=str(workspace) if workspace is not None else None,
            expires_at=float(expires_at),
            epoch=epoch,
        )

    def create(
        self,
        *,
        owner: str,
        mode_roles: Mapping[str, str],
        ttl_seconds: int = APPSHELL_SESSION_TTL_SECONDS,
        issuer: str | None = None,
        generation: str | None = None,
    ) -> tuple[str, AppShellPrincipalV1]:
        if not owner or not mode_roles.get("personal"):
            raise ValueError("AppShell session requires a Personal owner and role")
        if (issuer is None) != (generation is None):
            raise ValueError("managed AppShell session requires issuer and generation")
        if issuer is not None and (not issuer.strip() or not generation or not generation.strip()):
            raise ValueError("managed AppShell session provenance is invalid")
        normalized_issuer = issuer.strip() if issuer is not None else None
        normalized_generation = generation.strip() if generation is not None else None
        token = "jsas_" + secrets.token_urlsafe(32)
        session = "appshell-" + secrets.token_hex(16)
        now = time.time()
        expires_at = now + ttl_seconds
        roles = {
            mode: role
            for mode, role in mode_roles.items()
            if mode in {"personal", "work"} and isinstance(role, str) and role
        }
        principal = AppShellPrincipalV1(
            owner=owner,
            session=session,
            active_mode="personal",
            mode_roles=roles,
            workspace=None,
            expires_at=expires_at,
            epoch=0,
        )
        with db_connection(self._db_path) as connection:
            connection.execute(
                "DELETE FROM appshell_operations WHERE session IN "
                "(SELECT session FROM appshell_sessions WHERE expires_at <= ?)",
                (now,),
            )
            connection.execute(
                "DELETE FROM appshell_sessions WHERE expires_at <= ?",
                (now,),
            )
            connection.execute(
                """
                INSERT INTO appshell_sessions
                (token_hash, owner, session, active_mode, mode_roles_json,
                 workspace, created_at, expires_at, epoch, issuer, generation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _token_hash(token),
                    owner,
                    session,
                    principal.active_mode,
                    json.dumps(roles, sort_keys=True, separators=(",", ":")),
                    None,
                    now,
                    expires_at,
                    0,
                    normalized_issuer,
                    normalized_generation,
                ),
            )
            connection.commit()
        return token, principal

    def revoke_issuer_sessions(
        self,
        *,
        issuer: str,
        legacy_owner_hashes: set[str] | None = None,
    ) -> list[str]:
        """Atomically revoke exact-issuer sessions and trusted legacy bindings."""
        if not isinstance(issuer, str) or not issuer.strip():
            raise ValueError("AppShell session issuer is required")
        normalized_issuer = issuer.strip()
        legacy_owners = sorted(legacy_owner_hashes or ())
        if any(not owner for owner in legacy_owners):
            raise ValueError("legacy AppShell owner is invalid")

        clauses = ["issuer = ?"]
        parameters: list[object] = [normalized_issuer]
        if legacy_owners:
            placeholders = ",".join("?" for _owner in legacy_owners)
            clauses.append(f"(issuer IS NULL AND owner IN ({placeholders}))")
            parameters.extend(legacy_owners)
        predicate = " OR ".join(clauses)

        with db_connection(self._db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            sessions = sorted(
                str(row[0])
                for row in connection.execute(
                    f"SELECT session FROM appshell_sessions WHERE {predicate}",
                    parameters,
                )
            )
            if sessions:
                placeholders = ",".join("?" for _session in sessions)
                connection.execute(
                    f"DELETE FROM appshell_operations WHERE session IN ({placeholders})",
                    sessions,
                )
                connection.execute(
                    f"DELETE FROM appshell_sessions WHERE session IN ({placeholders})",
                    sessions,
                )
            connection.commit()
        return sessions

    def resolve(self, token: str | None) -> AppShellPrincipalV1 | None:
        if not isinstance(token, str) or not token:
            return None
        token_digest = _token_hash(token)
        with db_connection(self._db_path) as connection:
            row = connection.execute(
                """
                SELECT owner, session, active_mode, mode_roles_json,
                       workspace, expires_at, epoch
                FROM appshell_sessions WHERE token_hash = ?
                """,
                (token_digest,),
            ).fetchone()
            if row is None:
                return None
            if float(row[5]) <= time.time():
                connection.execute("BEGIN IMMEDIATE")
                locked_row = connection.execute(
                    """
                    SELECT owner, session, active_mode, mode_roles_json,
                           workspace, expires_at, epoch
                    FROM appshell_sessions WHERE token_hash = ?
                    """,
                    (token_digest,),
                ).fetchone()
                if locked_row is None:
                    connection.rollback()
                    return None
                if float(locked_row[5]) > time.time():
                    connection.rollback()
                    row = locked_row
                else:
                    session = str(locked_row[1])
                    connection.execute(
                        "DELETE FROM appshell_operations WHERE session = ?",
                        (session,),
                    )
                    connection.execute(
                        "DELETE FROM appshell_sessions WHERE token_hash = ? "
                        "AND session = ?",
                        (token_digest, session),
                    )
                    connection.commit()
                    return None
        return self._from_row(row)

    def update_mode(
        self,
        token: str,
        *,
        expected_owner: str,
        expected_session: str,
        expected_from_mode: AppShellMode,
        expected_workspace: str | None,
        expected_epoch: int,
        to_mode: AppShellMode,
        workspace: str | None,
    ) -> AppShellPrincipalV1:
        token_digest = _token_hash(token)
        with db_connection(self._db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT owner, session, active_mode, mode_roles_json,
                       workspace, expires_at, epoch
                FROM appshell_sessions WHERE token_hash = ?
                """,
                (token_digest,),
            ).fetchone()
            if row is None or float(row[5]) <= time.time():
                connection.rollback()
                raise AppShellSessionError("AppShell session is missing or expired")
            principal = self._from_row(row)
            if (
                principal.owner != expected_owner
                or principal.session != expected_session
                or principal.active_mode != expected_from_mode
                or principal.workspace != expected_workspace
                or principal.epoch != expected_epoch
            ):
                connection.rollback()
                raise AppShellSessionConflictError(
                    "stored AppShell principal no longer matches the trusted switch snapshot"
                )
            if to_mode not in principal.mode_roles:
                connection.rollback()
                raise PermissionError(f"principal has no {to_mode} role")
            new_epoch = principal.epoch + 1
            cursor = connection.execute(
                "UPDATE appshell_sessions "
                "SET active_mode = ?, workspace = ?, epoch = ?, admission_open = 1 "
                "WHERE token_hash = ? AND owner = ? AND session = ? "
                "AND active_mode = ? AND workspace IS ? AND epoch = ? "
                "AND admission_open = 0 "
                "AND NOT EXISTS ("
                "SELECT 1 FROM appshell_operations AS operation "
                "WHERE operation.owner = ? AND operation.session = ? "
                "AND operation.active_mode = ? AND operation.workspace IS ? "
                "AND operation.epoch = ?)",
                (
                    to_mode,
                    workspace,
                    new_epoch,
                    token_digest,
                    expected_owner,
                    expected_session,
                    expected_from_mode,
                    expected_workspace,
                    expected_epoch,
                    expected_owner,
                    expected_session,
                    expected_from_mode,
                    expected_workspace,
                    expected_epoch,
                ),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise AppShellSessionConflictError(
                    "AppShell mode/epoch CAS lost its authoritative session"
                )
            connection.commit()
        return replace(principal, active_mode=to_mode, workspace=workspace, epoch=new_epoch)

    def close_epoch(self, token: str, binding: AppShellEpochBindingV1) -> None:
        """CAS-close admission before any departing-resource discovery."""
        token_digest = _token_hash(token)
        with db_connection(self._db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE appshell_sessions SET admission_open = 0 "
                "WHERE token_hash = ? AND owner = ? AND session = ? "
                "AND active_mode = ? AND workspace IS ? AND epoch = ? "
                "AND admission_open = 1 AND expires_at > ?",
                (
                    token_digest,
                    binding.owner,
                    binding.session,
                    binding.active_mode,
                    binding.workspace,
                    binding.epoch,
                    time.time(),
                ),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise AppShellSessionConflictError(
                    "AppShell epoch is already closed or no longer current"
                )
            connection.commit()

    def reopen_epoch(self, binding: AppShellEpochBindingV1) -> None:
        """Reopen the unchanged old epoch after a failed switch."""
        with db_connection(self._db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE appshell_sessions SET admission_open = 1 "
                "WHERE owner = ? AND session = ? AND active_mode = ? "
                "AND workspace IS ? AND epoch = ? AND admission_open = 0 "
                "AND expires_at > ?",
                (
                    binding.owner,
                    binding.session,
                    binding.active_mode,
                    binding.workspace,
                    binding.epoch,
                    time.time(),
                ),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise AppShellSessionConflictError(
                    "failed AppShell switch cannot reopen a changed session epoch"
                )
            connection.commit()

    def is_epoch_current(
        self,
        binding: AppShellEpochBindingV1,
        *,
        require_open: bool = True,
    ) -> bool:
        """Revalidate a captured binding against the authoritative session row."""
        admission_clause = " AND admission_open = 1" if require_open else ""
        with db_connection(self._db_path) as connection:
            row = connection.execute(
                "SELECT 1 FROM appshell_sessions "
                "WHERE owner = ? AND session = ? AND active_mode = ? "
                "AND workspace IS ? AND epoch = ? AND expires_at > ?"
                + admission_clause,
                (
                    binding.owner,
                    binding.session,
                    binding.active_mode,
                    binding.workspace,
                    binding.epoch,
                    time.time(),
                ),
            ).fetchone()
        return row is not None

    def require_epoch_current(self, binding: AppShellEpochBindingV1) -> None:
        if not self.is_epoch_current(binding):
            raise PermissionError("AppShell request epoch is closed or stale")

    def begin_operation(
        self,
        binding: AppShellEpochBindingV1,
        *,
        operation_kind: str,
    ) -> AppShellOperationV1:
        if (
            not isinstance(operation_kind, str)
            or not operation_kind.strip()
            or len(operation_kind) > 64
        ):
            raise ValueError("AppShell operation kind is invalid")
        operation = AppShellOperationV1(
            operation_id="jsao_" + secrets.token_hex(16),
            binding=binding,
            operation_kind=operation_kind,
            started_at=time.time(),
        )
        with db_connection(self._db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "INSERT INTO appshell_operations "
                "(operation_id, owner, session, active_mode, workspace, epoch, "
                "operation_kind, started_at) "
                "SELECT ?, ?, ?, ?, ?, ?, ?, ? "
                "WHERE EXISTS ("
                "SELECT 1 FROM appshell_sessions "
                "WHERE owner = ? AND session = ? AND active_mode = ? "
                "AND workspace IS ? AND epoch = ? AND admission_open = 1 "
                "AND expires_at > ?) "
                "AND (SELECT COUNT(*) FROM appshell_operations AS active_operation "
                "WHERE active_operation.session = ?) < ?",
                (
                    operation.operation_id,
                    binding.owner,
                    binding.session,
                    binding.active_mode,
                    binding.workspace,
                    binding.epoch,
                    operation.operation_kind,
                    operation.started_at,
                    binding.owner,
                    binding.session,
                    binding.active_mode,
                    binding.workspace,
                    binding.epoch,
                    time.time(),
                    binding.session,
                    APPSHELL_ACTIVE_OPERATION_LIMIT,
                ),
            )
            if cursor.rowcount != 1:
                current = connection.execute(
                    "SELECT 1 FROM appshell_sessions "
                    "WHERE owner = ? AND session = ? AND active_mode = ? "
                    "AND workspace IS ? AND epoch = ? AND admission_open = 1 "
                    "AND expires_at > ?",
                    (
                        binding.owner,
                        binding.session,
                        binding.active_mode,
                        binding.workspace,
                        binding.epoch,
                        time.time(),
                    ),
                ).fetchone()
                active_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM appshell_operations WHERE session = ?",
                        (binding.session,),
                    ).fetchone()[0]
                )
                connection.rollback()
                if current is None:
                    raise PermissionError("AppShell request epoch is closed or stale")
                if active_count >= APPSHELL_ACTIVE_OPERATION_LIMIT:
                    raise AppShellOperationLimitError(
                        "AppShell operation capacity is exhausted"
                    )
                raise AppShellSessionError("AppShell operation admission failed")
            connection.commit()
        return operation

    def release_operation(self, operation: AppShellOperationV1) -> bool:
        binding = operation.binding
        with db_connection(self._db_path) as connection:
            cursor = connection.execute(
                "DELETE FROM appshell_operations WHERE operation_id = ? "
                "AND owner = ? AND session = ? AND active_mode = ? "
                "AND workspace IS ? AND epoch = ? AND operation_kind = ?",
                (
                    operation.operation_id,
                    binding.owner,
                    binding.session,
                    binding.active_mode,
                    binding.workspace,
                    binding.epoch,
                    operation.operation_kind,
                ),
            )
            connection.commit()
        return cursor.rowcount == 1

    def active_operation_count(self, binding: AppShellEpochBindingV1) -> int:
        with db_connection(self._db_path) as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM appshell_operations "
                "WHERE owner = ? AND session = ? AND active_mode = ? "
                "AND workspace IS ? AND epoch = ?",
                (
                    binding.owner,
                    binding.session,
                    binding.active_mode,
                    binding.workspace,
                    binding.epoch,
                ),
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def revoke(self, token: str | None) -> bool:
        if not isinstance(token, str) or not token:
            return False
        with db_connection(self._db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT session FROM appshell_sessions WHERE token_hash = ?",
                (_token_hash(token),),
            ).fetchone()
            if row is None:
                connection.rollback()
                return False
            session = str(row[0])
            connection.execute(
                "DELETE FROM appshell_operations WHERE session = ?",
                (session,),
            )
            cursor = connection.execute(
                "DELETE FROM appshell_sessions WHERE token_hash = ? AND session = ?",
                (_token_hash(token), session),
            )
            connection.commit()
            return cursor.rowcount > 0


def appshell_principal_from_scope(
    scope: Mapping[str, Any],
) -> tuple[bool, AppShellPrincipalV1 | None]:
    """Return whether the scope is parent-managed and its trusted principal."""
    state = scope.get("state")
    if not isinstance(state, Mapping) or not state.get(APPSHELL_SCOPE_MANAGED):
        return False, None
    principal = state.get(APPSHELL_SCOPE_PRINCIPAL)
    if principal is not None and not isinstance(principal, AppShellPrincipalV1):
        return True, None
    return True, principal


def appshell_auth_context_from_scope(
    scope: Mapping[str, Any],
) -> tuple[bool, dict[str, Any] | None]:
    managed, principal = appshell_principal_from_scope(scope)
    if not managed or principal is None:
        return managed, None
    try:
        return True, principal.auth_context()
    except PermissionError:
        return True, None
