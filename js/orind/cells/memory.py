"""Strict Memory Cell for the explicit C3 harness only.

The Cell owns a private SQLite file.  Production ``js.memory.store`` and
``enhanced_store`` are not imported.  Owner / profile / session / task
isolation is fail-closed; SECRET and low-integrity rows cannot be washed
by a later summary write.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from js.orin.draft import (
    CellPackage,
    CommitPermit,
    Impact,
    StateWitness,
    seal_signed_effect_receipt,
)
from js.orin.protocol import ProtocolError, canonical_json
from js.orin.taint import SECRET
from js.orind.cells.base import CellBase

_WITNESS_TTL_MS: Final[int] = 60_000
_MAX_KEY: Final[int] = 256
_MAX_VALUE: Final[int] = 8_192
_SOURCES: Final[frozenset[str]] = frozenset({"user", "tool", "model", "system"})
_PROFILES: Final[frozenset[str]] = frozenset({"personal", "work"})


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _bounded(value: Any, name: str, *, max_len: int) -> str:
    if type(value) is not str or not value or len(value) > max_len:
        raise ProtocolError(f"{name} must be a bounded string")
    return value


@dataclass(frozen=True, slots=True)
class _Scope:
    owner_key_hash: str
    profile: str
    session_id: str
    task_id: str
    key: str


@dataclass(frozen=True, slots=True)
class MemoryPreflightResult:
    witness: StateWitness
    projection: dict[str, Any]


class MemoryCell(CellBase):
    """``cell.memory`` strict package executor for the C3 test harness."""

    def __init__(
        self,
        *,
        socket_path: Path,
        state_dir: Path,
        mac_key: bytes,
        private_state_dir: Path | None = None,
    ) -> None:
        if not isinstance(mac_key, bytes) or len(mac_key) != 32:
            raise ProtocolError("Memory Cell mac key must be 32 bytes")
        self._mac_key = mac_key
        db_root = private_state_dir if private_state_dir is not None else state_dir
        db_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._db_path = db_root / "memory-cell.db"
        if not self._db_path.exists():
            fd = os.open(self._db_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(fd)
        mode = self._db_path.stat().st_mode
        if stat.S_ISLNK(mode) or (mode & 0o777) != 0o600:
            raise ProtocolError("memory cell database is not a private 0600 file")
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS memories (
                record_id TEXT PRIMARY KEY,
                owner_key_hash TEXT NOT NULL,
                profile TEXT NOT NULL,
                session_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL,
                taint INTEGER NOT NULL,
                clearance INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                UNIQUE(owner_key_hash, profile, session_id, task_id, key)
            );
            CREATE TABLE IF NOT EXISTS commits (
                draft_id TEXT PRIMARY KEY,
                effect_hash TEXT NOT NULL,
                record_id TEXT NOT NULL,
                state TEXT NOT NULL
            );
            """
        )
        self._conn.commit()
        super().__init__(
            cap="cell.memory",
            socket_path=socket_path,
            state_dir=state_dir,
            handler=self._commit_package,
            preflight_handler=self._preflight_package,
            reconcile_handler=self._reconcile_effect,
            strict_effect_protocol=True,
        )

    def _scope(self, package: CellPackage) -> _Scope:
        args = package.draft.arguments
        if not isinstance(args, dict):
            raise ProtocolError("memory arguments must be an object")
        profile = args.get("profile")
        if profile not in _PROFILES:
            raise ProtocolError("memory profile is invalid")
        task_id = _bounded(package.draft.task_id, "task_id", max_len=256)
        if args.get("task_id") not in {None, task_id}:
            raise ProtocolError("memory task_id does not match the draft")
        return _Scope(
            owner_key_hash=_bounded(args.get("owner_key_hash"), "owner_key_hash", max_len=80),
            profile=str(profile),
            session_id=_bounded(args.get("session_id"), "session_id", max_len=256),
            task_id=task_id,
            key=_bounded(args.get("key"), "key", max_len=_MAX_KEY),
        )

    def _row(self, scope: _Scope) -> tuple[Any, ...] | None:
        fetched = self._conn.execute(
            "SELECT record_id, value, source, taint, clearance FROM memories "
            "WHERE owner_key_hash = ? AND profile = ? AND session_id = ? "
            "AND task_id = ? AND key = ?",
            (scope.owner_key_hash, scope.profile, scope.session_id, scope.task_id, scope.key),
        ).fetchone()
        return tuple(fetched) if fetched is not None else None

    def _project_row(
        self,
        row: tuple[Any, ...],
        *,
        clearance: int,
    ) -> dict[str, Any]:
        record_id, value, source, taint, stored_clearance = row
        secret = bool(int(taint) & SECRET) or int(stored_clearance) >= 2
        if secret and clearance < 2:
            return {
                "status": "REDACTED",
                "record_id": str(record_id),
                "source": str(source),
                "taint": int(taint),
                "clearance": int(stored_clearance),
            }
        return {
            "status": "READ",
            "record_id": str(record_id),
            "value": str(value),
            "source": str(source),
            "taint": int(taint),
            "clearance": int(stored_clearance),
        }

    def _new_witness(
        self,
        package: CellPackage,
        *,
        target_version: str,
        material: dict[str, Any],
        writes: int,
    ) -> StateWitness:
        now = _now_ms()
        witness_id = (
            "state:"
            + hmac.new(
                self._mac_key,
                canonical_json(material).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        )
        return StateWitness(
            witness_id=witness_id,
            draft_id=package.draft.draft_id,
            executor_id=package.executor_id,
            target_version=target_version,
            canonical_effect_hash=package.canonical_effect_hash,
            impact=Impact(writes=writes),
            reversibility=(
                "reversible_until_stage" if writes == 0 else "irreversible_after_provider_accept"
            ),
            idempotency_support="query_only" if writes == 0 else "client_key",
            created_at_ms=now,
            expires_at_ms=now + _WITNESS_TTL_MS,
        )

    def _preflight_package(self, package: CellPackage) -> MemoryPreflightResult:
        package.validate_binding()
        if package.executor_id != "cell.memory":
            raise ProtocolError("Memory Cell executor mismatch")
        effect = package.draft.effect_type
        if effect == "memory.read":
            return self._preflight_read(package)
        if effect in {"memory.write", "memory.mutate"}:
            return self._preflight_write(package)
        raise ProtocolError("Memory Cell accepts only memory.read/write/mutate")

    def _preflight_read(self, package: CellPackage) -> MemoryPreflightResult:
        scope = self._scope(package)
        row = self._row(scope)
        projection = (
            self._project_row(row, clearance=package.clearance)
            if row is not None
            else {"status": "ABSENT", "key": scope.key}
        )
        material = {
            "schema": "MemoryReadV1",
            "draft_id": package.draft.draft_id,
            "scope": [
                scope.owner_key_hash,
                scope.profile,
                scope.session_id,
                scope.task_id,
                scope.key,
            ],
            "status": projection["status"],
        }
        witness = self._new_witness(
            package,
            target_version="memory:" + _sha256(canonical_json(material).encode("utf-8")),
            material=material,
            writes=0,
        )
        return MemoryPreflightResult(witness=witness, projection=projection)

    def _write_fields(
        self,
        package: CellPackage,
    ) -> tuple[_Scope, str, str, int, int, tuple[Any, ...] | None]:
        scope = self._scope(package)
        args = package.draft.arguments
        value = _bounded(args.get("value"), "value", max_len=_MAX_VALUE)
        source = args.get("source")
        if source not in _SOURCES:
            raise ProtocolError("memory source is invalid")
        taint = args.get("taint", 0)
        clearance = args.get("clearance", package.clearance)
        if type(taint) is not int or isinstance(taint, bool) or taint < 0:
            raise ProtocolError("memory taint is invalid")
        if clearance not in {0, 1, 2}:
            raise ProtocolError("memory clearance is invalid")
        existing = self._row(scope)
        if package.draft.effect_type == "memory.write" and existing is not None:
            raise ProtocolError("memory.write refuses to overwrite an existing key")
        if package.draft.effect_type == "memory.mutate" and existing is None:
            raise ProtocolError("memory.mutate requires an existing key")
        if existing is not None:
            _record_id, _value, _source, old_taint, old_clearance = existing
            if (int(old_taint) & SECRET) and not (int(taint) & SECRET):
                raise ProtocolError("SECRET memory cannot be washed")
            if int(old_clearance) > int(clearance):
                raise ProtocolError("memory clearance cannot be lowered")
            if int(old_taint) & ~int(taint):
                raise ProtocolError("memory taint bits cannot be dropped")
        return scope, value, str(source), int(taint), int(clearance), existing

    def _preflight_write(self, package: CellPackage) -> MemoryPreflightResult:
        scope, value, source, taint, clearance, _existing = self._write_fields(package)
        material = {
            "schema": "MemoryWriteV1",
            "draft_id": package.draft.draft_id,
            "effect_type": package.draft.effect_type,
            "scope": [
                scope.owner_key_hash,
                scope.profile,
                scope.session_id,
                scope.task_id,
                scope.key,
            ],
            "value_digest": _sha256(value.encode("utf-8")),
            "source": source,
            "taint": taint,
            "clearance": clearance,
        }
        witness = self._new_witness(
            package,
            target_version="memory:" + _sha256(canonical_json(material).encode("utf-8")),
            material=material,
            writes=1,
        )
        return MemoryPreflightResult(
            witness=witness,
            projection={
                "status": "PREPARED",
                "key": scope.key,
                "effect": package.draft.effect_type,
            },
        )

    def _commit_package(self, permit: CommitPermit, package: CellPackage) -> dict[str, Any]:
        package.validate_binding(permit, require_witness=True)
        if package.draft.effect_type not in {"memory.write", "memory.mutate"}:
            raise ProtocolError("Memory Cell commit accepts only write/mutate")
        existing_commit = self._conn.execute(
            "SELECT state, record_id FROM commits WHERE draft_id = ?",
            (package.draft.draft_id,),
        ).fetchone()
        if existing_commit is not None:
            if existing_commit[0] == "committed":
                return {
                    "status": "COMMITTED",
                    "duplicate": True,
                    "record_id": str(existing_commit[1]),
                }
            return {"status": "UNKNOWN_COMMIT", "record_id": str(existing_commit[1])}
        scope, value, source, taint, clearance, _existing = self._write_fields(package)
        now = _now_ms()
        record_id = "memory:" + _sha256(
            canonical_json(
                [scope.owner_key_hash, scope.profile, scope.session_id, scope.task_id, scope.key]
            ).encode("utf-8")
        )
        self._conn.execute(
            "INSERT INTO commits(draft_id, effect_hash, record_id, state) VALUES (?, ?, ?, ?)",
            (package.draft.draft_id, package.canonical_effect_hash, record_id, "unknown"),
        )
        self._conn.commit()
        if package.draft.effect_type == "memory.write":
            self._conn.execute(
                "INSERT INTO memories("
                "record_id, owner_key_hash, profile, session_id, task_id, key, "
                "value, source, taint, clearance, created_at_ms, updated_at_ms"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record_id,
                    scope.owner_key_hash,
                    scope.profile,
                    scope.session_id,
                    scope.task_id,
                    scope.key,
                    value,
                    source,
                    taint,
                    clearance,
                    now,
                    now,
                ),
            )
        else:
            updated = self._conn.execute(
                "UPDATE memories SET value = ?, source = ?, taint = ?, clearance = ?, "
                "updated_at_ms = ? WHERE owner_key_hash = ? AND profile = ? "
                "AND session_id = ? AND task_id = ? AND key = ?",
                (
                    value,
                    source,
                    taint,
                    clearance,
                    now,
                    scope.owner_key_hash,
                    scope.profile,
                    scope.session_id,
                    scope.task_id,
                    scope.key,
                ),
            )
            if updated.rowcount != 1:
                self._conn.commit()
                raise ProtocolError("memory.mutate target disappeared")
            existing = self._row(scope)
            record_id = str(existing[0]) if existing is not None else record_id
        self._conn.execute(
            "UPDATE commits SET state = 'committed' WHERE draft_id = ?",
            (package.draft.draft_id,),
        )
        self._conn.commit()
        public = {"status": "COMMITTED", "record_id": record_id, "duplicate": False}
        finished_at_ms = _now_ms()
        public["signed_receipt"] = seal_signed_effect_receipt(
            mac_key=self._mac_key,
            permit_id=permit.permit_id,
            executor_id="cell.memory",
            status="COMMITTED",
            canonical_effect_hash=package.canonical_effect_hash,
            result_digest=_sha256(
                canonical_json(
                    {key: public[key] for key in public if key != "signed_receipt"}
                ).encode("utf-8")
            ),
            started_at_ms=now,
            finished_at_ms=finished_at_ms,
            receipt_id="receipt:"
            + hmac.new(
                self._mac_key,
                canonical_json(["orin:memory-receipt:v1", permit.permit_id, record_id]).encode(
                    "utf-8"
                ),
                hashlib.sha256,
            ).hexdigest(),
        )
        return public

    def _reconcile_effect(self, effect_id: str, probe: dict[str, Any]) -> dict[str, str]:
        try:
            draft_id = probe.get("draft_id") if isinstance(probe, dict) else None
            key = str(draft_id or effect_id)
            row = self._conn.execute(
                "SELECT state FROM commits WHERE draft_id = ?",
                (key,),
            ).fetchone()
            if row is None:
                return {"state": "PREPARED"}
            if row[0] == "committed":
                return {"state": "COMMITTED"}
            return {"state": "UNKNOWN_COMMIT"}
        except Exception:  # noqa: BLE001 - reconciliation is fail-closed
            return {"state": "unknown"}


def main() -> None:  # pragma: no cover - subprocess entry
    socket_path = os.environ.get("ORIN_CELLS_SOCKET")
    state_dir_env = os.environ.get("ORIN_STATE_DIR")
    if not socket_path or not state_dir_env:
        raise SystemExit("ORIN_CELLS_SOCKET and ORIN_STATE_DIR are required")
    from js.orind.keybox import KeyBox

    state_dir = Path(state_dir_env)
    private_state_env = os.environ.get("ORIN_CELL_PRIVATE_STATE")
    if not private_state_env:
        raise SystemExit("ORIN_CELL_PRIVATE_STATE is required")
    cell_state = Path(private_state_env)
    strict_paths = os.environ.get("ORIN_CELL_IDENTITY_ENFORCE") == "1"
    keybox_tier = os.environ.get("ORIN_KEYBOX_TIER")
    if strict_paths and keybox_tier not in {"dev", "production"}:
        raise SystemExit("ORIN_KEYBOX_TIER must be explicit in Cell identity enforce mode")
    keybox = KeyBox(
        state_dir,
        tier=keybox_tier or "dev",
        strict_paths=strict_paths,
    )
    cell = MemoryCell(
        socket_path=Path(socket_path),
        state_dir=state_dir,
        private_state_dir=cell_state,
        mac_key=keybox.key,
    )
    cell.start()
    try:
        while True:
            time.sleep(1)
            if not cell.healthy():
                raise SystemExit("Memory Cell became unhealthy")
    except KeyboardInterrupt:
        pass
    finally:
        cell.stop()


if __name__ == "__main__":  # pragma: no cover
    main()


__all__ = ["MemoryCell", "MemoryPreflightResult"]
