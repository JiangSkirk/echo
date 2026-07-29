from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
import stat
import tempfile
import threading
import weakref
from collections.abc import Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final

_FORMAT: Final = "echo-sqlite-archive"
_SCHEMA_VERSION: Final = 1
_DEFAULT_BUSY_TIMEOUT_MS: Final = 5_000
_CACHE_SIZE_KIB: Final = 64
_RECORD_SNAPSHOT_MEMORY_BYTES: Final = 64 * 1024
_MAX_IDENTIFIER_LENGTH: Final = 512
_MAX_SQLITE_INTEGER: Final = (1 << 63) - 1
_HASH_SIZE: Final = hashlib.sha256().digest_size
_STORE_ID_SIZE: Final = 16
_ZERO_HASH: Final = bytes(_HASH_SIZE)
_STRING_LIKE: Final = (str, bytes, bytearray)

_FileFingerprint = tuple[int, int, int, int, int]
_ArchiveFingerprint = tuple[
    _FileFingerprint,
    _FileFingerprint | None,
    _FileFingerprint | None,
]


class ArchiveStoreError(RuntimeError):
    """The archive cannot safely complete the requested operation."""


class ArchiveConflictError(ArchiveStoreError):
    """An immutable generation already exists with a different delta."""


@dataclass(frozen=True, slots=True)
class ArchiveRecord:
    """The complete journal semantics retained by an archive record."""

    record_type: str
    tenant_id: str
    run_id: str
    payload: object


@dataclass(frozen=True, slots=True)
class ArchiveManifestRef:
    """A fixed-field authenticated anchor for one immutable generation."""

    format: str
    schema_version: int
    store_id: bytes
    tenant_id: str
    generation: int
    prev_manifest_hash: bytes
    first_seq: int
    added_record_count: int
    cumulative_record_count: int
    archive_tip_hash: bytes
    added_tombstone_count: int
    cumulative_tombstone_count: int
    tombstone_tip_hash: bytes
    manifest_hash: bytes
    mac: bytes


@dataclass(frozen=True, slots=True)
class ArchiveManifest:
    """Authenticated state committed by one archive generation."""

    format: str
    schema_version: int
    store_id: bytes
    tenant_id: str
    generation: int
    prev_manifest_hash: bytes
    first_seq: int
    added_record_count: int
    cumulative_record_count: int
    archive_tip_hash: bytes
    added_tombstone_count: int
    cumulative_tombstone_count: int
    tombstone_tip_hash: bytes
    manifest_hash: bytes
    mac: bytes

    def to_ref(self) -> ArchiveManifestRef:
        return ArchiveManifestRef(
            format=self.format,
            schema_version=self.schema_version,
            store_id=self.store_id,
            tenant_id=self.tenant_id,
            generation=self.generation,
            prev_manifest_hash=self.prev_manifest_hash,
            first_seq=self.first_seq,
            added_record_count=self.added_record_count,
            cumulative_record_count=self.cumulative_record_count,
            archive_tip_hash=self.archive_tip_hash,
            added_tombstone_count=self.added_tombstone_count,
            cumulative_tombstone_count=self.cumulative_tombstone_count,
            tombstone_tip_hash=self.tombstone_tip_hash,
            manifest_hash=self.manifest_hash,
            mac=self.mac,
        )


@dataclass(frozen=True, slots=True)
class _PreparedRecord:
    record_type: str
    tenant_id: str
    run_id: str
    canonical_payload: str


@dataclass(frozen=True, slots=True)
class _StoredRecord:
    sequence: int
    generation: int
    record_type: str
    tenant_id: str
    run_id: str
    canonical_payload: str
    prev_hash: bytes
    prev_mac: bytes
    record_hash: bytes
    mac: bytes


@dataclass(frozen=True, slots=True)
class _StoredTombstone:
    sequence: int
    generation: int
    effect_id: str
    prev_hash: bytes
    prev_mac: bytes
    tombstone_hash: bytes
    mac: bytes


class _SnapshotRecordIterator(Iterator[ArchiveRecord]):
    __slots__ = ("_cleanup_pending", "_closed", "_lock", "_snapshot")

    def __init__(self, snapshot: IO[str]) -> None:
        self._snapshot = snapshot
        self._closed = False
        self._cleanup_pending = True
        self._lock = threading.RLock()

    def __iter__(self) -> _SnapshotRecordIterator:
        return self

    def __next__(self) -> ArchiveRecord:
        with self._lock:
            if self._closed:
                raise StopIteration
            try:
                line = next(self._snapshot)
            except StopIteration:
                self._close_locked()
                raise
            except (OSError, ValueError) as exc:
                self._close_quietly_locked()
                raise ArchiveStoreError("archive record snapshot is invalid") from exc
            try:
                return _snapshot_record_from_line(line)
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                self._close_quietly_locked()
                raise ArchiveStoreError("archive record snapshot is invalid") from exc

    def close(self) -> None:
        with self._lock:
            self._close_locked()

    def _close_locked(self) -> None:
        if self._closed and not self._cleanup_pending:
            return
        self._closed = True
        try:
            self._snapshot.close()
        except (OSError, ValueError) as exc:
            raise ArchiveStoreError("archive record snapshot close failed") from exc
        self._cleanup_pending = False

    def _close_quietly(self) -> None:
        with self._lock:
            self._close_quietly_locked()

    def _close_quietly_locked(self) -> None:
        self._closed = True
        if not self._cleanup_pending:
            return
        with suppress(OSError, ValueError):
            self._snapshot.close()
            self._cleanup_pending = False

    def __del__(self) -> None:
        with suppress(Exception):
            self._close_quietly()


class _PathLock:
    __slots__ = ("lock", "__weakref__")

    def __init__(self) -> None:
        self.lock = threading.RLock()


_PATH_LOCKS: weakref.WeakValueDictionary[Path, _PathLock] = weakref.WeakValueDictionary()
_PATH_LOCKS_GUARD = threading.Lock()


_CREATE_TABLES: Final = (
    """
    CREATE TABLE archive_meta (
        singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
        format TEXT NOT NULL,
        schema_version INTEGER NOT NULL CHECK (schema_version = 1),
        store_id BLOB NOT NULL CHECK (length(store_id) = 16),
        tenant_id TEXT NOT NULL,
        key_commitment BLOB NOT NULL CHECK (length(key_commitment) = 32)
    ) STRICT
    """,
    """
    CREATE TABLE archive_manifests (
        generation INTEGER NOT NULL PRIMARY KEY CHECK (generation >= 1),
        format TEXT NOT NULL,
        schema_version INTEGER NOT NULL CHECK (schema_version = 1),
        store_id BLOB NOT NULL CHECK (length(store_id) = 16),
        tenant_id TEXT NOT NULL,
        prev_manifest_hash BLOB NOT NULL CHECK (length(prev_manifest_hash) = 32),
        first_seq INTEGER NOT NULL CHECK (first_seq >= 1),
        added_record_count INTEGER NOT NULL CHECK (added_record_count >= 0),
        cumulative_record_count INTEGER NOT NULL CHECK (cumulative_record_count >= 0),
        archive_tip_hash BLOB NOT NULL CHECK (length(archive_tip_hash) = 32),
        added_tombstone_count INTEGER NOT NULL CHECK (added_tombstone_count >= 0),
        cumulative_tombstone_count INTEGER NOT NULL CHECK (cumulative_tombstone_count >= 0),
        tombstone_tip_hash BLOB NOT NULL CHECK (length(tombstone_tip_hash) = 32),
        manifest_hash BLOB NOT NULL UNIQUE CHECK (length(manifest_hash) = 32),
        mac BLOB NOT NULL CHECK (length(mac) = 32)
    ) STRICT
    """,
    """
    CREATE TABLE archive_records (
        sequence INTEGER NOT NULL PRIMARY KEY CHECK (sequence >= 1),
        generation INTEGER NOT NULL CHECK (generation >= 1),
        record_type TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        canonical_payload TEXT NOT NULL,
        prev_hash BLOB NOT NULL CHECK (length(prev_hash) = 32),
        prev_mac BLOB NOT NULL CHECK (length(prev_mac) = 32),
        record_hash BLOB NOT NULL UNIQUE CHECK (length(record_hash) = 32),
        mac BLOB NOT NULL CHECK (length(mac) = 32),
        FOREIGN KEY (generation) REFERENCES archive_manifests (generation)
    ) STRICT
    """,
    """
    CREATE TABLE archive_tombstones (
        sequence INTEGER NOT NULL PRIMARY KEY CHECK (sequence >= 1),
        generation INTEGER NOT NULL CHECK (generation >= 1),
        effect_id TEXT NOT NULL COLLATE BINARY UNIQUE,
        prev_hash BLOB NOT NULL CHECK (length(prev_hash) = 32),
        prev_mac BLOB NOT NULL CHECK (length(prev_mac) = 32),
        tombstone_hash BLOB NOT NULL UNIQUE CHECK (length(tombstone_hash) = 32),
        mac BLOB NOT NULL CHECK (length(mac) = 32),
        FOREIGN KEY (generation) REFERENCES archive_manifests (generation)
    ) STRICT
    """,
    "CREATE INDEX archive_records_by_generation_sequence ON archive_records (generation, sequence)",
    "CREATE INDEX archive_tombstones_by_generation_sequence "
    "ON archive_tombstones (generation, sequence)",
)

_EXPECTED_COLUMNS: Final = {
    "archive_meta": (
        ("singleton", "INTEGER", 1, 1),
        ("format", "TEXT", 1, 0),
        ("schema_version", "INTEGER", 1, 0),
        ("store_id", "BLOB", 1, 0),
        ("tenant_id", "TEXT", 1, 0),
        ("key_commitment", "BLOB", 1, 0),
    ),
    "archive_manifests": (
        ("generation", "INTEGER", 1, 1),
        ("format", "TEXT", 1, 0),
        ("schema_version", "INTEGER", 1, 0),
        ("store_id", "BLOB", 1, 0),
        ("tenant_id", "TEXT", 1, 0),
        ("prev_manifest_hash", "BLOB", 1, 0),
        ("first_seq", "INTEGER", 1, 0),
        ("added_record_count", "INTEGER", 1, 0),
        ("cumulative_record_count", "INTEGER", 1, 0),
        ("archive_tip_hash", "BLOB", 1, 0),
        ("added_tombstone_count", "INTEGER", 1, 0),
        ("cumulative_tombstone_count", "INTEGER", 1, 0),
        ("tombstone_tip_hash", "BLOB", 1, 0),
        ("manifest_hash", "BLOB", 1, 0),
        ("mac", "BLOB", 1, 0),
    ),
    "archive_records": (
        ("sequence", "INTEGER", 1, 1),
        ("generation", "INTEGER", 1, 0),
        ("record_type", "TEXT", 1, 0),
        ("tenant_id", "TEXT", 1, 0),
        ("run_id", "TEXT", 1, 0),
        ("canonical_payload", "TEXT", 1, 0),
        ("prev_hash", "BLOB", 1, 0),
        ("prev_mac", "BLOB", 1, 0),
        ("record_hash", "BLOB", 1, 0),
        ("mac", "BLOB", 1, 0),
    ),
    "archive_tombstones": (
        ("sequence", "INTEGER", 1, 1),
        ("generation", "INTEGER", 1, 0),
        ("effect_id", "TEXT", 1, 0),
        ("prev_hash", "BLOB", 1, 0),
        ("prev_mac", "BLOB", 1, 0),
        ("tombstone_hash", "BLOB", 1, 0),
        ("mac", "BLOB", 1, 0),
    ),
}


class ArchiveStore:
    """Authenticated immutable archive generations for one store and tenant."""

    def __init__(
        self,
        path: Path | str,
        *,
        tenant_id: str,
        mac_key: bytes,
        busy_timeout_ms: int = _DEFAULT_BUSY_TIMEOUT_MS,
    ) -> None:
        self._path = _validate_database_path(path)
        self._tenant_id = _validate_identifier(tenant_id, field="tenant_id")
        self._mac_key = _validate_mac_key(mac_key)
        self._busy_timeout_ms = _validate_timeout(busy_timeout_ms)
        self._verified_snapshot: tuple[ArchiveManifestRef, _ArchiveFingerprint] | None = None
        self._store_id = self._initialize_store()

    def prepare_generation(
        self,
        base_ref: ArchiveManifestRef | None,
        records: Iterable[ArchiveRecord],
        tombstones: Iterable[str],
    ) -> ArchiveManifestRef:
        """Atomically prepare the next immutable generation from an anchored base."""
        if base_ref is not None and not isinstance(base_ref, ArchiveManifestRef):
            raise TypeError("base_ref must be an ArchiveManifestRef or None")
        prepared_records = _iter_prepared_records(records, tenant_id=self._tenant_id)
        prepared_tombstones = _prepare_tombstones(tombstones)

        try:
            with self._write_transaction() as connection:
                self._validate_schema_and_meta(connection)
                base_generation = 0
                base_manifest_hash = _ZERO_HASH
                base_record_count = 0
                base_record_tip = _ZERO_HASH
                base_tombstone_count = 0
                base_tombstone_tip = _ZERO_HASH

                if base_ref is not None:
                    if not self._verify_ref_in_transaction(connection, base_ref):
                        self._verified_snapshot = None
                        raise ArchiveStoreError("base reference verification failed")
                    base_generation = base_ref.generation
                    base_manifest_hash = base_ref.manifest_hash
                    base_record_count = base_ref.cumulative_record_count
                    base_record_tip = base_ref.archive_tip_hash
                    base_tombstone_count = base_ref.cumulative_tombstone_count
                    base_tombstone_tip = base_ref.tombstone_tip_hash

                canonical_tombstones = self._new_tombstones_at_base(
                    connection,
                    prepared_tombstones,
                    base_generation,
                )
                target_generation = base_generation + 1
                existing_row = connection.execute(
                    "SELECT * FROM archive_manifests WHERE generation = ?",
                    (target_generation,),
                ).fetchone()
                if existing_row is not None:
                    existing = _manifest_from_row(existing_row)
                    if not self._verify_ref_in_transaction(connection, existing.to_ref()):
                        self._verified_snapshot = None
                        raise ArchiveStoreError("existing generation verification failed")
                    if self._generation_matches_delta(
                        connection,
                        existing,
                        base_manifest_hash,
                        prepared_records,
                        canonical_tombstones,
                    ):
                        prepared_ref = existing.to_ref()
                    else:
                        raise ArchiveConflictError(
                            f"generation {target_generation} conflict: immutable content differs"
                        )
                else:
                    future = connection.execute(
                        "SELECT 1 FROM archive_manifests WHERE generation > ? LIMIT 1",
                        (target_generation,),
                    ).fetchone()
                    if future is not None:
                        raise ArchiveConflictError("generation conflict: archive contains a gap")

                if existing_row is None:
                    connection.execute("PRAGMA defer_foreign_keys = ON")
                    previous_record_mac = self._tip_mac(
                        connection,
                        table="archive_records",
                        sequence=base_record_count,
                    )
                    previous_tombstone_mac = self._tip_mac(
                        connection,
                        table="archive_tombstones",
                        sequence=base_tombstone_count,
                    )
                    added_record_count, archive_tip = self._insert_record_rows(
                        connection,
                        target_generation,
                        base_record_count,
                        base_record_tip,
                        previous_record_mac,
                        prepared_records,
                    )
                    added_tombstone_count, tombstone_tip = self._insert_tombstone_rows(
                        connection,
                        target_generation,
                        base_tombstone_count,
                        base_tombstone_tip,
                        previous_tombstone_mac,
                        canonical_tombstones,
                    )
                    manifest = self._make_manifest(
                        generation=target_generation,
                        prev_manifest_hash=base_manifest_hash,
                        first_seq=base_record_count + 1,
                        added_record_count=added_record_count,
                        cumulative_record_count=base_record_count + added_record_count,
                        archive_tip_hash=archive_tip,
                        added_tombstone_count=added_tombstone_count,
                        cumulative_tombstone_count=base_tombstone_count + added_tombstone_count,
                        tombstone_tip_hash=tombstone_tip,
                    )
                    self._insert_manifest(connection, manifest)
                    prepared_ref = manifest.to_ref()
            self._verified_snapshot = None
            if not self.verify(prepared_ref):
                raise ArchiveStoreError("committed generation verification failed")
            return prepared_ref
        except sqlite3.Error as exc:
            self._verified_snapshot = None
            raise ArchiveStoreError("archive generation write failed") from exc

    def verify(self, ref: ArchiveManifestRef) -> bool:
        """Verify the complete archive history anchored by ref in one read snapshot."""
        if not isinstance(ref, ArchiveManifestRef):
            return False
        try:
            for _attempt in range(3):
                before = _archive_fingerprint(self._path)
                with self._read_transaction() as connection:
                    verified = self._verify_ref_in_transaction(
                        connection,
                        ref,
                        fingerprint=before,
                    )
                after = _archive_fingerprint(self._path)
                if before == after:
                    if verified:
                        self._verified_snapshot = (ref, after)
                    else:
                        self._verified_snapshot = None
                    return verified
                self._verified_snapshot = None
            return False
        except (ArchiveStoreError, sqlite3.Error, TypeError, ValueError, json.JSONDecodeError):
            self._verified_snapshot = None
            return False

    def contains_effect(self, effect_id: str, ref: ArchiveManifestRef) -> bool:
        """Query an exact tombstone only after verifying ref in the same snapshot."""
        validated_effect_id = _validate_identifier(effect_id, field="effect_id")
        if not isinstance(ref, ArchiveManifestRef):
            raise ArchiveStoreError("reference verification failed")
        try:
            for _attempt in range(3):
                before = _archive_fingerprint(self._path)
                with self._read_transaction() as connection:
                    cached = self._verified_snapshot
                    if cached is not None and cached == (ref, before):
                        verified = self._verify_cached_ref_in_transaction(connection, ref)
                    else:
                        verified = self._verify_in_transaction(connection, ref)
                    if not verified:
                        raise ArchiveStoreError("reference verification failed")
                    row = connection.execute(
                        "SELECT 1 FROM archive_tombstones "
                        "WHERE effect_id = ? AND generation <= ? LIMIT 1",
                        (validated_effect_id, ref.generation),
                    ).fetchone()
                    found = row is not None
                after = _archive_fingerprint(self._path)
                if before == after:
                    self._verified_snapshot = (ref, after)
                    return found
                self._verified_snapshot = None
            raise ArchiveStoreError("archive changed during effect query")
        except ArchiveStoreError:
            raise
        except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError) as exc:
            self._verified_snapshot = None
            raise ArchiveStoreError("archive effect query failed closed") from exc

    def iter_records(self, ref: ArchiveManifestRef) -> Iterator[ArchiveRecord]:
        """Return records anchored by ref after verification in the same snapshot."""
        if not isinstance(ref, ArchiveManifestRef):
            raise ArchiveStoreError("reference verification failed")
        try:
            snapshot = tempfile.SpooledTemporaryFile(  # noqa: SIM115 - iterator owns cleanup
                max_size=_RECORD_SNAPSHOT_MEMORY_BYTES,
                mode="w+t",
                encoding="utf-8",
                newline="\n",
            )
        except OSError as exc:
            raise ArchiveStoreError("archive record iteration failed closed") from exc
        try:
            for _attempt in range(3):
                snapshot.seek(0)
                snapshot.truncate()
                before = _archive_fingerprint(self._path)
                with self._read_transaction() as connection:
                    if not self._verify_ref_in_transaction(connection, ref, fingerprint=before):
                        raise ArchiveStoreError("reference verification failed")
                    if before != _archive_fingerprint(self._path):
                        self._verified_snapshot = None
                        continue
                    rows = connection.execute(
                        "SELECT record_type, tenant_id, run_id, canonical_payload "
                        "FROM archive_records WHERE generation <= ? ORDER BY sequence",
                        (ref.generation,),
                    )
                    for row in rows:
                        snapshot.write(
                            json.dumps(
                                (
                                    _require_str(row[0], field="record_type"),
                                    _require_str(row[1], field="tenant_id"),
                                    _require_str(row[2], field="run_id"),
                                    _require_str(row[3], field="canonical_payload"),
                                ),
                                ensure_ascii=False,
                                separators=(",", ":"),
                            )
                            + "\n"
                        )
                after = _archive_fingerprint(self._path)
                if before == after:
                    self._verified_snapshot = (ref, after)
                    snapshot.seek(0)
                    return _SnapshotRecordIterator(snapshot)
                self._verified_snapshot = None
            raise ArchiveStoreError("archive changed during record iteration")
        except ArchiveStoreError:
            _close_snapshot_quietly(snapshot)
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError, json.JSONDecodeError) as exc:
            _close_snapshot_quietly(snapshot)
            raise ArchiveStoreError("archive record iteration failed closed") from exc

    def iter_tombstones(self, ref: ArchiveManifestRef) -> tuple[str, ...]:
        """Return exact effect tombstones anchored by ref in insertion order."""
        if not isinstance(ref, ArchiveManifestRef):
            raise ArchiveStoreError("reference verification failed")
        try:
            for _attempt in range(3):
                before = _archive_fingerprint(self._path)
                with self._read_transaction() as connection:
                    if not self._verify_ref_in_transaction(connection, ref, fingerprint=before):
                        raise ArchiveStoreError("reference verification failed")
                    rows = connection.execute(
                        "SELECT effect_id FROM archive_tombstones "
                        "WHERE generation <= ? ORDER BY sequence",
                        (ref.generation,),
                    ).fetchall()
                    tombstones = tuple(_require_str(row[0], field="effect_id") for row in rows)
                after = _archive_fingerprint(self._path)
                if before == after:
                    self._verified_snapshot = (ref, after)
                    return tombstones
                self._verified_snapshot = None
            raise ArchiveStoreError("archive changed during tombstone iteration")
        except ArchiveStoreError:
            raise
        except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ArchiveStoreError("archive tombstone iteration failed closed") from exc

    def generation_count(self) -> int:
        """Return an unverified diagnostic count; this does not anchor latest."""
        try:
            with self._read_transaction() as connection:
                self._validate_schema_and_meta(connection)
                row = connection.execute("SELECT COUNT(*) FROM archive_manifests").fetchone()
                if row is None:
                    raise ArchiveStoreError("generation diagnostic returned no result")
                return _require_non_negative_int(row[0], field="generation_count")
        except ArchiveStoreError:
            raise
        except sqlite3.Error as exc:
            raise ArchiveStoreError("generation diagnostic failed") from exc

    def latest_manifest(self) -> ArchiveManifest | None:
        """Return the unverified latest manifest for diagnostics only."""
        try:
            with self._read_transaction() as connection:
                self._validate_schema_and_meta(connection)
                row = connection.execute(
                    "SELECT * FROM archive_manifests ORDER BY generation DESC LIMIT 1"
                ).fetchone()
                return None if row is None else _manifest_from_row(row)
        except ArchiveStoreError:
            raise
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise ArchiveStoreError("latest manifest diagnostic failed") from exc

    def _initialize_store(self) -> bytes:
        _prepare_parent_directory(self._path.parent)
        created_database = not self._path.exists()
        lock = _lock_for_path(self._path)
        with lock.lock:
            connection = self._connect(allow_create=True, configure_journal=True)
            store_id = b""
            try:
                connection.execute("BEGIN IMMEDIATE")
                tables = _user_table_names(connection)
                if not tables:
                    for statement in _CREATE_TABLES:
                        connection.execute(statement)
                    store_id = secrets.token_bytes(_STORE_ID_SIZE)
                    connection.execute(
                        "INSERT INTO archive_meta "
                        "(singleton, format, schema_version, store_id, tenant_id, key_commitment) "
                        "VALUES (1, ?, ?, ?, ?, ?)",
                        (
                            _FORMAT,
                            _SCHEMA_VERSION,
                            store_id,
                            self._tenant_id,
                            _store_key_commitment(
                                self._mac_key,
                                store_id=store_id,
                                tenant_id=self._tenant_id,
                            ),
                        ),
                    )
                    connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                else:
                    store_id = b""
                self._validate_schema(connection)
                meta = _read_meta(connection)
                if meta[0] != _FORMAT or meta[1] != _SCHEMA_VERSION:
                    raise ArchiveStoreError("archive schema metadata mismatch")
                if meta[3] != self._tenant_id:
                    raise ArchiveStoreError("archive tenant does not match requested tenant")
                if not hmac.compare_digest(
                    meta[4],
                    _store_key_commitment(
                        self._mac_key,
                        store_id=meta[2],
                        tenant_id=meta[3],
                    ),
                ):
                    raise ArchiveStoreError("archive key commitment mismatch")
                store_id = meta[2]
                connection.execute("COMMIT")
            except BaseException:
                with suppress(sqlite3.Error):
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
            if created_database:
                _fsync_directory(self._path.parent)
            return store_id

    def _connect(
        self,
        *,
        allow_create: bool = False,
        configure_journal: bool = False,
    ) -> sqlite3.Connection:
        _prepare_parent_directory(self._path.parent)
        if self._path.is_symlink():
            raise ArchiveStoreError("archive database path must not be a symlink")
        if not allow_create and not self._path.is_file():
            raise ArchiveStoreError("archive database is missing")
        try:
            connection = sqlite3.connect(
                self._path,
                timeout=self._busy_timeout_ms / 1000,
                isolation_level=None,
            )
        except sqlite3.Error as exc:
            raise ArchiveStoreError("unable to open archive database") from exc
        try:
            _repair_private_permissions(self._path, 0o600)
            connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
            connection.execute(f"PRAGMA cache_size = -{_CACHE_SIZE_KIB}")
            connection.execute("PRAGMA foreign_keys = ON")
            if configure_journal:
                _configure_journal_mode(connection)
            journal_mode_row = connection.execute("PRAGMA journal_mode").fetchone()
            journal_mode = "" if journal_mode_row is None else str(journal_mode_row[0]).lower()
            synchronous_name = "FULL" if journal_mode == "wal" else "EXTRA"
            expected_synchronous = 2 if journal_mode == "wal" else 3
            connection.execute(f"PRAGMA synchronous = {synchronous_name}")
            foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
            cache_size = connection.execute("PRAGMA cache_size").fetchone()
            synchronous = connection.execute("PRAGMA synchronous").fetchone()
            if foreign_keys is None or foreign_keys[0] != 1:
                raise ArchiveStoreError("unable to enable SQLite foreign keys")
            if cache_size is None or cache_size[0] != -_CACHE_SIZE_KIB:
                raise ArchiveStoreError("unable to bound SQLite archive cache")
            if synchronous is None or synchronous[0] != expected_synchronous:
                raise ArchiveStoreError(f"unable to enable SQLite synchronous {synchronous_name}")
            return connection
        except BaseException:
            connection.close()
            raise

    @contextmanager
    def _read_transaction(self) -> Iterator[sqlite3.Connection]:
        lock = _lock_for_path(self._path)
        with lock.lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN")
                yield connection
            finally:
                with suppress(sqlite3.Error):
                    connection.execute("ROLLBACK")
                connection.close()

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        lock = _lock_for_path(self._path)
        with lock.lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                with suppress(sqlite3.Error):
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        if _user_table_names(connection) != set(_EXPECTED_COLUMNS):
            raise ArchiveStoreError("archive schema table set mismatch")
        user_version = connection.execute("PRAGMA user_version").fetchone()
        if user_version is None or user_version[0] != _SCHEMA_VERSION:
            raise ArchiveStoreError("archive schema version mismatch")
        for table, expected in _EXPECTED_COLUMNS.items():
            rows = connection.execute(f'PRAGMA table_info("{table}")').fetchall()
            actual = tuple((row[1], row[2], row[3], row[5]) for row in rows)
            if actual != expected:
                raise ArchiveStoreError(f"archive schema mismatch for {table}")
            table_list = connection.execute(
                "SELECT strict FROM pragma_table_list WHERE name = ? AND schema = 'main'",
                (table,),
            ).fetchone()
            if table_list is None or table_list[0] != 1:
                raise ArchiveStoreError(f"archive table {table} must be STRICT")
        _require_unique_index(connection, "archive_tombstones", ("effect_id",))
        _require_index(
            connection,
            "archive_records",
            ("generation", "sequence"),
        )
        _require_index(
            connection,
            "archive_tombstones",
            ("generation", "sequence"),
        )
        _require_foreign_key(connection, "archive_records")
        _require_foreign_key(connection, "archive_tombstones")

    def _validate_schema_and_meta(self, connection: sqlite3.Connection) -> None:
        self._validate_schema(connection)
        format_name, schema_version, store_id, tenant_id, key_commitment = _read_meta(connection)
        if format_name != _FORMAT or schema_version != _SCHEMA_VERSION:
            raise ArchiveStoreError("archive metadata format mismatch")
        if store_id != self._store_id:
            raise ArchiveStoreError("archive store identity mismatch")
        if tenant_id != self._tenant_id:
            raise ArchiveStoreError("archive tenant mismatch")
        if not hmac.compare_digest(
            key_commitment,
            _store_key_commitment(
                self._mac_key,
                store_id=store_id,
                tenant_id=tenant_id,
            ),
        ):
            raise ArchiveStoreError("archive key commitment mismatch")

    def _verify_cached_ref_in_transaction(
        self,
        connection: sqlite3.Connection,
        ref: ArchiveManifestRef,
    ) -> bool:
        if not _valid_ref_shape(ref):
            return False
        self._validate_schema_and_meta(connection)
        row = connection.execute(
            "SELECT * FROM archive_manifests WHERE generation = ?",
            (ref.generation,),
        ).fetchone()
        return row is not None and _manifest_from_row(row).to_ref() == ref

    def _verify_ref_in_transaction(
        self,
        connection: sqlite3.Connection,
        ref: ArchiveManifestRef,
        *,
        fingerprint: _ArchiveFingerprint | None = None,
    ) -> bool:
        current_fingerprint = (
            _archive_fingerprint(self._path) if fingerprint is None else fingerprint
        )
        if self._verified_snapshot == (ref, current_fingerprint):
            return self._verify_cached_ref_in_transaction(connection, ref)
        return self._verify_in_transaction(connection, ref)

    def _verify_in_transaction(
        self,
        connection: sqlite3.Connection,
        ref: ArchiveManifestRef,
    ) -> bool:
        try:
            if not _valid_ref_shape(ref):
                return False
            self._validate_schema_and_meta(connection)
            if (
                ref.format != _FORMAT
                or ref.schema_version != _SCHEMA_VERSION
                or ref.store_id != self._store_id
                or ref.tenant_id != self._tenant_id
            ):
                return False
            manifest_rows = connection.execute(
                "SELECT * FROM archive_manifests WHERE generation <= ? ORDER BY generation",
                (ref.generation,),
            )

            expected_manifest_hash = _ZERO_HASH
            record_sequence = 0
            record_tip = _ZERO_HASH
            record_mac = _ZERO_HASH
            tombstone_sequence = 0
            tombstone_tip = _ZERO_HASH
            tombstone_mac = _ZERO_HASH
            final_manifest: ArchiveManifest | None = None
            manifest_count = 0

            for expected_generation, manifest_row in enumerate(manifest_rows, start=1):
                manifest_count = expected_generation
                manifest = _manifest_from_row(manifest_row)
                if manifest.generation != expected_generation:
                    return False
                if manifest.prev_manifest_hash != expected_manifest_hash:
                    return False
                if manifest.first_seq != record_sequence + 1:
                    return False

                record_rows = connection.execute(
                    "SELECT * FROM archive_records WHERE generation = ? ORDER BY sequence",
                    (expected_generation,),
                )
                added_record_count = 0
                for row in record_rows:
                    added_record_count += 1
                    record_sequence += 1
                    if not self._verify_record_row(
                        row,
                        generation=expected_generation,
                        sequence=record_sequence,
                        prev_hash=record_tip,
                        prev_mac=record_mac,
                    ):
                        return False
                    record_tip = _require_blob(row[8], field="record_hash")
                    record_mac = _require_blob(row[9], field="record_mac")
                if added_record_count != manifest.added_record_count:
                    return False

                tombstone_rows = connection.execute(
                    "SELECT * FROM archive_tombstones WHERE generation = ? ORDER BY sequence",
                    (expected_generation,),
                )
                added_tombstone_count = 0
                for row in tombstone_rows:
                    added_tombstone_count += 1
                    tombstone_sequence += 1
                    if not self._verify_tombstone_row(
                        row,
                        generation=expected_generation,
                        sequence=tombstone_sequence,
                        prev_hash=tombstone_tip,
                        prev_mac=tombstone_mac,
                    ):
                        return False
                    tombstone_tip = _require_blob(row[5], field="tombstone_hash")
                    tombstone_mac = _require_blob(row[6], field="tombstone_mac")
                if added_tombstone_count != manifest.added_tombstone_count:
                    return False

                if manifest.cumulative_record_count != record_sequence:
                    return False
                if manifest.archive_tip_hash != record_tip:
                    return False
                if manifest.cumulative_tombstone_count != tombstone_sequence:
                    return False
                if manifest.tombstone_tip_hash != tombstone_tip:
                    return False
                expected = self._make_manifest(
                    generation=expected_generation,
                    prev_manifest_hash=expected_manifest_hash,
                    first_seq=manifest.first_seq,
                    added_record_count=added_record_count,
                    cumulative_record_count=record_sequence,
                    archive_tip_hash=record_tip,
                    added_tombstone_count=added_tombstone_count,
                    cumulative_tombstone_count=tombstone_sequence,
                    tombstone_tip_hash=tombstone_tip,
                )
                if not _manifests_match(manifest, expected):
                    return False
                expected_manifest_hash = manifest.manifest_hash
                final_manifest = manifest

            if manifest_count != ref.generation:
                return False
            record_total = connection.execute(
                "SELECT COUNT(*) FROM archive_records WHERE generation <= ?",
                (ref.generation,),
            ).fetchone()
            tombstone_total = connection.execute(
                "SELECT COUNT(*) FROM archive_tombstones WHERE generation <= ?",
                (ref.generation,),
            ).fetchone()
            if record_total is None or record_total[0] != record_sequence:
                return False
            if tombstone_total is None or tombstone_total[0] != tombstone_sequence:
                return False
            return final_manifest is not None and final_manifest.to_ref() == ref
        except (ArchiveStoreError, sqlite3.Error, TypeError, ValueError, json.JSONDecodeError):
            return False

    def _verify_record_row(
        self,
        row: sqlite3.Row | tuple[object, ...],
        *,
        generation: int,
        sequence: int,
        prev_hash: bytes,
        prev_mac: bytes,
    ) -> bool:
        row_sequence = _require_positive_int(row[0], field="record_sequence")
        row_generation = _require_positive_int(row[1], field="record_generation")
        record_type = _validate_identifier(row[2], field="record_type")
        tenant_id = _validate_identifier(row[3], field="record_tenant_id")
        run_id = _validate_identifier(row[4], field="run_id")
        canonical_payload = _require_str(row[5], field="canonical_payload")
        row_prev_hash = _require_blob(row[6], field="record_prev_hash")
        row_prev_mac = _require_blob(row[7], field="record_prev_mac")
        record_hash = _require_blob(row[8], field="record_hash")
        record_mac = _require_blob(row[9], field="record_mac")
        payload = json.loads(canonical_payload)
        if _canonical_json(payload) != canonical_payload:
            return False
        if (
            row_sequence != sequence
            or row_generation != generation
            or tenant_id != self._tenant_id
            or row_prev_hash != prev_hash
            or row_prev_mac != prev_mac
        ):
            return False
        expected_hash = self._record_hash(
            generation=generation,
            sequence=sequence,
            record_type=record_type,
            tenant_id=tenant_id,
            run_id=run_id,
            canonical_payload=canonical_payload,
            prev_hash=prev_hash,
            prev_mac=prev_mac,
        )
        expected_mac = self._chain_mac("record", prev_mac, expected_hash)
        return hmac.compare_digest(record_hash, expected_hash) and hmac.compare_digest(
            record_mac,
            expected_mac,
        )

    def _verify_tombstone_row(
        self,
        row: sqlite3.Row | tuple[object, ...],
        *,
        generation: int,
        sequence: int,
        prev_hash: bytes,
        prev_mac: bytes,
    ) -> bool:
        row_sequence = _require_positive_int(row[0], field="tombstone_sequence")
        row_generation = _require_positive_int(row[1], field="tombstone_generation")
        effect_id = _validate_identifier(row[2], field="effect_id")
        row_prev_hash = _require_blob(row[3], field="tombstone_prev_hash")
        row_prev_mac = _require_blob(row[4], field="tombstone_prev_mac")
        tombstone_hash = _require_blob(row[5], field="tombstone_hash")
        tombstone_mac = _require_blob(row[6], field="tombstone_mac")
        if (
            row_sequence != sequence
            or row_generation != generation
            or row_prev_hash != prev_hash
            or row_prev_mac != prev_mac
        ):
            return False
        expected_hash = self._tombstone_hash(
            generation=generation,
            sequence=sequence,
            effect_id=effect_id,
            prev_hash=prev_hash,
            prev_mac=prev_mac,
        )
        expected_mac = self._chain_mac("tombstone", prev_mac, expected_hash)
        return hmac.compare_digest(tombstone_hash, expected_hash) and hmac.compare_digest(
            tombstone_mac,
            expected_mac,
        )

    def _generation_matches_delta(
        self,
        connection: sqlite3.Connection,
        manifest: ArchiveManifest,
        base_manifest_hash: bytes,
        records: Iterable[_PreparedRecord],
        tombstones: tuple[str, ...],
    ) -> bool:
        if manifest.prev_manifest_hash != base_manifest_hash:
            return False
        record_rows = iter(
            connection.execute(
                "SELECT record_type, tenant_id, run_id, canonical_payload "
                "FROM archive_records WHERE generation = ? ORDER BY sequence",
                (manifest.generation,),
            )
        )
        for record in records:
            row = next(record_rows, None)
            if row is None or tuple(row) != (
                record.record_type,
                record.tenant_id,
                record.run_id,
                record.canonical_payload,
            ):
                return False
        if next(record_rows, None) is not None:
            return False
        tombstone_rows = connection.execute(
            "SELECT effect_id FROM archive_tombstones WHERE generation = ? ORDER BY sequence",
            (manifest.generation,),
        ).fetchall()
        actual_tombstones = tuple(_require_str(row[0], field="effect_id") for row in tombstone_rows)
        return actual_tombstones == tombstones

    def _new_tombstones_at_base(
        self,
        connection: sqlite3.Connection,
        effect_ids: tuple[str, ...],
        base_generation: int,
    ) -> tuple[str, ...]:
        new_effect_ids: list[str] = []
        for effect_id in effect_ids:
            row = connection.execute(
                "SELECT 1 FROM archive_tombstones WHERE effect_id = ? AND generation <= ? LIMIT 1",
                (effect_id, base_generation),
            ).fetchone()
            if row is None:
                new_effect_ids.append(effect_id)
        return tuple(new_effect_ids)

    def _tip_mac(self, connection: sqlite3.Connection, *, table: str, sequence: int) -> bytes:
        if sequence == 0:
            return _ZERO_HASH
        if table not in {"archive_records", "archive_tombstones"}:
            raise ArchiveStoreError("invalid archive chain table")
        row = connection.execute(
            f"SELECT mac FROM {table} WHERE sequence = ?",
            (sequence,),
        ).fetchone()
        if row is None:
            raise ArchiveStoreError("archive chain tip is missing")
        return _require_blob(row[0], field="chain_tip_mac")

    def _insert_record_rows(
        self,
        connection: sqlite3.Connection,
        generation: int,
        base_sequence: int,
        base_hash: bytes,
        base_mac: bytes,
        records: Iterable[_PreparedRecord],
    ) -> tuple[int, bytes]:
        count = 0
        prev_hash = base_hash
        prev_mac = base_mac
        for offset, record in enumerate(records, start=1):
            sequence = base_sequence + offset
            record_hash = self._record_hash(
                generation=generation,
                sequence=sequence,
                record_type=record.record_type,
                tenant_id=record.tenant_id,
                run_id=record.run_id,
                canonical_payload=record.canonical_payload,
                prev_hash=prev_hash,
                prev_mac=prev_mac,
            )
            record_mac = self._chain_mac("record", prev_mac, record_hash)
            stored_record = _StoredRecord(
                sequence=sequence,
                generation=generation,
                record_type=record.record_type,
                tenant_id=record.tenant_id,
                run_id=record.run_id,
                canonical_payload=record.canonical_payload,
                prev_hash=prev_hash,
                prev_mac=prev_mac,
                record_hash=record_hash,
                mac=record_mac,
            )
            self._insert_record(connection, stored_record)
            count = offset
            prev_hash = record_hash
            prev_mac = record_mac
        return count, prev_hash

    def _insert_tombstone_rows(
        self,
        connection: sqlite3.Connection,
        generation: int,
        base_sequence: int,
        base_hash: bytes,
        base_mac: bytes,
        effect_ids: tuple[str, ...],
    ) -> tuple[int, bytes]:
        count = 0
        prev_hash = base_hash
        prev_mac = base_mac
        for offset, effect_id in enumerate(effect_ids, start=1):
            sequence = base_sequence + offset
            tombstone_hash = self._tombstone_hash(
                generation=generation,
                sequence=sequence,
                effect_id=effect_id,
                prev_hash=prev_hash,
                prev_mac=prev_mac,
            )
            tombstone_mac = self._chain_mac("tombstone", prev_mac, tombstone_hash)
            stored_tombstone = _StoredTombstone(
                sequence=sequence,
                generation=generation,
                effect_id=effect_id,
                prev_hash=prev_hash,
                prev_mac=prev_mac,
                tombstone_hash=tombstone_hash,
                mac=tombstone_mac,
            )
            self._insert_tombstone(connection, stored_tombstone)
            count = offset
            prev_hash = tombstone_hash
            prev_mac = tombstone_mac
        return count, prev_hash

    def _record_hash(
        self,
        *,
        generation: int,
        sequence: int,
        record_type: str,
        tenant_id: str,
        run_id: str,
        canonical_payload: str,
        prev_hash: bytes,
        prev_mac: bytes,
    ) -> bytes:
        return hashlib.sha256(
            _encode_fields(
                "archive-record-v1",
                self._store_id,
                tenant_id,
                generation,
                sequence,
                record_type,
                run_id,
                canonical_payload,
                prev_hash,
                prev_mac,
            )
        ).digest()

    def _tombstone_hash(
        self,
        *,
        generation: int,
        sequence: int,
        effect_id: str,
        prev_hash: bytes,
        prev_mac: bytes,
    ) -> bytes:
        return hashlib.sha256(
            _encode_fields(
                "archive-tombstone-v1",
                self._store_id,
                self._tenant_id,
                generation,
                sequence,
                effect_id,
                prev_hash,
                prev_mac,
            )
        ).digest()

    def _chain_mac(self, chain: str, prev_mac: bytes, item_hash: bytes) -> bytes:
        return hmac.new(
            self._mac_key,
            _encode_fields(f"archive-{chain}-mac-v1", self._store_id, prev_mac, item_hash),
            hashlib.sha256,
        ).digest()

    def _make_manifest(
        self,
        *,
        generation: int,
        prev_manifest_hash: bytes,
        first_seq: int,
        added_record_count: int,
        cumulative_record_count: int,
        archive_tip_hash: bytes,
        added_tombstone_count: int,
        cumulative_tombstone_count: int,
        tombstone_tip_hash: bytes,
    ) -> ArchiveManifest:
        fields = (
            _FORMAT,
            _SCHEMA_VERSION,
            self._store_id,
            self._tenant_id,
            generation,
            prev_manifest_hash,
            first_seq,
            added_record_count,
            cumulative_record_count,
            archive_tip_hash,
            added_tombstone_count,
            cumulative_tombstone_count,
            tombstone_tip_hash,
        )
        manifest_hash = hashlib.sha256(_encode_fields("archive-manifest-v1", *fields)).digest()
        manifest_mac = hmac.new(
            self._mac_key,
            _encode_fields("archive-manifest-mac-v1", self._store_id, manifest_hash),
            hashlib.sha256,
        ).digest()
        return ArchiveManifest(
            format=_FORMAT,
            schema_version=_SCHEMA_VERSION,
            store_id=self._store_id,
            tenant_id=self._tenant_id,
            generation=generation,
            prev_manifest_hash=prev_manifest_hash,
            first_seq=first_seq,
            added_record_count=added_record_count,
            cumulative_record_count=cumulative_record_count,
            archive_tip_hash=archive_tip_hash,
            added_tombstone_count=added_tombstone_count,
            cumulative_tombstone_count=cumulative_tombstone_count,
            tombstone_tip_hash=tombstone_tip_hash,
            manifest_hash=manifest_hash,
            mac=manifest_mac,
        )

    @staticmethod
    def _insert_manifest(connection: sqlite3.Connection, manifest: ArchiveManifest) -> None:
        connection.execute(
            "INSERT INTO archive_manifests "
            "(generation, format, schema_version, store_id, tenant_id, "
            "prev_manifest_hash, first_seq, added_record_count, cumulative_record_count, "
            "archive_tip_hash, added_tombstone_count, cumulative_tombstone_count, "
            "tombstone_tip_hash, manifest_hash, mac) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                manifest.generation,
                manifest.format,
                manifest.schema_version,
                manifest.store_id,
                manifest.tenant_id,
                manifest.prev_manifest_hash,
                manifest.first_seq,
                manifest.added_record_count,
                manifest.cumulative_record_count,
                manifest.archive_tip_hash,
                manifest.added_tombstone_count,
                manifest.cumulative_tombstone_count,
                manifest.tombstone_tip_hash,
                manifest.manifest_hash,
                manifest.mac,
            ),
        )

    def _insert_record(self, connection: sqlite3.Connection, record: _StoredRecord) -> None:
        connection.execute(
            "INSERT INTO archive_records "
            "(sequence, generation, record_type, tenant_id, run_id, canonical_payload, "
            "prev_hash, prev_mac, record_hash, mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.sequence,
                record.generation,
                record.record_type,
                record.tenant_id,
                record.run_id,
                record.canonical_payload,
                record.prev_hash,
                record.prev_mac,
                record.record_hash,
                record.mac,
            ),
        )

    @staticmethod
    def _insert_tombstone(
        connection: sqlite3.Connection,
        tombstone: _StoredTombstone,
    ) -> None:
        connection.execute(
            "INSERT INTO archive_tombstones "
            "(sequence, generation, effect_id, prev_hash, prev_mac, tombstone_hash, mac) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                tombstone.sequence,
                tombstone.generation,
                tombstone.effect_id,
                tombstone.prev_hash,
                tombstone.prev_mac,
                tombstone.tombstone_hash,
                tombstone.mac,
            ),
        )


def _iter_prepared_records(
    records: Iterable[ArchiveRecord],
    *,
    tenant_id: str,
) -> Iterator[_PreparedRecord]:
    if isinstance(records, _STRING_LIKE):
        raise TypeError("records must not be a string-like iterable")
    try:
        raw_records = iter(records)
    except TypeError as exc:
        raise TypeError("records must be an iterable of ArchiveRecord values") from exc
    for record in raw_records:
        if not isinstance(record, ArchiveRecord):
            raise TypeError("records must contain ArchiveRecord values")
        record_type = _validate_identifier(record.record_type, field="record_type")
        record_tenant = _validate_identifier(record.tenant_id, field="record tenant_id")
        if record_tenant != tenant_id:
            raise ValueError("record tenant_id must match archive tenant")
        run_id = _validate_identifier(record.run_id, field="run_id")
        canonical_payload = _canonical_json(record.payload)
        yield _PreparedRecord(
            record_type=record_type,
            tenant_id=record_tenant,
            run_id=run_id,
            canonical_payload=canonical_payload,
        )


def _snapshot_record_from_line(line: str) -> ArchiveRecord:
    raw = json.loads(line)
    if not isinstance(raw, list) or len(raw) != 4:
        raise ValueError("invalid archive record snapshot")
    record_type = _require_str(raw[0], field="record_type")
    tenant_id = _require_str(raw[1], field="tenant_id")
    run_id = _require_str(raw[2], field="run_id")
    canonical_payload = _require_str(raw[3], field="canonical_payload")
    return ArchiveRecord(
        record_type=record_type,
        tenant_id=tenant_id,
        run_id=run_id,
        payload=json.loads(canonical_payload),
    )


def _close_snapshot_quietly(snapshot: IO[str]) -> None:
    with suppress(OSError):
        snapshot.close()


def _prepare_tombstones(tombstones: Iterable[str]) -> tuple[str, ...]:
    if isinstance(tombstones, _STRING_LIKE):
        raise TypeError("tombstones must not be a string-like iterable")
    try:
        raw_effect_ids = tuple(tombstones)
    except TypeError as exc:
        raise TypeError("tombstones must be an iterable of effect IDs") from exc
    seen: set[str] = set()
    for effect_id in raw_effect_ids:
        validated = _validate_identifier(effect_id, field="effect_id")
        seen.add(validated)
    return tuple(sorted(seen))


def _canonical_json(payload: object) -> str:
    try:
        _validate_json_value(payload)
        return json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("payload must contain canonical JSON values") from exc


def _validate_json_value(value: object, *, depth: int = 0) -> None:
    if depth > 100:
        raise ValueError("payload nesting is too deep")
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("payload floats must be finite")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("payload object keys must be strings")
            _validate_json_value(item, depth=depth + 1)
        return
    raise TypeError("payload contains a non-JSON value")


def _validate_database_path(path: Path | str) -> Path:
    if not isinstance(path, (Path, str)):
        raise TypeError("path must be a Path or string")
    if isinstance(path, str):
        if not path.strip():
            raise ValueError("path must not be empty")
        if "\x00" in path:
            raise ValueError("path must not contain a null byte")
    expanded = Path(path).expanduser()
    if expanded.is_symlink():
        raise ValueError("path must not be a symlink")
    resolved = expanded.resolve(strict=False)
    if not resolved.name:
        raise ValueError("path must name a database file")
    return resolved


def _archive_fingerprint(path: Path) -> _ArchiveFingerprint:
    database = _file_fingerprint(path, required=True)
    if database is None:
        raise ArchiveStoreError("archive database is missing")
    return (
        database,
        _sidecar_fingerprint(Path(str(path) + "-wal")),
        _sidecar_fingerprint(Path(str(path) + "-journal")),
    )


def _sidecar_fingerprint(path: Path) -> _FileFingerprint | None:
    fingerprint = _file_fingerprint(path, required=False)
    if fingerprint is not None and fingerprint[2] == 0:
        return None
    return fingerprint


def _file_fingerprint(path: Path, *, required: bool) -> _FileFingerprint | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if required:
            raise ArchiveStoreError("archive database is missing") from None
        return None
    except OSError as exc:
        raise ArchiveStoreError("archive fingerprint failed") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ArchiveStoreError("archive database files must be regular files")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_mac_key(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError("mac_key must be bytes")
    if len(value) < 32:
        raise ValueError("mac_key must contain at least 32 bytes")
    return value


def _validate_timeout(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("busy_timeout_ms must be a positive integer")
    if value > _MAX_SQLITE_INTEGER:
        raise ValueError("busy_timeout_ms exceeds SQLite integer range")
    return value


def _validate_identifier(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    if not value or len(value) > _MAX_IDENTIFIER_LENGTH:
        raise ValueError(
            f"{field} must be non-empty and no longer than {_MAX_IDENTIFIER_LENGTH} characters"
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field} must not contain control characters")
    return value


def _prepare_parent_directory(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise ArchiveStoreError("archive directory creation failed") from exc
    if path.is_symlink() or not path.is_dir():
        raise ArchiveStoreError("archive parent must be a real directory")
    _repair_private_permissions(path, 0o700)


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY)
        os.fsync(descriptor)
    except OSError as exc:
        raise ArchiveStoreError("archive directory sync failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _repair_private_permissions(path: Path, expected_mode: int) -> None:
    if os.name != "posix":
        return
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ArchiveStoreError(f"archive path must not be a symlink: {path}")
        actual_mode = stat.S_IMODE(metadata.st_mode)
        if actual_mode != expected_mode:
            os.chmod(path, expected_mode)
            actual_mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        raise ArchiveStoreError(f"archive permission repair failed for {path}") from exc
    if actual_mode != expected_mode:
        raise ArchiveStoreError(f"archive permission repair failed for {path}")


def _configure_journal_mode(connection: sqlite3.Connection) -> None:
    try:
        row = connection.execute("PRAGMA journal_mode = WAL").fetchone()
        mode = "" if row is None else str(row[0]).lower()
    except sqlite3.Error:
        mode = ""
    if mode == "wal":
        return
    try:
        row = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
    except sqlite3.Error as exc:
        raise ArchiveStoreError("unable to configure SQLite journal mode") from exc
    if row is None or str(row[0]).lower() != "delete":
        raise ArchiveStoreError("unable to configure SQLite journal fallback")


def _user_table_names(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {_require_str(row[0], field="schema table name") for row in rows}


def _read_meta(connection: sqlite3.Connection) -> tuple[str, int, bytes, str, bytes]:
    rows = connection.execute(
        "SELECT format, schema_version, store_id, tenant_id, key_commitment "
        "FROM archive_meta WHERE singleton = 1"
    ).fetchall()
    if len(rows) != 1:
        raise ArchiveStoreError("archive metadata row is missing or ambiguous")
    row = rows[0]
    format_name = _require_str(row[0], field="format")
    schema_version = _require_positive_int(row[1], field="schema_version")
    store_id = _require_blob(row[2], field="store_id", size=_STORE_ID_SIZE)
    tenant_id = _require_str(row[3], field="tenant_id")
    key_commitment = _require_blob(row[4], field="key_commitment")
    return format_name, schema_version, store_id, tenant_id, key_commitment


def _store_key_commitment(mac_key: bytes, *, store_id: bytes, tenant_id: str) -> bytes:
    return hmac.new(
        mac_key,
        _encode_fields("archive-store-key-v1", _FORMAT, store_id, tenant_id),
        hashlib.sha256,
    ).digest()


def _manifest_from_row(row: sqlite3.Row | tuple[object, ...]) -> ArchiveManifest:
    return ArchiveManifest(
        generation=_require_positive_int(row[0], field="generation"),
        format=_require_str(row[1], field="format"),
        schema_version=_require_positive_int(row[2], field="schema_version"),
        store_id=_require_blob(row[3], field="store_id", size=_STORE_ID_SIZE),
        tenant_id=_require_str(row[4], field="tenant_id"),
        prev_manifest_hash=_require_blob(row[5], field="prev_manifest_hash"),
        first_seq=_require_positive_int(row[6], field="first_seq"),
        added_record_count=_require_non_negative_int(row[7], field="added_record_count"),
        cumulative_record_count=_require_non_negative_int(row[8], field="cumulative_record_count"),
        archive_tip_hash=_require_blob(row[9], field="archive_tip_hash"),
        added_tombstone_count=_require_non_negative_int(row[10], field="added_tombstone_count"),
        cumulative_tombstone_count=_require_non_negative_int(
            row[11], field="cumulative_tombstone_count"
        ),
        tombstone_tip_hash=_require_blob(row[12], field="tombstone_tip_hash"),
        manifest_hash=_require_blob(row[13], field="manifest_hash"),
        mac=_require_blob(row[14], field="manifest_mac"),
    )


def _valid_ref_shape(ref: ArchiveManifestRef) -> bool:
    try:
        if ref.format != _FORMAT or ref.schema_version != _SCHEMA_VERSION:
            return False
        _require_blob(ref.store_id, field="store_id", size=_STORE_ID_SIZE)
        _validate_identifier(ref.tenant_id, field="tenant_id")
        _require_positive_int(ref.generation, field="generation")
        _require_blob(ref.prev_manifest_hash, field="prev_manifest_hash")
        _require_positive_int(ref.first_seq, field="first_seq")
        _require_non_negative_int(ref.added_record_count, field="added_record_count")
        _require_non_negative_int(
            ref.cumulative_record_count,
            field="cumulative_record_count",
        )
        _require_blob(ref.archive_tip_hash, field="archive_tip_hash")
        _require_non_negative_int(
            ref.added_tombstone_count,
            field="added_tombstone_count",
        )
        _require_non_negative_int(
            ref.cumulative_tombstone_count,
            field="cumulative_tombstone_count",
        )
        _require_blob(ref.tombstone_tip_hash, field="tombstone_tip_hash")
        _require_blob(ref.manifest_hash, field="manifest_hash")
        _require_blob(ref.mac, field="manifest_mac")
    except (TypeError, ValueError):
        return False
    return True


def _manifests_match(actual: ArchiveManifest, expected: ArchiveManifest) -> bool:
    if (
        actual.format != expected.format
        or actual.schema_version != expected.schema_version
        or actual.store_id != expected.store_id
        or actual.tenant_id != expected.tenant_id
        or actual.generation != expected.generation
        or actual.first_seq != expected.first_seq
        or actual.added_record_count != expected.added_record_count
        or actual.cumulative_record_count != expected.cumulative_record_count
        or actual.added_tombstone_count != expected.added_tombstone_count
        or actual.cumulative_tombstone_count != expected.cumulative_tombstone_count
    ):
        return False
    byte_pairs = (
        (actual.prev_manifest_hash, expected.prev_manifest_hash),
        (actual.archive_tip_hash, expected.archive_tip_hash),
        (actual.tombstone_tip_hash, expected.tombstone_tip_hash),
        (actual.manifest_hash, expected.manifest_hash),
        (actual.mac, expected.mac),
    )
    return all(hmac.compare_digest(left, right) for left, right in byte_pairs)


def _sqlite_check_is_ok(connection: sqlite3.Connection, pragma: str) -> bool:
    if pragma not in {"quick_check", "integrity_check"}:
        raise ValueError("unsupported SQLite check")
    rows = connection.execute(f"PRAGMA {pragma}").fetchall()
    return len(rows) == 1 and rows[0][0] == "ok"


def _require_unique_index(
    connection: sqlite3.Connection,
    table: str,
    expected_columns: tuple[str, ...],
) -> None:
    for index_row in connection.execute(f'PRAGMA index_list("{table}")').fetchall():
        if index_row[2] != 1:
            continue
        index_name = _require_str(index_row[1], field="index_name")
        columns = tuple(
            _require_str(row[2], field="index_column")
            for row in connection.execute(f'PRAGMA index_info("{index_name}")').fetchall()
        )
        if columns == expected_columns:
            return
    raise ArchiveStoreError(f"archive table {table} lacks required unique index")


def _require_index(
    connection: sqlite3.Connection,
    table: str,
    expected_columns: tuple[str, ...],
) -> None:
    for index_row in connection.execute(f'PRAGMA index_list("{table}")').fetchall():
        index_name = _require_str(index_row[1], field="index_name")
        columns = tuple(
            _require_str(row[2], field="index_column")
            for row in connection.execute(f'PRAGMA index_info("{index_name}")').fetchall()
        )
        if columns == expected_columns:
            return
    raise ArchiveStoreError(f"archive table {table} lacks required generation index")


def _require_foreign_key(connection: sqlite3.Connection, table: str) -> None:
    rows = connection.execute(f'PRAGMA foreign_key_list("{table}")').fetchall()
    expected = [row for row in rows if row[2] == "archive_manifests" and row[3] == "generation"]
    if len(expected) != 1 or expected[0][4] != "generation":
        raise ArchiveStoreError(f"archive table {table} lacks generation foreign key")


def _require_str(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be text")
    return value


def _require_blob(value: object, *, field: str, size: int = _HASH_SIZE) -> bytes:
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError(f"{field} must be a {size}-byte blob")
    return value


def _require_positive_int(value: object, *, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= _MAX_SQLITE_INTEGER
    ):
        raise ValueError(f"{field} must be a positive SQLite integer")
    return value


def _require_non_negative_int(value: object, *, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= _MAX_SQLITE_INTEGER
    ):
        raise ValueError(f"{field} must be a non-negative SQLite integer")
    return value


def _encode_fields(*values: str | bytes | int) -> bytes:
    encoded = bytearray()
    for value in values:
        if isinstance(value, bool):
            raise TypeError("boolean is not a valid encoded integer")
        if isinstance(value, int):
            if not 0 <= value <= _MAX_SQLITE_INTEGER:
                raise ValueError("encoded integer is outside SQLite range")
            encoded.extend(b"i")
            encoded.extend(value.to_bytes(8, "big"))
        elif isinstance(value, str):
            raw = value.encode("utf-8")
            encoded.extend(b"s")
            encoded.extend(len(raw).to_bytes(8, "big"))
            encoded.extend(raw)
        elif isinstance(value, bytes):
            encoded.extend(b"b")
            encoded.extend(len(value).to_bytes(8, "big"))
            encoded.extend(value)
        else:
            raise TypeError("unsupported authenticated field type")
    return bytes(encoded)


def _lock_for_path(path: Path) -> _PathLock:
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(path)
        if lock is None:
            lock = _PathLock()
            _PATH_LOCKS[path] = lock
        return lock


def _path_lock_count() -> int:
    with _PATH_LOCKS_GUARD:
        return len(_PATH_LOCKS)
