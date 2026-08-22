from __future__ import annotations

import fcntl
import gzip
import hashlib
import json
import os
import stat
import threading
import time
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, TextIO, TypedDict
from weakref import WeakValueDictionary

from js.echo.ledger._hashing import hmac_matches, stable_hash, stable_hmac
from js.echo.ledger.archive_store import (
    ArchiveConflictError,
    ArchiveManifestRef,
    ArchiveRecord,
    ArchiveStore,
    ArchiveStoreError,
)

GENESIS_HASH = "sha256:" + "0" * 64
_SQLITE_ARCHIVE_FORMAT = "echo-sqlite-archive"
_SQLITE_ARCHIVE_SUFFIX = ".archive.sqlite3"
_COMPACTION_MAX_ATTEMPTS = 8
_ARCHIVE_REF_FIELDS = frozenset(
    {
        "format",
        "schema_version",
        "store_id",
        "tenant_id",
        "generation",
        "prev_manifest_hash",
        "first_seq",
        "added_record_count",
        "cumulative_record_count",
        "archive_tip_hash",
        "added_tombstone_count",
        "cumulative_tombstone_count",
        "tombstone_tip_hash",
        "manifest_hash",
        "mac",
    }
)
_FILE_LOCKS: WeakValueDictionary[Path, threading.RLock] = WeakValueDictionary()
_FILE_LOCKS_GUARD = threading.Lock()


@dataclass(frozen=True)
class CommitRecord:
    seq: int
    record_type: str
    tenant_id: str
    run_id: str
    payload: dict[str, Any]
    prev_hash: str
    record_hash: str
    mac: bytes

    def hash_payload(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "record_type": self.record_type,
            "tenant_id": self.tenant_id,
            "run_id": self.run_id,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
        }


@dataclass(frozen=True)
class VerificationReport:
    ok: bool
    errors: tuple[str, ...]


class JournalEntry(TypedDict):
    record_type: str
    tenant_id: str
    run_id: str
    payload: dict[str, Any]


SemanticSync = Callable[[tuple[CommitRecord, ...], bool], None]
ActiveJournalFingerprint = tuple[int, int, int, int, int, int]
ArchiveStatFingerprint = tuple[int, int, int, int, int, int]
ArchiveCandidateFingerprint = tuple[ArchiveStatFingerprint | None, ...]
RequiredArchivesFingerprint = tuple[
    tuple[str, str, tuple[tuple[str, ArchiveCandidateFingerprint], ...]],
    ...,
]


class EchoJournal:
    def __init__(self, *, mac_key: bytes) -> None:
        self._mac_key = mac_key
        self._records: list[CommitRecord] = []

    @property
    def records(self) -> tuple[CommitRecord, ...]:
        return tuple(self._records)

    @property
    def record_count(self) -> int:
        return len(self._records)

    @property
    def tip(self) -> CommitRecord | None:
        return self._records[-1] if self._records else None

    def append(
        self,
        *,
        record_type: str,
        tenant_id: str,
        run_id: str,
        payload: dict[str, Any],
    ) -> CommitRecord:
        seq = len(self._records)
        prev_hash = self._records[-1].record_hash if self._records else GENESIS_HASH
        payload_copy = _clone_payload(payload)
        base = {
            "seq": seq,
            "record_type": record_type,
            "tenant_id": tenant_id,
            "run_id": run_id,
            "payload": payload_copy,
            "prev_hash": prev_hash,
        }
        record_hash = stable_hash(base)
        mac_payload = {**base, "record_hash": record_hash}
        record = CommitRecord(
            seq=seq,
            record_type=record_type,
            tenant_id=tenant_id,
            run_id=run_id,
            payload=payload_copy,
            prev_hash=prev_hash,
            record_hash=record_hash,
            mac=stable_hmac(self._mac_key, mac_payload),
        )
        self._records.append(record)
        return record


class FileEchoLedger:
    def __init__(self, path: Path, *, mac_key: bytes) -> None:
        self._path = path
        self._mac_key = mac_key
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self._path.parent, 0o700)
        lock_path = _journal_lock_path(self._path)
        with _path_lock(self._path), lock_path.open("a+b") as lock_handle:
            _make_handle_private(lock_handle)
            _lock_file(lock_handle)
            try:
                try:
                    journal_fd = os.open(
                        self._path,
                        os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                        0o600,
                    )
                except FileExistsError:
                    pass
                else:
                    os.close(journal_fd)
                    _fsync_directory(self._path.parent)
                _make_path_private(self._path)
                report, records, offset = _read_verified_file(self._path, mac_key=self._mac_key)
                if not report.ok and _recoverable_tail_error(
                    report,
                    self._path,
                    clean_offset=offset,
                ):
                    _isolate_corrupt_tail_locked(self._path, clean_offset=offset)
                    report, records, offset = _read_verified_file(self._path, mac_key=self._mac_key)
            finally:
                _unlock_file(lock_handle)
        if not report.ok:
            raise ValueError("invalid journal file: " + ",".join(report.errors))
        self._records = records
        self._archive_anchors = [
            record for record in records if record.record_type == "snapshot_anchor"
        ]
        self._required_archives_cache: (
            tuple[RequiredArchivesFingerprint, VerificationReport] | None
        ) = None
        self._archive_store_cache: tuple[bytes, str, ArchiveStore] | None = None
        self._offset = offset
        self._active_fingerprint = _active_journal_fingerprint(self._path)

    @property
    def records(self) -> tuple[CommitRecord, ...]:
        return tuple(self._records)

    @property
    def record_count(self) -> int:
        return len(self._records)

    @property
    def tip(self) -> CommitRecord | None:
        return self._records[-1] if self._records else None

    def append(
        self,
        *,
        record_type: str,
        tenant_id: str,
        run_id: str,
        payload: dict[str, Any],
        semantic_sync: SemanticSync | None = None,
    ) -> CommitRecord:
        return self.append_many(
            (
                {
                    "record_type": record_type,
                    "tenant_id": tenant_id,
                    "run_id": run_id,
                    "payload": payload,
                },
            ),
            semantic_sync=semantic_sync,
        )[0]

    def append_many(
        self,
        entries: tuple[JournalEntry, ...],
        *,
        semantic_sync: SemanticSync | None = None,
    ) -> tuple[CommitRecord, ...]:
        if not entries:
            return ()
        lock_path = _journal_lock_path(self._path)
        with _path_lock(self._path), lock_path.open("a+b") as lock_handle:
            _make_handle_private(lock_handle)
            _lock_file(lock_handle)
            try:
                with self._path.open("r+", encoding="utf-8") as handle:
                    _make_handle_private(handle)
                    disk_changed = self._sync_from_disk_locked(handle)
                    if semantic_sync is not None:
                        records = tuple(self._records) if disk_changed else ()
                        semantic_sync(records, disk_changed)
                    appended: list[CommitRecord] = []
                    next_seq = self.record_count
                    tip = self.tip
                    prev_hash = tip.record_hash if tip is not None else GENESIS_HASH
                    for entry in entries:
                        record = _build_record_at(
                            seq=next_seq,
                            prev_hash=prev_hash,
                            mac_key=self._mac_key,
                            record_type=entry["record_type"],
                            tenant_id=entry["tenant_id"],
                            run_id=entry["run_id"],
                            payload=entry["payload"],
                        )
                        appended.append(record)
                        next_seq += 1
                        prev_hash = record.record_hash
                    handle.seek(0, os.SEEK_END)
                    original_end = handle.tell()
                    try:
                        _ensure_trailing_newline(handle)
                        handle.write("".join(_record_to_json(record) + "\n" for record in appended))
                        handle.flush()
                        os.fsync(handle.fileno())
                    except BaseException:
                        with suppress(OSError):
                            handle.seek(original_end)
                            handle.truncate()
                            handle.flush()
                            os.fsync(handle.fileno())
                        raise
                    self._records.extend(appended)
                    self._archive_anchors.extend(
                        record for record in appended if record.record_type == "snapshot_anchor"
                    )
                    self._offset = handle.tell()
                    self._active_fingerprint = _active_journal_fingerprint_from_handle(handle)
                    return tuple(appended)
            finally:
                _unlock_file(lock_handle)

    def refresh(self, *, semantic_sync: SemanticSync | None = None) -> bool:
        """Refresh this process snapshot while holding the journal process lock."""
        lock_path = _journal_lock_path(self._path)
        with _path_lock(self._path), lock_path.open("a+b") as lock_handle:
            _make_handle_private(lock_handle)
            _lock_file(lock_handle)
            try:
                with self._path.open("r+", encoding="utf-8") as handle:
                    _make_handle_private(handle)
                    disk_changed = self._sync_from_disk_locked(handle)
                    if semantic_sync is not None and disk_changed:
                        semantic_sync(tuple(self._records), disk_changed)
                    return disk_changed
            finally:
                _unlock_file(lock_handle)

    def refresh_and_verify_required_archives(
        self,
        *,
        semantic_sync: SemanticSync | None = None,
    ) -> tuple[bool, VerificationReport]:
        lock_path = _journal_lock_path(self._path)
        with _path_lock(self._path), lock_path.open("a+b") as lock_handle:
            _make_handle_private(lock_handle)
            _lock_file(lock_handle)
            try:
                with self._path.open("r+", encoding="utf-8") as handle:
                    _make_handle_private(handle)
                    disk_changed = self._sync_from_disk_locked(handle)
                    if semantic_sync is not None and disk_changed:
                        semantic_sync(tuple(self._records), disk_changed)
                    return disk_changed, self._verify_required_archives_locked()
            finally:
                _unlock_file(lock_handle)

    def verify_required_archives(self) -> VerificationReport:
        return self.refresh_and_verify_required_archives()[1]

    def verified_logical_records(self) -> tuple[CommitRecord | ArchiveRecord, ...]:
        """Return authenticated logical history across required archives and active tail."""
        lock_path = _journal_lock_path(self._path)
        with _path_lock(self._path), lock_path.open("a+b") as lock_handle:
            _make_handle_private(lock_handle)
            _lock_file(lock_handle)
            try:
                with self._path.open("r+", encoding="utf-8") as handle:
                    _make_handle_private(handle)
                    self._sync_from_disk_locked(handle)
                report = self._verify_required_archives_locked()
                if not report.ok:
                    raise ValueError(
                        "invalid required journal archive: " + ",".join(report.errors)
                    )
                anchors = tuple(self._archive_anchors)
                if not anchors:
                    return tuple(self._records)
                if len(anchors) != 1 or anchors[0] != self._records[0]:
                    raise ValueError(
                        "invalid journal archive chain: ambiguous_snapshot_anchor"
                    )
                anchor = anchors[0]
                if not _is_sqlite_archive_anchor(anchor.payload):
                    return tuple(
                        _logical_history_records(
                            self._path,
                            records=self._records,
                            mac_key=self._mac_key,
                        )
                    )
                ref = _archive_ref_from_payload(anchor.payload)
                store = _open_anchored_archive_store(
                    self._path,
                    payload=anchor.payload,
                    ref=ref,
                    mac_key=self._mac_key,
                )
                archived = tuple(store.iter_records(ref))
                retained_count = anchor.payload.get("retained_record_count")
                current = tuple(
                    record
                    for record in self._records
                    if record.record_type != "snapshot_anchor"
                )
                if (
                    not isinstance(retained_count, int)
                    or isinstance(retained_count, bool)
                    or retained_count < 0
                    or retained_count > len(current)
                ):
                    raise ValueError(
                        "invalid journal archive chain: retained_record_count"
                    )
                return archived + current[retained_count:]
            finally:
                _unlock_file(lock_handle)

    def contains_archived_effect(self, effect_id: str) -> bool:
        """Return whether a verified archive contains this exact effect tombstone."""
        if not isinstance(effect_id, str) or not effect_id:
            raise ValueError("effect_id must be a non-empty string")
        lock_path = _journal_lock_path(self._path)
        with _path_lock(self._path), lock_path.open("a+b") as lock_handle:
            _make_handle_private(lock_handle)
            _lock_file(lock_handle)
            try:
                with self._path.open("r+", encoding="utf-8") as handle:
                    _make_handle_private(handle)
                    self._sync_from_disk_locked(handle)
                report = self._verify_required_archives_locked()
                if not report.ok:
                    raise ValueError("invalid required journal archive: " + ",".join(report.errors))
                anchors = tuple(self._archive_anchors)
                if not anchors:
                    return False
                if len(anchors) != 1 or anchors[0] != self._records[0]:
                    raise ValueError("invalid journal archive chain: ambiguous_snapshot_anchor")
                anchor = anchors[0]
                if _is_sqlite_archive_anchor(anchor.payload):
                    ref = _archive_ref_from_payload(anchor.payload)
                    cached = self._archive_store_cache
                    if cached is not None and cached[:2] == (ref.store_id, ref.tenant_id):
                        store = cached[2]
                    else:
                        store = _open_anchored_archive_store(
                            self._path,
                            payload=anchor.payload,
                            ref=ref,
                            mac_key=self._mac_key,
                        )
                        self._archive_store_cache = (ref.store_id, ref.tenant_id, store)
                    try:
                        return store.contains_effect(effect_id, ref)
                    except ArchiveStoreError as exc:
                        raise ValueError(
                            "invalid required journal archive: sqlite_effect_lookup"
                        ) from exc
                tombstones = anchor.payload.get("effect_tombstones", [])
                if not isinstance(tombstones, list) or not all(
                    isinstance(item, str) and item for item in tombstones
                ):
                    raise ValueError("invalid required journal archive: effect_tombstones")
                return effect_id in tombstones
            finally:
                _unlock_file(lock_handle)

    def _verify_required_archives_locked(self) -> VerificationReport:
        active_record_count = len(self._records) - len(self._archive_anchors)
        for _attempt in range(3):
            fingerprint = _required_archives_fingerprint(self._path, self._archive_anchors)
            metadata_report = _verify_required_archive_metadata(
                self._path,
                archive_anchors=self._archive_anchors,
                active_record_count=active_record_count,
            )
            if not metadata_report.ok:
                if fingerprint == _required_archives_fingerprint(
                    self._path,
                    self._archive_anchors,
                ):
                    return metadata_report
                continue
            cached = self._required_archives_cache
            if cached is not None and cached[0] == fingerprint:
                report = cached[1]
            else:
                report = _verify_required_archive_contents(
                    self._path,
                    archive_anchors=self._archive_anchors,
                    mac_key=self._mac_key,
                )
            if fingerprint == _required_archives_fingerprint(
                self._path,
                self._archive_anchors,
            ):
                self._required_archives_cache = (fingerprint, report)
                return report
        return VerificationReport(ok=False, errors=("archive_changed_during_verification",))

    def compact(
        self,
        *,
        max_records: int,
        archive: bool = True,
        max_archives: int = 1,
    ) -> bool:
        """Archive semantic history and replace the active file with a bounded tail."""
        if max_records < 1:
            raise ValueError("max_records must be >= 1")
        if max_archives < 1:
            raise ValueError("max_archives must be >= 1")
        lock_path = _journal_lock_path(self._path)
        with _path_lock(self._path), lock_path.open("a+b") as lock_handle:
            _make_handle_private(lock_handle)
            _lock_file(lock_handle)
            try:
                for _attempt in range(_COMPACTION_MAX_ATTEMPTS):
                    _make_path_private(self._path)
                    source_fingerprint = _active_journal_fingerprint(self._path)
                    if source_fingerprint == self._active_fingerprint:
                        report = verify_records(tuple(self._records), mac_key=self._mac_key)
                        if not report.ok:
                            raise ValueError(
                                "invalid in-memory journal snapshot: "
                                + ",".join(report.errors)
                            )
                        records = self._records
                        offset = self._offset
                    else:
                        report, records, offset = _read_verified_file(
                            self._path,
                            mac_key=self._mac_key,
                        )
                        if _active_journal_fingerprint(self._path) != source_fingerprint:
                            continue
                    if not report.ok:
                        raise ValueError("invalid journal file: " + ",".join(report.errors))
                    anchors = tuple(
                        record for record in records if record.record_type == "snapshot_anchor"
                    )
                    if anchors and (len(anchors) != 1 or records[0] != anchors[0]):
                        raise ValueError("invalid journal archive chain: ambiguous_snapshot_anchor")
                    if (
                        (records is self._records or records == self._records)
                        and anchors == tuple(self._archive_anchors)
                        and _active_journal_fingerprint(self._path) == self._active_fingerprint
                    ):
                        archive_report = self._verify_required_archives_locked()
                    else:
                        archive_report = _verify_required_archives(
                            self._path,
                            archive_anchors=anchors,
                            active_record_count=len(records) - len(anchors),
                            mac_key=self._mac_key,
                        )
                    if not archive_report.ok:
                        raise ValueError(
                            "invalid required journal archive: " + ",".join(archive_report.errors)
                        )
                    anchor = anchors[0] if anchors else None
                    semantic_records = [
                        record for record in records if record.record_type != "snapshot_anchor"
                    ]
                    migrate_legacy = (
                        archive
                        and anchor is not None
                        and anchor.payload.get("archive_required", True) is not False
                        and not _is_sqlite_archive_anchor(anchor.payload)
                    )
                    if len(semantic_records) <= max_records and not migrate_legacy:
                        self._records = records
                        self._archive_anchors = list(anchors)
                        self._offset = self._path.stat().st_size if self._path.exists() else 0
                        self._active_fingerprint = _active_journal_fingerprint(self._path)
                        return False

                    tail = _compaction_records(records, max_records=max_records)
                    effect_tombstones = _non_idempotent_tool_effect_tombstones(
                        records,
                        retained_records=tail,
                    )
                    if (
                        self._path.stat().st_size != offset
                        or _active_journal_fingerprint(self._path) != source_fingerprint
                    ):
                        continue

                    if archive:
                        archive_path = _sqlite_archive_path(self._path)
                        base_ref: ArchiveManifestRef | None = None
                        if anchor is not None and _is_sqlite_archive_anchor(anchor.payload):
                            base_ref = _archive_ref_from_payload(anchor.payload)
                            retained_count = _retained_record_count(
                                anchor.payload,
                                active_count=len(semantic_records),
                            )
                            desired_records = semantic_records[retained_count:]
                            tenant_id = base_ref.tenant_id
                            cached = self._archive_store_cache
                            if cached is not None and cached[:2] == (
                                base_ref.store_id,
                                base_ref.tenant_id,
                            ):
                                store = cached[2]
                            else:
                                store = _open_anchored_archive_store(
                                    self._path,
                                    payload=anchor.payload,
                                    ref=base_ref,
                                    mac_key=self._mac_key,
                                )
                                self._archive_store_cache = (
                                    base_ref.store_id,
                                    base_ref.tenant_id,
                                    store,
                                )
                            tombstone_source = records
                        elif migrate_legacy:
                            logical_history = _logical_history_records(
                                self._path,
                                records=records,
                                mac_key=self._mac_key,
                            )
                            desired_records = logical_history
                            tenant_id = _archive_tenant_id(logical_history)
                            store = ArchiveStore(
                                archive_path,
                                tenant_id=tenant_id,
                                mac_key=_archive_mac_key(self._mac_key),
                            )
                            tombstone_source = logical_history
                        else:
                            desired_records = semantic_records
                            tenant_id = _archive_tenant_id(desired_records)
                            store = ArchiveStore(
                                archive_path,
                                tenant_id=tenant_id,
                                mac_key=_archive_mac_key(self._mac_key),
                            )
                            tombstone_source = records
                        desired_tombstones = _non_idempotent_tool_effect_tombstones(
                            tombstone_source,
                            retained_records=tail,
                        )
                        archive_records = tuple(
                            _to_archive_record(record) for record in desired_records
                        )
                        archive_ref = _prepare_archive_generation(
                            store,
                            base_ref=base_ref,
                            desired_records=archive_records,
                            desired_tombstones=desired_tombstones,
                        )
                        self._archive_store_cache = (
                            archive_ref.store_id,
                            archive_ref.tenant_id,
                            store,
                        )
                        anchor_payload = _sqlite_anchor_payload(
                            archive_path=archive_path,
                            ref=archive_ref,
                            retained_record_count=len(tail),
                        )
                    else:
                        archive_path = None
                        prior_archived_count = _prior_archived_record_count(anchor)
                        archived_count = prior_archived_count + len(semantic_records) - len(tail)
                        archive_hash = stable_hash(
                            {"record_hashes": [record.record_hash for record in records]}
                        )
                        tombstones = set(effect_tombstones)
                        if anchor is not None and _is_sqlite_archive_anchor(anchor.payload):
                            ref = _archive_ref_from_payload(anchor.payload)
                            store = _open_anchored_archive_store(
                                self._path,
                                payload=anchor.payload,
                                ref=ref,
                                mac_key=self._mac_key,
                            )
                            tombstones.update(store.iter_tombstones(ref))
                        anchor_payload = {
                            "archived_record_count": archived_count,
                            "retained_record_count": len(tail),
                            "archive_hash": archive_hash,
                            "archive_required": False,
                            "archive_name": None,
                            "compacted_at_ms": int(time.time() * 1000),
                            "effect_tombstones": sorted(tombstones),
                        }
                    compacted: list[CommitRecord] = []
                    compacted.append(
                        _build_record(
                            records=compacted,
                            mac_key=self._mac_key,
                            record_type="snapshot_anchor",
                            tenant_id="__system__",
                            run_id="compaction",
                            payload=anchor_payload,
                        )
                    )
                    for record in tail:
                        compacted.append(
                            _build_record(
                                records=compacted,
                                mac_key=self._mac_key,
                                record_type=record.record_type,
                                tenant_id=record.tenant_id,
                                run_id=record.run_id,
                                payload=record.payload,
                            )
                        )

                    tmp_path = self._path.with_suffix(self._path.suffix + ".compact")
                    try:
                        with tmp_path.open("w", encoding="utf-8") as handle:
                            _make_handle_private(handle)
                            for record in compacted:
                                handle.write(_record_to_json(record) + "\n")
                            handle.flush()
                            os.fsync(handle.fileno())
                        if (
                            self._path.stat().st_size != offset
                            or _active_journal_fingerprint(self._path) != source_fingerprint
                        ):
                            tmp_path.unlink()
                            continue
                        os.replace(tmp_path, self._path)
                        _fsync_directory(self._path.parent)
                    except Exception:
                        with suppress(FileNotFoundError):
                            tmp_path.unlink()
                        raise
                    self._records = compacted
                    self._archive_anchors = [
                        record for record in compacted if record.record_type == "snapshot_anchor"
                    ]
                    self._offset = self._path.stat().st_size
                    self._active_fingerprint = _active_journal_fingerprint(self._path)
                    if archive_path is not None:
                        _prune_legacy_archives_locked(self._path)
                        self._required_archives_cache = (
                            _required_archives_fingerprint(self._path, self._archive_anchors),
                            VerificationReport(ok=True, errors=()),
                        )
                    else:
                        self._archive_store_cache = None
                        self._required_archives_cache = None
                    return True
                raise ValueError("journal changed during compaction")
            finally:
                _unlock_file(lock_handle)

    def _sync_from_disk_locked(self, handle: TextIO) -> bool:
        """Load records appended by another writer without replaying the whole file."""
        current_fingerprint = _active_journal_fingerprint_from_handle(handle)
        path_fingerprint = _active_journal_fingerprint(self._path)
        if current_fingerprint[:2] != path_fingerprint[:2]:
            raise ValueError("invalid journal file: active_path_replaced_during_operation")
        if current_fingerprint[:2] != self._active_fingerprint[:2]:
            return self._reload_or_raise_locked(handle, replacement=True)
        end_offset = current_fingerprint[3]
        if end_offset < self._offset:
            raise ValueError("invalid journal file: active_journal_rollback")
        if end_offset == self._offset:
            if current_fingerprint == self._active_fingerprint:
                return False
            return self._reload_or_raise_locked(handle, replacement=False)
        return self._reload_external_growth_locked(handle)

    def _reload_external_growth_locked(self, handle: TextIO) -> bool:
        report, records, offset = _read_verified_handle(handle, mac_key=self._mac_key)
        if not report.ok and _recoverable_tail_error(
            report,
            self._path,
            clean_offset=offset,
        ):
            if records[: len(self._records)] != self._records:
                raise ValueError("invalid journal file: active_journal_rewrite")
            _isolate_corrupt_tail_locked(self._path, clean_offset=offset)
            report, records, offset = _read_verified_handle(handle, mac_key=self._mac_key)
        if not report.ok:
            raise ValueError("invalid journal file: " + ",".join(report.errors))
        if len(records) < len(self._records):
            raise ValueError("invalid journal file: active_journal_rollback")
        if records[: len(self._records)] != self._records:
            raise ValueError("invalid journal file: active_journal_rewrite")
        records_changed = len(records) != len(self._records)
        self._records = records
        self._archive_anchors = [
            record for record in records if record.record_type == "snapshot_anchor"
        ]
        self._offset = offset
        self._active_fingerprint = _active_journal_fingerprint_from_handle(handle)
        handle.seek(self._offset)
        return records_changed

    def _reload_or_raise_locked(self, handle: TextIO, *, replacement: bool) -> bool:
        report, records, offset = _read_verified_handle(handle, mac_key=self._mac_key)
        if not report.ok:
            raise ValueError("invalid journal file: " + ",".join(report.errors))
        records_changed = records != self._records
        if replacement:
            if not _is_legal_compaction_replacement(self._records, records):
                raise ValueError("invalid journal file: active_journal_replacement")
        elif offset < self._offset:
            raise ValueError("invalid journal file: active_journal_rollback")
        elif records_changed:
            raise ValueError("invalid journal file: active_journal_rewrite")
        self._records = records
        self._archive_anchors = [
            record for record in records if record.record_type == "snapshot_anchor"
        ]
        self._offset = offset
        self._active_fingerprint = _active_journal_fingerprint_from_handle(handle)
        handle.seek(self._offset)
        return records_changed

    def _recover_tail_locked(self, handle: TextIO, *, clean_offset: int) -> bool:
        handle.seek(0, os.SEEK_END)
        end_offset = handle.tell()
        if end_offset <= clean_offset:
            return False
        if self._offset != end_offset:
            return False
        tail = b""
        handle.flush()
        with self._path.open("rb") as reader:
            reader.seek(clean_offset)
            tail = reader.read()
        if not _is_incomplete_tail(tail):
            return False
        corrupt_path = self._path.with_suffix(self._path.suffix + ".corrupt")
        with corrupt_path.open("ab") as corrupt:
            _make_handle_private(corrupt)
            corrupt.write(tail)
            corrupt.flush()
            os.fsync(corrupt.fileno())
        handle.seek(clean_offset)
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())
        self._offset = clean_offset
        self._reload_or_raise_locked(handle, replacement=False)
        return True


def verify_records(records: tuple[CommitRecord, ...], *, mac_key: bytes) -> VerificationReport:
    errors: list[str] = []
    expected_prev = GENESIS_HASH
    for index, record in enumerate(records):
        if record.seq != index:
            errors.append(f"seq:{index}:seq_gap")
            break
        if record.prev_hash != expected_prev:
            errors.append(f"seq:{index}:prev_hash_mismatch")
            break
        recomputed_hash = stable_hash(record.hash_payload())
        if record.record_hash != recomputed_hash:
            errors.append(f"seq:{index}:record_hash_mismatch")
            break
        mac_payload = {**record.hash_payload(), "record_hash": record.record_hash}
        if not hmac_matches(mac_key, mac_payload, record.mac):
            errors.append(f"seq:{index}:mac_mismatch")
            break
        expected_prev = record.record_hash
    return VerificationReport(ok=not errors, errors=tuple(errors))


def verify_file(path: Path, *, mac_key: bytes) -> VerificationReport:
    report, _records, _offset = _read_verified_file(path, mac_key=mac_key)
    return report


def _read_verified_file(
    path: Path, *, mac_key: bytes
) -> tuple[VerificationReport, list[CommitRecord], int]:
    with path.open("r", encoding="utf-8") as handle:
        return _read_verified_handle(handle, mac_key=mac_key)


def _read_verified_handle(
    handle: TextIO,
    *,
    mac_key: bytes,
) -> tuple[VerificationReport, list[CommitRecord], int]:
    records: list[CommitRecord] = []
    handle.seek(0)
    line_number = 0
    while True:
        line_start = handle.tell()
        raw_line = handle.readline()
        if raw_line == "":
            break
        line_number += 1
        line = raw_line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return (
                VerificationReport(ok=False, errors=(f"line:{line_number}:invalid_json",)),
                records,
                line_start,
            )
        try:
            record = _record_from_row(row)
        except (KeyError, TypeError, ValueError):
            return (
                VerificationReport(ok=False, errors=(f"line:{line_number}:invalid_record",)),
                records,
                line_start,
            )
        tip = records[-1] if records else None
        error = _validate_next_record(
            record,
            expected_seq=len(records),
            expected_prev_hash=tip.record_hash if tip is not None else GENESIS_HASH,
            mac_key=mac_key,
        )
        if error:
            return (
                VerificationReport(ok=False, errors=(f"seq:{len(records)}:{error}",)),
                records,
                line_start,
            )
        records.append(record)
    return VerificationReport(ok=True, errors=()), records, handle.tell()


def _recoverable_tail_error(
    report: VerificationReport,
    path: Path,
    *,
    clean_offset: int,
) -> bool:
    if not report.errors:
        return False
    first = report.errors[0]
    if not (
        first.endswith(":invalid_json")
        or first.endswith(":invalid_record")
        or first.endswith(":record_hash_mismatch")
        or first.endswith(":mac_mismatch")
        or first.endswith(":seq_mismatch")
        or first.endswith(":prev_hash_mismatch")
    ):
        return False
    try:
        with path.open("rb") as handle:
            handle.seek(clean_offset)
            tail = handle.read()
    except OSError:
        return False
    # 半写尾部：无换行符（崩溃中断）
    if _is_incomplete_tail(tail):
        return True
    # 完整但 hash/MAC 错误的坏尾：出错记录是最后一条记录（含换行符）
    # 检查 clean_offset 之后是否只有一行
    return _is_last_record_tail(tail)


def _is_incomplete_tail(tail: bytes) -> bool:
    return bool(tail) and b"\n" not in tail and b"\r" not in tail


def _is_last_record_tail(tail: bytes) -> bool:
    """Check if the tail contains exactly one complete record line."""
    if not tail:
        return False
    stripped = tail.rstrip(b"\r\n")
    if not stripped:
        return False
    # 如果只有一行（可能带尾部换行），则为最后一条记录
    return b"\n" not in stripped and b"\r" not in stripped


def _isolate_corrupt_tail(path: Path, *, clean_offset: int) -> None:
    lock_path = _journal_lock_path(path)
    with _path_lock(path), lock_path.open("a+b") as lock_handle:
        _make_handle_private(lock_handle)
        _lock_file(lock_handle)
        try:
            _isolate_corrupt_tail_locked(path, clean_offset=clean_offset)
        finally:
            _unlock_file(lock_handle)


def _isolate_corrupt_tail_locked(path: Path, *, clean_offset: int) -> None:
    with path.open("rb+") as handle:
        _make_handle_private(handle)
        handle.seek(clean_offset)
        tail = handle.read()
        if tail:
            corrupt_path = path.with_suffix(path.suffix + ".corrupt")
            with corrupt_path.open("ab") as corrupt:
                _make_handle_private(corrupt)
                corrupt.write(tail)
                corrupt.flush()
                os.fsync(corrupt.fileno())
        handle.seek(clean_offset)
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _make_handle_private(handle: IO[Any]) -> None:
    if stat.S_IMODE(os.fstat(handle.fileno()).st_mode) != 0o600:
        os.fchmod(handle.fileno(), 0o600)


def _make_path_private(path: Path) -> None:
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        os.chmod(path, 0o600)


def _sqlite_archive_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + _SQLITE_ARCHIVE_SUFFIX)


def _archive_mac_key(mac_key: bytes) -> bytes:
    return hashlib.sha256(b"echo-sqlite-archive-v1\0" + mac_key).digest()


def _to_archive_record(record: CommitRecord) -> ArchiveRecord:
    return ArchiveRecord(
        record_type=record.record_type,
        tenant_id=record.tenant_id,
        run_id=record.run_id,
        payload=record.payload,
    )


def _archive_tenant_id(records: Sequence[CommitRecord]) -> str:
    tenant_ids = {record.tenant_id for record in records}
    if len(tenant_ids) != 1:
        raise ValueError("journal archive requires exactly one semantic tenant")
    return next(iter(tenant_ids))


def _retained_record_count(payload: dict[str, Any], *, active_count: int) -> int:
    retained_count = payload.get("retained_record_count")
    if (
        not isinstance(retained_count, int)
        or isinstance(retained_count, bool)
        or retained_count < 0
        or retained_count > active_count
    ):
        raise ValueError("invalid journal archive chain: retained_record_count")
    return retained_count


def _prior_archived_record_count(anchor: CommitRecord | None) -> int:
    if anchor is None:
        return 0
    archived_count = anchor.payload.get("archived_record_count")
    if (
        not isinstance(archived_count, int)
        or isinstance(archived_count, bool)
        or archived_count < 0
    ):
        raise ValueError("invalid journal archive chain: archived_record_count")
    return archived_count


def _archive_ref_to_payload(ref: ArchiveManifestRef) -> dict[str, object]:
    return {
        "format": ref.format,
        "schema_version": ref.schema_version,
        "store_id": ref.store_id.hex(),
        "tenant_id": ref.tenant_id,
        "generation": ref.generation,
        "prev_manifest_hash": ref.prev_manifest_hash.hex(),
        "first_seq": ref.first_seq,
        "added_record_count": ref.added_record_count,
        "cumulative_record_count": ref.cumulative_record_count,
        "archive_tip_hash": ref.archive_tip_hash.hex(),
        "added_tombstone_count": ref.added_tombstone_count,
        "cumulative_tombstone_count": ref.cumulative_tombstone_count,
        "tombstone_tip_hash": ref.tombstone_tip_hash.hex(),
        "manifest_hash": ref.manifest_hash.hex(),
        "mac": ref.mac.hex(),
    }


def _archive_ref_from_payload(payload: dict[str, Any]) -> ArchiveManifestRef:
    raw_ref = payload.get("archive_ref")
    if not isinstance(raw_ref, dict) or set(raw_ref) != _ARCHIVE_REF_FIELDS:
        raise ValueError("invalid journal archive chain: archive_ref")

    def required_string(field: str) -> str:
        value = raw_ref.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"invalid journal archive chain: archive_ref_{field}")
        return value

    def required_int(field: str, *, positive: bool = False) -> int:
        value = raw_ref.get(field)
        minimum = 1 if positive else 0
        if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
            raise ValueError(f"invalid journal archive chain: archive_ref_{field}")
        return value

    def required_hex(field: str, *, size: int) -> bytes:
        value = required_string(field)
        try:
            decoded = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError(f"invalid journal archive chain: archive_ref_{field}") from exc
        if len(decoded) != size or value != decoded.hex():
            raise ValueError(f"invalid journal archive chain: archive_ref_{field}")
        return decoded

    return ArchiveManifestRef(
        format=required_string("format"),
        schema_version=required_int("schema_version", positive=True),
        store_id=required_hex("store_id", size=16),
        tenant_id=required_string("tenant_id"),
        generation=required_int("generation", positive=True),
        prev_manifest_hash=required_hex("prev_manifest_hash", size=32),
        first_seq=required_int("first_seq", positive=True),
        added_record_count=required_int("added_record_count"),
        cumulative_record_count=required_int("cumulative_record_count"),
        archive_tip_hash=required_hex("archive_tip_hash", size=32),
        added_tombstone_count=required_int("added_tombstone_count"),
        cumulative_tombstone_count=required_int("cumulative_tombstone_count"),
        tombstone_tip_hash=required_hex("tombstone_tip_hash", size=32),
        manifest_hash=required_hex("manifest_hash", size=32),
        mac=required_hex("mac", size=32),
    )


def _is_sqlite_archive_anchor(payload: dict[str, Any]) -> bool:
    return payload.get("archive_format") == _SQLITE_ARCHIVE_FORMAT or "archive_ref" in payload


def _open_anchored_archive_store(
    journal_path: Path,
    *,
    payload: dict[str, Any],
    ref: ArchiveManifestRef,
    mac_key: bytes,
) -> ArchiveStore:
    archive_path = _sqlite_archive_path(journal_path)
    if payload.get("archive_name") != archive_path.name or not archive_path.is_file():
        raise ValueError("invalid required journal archive: archive_missing")
    store = ArchiveStore(
        archive_path,
        tenant_id=ref.tenant_id,
        mac_key=_archive_mac_key(mac_key),
    )
    if not store.verify(ref):
        raise ValueError("invalid required journal archive: sqlite_verification")
    return store


def _prepare_archive_generation(
    store: ArchiveStore,
    *,
    base_ref: ArchiveManifestRef | None,
    desired_records: tuple[ArchiveRecord, ...],
    desired_tombstones: tuple[str, ...],
) -> ArchiveManifestRef:
    base_generation = 0 if base_ref is None else base_ref.generation
    base_record_count = 0 if base_ref is None else base_ref.cumulative_record_count
    latest_manifest = store.latest_manifest()
    latest_ref = None if latest_manifest is None else latest_manifest.to_ref()

    if latest_ref is None:
        if base_ref is not None:
            raise ValueError("invalid required journal archive: anchored_generation_missing")
        working_ref = None
        consumed_records = 0
    elif latest_ref.generation < base_generation:
        raise ValueError("invalid required journal archive: archive_generation_rollback")
    elif latest_ref.generation == base_generation:
        if base_ref is None or latest_ref != base_ref:
            raise ValueError("invalid required journal archive: anchored_generation_mismatch")
        working_ref = base_ref
        consumed_records = 0
    else:
        if not store.verify(latest_ref):
            raise ValueError("invalid required journal archive: future_generation_invalid")
        archived_records = tuple(store.iter_records(latest_ref))
        if len(archived_records) < base_record_count:
            raise ValueError("invalid required journal archive: archive_record_rollback")
        future_delta = archived_records[base_record_count:]
        if (
            len(future_delta) > len(desired_records)
            or future_delta != desired_records[: len(future_delta)]
        ):
            raise ValueError("invalid required journal archive: future_generation_delta_mismatch")
        working_ref = latest_ref
        consumed_records = len(future_delta)

    remainder = desired_records[consumed_records:]
    existing_tombstones = set() if working_ref is None else set(store.iter_tombstones(working_ref))
    missing_tombstones = set(desired_tombstones).difference(existing_tombstones)
    if not remainder and not missing_tombstones:
        if working_ref is None:
            raise ValueError("journal archive generation cannot be empty")
        return working_ref
    try:
        prepared_ref = store.prepare_generation(
            working_ref,
            remainder,
            desired_tombstones,
        )
    except ArchiveConflictError as exc:
        raise ValueError(
            "invalid required journal archive: future_generation_delta_mismatch"
        ) from exc
    if not store.verify(prepared_ref):
        raise ValueError("invalid required journal archive: committed_generation_invalid")
    return prepared_ref


def _sqlite_anchor_payload(
    *,
    archive_path: Path,
    ref: ArchiveManifestRef,
    retained_record_count: int,
) -> dict[str, Any]:
    archived_record_count = ref.cumulative_record_count - retained_record_count
    if archived_record_count < 0:
        raise ValueError("invalid journal archive chain: retained_record_count")
    return {
        "archived_record_count": archived_record_count,
        "archived_tombstone_count": ref.cumulative_tombstone_count,
        "retained_record_count": retained_record_count,
        "archive_cumulative_record_count": ref.cumulative_record_count,
        "archive_cumulative_tombstone_count": ref.cumulative_tombstone_count,
        "archive_hash": "sha256:" + ref.manifest_hash.hex(),
        "archive_required": True,
        "archive_name": archive_path.name,
        "archive_format": ref.format,
        "archive_ref": _archive_ref_to_payload(ref),
        "compacted_at_ms": int(time.time() * 1000),
    }


def _prune_legacy_archives_locked(path: Path) -> None:
    removed = False
    for archive_path in path.parent.glob(path.name + ".archive.*.gz"):
        archive_path.unlink()
        removed = True
    if removed:
        _fsync_directory(path.parent)


def _archive_journal_locked(
    path: Path,
    *,
    records: Sequence[CommitRecord],
    mac_key: bytes,
) -> tuple[Path, tuple[CommitRecord, ...], str]:
    logical_history = _logical_history_records(
        path,
        records=records,
        mac_key=mac_key,
    )
    archived_records: list[CommitRecord] = []
    for record in logical_history:
        archived_records.append(
            _build_record(
                records=archived_records,
                mac_key=mac_key,
                record_type=record.record_type,
                tenant_id=record.tenant_id,
                run_id=record.run_id,
                payload=record.payload,
            )
        )
    timestamp = time.time_ns()
    archive_path = path.with_suffix(path.suffix + f".archive.{timestamp}.gz")
    tmp_path = path.with_suffix(path.suffix + f".archive.{timestamp}.tmp")
    archive_installed = False
    try:
        with tmp_path.open("wb") as raw_target:
            _make_handle_private(raw_target)
            with gzip.GzipFile(fileobj=raw_target, mode="wb", mtime=0) as target:
                for record in archived_records:
                    target.write((_record_to_json(record) + "\n").encode("utf-8"))
            raw_target.flush()
            os.fsync(raw_target.fileno())

        os.replace(tmp_path, archive_path)
        archive_installed = True
        _fsync_directory(path.parent)
        archive_hash = stable_hash(
            {"record_hashes": [record.record_hash for record in archived_records]}
        )
        return archive_path, tuple(archived_records), archive_hash
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        if archive_installed:
            try:
                archive_path.unlink()
            except FileNotFoundError:
                pass
        raise


def _logical_history_records(
    journal_path: Path,
    *,
    records: Sequence[CommitRecord],
    mac_key: bytes,
    visited_archives: frozenset[str] = frozenset(),
) -> list[CommitRecord]:
    anchors = [record for record in records if record.record_type == "snapshot_anchor"]
    if not anchors:
        return list(records)
    if len(anchors) != 1 or records[0].record_type != "snapshot_anchor":
        raise ValueError("invalid journal archive chain: ambiguous_snapshot_anchor")

    anchor = anchors[0]
    archive_name_raw = anchor.payload.get("archive_name")
    archive_name = str(archive_name_raw or "")
    if not archive_name or Path(archive_name).name != archive_name:
        raise ValueError("invalid journal archive chain: archive_name_invalid")
    if archive_name in visited_archives:
        raise ValueError("invalid journal archive chain: archive_cycle")

    expected_hash = str(anchor.payload.get("archive_hash") or "")
    archived_records: list[CommitRecord] | None = None
    for candidate in _required_archive_candidates(
        journal_path,
        archive_name=archive_name,
    ):
        if not candidate.is_file():
            continue
        report, candidate_records, actual_hash = _read_archive(
            candidate,
            mac_key=mac_key,
        )
        if report.ok and actual_hash == expected_hash:
            archived_records = candidate_records
            break
    if archived_records is None:
        raise ValueError("invalid journal archive chain: archive_missing_or_invalid")

    retained_count = anchor.payload.get("retained_record_count")
    current_records = [record for record in records if record.record_type != "snapshot_anchor"]
    if (
        not isinstance(retained_count, int)
        or retained_count < 0
        or retained_count > len(current_records)
    ):
        raise ValueError("invalid journal archive chain: retained_record_count")

    prior_history = _logical_history_records(
        journal_path,
        records=archived_records,
        mac_key=mac_key,
        visited_archives=visited_archives | {archive_name},
    )
    return prior_history + current_records[retained_count:]


def _prune_archives_locked(
    path: Path,
    *,
    max_archives: int,
    protected_names: set[str] | None = None,
) -> None:
    archives = sorted(path.parent.glob(path.name + ".archive.*.gz"))
    remove_count = max(0, len(archives) - max_archives)
    protected = protected_names or set()
    removable = [archive for archive in archives if archive.name not in protected]
    for old_archive in removable[:remove_count]:
        old_archive.unlink()
    if remove_count and removable:
        _fsync_directory(path.parent)


def _active_journal_fingerprint(path: Path) -> ActiveJournalFingerprint:
    return _active_journal_fingerprint_from_stat(path.stat())


def _active_journal_fingerprint_from_handle(handle: TextIO) -> ActiveJournalFingerprint:
    return _active_journal_fingerprint_from_stat(os.fstat(handle.fileno()))


def _active_journal_fingerprint_from_stat(metadata: os.stat_result) -> ActiveJournalFingerprint:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _is_legal_compaction_replacement(
    previous: Sequence[CommitRecord],
    replacement: Sequence[CommitRecord],
) -> bool:
    if not replacement or replacement[0].record_type != "snapshot_anchor":
        return False
    anchor = replacement[0]
    payload = anchor.payload
    retained_count = payload.get("retained_record_count")
    archived_count = payload.get("archived_record_count")
    compacted_at_ms = payload.get("compacted_at_ms")
    archive_hash = payload.get("archive_hash")
    if (
        not isinstance(retained_count, int)
        or retained_count != len(replacement) - 1
        or not isinstance(archived_count, int)
        or archived_count < 0
        or not isinstance(compacted_at_ms, int)
        or compacted_at_ms < 0
        or not isinstance(archive_hash, str)
        or not archive_hash.startswith("sha256:")
    ):
        return False
    previous_anchors = [record for record in previous if record.record_type == "snapshot_anchor"]
    if not previous_anchors:
        return True
    previous_times = [
        value
        for record in previous_anchors
        if isinstance((value := record.payload.get("compacted_at_ms")), int)
    ]
    return anchor.record_hash not in {record.record_hash for record in previous_anchors} and (
        not previous_times or compacted_at_ms >= max(previous_times)
    )


def _read_file_records(path: Path) -> list[CommitRecord]:
    records: list[CommitRecord] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if line:
                records.append(_record_from_row(json.loads(line)))
        return records


def _verify_archive(
    path: Path,
    *,
    mac_key: bytes,
) -> tuple[VerificationReport, str]:
    report, _records, archive_hash = _read_archive(path, mac_key=mac_key)
    return report, archive_hash


def _read_archive(
    path: Path,
    *,
    mac_key: bytes,
) -> tuple[VerificationReport, list[CommitRecord], str]:
    records: list[CommitRecord] = []
    try:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    records.append(_record_from_row(json.loads(line)))
                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    return (
                        VerificationReport(
                            ok=False,
                            errors=(f"archive_line:{line_number}:invalid_record",),
                        ),
                        records,
                        "",
                    )
    except (OSError, EOFError, gzip.BadGzipFile, UnicodeError) as exc:
        return (
            VerificationReport(
                ok=False,
                errors=(f"archive_read:{exc.__class__.__name__}",),
            ),
            records,
            "",
        )
    report = verify_records(tuple(records), mac_key=mac_key)
    archive_hash = stable_hash({"record_hashes": [record.record_hash for record in records]})
    return report, records, archive_hash


def _verify_required_archives(
    journal_path: Path,
    *,
    archive_anchors: Sequence[CommitRecord],
    active_record_count: int,
    mac_key: bytes,
) -> VerificationReport:
    metadata_report = _verify_required_archive_metadata(
        journal_path,
        archive_anchors=archive_anchors,
        active_record_count=active_record_count,
    )
    if not metadata_report.ok:
        return metadata_report
    return _verify_required_archive_contents(
        journal_path,
        archive_anchors=archive_anchors,
        mac_key=mac_key,
    )


def _verify_required_archive_metadata(
    journal_path: Path,
    *,
    archive_anchors: Sequence[CommitRecord],
    active_record_count: int,
) -> VerificationReport:
    errors: list[str] = []
    for record in archive_anchors:
        payload = record.payload
        if payload.get("archive_required", True) is False:
            continue
        if _is_sqlite_archive_anchor(payload):
            try:
                ref = _archive_ref_from_payload(payload)
                retained_count = _retained_record_count(
                    payload,
                    active_count=active_record_count,
                )
                expected_archived_count = ref.cumulative_record_count - retained_count
                if (
                    payload.get("archive_required") is not True
                    or payload.get("archive_name") != _sqlite_archive_path(journal_path).name
                    or payload.get("archive_format") != ref.format
                    or ref.format != _SQLITE_ARCHIVE_FORMAT
                    or payload.get("archive_hash") != "sha256:" + ref.manifest_hash.hex()
                    or payload.get("archived_record_count") != expected_archived_count
                    or payload.get("archived_tombstone_count") != ref.cumulative_tombstone_count
                    or payload.get("archive_cumulative_record_count") != ref.cumulative_record_count
                    or payload.get("archive_cumulative_tombstone_count")
                    != ref.cumulative_tombstone_count
                    or not isinstance(payload.get("compacted_at_ms"), int)
                    or isinstance(payload.get("compacted_at_ms"), bool)
                    or payload["compacted_at_ms"] < 0
                ):
                    raise ValueError("sqlite_anchor_metadata")
            except (TypeError, ValueError) as exc:
                errors.append(f"seq:{record.seq}:archive_invalid:{exc.__class__.__name__}")
            continue
        if "archive_format" in payload or "archive_ref" in payload:
            errors.append(f"seq:{record.seq}:archive_format_invalid")
    return VerificationReport(ok=not errors, errors=tuple(errors))


def _verify_required_archive_contents(
    journal_path: Path,
    *,
    archive_anchors: Sequence[CommitRecord],
    mac_key: bytes,
) -> VerificationReport:
    errors: list[str] = []
    for record in archive_anchors:
        payload = record.payload
        if payload.get("archive_required", True) is False:
            continue
        if _is_sqlite_archive_anchor(payload):
            try:
                ref = _archive_ref_from_payload(payload)
                _open_anchored_archive_store(
                    journal_path,
                    payload=payload,
                    ref=ref,
                    mac_key=mac_key,
                )
            except (ArchiveStoreError, OSError, TypeError, ValueError) as exc:
                if "archive_missing" in str(exc):
                    errors.append(f"seq:{record.seq}:archive_missing")
                else:
                    errors.append(f"seq:{record.seq}:archive_invalid:{exc.__class__.__name__}")
            continue
        if "archive_format" in payload or "archive_ref" in payload:
            errors.append(f"seq:{record.seq}:archive_format_invalid")
            continue
        expected_hash = str(payload.get("archive_hash", ""))
        archive_name = payload.get("archive_name")
        if archive_name is not None and Path(str(archive_name)).name != str(archive_name):
            errors.append(f"seq:{record.seq}:archive_name_invalid")
            continue
        candidates = _required_archive_candidates(journal_path, archive_name=archive_name)
        existing = tuple(candidate for candidate in candidates if candidate.is_file())
        if not existing:
            errors.append(f"seq:{record.seq}:archive_missing")
            continue

        valid_hashes: list[str] = []
        archive_errors: list[str] = []
        for candidate in existing:
            report, actual_hash = _verify_archive(candidate, mac_key=mac_key)
            if report.ok:
                valid_hashes.append(actual_hash)
                if actual_hash == expected_hash:
                    break
            else:
                archive_errors.extend(report.errors)
        else:
            if valid_hashes:
                errors.append(f"seq:{record.seq}:archive_hash_mismatch")
            else:
                detail = archive_errors[0] if archive_errors else "unreadable"
                errors.append(f"seq:{record.seq}:archive_invalid:{detail}")
    return VerificationReport(ok=not errors, errors=tuple(errors))


def _required_archives_fingerprint(
    journal_path: Path,
    archive_anchors: Sequence[CommitRecord],
) -> RequiredArchivesFingerprint:
    rows: list[tuple[str, str, tuple[tuple[str, ArchiveCandidateFingerprint], ...]]] = []
    for record in archive_anchors:
        payload = record.payload
        if payload.get("archive_required", True) is False:
            continue
        archive_name = payload.get("archive_name")
        candidates = _required_archive_candidates(journal_path, archive_name=archive_name)
        rows.append(
            (
                record.record_hash,
                str(archive_name),
                tuple(
                    (str(candidate), _archive_candidate_fingerprint(candidate))
                    for candidate in candidates
                ),
            )
        )
    return tuple(rows)


def _required_archive_candidates(
    journal_path: Path,
    *,
    archive_name: object,
) -> tuple[Path, ...]:
    if archive_name is not None:
        name = str(archive_name)
        if Path(name).name != name:
            return ()
        return (journal_path.parent / name,)
    return tuple(sorted(journal_path.parent.glob(journal_path.name + ".archive.*.gz")))


def _archive_stat_fingerprint(path: Path) -> ArchiveStatFingerprint | None:
    try:
        metadata = path.stat()
    except OSError:
        return None
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _archive_candidate_fingerprint(path: Path) -> ArchiveCandidateFingerprint:
    if path.name.endswith(_SQLITE_ARCHIVE_SUFFIX):
        return (
            _archive_stat_fingerprint(path),
            _archive_stat_fingerprint(Path(str(path) + "-wal")),
            _archive_stat_fingerprint(Path(str(path) + "-journal")),
        )
    return (_archive_stat_fingerprint(path),)


def _build_record(
    *,
    records: list[CommitRecord],
    mac_key: bytes,
    record_type: str,
    tenant_id: str,
    run_id: str,
    payload: dict[str, Any],
) -> CommitRecord:
    seq = len(records)
    prev_hash = records[-1].record_hash if records else GENESIS_HASH
    return _build_record_at(
        seq=seq,
        prev_hash=prev_hash,
        mac_key=mac_key,
        record_type=record_type,
        tenant_id=tenant_id,
        run_id=run_id,
        payload=payload,
    )


def _build_record_at(
    *,
    seq: int,
    prev_hash: str,
    mac_key: bytes,
    record_type: str,
    tenant_id: str,
    run_id: str,
    payload: dict[str, Any],
) -> CommitRecord:
    payload_copy = _clone_payload(payload)
    base = {
        "seq": seq,
        "record_type": record_type,
        "tenant_id": tenant_id,
        "run_id": run_id,
        "payload": payload_copy,
        "prev_hash": prev_hash,
    }
    record_hash = stable_hash(base)
    mac_payload = {**base, "record_hash": record_hash}
    return CommitRecord(
        seq=seq,
        record_type=record_type,
        tenant_id=tenant_id,
        run_id=run_id,
        payload=payload_copy,
        prev_hash=prev_hash,
        record_hash=record_hash,
        mac=stable_hmac(mac_key, mac_payload),
    )


def _validate_next_record(
    record: CommitRecord,
    *,
    expected_seq: int,
    expected_prev_hash: str,
    mac_key: bytes,
) -> str | None:
    if record.seq != expected_seq:
        return "seq_gap"
    if record.prev_hash != expected_prev_hash:
        return "prev_hash_mismatch"
    recomputed_hash = stable_hash(record.hash_payload())
    if record.record_hash != recomputed_hash:
        return "record_hash_mismatch"
    mac_payload = {**record.hash_payload(), "record_hash": record.record_hash}
    if not hmac_matches(mac_key, mac_payload, record.mac):
        return "mac_mismatch"
    return None


def _non_idempotent_tool_effect_tombstones(
    records: Sequence[CommitRecord],
    *,
    retained_records: Sequence[CommitRecord],
) -> tuple[str, ...]:
    tombstones: set[str] = set()
    tool_replay_classes: dict[str, str] = {}
    merged_effects: set[str] = set()
    for record in records:
        payload = record.payload
        if record.record_type == "snapshot_anchor":
            stored = payload.get("effect_tombstones", ())
            if isinstance(stored, list):
                tombstones.update(item for item in stored if isinstance(item, str) and item)
            continue
        if record.record_type == "outbox":
            effect_id = str(payload.get("effect_id") or "")
            seal = payload.get("seal")
            if not effect_id or not isinstance(seal, dict):
                continue
            action_kind = str(seal.get("action_kind") or "")
            replay_class = str(seal.get("replay_class") or "")
            if action_kind.startswith("tool."):
                tool_replay_classes[effect_id] = replay_class
            continue
        if record.record_type == "merge":
            effect_id = str(payload.get("effect_id") or "")
            if effect_id:
                merged_effects.add(effect_id)
    tombstones.update(
        effect_id
        for effect_id in merged_effects
        if tool_replay_classes.get(effect_id) in {"probe_required", "non_idempotent"}
    )
    tombstones.difference_update(
        str(record.payload.get("effect_id") or "")
        for record in retained_records
        if record.record_type == "outbox"
    )
    return tuple(sorted(tombstones))


def _compaction_records(
    records: Sequence[CommitRecord],
    *,
    max_records: int,
) -> list[CommitRecord]:
    """Select a bounded tail plus every still-open effect lifecycle.

    The selection may be non-contiguous. A snapshot anchor proves the
    archived records, while complete lifecycle records keep crash recovery
    replayable without retaining unrelated turns that happened after an old
    manual-review item.
    """
    outbox_starts: dict[str, int] = {}
    effect_starts: dict[str, int] = {}
    lifecycle_for_index: dict[int, int] = {}
    lifecycle_indices: dict[int, list[int]] = {}
    statuses: dict[int, str] = {}
    for index, record in enumerate(records):
        payload = record.payload
        if record.record_type == "snapshot_anchor":
            outbox_starts.clear()
            effect_starts.clear()
            lifecycle_for_index.clear()
            lifecycle_indices.clear()
            statuses.clear()
            continue
        if record.record_type == "outbox":
            outbox_id = str(payload.get("outbox_id") or "")
            effect_id = str(payload.get("effect_id") or "")
            if not outbox_id or not effect_id:
                raise RuntimeError("journal contains malformed effect lifecycle")
            outbox_starts[outbox_id] = index
            effect_starts[effect_id] = index
            lifecycle_for_index[index] = index
            lifecycle_indices[index] = [index]
            statuses[index] = "queued"
            continue
        if record.record_type in {"outbox_claimed", "outbox_manual_review", "receipt"}:
            lifecycle_start = outbox_starts.get(str(payload.get("outbox_id") or ""))
            if lifecycle_start is None:
                raise RuntimeError(f"journal contains orphan {record.record_type}")
            statuses[lifecycle_start] = {
                "outbox_claimed": "claimed",
                "outbox_manual_review": "manual_review",
                "receipt": "receipted",
            }[record.record_type]
        elif record.record_type in {"merge", "manual_review_resolution"}:
            lifecycle_start = effect_starts.get(str(payload.get("effect_id") or ""))
            if lifecycle_start is None:
                raise RuntimeError(f"journal contains orphan {record.record_type}")
            statuses[lifecycle_start] = "merged"
        else:
            lifecycle_start = None
        if lifecycle_start is not None:
            lifecycle_for_index[index] = lifecycle_start
            lifecycle_indices[lifecycle_start].append(index)

    selected = set(range(max(0, len(records) - max_records), len(records)))
    selected.difference_update(
        index for index, record in enumerate(records) if record.record_type == "snapshot_anchor"
    )
    starts_to_keep = {
        lifecycle_for_index[index] for index in selected if index in lifecycle_for_index
    }
    starts_to_keep.update(
        lifecycle_start for lifecycle_start, status in statuses.items() if status != "merged"
    )
    for lifecycle_start in starts_to_keep:
        selected.update(lifecycle_indices[lifecycle_start])
    return [record for index, record in enumerate(records) if index in selected]


def _path_lock(path: Path) -> threading.RLock:
    resolved = path.resolve()
    with _FILE_LOCKS_GUARD:
        lock = _FILE_LOCKS.get(resolved)
        if lock is None:
            lock = threading.RLock()
            _FILE_LOCKS[resolved] = lock
        return lock


def _journal_lock_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".lock")


def _lock_file(handle: IO[Any]) -> None:
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def _unlock_file(handle: IO[Any]) -> None:
    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _record_to_json(record: CommitRecord) -> str:
    row = {
        "seq": record.seq,
        "record_type": record.record_type,
        "tenant_id": record.tenant_id,
        "run_id": record.run_id,
        "payload": record.payload,
        "prev_hash": record.prev_hash,
        "record_hash": record.record_hash,
        "mac": record.mac.hex(),
    }
    return json.dumps(row, sort_keys=True, separators=(",", ":"))


def _clone_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Freeze caller-owned JSON data before hashing and retaining it."""
    cloned = json.loads(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    )
    if not isinstance(cloned, dict):
        raise TypeError("journal payload must be an object")
    return cloned


def _ensure_trailing_newline(handle: TextIO) -> None:
    """Normalize a verified final JSON record before appending another one."""
    end = handle.tell()
    if end == 0:
        return
    handle.seek(end - 1)
    final_character = handle.read(1)
    handle.seek(end)
    if final_character not in {"\n", "\r"}:
        handle.write("\n")


def _record_from_row(row: dict[str, Any]) -> CommitRecord:
    return CommitRecord(
        seq=int(row["seq"]),
        record_type=str(row["record_type"]),
        tenant_id=str(row["tenant_id"]),
        run_id=str(row["run_id"]),
        payload=dict(row["payload"]),
        prev_hash=str(row["prev_hash"]),
        record_hash=str(row["record_hash"]),
        mac=bytes.fromhex(str(row["mac"])),
    )
