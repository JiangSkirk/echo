from __future__ import annotations

import dataclasses
import gc
import io
import json
import os
import sqlite3
import stat
import threading
import tracemalloc
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Literal, cast

import pytest

from js.echo.ledger import archive_store

MAC_KEY = b"archive-test-key-material-32-bytes"


def _record(
    number: int,
    *,
    tenant_id: str = "tenant-a",
    record_type: str = "effect.receipt",
) -> Any:
    return archive_store.ArchiveRecord(
        record_type=record_type,
        tenant_id=tenant_id,
        run_id=f"run-{number}",
        payload={"nested": {"number": number}, "values": [True, None, number]},
    )


def _store(path: Path, *, tenant_id: str = "tenant-a", key: bytes = MAC_KEY) -> Any:
    return archive_store.ArchiveStore(path, tenant_id=tenant_id, mac_key=key)


def _prepare_one(store: Any) -> Any:
    return store.prepare_generation(None, (_record(1),), ("effect-1",))


def test_prepare_generation_streams_large_new_generation_with_bounded_peak_memory(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    records = (
        archive_store.ArchiveRecord(
            record_type="effect.receipt",
            tenant_id="tenant-a",
            run_id=f"run-{index}",
            payload={"index": index, "blob": "x" * 512},
        )
        for index in range(4_096)
    )

    tracemalloc.start()
    try:
        ref = store.prepare_generation(None, records, ())
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert ref.cumulative_record_count == 4_096
    assert store.verify(ref)
    assert peak < 4_000_000


def test_full_archive_verification_streams_with_bounded_peak_memory(tmp_path: Path) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    ref = store.prepare_generation(
        None,
        (
            archive_store.ArchiveRecord(
                record_type="effect.receipt",
                tenant_id="tenant-a",
                run_id=f"run-{index}",
                payload={"index": index, "blob": "x" * 512},
            )
            for index in range(4_096)
        ),
        (),
    )
    store._verified_snapshot = None

    tracemalloc.start()
    try:
        assert store.verify(ref)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert peak < 1_000_000


def test_archive_record_iteration_is_lazy_with_bounded_peak_memory(tmp_path: Path) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    ref = store.prepare_generation(
        None,
        (
            archive_store.ArchiveRecord(
                record_type="effect.receipt",
                tenant_id="tenant-a",
                run_id=f"run-{index}",
                payload={"index": index, "blob": "x" * 512},
            )
            for index in range(4_096)
        ),
        (),
    )

    tracemalloc.start()
    records = store.iter_records(ref)
    try:
        assert next(records).run_id == "run-0"
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        close = getattr(records, "close", None)
        if close is not None:
            close()
        tracemalloc.stop()

    assert peak < 1_000_000


def test_partial_record_iteration_does_not_hold_archive_path_lock(tmp_path: Path) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    first = store.prepare_generation(None, (_record(1),), ())
    records = store.iter_records(first)
    assert next(records).run_id == "run-1"
    completed = threading.Event()
    failures: list[BaseException] = []

    def append_generation() -> None:
        try:
            store.prepare_generation(first, (_record(2),), ())
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)
        finally:
            completed.set()

    worker = threading.Thread(target=append_generation)
    worker.start()
    completed_without_close = completed.wait(1.0)
    close = getattr(records, "close", None)
    if close is not None:
        close()
    worker.join(timeout=2.0)

    assert completed_without_close
    assert not worker.is_alive()
    assert failures == []


def test_record_iteration_wraps_snapshot_creation_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    ref = _prepare_one(store)

    def fail_snapshot_creation(**_kwargs: Any) -> Any:
        raise OSError("snapshot creation failed")

    monkeypatch.setattr(archive_store.tempfile, "SpooledTemporaryFile", fail_snapshot_creation)

    with pytest.raises(archive_store.ArchiveStoreError, match="record iteration"):
        store.iter_records(ref)


def test_record_iteration_wraps_deferred_snapshot_read_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    ref = _prepare_one(store)

    class FailingReadSnapshot(io.StringIO):
        def __next__(self) -> str:
            raise OSError("snapshot read failed")

    snapshot = FailingReadSnapshot()
    monkeypatch.setattr(
        archive_store.tempfile,
        "SpooledTemporaryFile",
        lambda **_kwargs: snapshot,
    )

    records = store.iter_records(ref)
    with pytest.raises(archive_store.ArchiveStoreError, match="snapshot is invalid"):
        next(records)
    assert snapshot.closed


def test_unstarted_record_iterator_close_releases_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    ref = _prepare_one(store)
    snapshot = io.StringIO()
    monkeypatch.setattr(
        archive_store.tempfile,
        "SpooledTemporaryFile",
        lambda **_kwargs: snapshot,
    )

    records = store.iter_records(ref)
    cast("Any", records).close()

    assert snapshot.closed


def test_record_iterator_wraps_explicit_snapshot_close_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    ref = _prepare_one(store)

    class FailingCloseSnapshot(io.StringIO):
        def close(self) -> None:
            raise OSError("snapshot close failed")

    snapshot = FailingCloseSnapshot()
    monkeypatch.setattr(
        archive_store.tempfile,
        "SpooledTemporaryFile",
        lambda **_kwargs: snapshot,
    )

    records = store.iter_records(ref)
    with pytest.raises(archive_store.ArchiveStoreError, match="snapshot close"):
        cast("Any", records).close()
    with pytest.raises(StopIteration):
        next(records)


def test_record_iterator_serializes_cross_thread_read_and_close(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    ref = _prepare_one(store)
    read_started = threading.Event()
    allow_read = threading.Event()
    close_finished = threading.Event()

    class BlockingReadSnapshot(io.StringIO):
        def __next__(self) -> str:
            read_started.set()
            assert allow_read.wait(2.0)
            return super().__next__()

    snapshot = BlockingReadSnapshot()
    monkeypatch.setattr(
        archive_store.tempfile,
        "SpooledTemporaryFile",
        lambda **_kwargs: snapshot,
    )
    records = store.iter_records(ref)
    observed: list[str] = []
    failures: list[BaseException] = []

    def read_one() -> None:
        try:
            observed.append(next(records).run_id)
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    def close_records() -> None:
        try:
            cast("Any", records).close()
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)
        finally:
            close_finished.set()

    reader = threading.Thread(target=read_one)
    closer = threading.Thread(target=close_records)
    reader.start()
    assert read_started.wait(1.0)
    closer.start()
    assert not close_finished.wait(0.1)
    allow_read.set()
    reader.join(timeout=2.0)
    closer.join(timeout=2.0)

    assert observed == ["run-1"]
    assert failures == []
    assert close_finished.is_set()
    assert snapshot.closed


def test_record_iteration_preserves_primary_error_when_snapshot_cleanup_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    ref = _prepare_one(store)

    class FailingWriteAndCloseSnapshot(io.StringIO):
        def write(self, _value: str) -> int:
            raise OSError("snapshot write failed")

        def close(self) -> None:
            raise OSError("snapshot close failed")

    monkeypatch.setattr(
        archive_store.tempfile,
        "SpooledTemporaryFile",
        lambda **_kwargs: FailingWriteAndCloseSnapshot(),
    )

    with pytest.raises(archive_store.ArchiveStoreError, match="record iteration") as captured:
        store.iter_records(ref)
    assert isinstance(captured.value.__cause__, OSError)
    assert str(captured.value.__cause__) == "snapshot write failed"


def _prepare_same_delta_in_process(path: str) -> bytes:
    store = _store(Path(path))
    ref = store.prepare_generation(None, (_record(1),), ("effect-1",))
    return cast("bytes", ref.manifest_hash)


def _prepare_distinct_delta_in_process(arguments: tuple[str, int]) -> tuple[str, bytes]:
    path, number = arguments
    store = _store(Path(path))
    try:
        ref = store.prepare_generation(
            None,
            (_record(number),),
            (f"effect-{number}",),
        )
    except archive_store.ArchiveConflictError:
        return "conflict", b""
    return "ok", cast("bytes", ref.manifest_hash)


def _tamper(path: Path, sql: str, parameters: tuple[object, ...] = ()) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(sql, parameters)


def test_new_archive_store_fsyncs_parent_directory_after_creation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    synced: list[Path] = []
    monkeypatch.setattr(archive_store, "_fsync_directory", synced.append)

    _store(tmp_path / "archive.sqlite3")

    assert synced == [tmp_path]


def test_manifest_and_ref_bind_the_complete_generation_state(tmp_path: Path) -> None:
    store = _store(tmp_path / "archive.sqlite3")

    ref = store.prepare_generation(None, (_record(1), _record(2)), ("effect-1",))
    manifest = store.latest_manifest()

    assert manifest is not None
    assert manifest.to_ref() == ref
    assert ref.format == "echo-sqlite-archive"
    assert ref.schema_version == 1
    assert len(ref.store_id) == 16
    assert ref.tenant_id == "tenant-a"
    assert ref.generation == 1
    assert ref.prev_manifest_hash == bytes(32)
    assert ref.first_seq == 1
    assert ref.added_record_count == 2
    assert ref.cumulative_record_count == 2
    assert len(ref.archive_tip_hash) == 32
    assert ref.added_tombstone_count == 1
    assert ref.cumulative_tombstone_count == 1
    assert len(ref.tombstone_tip_hash) == 32
    assert len(ref.manifest_hash) == 32
    assert len(ref.mac) == 32
    assert store.verify(ref)


def test_store_generates_continuous_record_hash_and_mac_chain(tmp_path: Path) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    first = store.prepare_generation(None, (_record(9),), ())
    second = store.prepare_generation(first, (_record(3), _record(7)), ())

    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT sequence, prev_hash, prev_mac, record_hash, mac "
            "FROM archive_records ORDER BY sequence"
        ).fetchall()

    assert [row[0] for row in rows] == [1, 2, 3]
    assert rows[0][1] == bytes(32)
    assert rows[0][2] == bytes(32)
    assert all(len(value) == 32 for row in rows for value in row[1:])
    assert rows[1][1] == rows[0][3]
    assert rows[1][2] == rows[0][4]
    assert rows[2][1] == rows[1][3]
    assert rows[2][2] == rows[1][4]
    assert store.verify(second)


def test_store_generates_continuous_tombstone_and_manifest_chains(tmp_path: Path) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    first = store.prepare_generation(None, (), ("effect-1",))
    second = store.prepare_generation(first, (), ("effect-2",))

    with sqlite3.connect(path) as connection:
        tombstones = connection.execute(
            "SELECT sequence, prev_hash, prev_mac, tombstone_hash, mac "
            "FROM archive_tombstones ORDER BY sequence"
        ).fetchall()
        manifests = connection.execute(
            "SELECT generation, prev_manifest_hash, manifest_hash "
            "FROM archive_manifests ORDER BY generation"
        ).fetchall()

    assert [row[0] for row in tombstones] == [1, 2]
    assert tombstones[0][1] == bytes(32)
    assert tombstones[0][2] == bytes(32)
    assert tombstones[1][1] == tombstones[0][3]
    assert tombstones[1][2] == tombstones[0][4]
    assert manifests[0][1] == bytes(32)
    assert manifests[1][1] == manifests[0][2]
    assert store.verify(second)


def test_payload_tampering_invalidates_verify_and_read_operations(tmp_path: Path) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    ref = _prepare_one(store)
    _tamper(
        path,
        "UPDATE archive_records SET canonical_payload = ? WHERE sequence = 1",
        (json.dumps({"nested": {"number": 999}}),),
    )

    assert not store.verify(ref)
    with pytest.raises(archive_store.ArchiveStoreError, match="verification"):
        store.contains_effect("missing", ref)
    with pytest.raises(archive_store.ArchiveStoreError, match="verification"):
        tuple(store.iter_records(ref))


def test_tombstone_deletion_invalidates_the_anchored_generation(tmp_path: Path) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    ref = _prepare_one(store)
    _tamper(path, "DELETE FROM archive_tombstones WHERE effect_id = 'effect-1'")

    assert not store.verify(ref)
    with pytest.raises(archive_store.ArchiveStoreError, match="verification"):
        store.contains_effect("effect-1", ref)


def test_manifest_tampering_invalidates_the_ref(tmp_path: Path) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    ref = _prepare_one(store)
    _tamper(
        path,
        "UPDATE archive_manifests SET cumulative_record_count = 99 WHERE generation = 1",
    )

    assert not store.verify(ref)


def test_wrong_mac_key_cannot_verify_existing_archive(tmp_path: Path) -> None:
    path = tmp_path / "archive.sqlite3"
    _prepare_one(_store(path))

    with pytest.raises(archive_store.ArchiveStoreError, match="key"):
        _store(path, key=b"different-test-key-material-32bytes")


def test_empty_store_is_bound_to_the_initial_mac_key(tmp_path: Path) -> None:
    path = tmp_path / "archive.sqlite3"
    original = _store(path)

    with pytest.raises(archive_store.ArchiveStoreError, match="key"):
        _store(path, key=b"different-test-key-material-32bytes")

    ref = _prepare_one(original)
    assert original.verify(ref)


def test_records_and_tombstones_survive_reopen(tmp_path: Path) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    first = store.prepare_generation(None, (_record(1),), ("effect-1",))
    second = store.prepare_generation(first, (_record(2),), ("effect-2",))

    reopened = _store(path)

    assert reopened.verify(second)
    assert [record.run_id for record in reopened.iter_records(second)] == ["run-1", "run-2"]
    assert reopened.contains_effect("effect-1", second)
    assert reopened.contains_effect("effect-2", second)


def test_tombstones_can_be_iterated_at_an_exact_verified_generation(tmp_path: Path) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    first = store.prepare_generation(None, (_record(1),), ("effect-2", "effect-1"))
    second = store.prepare_generation(first, (_record(2),), ("effect-3",))

    assert store.iter_tombstones(first) == ("effect-1", "effect-2")
    assert store.iter_tombstones(second) == ("effect-1", "effect-2", "effect-3")


def test_verified_effect_queries_reuse_unchanged_archive_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    ref = _prepare_one(store)
    original_verify = store._verify_in_transaction
    verify_calls = 0

    def count_verify(connection: sqlite3.Connection, candidate: Any) -> bool:
        nonlocal verify_calls
        verify_calls += 1
        return original_verify(connection, candidate)

    monkeypatch.setattr(store, "_verify_in_transaction", count_verify)

    assert store.verify(ref)
    assert verify_calls == 0
    assert store.contains_effect("effect-1", ref)
    assert not store.contains_effect("missing-effect", ref)
    assert store.contains_effect("effect-1", ref)
    assert verify_calls == 0


def test_prepare_generation_rejects_post_commit_chain_tampering(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    original_fingerprint = archive_store._archive_fingerprint
    tampered = False

    def tamper_before_cache(candidate: Path) -> Any:
        nonlocal tampered
        if not tampered:
            with sqlite3.connect(candidate) as connection:
                manifest_count = connection.execute(
                    "SELECT COUNT(*) FROM archive_manifests"
                ).fetchone()
                if manifest_count == (1,):
                    connection.execute("DELETE FROM archive_tombstones")
                    tampered = True
        return original_fingerprint(candidate)

    monkeypatch.setattr(archive_store, "_archive_fingerprint", tamper_before_cache)

    with pytest.raises(archive_store.ArchiveStoreError, match="committed generation"):
        store.prepare_generation(None, (_record(1),), ("effect-1",))
    assert tampered


def test_effect_query_cache_invalidates_after_archive_tampering(tmp_path: Path) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    ref = _prepare_one(store)
    assert store.verify(ref)

    _tamper(path, "DELETE FROM archive_tombstones WHERE effect_id = 'effect-1'")

    with pytest.raises(archive_store.ArchiveStoreError, match="verification"):
        store.contains_effect("effect-1", ref)


def test_verified_snapshot_rechecks_same_size_database_tampering(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    ref = _prepare_one(store)
    original_verify = store._verify_in_transaction
    verify_calls = 0

    def count_verify(connection: sqlite3.Connection, candidate: Any) -> bool:
        nonlocal verify_calls
        verify_calls += 1
        return original_verify(connection, candidate)

    monkeypatch.setattr(store, "_verify_in_transaction", count_verify)
    assert store.verify(ref)
    assert verify_calls == 0
    before_size = path.stat().st_size

    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute(
            "UPDATE archive_records SET canonical_payload = ? WHERE sequence = 1",
            (json.dumps({"nested": {"number": 9}, "values": [True, None, 1]}),),
        )

    assert path.stat().st_size == before_size
    assert not store.verify(ref)
    assert verify_calls == 1


def test_verified_snapshot_rechecks_wal_writes_before_reuse(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    ref = _prepare_one(store)
    original_verify = store._verify_in_transaction
    verify_calls = 0

    def count_verify(connection: sqlite3.Connection, candidate: Any) -> bool:
        nonlocal verify_calls
        verify_calls += 1
        return original_verify(connection, candidate)

    monkeypatch.setattr(store, "_verify_in_transaction", count_verify)
    assert store.verify(ref)
    assert verify_calls == 0

    with sqlite3.connect(path) as external:
        assert external.execute("PRAGMA journal_mode = WAL").fetchone() == ("wal",)
        external.execute("UPDATE archive_records SET run_id = 'run-x' WHERE sequence = 1")
        external.commit()
        assert Path(str(path) + "-wal").is_file()
        assert not store.verify(ref)

    assert verify_calls == 1


def test_database_is_bound_to_one_tenant_and_refs_are_store_bound(tmp_path: Path) -> None:
    path = tmp_path / "archive.sqlite3"
    ref = _prepare_one(_store(path, tenant_id="tenant-a"))

    with pytest.raises(archive_store.ArchiveStoreError, match="tenant"):
        _store(path, tenant_id="tenant-b")

    other = _store(tmp_path / "other.sqlite3", tenant_id="tenant-a")
    assert not other.verify(ref)


def test_record_tenant_must_match_store_tenant(tmp_path: Path) -> None:
    store = _store(tmp_path / "archive.sqlite3")

    with pytest.raises(ValueError, match="tenant"):
        store.prepare_generation(None, (_record(1, tenant_id="tenant-b"),), ())

    assert store.generation_count() == 0


def test_same_base_and_canonical_delta_are_idempotent(tmp_path: Path) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    records = (_record(1), _record(2))

    first = store.prepare_generation(None, records, ("effect-1", "effect-1"))
    repeated = store.prepare_generation(None, records, ("effect-1",))

    assert repeated == first
    assert store.generation_count() == 1
    assert store.latest_manifest() is not None
    assert store.latest_manifest().added_tombstone_count == 1


def test_tombstone_delta_is_canonical_across_input_order(tmp_path: Path) -> None:
    store = _store(tmp_path / "archive.sqlite3")

    first = store.prepare_generation(None, (), ("effect-2", "effect-1"))
    repeated = store.prepare_generation(None, (), ("effect-1", "effect-2"))

    assert repeated == first
    assert store.generation_count() == 1


def test_same_generation_with_different_delta_is_rejected_without_overwrite(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    original = store.prepare_generation(None, (_record(1),), ("effect-1",))

    with pytest.raises(archive_store.ArchiveConflictError, match="conflict"):
        store.prepare_generation(None, (_record(2),), ("effect-2",))

    assert store.verify(original)
    assert [record.run_id for record in store.iter_records(original)] == ["run-1"]
    assert store.contains_effect("effect-1", original)
    assert not store.contains_effect("effect-2", original)


def test_old_ref_ignores_unanchored_future_generation(tmp_path: Path) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    old_ref = store.prepare_generation(None, (_record(1),), ("effect-old",))
    new_ref = store.prepare_generation(old_ref, (_record(2),), ("effect-future",))

    assert store.verify(old_ref)
    assert store.verify(new_ref)
    assert [record.run_id for record in store.iter_records(old_ref)] == ["run-1"]
    assert store.contains_effect("effect-old", old_ref)
    assert not store.contains_effect("effect-future", old_ref)
    assert store.generation_count() == 2
    assert store.latest_manifest() is not None
    assert store.latest_manifest().generation == 2


def test_old_ref_does_not_depend_on_tampered_future_rows(tmp_path: Path) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    old_ref = store.prepare_generation(None, (_record(1),), ("effect-old",))
    new_ref = store.prepare_generation(old_ref, (_record(2),), ("effect-future",))
    _tamper(
        path,
        "UPDATE archive_records SET canonical_payload = '{}' WHERE generation = 2",
    )

    assert store.verify(old_ref)
    assert not store.verify(new_ref)
    assert store.contains_effect("effect-old", old_ref)
    assert not store.contains_effect("effect-future", old_ref)
    assert [record.run_id for record in store.iter_records(old_ref)] == ["run-1"]


def test_old_ref_ignores_future_generation_check_constraint_damage(tmp_path: Path) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    old_ref = store.prepare_generation(None, (_record(1),), ("effect-old",))
    new_ref = store.prepare_generation(old_ref, (_record(2),), ("effect-future",))
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute("UPDATE archive_records SET sequence = 0 WHERE generation = 2")

    assert store.verify(old_ref)
    assert not store.verify(new_ref)


def test_prepare_generation_rolls_back_atomically_on_insert_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    base_ref = store.prepare_generation(None, (_record(1),), ("effect-1",))
    original_insert = archive_store.ArchiveStore._insert_record
    calls = 0

    def fail_on_second_insert(
        self: Any,
        connection: sqlite3.Connection,
        record: Any,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("injected insert failure")
        original_insert(self, connection, record)

    monkeypatch.setattr(archive_store.ArchiveStore, "_insert_record", fail_on_second_insert)

    with pytest.raises(RuntimeError, match="injected"):
        store.prepare_generation(base_ref, (_record(2), _record(3)), ("effect-new",))

    assert store.generation_count() == 1
    assert store.latest_manifest() is not None
    assert store.latest_manifest().generation == 1
    assert store.verify(base_ref)
    assert not store.contains_effect("effect-new", base_ref)


def test_prepare_generation_rolls_back_streamed_rows_on_manifest_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    base_ref = store.prepare_generation(None, (_record(1),), ("effect-1",))
    original_insert = archive_store.ArchiveStore._insert_manifest

    def fail_second_manifest(
        _self: Any,
        connection: sqlite3.Connection,
        manifest: Any,
    ) -> None:
        if manifest.generation == 2:
            raise RuntimeError("injected manifest failure")
        original_insert(connection, manifest)

    monkeypatch.setattr(archive_store.ArchiveStore, "_insert_manifest", fail_second_manifest)

    with pytest.raises(RuntimeError, match="injected manifest failure"):
        store.prepare_generation(base_ref, (_record(2), _record(3)), ("effect-new",))

    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM archive_records").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM archive_tombstones").fetchone() == (1,)
    assert store.generation_count() == 1
    assert store.verify(base_ref)


def test_prepare_generation_rolls_back_streamed_rows_on_late_validation_failure(
    tmp_path: Path,
) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    base_ref = store.prepare_generation(None, (_record(1),), ())

    with pytest.raises(TypeError, match="ArchiveRecord"):
        store.prepare_generation(base_ref, iter((_record(2), object())), ())

    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM archive_records").fetchone() == (1,)
    assert store.generation_count() == 1
    assert store.verify(base_ref)


def test_concurrent_same_delta_returns_one_generation(tmp_path: Path) -> None:
    store = archive_store.ArchiveStore(
        tmp_path / "archive.sqlite3",
        tenant_id="tenant-a",
        mac_key=MAC_KEY,
        busy_timeout_ms=5_000,
    )
    start = threading.Barrier(8)
    refs: list[Any] = []
    errors: list[BaseException] = []

    def prepare() -> None:
        try:
            start.wait(timeout=5)
            refs.append(store.prepare_generation(None, (_record(1),), ("effect-1",)))
        except BaseException as exc:  # noqa: BLE001 - failures are asserted below
            errors.append(exc)

    threads = [threading.Thread(target=prepare) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert all(not thread.is_alive() for thread in threads)
    assert not errors
    assert len(refs) == 8
    assert all(ref == refs[0] for ref in refs)
    assert store.generation_count() == 1
    assert store.verify(refs[0])


def test_cross_process_same_delta_uses_sqlite_cas(tmp_path: Path) -> None:
    path = tmp_path / "archive.sqlite3"
    _store(path)

    with ProcessPoolExecutor(max_workers=4) as executor:
        manifest_hashes = tuple(executor.map(_prepare_same_delta_in_process, (str(path),) * 4))

    store = _store(path)
    manifest = store.latest_manifest()
    assert len(set(manifest_hashes)) == 1
    assert store.generation_count() == 1
    assert manifest is not None
    assert store.verify(manifest.to_ref())


def test_cross_process_distinct_delta_has_one_winner_and_one_conflict(tmp_path: Path) -> None:
    path = tmp_path / "archive.sqlite3"
    _store(path)

    with ProcessPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(
            executor.map(
                _prepare_distinct_delta_in_process,
                ((str(path), 1), (str(path), 2)),
            )
        )

    store = _store(path)
    manifest = store.latest_manifest()
    assert sorted(outcome for outcome, _hash in outcomes) == ["conflict", "ok"]
    assert store.generation_count() == 1
    assert manifest is not None
    assert store.verify(manifest.to_ref())


def test_retrying_stale_base_returns_existing_generation_after_later_commit(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    first = store.prepare_generation(None, (_record(1),), ("effect-1",))
    second = store.prepare_generation(first, (_record(2),), ("effect-2",))
    third = store.prepare_generation(second, (_record(3),), ("effect-3",))

    assert store.prepare_generation(first, (_record(2),), ("effect-2",)) == second
    with pytest.raises(archive_store.ArchiveConflictError, match="conflict"):
        store.prepare_generation(first, (_record(9),), ("effect-9",))
    assert store.verify(third)


@pytest.mark.parametrize("value", ["records", b"records", bytearray(b"records")])
def test_records_reject_string_like_iterables(tmp_path: Path, value: object) -> None:
    store = _store(tmp_path / "archive.sqlite3")

    with pytest.raises(TypeError, match="records"):
        store.prepare_generation(None, value, ())


@pytest.mark.parametrize("value", ["effect-1", b"effect-1", bytearray(b"effect-1")])
def test_tombstones_reject_string_like_iterables(tmp_path: Path, value: object) -> None:
    store = _store(tmp_path / "archive.sqlite3")

    with pytest.raises(TypeError, match="tombstones"):
        store.prepare_generation(None, (), value)


@pytest.mark.parametrize(
    ("path", "tenant_id", "mac_key", "match"),
    [
        ("", "tenant-a", MAC_KEY, "path"),
        (1, "tenant-a", MAC_KEY, "path"),
        (Path("archive.sqlite3"), "", MAC_KEY, "tenant_id"),
        (Path("archive.sqlite3"), 1, MAC_KEY, "tenant_id"),
        (Path("archive.sqlite3"), "tenant-a", b"short", "mac_key"),
        (Path("archive.sqlite3"), "tenant-a", "not-bytes", "mac_key"),
    ],
)
def test_constructor_rejects_empty_and_weakly_typed_inputs(
    tmp_path: Path,
    path: object,
    tenant_id: object,
    mac_key: object,
    match: str,
) -> None:
    candidate = tmp_path / path if isinstance(path, Path) else path

    with pytest.raises((TypeError, ValueError), match=match):
        archive_store.ArchiveStore(
            candidate,  # type: ignore[arg-type]
            tenant_id=tenant_id,  # type: ignore[arg-type]
            mac_key=mac_key,  # type: ignore[arg-type]
        )


def test_record_payload_must_be_canonical_json(tmp_path: Path) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    bad = archive_store.ArchiveRecord(
        record_type="effect.receipt",
        tenant_id="tenant-a",
        run_id="run-bad",
        payload={"bad": float("nan")},
    )

    with pytest.raises(ValueError, match="payload"):
        store.prepare_generation(None, (bad,), ())

    assert store.generation_count() == 0


def test_tombstone_ids_are_globally_unique_idempotent_and_exact(tmp_path: Path) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    first = store.prepare_generation(None, (), ("effect-1", "effect-1"))
    second = store.prepare_generation(first, (), ("effect-1", "effect-2", "effect-2"))

    assert second.added_tombstone_count == 1
    assert second.cumulative_tombstone_count == 2
    assert store.contains_effect("effect-1", second)
    assert store.contains_effect("effect-2", second)
    assert not store.contains_effect("effect", second)
    assert not store.contains_effect("effect-10", second)

    with sqlite3.connect(tmp_path / "archive.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*), COUNT(DISTINCT effect_id) FROM archive_tombstones"
        ).fetchone() == (2, 2)


def test_forged_ref_fields_fail_verification(tmp_path: Path) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    ref = _prepare_one(store)

    forged = dataclasses.replace(ref, cumulative_record_count=999)

    assert not store.verify(forged)


def test_each_public_operation_opens_a_fresh_connection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "archive.sqlite3")
    ref = _prepare_one(store)
    real_connect = sqlite3.connect
    calls = 0

    def counting_connect(
        database: str | Path,
        *,
        timeout: float,
        isolation_level: Literal["DEFERRED", "EXCLUSIVE", "IMMEDIATE"] | None,
    ) -> sqlite3.Connection:
        nonlocal calls
        calls += 1
        return real_connect(database, timeout=timeout, isolation_level=isolation_level)

    monkeypatch.setattr(sqlite3, "connect", counting_connect)

    assert store.verify(ref)
    assert store.contains_effect("effect-1", ref)
    assert tuple(store.iter_records(ref))
    assert store.generation_count() == 1
    assert store.latest_manifest() is not None
    assert calls == 5


@pytest.mark.parametrize(
    "index_name",
    [
        "archive_records_by_generation_sequence",
        "archive_tombstones_by_generation_sequence",
    ],
)
def test_required_generation_indexes_are_part_of_schema_validation(
    tmp_path: Path,
    index_name: str,
) -> None:
    path = tmp_path / "archive.sqlite3"
    store = _store(path)
    ref = _prepare_one(store)
    _tamper(path, f'DROP INDEX "{index_name}"')

    assert not store.verify(ref)
    with pytest.raises(archive_store.ArchiveStoreError, match="index"):
        _store(path)


def test_delete_journal_fallback_uses_extra_synchronous_durability(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "archive.sqlite3"

    def force_delete_journal(connection: sqlite3.Connection) -> None:
        assert connection.execute("PRAGMA journal_mode = DELETE").fetchone() == ("delete",)

    monkeypatch.setattr(archive_store, "_configure_journal_mode", force_delete_journal)
    store = _store(path)
    with store._read_transaction() as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)
        assert connection.execute("PRAGMA synchronous").fetchone() == (3,)


def test_archive_connections_use_bounded_page_cache(tmp_path: Path) -> None:
    store = _store(tmp_path / "archive.sqlite3")

    connection = store._connect()
    try:
        assert connection.execute("PRAGMA cache_size").fetchone() == (-64,)
    finally:
        connection.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_store_creates_and_repairs_private_permissions(tmp_path: Path) -> None:
    path = tmp_path / "private" / "archive.sqlite3"
    _store(path)

    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    path.parent.chmod(0o755)
    path.chmod(0o644)
    _store(path)

    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_permission_repair_failure_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "archive.sqlite3"
    _store(path)
    path.chmod(0o644)
    real_chmod = os.chmod

    def deny_database_chmod(candidate: os.PathLike[str] | str, mode: int) -> None:
        if Path(candidate) == path:
            raise PermissionError("permission repair denied")
        real_chmod(candidate, mode)

    monkeypatch.setattr(os, "chmod", deny_database_chmod)

    with pytest.raises(archive_store.ArchiveStoreError, match="permission"):
        _store(path)


def test_path_lock_registry_releases_unused_paths(tmp_path: Path) -> None:
    baseline = archive_store._path_lock_count()

    for number in range(24):
        _store(tmp_path / f"archive-{number}.sqlite3")

    gc.collect()

    assert archive_store._path_lock_count() <= baseline
