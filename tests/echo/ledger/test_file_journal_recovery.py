from __future__ import annotations

import gc
import gzip
import json
import multiprocessing
import os
import pathlib
import shutil
import sqlite3
import stat
import threading
from typing import Any

import pytest

from js.echo.ledger import journal as journal_module
from js.echo.ledger.archive_store import ArchiveRecord, ArchiveStore
from js.echo.ledger.journal import FileEchoLedger, verify_file


def _sqlite_archive_path(path: pathlib.Path) -> pathlib.Path:
    return path.with_suffix(path.suffix + ".archive.sqlite3")


def _append_decisions(
    journal: FileEchoLedger,
    *,
    start: int,
    stop: int,
) -> None:
    for index in range(start, stop):
        journal.append(
            record_type="decision",
            tenant_id="tenant-a",
            run_id=f"run-{index}",
            payload={"decision_id": f"d{index}"},
        )


def _install_legacy_gzip_compaction(
    path: pathlib.Path,
    *,
    journal: FileEchoLedger,
    retained_count: int,
) -> pathlib.Path:
    records = list(journal.records)
    archive_path = path.with_suffix(path.suffix + ".archive.legacy.gz")
    with archive_path.open("wb") as raw_archive:
        with gzip.GzipFile(fileobj=raw_archive, mode="wb", mtime=0) as archive:
            for record in records:
                archive.write((journal_module._record_to_json(record) + "\n").encode())
        raw_archive.flush()
        os.fsync(raw_archive.fileno())

    retained = records[-retained_count:]
    archive_hash = journal_module.stable_hash(
        {"record_hashes": [record.record_hash for record in records]}
    )
    compacted = [
        journal_module._build_record(
            records=[],
            mac_key=b"journal-key",
            record_type="snapshot_anchor",
            tenant_id="__system__",
            run_id="compaction",
            payload={
                "archived_record_count": len(records) - retained_count,
                "retained_record_count": retained_count,
                "archive_hash": archive_hash,
                "archive_required": True,
                "archive_name": archive_path.name,
                "compacted_at_ms": 1,
                "effect_tombstones": [],
            },
        )
    ]
    for record in retained:
        compacted.append(
            journal_module._build_record(
                records=compacted,
                mac_key=b"journal-key",
                record_type=record.record_type,
                tenant_id=record.tenant_id,
                run_id=record.run_id,
                payload=record.payload,
            )
        )
    path.write_text(
        "".join(journal_module._record_to_json(record) + "\n" for record in compacted),
        encoding="utf-8",
    )
    return archive_path


def _concurrent_compaction_worker(
    path: str,
    start: object,
    results: object,
) -> None:
    try:
        start.wait(timeout=10)  # type: ignore[attr-defined]
        compacted = FileEchoLedger(pathlib.Path(path), mac_key=b"journal-key").compact(
            max_records=2,
            max_archives=1,
        )
        results.put(("ok", compacted))  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover - assertion reports child failure
        results.put(("error", f"{type(exc).__name__}: {exc}"))  # type: ignore[attr-defined]


def test_file_journal_persists_and_verifies_after_reload(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    first = journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"decision_id": "d1"},
    )
    second = journal.append(
        record_type="permit",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"effect_id": "e1"},
    )

    reloaded = FileEchoLedger(path, mac_key=b"journal-key")
    report = verify_file(path, mac_key=b"journal-key")

    assert first.seq == 0
    assert second.seq == 1
    assert tuple(record.record_type for record in reloaded.records) == ("decision", "permit")
    assert report.ok


def test_process_path_lock_registry_does_not_retain_closed_journal_paths(
    tmp_path: pathlib.Path,
) -> None:
    for index in range(1_000):
        FileEchoLedger(tmp_path / f"tenant-{index}.jsonl", mac_key=b"journal-key")

    gc.collect()
    retained = [
        path for path in journal_module._FILE_LOCKS if path.is_relative_to(tmp_path.resolve())
    ]

    assert retained == []


def test_file_journal_appends_after_valid_record_without_trailing_newline(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"decision_id": "d1"},
    )
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    reopened = FileEchoLedger(path, mac_key=b"journal-key")

    reopened.append(
        record_type="permit",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"effect_id": "e1"},
    )

    assert verify_file(path, mac_key=b"journal-key").ok
    assert tuple(
        record.record_type for record in FileEchoLedger(path, mac_key=b"journal-key").records
    ) == (
        "decision",
        "permit",
    )


def test_file_journal_defensively_copies_appended_payload(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    payload = {"nested": {"value": "before"}}

    record = journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload=payload,
    )
    payload["nested"]["value"] = "after"

    assert record.payload == {"nested": {"value": "before"}}
    assert journal.records[0].payload == {"nested": {"value": "before"}}
    assert verify_file(path, mac_key=b"journal-key").ok


def test_file_journal_detects_corrupt_crash_tail(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"decision_id": "d1"},
    )
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"seq":')

    report = verify_file(path, mac_key=b"journal-key")

    assert not report.ok
    assert report.errors == ("line:2:invalid_json",)


def test_file_journal_recovers_clean_prefix_from_corrupt_tail(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"decision_id": "d1"},
    )
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"seq":')

    recovered = FileEchoLedger(path, mac_key=b"journal-key")

    assert tuple(record.record_type for record in recovered.records) == ("decision",)
    assert verify_file(path, mac_key=b"journal-key").ok


def test_corrupt_tail_recovery_cannot_truncate_a_concurrent_valid_append(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    import js.echo.ledger.journal as journal_mod

    path = tmp_path / "echo_ledger.jsonl"
    writer = FileEchoLedger(path, mac_key=b"journal-key")
    writer.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"decision_id": "d1"},
    )
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"seq":')

    stale_read_ready = threading.Event()
    allow_recovery = threading.Event()
    writer_done = threading.Event()
    real_read = journal_mod._read_verified_file

    def paused_read(*args: Any, **kwargs: Any) -> Any:
        result = real_read(*args, **kwargs)
        if threading.current_thread().name == "recoverer" and not result[0].ok:
            stale_read_ready.set()
            assert allow_recovery.wait(timeout=5)
        return result

    monkeypatch.setattr(journal_mod, "_read_verified_file", paused_read)
    recovery_errors: list[BaseException] = []

    def recover() -> None:
        try:
            FileEchoLedger(path, mac_key=b"journal-key")
        except BaseException as exc:  # noqa: BLE001 - surfaced in assertion below
            recovery_errors.append(exc)

    def append_valid() -> None:
        writer.append(
            record_type="permit",
            tenant_id="tenant-a",
            run_id="run-1",
            payload={"effect_id": "e1"},
        )
        writer_done.set()

    recovery_thread = threading.Thread(target=recover, name="recoverer")
    recovery_thread.start()
    assert stale_read_ready.wait(timeout=5)
    writer_thread = threading.Thread(target=append_valid, name="writer")
    writer_thread.start()
    writer_done.wait(timeout=0.2)
    allow_recovery.set()
    recovery_thread.join(timeout=5)
    writer_thread.join(timeout=5)

    assert not recovery_errors
    assert not recovery_thread.is_alive()
    assert not writer_thread.is_alive()
    reloaded = FileEchoLedger(path, mac_key=b"journal-key")
    assert tuple(record.record_type for record in reloaded.records) == ("decision", "permit")
    assert verify_file(path, mac_key=b"journal-key").ok


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("record_hash", "sha256:" + "f" * 64),
        ("mac", "00" * 32),
    ),
)
def test_file_journal_recovers_complete_cryptographic_tamper_at_tail(
    tmp_path: pathlib.Path,
    field: str,
    replacement: str,
) -> None:
    """完整但 hash/MAC 错误的坏尾应被隔离恢复，保留 clean prefix（§4 要求）."""
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"decision_id": "d1"},
    )
    journal.append(
        record_type="permit",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"effect_id": "e1"},
    )
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[-1][field] = replacement
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows) + "\n",
        encoding="utf-8",
    )

    # 应恢复而非拒绝：journal 可正常加载，clean prefix 保留
    recovered = FileEchoLedger(path, mac_key=b"journal-key")
    assert len(recovered.records) == 1, "clean prefix 应保留第1条记录"
    assert recovered.records[0].record_type == "decision"

    # 坏尾应被隔离到 .corrupt 文件
    corrupt_path = path.with_suffix(path.suffix + ".corrupt")
    assert corrupt_path.exists(), "坏尾应被隔离到 .corrupt 文件"

    # 主文件应只含 clean prefix
    remaining = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(remaining) == 1, "主文件应只含 clean prefix"

    # 验证 clean prefix 仍可通过 MAC 校验
    assert verify_file(path, mac_key=b"journal-key").ok


def test_file_journal_rejects_bad_hash_in_middle(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    for index in range(3):
        journal.append(
            record_type="decision",
            tenant_id="tenant-a",
            run_id=f"run-{index}",
            payload={"decision_id": f"d{index}"},
        )
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[1]["record_hash"] = "sha256:" + "f" * 64
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows) + "\n",
        encoding="utf-8",
    )

    try:
        FileEchoLedger(path, mac_key=b"journal-key")
    except ValueError as exc:
        assert "record_hash_mismatch" in str(exc)
    else:
        raise AssertionError("middle journal corruption must fail closed")

    assert not verify_file(path, mac_key=b"journal-key").ok


def test_file_journal_append_reloads_latest_records_before_writing(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    first_writer = FileEchoLedger(path, mac_key=b"journal-key")
    stale_writer = FileEchoLedger(path, mac_key=b"journal-key")

    first = first_writer.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"decision_id": "d1"},
    )
    second = stale_writer.append(
        record_type="permit",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"effect_id": "e1"},
    )

    reloaded = FileEchoLedger(path, mac_key=b"journal-key")

    assert first.seq == 0
    assert second.seq == 1
    assert tuple(record.seq for record in reloaded.records) == (0, 1)
    assert tuple(record.record_type for record in reloaded.records) == ("decision", "permit")
    assert verify_file(path, mac_key=b"journal-key").ok


def test_file_journal_live_append_recovers_clean_prefix_from_corrupt_tail(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"decision_id": "d1"},
    )
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"seq":')

    second = journal.append(
        record_type="permit",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"effect_id": "e1"},
    )
    reloaded = FileEchoLedger(path, mac_key=b"journal-key")

    assert second.seq == 1
    assert tuple(record.record_type for record in reloaded.records) == ("decision", "permit")
    assert verify_file(path, mac_key=b"journal-key").ok
    assert path.with_suffix(path.suffix + ".corrupt").is_file()


def test_file_journal_append_fsyncs_record(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    fsync_calls: list[int] = []
    monkeypatch.setattr("js.echo.ledger.journal.os.fsync", fsync_calls.append)
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    fsync_calls.clear()

    journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"decision_id": "d1"},
    )

    assert len(fsync_calls) == 1


def test_file_journal_append_many_does_not_reverify_unchanged_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    import js.echo.ledger.journal as journal_mod

    path = tmp_path / "echo_ledger.jsonl"
    calls = 0
    real_read_verified_file = journal_mod._read_verified_file

    def counted_read_verified_file(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        return real_read_verified_file(*args, **kwargs)

    monkeypatch.setattr(journal_mod, "_read_verified_file", counted_read_verified_file)
    journal = FileEchoLedger(path, mac_key=b"journal-key")

    journal.append_many(
        (
            {
                "record_type": "decision",
                "tenant_id": "tenant-a",
                "run_id": "run-1",
                "payload": {"decision_id": "d1"},
            },
            {
                "record_type": "permit",
                "tenant_id": "tenant-a",
                "run_id": "run-1",
                "payload": {"effect_id": "e1"},
            },
        )
    )

    assert calls == 1
    assert tuple(record.record_type for record in journal.records) == ("decision", "permit")


def test_file_journal_reverifies_equal_length_change_when_mtime_is_restored(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"decision_id": "d1"},
    )
    original_stat = path.stat()
    original = path.read_bytes()
    tampered = original.replace(b'"run_id":"run-1"', b'"run_id":"run-x"', 1)
    assert len(tampered) == len(original)
    path.write_bytes(tampered)
    os.utime(
        path,
        ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
    )

    tampered_stat = path.stat()
    assert tampered_stat.st_size == original_stat.st_size
    assert tampered_stat.st_mtime_ns == original_stat.st_mtime_ns
    assert tampered_stat.st_ctime_ns != original_stat.st_ctime_ns
    with pytest.raises(ValueError, match="record_hash_mismatch|mac_mismatch"):
        journal.refresh()


def test_file_journal_reverifies_old_prefix_before_accepting_external_append(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    writer = FileEchoLedger(path, mac_key=b"journal-key")
    writer.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"decision_id": "d1"},
    )
    observer = FileEchoLedger(path, mac_key=b"journal-key")
    writer.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-2",
        payload={"decision_id": "d2"},
    )

    original = path.read_bytes()
    tampered = original.replace(b'"run_id":"run-1"', b'"run_id":"run-x"', 1)
    assert len(tampered) == len(original)
    path.write_bytes(tampered)

    with pytest.raises(ValueError, match="record_hash_mismatch|mac_mismatch"):
        observer.refresh()


def test_file_journal_rejects_valid_older_active_file_rollback(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"decision_id": "d1"},
    )
    older_valid_bytes = path.read_bytes()
    journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-2",
        payload={"decision_id": "d2"},
    )
    path.write_bytes(older_valid_bytes)

    with pytest.raises(ValueError, match="active_journal_rollback"):
        journal.refresh()


def test_file_journal_rejects_valid_non_compaction_replacement(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"decision_id": "d1"},
    )
    replacement_path = tmp_path / "replacement.jsonl"
    replacement = FileEchoLedger(replacement_path, mac_key=b"journal-key")
    replacement.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="replacement-run",
        payload={"decision_id": "replacement"},
    )
    os.replace(replacement_path, path)

    with pytest.raises(ValueError, match="active_journal_replacement"):
        journal.refresh()


def test_file_journal_append_many_does_not_iterate_existing_records(
    tmp_path: pathlib.Path,
) -> None:
    class ExistingRecordsMustNotBeIterated(list[Any]):
        def __iter__(self):  # type: ignore[no-untyped-def]
            raise AssertionError("append_many iterated existing records")

    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    for index in range(3):
        journal.append(
            record_type="decision",
            tenant_id="tenant-a",
            run_id=f"run-{index}",
            payload={"decision_id": f"d{index}"},
        )
    journal._records = ExistingRecordsMustNotBeIterated(journal._records)

    appended = journal.append_many(
        (
            {
                "record_type": "permit",
                "tenant_id": "tenant-a",
                "run_id": "run-new",
                "payload": {"effect_id": "e-new"},
            },
        )
    )

    assert appended[0].seq == 3
    assert verify_file(path, mac_key=b"journal-key").ok


def test_file_journal_stale_writer_incremental_sync_does_not_iterate_history(
    tmp_path: pathlib.Path,
) -> None:
    class ExistingRecordsMustNotBeIterated(list[Any]):
        def __iter__(self):  # type: ignore[no-untyped-def]
            raise AssertionError("incremental sync iterated existing records")

    path = tmp_path / "echo_ledger.jsonl"
    first_writer = FileEchoLedger(path, mac_key=b"journal-key")
    first_writer.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"decision_id": "d1"},
    )
    stale_writer = FileEchoLedger(path, mac_key=b"journal-key")
    first_writer.append_many(
        (
            {
                "record_type": "decision",
                "tenant_id": "tenant-a",
                "run_id": "run-2",
                "payload": {"decision_id": "d2"},
            },
            {
                "record_type": "decision",
                "tenant_id": "tenant-a",
                "run_id": "run-3",
                "payload": {"decision_id": "d3"},
            },
        )
    )
    stale_writer._records = ExistingRecordsMustNotBeIterated(stale_writer._records)

    appended = stale_writer.append(
        record_type="permit",
        tenant_id="tenant-a",
        run_id="run-4",
        payload={"effect_id": "e4"},
    )

    assert appended.seq == 3
    assert verify_file(path, mac_key=b"journal-key").ok


def test_file_journal_compacts_with_bounded_sqlite_snapshot_anchor(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=5)

    compacted = journal.compact(max_records=2)
    reloaded = FileEchoLedger(path, mac_key=b"journal-key")
    anchor = reloaded.records[0]
    archive_path = _sqlite_archive_path(path)

    assert compacted is True
    assert verify_file(path, mac_key=b"journal-key").ok
    assert tuple(record.record_type for record in reloaded.records) == (
        "snapshot_anchor",
        "decision",
        "decision",
    )
    assert anchor.payload["archived_record_count"] == 3
    assert anchor.payload["retained_record_count"] == 2
    assert anchor.payload["archive_name"] == archive_path.name
    assert anchor.payload["archive_format"] == "echo-sqlite-archive"
    assert anchor.payload["archive_hash"].startswith("sha256:")
    assert anchor.payload["archived_tombstone_count"] == 0
    assert "effect_tombstones" not in anchor.payload
    assert set(anchor.payload["archive_ref"]) == {
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
    for field in (
        "store_id",
        "prev_manifest_hash",
        "archive_tip_hash",
        "tombstone_tip_hash",
        "manifest_hash",
        "mac",
    ):
        bytes.fromhex(anchor.payload["archive_ref"][field])
    assert len(json.dumps(anchor.payload, sort_keys=True)) < 2_048
    assert reloaded.records[1].payload["decision_id"] == "d3"
    assert reloaded.records[2].payload["decision_id"] == "d4"
    assert archive_path.is_file()
    assert list(tmp_path.glob("echo_ledger.jsonl.archive.*.gz")) == []
    with sqlite3.connect(archive_path) as connection:
        archived_payloads = [
            json.loads(row[0])
            for row in connection.execute(
                "SELECT canonical_payload FROM archive_records ORDER BY sequence"
            )
        ]
    assert [payload["decision_id"] for payload in archived_payloads] == [
        "d0",
        "d1",
        "d2",
        "d3",
        "d4",
    ]
    assert reloaded.verify_required_archives().ok


def test_compaction_reuses_unchanged_verified_active_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=5)
    real_read = journal_module._read_verified_file

    def reject_reparse(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("unchanged verified journal must not be reparsed")

    monkeypatch.setattr(journal_module, "_read_verified_file", reject_reparse)

    assert journal.compact(max_records=2) is True
    report, _records, _offset = real_read(path, mac_key=b"journal-key")
    assert report.ok


def test_compaction_rejects_mutated_in_memory_payload(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=5)
    original = path.read_bytes()

    journal.records[0].payload["decision_id"] = "tampered-in-memory"

    with pytest.raises(ValueError, match="in-memory journal snapshot"):
        journal.compact(max_records=2)

    assert path.read_bytes() == original
    assert verify_file(path, mac_key=b"journal-key").ok


def test_stale_observer_compaction_uses_latest_disk_records(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    writer = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(writer, start=0, stop=3)
    observer = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(writer, start=3, stop=6)

    assert observer.compact(max_records=2) is True

    reloaded = FileEchoLedger(path, mac_key=b"journal-key")
    assert [record.payload["decision_id"] for record in reloaded.records[1:]] == ["d4", "d5"]
    assert reloaded.records[0].payload["archive_cumulative_record_count"] == 6


def test_compaction_fails_closed_after_bounded_source_churn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=5)
    real_fingerprint = journal_module._active_journal_fingerprint
    fingerprint_calls = 0

    def changing_fingerprint(current_path: pathlib.Path) -> tuple[int, int, int, int, int, int]:
        nonlocal fingerprint_calls
        fingerprint_calls += 1
        actual = real_fingerprint(current_path)
        if fingerprint_calls <= 100:
            return (*actual[:-1], actual[-1] + fingerprint_calls)
        return actual

    monkeypatch.setattr(journal_module, "_active_journal_fingerprint", changing_fingerprint)

    with pytest.raises(ValueError, match="journal changed during compaction"):
        journal.compact(max_records=2)


def test_sqlite_anchor_rejects_retained_count_larger_than_active_tail(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=5)
    assert journal.compact(max_records=2) is True

    records = list(journal.records)
    payload = dict(records[0].payload)
    payload["retained_record_count"] = 3
    payload["archived_record_count"] = 2
    rewritten = [
        journal_module._build_record(
            records=[],
            mac_key=b"journal-key",
            record_type="snapshot_anchor",
            tenant_id="__system__",
            run_id="compaction",
            payload=payload,
        )
    ]
    for record in records[1:]:
        rewritten.append(
            journal_module._build_record(
                records=rewritten,
                mac_key=b"journal-key",
                record_type=record.record_type,
                tenant_id=record.tenant_id,
                run_id=record.run_id,
                payload=record.payload,
            )
        )
    path.write_text(
        "".join(journal_module._record_to_json(record) + "\n" for record in rewritten),
        encoding="utf-8",
    )

    reloaded = FileEchoLedger(path, mac_key=b"journal-key")
    report = reloaded.verify_required_archives()

    assert report.ok is False
    assert "archive_invalid" in ",".join(report.errors)


def test_sqlite_archive_verification_is_reused_after_active_appends(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=5)
    assert journal.compact(max_records=2) is True

    original_verify = ArchiveStore.verify
    verify_calls = 0

    def count_verify(self: ArchiveStore, ref: Any) -> bool:
        nonlocal verify_calls
        verify_calls += 1
        return original_verify(self, ref)

    monkeypatch.setattr(ArchiveStore, "verify", count_verify)

    assert journal.verify_required_archives().ok
    _append_decisions(journal, start=5, stop=6)
    assert journal.verify_required_archives().ok
    _append_decisions(journal, start=6, stop=7)
    assert journal.verify_required_archives().ok

    assert verify_calls == 0


def test_cached_sqlite_archive_verification_invalidates_after_archive_tampering(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    archive_path = _sqlite_archive_path(path)
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=5)
    assert journal.compact(max_records=2) is True

    original_verify = ArchiveStore.verify
    verify_calls = 0

    def count_verify(self: ArchiveStore, ref: Any) -> bool:
        nonlocal verify_calls
        verify_calls += 1
        return original_verify(self, ref)

    monkeypatch.setattr(ArchiveStore, "verify", count_verify)

    assert journal.verify_required_archives().ok
    with sqlite3.connect(archive_path) as connection:
        connection.execute("UPDATE archive_records SET canonical_payload = '{}' WHERE sequence = 1")

    assert not journal.verify_required_archives().ok
    assert verify_calls == 1


def test_cached_sqlite_archive_verification_invalidates_after_archive_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    archive_path = _sqlite_archive_path(path)
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=5)
    assert journal.compact(max_records=2) is True

    original_verify = ArchiveStore.verify
    verify_calls = 0

    def count_verify(self: ArchiveStore, ref: Any) -> bool:
        nonlocal verify_calls
        verify_calls += 1
        return original_verify(self, ref)

    monkeypatch.setattr(ArchiveStore, "verify", count_verify)

    assert journal.verify_required_archives().ok
    original_inode = archive_path.stat().st_ino
    replacement_path = tmp_path / "archive-replacement.sqlite3"
    shutil.copy2(archive_path, replacement_path)
    os.replace(replacement_path, archive_path)

    assert archive_path.stat().st_ino != original_inode
    assert journal.verify_required_archives().ok
    assert verify_calls == 1


def test_compaction_rechecks_archive_after_identical_active_journal_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=5)
    assert journal.compact(max_records=2) is True
    original_inode = path.stat().st_ino
    replacement = tmp_path / "journal-replacement.jsonl"
    shutil.copy2(path, replacement)
    os.replace(replacement, path)

    original_verify = ArchiveStore.verify
    verify_calls = 0

    def count_verify(self: ArchiveStore, ref: Any) -> bool:
        nonlocal verify_calls
        verify_calls += 1
        return original_verify(self, ref)

    monkeypatch.setattr(ArchiveStore, "verify", count_verify)

    assert path.stat().st_ino != original_inode
    assert journal.compact(max_records=2) is False
    assert verify_calls == 1


def test_active_journal_rollback_fails_closed_after_archive_verification(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=5)
    assert journal.compact(max_records=2) is True
    assert journal.verify_required_archives().ok

    path.write_text(
        "".join(journal_module._record_to_json(record) + "\n" for record in journal.records[:-1]),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="active_journal_rollback"):
        journal.verify_required_archives()


def test_cached_sqlite_archive_verification_invalidates_after_external_compaction(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    writer = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(writer, start=0, stop=5)
    assert writer.compact(max_records=2) is True
    observer = FileEchoLedger(path, mac_key=b"journal-key")

    original_verify = ArchiveStore.verify
    verify_calls = 0

    def count_verify(self: ArchiveStore, ref: Any) -> bool:
        nonlocal verify_calls
        verify_calls += 1
        return original_verify(self, ref)

    monkeypatch.setattr(ArchiveStore, "verify", count_verify)

    assert observer.verify_required_archives().ok
    _append_decisions(writer, start=5, stop=8)
    assert writer.compact(max_records=2) is True
    verify_calls = 0

    assert observer.verify_required_archives().ok
    assert observer.records[0].payload["archive_ref"]["generation"] == 2
    assert verify_calls == 1


def test_file_journal_and_archive_permissions_remain_private_after_compaction(
    tmp_path: pathlib.Path,
) -> None:
    previous_umask = os.umask(0o022)
    try:
        path = tmp_path / "echo_ledger.jsonl"
        journal = FileEchoLedger(path, mac_key=b"journal-key")
        _append_decisions(journal, start=0, stop=3)
        assert journal.compact(max_records=1) is True
    finally:
        os.umask(previous_umask)

    archive = _sqlite_archive_path(path)
    lock_path = path.with_suffix(path.suffix + ".lock")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600


def test_file_journal_observer_refreshes_after_valid_external_compaction(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    writer = FileEchoLedger(path, mac_key=b"journal-key")
    for index in range(5):
        writer.append(
            record_type="decision",
            tenant_id="tenant-a",
            run_id=f"run-{index}",
            payload={"decision_id": f"d{index}"},
        )
    observer = FileEchoLedger(path, mac_key=b"journal-key")

    assert writer.compact(max_records=2) is True

    assert observer.refresh() is True
    assert [record.record_type for record in observer.records] == [
        "snapshot_anchor",
        "decision",
        "decision",
    ]
    assert observer.records[-1].payload["decision_id"] == "d4"


def test_repeated_compaction_archives_only_delta_in_one_sqlite_store(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    archive_path = _sqlite_archive_path(path)
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=6)

    assert journal.compact(max_records=2) is True
    first_anchor_size = len(json.dumps(journal.records[0].payload, sort_keys=True))
    _append_decisions(journal, start=6, stop=9)
    assert journal.compact(max_records=2) is True
    second_anchor_size = len(json.dumps(journal.records[0].payload, sort_keys=True))
    _append_decisions(journal, start=9, stop=13)
    assert journal.compact(max_records=2) is True
    third_anchor_size = len(json.dumps(journal.records[0].payload, sort_keys=True))

    with sqlite3.connect(archive_path) as connection:
        generations = connection.execute(
            "SELECT generation, added_record_count, cumulative_record_count "
            "FROM archive_manifests ORDER BY generation"
        ).fetchall()
        archived_count = connection.execute("SELECT COUNT(*) FROM archive_records").fetchone()

    assert generations == [(1, 6, 6), (2, 3, 9), (3, 4, 13)]
    assert archived_count == (13,)
    assert max(first_anchor_size, second_anchor_size, third_anchor_size) < 2_048
    assert (
        max(first_anchor_size, second_anchor_size, third_anchor_size)
        - min(first_anchor_size, second_anchor_size, third_anchor_size)
        < 32
    )
    assert journal.records[0].payload["retained_record_count"] == 2
    assert "effect_tombstones" not in journal.records[0].payload
    assert list(tmp_path.glob("echo_ledger.jsonl.archive.*.gz")) == []
    assert journal.compact(max_records=2) is False
    assert (
        ArchiveStore(
            archive_path,
            tenant_id="tenant-a",
            mac_key=journal_module._archive_mac_key(b"journal-key"),
        ).generation_count()
        == 3
    )


def test_repeated_compaction_full_verifies_new_archive_generation_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=5)
    assert journal.compact(max_records=2) is True
    _append_decisions(journal, start=5, stop=8)

    original_verify = ArchiveStore._verify_in_transaction
    verify_calls = 0

    def count_verify(self: ArchiveStore, connection: Any, ref: Any) -> bool:
        nonlocal verify_calls
        verify_calls += 1
        return original_verify(self, connection, ref)

    monkeypatch.setattr(ArchiveStore, "_verify_in_transaction", count_verify)

    assert journal.compact(max_records=2) is True
    assert verify_calls == 1


def test_db_commit_before_active_replace_recovers_prefix_then_appends_remainder(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    archive_path = _sqlite_archive_path(path)
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=5)
    assert journal.compact(max_records=2) is True
    _append_decisions(journal, start=5, stop=8)
    active_before = path.read_bytes()
    real_replace = os.replace

    def fail_active_replace(source: pathlib.Path, target: pathlib.Path) -> None:
        if target == path:
            raise OSError("active journal install failed")
        real_replace(source, target)

    with monkeypatch.context() as context:
        context.setattr(os, "replace", fail_active_replace)
        with pytest.raises(OSError, match="active journal install failed"):
            journal.compact(max_records=2)

    assert path.read_bytes() == active_before
    anchored = FileEchoLedger(path, mac_key=b"journal-key")
    assert anchored.records[0].payload["archive_ref"]["generation"] == 1
    assert anchored.verify_required_archives().ok
    store = ArchiveStore(
        archive_path,
        tenant_id="tenant-a",
        mac_key=journal_module._archive_mac_key(b"journal-key"),
    )
    assert store.latest_manifest() is not None
    assert store.latest_manifest().generation == 2

    _append_decisions(journal, start=8, stop=9)
    assert journal.compact(max_records=2) is True

    with sqlite3.connect(archive_path) as connection:
        generations = connection.execute(
            "SELECT generation, added_record_count FROM archive_manifests ORDER BY generation"
        ).fetchall()
    assert generations == [(1, 5), (2, 3), (3, 1)]
    assert journal.records[0].payload["archive_ref"]["generation"] == 3
    assert journal.verify_required_archives().ok


def test_unanchored_future_generation_mismatch_fails_closed(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    archive_path = _sqlite_archive_path(path)
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=5)
    assert journal.compact(max_records=2) is True
    _append_decisions(journal, start=5, stop=8)
    active_before = path.read_bytes()

    store = ArchiveStore(
        archive_path,
        tenant_id="tenant-a",
        mac_key=journal_module._archive_mac_key(b"journal-key"),
    )
    base_manifest = store.latest_manifest()
    assert base_manifest is not None
    store.prepare_generation(
        base_manifest.to_ref(),
        (
            ArchiveRecord(
                record_type="decision",
                tenant_id="tenant-a",
                run_id="wrong-run",
                payload={"decision_id": "wrong"},
            ),
        ),
        (),
    )

    with pytest.raises(ValueError, match="future_generation_delta_mismatch"):
        journal.compact(max_records=2)

    assert path.read_bytes() == active_before
    assert FileEchoLedger(path, mac_key=b"journal-key").verify_required_archives().ok


def test_tampered_sqlite_archive_fails_verification_and_effect_lookup(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    archive_path = _sqlite_archive_path(path)
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=4)
    assert journal.compact(max_records=1) is True

    with sqlite3.connect(archive_path) as connection:
        connection.execute("UPDATE archive_records SET canonical_payload = '{}' WHERE sequence = 1")

    assert not journal.verify_required_archives().ok
    with pytest.raises(ValueError, match="invalid required journal archive"):
        journal.contains_archived_effect("effect-1")


def test_missing_sqlite_archive_fails_verification_and_effect_lookup(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    archive_path = _sqlite_archive_path(path)
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=4)
    assert journal.compact(max_records=1) is True
    archive_path.unlink()

    assert not journal.verify_required_archives().ok
    with pytest.raises(ValueError, match="invalid required journal archive"):
        journal.contains_archived_effect("effect-1")


def test_contains_archived_effect_uses_exact_sqlite_tombstone_lookup(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    journal.append(
        record_type="outbox",
        tenant_id="tenant-a",
        run_id="run-effect",
        payload={
            "outbox_id": "outbox-1",
            "effect_id": "effect-1",
            "seal": {
                "action_kind": "tool.file_write",
                "replay_class": "non_idempotent",
            },
        },
    )
    journal.append(
        record_type="merge",
        tenant_id="tenant-a",
        run_id="run-effect",
        payload={"effect_id": "effect-1"},
    )
    journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-later",
        payload={"decision_id": "later"},
    )

    assert journal.compact(max_records=1) is True

    assert journal.contains_archived_effect("effect-1") is True
    assert journal.contains_archived_effect("effect") is False
    assert journal.contains_archived_effect("effect-10") is False
    assert "effect_tombstones" not in journal.records[0].payload


def test_repeated_archived_effect_lookup_reuses_verified_store(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    journal.append(
        record_type="outbox",
        tenant_id="tenant-a",
        run_id="run-effect",
        payload={
            "outbox_id": "outbox-1",
            "effect_id": "effect-1",
            "seal": {
                "action_kind": "tool.file_write",
                "replay_class": "non_idempotent",
            },
        },
    )
    journal.append(
        record_type="merge",
        tenant_id="tenant-a",
        run_id="run-effect",
        payload={"effect_id": "effect-1"},
    )
    journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-later",
        payload={"decision_id": "later"},
    )
    assert journal.compact(max_records=1) is True

    original_verify = ArchiveStore._verify_in_transaction
    verify_calls = 0

    def count_verify(self: ArchiveStore, connection: Any, ref: Any) -> bool:
        nonlocal verify_calls
        verify_calls += 1
        return original_verify(self, connection, ref)

    monkeypatch.setattr(ArchiveStore, "_verify_in_transaction", count_verify)

    assert journal.contains_archived_effect("effect-1")
    first_lookup_calls = verify_calls
    assert first_lookup_calls == 0
    assert not journal.contains_archived_effect("missing-1")
    assert not journal.contains_archived_effect("missing-2")
    assert verify_calls == first_lookup_calls


def test_legacy_gzip_anchor_is_verified_then_migrated_once(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    original = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(original, start=0, stop=5)
    legacy_archive = _install_legacy_gzip_compaction(
        path,
        journal=original,
        retained_count=2,
    )
    migrating = FileEchoLedger(path, mac_key=b"journal-key")
    assert migrating.verify_required_archives().ok
    _append_decisions(migrating, start=5, stop=8)

    assert migrating.compact(max_records=2) is True

    archive_path = _sqlite_archive_path(path)
    assert archive_path.is_file()
    assert not legacy_archive.exists()
    assert migrating.records[0].payload["archive_format"] == "echo-sqlite-archive"
    assert migrating.records[0].payload["archive_ref"]["generation"] == 1
    assert "effect_tombstones" not in migrating.records[0].payload
    with sqlite3.connect(archive_path) as connection:
        generations = connection.execute(
            "SELECT generation, added_record_count, cumulative_record_count FROM archive_manifests"
        ).fetchall()
    assert generations == [(1, 8, 8)]
    assert migrating.verify_required_archives().ok


def test_archive_false_remains_self_contained_and_recompactable(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    _append_decisions(journal, start=0, stop=4)

    assert journal.compact(max_records=2, archive=False) is True
    assert journal.records[0].payload["archive_required"] is False
    assert journal.records[0].payload["archive_name"] is None
    assert not _sqlite_archive_path(path).exists()
    assert list(tmp_path.glob("echo_ledger.jsonl.archive.*.gz")) == []
    assert journal.verify_required_archives().ok

    _append_decisions(journal, start=4, stop=7)
    assert journal.compact(max_records=2, archive=False) is True
    assert verify_file(path, mac_key=b"journal-key").ok


def test_file_journal_compaction_retries_when_source_changes_before_replace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    import js.echo.ledger.journal as journal_mod

    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    for index in range(5):
        journal.append(
            record_type="decision",
            tenant_id="tenant-a",
            run_id=f"run-{index}",
            payload={"decision_id": f"d{index}"},
        )

    real_compaction_records = journal_mod._compaction_records
    injected = False

    def append_after_first_snapshot(*args: Any, **kwargs: Any) -> Any:
        nonlocal injected
        tail = real_compaction_records(*args, **kwargs)
        records = args[0] if args else kwargs["records"]
        if not injected:
            injected = True
            extra = journal_mod._build_record(
                records=list(records),
                mac_key=b"journal-key",
                record_type="decision",
                tenant_id="tenant-a",
                run_id="run-late",
                payload={"decision_id": "late"},
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write(journal_mod._record_to_json(extra) + "\n")
        return tail

    monkeypatch.setattr(journal_mod, "_compaction_records", append_after_first_snapshot)

    assert journal.compact(max_records=2) is True
    reloaded = FileEchoLedger(path, mac_key=b"journal-key")

    assert verify_file(path, mac_key=b"journal-key").ok
    assert reloaded.records[-1].payload["decision_id"] == "late"


def test_file_journal_concurrent_compaction_is_serialized_across_processes(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "echo_ledger.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key")
    for index in range(10):
        journal.append(
            record_type="decision",
            tenant_id="tenant-a",
            run_id=f"run-{index}",
            payload={"decision_id": f"d{index}"},
        )

    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=_concurrent_compaction_worker,
            args=(str(path), start, results),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(timeout=15)

    outcomes = [results.get(timeout=2) for _ in processes]
    assert all(process.exitcode == 0 for process in processes)
    assert all(outcome[0] == "ok" for outcome in outcomes), outcomes
    assert verify_file(path, mac_key=b"journal-key").ok
    assert FileEchoLedger(path, mac_key=b"journal-key").verify_required_archives().ok
    assert _sqlite_archive_path(path).is_file()
    assert list(tmp_path.glob("echo_ledger.jsonl.archive.*.gz")) == []
