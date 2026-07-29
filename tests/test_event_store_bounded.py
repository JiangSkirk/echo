"""Bounded-storage regression tests for :mod:`js.events.store`."""

from __future__ import annotations

import json
import multiprocessing
import os
import subprocess
import sys
import textwrap
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import js.events.store as event_store_module
from js.events.models import AgentEvent
from js.events.store import EventStore


class _PlainSecrets:
    """Keep file assertions readable while exercising the real store paths."""

    def encrypt_blob(self, data: bytes) -> bytes:
        return data

    def decrypt_blob(self, data: bytes) -> bytes:
        return data


def _event(index: int, *, padding: int = 0) -> AgentEvent:
    return AgentEvent(
        event_type="bounded_store_test",
        timestamp="2026-07-12T00:00:00+00:00",
        session_id=f"session-{index:04d}",
        run_id="run",
        payload={"index": index, "padding": "x" * padding},
    )


def _encoded_line(event: AgentEvent) -> bytes:
    raw = json.dumps(event.to_dict(), ensure_ascii=False, default=str)
    return raw.encode("utf-8") + b"\n"


def _store(
    base_dir: Path,
    *,
    retention_days: int = 90,
    max_file_bytes: int,
    max_archives: int,
) -> EventStore:
    store = EventStore(
        base_dir,
        retention_days=retention_days,
        max_file_bytes=max_file_bytes,
        max_archives=max_archives,
    )
    store._secrets_inst = _PlainSecrets()
    return store


def _archive_path(active: Path, sequence: int) -> Path:
    return active.with_name(f"{active.stem}.{sequence}{active.suffix}")


def _emit_in_process(
    base_dir: str,
    start: int,
    count: int,
    max_file_bytes: int,
) -> None:
    store = _store(
        Path(base_dir),
        max_file_bytes=max_file_bytes,
        max_archives=100,
    )
    for index in range(start, start + count):
        store.emit(_event(index))


def test_default_limits_target_low_storage_footprint(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events")

    assert event_store_module.DEFAULT_MAX_FILE_BYTES == 256 * 1024
    assert event_store_module.DEFAULT_MAX_ARCHIVES == 4
    assert store._max_file_bytes == 256 * 1024
    assert store._max_archives == 4


def test_store_module_import_does_not_require_fcntl() -> None:
    script = textwrap.dedent(
        """
        import builtins

        original_import = builtins.__import__

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "fcntl":
                raise ModuleNotFoundError("fcntl is unavailable")
            return original_import(name, globals, locals, fromlist, level)

        builtins.__import__ = guarded_import
        import js.events.store
        """
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_windows_lock_backend_uses_msvcrt(tmp_path: Path, monkeypatch) -> None:
    calls: list[tuple[int, int]] = []
    imports: list[str] = []

    class FakeMsvcrt:
        LK_LOCK = 1
        LK_UNLCK = 2

        @staticmethod
        def locking(fd: int, mode: int, size: int) -> None:
            calls.append((mode, size))

    def import_module(name: str):
        imports.append(name)
        return FakeMsvcrt

    monkeypatch.setattr(event_store_module, "_LOCK_BACKEND", "windows", raising=False)
    monkeypatch.setattr(event_store_module.importlib, "import_module", import_module)
    lock_path = tmp_path / "events.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        event_store_module._acquire_file_lock(lock_fd)
        event_store_module._release_file_lock(lock_fd)
    finally:
        os.close(lock_fd)

    assert imports == ["msvcrt", "msvcrt"]
    assert calls == [(FakeMsvcrt.LK_LOCK, 1), (FakeMsvcrt.LK_UNLCK, 1)]
    assert lock_path.read_bytes() == b"\0"


def test_windows_backend_skips_directory_fsync(tmp_path: Path, monkeypatch) -> None:
    store = EventStore(tmp_path / "events")
    monkeypatch.setattr(event_store_module, "_LOCK_BACKEND", "windows", raising=False)

    def unexpected_open(*args, **kwargs):
        raise AssertionError("Windows directory fsync must be skipped")

    monkeypatch.setattr(event_store_module.os, "open", unexpected_open)

    store._sync_directory()


def test_emit_rotates_before_crossing_cap_and_preserves_daily_query_order(
    tmp_path: Path,
) -> None:
    first = _event(1)
    max_file_bytes = len(_encoded_line(first)) * 2 - 1
    store = _store(
        tmp_path / "events",
        max_file_bytes=max_file_bytes,
        max_archives=10,
    )

    for index in range(1, 4):
        store.emit(_event(index))

    active = store._get_file()
    part_one = _archive_path(active, 1)
    part_two = _archive_path(active, 2)
    assert part_one.exists()
    assert part_two.exists()
    assert active.exists()
    assert not list(store.base_dir.glob("*.gz"))
    assert all(path.stat().st_size <= max_file_bytes for path in (part_one, part_two, active))

    results = store.query(limit=10)
    assert [event.session_id for event in results] == [
        "session-0001",
        "session-0002",
        "session-0003",
    ]
    assert [event.session_id for event in store.query(session_id="session-0002")] == [
        "session-0002"
    ]


def test_query_keeps_newest_day_first_across_rotated_layout(tmp_path: Path) -> None:
    store = _store(
        tmp_path / "events",
        max_file_bytes=4096,
        max_archives=10,
    )
    yesterday = datetime.now(UTC).date() - timedelta(days=1)
    yesterday_file = store.base_dir / f"events_{yesterday}.jsonl"
    yesterday_file.write_bytes(_encoded_line(_event(1)))

    store.emit(_event(2))

    assert [event.session_id for event in store.query(limit=10)] == [
        "session-0002",
        "session-0001",
    ]


def test_oversized_record_is_never_split_or_discarded(tmp_path: Path) -> None:
    store = _store(
        tmp_path / "events",
        max_file_bytes=64,
        max_archives=10,
    )

    store.emit(_event(1, padding=512))
    store.emit(_event(2))

    active = store._get_file()
    archive = _archive_path(active, 1)
    assert archive.stat().st_size > 64
    assert len(archive.read_text(encoding="utf-8").splitlines()) == 1
    assert len(active.read_text(encoding="utf-8").splitlines()) == 1
    assert [event.session_id for event in store.query(limit=10)] == [
        "session-0001",
        "session-0002",
    ]


def test_oversized_record_emits_capacity_warning(tmp_path: Path, monkeypatch) -> None:
    store = _store(
        tmp_path / "events",
        max_file_bytes=64,
        max_archives=10,
    )
    event = _event(1, padding=512)
    warnings: list[str] = []

    def capture_warning(message: str, *args, **kwargs) -> None:
        warnings.append(message % args)

    monkeypatch.setattr(event_store_module.logger, "warning", capture_warning)

    store.emit(event)

    assert warnings == [
        f"Event record size {len(_encoded_line(event))} exceeds max_file_bytes 64; storing intact"
    ]


def test_encrypted_records_round_trip_after_rotation_and_reopen(tmp_path: Path) -> None:
    base_dir = tmp_path / "state" / "events"
    store = EventStore(base_dir, max_file_bytes=1, max_archives=10)

    store.emit(_event(1))
    store.emit(_event(2))

    active = store._get_file()
    archive = _archive_path(active, 1)
    assert b"session-0001" not in archive.read_bytes()
    assert b"session-0002" not in active.read_bytes()

    reopened = EventStore(base_dir, max_file_bytes=1, max_archives=10)
    assert [event.session_id for event in reopened.query(limit=10)] == [
        "session-0001",
        "session-0002",
    ]


def test_multiple_store_instances_emit_without_loss_or_partial_lines(
    tmp_path: Path,
) -> None:
    base_dir = tmp_path / "events"
    sample_size = len(_encoded_line(_event(0)))
    stores = [
        _store(
            base_dir,
            max_file_bytes=sample_size * 4,
            max_archives=100,
        )
        for _ in range(4)
    ]

    def emit(index: int) -> None:
        stores[index % len(stores)].emit(_event(index))

    with ThreadPoolExecutor(max_workers=12) as executor:
        list(executor.map(emit, range(120)))

    results = stores[0].query(limit=200)
    assert Counter(event.session_id for event in results) == Counter(
        f"session-{index:04d}" for index in range(120)
    )
    for path in base_dir.glob("events_*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            json.loads(line)


def test_separate_processes_emit_without_rotation_races(tmp_path: Path) -> None:
    base_dir = tmp_path / "events"
    sample_size = len(_encoded_line(_event(0)))
    context = multiprocessing.get_context("spawn")
    processes = [
        context.Process(
            target=_emit_in_process,
            args=(str(base_dir), start, 40, sample_size * 3),
        )
        for start in (0, 40)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=15)
        assert process.exitcode == 0

    store = _store(
        base_dir,
        max_file_bytes=sample_size * 3,
        max_archives=100,
    )
    results = store.query(limit=100)
    assert Counter(event.session_id for event in results) == Counter(
        f"session-{index:04d}" for index in range(80)
    )


def test_rotation_enforces_archive_cap_without_external_prune(tmp_path: Path) -> None:
    max_file_bytes = len(_encoded_line(_event(1)))
    store = _store(
        tmp_path / "events",
        max_file_bytes=max_file_bytes,
        max_archives=2,
    )

    for index in range(1, 6):
        store.emit(_event(index))

    active = store._get_file()
    assert not _archive_path(active, 1).exists()
    assert not _archive_path(active, 2).exists()
    assert _archive_path(active, 3).exists()
    assert _archive_path(active, 4).exists()
    assert active.exists()
    assert [event.session_id for event in store.query(limit=10)] == [
        "session-0003",
        "session-0004",
        "session-0005",
    ]


def test_prune_applies_age_and_global_archive_count_without_deleting_active(
    tmp_path: Path,
) -> None:
    store = _store(
        tmp_path / "events",
        retention_days=30,
        max_file_bytes=1024,
        max_archives=2,
    )
    active = store._get_file()
    active.write_text("active\n", encoding="utf-8")
    old_daily = store.base_dir / "events_2000-01-01.jsonl"
    old_archive = store.base_dir / "events_2000-01-01.1.jsonl"
    old_daily.write_text("old\n", encoding="utf-8")
    old_archive.write_text("old archive\n", encoding="utf-8")
    current_archives = [_archive_path(active, sequence) for sequence in range(1, 5)]
    for path in current_archives:
        path.write_text(path.name, encoding="utf-8")

    deleted = store.prune()

    assert deleted == 4
    assert active.exists()
    assert not old_daily.exists()
    assert not old_archive.exists()
    assert not current_archives[0].exists()
    assert not current_archives[1].exists()
    assert current_archives[2].exists()
    assert current_archives[3].exists()


def test_archive_count_includes_past_daily_base_files(tmp_path: Path) -> None:
    store = _store(
        tmp_path / "events",
        retention_days=365,
        max_file_bytes=1024,
        max_archives=2,
    )
    active = store._get_file()
    active.write_text("active\n", encoding="utf-8")
    today = datetime.now(UTC).date()
    past_daily = [
        store.base_dir / f"events_{today - timedelta(days=offset)}.jsonl" for offset in range(1, 4)
    ]
    for path in past_daily:
        path.write_text(path.name, encoding="utf-8")

    deleted = store.prune()

    assert deleted == 1
    assert active.exists()
    assert past_daily[0].exists()
    assert past_daily[1].exists()
    assert not past_daily[2].exists()


def test_short_write_is_rolled_back_and_retried_as_one_complete_record(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = _store(
        tmp_path / "events",
        max_file_bytes=4096,
        max_archives=10,
    )
    real_write = os.write
    call_count = 0

    def flaky_write(fd: int, data: bytes) -> int:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            partial = max(1, len(data) // 2)
            return real_write(fd, data[:partial])
        if call_count == 2:
            raise OSError("simulated interrupted append")
        return real_write(fd, data)

    monkeypatch.setattr(event_store_module.os, "write", flaky_write)

    store.emit(_event(1))

    lines = store._get_file().read_text(encoding="utf-8").splitlines()
    assert call_count >= 3
    assert len(lines) == 1
    assert json.loads(lines[0])["session_id"] == "session-0001"
    assert [event.session_id for event in store.query(limit=10)] == ["session-0001"]


def test_failed_short_write_rollback_is_preserved_without_poisoning_next_record(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = _store(
        tmp_path / "events",
        max_file_bytes=4096,
        max_archives=10,
    )
    real_write = os.write
    real_ftruncate = os.ftruncate
    write_calls = 0

    def interrupted_write(fd: int, data: bytes) -> int:
        nonlocal write_calls
        write_calls += 1
        if write_calls == 1:
            partial = max(1, len(data) // 2)
            return real_write(fd, data[:partial])
        if write_calls == 2:
            raise OSError("simulated interrupted append")
        return real_write(fd, data)

    def failed_rollback(fd: int, length: int) -> None:
        raise OSError("simulated rollback failure")

    monkeypatch.setattr(event_store_module.os, "write", interrupted_write)
    monkeypatch.setattr(event_store_module.os, "ftruncate", failed_rollback)
    store.emit(_event(1))

    partial_bytes = store._get_file().read_bytes()
    assert partial_bytes
    assert not partial_bytes.endswith(b"\n")

    monkeypatch.setattr(event_store_module.os, "write", real_write)
    monkeypatch.setattr(event_store_module.os, "ftruncate", real_ftruncate)
    store.emit(_event(2))

    active = store._get_file()
    archive = _archive_path(active, 1)
    assert archive.read_bytes() == partial_bytes
    assert json.loads(active.read_text(encoding="utf-8"))["session_id"] == "session-0002"
    assert [event.session_id for event in store.query(limit=10)] == ["session-0002"]


def test_emit_failure_is_observable_and_later_success_recovers_health(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = _store(
        tmp_path / "events",
        max_file_bytes=4096,
        max_archives=10,
    )
    real_append = store._append_line

    def fail_append(path: Path, line: bytes) -> None:
        del path, line
        raise OSError("disk full")

    monkeypatch.setattr(store, "_append_line", fail_append)

    assert store.emit(_event(1)) is False
    failed = store.health()
    assert failed["ok"] is False
    assert failed["write_failures"] == 1
    assert failed["consecutive_write_failures"] == 1
    assert "disk full" in failed["last_error"]
    assert failed["last_failure_at"] is not None

    monkeypatch.setattr(store, "_append_line", real_append)
    assert store.emit(_event(2)) is True
    recovered = store.health()
    assert recovered["ok"] is True
    assert recovered["write_failures"] == 1
    assert recovered["consecutive_write_failures"] == 0
    assert recovered["last_error"] == ""
    assert recovered["last_success_at"] is not None
    assert [event.session_id for event in store.query(limit=10)] == ["session-0002"]
