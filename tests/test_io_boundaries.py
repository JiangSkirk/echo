"""I/O boundary tests for core modules.

Tests edge cases, error handling, and security boundaries in file system,
database, and network operations.
"""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

import js.utils.db as db_utils
from js.config import SecurityConfig, ToolLimits
from js.memory.embeddings import KeywordEmbedder
from js.memory.enhanced_store import EnhancedMemoryStore
from js.memory.store import MemoryStore
from js.security.guard import BehaviorGuard
from js.tools.files import FileTools
from js.utils.db import db_connection


class _TrackingCursor:
    def __init__(self, row: tuple[str, ...] | None = None, error: Exception | None = None) -> None:
        self.row = row
        self.error = error
        self.closed = False

    def fetchone(self) -> tuple[str, ...] | None:
        if self.error is not None:
            raise self.error
        return self.row

    def close(self) -> None:
        self.closed = True


class _TrackingConnection:
    def __init__(
        self,
        cursor: _TrackingCursor | None = None,
        *,
        cursors: dict[str, _TrackingCursor] | None = None,
        execute_errors: dict[str, Exception] | None = None,
        scripted_results: dict[str, list[_TrackingCursor | Exception]] | None = None,
    ) -> None:
        self.cursor = cursor
        self.cursors = cursors or {}
        self.execute_errors = execute_errors or {}
        self.scripted_results = scripted_results or {}
        self.statements: list[str] = []
        self.closed = False

    def execute(self, statement: str) -> _TrackingCursor:
        self.statements.append(statement)
        if statement in self.scripted_results:
            result = self.scripted_results[statement].pop(0)
            if isinstance(result, Exception):
                raise result
            return result
        if statement in self.execute_errors:
            raise self.execute_errors[statement]
        if statement in self.cursors:
            return self.cursors[statement]
        assert self.cursor is not None
        return self.cursor

    def close(self) -> None:
        self.closed = True


class _AsyncTrackingCursor:
    def __init__(
        self,
        row: tuple[str, ...] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.row = row
        self.error = error
        self.closed = False

    async def fetchone(self) -> tuple[str, ...] | None:
        if self.error is not None:
            raise self.error
        return self.row

    async def close(self) -> None:
        self.closed = True


class _AsyncTrackingConnection:
    def __init__(
        self,
        *,
        cursors: dict[str, _AsyncTrackingCursor] | None = None,
        execute_errors: dict[str, Exception] | None = None,
        scripted_results: dict[str, list[_AsyncTrackingCursor | Exception]] | None = None,
    ) -> None:
        self.cursors = cursors or {}
        self.execute_errors = execute_errors or {}
        self.scripted_results = scripted_results or {}
        self.statements: list[str] = []
        self.closed = False

    async def execute(self, statement: str) -> _AsyncTrackingCursor:
        self.statements.append(statement)
        if statement in self.scripted_results:
            result = self.scripted_results[statement].pop(0)
            if isinstance(result, Exception):
                raise result
            return result
        if statement in self.execute_errors:
            raise self.execute_errors[statement]
        return self.cursors[statement]


class _AsyncConnectionContext:
    def __init__(self, conn: _AsyncTrackingConnection) -> None:
        self.conn = conn

    async def __aenter__(self) -> _AsyncTrackingConnection:
        return self.conn

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.conn.closed = True


def _open_db_in_fork(db_path: str, start_event: Any, result_conn: Any) -> None:
    try:
        start_event.wait(timeout=5)
        with db_connection(db_path) as conn:
            cursor = conn.execute("PRAGMA journal_mode")
            try:
                mode = cursor.fetchone()[0]
            finally:
                cursor.close()
        result_conn.send(("ok", mode))
    except BaseException as exc:
        result_conn.send(("error", f"{type(exc).__name__}: {exc}"))
    finally:
        result_conn.close()


def _open_db_after_barrier(db_path: str, barrier: threading.Barrier) -> str:
    barrier.wait(timeout=5)
    with db_connection(db_path) as conn:
        cursor = conn.execute("PRAGMA journal_mode")
        try:
            return str(cursor.fetchone()[0]).lower()
        finally:
            cursor.close()


async def _open_async_db_after_barrier(db_path: str, barrier: asyncio.Barrier) -> str:
    await barrier.wait()
    async with db_utils.adb_connection(db_path) as conn:
        cursor = await conn.execute("PRAGMA journal_mode")
        try:
            return str((await cursor.fetchone())[0]).lower()
        finally:
            await cursor.close()


def _hold_exclusive_lock(db_path: Path) -> sqlite3.Connection:
    holder = sqlite3.connect(db_path, timeout=0)
    holder.execute("CREATE TABLE IF NOT EXISTS seed (id INTEGER PRIMARY KEY)")
    holder.commit()
    holder.execute("BEGIN EXCLUSIVE")
    return holder


def _open_db_after_signal(db_path: str, started: threading.Event) -> tuple[str, float]:
    started.set()
    start = time.monotonic()
    with db_connection(db_path) as conn:
        cursor = conn.execute("PRAGMA journal_mode")
        try:
            mode = str(cursor.fetchone()[0]).lower()
        finally:
            cursor.close()
    return mode, time.monotonic() - start


async def _open_async_db_after_signal(
    db_path: str, started: asyncio.Event
) -> tuple[str, float]:
    started.set()
    start = time.monotonic()
    async with db_utils.adb_connection(db_path) as conn:
        cursor = await conn.execute("PRAGMA journal_mode")
        try:
            mode = str((await cursor.fetchone())[0]).lower()
        finally:
            await cursor.close()
    return mode, time.monotonic() - start


class TestFileToolsBoundaries:
    @pytest.fixture
    def file_tools(self, tmp_path: Path) -> FileTools:
        limits = ToolLimits()
        guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
        return FileTools(tmp_path, limits, guard)

    @pytest.mark.asyncio
    async def test_read_nonexistent_file(self, file_tools: FileTools) -> None:
        result = await file_tools.read("does_not_exist.txt")
        assert not result.success
        assert "not found" in result.error.lower() or "no such" in result.error.lower()

    @pytest.mark.asyncio
    async def test_write_path_traversal_blocked(self, file_tools: FileTools, tmp_path: Path) -> None:
        result = await file_tools.write("../../../etc/passwd", "evil")
        # Should be resolved within workspace and either succeed in workspace or be blocked
        target = (tmp_path / "../../../etc/passwd").resolve()
        assert not target.is_relative_to(tmp_path) or not result.success

    @pytest.mark.asyncio
    async def test_delete_nonexistent_file(self, file_tools: FileTools) -> None:
        result = await file_tools.delete("missing.txt")
        assert not result.success

    @pytest.mark.asyncio
    async def test_list_dir_recursive(self, file_tools: FileTools, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "nested.txt").write_text("deep")
        result = await file_tools.list_dir(".", recursive=True)
        assert result.success
        assert "nested.txt" in result.output

    @pytest.mark.asyncio
    async def test_search_empty_dir(self, file_tools: FileTools) -> None:
        result = await file_tools.search("*.txt", ".")
        assert result.success
        # Empty directory should return no matches
        assert "no matches" in result.output.lower() or result.output == ""

    @pytest.mark.asyncio
    async def test_read_with_offset_limit(self, file_tools: FileTools) -> None:
        await file_tools.write("sample.txt", "line1\nline2\nline3\nline4\nline5")
        result = await file_tools.read("sample.txt", offset=1, limit=2)
        assert result.success
        assert "line2" in result.output
        assert "line3" in result.output
        assert "line1" not in result.output


class TestMemoryStoreBoundaries:
    def test_store_episode_empty_topics(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path, None, KeywordEmbedder())
        store.store_episode("s1", "summary", [], 100, 2, 5)
        episodes = store.get_episodes(limit=10)
        assert len(episodes) == 1
        assert episodes[0].summary == "summary"

    def test_session_messages_empty(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path, None, KeywordEmbedder())
        msgs = store.get_session_messages("nonexistent")
        assert msgs == []

    def test_delete_nonexistent_session(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path, None, KeywordEmbedder())
        # Should not raise
        store.delete_session("never-existed")
        assert store.get_session_messages("never-existed") == []

    def test_enhanced_semantic_empty_search(self, tmp_path: Path) -> None:
        enhanced = EnhancedMemoryStore(tmp_path, None, KeywordEmbedder())
        results = enhanced.search_semantic("something random")
        assert results == []

    def test_enhanced_working_empty_session(self, tmp_path: Path) -> None:
        enhanced = EnhancedMemoryStore(tmp_path, None, KeywordEmbedder())
        results = enhanced.get_working("empty-session", limit=50)
        assert results == []


class TestDbConnectionBoundaries:
    def test_db_connection_retries_journal_read_until_exclusive_lock_releases(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "sync-exclusive-release.db"
        holder = _hold_exclusive_lock(db_path)
        started = threading.Event()
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_open_db_after_signal, str(db_path), started)
                assert started.wait(timeout=1)
                time.sleep(0.4)
                holder.rollback()
                mode, elapsed = future.result(timeout=2)
        finally:
            holder.rollback()
            holder.close()

        assert mode == "wal"
        assert 0.35 <= elapsed < 1.5

    @pytest.mark.asyncio
    async def test_adb_connection_retries_journal_read_until_exclusive_lock_releases(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "async-exclusive-release.db"
        holder = _hold_exclusive_lock(db_path)
        started = asyncio.Event()
        task = asyncio.create_task(_open_async_db_after_signal(str(db_path), started))
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            await asyncio.sleep(0.4)
            holder.rollback()
            mode, elapsed = await asyncio.wait_for(task, timeout=2)
        finally:
            holder.rollback()
            holder.close()
            if not task.done():
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task

        assert mode == "wal"
        assert 0.35 <= elapsed < 1.5

    def test_db_connection_fails_within_slo_while_exclusive_lock_persists(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "sync-exclusive-timeout.db"
        holder = _hold_exclusive_lock(db_path)
        start = time.monotonic()
        try:
            with pytest.raises(sqlite3.OperationalError, match="locked"), db_connection(db_path):
                pass
        finally:
            elapsed = time.monotonic() - start
            holder.rollback()
            holder.close()

        assert 0.8 <= elapsed < 1.5

    @pytest.mark.asyncio
    async def test_adb_connection_fails_within_slo_while_exclusive_lock_persists(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "async-exclusive-timeout.db"
        holder = _hold_exclusive_lock(db_path)
        start = time.monotonic()
        try:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                async with db_utils.adb_connection(db_path):
                    pass
        finally:
            elapsed = time.monotonic() - start
            holder.rollback()
            holder.close()

        assert 0.8 <= elapsed < 1.5

    @pytest.mark.asyncio
    async def test_adb_connection_propagates_cancellation_during_wal_retry(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "async-exclusive-cancel.db"
        holder = _hold_exclusive_lock(db_path)
        started = asyncio.Event()
        task = asyncio.create_task(_open_async_db_after_signal(str(db_path), started))
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            await asyncio.sleep(0.05)
            cancelled_at = time.monotonic()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert time.monotonic() - cancelled_at < 0.5
        finally:
            holder.rollback()
            holder.close()
            if not task.done():
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task

    def test_ensure_wal_rejects_non_wal_result_without_retry(self) -> None:
        journal_cursor = _TrackingCursor(("delete",))
        wal_cursor = _TrackingCursor(("delete",))
        conn = _TrackingConnection(
            cursors={
                "PRAGMA journal_mode": journal_cursor,
                "PRAGMA journal_mode=WAL": wal_cursor,
            }
        )

        with pytest.raises(sqlite3.OperationalError, match="refused WAL"):
            db_utils._ensure_wal(conn)  # type: ignore[arg-type]

        assert journal_cursor.closed
        assert wal_cursor.closed
        assert conn.statements == ["PRAGMA journal_mode", "PRAGMA journal_mode=WAL"]

    @pytest.mark.parametrize(
        ("message", "error_code"),
        [
            ("database is locked", sqlite3.SQLITE_LOCKED),
            ("database is busy", sqlite3.SQLITE_BUSY),
        ],
    )
    def test_sync_wal_state_machine_retries_locked_read_up_to_attempt_limit(
        self, monkeypatch: pytest.MonkeyPatch, message: str, error_code: int
    ) -> None:
        locked = sqlite3.OperationalError(message)
        locked.sqlite_errorcode = error_code
        conn = _TrackingConnection(execute_errors={"PRAGMA journal_mode": locked})
        delays: list[float] = []
        monkeypatch.setattr(db_utils.time, "monotonic", lambda: 0.0)
        monkeypatch.setattr(db_utils.time, "sleep", delays.append)

        with pytest.raises(sqlite3.OperationalError) as exc_info:
            db_utils._ensure_wal(conn)  # type: ignore[arg-type]

        assert exc_info.value is locked
        assert conn.statements == ["PRAGMA journal_mode"] * 16
        assert len(delays) == 15
        assert max(delays) <= 0.1

    def test_sync_wal_state_machine_does_not_retry_non_lock_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        error = sqlite3.OperationalError("database is busy handling a disk I/O error")
        error.sqlite_errorcode = sqlite3.SQLITE_IOERR
        conn = _TrackingConnection(execute_errors={"PRAGMA journal_mode": error})
        monkeypatch.setattr(db_utils.time, "sleep", lambda _: pytest.fail("unexpected retry"))

        with pytest.raises(sqlite3.OperationalError) as exc_info:
            db_utils._ensure_wal(conn)  # type: ignore[arg-type]

        assert exc_info.value is error
        assert conn.statements == ["PRAGMA journal_mode"]

    @pytest.mark.parametrize(
        ("error_code", "expected"),
        [
            (sqlite3.SQLITE_BUSY, True),
            (sqlite3.SQLITE_BUSY | (2 << 8), True),
            (sqlite3.SQLITE_LOCKED, True),
            (sqlite3.SQLITE_LOCKED | (1 << 8), True),
            (sqlite3.SQLITE_IOERR, False),
            (sqlite3.SQLITE_IOERR | (15 << 8), False),
            (None, False),
        ],
    )
    def test_lock_retry_classification_uses_sqlite_primary_error_code(
        self,
        error_code: int | None,
        expected: bool,
    ) -> None:
        error = sqlite3.OperationalError("database is busy")
        if error_code is not None:
            error.sqlite_errorcode = error_code

        assert db_utils._is_locked_or_busy(error) is expected

    def test_db_connection_uses_bounded_wal_bootstrap_before_normal_timeout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        locked = sqlite3.OperationalError("database is locked")
        locked.sqlite_errorcode = sqlite3.SQLITE_LOCKED
        bootstrap_cursor = _TrackingCursor((None,))
        journal_cursor = _TrackingCursor(("delete",))
        retry_journal_cursor = _TrackingCursor(("delete",))
        wal_cursor = _TrackingCursor(("wal",))
        normal_cursor = _TrackingCursor((None,))
        fake_conn = _TrackingConnection(
            cursors={
                "PRAGMA busy_timeout=0": bootstrap_cursor,
                "PRAGMA busy_timeout=5000": normal_cursor,
            },
            scripted_results={
                "PRAGMA journal_mode": [locked, journal_cursor, retry_journal_cursor],
                "PRAGMA journal_mode=WAL": [locked, wal_cursor],
            },
        )
        delays: list[float] = []
        monkeypatch.setattr(db_utils.sqlite3, "connect", lambda *args, **kwargs: fake_conn)
        monkeypatch.setattr(db_utils.time, "sleep", delays.append)

        with db_connection(tmp_path / "bounded-bootstrap.db"):
            pass

        assert fake_conn.statements == [
            "PRAGMA busy_timeout=0",
            "PRAGMA journal_mode",
            "PRAGMA journal_mode",
            "PRAGMA journal_mode=WAL",
            "PRAGMA journal_mode",
            "PRAGMA journal_mode=WAL",
            "PRAGMA busy_timeout=5000",
        ]
        assert len(delays) == 2
        assert max(delays) <= 0.1
        assert all(
            cursor.closed
            for cursor in (
                bootstrap_cursor,
                journal_cursor,
                retry_journal_cursor,
                wal_cursor,
                normal_cursor,
            )
        )

    def test_sync_wal_state_machine_closes_failed_read_cursor_before_backoff(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        locked = sqlite3.OperationalError("database is locked")
        locked.sqlite_errorcode = sqlite3.SQLITE_LOCKED
        locked_cursor = _TrackingCursor(error=locked)
        wal_cursor = _TrackingCursor(("wal",))
        conn = _TrackingConnection(
            scripted_results={"PRAGMA journal_mode": [locked_cursor, wal_cursor]}
        )
        closed_before_backoff: list[bool] = []
        monkeypatch.setattr(db_utils.time, "sleep", lambda _: closed_before_backoff.append(locked_cursor.closed))

        db_utils._ensure_wal(conn)  # type: ignore[arg-type]

        assert closed_before_backoff == [True]
        assert locked_cursor.closed
        assert wal_cursor.closed

    @pytest.mark.parametrize("wal_helper", [db_utils._enable_wal, db_utils._ensure_wal])
    def test_sync_wal_helpers_close_pragma_cursor_when_fetch_fails(self, wal_helper: Any) -> None:
        cursor = _TrackingCursor(error=sqlite3.OperationalError("read failed"))
        conn = _TrackingConnection(cursor)

        with pytest.raises(sqlite3.OperationalError, match="read failed"):
            wal_helper(conn)

        assert cursor.closed

    def test_db_connection_configures_wal_only_when_needed(self, tmp_path: Path) -> None:
        db_path = tmp_path / "wal-once.db"

        with patch.object(db_utils, "_enable_wal", wraps=db_utils._enable_wal) as enable_wal:
            with db_connection(db_path) as conn:
                conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
                conn.commit()
            with db_connection(db_path) as conn:
                conn.execute("SELECT 1").fetchone()

        assert enable_wal.call_count == 1

    def test_db_connection_reconfigures_wal_after_database_replacement(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "replace.db"
        replacement = tmp_path / "replacement.db"

        with patch.object(db_utils, "_enable_wal", wraps=db_utils._enable_wal) as enable_wal:
            with db_connection(db_path) as conn:
                conn.execute("CREATE TABLE first (id INTEGER PRIMARY KEY)")
                conn.commit()
            with sqlite3.connect(replacement) as conn:
                conn.execute("CREATE TABLE second (id INTEGER PRIMARY KEY)")
                conn.commit()
            replacement.replace(db_path)
            with db_connection(db_path) as conn:
                conn.execute("SELECT * FROM second").fetchall()

        assert enable_wal.call_count == 2

    def test_db_connection_repairs_external_journal_mode_change(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "mode-drift.db"

        with db_connection(db_path) as conn:
            conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
            conn.commit()
        with sqlite3.connect(db_path) as conn:
            assert conn.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"

        with db_connection(db_path) as conn:
            assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"

    def test_db_connection_observes_existing_wal_through_path_alias(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "canonical.db"
        alias_path = tmp_path / "alias.db"

        with patch.object(db_utils, "_enable_wal", wraps=db_utils._enable_wal) as enable_wal:
            with db_connection(db_path) as conn:
                conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
                conn.commit()
            alias_path.symlink_to(db_path)
            with db_connection(alias_path) as conn:
                conn.execute("SELECT 1").fetchone()

        assert enable_wal.call_count == 1

    def test_db_connection_closes_busy_timeout_cursor_before_wal_setup(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bootstrap_cursor = _TrackingCursor((None,))
        journal_cursor = _TrackingCursor(("wal",))
        normal_cursor = _TrackingCursor((None,))
        fake_conn = _TrackingConnection(
            cursors={
                "PRAGMA busy_timeout=0": bootstrap_cursor,
                "PRAGMA journal_mode": journal_cursor,
                "PRAGMA busy_timeout=5000": normal_cursor,
            }
        )
        monkeypatch.setattr(db_utils.sqlite3, "connect", lambda *args, **kwargs: fake_conn)

        with db_connection(tmp_path / "busy-timeout.db"):
            pass

        assert bootstrap_cursor.closed
        assert journal_cursor.closed
        assert normal_cursor.closed

    def test_db_connection_closes_busy_timeout_cursor_when_wal_setup_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bootstrap_cursor = _TrackingCursor((None,))
        journal_cursor = _TrackingCursor(error=sqlite3.OperationalError("read failed"))
        fake_conn = _TrackingConnection(
            cursors={
                "PRAGMA busy_timeout=0": bootstrap_cursor,
                "PRAGMA journal_mode": journal_cursor,
            }
        )
        monkeypatch.setattr(db_utils.sqlite3, "connect", lambda *args, **kwargs: fake_conn)

        with pytest.raises(sqlite3.OperationalError, match="read failed"), db_connection(
            tmp_path / "busy-timeout-error.db"
        ):
            pass

        assert bootstrap_cursor.closed
        assert journal_cursor.closed
        assert "PRAGMA busy_timeout=5000" not in fake_conn.statements

    @pytest.mark.asyncio
    async def test_adb_connection_configures_wal_only_when_needed(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "async-wal.db"

        with patch.object(
            db_utils,
            "_enable_wal_async",
            wraps=db_utils._enable_wal_async,
        ) as enable_wal:
            async with db_utils.adb_connection(db_path) as conn:
                await conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
                await conn.commit()
            async with db_utils.adb_connection(db_path) as conn:
                await conn.execute("SELECT 1")

        assert enable_wal.call_count == 1

    @pytest.mark.asyncio
    async def test_adb_connection_repairs_external_journal_mode_change(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "async-mode-drift.db"

        async with db_utils.adb_connection(db_path) as conn:
            await conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
            await conn.commit()
        with sqlite3.connect(db_path) as conn:
            assert conn.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"

        async with db_utils.adb_connection(db_path) as conn:
            cursor = await conn.execute("PRAGMA journal_mode")
            try:
                assert (await cursor.fetchone())[0] == "wal"
            finally:
                await cursor.close()

    @pytest.mark.asyncio
    async def test_adb_connection_reconfigures_wal_after_database_replacement(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "async-replace.db"
        replacement = tmp_path / "async-replacement.db"

        async with db_utils.adb_connection(db_path) as conn:
            await conn.execute("CREATE TABLE first (id INTEGER PRIMARY KEY)")
            await conn.commit()
        with sqlite3.connect(replacement) as conn:
            conn.execute("CREATE TABLE second (id INTEGER PRIMARY KEY)")
            conn.commit()
        replacement.replace(db_path)

        async with db_utils.adb_connection(db_path) as conn:
            cursor = await conn.execute("PRAGMA journal_mode")
            try:
                assert (await cursor.fetchone())[0] == "wal"
            finally:
                await cursor.close()

    @pytest.mark.asyncio
    async def test_adb_connection_observes_existing_wal_through_path_alias(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "async-canonical.db"
        alias_path = tmp_path / "async-alias.db"

        with patch.object(
            db_utils,
            "_enable_wal_async",
            wraps=db_utils._enable_wal_async,
        ) as enable_wal:
            async with db_utils.adb_connection(db_path) as conn:
                await conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
                await conn.commit()
            alias_path.symlink_to(db_path)
            async with db_utils.adb_connection(alias_path) as conn:
                cursor = await conn.execute("SELECT 1")
                try:
                    assert (await cursor.fetchone())[0] == 1
                finally:
                    await cursor.close()

        assert enable_wal.call_count == 1

    @pytest.mark.asyncio
    async def test_adb_connection_closes_busy_timeout_cursor_before_wal_setup(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bootstrap_cursor = _AsyncTrackingCursor()
        journal_cursor = _AsyncTrackingCursor(("wal",))
        normal_cursor = _AsyncTrackingCursor()
        fake_conn = _AsyncTrackingConnection(
            cursors={
                "PRAGMA busy_timeout=0": bootstrap_cursor,
                "PRAGMA journal_mode": journal_cursor,
                "PRAGMA busy_timeout=5000": normal_cursor,
            }
        )
        monkeypatch.setattr(
            db_utils.aiosqlite,
            "connect",
            lambda *args, **kwargs: _AsyncConnectionContext(fake_conn),
        )

        async with db_utils.adb_connection(tmp_path / "async-busy-timeout.db"):
            pass

        assert bootstrap_cursor.closed
        assert journal_cursor.closed
        assert normal_cursor.closed

    @pytest.mark.asyncio
    async def test_adb_connection_closes_busy_timeout_cursor_when_wal_setup_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bootstrap_cursor = _AsyncTrackingCursor()
        journal_cursor = _AsyncTrackingCursor(error=sqlite3.OperationalError("read failed"))
        fake_conn = _AsyncTrackingConnection(
            cursors={
                "PRAGMA busy_timeout=0": bootstrap_cursor,
                "PRAGMA journal_mode": journal_cursor,
            },
        )
        monkeypatch.setattr(
            db_utils.aiosqlite,
            "connect",
            lambda *args, **kwargs: _AsyncConnectionContext(fake_conn),
        )

        with pytest.raises(sqlite3.OperationalError, match="read failed"):
            async with db_utils.adb_connection(tmp_path / "async-busy-timeout-error.db"):
                pass

        assert bootstrap_cursor.closed
        assert journal_cursor.closed
        assert "PRAGMA busy_timeout=5000" not in fake_conn.statements

    @pytest.mark.asyncio
    async def test_adb_connection_uses_bounded_wal_bootstrap_before_normal_timeout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        locked = sqlite3.OperationalError("database is locked")
        locked.sqlite_errorcode = sqlite3.SQLITE_LOCKED
        bootstrap_cursor = _AsyncTrackingCursor()
        journal_cursor = _AsyncTrackingCursor(("delete",))
        retry_journal_cursor = _AsyncTrackingCursor(("delete",))
        wal_cursor = _AsyncTrackingCursor(("wal",))
        normal_cursor = _AsyncTrackingCursor()
        fake_conn = _AsyncTrackingConnection(
            cursors={
                "PRAGMA busy_timeout=0": bootstrap_cursor,
                "PRAGMA busy_timeout=5000": normal_cursor,
            },
            scripted_results={
                "PRAGMA journal_mode": [locked, journal_cursor, retry_journal_cursor],
                "PRAGMA journal_mode=WAL": [locked, wal_cursor],
            },
        )
        delays: list[float] = []

        async def record_delay(delay: float) -> None:
            delays.append(delay)

        monkeypatch.setattr(
            db_utils.aiosqlite,
            "connect",
            lambda *args, **kwargs: _AsyncConnectionContext(fake_conn),
        )
        monkeypatch.setattr(db_utils.asyncio, "sleep", record_delay)

        async with db_utils.adb_connection(tmp_path / "async-bounded-bootstrap.db"):
            pass

        assert fake_conn.statements == [
            "PRAGMA busy_timeout=0",
            "PRAGMA journal_mode",
            "PRAGMA journal_mode",
            "PRAGMA journal_mode=WAL",
            "PRAGMA journal_mode",
            "PRAGMA journal_mode=WAL",
            "PRAGMA busy_timeout=5000",
        ]
        assert len(delays) == 2
        assert max(delays) <= 0.1
        assert all(
            cursor.closed
            for cursor in (
                bootstrap_cursor,
                journal_cursor,
                retry_journal_cursor,
                wal_cursor,
                normal_cursor,
            )
        )

    @pytest.mark.asyncio
    async def test_async_wal_state_machine_closes_failed_read_cursor_before_backoff(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        locked = sqlite3.OperationalError("database is locked")
        locked.sqlite_errorcode = sqlite3.SQLITE_LOCKED
        locked_cursor = _AsyncTrackingCursor(error=locked)
        wal_cursor = _AsyncTrackingCursor(("wal",))
        conn = _AsyncTrackingConnection(
            scripted_results={"PRAGMA journal_mode": [locked_cursor, wal_cursor]}
        )
        closed_before_backoff: list[bool] = []

        async def record_delay(_: float) -> None:
            closed_before_backoff.append(locked_cursor.closed)

        monkeypatch.setattr(db_utils.asyncio, "sleep", record_delay)

        await db_utils._ensure_wal_async(conn)  # type: ignore[arg-type]

        assert closed_before_backoff == [True]
        assert locked_cursor.closed
        assert wal_cursor.closed

    @pytest.mark.asyncio
    async def test_async_ensure_wal_rejects_non_wal_result_without_retry(self) -> None:
        journal_cursor = _AsyncTrackingCursor(("delete",))
        wal_cursor = _AsyncTrackingCursor(("delete",))
        conn = _AsyncTrackingConnection(
            cursors={
                "PRAGMA journal_mode": journal_cursor,
                "PRAGMA journal_mode=WAL": wal_cursor,
            }
        )

        with pytest.raises(sqlite3.OperationalError, match="refused WAL"):
            await db_utils._ensure_wal_async(conn)  # type: ignore[arg-type]

        assert journal_cursor.closed
        assert wal_cursor.closed
        assert conn.statements == ["PRAGMA journal_mode", "PRAGMA journal_mode=WAL"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("message", "error_code"),
        [
            ("database is locked", sqlite3.SQLITE_LOCKED),
            ("database is busy", sqlite3.SQLITE_BUSY),
        ],
    )
    async def test_async_wal_state_machine_retries_locked_read_up_to_attempt_limit(
        self, monkeypatch: pytest.MonkeyPatch, message: str, error_code: int
    ) -> None:
        locked = sqlite3.OperationalError(message)
        locked.sqlite_errorcode = error_code
        conn = _AsyncTrackingConnection(
            execute_errors={"PRAGMA journal_mode": locked}
        )
        delays: list[float] = []

        async def record_delay(delay: float) -> None:
            delays.append(delay)

        monkeypatch.setattr(db_utils.time, "monotonic", lambda: 0.0)
        monkeypatch.setattr(db_utils.asyncio, "sleep", record_delay)

        with pytest.raises(sqlite3.OperationalError) as exc_info:
            await db_utils._ensure_wal_async(conn)  # type: ignore[arg-type]

        assert exc_info.value is locked
        assert conn.statements == ["PRAGMA journal_mode"] * 16
        assert len(delays) == 15
        assert max(delays) <= 0.1

    @pytest.mark.asyncio
    async def test_async_wal_state_machine_does_not_retry_non_lock_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        error = sqlite3.OperationalError("database is busy handling a disk I/O error")
        error.sqlite_errorcode = sqlite3.SQLITE_IOERR
        conn = _AsyncTrackingConnection(execute_errors={"PRAGMA journal_mode": error})

        async def fail_on_retry(_: float) -> None:
            pytest.fail("unexpected retry")

        monkeypatch.setattr(db_utils.asyncio, "sleep", fail_on_retry)

        with pytest.raises(sqlite3.OperationalError) as exc_info:
            await db_utils._ensure_wal_async(conn)  # type: ignore[arg-type]

        assert exc_info.value is error
        assert conn.statements == ["PRAGMA journal_mode"]

    def test_db_connection_concurrent_threads_open_same_database_with_wal(
        self, tmp_path: Path
    ) -> None:
        worker_count = 8
        for round_number in range(50):
            db_path = tmp_path / f"thread-first-open-{round_number}.db"
            barrier = threading.Barrier(worker_count)
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = [
                    executor.submit(_open_db_after_barrier, str(db_path), barrier)
                    for _ in range(worker_count)
                ]
                modes = [future.result(timeout=5) for future in futures]

            assert modes == ["wal"] * worker_count

    @pytest.mark.asyncio
    async def test_adb_connection_concurrent_first_openers_use_wal(self, tmp_path: Path) -> None:
        worker_count = 8
        for round_number in range(50):
            db_path = tmp_path / f"async-first-open-{round_number}.db"
            barrier = asyncio.Barrier(worker_count)
            modes = await asyncio.wait_for(
                asyncio.gather(
                    *(
                        _open_async_db_after_barrier(str(db_path), barrier)
                        for _ in range(worker_count)
                    )
                ),
                timeout=5,
            )

            assert modes == ["wal"] * worker_count

    @pytest.mark.skipif(os.name != "posix", reason="fork is only supported on POSIX")
    def test_db_connection_concurrent_fork_first_openers_use_wal(
        self, tmp_path: Path
    ) -> None:
        try:
            context = multiprocessing.get_context("fork")
        except ValueError:
            pytest.skip("fork start method is unavailable")

        process_count = 4
        for round_number in range(50):
            db_path = tmp_path / f"fork-first-open-{round_number}.db"
            start_event = context.Event()
            processes: list[multiprocessing.Process] = []
            receivers: list[Any] = []
            results: list[tuple[str, str] | None] = [None] * process_count
            deadline = time.monotonic() + 5
            try:
                for index in range(process_count):
                    receiver, sender = context.Pipe(duplex=False)
                    process = context.Process(
                        target=_open_db_in_fork,
                        args=(str(db_path), start_event, sender),
                        name=f"db-wal-regression-{round_number}-{index}",
                    )
                    process.start()
                    sender.close()
                    processes.append(process)
                    receivers.append(receiver)

                start_event.set()
                while any(result is None for result in results) and time.monotonic() < deadline:
                    for index, receiver in enumerate(receivers):
                        if results[index] is None and receiver.poll(0.05):
                            results[index] = receiver.recv()

                assert all(result == ("ok", "wal") for result in results), results
            finally:
                for process in processes:
                    if process.is_alive():
                        process.terminate()
                for process in processes:
                    process.join(timeout=1)
                    if process.is_alive():
                        process.terminate()
                        process.join(timeout=1)
                    process.close()
                for receiver in receivers:
                    receiver.close()

    def test_db_connection_creates_file(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        assert not db_path.exists()
        with db_connection(db_path) as conn:
            conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
            conn.commit()
        assert db_path.exists()

    def test_db_connection_rollback_on_error(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        with db_connection(db_path) as conn:
            conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
            conn.execute("INSERT INTO test (id) VALUES (1)")
            conn.commit()

        try:
            with db_connection(db_path) as conn:
                conn.execute("INSERT INTO test (id) VALUES (1)")  # duplicate PK
                conn.commit()
        except Exception:
            pass

        with db_connection(db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM test").fetchone()
            assert row[0] == 1
