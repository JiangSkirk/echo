"""Memory dreaming / session store: disk full, clock rollback, and truncated DB."""

from __future__ import annotations

import errno
import sqlite3
from pathlib import Path

import pytest

from js.config import MemoryConfig
from js.memory.enhanced_store import EnhancedMemoryStore
from js.memory.scheduler import DreamScheduler


def test_session_messages_stay_owner_scoped_after_shared_session(tmp_path: Path) -> None:
    store = EnhancedMemoryStore(tmp_path, MemoryConfig())
    try:
        store.store_messages(
            "shared",
            [{"role": "user", "content": "owner-a-secret"}],
            owner_key_hash="owner-a",
        )
        store.store_messages(
            "shared",
            [{"role": "user", "content": "owner-b-secret"}],
            owner_key_hash="owner-b",
        )
        alice = store.get_session_messages("shared", owner_key_hash="owner-a")
        bob = store.get_session_messages("shared", owner_key_hash="owner-b")
        assert [row["content"] for row in alice] == ["owner-a-secret"]
        assert [row["content"] for row in bob] == ["owner-b-secret"]
    finally:
        store.close()


def test_enospc_on_dream_diary_does_not_leak_across_owners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EnhancedMemoryStore(tmp_path, MemoryConfig())
    try:
        store.store_messages(
            "s-a",
            [{"role": "user", "content": "keep-a"}],
            owner_key_hash="owner-a",
        )

        def _full(*args: object, **kwargs: object) -> None:
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(store, "_atomic_write_text", _full)
        with pytest.raises(OSError, match="No space left"):
            store._append_dream_diary({"phases": []}, owner_key_hash="owner-a")
        leftover = store.get_session_messages("s-a", owner_key_hash="owner-a")
        assert leftover[0]["content"] == "keep-a"
        assert store.get_session_messages("s-a", owner_key_hash="owner-b") == []
    finally:
        store.close()


def test_truncated_enhanced_db_fails_closed(tmp_path: Path) -> None:
    store = EnhancedMemoryStore(tmp_path, MemoryConfig())
    try:
        store.store_messages(
            "s-a",
            [{"role": "user", "content": "keep-a"}],
            owner_key_hash="owner-a",
        )
        store.db_path.write_bytes(store.db_path.read_bytes()[:64])
        with pytest.raises(sqlite3.Error):
            store.get_session_messages("s-a", owner_key_hash="owner-a")
    finally:
        store.close()


def test_clock_rollback_does_not_flush_foreign_owner_buffer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 1_000.0}
    monkeypatch.setattr("js.memory.scheduler.time.time", lambda: clock["now"])
    scheduler = DreamScheduler(agent=object())
    scheduler.notify_activity("hello-a", "reply-a", owner_key_hash="owner-a", session_id="s-a")
    clock["now"] = 500.0
    scheduler.notify_activity("hello-b", "reply-b", owner_key_hash="owner-b", session_id="s-b")
    owners = {row["owner_key_hash"] for row in scheduler.snapshot_buffer()}
    assert owners == {"owner-a", "owner-b"}
    assert all(
        (row["owner_key_hash"] == "owner-a" and "hello-b" not in row["user"])
        or (row["owner_key_hash"] == "owner-b" and "hello-a" not in row["user"])
        for row in scheduler.snapshot_buffer()
    )
