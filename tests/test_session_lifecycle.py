"""Tests for SessionLifecycleStore and abnormal-exit recovery."""

from __future__ import annotations

import time

from js.persistence.lifecycle_store import SessionLifecycleStore


def test_mark_started_and_completed(tmp_path):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("s1", "owner_a")
    row = store.get("s1", "owner_a")
    assert row is not None
    assert row["status"] == "running"
    assert row["owner_key_hash"] == "owner_a"

    store.mark_completed("s1", "done")
    row = store.get("s1", "owner_a")
    assert row["status"] == "completed"
    assert row["exit_reason"] == "done"
    assert row["completed_at"] is not None


def test_owner_isolation(tmp_path):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("s2", "owner_a")
    assert store.get("s2", "owner_a") is not None
    assert store.get("s2", "owner_b") is None
    assert store.get("s2") is not None  # legacy/unscoped read allowed


def test_legacy_null_owner_backfill(tmp_path):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("s3", None)
    row = store.get("s3")
    assert row["owner_key_hash"] == "__legacy_local__"


def test_list_active(tmp_path):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("s4", "owner_a")
    store.mark_started("s5", "owner_b")
    store.mark_completed("s4", "done")

    active_a = store.list_active("owner_a")
    assert [r["session_id"] for r in active_a] == []

    active_b = store.list_active("owner_b")
    assert [r["session_id"] for r in active_b] == ["s5"]


def test_recover_aborted_sessions(tmp_path):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("stale", "owner_a")
    # Simulate old heartbeat
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "lifecycle.db"), check_same_thread=False)
    conn.execute(
        "UPDATE session_lifecycle SET last_heartbeat_at = ? WHERE session_id = ?",
        (time.time() - 1000, "stale"),
    )
    conn.commit()
    conn.close()

    store.mark_started("fresh", "owner_a")

    recovered = store.recover_aborted_sessions(threshold_seconds=300)
    assert recovered == ["stale"]

    stale = store.get("stale", "owner_a")
    assert stale["status"] == "aborted"
    assert "abnormal_exit" in stale["exit_reason"]

    fresh = store.get("fresh", "owner_a")
    assert fresh["status"] == "running"
