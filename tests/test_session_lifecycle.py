"""Tests for SessionLifecycleStore and abnormal-exit recovery."""

from __future__ import annotations

import sqlite3
import time
from typing import TYPE_CHECKING

from js.persistence.lifecycle_store import SessionLifecycleStore

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


class _HeartbeatBeforeAbortConnection:
    def __init__(
        self,
        connection: sqlite3.Connection,
        heartbeat_connection: sqlite3.Connection,
        session_id: str,
        owner: str,
    ) -> None:
        self._connection = connection
        self._heartbeat_connection = heartbeat_connection
        self._session_id = session_id
        self._owner = owner
        self._triggered = False

    def execute(
        self,
        sql: str,
        parameters: tuple[object, ...] = (),
    ) -> sqlite3.Cursor:
        compact_sql = "".join(sql.casefold().split())
        if (
            not self._triggered
            and "updatesession_lifecycle" in compact_sql
            and "setstatus='aborted'" in compact_sql
        ):
            self._heartbeat_connection.execute(
                "UPDATE session_lifecycle SET last_heartbeat_at = ? "
                "WHERE session_id = ? AND owner_key_hash = ?",
                (time.time(), self._session_id, self._owner),
            )
            self._heartbeat_connection.commit()
            self._triggered = True
        return self._connection.execute(sql, parameters)

    def __enter__(self) -> _HeartbeatBeforeAbortConnection:
        self._connection.__enter__()
        return self

    def commit(self) -> None:
        self._connection.commit()

    def __exit__(self, *args: object) -> bool | None:
        return self._connection.__exit__(*args)


def _interleave_heartbeat_before_abort(
    store: SessionLifecycleStore,
    monkeypatch: pytest.MonkeyPatch,
    session_id: str,
    owner: str,
) -> sqlite3.Connection:
    heartbeat_connection = sqlite3.connect(store.db_path, check_same_thread=False)
    connection = _HeartbeatBeforeAbortConnection(
        store._conn(),
        heartbeat_connection,
        session_id,
        owner,
    )
    monkeypatch.setattr(store, "_conn", lambda: connection)
    return heartbeat_connection


def test_mark_started_and_completed(tmp_path):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("s1", "owner_a")
    row = store.get("s1", "owner_a")
    assert row is not None
    assert row["status"] == "running"
    assert row["owner_key_hash"] == "owner_a"

    store.mark_completed("s1", "done", "owner_a")
    row = store.get("s1", "owner_a")
    assert row["status"] == "completed"
    assert row["exit_reason"] == "done"
    assert row["completed_at"] is not None


def test_terminal_state_is_single_assignment_for_one_run(tmp_path: Path) -> None:
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("session", "owner", "run-1")

    store.mark_terminal("session", "completed", "done", "owner", "run-1")
    store.mark_terminal("session", "cancelled", "late cancel", "owner", "run-1")
    store.mark_aborted("session", "late recovery", "owner", "run-1")

    row = store.get("session", "owner")
    assert row is not None
    assert row["run_id"] == "run-1"
    assert row["status"] == "completed"
    assert row["exit_reason"] == "done"


def test_late_terminal_from_old_run_cannot_overwrite_new_run(tmp_path: Path) -> None:
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("session", "owner", "run-1")
    store.mark_terminal("session", "completed", "done", "owner", "run-1")
    store.mark_started("session", "owner", "run-2")

    store.mark_terminal("session", "error", "late failure", "owner", "run-1")
    store.heartbeat("session", "owner", "run-1")

    row = store.get("session", "owner")
    assert row is not None
    assert row["run_id"] == "run-2"
    assert row["status"] == "running"
    assert row["exit_reason"] == ""


def test_owner_isolation(tmp_path):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("s2", "owner_a")
    assert store.get("s2", "owner_a") is not None
    assert store.get("s2", "owner_b") is None
    # legacy/unscoped read normalizes to sentinel and still finds exact row
    # because owner_a != __legacy_local__
    row = store.get("s2")
    assert row is None  # sentinel does not match owner_a


def test_legacy_null_owner_backfill(tmp_path):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("s3", None)
    row = store.get("s3")
    assert row["owner_key_hash"] == "__legacy_local__"


def test_migrates_composite_owner_schema_without_run_id(tmp_path: Path) -> None:
    db_path = tmp_path / "lifecycle.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE session_lifecycle (
                session_id TEXT NOT NULL,
                owner_key_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                completed_at REAL,
                exit_reason TEXT,
                status TEXT NOT NULL DEFAULT 'running',
                last_heartbeat_at REAL NOT NULL,
                PRIMARY KEY (session_id, owner_key_hash)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO session_lifecycle
            (session_id, owner_key_hash, created_at, completed_at, exit_reason,
             status, last_heartbeat_at)
            VALUES ('legacy', 'owner', 1.0, NULL, NULL, 'running', 1.0)
            """
        )

    store = SessionLifecycleStore(db_path)

    legacy = store.get("legacy", "owner")
    assert legacy is not None
    assert legacy["run_id"] == ""
    store.mark_started("new", "owner", "run-new")
    assert store.get("new", "owner")["run_id"] == "run-new"


def test_migrates_single_primary_key_schema_without_run_id(tmp_path: Path) -> None:
    db_path = tmp_path / "lifecycle.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE session_lifecycle (
                session_id TEXT PRIMARY KEY,
                owner_key_hash TEXT,
                created_at REAL NOT NULL,
                completed_at REAL,
                exit_reason TEXT,
                status TEXT NOT NULL DEFAULT 'running',
                last_heartbeat_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO session_lifecycle
            (session_id, owner_key_hash, created_at, completed_at, exit_reason,
             status, last_heartbeat_at)
            VALUES ('legacy', NULL, 1.0, NULL, NULL, 'running', 1.0)
            """
        )

    store = SessionLifecycleStore(db_path)

    legacy = store.get("legacy")
    assert legacy is not None
    assert legacy["owner_key_hash"] == "__legacy_local__"
    assert legacy["run_id"] == ""
    store.mark_started("legacy", "other-owner", "run-2")
    assert store.get("legacy", "other-owner")["run_id"] == "run-2"


def test_same_session_id_different_owners(tmp_path):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("same_session", "owner_a")
    store.mark_started("same_session", "owner_b")
    row_a = store.get("same_session", "owner_a")
    row_b = store.get("same_session", "owner_b")
    assert row_a is not None
    assert row_b is not None
    assert row_a["owner_key_hash"] == "owner_a"
    assert row_b["owner_key_hash"] == "owner_b"


def test_mark_completed_does_not_affect_other_owner(tmp_path):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("s_comp", "owner_a")
    store.mark_started("s_comp", "owner_b")
    store.mark_completed("s_comp", "done", "owner_a")
    assert store.get("s_comp", "owner_a")["status"] == "completed"
    assert store.get("s_comp", "owner_b")["status"] == "running"


def test_heartbeat_does_not_affect_other_owner(tmp_path):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("s_hb", "owner_a")
    store.mark_started("s_hb", "owner_b")
    old_a = store.get("s_hb", "owner_a")["last_heartbeat_at"]
    old_b = store.get("s_hb", "owner_b")["last_heartbeat_at"]
    time.sleep(0.05)
    store.heartbeat("s_hb", "owner_a")
    new_a = store.get("s_hb", "owner_a")["last_heartbeat_at"]
    new_b = store.get("s_hb", "owner_b")["last_heartbeat_at"]
    assert new_a > old_a
    assert new_b == old_b


def test_mark_aborted_does_not_affect_other_owner(tmp_path):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("s_ab", "owner_a")
    store.mark_started("s_ab", "owner_b")
    store.mark_aborted("s_ab", "fail", "owner_a")
    assert store.get("s_ab", "owner_a")["status"] == "aborted"
    assert store.get("s_ab", "owner_b")["status"] == "running"


def test_list_active(tmp_path):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("s4", "owner_a")
    store.mark_started("s5", "owner_b")
    store.mark_completed("s4", "done", "owner_a")

    active_a = store.list_active("owner_a")
    assert [r["session_id"] for r in active_a] == []

    active_b = store.list_active("owner_b")
    assert [r["session_id"] for r in active_b] == ["s5"]


def test_list_active_none_does_not_leak_authenticated_owners(tmp_path):
    """list_active(None) must NOT return rows from authenticated owners."""
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("s_auth_a", "owner_a")
    store.mark_started("s_auth_b", "owner_b")

    leaked = store.list_active(None)
    assert [r["session_id"] for r in leaked] == []

    # Default arg (no owner) is treated as legacy-local, also empty here.
    assert [r["session_id"] for r in store.list_active()] == []


def test_recover_aborted_sessions(tmp_path):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("stale", "owner_a")
    # Simulate old heartbeat
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "lifecycle.db"), check_same_thread=False)
    conn.execute(
        "UPDATE session_lifecycle SET last_heartbeat_at = ? WHERE session_id = ? AND owner_key_hash = ?",
        (time.time() - 1000, "stale", "owner_a"),
    )
    conn.commit()
    conn.close()

    store.mark_started("fresh", "owner_a")

    recovered = store.recover_aborted_sessions(threshold_seconds=300, owner_key_hash="owner_a")
    assert recovered == ["stale"]

    stale = store.get("stale", "owner_a")
    assert stale["status"] == "aborted"
    assert "abnormal_exit" in stale["exit_reason"]

    fresh = store.get("fresh", "owner_a")
    assert fresh["status"] == "running"


def test_recover_aborted_sessions_scoped_by_owner(tmp_path):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("stale_a", "owner_a")
    store.mark_started("stale_b", "owner_b")
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "lifecycle.db"), check_same_thread=False)
    conn.execute(
        "UPDATE session_lifecycle SET last_heartbeat_at = ? WHERE session_id = ? AND owner_key_hash = ?",
        (time.time() - 1000, "stale_a", "owner_a"),
    )
    conn.execute(
        "UPDATE session_lifecycle SET last_heartbeat_at = ? WHERE session_id = ? AND owner_key_hash = ?",
        (time.time() - 1000, "stale_b", "owner_b"),
    )
    conn.commit()
    conn.close()

    recovered_a = store.recover_aborted_sessions(threshold_seconds=300, owner_key_hash="owner_a")
    assert recovered_a == ["stale_a"]
    assert store.get("stale_a", "owner_a")["status"] == "aborted"
    assert store.get("stale_b", "owner_b")["status"] == "running"


def test_owner_recovery_does_not_overwrite_interleaved_heartbeat(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("shared", "owner_a")
    store.mark_started("shared", "owner_b")
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "UPDATE session_lifecycle SET last_heartbeat_at = ? WHERE session_id = ?",
            (time.time() - 1_000, "shared"),
        )

    heartbeat_connection = _interleave_heartbeat_before_abort(
        store,
        monkeypatch,
        "shared",
        "owner_a",
    )
    try:
        recovered = store.recover_aborted_sessions(
            threshold_seconds=300,
            owner_key_hash="owner_a",
        )
    finally:
        heartbeat_connection.close()

    assert recovered == []
    assert store.get("shared", "owner_a")["status"] == "running"
    assert store.get("shared", "owner_b")["status"] == "running"


def test_recover_all_aborted_sessions_sweeps_every_owner(tmp_path):
    """Startup recovery must mark stale rows across ALL owners, not just legacy-local.

    Regression for v0.1.4-alpha P1: ``Agent.__init__`` originally called
    ``recover_aborted_sessions()`` with no owner, which sentinel-normalized to
    ``__legacy_local__`` and left every authenticated owner's stale ``running``
    row stuck forever. The new ``recover_all_aborted_sessions`` API is the only
    cross-owner write path and is the one wired into startup.
    """
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("legacy_stale", None)  # __legacy_local__
    store.mark_started("auth_stale_a", "owner_a")
    store.mark_started("auth_stale_b", "owner_b")
    store.mark_started("auth_fresh_c", "owner_c")  # heartbeat stays fresh

    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "lifecycle.db"), check_same_thread=False)
    cutoff = time.time() - 1000
    for sid, owner in (
        ("legacy_stale", "__legacy_local__"),
        ("auth_stale_a", "owner_a"),
        ("auth_stale_b", "owner_b"),
    ):
        conn.execute(
            "UPDATE session_lifecycle SET last_heartbeat_at = ? "
            "WHERE session_id = ? AND owner_key_hash = ?",
            (cutoff, sid, owner),
        )
    conn.commit()
    conn.close()

    recovered = store.recover_all_aborted_sessions(threshold_seconds=300)
    assert sorted(recovered) == sorted(
        [
            ("legacy_stale", "__legacy_local__"),
            ("auth_stale_a", "owner_a"),
            ("auth_stale_b", "owner_b"),
        ]
    )

    # All three stale rows flipped to aborted with the expected exit_reason,
    # regardless of owner; the fresh row is untouched.
    for sid, owner in (
        ("legacy_stale", "__legacy_local__"),
        ("auth_stale_a", "owner_a"),
        ("auth_stale_b", "owner_b"),
    ):
        row = store.get(sid, owner)
        assert row is not None
        assert row["status"] == "aborted"
        assert row["exit_reason"] == "abnormal_exit_recovery"
    fresh = store.get("auth_fresh_c", "owner_c")
    assert fresh is not None
    assert fresh["status"] == "running"


def test_recover_all_aborted_sessions_ignores_fresh_heartbeats(tmp_path):
    """The all-owner sweep must respect the heartbeat threshold."""
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("fresh_a", "owner_a")
    store.mark_started("fresh_b", "owner_b")

    recovered = store.recover_all_aborted_sessions(threshold_seconds=300)
    assert recovered == []
    assert store.get("fresh_a", "owner_a")["status"] == "running"
    assert store.get("fresh_b", "owner_b")["status"] == "running"


def test_all_owner_recovery_reports_only_atomic_updates_after_interleaved_heartbeat(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    store.mark_started("shared", "owner_a")
    store.mark_started("shared", "owner_b")
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "UPDATE session_lifecycle SET last_heartbeat_at = ? WHERE session_id = ?",
            (time.time() - 1_000, "shared"),
        )

    heartbeat_connection = _interleave_heartbeat_before_abort(
        store,
        monkeypatch,
        "shared",
        "owner_a",
    )
    try:
        recovered = store.recover_all_aborted_sessions(threshold_seconds=300)
    finally:
        heartbeat_connection.close()

    assert recovered == [("shared", "owner_b")]
    assert store.get("shared", "owner_a")["status"] == "running"
    assert store.get("shared", "owner_b")["status"] == "aborted"
