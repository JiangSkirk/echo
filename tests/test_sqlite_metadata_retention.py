"""Retention tests for long-lived SQLite metadata stores."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from js.persistence.lifecycle_store import SessionLifecycleStore
from js.persistence.review_store import ReviewCapsule, ReviewStore
from js.runtime.governor import ResourceGovernor
from js.web.stats_store import TokenStatsStore


def _set_lifecycle_timestamp(
    store: SessionLifecycleStore,
    session_id: str,
    owner: str,
    timestamp: float,
) -> None:
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            """
            UPDATE session_lifecycle
            SET created_at = ?, completed_at = CASE WHEN status = 'running' THEN NULL ELSE ? END,
                last_heartbeat_at = ?
            WHERE session_id = ? AND owner_key_hash = ?
            """,
            (timestamp, timestamp, timestamp, session_id, owner),
        )


def _add_lifecycle_row(
    store: SessionLifecycleStore,
    session_id: str,
    owner: str,
    status: str,
    timestamp: float,
) -> None:
    store.mark_started(session_id, owner)
    if status == "completed":
        store.mark_completed(session_id, owner_key_hash=owner)
    elif status == "aborted":
        store.mark_aborted(session_id, "test", owner)
    elif status != "running":
        with sqlite3.connect(store.db_path) as conn:
            conn.execute(
                """
                UPDATE session_lifecycle
                SET status = ?
                WHERE session_id = ? AND owner_key_hash = ?
                """,
                (status, session_id, owner),
            )
    _set_lifecycle_timestamp(store, session_id, owner, timestamp)


def _capsule(key: str, owner: str, created_at: float) -> ReviewCapsule:
    return ReviewCapsule(
        session_id=f"session-{key}",
        run_id=f"run-{key}",
        first_user_message=key,
        last_assistant_message="done",
        tools_used=[],
        total_tokens=1,
        turn_count=1,
        status="completed",
        error_message="",
        owner_key_hash=owner,
        created_at=created_at,
    )


@pytest.mark.parametrize(
    "store_type",
    [SessionLifecycleStore, ReviewStore],
    ids=["lifecycle", "review"],
)
def test_store_construction_does_not_replace_locked_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    store_type: type[SessionLifecycleStore] | type[ReviewStore],
) -> None:
    db_path = tmp_path / "metadata.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE lock_sentinel (value TEXT NOT NULL)")
        conn.execute("INSERT INTO lock_sentinel VALUES ('preserved')")

    original_inode = db_path.stat().st_ino
    locking_conn = sqlite3.connect(db_path, timeout=0.01)
    locking_conn.execute("BEGIN EXCLUSIVE")
    locking_conn.execute("UPDATE lock_sentinel SET value = 'locked'")

    real_connect = sqlite3.connect

    def fast_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        kwargs.setdefault("timeout", 0.01)
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", fast_connect)
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            store_type(db_path)
        assert db_path.stat().st_ino == original_inode
    finally:
        locking_conn.rollback()
        locking_conn.close()

    with real_connect(db_path) as conn:
        value = conn.execute("SELECT value FROM lock_sentinel").fetchone()[0]
    assert value == "preserved"


@pytest.mark.parametrize(
    "store_type",
    [SessionLifecycleStore, ReviewStore],
    ids=["lifecycle", "review"],
)
def test_store_quarantines_not_a_database_before_recovery(
    tmp_path: Path,
    store_type: type[SessionLifecycleStore] | type[ReviewStore],
) -> None:
    db_path = tmp_path / "metadata.db"
    corrupt_bytes = b"this is explicitly not a sqlite database"
    db_path.write_bytes(corrupt_bytes)

    store_type(db_path)

    quarantined = list(tmp_path.glob("metadata.db.corrupt-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == corrupt_bytes
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_lifecycle_prune_deletes_all_old_terminal_statuses(tmp_path: Path) -> None:
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    old = time.time() - 91 * 86_400
    for status in ("completed", "aborted", "running", "cancelled", "error"):
        _add_lifecycle_row(store, status, "owner-a", status, old)

    deleted = store.prune(retention_days=90, max_per_owner=100)

    assert deleted == 4
    for deleted_status in ("completed", "aborted", "cancelled", "error"):
        assert store.get(deleted_status, "owner-a") is None
    assert store.get("running", "owner-a") is not None


def test_lifecycle_prune_applies_terminal_cap_per_owner_and_never_counts_running(
    tmp_path: Path,
) -> None:
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    now = time.time()
    for index, (age, status) in enumerate(((30, "completed"), (20, "cancelled"), (10, "error"))):
        _add_lifecycle_row(store, f"a-{index}", "owner-a", status, now - age)
    for index, (age, status) in enumerate(((25, "aborted"), (15, "error"))):
        _add_lifecycle_row(store, f"b-{index}", "owner-b", status, now - age)
    _add_lifecycle_row(store, "a-running", "owner-a", "running", now - 1_000)

    deleted = store.prune(retention_days=3_650, max_per_owner=2)

    assert deleted == 1
    assert store.get("a-0", "owner-a") is None
    assert store.get("a-1", "owner-a") is not None
    assert store.get("a-2", "owner-a") is not None
    running = store.get("a-running", "owner-a")
    assert running is not None
    assert running["status"] == "running"
    assert store.get("b-0", "owner-b") is not None
    assert store.get("b-1", "owner-b") is not None


def test_lifecycle_exposes_all_running_pairs_for_internal_maintenance(
    tmp_path: Path,
) -> None:
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    _add_lifecycle_row(store, "running-a", "owner-a", "running", time.time())
    _add_lifecycle_row(store, "running-b", "owner-b", "running", time.time())
    _add_lifecycle_row(store, "completed", "owner-a", "completed", time.time())

    assert store.running_pairs_for_maintenance() == {
        ("owner-a", "running-a"),
        ("owner-b", "running-b"),
    }


def test_lifecycle_prune_applies_global_terminal_cap_without_counting_running(
    tmp_path: Path,
) -> None:
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    now = time.time()
    for session_id, owner, status, age in (
        ("a-old", "owner-a", "completed", 40),
        ("b-old", "owner-b", "cancelled", 30),
        ("a-new", "owner-a", "error", 20),
        ("b-new", "owner-b", "aborted", 10),
    ):
        _add_lifecycle_row(store, session_id, owner, status, now - age)
    _add_lifecycle_row(store, "old-running", "owner-c", "running", now - 1_000)

    deleted = store.prune(retention_days=3_650, max_per_owner=10, max_total=3)

    assert deleted == 1
    assert store.get("a-old", "owner-a") is None
    assert store.get("b-old", "owner-b") is not None
    assert store.get("a-new", "owner-a") is not None
    assert store.get("b-new", "owner-b") is not None
    running = store.get("old-running", "owner-c")
    assert running is not None
    assert running["status"] == "running"


def test_lifecycle_prune_rolls_back_age_deletion_when_cap_deletion_fails(
    tmp_path: Path,
) -> None:
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    now = time.time()
    _add_lifecycle_row(store, "old-by-age", "owner-a", "completed", now - 91 * 86_400)
    _add_lifecycle_row(store, "cap-old", "owner-a", "completed", now - 2)
    _add_lifecycle_row(store, "cap-new", "owner-a", "completed", now - 1)
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            """
            CREATE TRIGGER fail_lifecycle_cap_delete
            BEFORE DELETE ON session_lifecycle
            WHEN OLD.session_id = 'cap-old'
            BEGIN
                SELECT RAISE(ABORT, 'blocked lifecycle delete');
            END
            """
        )

    with pytest.raises(sqlite3.DatabaseError, match="blocked lifecycle delete"):
        store.prune(retention_days=90, max_per_owner=1)

    assert store.get("old-by-age", "owner-a") is not None
    assert store.get("cap-old", "owner-a") is not None
    assert store.get("cap-new", "owner-a") is not None


def test_lifecycle_prune_rolls_back_per_owner_deletion_when_global_deletion_fails(
    tmp_path: Path,
) -> None:
    store = SessionLifecycleStore(tmp_path / "lifecycle.db")
    now = time.time()
    rows = (
        ("a-old", "owner-a", "completed", now - 5),
        ("b-old", "owner-b", "aborted", now - 4),
        ("b-new", "owner-b", "aborted", now - 3),
        ("a-mid", "owner-a", "completed", now - 2),
        ("a-new", "owner-a", "completed", now - 1),
    )
    for session_id, owner, status, timestamp in rows:
        _add_lifecycle_row(store, session_id, owner, status, timestamp)
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            """
            CREATE TRIGGER fail_lifecycle_global_delete
            BEFORE DELETE ON session_lifecycle
            WHEN OLD.session_id = 'b-old'
            BEGIN
                SELECT RAISE(ABORT, 'blocked lifecycle global delete');
            END
            """
        )

    with pytest.raises(sqlite3.DatabaseError, match="blocked lifecycle global delete"):
        store.prune(retention_days=3_650, max_per_owner=2, max_total=3)

    for session_id, owner, _status, _timestamp in rows:
        assert store.get(session_id, owner) is not None


def test_review_prune_enforces_per_owner_cap_by_deleting_each_owners_oldest(
    tmp_path: Path,
) -> None:
    store = ReviewStore(tmp_path / "review.db")
    for key, owner, created_at in (
        ("a-old", "owner-a", 1.0),
        ("b-old", "owner-b", 2.0),
        ("b-mid", "owner-b", 3.0),
        ("a-mid", "owner-a", 4.0),
        ("a-new", "owner-a", 5.0),
        ("b-new", "owner-b", 6.0),
    ):
        store.store(_capsule(key, owner, created_at))

    deleted = store.prune(max_per_owner=2, max_total=100)

    assert deleted == 2
    assert store.get("session-a-old", "run-a-old", "owner-a") is None
    assert store.get("session-b-old", "run-b-old", "owner-b") is None
    assert [capsule.run_id for capsule in store.list_recent("owner-a", limit=10)] == [
        "run-a-new",
        "run-a-mid",
    ]
    assert [capsule.run_id for capsule in store.list_recent("owner-b", limit=10)] == [
        "run-b-new",
        "run-b-mid",
    ]


def test_review_prune_enforces_global_cap_by_deleting_globally_oldest(
    tmp_path: Path,
) -> None:
    store = ReviewStore(tmp_path / "review.db")
    for key, owner, created_at in (
        ("a-old", "owner-a", 1.0),
        ("b-old", "owner-b", 2.0),
        ("b-mid", "owner-b", 3.0),
        ("a-mid", "owner-a", 4.0),
        ("a-new", "owner-a", 5.0),
        ("b-new", "owner-b", 6.0),
    ):
        store.store(_capsule(key, owner, created_at))

    deleted = store.prune(max_per_owner=10, max_total=3)

    assert deleted == 3
    assert store.get("session-a-old", "run-a-old", "owner-a") is None
    assert store.get("session-b-old", "run-b-old", "owner-b") is None
    assert store.get("session-b-mid", "run-b-mid", "owner-b") is None
    assert store.get("session-a-mid", "run-a-mid", "owner-a") is not None
    assert store.get("session-a-new", "run-a-new", "owner-a") is not None
    assert store.get("session-b-new", "run-b-new", "owner-b") is not None


def test_review_prune_rolls_back_owner_deletion_when_global_deletion_fails(
    tmp_path: Path,
) -> None:
    store = ReviewStore(tmp_path / "review.db")
    rows = (
        ("a-old", "owner-a", 1.0),
        ("b-old", "owner-b", 2.0),
        ("b-mid", "owner-b", 3.0),
        ("b-new", "owner-b", 4.0),
        ("a-mid", "owner-a", 5.0),
        ("a-newer", "owner-a", 6.0),
        ("a-new", "owner-a", 7.0),
    )
    for key, owner, created_at in rows:
        store.store(_capsule(key, owner, created_at))
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            """
            CREATE TRIGGER fail_review_global_delete
            BEFORE DELETE ON review_capsules
            WHEN OLD.run_id = 'run-b-old'
            BEGIN
                SELECT RAISE(ABORT, 'blocked review delete');
            END
            """
        )

    with pytest.raises(sqlite3.DatabaseError, match="blocked review delete"):
        store.prune(max_per_owner=3, max_total=5)

    for key, owner, _created_at in rows:
        assert store.get(f"session-{key}", f"run-{key}", owner) is not None


def test_token_stats_prune_is_transactional(tmp_path: Path) -> None:
    store = TokenStatsStore(tmp_path)
    store.record("model", "provider", 1, 1, run_id="old-1")
    store.record("model", "provider", 1, 1, run_id="old-2")
    with sqlite3.connect(store.db_path) as conn:
        conn.execute("UPDATE token_usage SET timestamp = ?", (time.time() - 2 * 86_400,))
        conn.execute(
            """
            CREATE TRIGGER fail_token_stats_delete
            BEFORE DELETE ON token_usage
            WHEN OLD.run_id = 'old-2'
            BEGIN
                SELECT RAISE(ABORT, 'blocked token stats delete');
            END
            """
        )

    with pytest.raises(sqlite3.DatabaseError, match="blocked token stats delete"):
        store.prune(days=1)

    with sqlite3.connect(store.db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM token_usage").fetchone()[0]
    assert count == 2


def test_token_stats_prune_applies_age_then_global_row_cap(tmp_path: Path) -> None:
    store = TokenStatsStore(tmp_path)
    run_ids = ("old-by-age", "recent-1", "recent-2", "recent-3", "recent-4", "recent-5")
    for run_id in run_ids:
        store.record("model", "provider", 1, 1, run_id=run_id)
    now = time.time()
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "UPDATE token_usage SET timestamp = ? WHERE run_id = ?",
            (now - 91 * 86_400, "old-by-age"),
        )
        for age, run_id in enumerate(run_ids[1:], start=1):
            conn.execute(
                "UPDATE token_usage SET timestamp = ? WHERE run_id = ?",
                (now - (6 - age), run_id),
            )

    deleted = store.prune(days=90, max_rows=3)

    assert deleted == 3
    with sqlite3.connect(store.db_path) as conn:
        remaining = conn.execute(
            "SELECT run_id FROM token_usage ORDER BY timestamp ASC, id ASC"
        ).fetchall()
    assert [row[0] for row in remaining] == ["recent-3", "recent-4", "recent-5"]


def test_high_write_metadata_defaults_retain_only_one_thousand_recent_rows(
    tmp_path: Path,
) -> None:
    lifecycle = SessionLifecycleStore(tmp_path / "lifecycle.db")
    review = ReviewStore(tmp_path / "review.db")
    stats = TokenStatsStore(tmp_path)
    now = time.time()
    row_count = 1_025

    with sqlite3.connect(lifecycle.db_path) as conn:
        conn.executemany(
            """
            INSERT INTO session_lifecycle
            (session_id, owner_key_hash, run_id, created_at, completed_at,
             exit_reason, status, last_heartbeat_at)
            VALUES (?, 'owner-a', ?, ?, ?, 'completed', 'completed', ?)
            """,
            (
                (f"session-{index}", f"run-{index}", now + index, now + index, now + index)
                for index in range(row_count)
            ),
        )
    with sqlite3.connect(review.db_path) as conn:
        conn.executemany(
            """
            INSERT INTO review_capsules
            (session_id, run_id, owner_key_hash, first_user_message,
             last_assistant_message, tools_used, total_tokens, turn_count,
             status, error_message, created_at)
            VALUES (?, ?, 'owner-a', '', '', '[]', 0, 1, 'completed', '', ?)
            """,
            ((f"session-{index}", f"run-{index}", now + index) for index in range(row_count)),
        )
    with sqlite3.connect(stats.db_path) as conn:
        conn.executemany(
            """
            INSERT INTO token_usage
            (session_id, run_id, model, provider, prompt_tokens,
             completion_tokens, total_tokens, cost, cached_tokens, timestamp)
            VALUES (?, ?, 'model', 'provider', 1, 1, 2, 0.0, 0, ?)
            """,
            ((f"session-{index}", f"run-{index}", now + index) for index in range(row_count)),
        )

    assert lifecycle.prune() == 25
    assert review.prune() == 25
    assert stats.prune() == 0

    for db_path, table, retained in (
        (lifecycle.db_path, "session_lifecycle", 1_000),
        (review.db_path, "review_capsules", 1_000),
        (stats.db_path, "token_usage", row_count),
    ):
        with sqlite3.connect(db_path) as conn:
            assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == retained


def test_token_stats_prune_rolls_back_age_deletion_when_row_cap_deletion_fails(
    tmp_path: Path,
) -> None:
    store = TokenStatsStore(tmp_path)
    for run_id in ("old-by-age", "cap-old", "cap-new"):
        store.record("model", "provider", 1, 1, run_id=run_id)
    now = time.time()
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "UPDATE token_usage SET timestamp = ? WHERE run_id = ?",
            (now - 91 * 86_400, "old-by-age"),
        )
        conn.execute(
            "UPDATE token_usage SET timestamp = ? WHERE run_id = ?",
            (now - 2, "cap-old"),
        )
        conn.execute(
            "UPDATE token_usage SET timestamp = ? WHERE run_id = ?",
            (now - 1, "cap-new"),
        )
        conn.execute(
            """
            CREATE TRIGGER fail_token_stats_cap_delete
            BEFORE DELETE ON token_usage
            WHEN OLD.run_id = 'cap-old'
            BEGIN
                SELECT RAISE(ABORT, 'blocked token stats cap delete');
            END
            """
        )

    with pytest.raises(sqlite3.DatabaseError, match="blocked token stats cap delete"):
        store.prune(days=90, max_rows=1)

    with sqlite3.connect(store.db_path) as conn:
        remaining = conn.execute("SELECT run_id FROM token_usage ORDER BY id").fetchall()
    assert [row[0] for row in remaining] == ["old-by-age", "cap-old", "cap-new"]


@pytest.mark.asyncio
async def test_governor_prunes_metadata_stores_and_continues_after_failures(
    tmp_path: Path,
) -> None:
    lifecycle = MagicMock()
    lifecycle.prune.side_effect = RuntimeError("lifecycle unavailable")
    review = MagicMock()
    review.prune.return_value = 2
    agent = SimpleNamespace(
        _state_store=None,
        lifecycle_store=lifecycle,
        review_store=review,
        audit=None,
        memory=None,
    )
    governor = ResourceGovernor(agent, state_dir=tmp_path)
    checkpoint = AsyncMock()
    governor._checkpoint_wal = checkpoint  # type: ignore[method-assign]

    with patch("js.web.stats_store.TokenStatsStore") as stats_store_type:
        stats_store = stats_store_type.return_value
        stats_store.prune.side_effect = RuntimeError("stats unavailable")

        await governor._prune_databases()

    lifecycle.prune.assert_called_once_with()
    review.prune.assert_called_once_with()
    stats_store_type.assert_called_once_with(tmp_path)
    stats_store.prune.assert_called_once_with()
    checkpoint.assert_awaited_once_with(force=True)
