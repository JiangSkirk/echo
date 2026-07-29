"""Bounded-retention tests for session-scoped enhanced memory."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from js.config import MemoryConfig
from js.memory.enhanced_store import EnhancedMemoryStore
from js.persistence.lifecycle_store import SessionLifecycleStore
from js.runtime.governor import ResourceGovernor

_SESSION_TABLES = (
    "session_messages",
    "episodes",
    "working_memories",
    "session_capsules",
)


@pytest.fixture
def store(tmp_path: Path) -> EnhancedMemoryStore:
    return EnhancedMemoryStore(tmp_path / "state", MemoryConfig())


def _seed_complete_session(
    store: EnhancedMemoryStore,
    owner: str,
    session_id: str,
    *,
    message_at: float,
    episode_at: float | None = None,
    working_at: float | None = None,
    capsule_at: float | None = None,
) -> None:
    episode_at = message_at if episode_at is None else episode_at
    working_at = message_at if working_at is None else working_at
    capsule_at = message_at if capsule_at is None else capsule_at
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            """
            INSERT INTO session_messages
                (session_id, role, content, created_at, owner_key_hash)
            VALUES (?, 'user', 'message', ?, ?)
            """,
            (session_id, message_at, owner),
        )
        conn.execute(
            """
            INSERT INTO episodes
                (session_id, summary, topics, created_at, owner_key_hash)
            VALUES (?, 'summary', '[]', ?, ?)
            """,
            (session_id, episode_at, owner),
        )
        conn.execute(
            """
            INSERT INTO working_memories
                (session_id, key, value, created_at, last_accessed, owner_key_hash)
            VALUES (?, 'context', 'value', ?, ?, ?)
            """,
            (session_id, working_at, working_at, owner),
        )
        conn.execute(
            """
            INSERT INTO session_capsules
                (session_id, capsule_text, updated_at, last_accessed, owner_key_hash)
            VALUES (?, 'capsule', ?, ?, ?)
            """,
            (session_id, capsule_at, capsule_at, owner),
        )


def _row_counts(
    store: EnhancedMemoryStore,
    owner: str,
    session_id: str,
) -> dict[str, int]:
    with sqlite3.connect(store.db_path) as conn:
        return {
            table: int(
                conn.execute(
                    f"SELECT COUNT(*) FROM {table} "
                    "WHERE owner_key_hash = ? AND session_id = ?",
                    (owner, session_id),
                ).fetchone()[0]
            )
            for table in _SESSION_TABLES
        }


def test_maintenance_enforces_owner_limit_and_deletes_all_session_tables(
    store: EnhancedMemoryStore,
) -> None:
    _seed_complete_session(store, "owner-a", "shared", message_at=10)
    _seed_complete_session(store, "owner-a", "a-recent", message_at=30)
    _seed_complete_session(store, "owner-b", "shared", message_at=20)

    deleted = store.maintain_session_bounds(
        max_sessions_per_owner=1,
        max_sessions_global=10,
    )

    assert deleted == 1
    assert _row_counts(store, "owner-a", "shared") == dict.fromkeys(_SESSION_TABLES, 0)
    assert _row_counts(store, "owner-a", "a-recent") == dict.fromkeys(_SESSION_TABLES, 1)
    assert _row_counts(store, "owner-b", "shared") == dict.fromkeys(_SESSION_TABLES, 1)


def test_maintenance_uses_latest_activity_across_all_session_tables(
    store: EnhancedMemoryStore,
) -> None:
    _seed_complete_session(
        store,
        "owner-a",
        "capsule-recent",
        message_at=10,
        episode_at=10,
        working_at=10,
        capsule_at=100,
    )
    _seed_complete_session(store, "owner-a", "uniformly-older", message_at=50)

    deleted = store.maintain_session_bounds(
        max_sessions_per_owner=1,
        max_sessions_global=10,
    )

    assert deleted == 1
    assert _row_counts(store, "owner-a", "capsule-recent") == dict.fromkeys(
        _SESSION_TABLES, 1
    )
    assert _row_counts(store, "owner-a", "uniformly-older") == dict.fromkeys(
        _SESSION_TABLES, 0
    )


def test_maintenance_enforces_global_limit_after_owner_limits(
    store: EnhancedMemoryStore,
) -> None:
    _seed_complete_session(store, "owner-a", "global-oldest", message_at=10)
    _seed_complete_session(store, "owner-a", "a-recent", message_at=30)
    _seed_complete_session(store, "owner-b", "b-recent", message_at=20)

    deleted = store.maintain_session_bounds(
        max_sessions_per_owner=10,
        max_sessions_global=2,
    )

    assert deleted == 1
    assert _row_counts(store, "owner-a", "global-oldest") == dict.fromkeys(
        _SESSION_TABLES, 0
    )
    assert _row_counts(store, "owner-a", "a-recent") == dict.fromkeys(_SESSION_TABLES, 1)
    assert _row_counts(store, "owner-b", "b-recent") == dict.fromkeys(_SESSION_TABLES, 1)


def test_maintenance_never_deletes_protected_sessions(store: EnhancedMemoryStore) -> None:
    _seed_complete_session(store, "owner-a", "running", message_at=10)
    _seed_complete_session(store, "owner-a", "middle", message_at=20)
    _seed_complete_session(store, "owner-a", "recent", message_at=30)

    deleted = store.maintain_session_bounds(
        max_sessions_per_owner=2,
        max_sessions_global=1,
        protected_sessions={("owner-a", "running")},
    )

    assert deleted == 2
    assert _row_counts(store, "owner-a", "running") == dict.fromkeys(_SESSION_TABLES, 1)
    assert _row_counts(store, "owner-a", "middle") == dict.fromkeys(_SESSION_TABLES, 0)
    assert _row_counts(store, "owner-a", "recent") == dict.fromkeys(_SESSION_TABLES, 0)


def test_maintenance_rolls_back_entire_batch_on_delete_failure(
    store: EnhancedMemoryStore,
) -> None:
    _seed_complete_session(store, "owner-a", "first", message_at=10)
    _seed_complete_session(store, "owner-a", "fail", message_at=20)
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            """
            CREATE TRIGGER fail_episode_delete
            BEFORE DELETE ON episodes
            WHEN OLD.session_id = 'fail' AND OLD.owner_key_hash = 'owner-a'
            BEGIN
                SELECT RAISE(ABORT, 'forced session delete failure');
            END
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="forced session delete failure"):
        store.maintain_session_bounds(
            max_sessions_per_owner=0,
            max_sessions_global=0,
        )

    assert _row_counts(store, "owner-a", "first") == dict.fromkeys(_SESSION_TABLES, 1)
    assert _row_counts(store, "owner-a", "fail") == dict.fromkeys(_SESSION_TABLES, 1)


@pytest.mark.parametrize(
    ("max_sessions_per_owner", "max_sessions_global"),
    [(-1, 10), (10, -1)],
)
def test_maintenance_rejects_negative_limits(
    store: EnhancedMemoryStore,
    max_sessions_per_owner: int,
    max_sessions_global: int,
) -> None:
    with pytest.raises(ValueError, match="must be non-negative"):
        store.maintain_session_bounds(
            max_sessions_per_owner=max_sessions_per_owner,
            max_sessions_global=max_sessions_global,
        )


@pytest.mark.asyncio
async def test_governor_passes_running_session_pairs_to_memory_maintenance(
    tmp_path: Path,
) -> None:
    lifecycle = MagicMock()
    lifecycle.running_pairs_for_maintenance.return_value = {("owner-a", "running")}
    lifecycle.prune.return_value = 0
    enhanced = MagicMock()
    enhanced.maintain_session_bounds.return_value = 2
    enhanced._evict_semantic_if_needed.return_value = 0
    memory = SimpleNamespace(cleanup_empty_sessions=lambda: 0, enhanced=enhanced)
    agent = SimpleNamespace(
        _state_store=None,
        event_store=None,
        audit=None,
        memory=memory,
        lifecycle_store=lifecycle,
        review_store=None,
    )
    governor = ResourceGovernor(agent, state_dir=None)

    await governor._prune_databases()

    enhanced.maintain_session_bounds.assert_called_once_with(
        protected_sessions={("owner-a", "running")}
    )


@pytest.mark.asyncio
async def test_governor_recovers_stale_running_before_collecting_protected_pairs(
    tmp_path: Path,
) -> None:
    lifecycle = SessionLifecycleStore(tmp_path / "lifecycle.db")
    lifecycle.mark_started("shared-session", "owner-stale")
    lifecycle.mark_started("shared-session", "owner-fresh")
    with sqlite3.connect(lifecycle.db_path) as conn:
        conn.execute(
            "UPDATE session_lifecycle SET last_heartbeat_at = ? "
            "WHERE session_id = ? AND owner_key_hash = ?",
            (time.time() - 301, "shared-session", "owner-stale"),
        )

    enhanced = MagicMock()
    enhanced.maintain_session_bounds.return_value = 0
    enhanced._evict_semantic_if_needed.return_value = 0
    memory = SimpleNamespace(cleanup_empty_sessions=lambda: 0, enhanced=enhanced)
    agent = SimpleNamespace(
        _state_store=None,
        event_store=None,
        audit=None,
        memory=memory,
        lifecycle_store=lifecycle,
        review_store=None,
    )

    await ResourceGovernor(agent, state_dir=None)._prune_databases()

    stale = lifecycle.get("shared-session", "owner-stale")
    fresh = lifecycle.get("shared-session", "owner-fresh")
    assert stale is not None
    assert stale["status"] == "aborted"
    assert fresh is not None
    assert fresh["status"] == "running"
    enhanced.maintain_session_bounds.assert_called_once_with(
        protected_sessions={("owner-fresh", "shared-session")}
    )


@pytest.mark.parametrize("failed_operation", ["recovery", "empty_cleanup", "session_bounds"])
@pytest.mark.asyncio
async def test_governor_isolates_each_memory_maintenance_failure(
    failed_operation: str,
) -> None:
    lifecycle = MagicMock()
    lifecycle.recover_all_aborted_sessions.return_value = []
    lifecycle.running_pairs_for_maintenance.return_value = set()
    lifecycle.prune.return_value = 0
    if failed_operation == "recovery":
        lifecycle.recover_all_aborted_sessions.side_effect = RuntimeError("recovery unavailable")

    cleanup_empty_sessions = MagicMock(return_value=0)
    if failed_operation == "empty_cleanup":
        cleanup_empty_sessions.side_effect = RuntimeError("empty cleanup unavailable")

    enhanced = MagicMock()
    enhanced.maintain_session_bounds.return_value = 0
    enhanced._evict_semantic_if_needed.return_value = 0
    if failed_operation == "session_bounds":
        enhanced.maintain_session_bounds.side_effect = RuntimeError("bounds unavailable")

    review = MagicMock()
    review.prune.return_value = 0
    memory = SimpleNamespace(
        cleanup_empty_sessions=cleanup_empty_sessions,
        enhanced=enhanced,
    )
    agent = SimpleNamespace(
        _state_store=None,
        event_store=None,
        audit=None,
        memory=memory,
        lifecycle_store=lifecycle,
        review_store=review,
    )

    await ResourceGovernor(agent, state_dir=None)._prune_databases()

    lifecycle.recover_all_aborted_sessions.assert_called_once_with(threshold_seconds=300.0)
    cleanup_empty_sessions.assert_called_once_with()
    enhanced.maintain_session_bounds.assert_called_once_with(protected_sessions=set())
    enhanced._evict_semantic_if_needed.assert_called_once_with(max_memories=1_000)
    lifecycle.prune.assert_called_once_with()
    review.prune.assert_called_once_with()


@pytest.mark.asyncio
async def test_governor_skips_session_prune_when_active_protection_lookup_fails(
    tmp_path: Path,
) -> None:
    lifecycle = MagicMock()
    lifecycle.running_pairs_for_maintenance.side_effect = RuntimeError("lifecycle unavailable")
    lifecycle.prune.return_value = 0
    enhanced = MagicMock()
    enhanced._evict_semantic_if_needed.return_value = 0
    memory = SimpleNamespace(cleanup_empty_sessions=lambda: 0, enhanced=enhanced)
    agent = SimpleNamespace(
        _state_store=None,
        event_store=None,
        audit=None,
        memory=memory,
        lifecycle_store=lifecycle,
        review_store=None,
    )
    governor = ResourceGovernor(agent, state_dir=None)

    await governor._prune_databases()

    enhanced.maintain_session_bounds.assert_not_called()
