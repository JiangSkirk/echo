"""Long-term retention and REM-link regression tests for enhanced memory."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from js.config import MemoryConfig
from js.memory.enhanced_store import EnhancedMemoryStore


@pytest.fixture
def store(tmp_path: Path) -> EnhancedMemoryStore:
    return EnhancedMemoryStore(tmp_path / "state", MemoryConfig())


def _insert_semantic(
    store: EnhancedMemoryStore,
    *,
    key: str,
    value: str,
    owner: str | None,
    created_at: float,
) -> int:
    with sqlite3.connect(store.db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO semantic_memories (
                key, value, category, created_at, last_accessed, owner_key_hash
            ) VALUES (?, ?, 'fact', ?, ?, ?)
            """,
            (key, value, created_at, created_at, owner),
        )
        return int(cursor.lastrowid)


def _insert_dream_log(
    store: EnhancedMemoryStore,
    summary: str,
    created_at: float,
) -> None:
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            """
            INSERT INTO dream_logs (phase, summary, changes, created_at)
            VALUES ('rem', ?, '', ?)
            """,
            (summary, created_at),
        )


def _insert_proposal(
    store: EnhancedMemoryStore,
    *,
    owner: str,
    key: str,
    status: str,
    created_at: float,
) -> None:
    decided_at = None if status in {"pending", "needs_review"} else created_at
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            """
            INSERT INTO proposed_changes (
                owner_key_hash, key, value, status, created_at, decided_at
            ) VALUES (?, ?, 'value', ?, ?, ?)
            """,
            (owner, key, status, created_at, decided_at),
        )


def test_repeated_rem_writes_one_link_per_owner_edge(store: EnhancedMemoryStore) -> None:
    now = time.time()
    for key, value, owner, age in (
        ("a-python", "python asyncio event loop programming", "owner-a", 4),
        ("a-loop", "python asyncio event loop scheduling", "owner-a", 3),
        ("b-docker", "docker container cluster deployment scaling", "owner-b", 2),
        ("b-k8s", "kubernetes container cluster deployment scaling", "owner-b", 1),
    ):
        _insert_semantic(store, key=key, value=value, owner=owner, created_at=now - age)

    store._rem_sleep()
    store._rem_sleep()

    with sqlite3.connect(store.db_path) as conn:
        total = int(conn.execute("SELECT COUNT(*) FROM memory_links").fetchone()[0])
        per_owner = dict(
            conn.execute(
                """
                SELECT owner_key_hash, COUNT(*)
                FROM memory_links
                GROUP BY owner_key_hash
                """
            ).fetchall()
        )

    assert total == 2
    assert per_owner == {"owner-a": 1, "owner-b": 1}


def test_rem_never_links_semantic_memories_across_owners(
    store: EnhancedMemoryStore,
) -> None:
    now = time.time()
    shared_words = "python asyncio event loop programming"
    _insert_semantic(
        store,
        key="owner-a-memory",
        value=shared_words,
        owner="owner-a",
        created_at=now - 1,
    )
    _insert_semantic(
        store,
        key="owner-b-memory",
        value=shared_words,
        owner="owner-b",
        created_at=now,
    )

    store._rem_sleep()

    with sqlite3.connect(store.db_path) as conn:
        count = int(conn.execute("SELECT COUNT(*) FROM memory_links").fetchone()[0])
    assert count == 0


def test_memory_link_migration_deduplicates_before_unique_index(
    store: EnhancedMemoryStore,
) -> None:
    source_id = _insert_semantic(
        store,
        key="source",
        value="python asyncio event loop programming",
        owner="owner-a",
        created_at=1.0,
    )
    target_id = _insert_semantic(
        store,
        key="target",
        value="python asyncio event loop scheduling",
        owner="owner-a",
        created_at=2.0,
    )
    with sqlite3.connect(store.db_path) as conn:
        conn.execute("DROP TABLE memory_links")
        conn.execute(
            """
            CREATE TABLE memory_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_id INTEGER,
                to_id INTEGER,
                from_table TEXT,
                to_table TEXT,
                strength REAL DEFAULT 0.5,
                link_type TEXT DEFAULT 'association',
                created_at REAL NOT NULL
            )
            """
        )
        conn.executemany(
            """
            INSERT INTO memory_links (
                from_id, to_id, from_table, to_table,
                strength, link_type, created_at
            ) VALUES (?, ?, 'semantic_memories', 'semantic_memories', ?, 'association', ?)
            """,
            (
                (source_id, target_id, 0.4, 10.0),
                (source_id, target_id, 0.9, 20.0),
            ),
        )

    migrated = EnhancedMemoryStore(store.state_dir, MemoryConfig())
    with sqlite3.connect(migrated.db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM memory_links").fetchall()
        index_names = {
            str(row[1]) for row in conn.execute("PRAGMA index_list(memory_links)").fetchall()
        }

    assert len(rows) == 1
    assert rows[0]["owner_key_hash"] == "owner-a"
    assert rows[0]["strength"] == pytest.approx(0.9)
    assert "idx_memory_links_owner_edge" in index_names


def test_long_term_maintenance_prunes_dream_logs_by_age_and_hard_cap(
    store: EnhancedMemoryStore,
) -> None:
    now = time.time()
    for summary, created_at in (
        ("expired", now - 100 * 86_400),
        ("cap-oldest", now - 30),
        ("keep-middle", now - 20),
        ("keep-newest", now - 10),
    ):
        _insert_dream_log(store, summary, created_at)

    deleted = store.maintain_long_term_bounds(
        dream_log_retention_days=90,
        max_dream_logs=2,
        proposal_retention_days=3_650,
        max_proposals_per_owner=100,
        max_proposals_global=100,
    )

    with sqlite3.connect(store.db_path) as conn:
        summaries = [
            str(row[0])
            for row in conn.execute(
                "SELECT summary FROM dream_logs ORDER BY created_at DESC"
            ).fetchall()
        ]
    assert deleted == 2
    assert summaries == ["keep-newest", "keep-middle"]


def test_proposal_maintenance_preserves_manual_states_and_owner_partition(
    store: EnhancedMemoryStore,
) -> None:
    now = time.time()
    for key, status, age_days in (
        ("pending-old", "pending", 200),
        ("manual-old", "needs_review", 200),
        ("approved-expired", "approved", 100),
        ("rejected-cap-old", "rejected", 40),
        ("auto-keep", "auto_applied", 30),
        ("approved-keep", "approved", 20),
    ):
        _insert_proposal(
            store,
            owner="owner-a",
            key=key,
            status=status,
            created_at=now - age_days * 86_400,
        )
    _insert_proposal(
        store,
        owner="owner-b",
        key="owner-b-terminal",
        status="approved",
        created_at=now - 50 * 86_400,
    )

    deleted = store.maintain_long_term_bounds(
        dream_log_retention_days=3_650,
        max_dream_logs=100,
        proposal_retention_days=90,
        max_proposals_per_owner=4,
        max_proposals_global=100,
    )

    with sqlite3.connect(store.db_path) as conn:
        owner_a = dict(
            conn.execute(
                """
                SELECT key, status
                FROM proposed_changes
                WHERE owner_key_hash = 'owner-a'
                """
            ).fetchall()
        )
        owner_b = conn.execute(
            """
            SELECT key, status
            FROM proposed_changes
            WHERE owner_key_hash = 'owner-b'
            """
        ).fetchall()

    assert deleted == 2
    assert owner_a == {
        "pending-old": "pending",
        "manual-old": "needs_review",
        "auto-keep": "auto_applied",
        "approved-keep": "approved",
    }
    assert owner_b == [("owner-b-terminal", "approved")]


def test_proposal_maintenance_global_cap_only_prunes_terminal_states(
    store: EnhancedMemoryStore,
) -> None:
    now = time.time()
    for key, status, age_days in (
        ("pending-old", "pending", 100),
        ("needs-review-old", "needs_review", 90),
        ("awaiting-user-old", "awaiting_user", 80),
        ("owner-a-terminal-old", "approved", 70),
        ("owner-b-terminal-new", "auto_applied", 10),
    ):
        _insert_proposal(
            store,
            owner="owner-a" if key != "owner-b-terminal-new" else "owner-b",
            key=key,
            status=status,
            created_at=now - age_days * 86_400,
        )

    deleted = store.maintain_long_term_bounds(
        dream_log_retention_days=3_650,
        max_dream_logs=100,
        proposal_retention_days=3_650,
        max_proposals_per_owner=100,
        max_proposals_global=4,
    )

    with sqlite3.connect(store.db_path) as conn:
        rows = conn.execute(
            "SELECT key, status FROM proposed_changes ORDER BY key"
        ).fetchall()

    assert deleted == 1
    assert rows == [
        ("awaiting-user-old", "awaiting_user"),
        ("needs-review-old", "needs_review"),
        ("owner-b-terminal-new", "auto_applied"),
        ("pending-old", "pending"),
    ]


def test_long_term_maintenance_rolls_back_all_tables_on_failure(
    store: EnhancedMemoryStore,
) -> None:
    old = time.time() - 100 * 86_400
    _insert_dream_log(store, "expired", old)
    _insert_proposal(
        store,
        owner="owner-a",
        key="blocked",
        status="approved",
        created_at=old,
    )
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            """
            CREATE TRIGGER fail_proposal_delete
            BEFORE DELETE ON proposed_changes
            WHEN OLD.key = 'blocked'
            BEGIN
                SELECT RAISE(ABORT, 'blocked proposal delete');
            END
            """
        )

    with pytest.raises(sqlite3.DatabaseError, match="blocked proposal delete"):
        store.maintain_long_term_bounds(
            dream_log_retention_days=90,
            max_dream_logs=100,
            proposal_retention_days=90,
            max_proposals_per_owner=100,
            max_proposals_global=100,
        )

    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM dream_logs").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM proposed_changes").fetchone()[0] == 1


def test_session_maintenance_also_runs_default_long_term_retention(
    store: EnhancedMemoryStore,
) -> None:
    old = time.time() - 100 * 86_400
    _insert_dream_log(store, "expired", old)
    _insert_proposal(
        store,
        owner="owner-a",
        key="expired",
        status="approved",
        created_at=old,
    )

    deleted_sessions = store.maintain_session_bounds()

    with sqlite3.connect(store.db_path) as conn:
        dream_count = int(conn.execute("SELECT COUNT(*) FROM dream_logs").fetchone()[0])
        proposal_count = int(
            conn.execute("SELECT COUNT(*) FROM proposed_changes").fetchone()[0]
        )
    assert deleted_sessions == 0
    assert dream_count == 0
    assert proposal_count == 0
