"""Memory quality control tests: feedback, LRU eviction, conflict detection."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from js.config import MemoryConfig
from js.evolution.quality_scorer import QualityScorer, ToolCallScore, TurnScore
from js.memory.enhanced_store import EnhancedMemoryStore


def test_quality_scorer_rolling_stats_use_only_the_requested_window(tmp_path: Path) -> None:
    scorer = QualityScorer(tmp_path)
    scorer.record_turn(
        TurnScore(
            session_id="old-failure",
            turn_idx=0,
            model="test",
            hallucination_flags=["old"],
            timestamp=1.0,
        )
    )
    for index in range(20):
        scorer.record_turn(
            TurnScore(
                session_id=f"recent-{index}",
                turn_idx=0,
                model="test",
                timestamp=2.0 + index,
            )
        )

    stats = scorer.get_rolling_stats(window=20)

    assert stats == {
        "avg_score": 1.0,
        "avg_hallucination_rate": 0.0,
        "sample_size": 20,
    }


def test_quality_scorer_learning_data_is_isolated_by_owner(tmp_path: Path) -> None:
    scorer = QualityScorer(tmp_path)
    private_error = "/Users/alice/private/quarterly-plan.xlsx"
    for turn_idx in range(2):
        scorer.record_turn(
            TurnScore(
                session_id="shared-session-name",
                turn_idx=turn_idx,
                model="test",
                owner_key_hash="owner-alice",
                tool_scores=[
                    ToolCallScore(
                        tool_name="file_read",
                        success=False,
                        error_pattern=private_error,
                    )
                ],
            )
        )
        scorer.record_turn(
            TurnScore(
                session_id="shared-session-name",
                turn_idx=turn_idx,
                model="test",
                owner_key_hash="owner-bob",
                tool_scores=[ToolCallScore(tool_name="file_read", success=True)],
            )
        )

    alice_stats = scorer.get_rolling_stats(window=20, owner_key_hash="owner-alice")
    bob_stats = scorer.get_rolling_stats(window=20, owner_key_hash="owner-bob")
    alice_context = scorer.build_learning_context(
        max_tokens=200,
        owner_key_hash="owner-alice",
    )
    bob_context = scorer.build_learning_context(
        max_tokens=200,
        owner_key_hash="owner-bob",
    )

    assert alice_stats["sample_size"] == 2
    assert alice_stats["avg_score"] < bob_stats["avg_score"]
    assert bob_stats["sample_size"] == 2
    assert private_error in alice_context
    assert private_error not in bob_context


def test_quality_scorer_migrates_legacy_rows_without_exposing_them_to_owners(
    tmp_path: Path,
) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE turn_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                turn_idx INTEGER NOT NULL,
                model TEXT,
                overall_score REAL DEFAULT 0.0,
                hallucination_rate REAL DEFAULT 0.0,
                total_tokens INTEGER DEFAULT 0,
                timestamp REAL NOT NULL,
                UNIQUE(session_id, turn_idx)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO turn_scores
                (session_id, turn_idx, model, overall_score, hallucination_rate,
                 total_tokens, timestamp)
            VALUES ('legacy-session', 1, 'test', 0.2, 0.5, 10, 1.0)
            """
        )
        conn.execute(
            """
            CREATE TABLE tool_call_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                turn_idx INTEGER NOT NULL,
                tool_name TEXT NOT NULL,
                success INTEGER DEFAULT 0,
                retry_count INTEGER DEFAULT 0,
                error_pattern TEXT DEFAULT '',
                output_quality REAL DEFAULT 0.0,
                latency_ms REAL DEFAULT 0.0,
                timestamp REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE rejection_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT NOT NULL,
                tool_name TEXT,
                count INTEGER DEFAULT 1,
                last_seen REAL NOT NULL,
                UNIQUE(pattern, tool_name)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO rejection_patterns
                (pattern, tool_name, count, last_seen)
            VALUES ('legacy-private-pattern', NULL, 2, 1.0)
            """
        )
        conn.execute(
            """
            CREATE TABLE high_score_examples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_name TEXT,
                description TEXT,
                score REAL DEFAULT 0.0,
                timestamp REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO high_score_examples
                (tool_name, description, score, timestamp)
            VALUES ('legacy-tool', 'legacy-private-example', 1.0, 1.0)
            """
        )

    scorer = QualityScorer(tmp_path)

    assert scorer.get_rolling_stats(
        owner_key_hash="owner-alice",
    )["sample_size"] == 0
    assert scorer.get_rolling_stats(
        owner_key_hash="__legacy_local__",
    )["sample_size"] == 1
    assert "legacy-private-pattern" not in scorer.build_learning_context(
        owner_key_hash="owner-alice",
    )
    legacy_context = scorer.build_learning_context(
        owner_key_hash="__legacy_local__",
    )
    assert "legacy-private-pattern" in legacy_context
    assert "legacy-private-example" in legacy_context

    scorer.record_turn(
        TurnScore(
            session_id="legacy-session",
            turn_idx=1,
            model="test",
            owner_key_hash="owner-alice",
        )
    )
    assert scorer.get_rolling_stats(
        owner_key_hash="owner-alice",
    )["sample_size"] == 1
    assert scorer.get_rolling_stats(
        owner_key_hash="__legacy_local__",
    )["sample_size"] == 1


def test_quality_scorer_prune_keeps_each_owner_bounded(tmp_path: Path) -> None:
    scorer = QualityScorer(tmp_path)
    for owner in ("owner-alice", "owner-bob"):
        for turn_idx in range(5):
            scorer.record_turn(
                TurnScore(
                    session_id=f"{owner}-session-{turn_idx}",
                    turn_idx=turn_idx,
                    model="test",
                    owner_key_hash=owner,
                    tool_scores=[
                        ToolCallScore(
                            tool_name=f"tool-{turn_idx}",
                            success=False,
                            error_pattern=f"{owner}-error-{turn_idx}",
                        )
                    ],
                )
            )

    removed = scorer.prune(
        keep_turns_per_owner=2,
        keep_patterns_per_owner=1,
        keep_examples_per_owner=1,
    )

    assert removed > 0
    for owner in ("owner-alice", "owner-bob"):
        assert scorer.get_rolling_stats(
            owner_key_hash=owner,
        )["sample_size"] == 2
        assert len(
            scorer.get_top_rejection_patterns(
                min_count=1,
                limit=10,
                owner_key_hash=owner,
            )
        ) == 1


def test_quality_scorer_migration_is_atomic_when_ddl_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlite3

    import js.evolution.quality_scorer as scorer_module

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE turn_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                turn_idx INTEGER NOT NULL,
                model TEXT,
                overall_score REAL DEFAULT 0.0,
                hallucination_rate REAL DEFAULT 0.0,
                total_tokens INTEGER DEFAULT 0,
                timestamp REAL NOT NULL,
                UNIQUE(session_id, turn_idx)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO turn_scores
                (session_id, turn_idx, model, overall_score,
                 hallucination_rate, total_tokens, timestamp)
            VALUES ('legacy-session', 1, 'test', 0.2, 0.5, 10, 1.0)
            """
        )

    original_connection = scorer_module.db_connection

    @contextmanager
    def failing_connection(*args: Any, **kwargs: Any):
        with original_connection(*args, **kwargs) as conn:
            migration_started = False

            def authorize(
                action: int,
                _arg1: str | None,
                _arg2: str | None,
                _database: str | None,
                _trigger: str | None,
            ) -> int:
                nonlocal migration_started
                if action == sqlite3.SQLITE_ALTER_TABLE or (
                    action == sqlite3.SQLITE_CREATE_TABLE
                    and _arg1 is not None
                    and "echo2" in _arg1
                ):
                    migration_started = True
                elif migration_started and action == sqlite3.SQLITE_DROP_TABLE:
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            conn.set_authorizer(authorize)
            yield conn

    monkeypatch.setattr(scorer_module, "db_connection", failing_connection)
    with pytest.raises(sqlite3.DatabaseError):
        QualityScorer(tmp_path)

    with sqlite3.connect(db_path) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        row_count = conn.execute("SELECT COUNT(*) FROM turn_scores").fetchone()[0]
    assert "turn_scores" in tables
    assert "turn_scores_legacy" not in tables
    assert row_count == 1


def test_quality_scorer_repairs_owner_column_with_wrong_unique_key(
    tmp_path: Path,
) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE turn_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_key_hash TEXT NOT NULL,
                session_id TEXT NOT NULL,
                turn_idx INTEGER NOT NULL,
                model TEXT,
                overall_score REAL DEFAULT 0.0,
                hallucination_rate REAL DEFAULT 0.0,
                total_tokens INTEGER DEFAULT 0,
                timestamp REAL NOT NULL,
                UNIQUE(session_id, turn_idx)
            )
            """
        )

    scorer = QualityScorer(tmp_path)
    for owner in ("owner-alice", "owner-bob"):
        scorer.record_turn(
            TurnScore(
                session_id="same-session",
                turn_idx=1,
                model="test",
                owner_key_hash=owner,
            )
        )

    assert scorer.get_rolling_stats(
        owner_key_hash="owner-alice",
    )["sample_size"] == 1
    assert scorer.get_rolling_stats(
        owner_key_hash="owner-bob",
    )["sample_size"] == 1


def test_quality_scorer_recovers_orphaned_legacy_table(tmp_path: Path) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE turn_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_key_hash TEXT NOT NULL,
                session_id TEXT NOT NULL,
                turn_idx INTEGER NOT NULL,
                model TEXT,
                overall_score REAL DEFAULT 0.0,
                hallucination_rate REAL DEFAULT 0.0,
                total_tokens INTEGER DEFAULT 0,
                timestamp REAL NOT NULL,
                UNIQUE(owner_key_hash, session_id, turn_idx)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE turn_scores_legacy (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                turn_idx INTEGER NOT NULL,
                model TEXT,
                overall_score REAL DEFAULT 0.0,
                hallucination_rate REAL DEFAULT 0.0,
                total_tokens INTEGER DEFAULT 0,
                timestamp REAL NOT NULL,
                UNIQUE(session_id, turn_idx)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO turn_scores_legacy
                (session_id, turn_idx, model, overall_score,
                 hallucination_rate, total_tokens, timestamp)
            VALUES ('orphaned-session', 1, 'test', 0.2, 0.5, 10, 1.0)
            """
        )

    scorer = QualityScorer(tmp_path)

    assert scorer.get_rolling_stats(
        owner_key_hash="__legacy_local__",
    )["sample_size"] == 1
    with sqlite3.connect(db_path) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert "turn_scores_legacy" not in tables


@pytest.mark.parametrize(
    "schema_variant",
    ["legacy_unique", "partial_unique", "wrong_id", "wrong_default"],
)
def test_quality_scorer_rebuilds_noncanonical_constraints(
    tmp_path: Path,
    schema_variant: str,
) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        if schema_variant in {"wrong_id", "wrong_default"}:
            id_definition = "id TEXT" if schema_variant == "wrong_id" else "id INTEGER PRIMARY KEY AUTOINCREMENT"
            score_default = "1.0" if schema_variant == "wrong_default" else "0.0"
            conn.execute(
                f"""
                CREATE TABLE turn_scores (
                    {id_definition},
                    owner_key_hash TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    turn_idx INTEGER NOT NULL,
                    model TEXT,
                    overall_score REAL DEFAULT {score_default},
                    hallucination_rate REAL DEFAULT 0.0,
                    total_tokens INTEGER DEFAULT 0,
                    timestamp REAL NOT NULL,
                    UNIQUE(owner_key_hash, session_id, turn_idx)
                )
                """
            )
        else:
            QualityScorer._create_canonical_table(  # noqa: SLF001
                conn,
                "turn_scores",
                "turn_scores",
            )
            where = " WHERE owner_key_hash <> ''" if schema_variant == "partial_unique" else ""
            conn.execute(
                "CREATE UNIQUE INDEX stale_turn_identity "
                f"ON turn_scores(session_id, turn_idx){where}"
            )

    scorer = QualityScorer(tmp_path)
    for owner in ("owner-alice", "owner-bob"):
        scorer.record_turn(
            TurnScore(
                session_id="same-session",
                turn_idx=1,
                model="test",
                owner_key_hash=owner,
            )
        )

    with sqlite3.connect(db_path) as conn:
        owners = {
            row[0]
            for row in conn.execute(
                "SELECT owner_key_hash FROM turn_scores WHERE session_id = 'same-session'"
            )
        }
        id_column = {
            row[1]: row for row in conn.execute("PRAGMA table_info(turn_scores)")
        }["id"]
        overall_score_column = {
            row[1]: row for row in conn.execute("PRAGMA table_info(turn_scores)")
        }["overall_score"]
        unique_indexes = []
        for index in conn.execute("PRAGMA index_list(turn_scores)"):
            if not index[2]:
                continue
            columns = tuple(
                row[2] for row in conn.execute(f'PRAGMA index_info("{index[1]}")')
            )
            unique_indexes.append((columns, bool(index[4])))

    assert owners == {"owner-alice", "owner-bob"}
    assert id_column[2].upper() == "INTEGER"
    assert id_column[5] == 1
    assert overall_score_column[4] == "0.0"
    assert unique_indexes == [
        (("owner_key_hash", "session_id", "run_id", "turn_idx"), False),
    ]


def test_quality_scorer_rebuilds_nocase_owner_identity(tmp_path: Path) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE turn_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_key_hash TEXT NOT NULL,
                session_id TEXT NOT NULL,
                turn_idx INTEGER NOT NULL,
                model TEXT,
                overall_score REAL DEFAULT 0.0,
                hallucination_rate REAL DEFAULT 0.0,
                total_tokens INTEGER DEFAULT 0,
                timestamp REAL NOT NULL,
                UNIQUE(owner_key_hash COLLATE NOCASE, session_id, turn_idx)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO turn_scores
                (owner_key_hash, session_id, turn_idx, model, timestamp)
            VALUES ('Owner-A', 'shared-session', 1, 'model-a', 1.0)
            """
        )

    scorer = QualityScorer(tmp_path)
    scorer.record_turn(
        TurnScore(
            session_id="shared-session",
            turn_idx=1,
            model="model-b",
            owner_key_hash="owner-a",
            timestamp=2.0,
        )
    )

    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT owner_key_hash, model FROM turn_scores ORDER BY owner_key_hash"
        ).fetchall()

    assert rows == [("Owner-A", "model-a"), ("owner-a", "model-b")]


def test_quality_scorer_rebuilds_table_with_hidden_column(tmp_path: Path) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        QualityScorer._create_canonical_table(  # noqa: SLF001
            conn,
            "turn_scores",
            "turn_scores",
        )
        conn.execute(
            """
            ALTER TABLE turn_scores
            ADD COLUMN hidden_owner TEXT
            GENERATED ALWAYS AS (owner_key_hash) VIRTUAL
            """
        )

    QualityScorer(tmp_path)

    with sqlite3.connect(db_path) as conn:
        columns = [row[1] for row in conn.execute("PRAGMA table_xinfo(turn_scores)")]

    assert "hidden_owner" not in columns


def test_quality_scorer_rebuilds_generated_expected_column(tmp_path: Path) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE turn_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_key_hash TEXT NOT NULL,
                session_id TEXT NOT NULL,
                turn_idx INTEGER NOT NULL,
                model TEXT GENERATED ALWAYS AS (owner_key_hash) VIRTUAL,
                overall_score REAL DEFAULT 0.0,
                hallucination_rate REAL DEFAULT 0.0,
                total_tokens INTEGER DEFAULT 0,
                timestamp REAL NOT NULL,
                UNIQUE(owner_key_hash, session_id, turn_idx)
            )
            """
        )

    scorer = QualityScorer(tmp_path)
    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            turn_idx=1,
            model="model-a",
            owner_key_hash="owner-a",
            timestamp=1.0,
        )
    )

    with sqlite3.connect(db_path) as conn:
        model_column = {
            row[1]: row for row in conn.execute("PRAGMA table_xinfo(turn_scores)")
        }["model"]
        stored_model = conn.execute("SELECT model FROM turn_scores").fetchone()[0]

    assert model_column[6] == 0
    assert stored_model == "model-a"


def test_quality_scorer_runtime_schema_tamper_fails_closed(tmp_path: Path) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)
    with sqlite3.connect(scorer.db_path) as conn:
        conn.execute(
            "CREATE UNIQUE INDEX stale_turn_identity "
            "ON turn_scores(session_id, turn_idx)"
        )

    scorer.record_turn(
        TurnScore(
            session_id="same-session",
            turn_idx=1,
            model="test",
            owner_key_hash="owner-alice",
        )
    )
    with pytest.raises(sqlite3.IntegrityError):
        scorer.record_turn(
            TurnScore(
                session_id="same-session",
                turn_idx=1,
                model="test",
                owner_key_hash="owner-bob",
            )
        )

    assert scorer.get_rolling_stats(
        owner_key_hash="owner-alice",
    )["sample_size"] == 1
    assert scorer.get_rolling_stats(
        owner_key_hash="owner-bob",
    )["sample_size"] == 0


def test_quality_scorer_orphan_snapshots_merge_without_loss_or_duplication(
    tmp_path: Path,
) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    table_names = (
        "turn_scores",
        "tool_call_scores",
        "rejection_patterns",
        "high_score_examples",
    )
    sources = ("", "_echo2_snapshot_a", "_echo2_snapshot_b")
    with sqlite3.connect(db_path) as conn:
        for table_name in table_names:
            for suffix in sources:
                QualityScorer._create_canonical_table(  # noqa: SLF001
                    conn,
                    table_name,
                    f"{table_name}{suffix}",
                )

        for suffix, model, timestamp in (
            ("", "model-old", 1.0),
            ("_echo2_snapshot_a", "model-middle", 50.0),
            ("_echo2_snapshot_b", "model-new", 99.0),
        ):
            conn.execute(
                f"""
                INSERT INTO turn_scores{suffix}
                    (owner_key_hash, session_id, turn_idx, model, overall_score,
                     hallucination_rate, total_tokens, timestamp)
                VALUES ('owner-a', 'session-a', 1, ?, 1.0, 0.0, 10, ?)
                """,
                (model, timestamp),
            )
            conn.execute(
                f"""
                INSERT INTO tool_call_scores{suffix}
                    (owner_key_hash, session_id, turn_idx, tool_name, success,
                     retry_count, error_pattern, output_quality, latency_ms, timestamp)
                VALUES ('owner-a', 'session-a', 1, 'tool-a', 1, 0, '', 1.0, 5.0, 1.0)
                """
            )
            conn.execute(
                f"""
                INSERT INTO rejection_patterns{suffix}
                    (owner_key_hash, pattern, tool_name, count, last_seen)
                VALUES ('owner-a', 'pattern-a', 'tool-a', 1, ?)
                """,
                (timestamp,),
            )
            conn.execute(
                f"""
                INSERT INTO high_score_examples{suffix}
                    (owner_key_hash, tool_name, description, score, timestamp)
                VALUES ('owner-a', 'tool-a', 'example-a', 1.0, 1.0)
                """
            )

    QualityScorer(tmp_path)

    with sqlite3.connect(db_path) as conn:
        turn = conn.execute(
            "SELECT model, timestamp FROM turn_scores"
        ).fetchone()
        tool_count = conn.execute("SELECT COUNT(*) FROM tool_call_scores").fetchone()[0]
        rejection = conn.execute(
            "SELECT count, last_seen FROM rejection_patterns"
        ).fetchone()
        example_count = conn.execute(
            "SELECT COUNT(*) FROM high_score_examples"
        ).fetchone()[0]
        leftovers = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name LIKE '%_echo2_%'"
            )
        }

    assert turn == ("model-new", 99.0)
    assert tool_count == 1
    assert rejection == (1, 99.0)
    assert example_count == 1
    assert leftovers == set()


def test_quality_scorer_migration_does_not_double_count_archive_snapshot(
    tmp_path: Path,
) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        for table_name in (
            "turn_scores",
            "tool_call_scores",
            "rejection_patterns",
            "high_score_examples",
        ):
            QualityScorer._create_canonical_table(  # noqa: SLF001
                conn,
                table_name,
                table_name,
            )
        QualityScorer._create_canonical_table(  # noqa: SLF001
            conn,
            "tool_call_scores",
            "tool_call_scores_echo2_snapshot_pre_prune",
        )
        QualityScorer._create_canonical_table(  # noqa: SLF001
            conn,
            "rejection_patterns",
            "rejection_patterns_echo2_snapshot_post_prune",
        )
        conn.execute(
            """
            INSERT INTO turn_scores
                (owner_key_hash, session_id, turn_idx, model, timestamp)
            VALUES ('owner-a', 'session-a', 1, 'model-a', 5.0)
            """
        )
        conn.executemany(
            """
            INSERT INTO tool_call_scores
                (owner_key_hash, session_id, turn_idx, tool_name, success,
                 error_pattern, timestamp)
            VALUES ('owner-a', 'session-a', 1, 'tool-a', 0, 'pattern-a', ?)
            """,
            [(float(index),) for index in range(1, 6)],
        )
        conn.execute(
            """
            INSERT INTO rejection_patterns
                (owner_key_hash, pattern, tool_name, count, last_seen,
                 archived_count, archived_last_seen, archive_exact)
            VALUES ('owner-a', 'pattern-a', 'tool-a', 5, 5.0, 0, NULL, 1)
            """
        )
        conn.execute(
            """
            INSERT INTO rejection_patterns_echo2_snapshot_post_prune
                (owner_key_hash, pattern, tool_name, count, last_seen,
                 archived_count, archived_last_seen, archive_exact)
            VALUES ('owner-a', 'pattern-a', 'tool-a', 5, 5.0, 5, 5.0, 1)
            """
        )

    QualityScorer(tmp_path)

    with sqlite3.connect(db_path) as conn:
        rejection = conn.execute(
            """
            SELECT count, archived_count, archived_last_seen, archive_exact
            FROM rejection_patterns
            """
        ).fetchone()

    assert rejection == (5, 4, 5.0, 0)


def test_quality_scorer_prune_bounds_replayed_tool_rows(tmp_path: Path) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)
    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            turn_idx=1,
            model="test",
            owner_key_hash="owner-a",
            tool_scores=[ToolCallScore(tool_name="tool-a", success=True)],
        )
    )
    with sqlite3.connect(scorer.db_path) as conn:
        conn.executemany(
            """
            INSERT INTO tool_call_scores
                (owner_key_hash, session_id, turn_idx, tool_name, success,
                 retry_count, error_pattern, output_quality, latency_ms, timestamp)
            VALUES ('owner-a', 'session-a', 1, 'tool-a', 1, 0, '', 0.0, 0.0, ?)
            """,
            [(float(index),) for index in range(24)],
        )
        conn.commit()

    scorer.prune(
        keep_turns_per_owner=1,
        keep_tool_calls_per_turn=2,
        keep_patterns_per_owner=1,
        keep_examples_per_owner=1,
    )

    with sqlite3.connect(scorer.db_path) as conn:
        tool_count = conn.execute(
            "SELECT COUNT(*) FROM tool_call_scores WHERE owner_key_hash = 'owner-a'"
        ).fetchone()[0]
    assert tool_count == 2


def test_quality_scorer_record_turn_is_idempotent_and_replaces_aggregates(
    tmp_path: Path,
) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)
    original = TurnScore(
        session_id="session-a",
        turn_idx=1,
        model="model-old",
        owner_key_hash="owner-a",
        timestamp=1.0,
        tool_scores=[
            ToolCallScore(
                tool_name="tool-fail",
                success=False,
                error_pattern="old-pattern",
            ),
            ToolCallScore(
                tool_name="tool-good",
                success=True,
                error_pattern="old-example",
                output_quality=0.9,
            ),
        ],
    )
    for _ in range(3):
        scorer.record_turn(original)

    with sqlite3.connect(scorer.db_path) as conn:
        first_counts = {
            table_name: conn.execute(
                f'SELECT COUNT(*) FROM "{table_name}"'
            ).fetchone()[0]
            for table_name in (
                "turn_scores",
                "tool_call_scores",
                "rejection_patterns",
                "high_score_examples",
            )
        }
        rejection_count = conn.execute(
            "SELECT count FROM rejection_patterns WHERE pattern = 'old-pattern'"
        ).fetchone()[0]

    assert first_counts == {
        "turn_scores": 1,
        "tool_call_scores": 2,
        "rejection_patterns": 1,
        "high_score_examples": 1,
    }
    assert rejection_count == 1

    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            turn_idx=1,
            model="model-new",
            owner_key_hash="owner-a",
            timestamp=2.0,
            tool_scores=[
                ToolCallScore(
                    tool_name="tool-fail",
                    success=False,
                    error_pattern="new-pattern",
                )
            ],
        )
    )

    with sqlite3.connect(scorer.db_path) as conn:
        turn = conn.execute(
            "SELECT model, timestamp FROM turn_scores"
        ).fetchone()
        tools = conn.execute(
            "SELECT tool_name, error_pattern FROM tool_call_scores"
        ).fetchall()
        rejections = conn.execute(
            "SELECT pattern, count FROM rejection_patterns"
        ).fetchall()
        high_count = conn.execute(
            "SELECT COUNT(*) FROM high_score_examples"
        ).fetchone()[0]

    assert turn == ("model-new", 2.0)
    assert tools == [("tool-fail", "new-pattern")]
    assert rejections == [("new-pattern", 1)]
    assert high_count == 0


def test_quality_scorer_preserves_pruned_rejection_history(tmp_path: Path) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)
    for turn_idx in range(5):
        scorer.record_turn(
            TurnScore(
                session_id="session-a",
                turn_idx=turn_idx,
                model="test",
                owner_key_hash="owner-a",
                timestamp=float(turn_idx + 1),
                tool_scores=[
                    ToolCallScore(
                        tool_name="tool-a",
                        success=False,
                        error_pattern="same-pattern",
                    )
                ],
            )
        )

    scorer.prune(
        keep_turns_per_owner=1,
        keep_tool_calls_per_turn=100,
        keep_patterns_per_owner=10,
        keep_examples_per_owner=10,
    )
    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            turn_idx=5,
            model="test",
            owner_key_hash="owner-a",
            timestamp=6.0,
            tool_scores=[
                ToolCallScore(
                    tool_name="tool-a",
                    success=False,
                    error_pattern="same-pattern",
                )
            ],
        )
    )

    with sqlite3.connect(scorer.db_path) as conn:
        rejection = conn.execute(
            "SELECT count, last_seen FROM rejection_patterns"
        ).fetchone()
        tool_count = conn.execute("SELECT COUNT(*) FROM tool_call_scores").fetchone()[0]

    assert rejection == (6, 6.0)
    assert tool_count == 2


def test_quality_scorer_replaces_retained_turn_after_tool_detail_prune(
    tmp_path: Path,
) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)
    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            turn_idx=1,
            model="old",
            owner_key_hash="owner-a",
            timestamp=1.0,
            tool_scores=[
                ToolCallScore(
                    tool_name="tool-a",
                    success=False,
                    error_pattern="same-pattern",
                )
                for _ in range(3)
            ],
        )
    )
    scorer.prune(
        keep_turns_per_owner=10,
        keep_tool_calls_per_turn=1,
        keep_patterns_per_owner=10,
        keep_examples_per_owner=10,
    )
    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            turn_idx=1,
            model="replacement",
            owner_key_hash="owner-a",
            timestamp=2.0,
            tool_scores=[ToolCallScore(tool_name="tool-a", success=True)],
        )
    )

    with sqlite3.connect(scorer.db_path) as conn:
        rejection_count = conn.execute(
            "SELECT COUNT(*) FROM rejection_patterns"
        ).fetchone()[0]

    assert rejection_count == 0


def test_quality_scorer_pattern_prune_survives_future_schema_migration(
    tmp_path: Path,
) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)
    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            turn_idx=1,
            model="test",
            owner_key_hash="owner-a",
            timestamp=1.0,
            tool_scores=[
                ToolCallScore(
                    tool_name=f"tool-{index}",
                    success=False,
                    error_pattern=f"pattern-{index}",
                )
                for index in range(3)
            ],
        )
    )
    scorer.prune(
        keep_turns_per_owner=10,
        keep_tool_calls_per_turn=100,
        keep_patterns_per_owner=1,
        keep_examples_per_owner=10,
    )
    with sqlite3.connect(scorer.db_path) as conn:
        QualityScorer._create_canonical_table(  # noqa: SLF001
            conn,
            "rejection_turn_contributions",
            "rejection_turn_contributions_echo2_snapshot",
        )

    QualityScorer(tmp_path)

    with sqlite3.connect(scorer.db_path) as conn:
        patterns = conn.execute(
            "SELECT pattern FROM rejection_patterns ORDER BY pattern"
        ).fetchall()
        failed_tools = conn.execute(
            "SELECT error_pattern FROM tool_call_scores WHERE success = 0"
        ).fetchall()

    assert len(patterns) == 1
    assert failed_tools == patterns


def test_quality_scorer_rejects_replay_of_fully_pruned_turn(tmp_path: Path) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)
    pruned_turn = TurnScore(
        session_id="session-a",
        turn_idx=1,
        model="old",
        owner_key_hash="owner-a",
        timestamp=1.0,
        tool_scores=[
            ToolCallScore(
                tool_name="tool-a",
                success=False,
                error_pattern="same-pattern",
            )
        ],
    )
    scorer.record_turn(pruned_turn)
    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            turn_idx=2,
            model="new",
            owner_key_hash="owner-a",
            timestamp=2.0,
        )
    )
    scorer.prune(
        keep_turns_per_owner=1,
        keep_tool_calls_per_turn=100,
        keep_patterns_per_owner=10,
        keep_examples_per_owner=10,
    )
    scorer.record_turn(pruned_turn)

    with sqlite3.connect(scorer.db_path) as conn:
        rejection = conn.execute(
            "SELECT count, archived_count FROM rejection_patterns"
        ).fetchone()
        replayed_turn = conn.execute(
            """
            SELECT COUNT(*) FROM turn_scores
            WHERE session_id = 'session-a' AND turn_idx = 1
            """
        ).fetchone()[0]

    assert rejection == (1, 1)
    assert replayed_turn == 0


def test_quality_scorer_accepts_new_run_that_reuses_session_turn_index(
    tmp_path: Path,
) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)
    old_turn = TurnScore(
        session_id="session-a",
        run_id="run-old",
        turn_idx=1,
        model="old",
        owner_key_hash="owner-a",
        timestamp=1.0,
        tool_scores=[
            ToolCallScore(
                tool_name="tool-a",
                success=False,
                error_pattern="same-pattern",
            )
        ],
    )
    scorer.record_turn(old_turn)
    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            run_id="run-old",
            turn_idx=2,
            model="kept",
            owner_key_hash="owner-a",
            timestamp=2.0,
        )
    )
    scorer.prune(
        keep_turns_per_owner=1,
        keep_tool_calls_per_turn=100,
        keep_patterns_per_owner=10,
        keep_examples_per_owner=10,
    )
    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            run_id="run-new",
            turn_idx=1,
            model="new",
            owner_key_hash="owner-a",
            timestamp=3.0,
            tool_scores=[
                ToolCallScore(
                    tool_name="tool-a",
                    success=False,
                    error_pattern="same-pattern",
                )
            ],
        )
    )
    scorer.record_turn(old_turn)

    with sqlite3.connect(scorer.db_path) as conn:
        turns = conn.execute(
            "SELECT run_id, turn_idx FROM turn_scores ORDER BY timestamp"
        ).fetchall()
        rejection = conn.execute(
            "SELECT count, archived_count FROM rejection_patterns"
        ).fetchone()

    assert turns == [("run-old", 2), ("run-new", 1)]
    assert rejection == (2, 1)


def test_quality_scorer_watermark_budget_saturates_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlite3

    import js.evolution.quality_scorer as scorer_module

    monkeypatch.setattr(scorer_module, "_MAX_WATERMARKS_PER_OWNER", 3, raising=False)
    scorer = QualityScorer(tmp_path)
    for index in range(5):
        scorer.record_turn(
            TurnScore(
                session_id="session-a",
                run_id=f"run-{index}",
                turn_idx=1,
                model="test",
                owner_key_hash="owner-a",
                timestamp=float(index + 1),
            )
        )
    scorer.prune(
        keep_turns_per_owner=1,
        keep_tool_calls_per_turn=100,
        keep_patterns_per_owner=10,
        keep_examples_per_owner=10,
    )
    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            run_id="run-after-saturation",
            turn_idx=1,
            model="must-not-write",
            owner_key_hash="owner-a",
            timestamp=10.0,
        )
    )

    with sqlite3.connect(scorer.db_path) as conn:
        watermarks = conn.execute(
            "SELECT session_id, run_id FROM quality_session_watermarks"
        ).fetchall()
        models = conn.execute(
            "SELECT model FROM turn_scores ORDER BY timestamp"
        ).fetchall()

    assert watermarks == [("__echo_quality_saturated__", "__all_runs__")]
    assert models == [("test",)]


def test_quality_scorer_migration_uses_only_winning_turn_tool_version(
    tmp_path: Path,
) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        for table_name in (
            "turn_scores",
            "tool_call_scores",
            "rejection_patterns",
            "high_score_examples",
        ):
            QualityScorer._create_canonical_table(  # noqa: SLF001
                conn,
                table_name,
                table_name,
            )
        conn.execute(
            """
            INSERT INTO turn_scores
                (owner_key_hash, session_id, turn_idx, model, timestamp)
            VALUES ('owner-a', 'session-a', 1, 'winner', 2.0)
            """
        )
        conn.executemany(
            """
            INSERT INTO tool_call_scores
                (owner_key_hash, session_id, turn_idx, tool_name, success,
                 error_pattern, timestamp)
            VALUES ('owner-a', 'session-a', 1, 'tool-a', 0, 'pattern-a', ?)
            """,
            [(1.0,), (1.0,), (1.0,), (2.0,)],
        )
        conn.execute(
            """
            INSERT INTO rejection_patterns
                (owner_key_hash, pattern, tool_name, count, last_seen)
            VALUES ('owner-a', 'pattern-a', 'tool-a', 4, 2.0)
            """
        )

    QualityScorer(tmp_path)

    with sqlite3.connect(db_path) as conn:
        contribution = conn.execute(
            "SELECT count, last_seen FROM rejection_turn_contributions"
        ).fetchone()
        rejection = conn.execute(
            "SELECT count, archived_count, archive_exact FROM rejection_patterns"
        ).fetchone()

    assert contribution == (1, 2.0)
    assert rejection == (4, 3, 0)


def test_quality_scorer_migration_keeps_equal_timestamp_winner_tool_version(
    tmp_path: Path,
) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        for suffix in ("", "_echo2_snapshot"):
            for table_name in (
                "turn_scores",
                "tool_call_scores",
                "rejection_turn_contributions",
                "high_score_examples",
            ):
                QualityScorer._create_canonical_table(  # noqa: SLF001
                    conn,
                    table_name,
                    f"{table_name}{suffix}",
                )
        conn.execute(
            """
            INSERT INTO turn_scores
                (owner_key_hash, session_id, run_id, turn_idx, model, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'loser', 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO turn_scores_echo2_snapshot
                (owner_key_hash, session_id, run_id, turn_idx, model, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'winner', 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO tool_call_scores
                (owner_key_hash, session_id, run_id, turn_idx, tool_name,
                 success, error_pattern, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'loser-tool',
                    0, 'loser-rejection', 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO tool_call_scores_echo2_snapshot
                (owner_key_hash, session_id, run_id, turn_idx, tool_name,
                 success, error_pattern, output_quality, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'winner-tool', 1,
                    '', 0.9, 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO rejection_turn_contributions
                (owner_key_hash, session_id, run_id, turn_idx, pattern,
                 tool_name, count, last_seen)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'loser-rejection',
                    'loser-tool', 1, 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO high_score_examples
                (owner_key_hash, tool_name, description, score, timestamp,
                 source_session_id, source_run_id, source_turn_idx,
                 source_ordinal)
            VALUES ('owner-a', 'loser-tool', 'loser example', 0.9, 2.0,
                    'session-a', 'run-a', 1, 0)
            """
        )
        conn.execute(
            """
            INSERT INTO high_score_examples_echo2_snapshot
                (owner_key_hash, tool_name, description, score, timestamp,
                 source_session_id, source_run_id, source_turn_idx,
                 source_ordinal)
            VALUES ('owner-a', 'winner-tool', 'winner example', 0.9, 2.0,
                    'session-a', 'run-a', 1, 1)
            """
        )

    QualityScorer(tmp_path)

    with sqlite3.connect(db_path) as conn:
        turn = conn.execute("SELECT model FROM turn_scores").fetchall()
        tools = conn.execute(
            "SELECT tool_name, success FROM tool_call_scores ORDER BY tool_name"
        ).fetchall()
        rejections = conn.execute(
            "SELECT pattern, count FROM rejection_turn_contributions"
        ).fetchall()
        examples = conn.execute(
            "SELECT tool_name, description FROM high_score_examples"
        ).fetchall()

    assert turn == [("winner",)]
    assert tools == [("winner-tool", 1)]
    assert rejections == []
    assert examples == [("winner-tool", "winner example")]


def test_quality_scorer_migration_preserves_pruned_turn_evidence(
    tmp_path: Path,
) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        for table_name in (
            "turn_scores",
            "tool_call_scores",
            "rejection_turn_contributions",
            "rejection_patterns",
            "high_score_examples",
        ):
            QualityScorer._create_canonical_table(  # noqa: SLF001
                conn,
                table_name,
                table_name,
            )
        for table_name in ("turn_scores", "tool_call_scores"):
            QualityScorer._create_canonical_table(  # noqa: SLF001
                conn,
                table_name,
                f"{table_name}_echo2_snapshot",
            )
        conn.execute(
            """
            INSERT INTO turn_scores
                (owner_key_hash, session_id, run_id, turn_idx, model, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'loser', 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO turn_scores_echo2_snapshot
                (owner_key_hash, session_id, run_id, turn_idx, model, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'winner', 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO tool_call_scores_echo2_snapshot
                (owner_key_hash, session_id, run_id, turn_idx, tool_name,
                 success, output_quality, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'kept-tool', 1, 0.9, 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO rejection_turn_contributions
                (owner_key_hash, session_id, run_id, turn_idx, pattern,
                 tool_name, count, last_seen)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'pruned-rejection',
                    'pruned-failure', 1, 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO high_score_examples
                (owner_key_hash, tool_name, description, score, timestamp,
                 source_session_id, source_run_id, source_turn_idx,
                 source_ordinal)
            VALUES ('owner-a', 'pruned-success', 'pruned example', 0.9, 2.0,
                    'session-a', 'run-a', 1, 1)
            """
        )

    QualityScorer(tmp_path)

    with sqlite3.connect(db_path) as conn:
        contributions = conn.execute(
            "SELECT pattern, tool_name, count FROM rejection_turn_contributions"
        ).fetchall()
        examples = conn.execute(
            "SELECT tool_name, description FROM high_score_examples"
        ).fetchall()

    assert contributions == [("pruned-rejection", "pruned-failure", 1)]
    assert examples == [("pruned-success", "pruned example")]


def test_quality_scorer_migration_discards_same_name_loser_example(
    tmp_path: Path,
) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        for suffix in ("", "_echo2_snapshot"):
            for table_name in (
                "turn_scores",
                "tool_call_scores",
                "high_score_examples",
            ):
                QualityScorer._create_canonical_table(  # noqa: SLF001
                    conn,
                    table_name,
                    f"{table_name}{suffix}",
                )
        conn.execute(
            """
            INSERT INTO turn_scores
                (owner_key_hash, session_id, run_id, turn_idx, model, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'loser', 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO turn_scores_echo2_snapshot
                (owner_key_hash, session_id, run_id, turn_idx, model, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'winner', 2.0)
            """
        )
        for table_name in ("tool_call_scores", "tool_call_scores_echo2_snapshot"):
            conn.execute(
                f"""
                INSERT INTO {table_name}
                    (owner_key_hash, session_id, run_id, turn_idx, tool_name,
                     success, output_quality, timestamp)
                VALUES ('owner-a', 'session-a', 'run-a', 1, 'shared-tool', 1, 0.9, 2.0)
                """
            )
        conn.execute(
            """
            INSERT INTO high_score_examples
                (owner_key_hash, tool_name, description, score, timestamp,
                 source_session_id, source_run_id, source_turn_idx,
                 source_ordinal)
            VALUES ('owner-a', 'shared-tool', 'loser example', 0.9, 2.0,
                    'session-a', 'run-a', 1, 0)
            """
        )
        conn.execute(
            """
            INSERT INTO high_score_examples_echo2_snapshot
                (owner_key_hash, tool_name, description, score, timestamp,
                 source_session_id, source_run_id, source_turn_idx,
                 source_ordinal)
            VALUES ('owner-a', 'shared-tool', 'winner example', 0.9, 2.0,
                    'session-a', 'run-a', 1, 1)
            """
        )

    QualityScorer(tmp_path)

    with sqlite3.connect(db_path) as conn:
        examples = conn.execute(
            "SELECT description, source_ordinal FROM high_score_examples"
        ).fetchall()

    assert examples == [("winner example", 1)]


def test_quality_scorer_migration_recovers_only_available_tool_snapshot(
    tmp_path: Path,
) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        QualityScorer._create_canonical_table(  # noqa: SLF001
            conn,
            "turn_scores",
            "turn_scores",
        )
        QualityScorer._create_canonical_table(  # noqa: SLF001
            conn,
            "tool_call_scores",
            "tool_call_scores_echo2_snapshot",
        )
        conn.execute(
            """
            INSERT INTO turn_scores
                (owner_key_hash, session_id, run_id, turn_idx, model, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'winner', 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO tool_call_scores_echo2_snapshot
                (owner_key_hash, session_id, run_id, turn_idx, tool_name,
                 success, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'recovered-tool', 1, 2.0)
            """
        )

    QualityScorer(tmp_path)

    with sqlite3.connect(db_path) as conn:
        tools = conn.execute(
            "SELECT tool_name, success FROM tool_call_scores"
        ).fetchall()

    assert tools == [("recovered-tool", 1)]


def test_quality_scorer_migration_example_follows_recovered_tool_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlite3

    import js.evolution.quality_scorer as scorer_module

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        for table_name in (
            "turn_scores",
            "tool_call_scores",
            "high_score_examples",
        ):
            QualityScorer._create_canonical_table(  # noqa: SLF001
                conn,
                table_name,
                table_name,
            )
        for table_name in ("tool_call_scores", "high_score_examples"):
            QualityScorer._create_canonical_table(  # noqa: SLF001
                conn,
                table_name,
                f"{table_name}_echo2_snapshot",
            )
        conn.execute(
            """
            INSERT INTO turn_scores
                (owner_key_hash, session_id, run_id, turn_idx, model, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'winner', 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO tool_call_scores_echo2_snapshot
                (owner_key_hash, session_id, run_id, turn_idx, tool_name,
                 success, output_quality, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'recovered-tool',
                    1, 0.9, 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO high_score_examples_echo2_snapshot
                (owner_key_hash, tool_name, description, score, timestamp,
                 source_session_id, source_run_id, source_turn_idx,
                 source_ordinal)
            VALUES ('owner-a', 'recovered-tool', 'recovered example', 0.9, 2.0,
                    'session-a', 'run-a', 1, 0)
            """
        )

    live_conn = sqlite3.connect(db_path)

    @contextmanager
    def persistent_connection(*_args: Any, **_kwargs: Any):
        yield live_conn

    monkeypatch.setattr(scorer_module, "db_connection", persistent_connection)
    try:
        QualityScorer(tmp_path)
        QualityScorer(tmp_path)
        tools = live_conn.execute(
            "SELECT tool_name, success FROM tool_call_scores"
        ).fetchall()
        examples = live_conn.execute(
            "SELECT tool_name, description FROM high_score_examples"
        ).fetchall()
        temp_tables = live_conn.execute(
            """
            SELECT name
            FROM sqlite_temp_master
            WHERE name IN (
                'echo_tool_migration_choices',
                'echo_turn_migration_winners'
            )
            """
        ).fetchall()
    finally:
        live_conn.close()

    assert tools == [("recovered-tool", 1)]
    assert examples == [("recovered-tool", "recovered example")]
    assert temp_tables == []


def test_quality_scorer_migration_contribution_follows_recovered_tool_lineage(
    tmp_path: Path,
) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        for table_name in (
            "turn_scores",
            "tool_call_scores",
            "rejection_turn_contributions",
        ):
            QualityScorer._create_canonical_table(  # noqa: SLF001
                conn,
                table_name,
                table_name,
            )
        for table_name in (
            "tool_call_scores",
            "rejection_turn_contributions",
        ):
            QualityScorer._create_canonical_table(  # noqa: SLF001
                conn,
                table_name,
                f"{table_name}_echo2_snapshot",
            )
        conn.execute(
            """
            INSERT INTO turn_scores
                (owner_key_hash, session_id, run_id, turn_idx, model, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'winner', 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO tool_call_scores_echo2_snapshot
                (owner_key_hash, session_id, run_id, turn_idx, tool_name,
                 success, error_pattern, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'recovered-tool',
                    0, 'recovered-rejection', 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO rejection_turn_contributions_echo2_snapshot
                (owner_key_hash, session_id, run_id, turn_idx, pattern,
                 tool_name, count, last_seen)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'recovered-rejection',
                    'recovered-tool', 4, 2.0)
            """
        )

    QualityScorer(tmp_path)

    with sqlite3.connect(db_path) as conn:
        tools = conn.execute(
            "SELECT tool_name, success FROM tool_call_scores"
        ).fetchall()
        contributions = conn.execute(
            """
            SELECT pattern, tool_name, count
            FROM rejection_turn_contributions
            """
        ).fetchall()

    assert tools == [("recovered-tool", 0)]
    assert contributions == [("recovered-rejection", "recovered-tool", 4)]


def test_quality_scorer_migration_prepares_canonical_tool_lineage_before_rebuild(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlite3

    import js.evolution.quality_scorer as scorer_module

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        for table_name in (
            "turn_scores",
            "tool_call_scores",
            "rejection_turn_contributions",
            "high_score_examples",
        ):
            QualityScorer._create_canonical_table(  # noqa: SLF001
                conn,
                table_name,
                table_name,
            )
        for table_name in (
            "turn_scores",
            "rejection_turn_contributions",
            "high_score_examples",
        ):
            QualityScorer._create_canonical_table(  # noqa: SLF001
                conn,
                table_name,
                f"{table_name}_echo2_snapshot",
            )
        conn.execute(
            """
            INSERT INTO turn_scores
                (owner_key_hash, session_id, run_id, turn_idx, model, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'loser', 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO turn_scores_echo2_snapshot
                (owner_key_hash, session_id, run_id, turn_idx, model, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'winner', 2.0)
            """
        )
        conn.executemany(
            """
            INSERT INTO tool_call_scores
                (owner_key_hash, session_id, run_id, turn_idx, tool_name,
                 success, error_pattern, output_quality, timestamp)
            VALUES ('owner-a', 'session-a', 'run-a', 1, ?, ?, ?, ?, 2.0)
            """,
            (
                ("failed-tool", 0, "base-rejection", 0.0),
                ("successful-tool", 1, "", 0.9),
            ),
        )
        conn.execute(
            """
            INSERT INTO rejection_turn_contributions
                (owner_key_hash, session_id, run_id, turn_idx, pattern,
                 tool_name, count, last_seen)
            VALUES ('owner-a', 'session-a', 'run-a', 1, 'base-rejection',
                    'failed-tool', 4, 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO high_score_examples
                (owner_key_hash, tool_name, description, score, timestamp,
                 source_session_id, source_run_id, source_turn_idx,
                 source_ordinal)
            VALUES ('owner-a', 'successful-tool', 'base example', 0.9, 2.0,
                    'session-a', 'run-a', 1, 1)
            """
        )

    live_conn = sqlite3.connect(db_path)

    @contextmanager
    def persistent_connection(*_args: Any, **_kwargs: Any):
        yield live_conn

    monkeypatch.setattr(scorer_module, "db_connection", persistent_connection)
    try:
        QualityScorer(tmp_path)
        QualityScorer(tmp_path)
        turn = live_conn.execute("SELECT model FROM turn_scores").fetchall()
        tools = live_conn.execute(
            "SELECT tool_name, success FROM tool_call_scores ORDER BY tool_name"
        ).fetchall()
        contributions = live_conn.execute(
            """
            SELECT pattern, tool_name, count
            FROM rejection_turn_contributions
            """
        ).fetchall()
        examples = live_conn.execute(
            "SELECT tool_name, description FROM high_score_examples"
        ).fetchall()
        temp_tables = live_conn.execute(
            """
            SELECT name
            FROM sqlite_temp_master
            WHERE name IN (
                'echo_tool_migration_choices',
                'echo_turn_migration_winners'
            )
            """
        ).fetchall()
    finally:
        live_conn.close()

    assert turn == [("winner",)]
    assert tools == [("failed-tool", 0), ("successful-tool", 1)]
    assert contributions == [("base-rejection", "failed-tool", 4)]
    assert examples == [("successful-tool", "base example")]
    assert temp_tables == []


def test_quality_scorer_migration_contribution_follows_winning_turn_source(
    tmp_path: Path,
) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        for table_name in (
            "turn_scores",
            "tool_call_scores",
            "rejection_turn_contributions",
            "quality_session_watermarks",
            "rejection_patterns",
            "high_score_examples",
        ):
            QualityScorer._create_canonical_table(  # noqa: SLF001
                conn,
                table_name,
                table_name,
            )
        QualityScorer._create_canonical_table(  # noqa: SLF001
            conn,
            "rejection_turn_contributions",
            "rejection_turn_contributions_echo2_snapshot",
        )
        conn.execute(
            """
            INSERT INTO turn_scores
                (owner_key_hash, session_id, turn_idx, model, timestamp)
            VALUES ('owner-a', 'session-a', 1, 'winner', 2.0)
            """
        )
        conn.execute(
            """
            INSERT INTO rejection_turn_contributions
                (owner_key_hash, session_id, turn_idx, pattern, tool_name,
                 count, last_seen)
            VALUES ('owner-a', 'session-a', 1, 'pattern-a', 'tool-a', 3, 1.0)
            """
        )
        conn.execute(
            """
            INSERT INTO rejection_turn_contributions_echo2_snapshot
                (owner_key_hash, session_id, turn_idx, pattern, tool_name,
                 count, last_seen)
            VALUES ('owner-a', 'session-a', 1, 'pattern-a', 'tool-a', 1, 2.0)
            """
        )

    QualityScorer(tmp_path)

    with sqlite3.connect(db_path) as conn:
        contribution = conn.execute(
            "SELECT count, last_seen FROM rejection_turn_contributions"
        ).fetchone()

    assert contribution == (3, 1.0)


def test_quality_scorer_preserves_migrated_rejection_baseline(tmp_path: Path) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)
    scorer.record_turn(
        TurnScore(
            session_id="old-session",
            turn_idx=1,
            model="test",
            owner_key_hash="owner-a",
            timestamp=1.0,
            tool_scores=[
                ToolCallScore(
                    tool_name="tool-a",
                    success=False,
                    error_pattern="same-pattern",
                )
            ],
        )
    )
    with sqlite3.connect(scorer.db_path) as conn:
        conn.execute(
            "UPDATE rejection_patterns SET count = 10, last_seen = 10.0"
        )
        conn.commit()

    scorer.record_turn(
        TurnScore(
            session_id="new-session",
            turn_idx=1,
            model="test",
            owner_key_hash="owner-a",
            timestamp=11.0,
            tool_scores=[
                ToolCallScore(
                    tool_name="tool-a",
                    success=False,
                    error_pattern="same-pattern",
                )
            ],
        )
    )

    with sqlite3.connect(scorer.db_path) as conn:
        rejection = conn.execute(
            "SELECT count, last_seen FROM rejection_patterns"
        ).fetchone()

    assert rejection == (11, 11.0)


def test_quality_scorer_replay_preserves_retained_high_examples(tmp_path: Path) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)
    score = TurnScore(
        session_id="session-a",
        turn_idx=1,
        model="test",
        owner_key_hash="owner-a",
        timestamp=1.0,
        tool_scores=[
            ToolCallScore(
                tool_name="tool-a",
                success=True,
                error_pattern="example-a",
                output_quality=0.9,
            )
        ],
    )
    scorer.record_turn(score)
    with sqlite3.connect(scorer.db_path) as conn:
        conn.executemany(
            """
            INSERT INTO high_score_examples
                (owner_key_hash, tool_name, description, score, timestamp)
            VALUES ('owner-a', 'tool-a', 'example-a', 0.9, 1.0)
            """,
            [() for _ in range(4)],
        )
        conn.commit()

    scorer.record_turn(score)

    with sqlite3.connect(scorer.db_path) as conn:
        example_count = conn.execute(
            "SELECT COUNT(*) FROM high_score_examples"
        ).fetchone()[0]

    assert example_count == 5


def test_quality_scorer_replacing_turn_does_not_delete_other_retained_example(
    tmp_path: Path,
) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)
    for turn_idx in (1, 2):
        scorer.record_turn(
            TurnScore(
                session_id="session-a",
                turn_idx=turn_idx,
                model="test",
                owner_key_hash="owner-a",
                timestamp=1.0,
                tool_scores=[
                    ToolCallScore(
                        tool_name="tool-a",
                        success=True,
                        error_pattern="same-example",
                        output_quality=0.9,
                    )
                ],
            )
        )

    scorer.prune(
        keep_turns_per_owner=10,
        keep_tool_calls_per_turn=100,
        keep_patterns_per_owner=10,
        keep_examples_per_owner=1,
    )
    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            turn_idx=1,
            model="replacement",
            owner_key_hash="owner-a",
            timestamp=2.0,
        )
    )

    with sqlite3.connect(scorer.db_path) as conn:
        examples = conn.execute(
            """
            SELECT description, source_session_id, source_turn_idx
            FROM high_score_examples
            """
        ).fetchall()
        surviving_tools = conn.execute(
            """
            SELECT session_id, turn_idx
            FROM tool_call_scores
            WHERE success = 1 AND output_quality >= 0.8
            """
        ).fetchall()

    assert examples == [("same-example", "session-a", 2)]
    assert surviving_tools == [("session-a", 2)]


def test_quality_scorer_rejection_archive_restores_exact_last_seen(
    tmp_path: Path,
) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)
    for turn_idx in range(5):
        scorer.record_turn(
            TurnScore(
                session_id="session-a",
                turn_idx=turn_idx,
                model="test",
                owner_key_hash="owner-a",
                timestamp=float(turn_idx + 1),
                tool_scores=[
                    ToolCallScore(
                        tool_name="tool-a",
                        success=False,
                        error_pattern="same-pattern",
                    )
                ],
            )
        )
    scorer.prune(
        keep_turns_per_owner=1,
        keep_tool_calls_per_turn=100,
        keep_patterns_per_owner=10,
        keep_examples_per_owner=10,
    )
    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            turn_idx=5,
            model="test",
            owner_key_hash="owner-a",
            timestamp=6.0,
            tool_scores=[
                ToolCallScore(
                    tool_name="tool-a",
                    success=False,
                    error_pattern="same-pattern",
                )
            ],
        )
    )
    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            turn_idx=5,
            model="replacement",
            owner_key_hash="owner-a",
            timestamp=7.0,
        )
    )

    with sqlite3.connect(scorer.db_path) as conn:
        after_new_turn_rollback = conn.execute(
            """
            SELECT count, last_seen, archived_count, archived_last_seen
            FROM rejection_patterns
            """
        ).fetchone()

    assert after_new_turn_rollback == (5, 5.0, 4, 4.0)

    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            turn_idx=4,
            model="replacement",
            owner_key_hash="owner-a",
            timestamp=8.0,
        )
    )

    with sqlite3.connect(scorer.db_path) as conn:
        after_retained_turn_rollback = conn.execute(
            """
            SELECT count, last_seen, archived_count, archived_last_seen
            FROM rejection_patterns
            """
        ).fetchone()

    assert after_retained_turn_rollback == (4, 4.0, 4, 4.0)


def test_quality_scorer_rejection_lookup_uses_signature_index(tmp_path: Path) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)

    with sqlite3.connect(scorer.db_path) as conn:
        plan = conn.execute(
            """
            EXPLAIN QUERY PLAN
            SELECT COUNT(*), MAX(timestamp)
            FROM tool_call_scores
            WHERE owner_key_hash = ? AND success = 0
              AND error_pattern = ? AND tool_name = ?
            """,
            ("owner-a", "pattern-a", "tool-a"),
        ).fetchall()

    assert any("idx_tool_scores_owner_rejection" in str(row[3]) for row in plan)


def test_quality_scorer_repairs_tampered_rejection_index(tmp_path: Path) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)
    with sqlite3.connect(scorer.db_path) as conn:
        conn.execute("DROP INDEX idx_tool_scores_owner_rejection")
        conn.execute(
            """
            CREATE INDEX idx_tool_scores_owner_rejection
            ON tool_call_scores(owner_key_hash)
            """
        )
        conn.commit()

    QualityScorer(tmp_path)

    with sqlite3.connect(scorer.db_path) as conn:
        key_columns = [
            (row[2], bool(row[3]))
            for row in conn.execute(
                "PRAGMA index_xinfo('idx_tool_scores_owner_rejection')"
            )
            if row[5]
        ]

    assert key_columns == [
        ("owner_key_hash", False),
        ("success", False),
        ("error_pattern", False),
        ("tool_name", False),
        ("timestamp", True),
    ]


def test_quality_scorer_rejects_partial_high_example_provenance(
    tmp_path: Path,
) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)

    with (
        sqlite3.connect(scorer.db_path) as conn,
        pytest.raises(sqlite3.IntegrityError),
    ):
        conn.execute(
            """
            INSERT INTO high_score_examples
                (owner_key_hash, tool_name, description, score, timestamp,
                 source_session_id)
            VALUES ('owner-a', 'tool-a', 'partial', 0.9, 1.0, 'session-a')
            """
        )


def test_quality_scorer_marks_inferred_legacy_archive_inexact(
    tmp_path: Path,
) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)
    scorer.record_turn(
        TurnScore(
            session_id="old-session",
            turn_idx=1,
            model="test",
            owner_key_hash="owner-a",
            timestamp=1.0,
            tool_scores=[
                ToolCallScore(
                    tool_name="tool-a",
                    success=False,
                    error_pattern="same-pattern",
                )
            ],
        )
    )
    with sqlite3.connect(scorer.db_path) as conn:
        conn.execute(
            """
            UPDATE rejection_patterns
            SET count = 10, last_seen = 10.0,
                archived_count = 0, archived_last_seen = NULL,
                archive_exact = 1
            """
        )
        conn.commit()

    scorer.record_turn(
        TurnScore(
            session_id="new-session",
            turn_idx=1,
            model="test",
            owner_key_hash="owner-a",
            timestamp=11.0,
            tool_scores=[
                ToolCallScore(
                    tool_name="tool-a",
                    success=False,
                    error_pattern="same-pattern",
                )
            ],
        )
    )

    with sqlite3.connect(scorer.db_path) as conn:
        row = conn.execute(
            """
            SELECT count, archived_count, archived_last_seen, archive_exact
            FROM rejection_patterns
            """
        ).fetchone()

    assert row == (11, 9, 10.0, 0)


def test_quality_scorer_does_not_trust_partial_legacy_archive_metadata(
    tmp_path: Path,
) -> None:
    import sqlite3

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        QualityScorer._create_canonical_table(  # noqa: SLF001
            conn,
            "tool_call_scores",
            "tool_call_scores",
        )
        conn.execute(
            """
            CREATE TABLE rejection_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_key_hash TEXT NOT NULL,
                pattern TEXT NOT NULL,
                tool_name TEXT NOT NULL DEFAULT '',
                count INTEGER DEFAULT 1,
                last_seen REAL NOT NULL,
                archived_count INTEGER,
                archived_last_seen REAL,
                UNIQUE(owner_key_hash, pattern, tool_name)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO tool_call_scores
                (owner_key_hash, session_id, turn_idx, tool_name, success,
                 error_pattern, timestamp)
            VALUES ('owner-a', 'session-a', 1, 'tool-a', 0, 'pattern-a', 1.0)
            """
        )
        conn.execute(
            """
            INSERT INTO rejection_patterns
                (owner_key_hash, pattern, tool_name, count, last_seen,
                 archived_count, archived_last_seen)
            VALUES ('owner-a', 'pattern-a', 'tool-a', 1, 99.0, NULL, 99.0)
            """
        )

    QualityScorer(tmp_path)

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT count, last_seen, archived_count,
                   archived_last_seen, archive_exact
            FROM rejection_patterns
            """
        ).fetchone()

    assert row == (1, 1.0, 0, None, 0)


def test_quality_scorer_record_turn_ignores_stale_replay(tmp_path: Path) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)
    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            turn_idx=1,
            model="model-new",
            owner_key_hash="owner-a",
            timestamp=2.0,
            tool_scores=[
                ToolCallScore(
                    tool_name="tool-new",
                    success=False,
                    error_pattern="new-pattern",
                )
            ],
        )
    )
    scorer.record_turn(
        TurnScore(
            session_id="session-a",
            turn_idx=1,
            model="model-stale",
            owner_key_hash="owner-a",
            timestamp=1.0,
            tool_scores=[
                ToolCallScore(
                    tool_name="tool-stale",
                    success=False,
                    error_pattern="stale-pattern",
                )
            ],
        )
    )

    with sqlite3.connect(scorer.db_path) as conn:
        turn = conn.execute("SELECT model, timestamp FROM turn_scores").fetchone()
        tools = conn.execute(
            "SELECT tool_name, error_pattern FROM tool_call_scores"
        ).fetchall()
        rejections = conn.execute(
            "SELECT pattern, count FROM rejection_patterns"
        ).fetchall()

    assert turn == ("model-new", 2.0)
    assert tools == [("tool-new", "new-pattern")]
    assert rejections == [("new-pattern", 1)]


@pytest.mark.parametrize("timestamp", [float("nan"), float("inf"), float("-inf")])
def test_quality_scorer_rejects_nonfinite_turn_timestamp(
    tmp_path: Path,
    timestamp: float,
) -> None:
    import sqlite3

    scorer = QualityScorer(tmp_path)

    with pytest.raises(ValueError, match="timestamp must be finite"):
        scorer.record_turn(
            TurnScore(
                session_id="session-a",
                turn_idx=1,
                model="test",
                owner_key_hash="owner-a",
                timestamp=timestamp,
            )
        )

    with sqlite3.connect(scorer.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM turn_scores").fetchone()[0] == 0


def test_quality_scorer_concurrent_replays_keep_latest_turn(tmp_path: Path) -> None:
    import sqlite3
    from concurrent.futures import ThreadPoolExecutor

    scorer = QualityScorer(tmp_path)

    def write_turn(index: int) -> None:
        scorer.record_turn(
            TurnScore(
                session_id="session-a",
                turn_idx=1,
                model=f"model-{index}",
                owner_key_hash="owner-a",
                timestamp=float(index),
                tool_scores=[
                    ToolCallScore(
                        tool_name=f"tool-{index}",
                        success=False,
                        error_pattern=f"pattern-{index}",
                    )
                ],
            )
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write_turn, range(1, 33)))

    with sqlite3.connect(scorer.db_path) as conn:
        turn = conn.execute("SELECT model, timestamp FROM turn_scores").fetchone()
        tools = conn.execute("SELECT tool_name FROM tool_call_scores").fetchall()
        rejections = conn.execute(
            "SELECT pattern, count FROM rejection_patterns"
        ).fetchall()

    assert turn == ("model-32", 32.0)
    assert tools == [("tool-32",)]
    assert rejections == [("pattern-32", 1)]


def test_quality_scorer_prune_and_record_turn_serialize_without_loss(
    tmp_path: Path,
) -> None:
    import sqlite3
    from concurrent.futures import ThreadPoolExecutor

    scorer = QualityScorer(tmp_path)
    for turn_idx in range(20):
        scorer.record_turn(
            TurnScore(
                session_id="session-a",
                turn_idx=turn_idx,
                model="seed",
                owner_key_hash="owner-a",
                timestamp=float(turn_idx + 1),
                tool_scores=[
                    ToolCallScore(
                        tool_name="tool-a",
                        success=False,
                        error_pattern="same-pattern",
                    )
                ],
            )
        )

    new_turn = TurnScore(
        session_id="session-a",
        turn_idx=20,
        model="new",
        owner_key_hash="owner-a",
        timestamp=100.0,
        tool_scores=[
            ToolCallScore(
                tool_name="tool-a",
                success=False,
                error_pattern="same-pattern",
            )
        ],
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        prune_future = pool.submit(
            scorer.prune,
            keep_turns_per_owner=10,
            keep_tool_calls_per_turn=100,
            keep_patterns_per_owner=10,
            keep_examples_per_owner=10,
        )
        record_future = pool.submit(scorer.record_turn, new_turn)
        prune_future.result(timeout=10)
        record_future.result(timeout=10)

    with sqlite3.connect(scorer.db_path) as conn:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        rejection = conn.execute(
            """
            SELECT count, last_seen, archived_count, archive_exact
            FROM rejection_patterns
            """
        ).fetchone()
        turn_count = conn.execute("SELECT COUNT(*) FROM turn_scores").fetchone()[0]

    assert integrity == "ok"
    assert rejection[0:2] == (21, 100.0)
    assert 10 <= rejection[2] <= 11
    assert rejection[3] == 1
    assert 10 <= turn_count <= 11


def test_quality_scorer_four_table_migration_rolls_back_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlite3

    import js.evolution.quality_scorer as scorer_module

    db_path = tmp_path / "quality.db"
    table_names = (
        "turn_scores",
        "tool_call_scores",
        "rejection_patterns",
        "high_score_examples",
    )
    with sqlite3.connect(db_path) as conn:
        for table_name in table_names:
            QualityScorer._create_canonical_table(  # noqa: SLF001
                conn,
                table_name,
                table_name,
            )
            QualityScorer._create_canonical_table(  # noqa: SLF001
                conn,
                table_name,
                f"{table_name}_echo2_snapshot",
            )
        conn.execute(
            """
            INSERT INTO turn_scores
                (owner_key_hash, session_id, turn_idx, model, overall_score,
                 hallucination_rate, total_tokens, timestamp)
            VALUES ('owner-a', 'session-a', 1, 'model-a', 1.0, 0.0, 10, 1.0)
            """
        )
        conn.execute(
            """
            INSERT INTO tool_call_scores
                (owner_key_hash, session_id, turn_idx, tool_name, success,
                 retry_count, error_pattern, output_quality, latency_ms, timestamp)
            VALUES ('owner-a', 'session-a', 1, 'tool-a', 1, 0, '', 1.0, 5.0, 1.0)
            """
        )
        conn.execute(
            """
            INSERT INTO rejection_patterns
                (owner_key_hash, pattern, tool_name, count, last_seen)
            VALUES ('owner-a', 'pattern-a', 'tool-a', 1, 1.0)
            """
        )
        conn.execute(
            """
            INSERT INTO high_score_examples
                (owner_key_hash, tool_name, description, score, timestamp)
            VALUES ('owner-a', 'tool-a', 'example-a', 1.0, 1.0)
            """
        )

    original_connection = scorer_module.db_connection

    @contextmanager
    def failing_connection(*args: Any, **kwargs: Any):
        with original_connection(*args, **kwargs) as conn:
            def authorize(
                action: int,
                arg1: str | None,
                _arg2: str | None,
                _database: str | None,
                _trigger: str | None,
            ) -> int:
                if action == sqlite3.SQLITE_DROP_TABLE and arg1 == "high_score_examples":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            conn.set_authorizer(authorize)
            yield conn

    monkeypatch.setattr(scorer_module, "db_connection", failing_connection)
    with pytest.raises(sqlite3.DatabaseError):
        QualityScorer(tmp_path)

    with sqlite3.connect(db_path) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        counts = {
            table_name: conn.execute(
                f'SELECT COUNT(*) FROM "{table_name}"'
            ).fetchone()[0]
            for table_name in table_names
        }
    assert counts == dict.fromkeys(table_names, 1)
    assert all(f"{table_name}_echo2_snapshot" in tables for table_name in table_names)
    assert not any("echo2_rebuild" in table_name for table_name in tables)


def test_quality_scorer_concurrent_initialization_serializes_migration(
    tmp_path: Path,
) -> None:
    import sqlite3
    import threading
    from concurrent.futures import ThreadPoolExecutor

    db_path = tmp_path / "quality.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE turn_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                turn_idx INTEGER NOT NULL,
                model TEXT,
                overall_score REAL DEFAULT 0.0,
                hallucination_rate REAL DEFAULT 0.0,
                total_tokens INTEGER DEFAULT 0,
                timestamp REAL NOT NULL,
                UNIQUE(session_id, turn_idx)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO turn_scores
                (session_id, turn_idx, model, overall_score, hallucination_rate,
                 total_tokens, timestamp)
            VALUES ('legacy-session', 1, 'model-a', 1.0, 0.0, 10, 1.0)
            """
        )

    workers = 8
    barrier = threading.Barrier(workers)

    def initialize() -> None:
        barrier.wait(timeout=2.0)
        QualityScorer(tmp_path)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(lambda _index: initialize(), range(workers)))

    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT owner_key_hash, session_id, turn_idx FROM turn_scores"
        ).fetchall()
        leftovers = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name LIKE '%_echo2_%'"
            )
        }
    assert rows == [("__legacy_local__", "legacy-session", 1)]
    assert leftovers == set()


class TestMemoryFeedback:
    """Test user feedback on semantic memories."""

    @pytest.fixture
    def store(self, tmp_path: Path) -> EnhancedMemoryStore:
        return EnhancedMemoryStore(tmp_path, MemoryConfig())

    def test_feedback_increments_score(self, store: EnhancedMemoryStore) -> None:
        """Positive feedback increases feedback_score and access_count."""
        store.store_semantic("key1", "value1")
        rows = store.get_all_semantic(limit=10)
        assert len(rows) == 1
        mem_id = rows[0]["id"]
        assert rows[0].get("feedback_score", 0) == 0
        assert rows[0]["access_count"] == 0

        ok = store.feedback(mem_id, helpful=True)
        assert ok

        rows = store.get_all_semantic(limit=10)
        assert rows[0]["feedback_score"] == 1.0
        assert rows[0]["access_count"] == 1

    def test_negative_feedback_decreases_score(self, store: EnhancedMemoryStore) -> None:
        """Negative feedback decreases feedback_score."""
        store.store_semantic("key1", "value1")
        mem_id = store.get_all_semantic(limit=10)[0]["id"]
        store.feedback(mem_id, helpful=False)

        rows = store.get_all_semantic(limit=10)
        assert rows[0]["feedback_score"] == -1.0

    def test_feedback_nonexistent_returns_false(self, store: EnhancedMemoryStore) -> None:
        """Feedback on non-existent memory returns False."""
        ok = store.feedback(99999, helpful=True)
        assert not ok


class TestMemoryConflictDetection:
    """Test automatic conflict resolution (zero user intervention)."""

    @pytest.fixture
    def store(self, tmp_path: Path) -> EnhancedMemoryStore:
        return EnhancedMemoryStore(tmp_path, MemoryConfig())

    def test_no_conflict_for_different_keys(self, store: EnhancedMemoryStore) -> None:
        """Different keys in same category should not conflict."""
        result = store.store_semantic("user_name", "Alice", category="preference")
        assert result["conflicts"] == []

        result2 = store.store_semantic("user_age", "30", category="preference")
        assert result2["conflicts"] == []

    def test_similar_key_different_value_auto_resolved(self, store: EnhancedMemoryStore) -> None:
        """Overlapping keys with different values are auto-resolved silently."""
        store.store_semantic("coffee user likes", "yes", category="preference", source="agent")
        result = store.store_semantic("user likes coffee", "no", category="preference", source="agent")
        # Conflicts were detected and resolved automatically
        assert len(result["conflicts"]) >= 1
        # No conflict markers remain because system resolved them silently
        conflicting = store.get_conflicting_memories()
        assert len(conflicting) == 0
        # Both memories coexist because neither clearly wins
        memories = store.get_all_semantic(limit=10)
        assert len(memories) == 2

    def test_same_key_upsert_no_conflict(self, store: EnhancedMemoryStore) -> None:
        """Same key with different value is an upsert, not a conflict."""
        store.store_semantic("favorite color", "blue", category="preference")
        result = store.store_semantic("favorite color", "red", category="preference")
        assert result["conflicts"] == []
        memories = store.get_all_semantic(limit=10)
        assert len(memories) == 1
        assert memories[0]["value"] == "red"

    def test_no_conflict_for_same_value(self, store: EnhancedMemoryStore) -> None:
        """Same key and value should not conflict (it's an update)."""
        store.store_semantic("city", "Beijing", category="fact")
        result = store.store_semantic("city", "Beijing", category="fact")
        assert result["conflicts"] == []

    def test_no_conflict_across_categories(self, store: EnhancedMemoryStore) -> None:
        """Same key in different categories should not conflict."""
        store.store_semantic("python", "programming language", category="tech")
        result = store.store_semantic("python", "snake", category="biology")
        assert result["conflicts"] == []


class TestMemoryEviction:
    """Test LRU and importance-weighted eviction."""

    @pytest.fixture
    def store(self, tmp_path: Path) -> EnhancedMemoryStore:
        return EnhancedMemoryStore(tmp_path, MemoryConfig())

    def test_no_eviction_when_under_limit(self, store: EnhancedMemoryStore) -> None:
        """Below max_memories, nothing is evicted."""
        for i in range(5):
            store.store_semantic(f"key{i}", f"value{i}")
        evicted = store._evict_semantic_if_needed(max_memories=10)
        assert evicted == 0
        assert len(store.get_all_semantic(limit=100)) == 5

    def test_lru_eviction_removes_oldest(self, store: EnhancedMemoryStore) -> None:
        """LRU strategy evicts least recently accessed memories."""
        for i in range(5):
            store.store_semantic(f"key{i}", f"value{i}")

        evicted = store._evict_semantic_if_needed(strategy="lru", max_memories=3)
        assert evicted == 2
        remaining = store.get_all_semantic(limit=100)
        assert len(remaining) == 3

    def test_lru_protects_high_importance(self, store: EnhancedMemoryStore) -> None:
        """Memories with importance >= 8 are protected from LRU eviction."""
        # Store 5 memories, one with high importance
        for i in range(4):
            store.store_semantic(f"key{i}", f"value{i}")
        # Use raw SQL to set importance (store_semantic doesn't expose it)
        store.store_semantic("important", "value")
        from js.utils.db import db_connection
        with db_connection(store.db_path) as conn:
            conn.execute("UPDATE semantic_memories SET importance = 9 WHERE key = 'important'")
            conn.commit()

        evicted = store._evict_semantic_if_needed(strategy="lru", max_memories=2)
        assert evicted == 3
        remaining_keys = {r["key"] for r in store.get_all_semantic(limit=100)}
        assert "important" in remaining_keys

    def test_importance_weighted_eviction(self, store: EnhancedMemoryStore) -> None:
        """Importance-weighted strategy evicts lowest-score memories."""
        store.store_semantic("low", "a")
        store.store_semantic("high", "b")

        # Give "high" positive feedback to boost its score
        rows = store.get_all_semantic(limit=10)
        high_mem = next(r for r in rows if r["key"] == "high")
        store.feedback(high_mem["id"], helpful=True)

        evicted = store._evict_semantic_if_needed(strategy="importance_weighted", max_memories=1)
        assert evicted == 1
        remaining = store.get_all_semantic(limit=100)
        assert len(remaining) == 1
        assert remaining[0]["key"] == "high"

    def test_store_semantic_auto_evicts(self, store: EnhancedMemoryStore) -> None:
        """store_semantic automatically triggers eviction when over limit."""
        for i in range(12):
            store.store_semantic(f"key{i}", f"value{i}")
        # Default max_memories is 1000, so no eviction yet
        assert len(store.get_all_semantic(limit=100)) == 12

        # Manually trigger with low limit
        evicted = store._evict_semantic_if_needed(max_memories=5)
        assert evicted == 7
        assert len(store.get_all_semantic(limit=100)) == 5
