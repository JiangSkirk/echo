"""Quality scoring and self-learning闭环 (OpenHuman-inspired).

Tracks per-agent output quality, extracts rejection patterns, and builds
a learning-context block that is injected into the system prompt.
"""

from __future__ import annotations

import math
import sqlite3
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from js.utils.db import db_connection
from js.utils.log import get_logger

logger = get_logger("js.evolution.quality")

_LEGACY_OWNER = "__legacy_local__"
_LEGACY_RUN = "__legacy_run__"
_MAX_WATERMARKS_PER_OWNER = 100_000
_SATURATED_SESSION = "__echo_quality_saturated__"
_SATURATED_RUN = "__all_runs__"

_CANONICAL_COLUMN_SPECS: dict[
    str,
    tuple[tuple[str, str, int, str | None, int], ...],
] = {
    "turn_scores": (
        ("id", "INTEGER", 0, None, 1),
        ("owner_key_hash", "TEXT", 1, None, 0),
        ("session_id", "TEXT", 1, None, 0),
        ("run_id", "TEXT", 1, "'__legacy_run__'", 0),
        ("turn_idx", "INTEGER", 1, None, 0),
        ("model", "TEXT", 0, None, 0),
        ("overall_score", "REAL", 0, "0.0", 0),
        ("hallucination_rate", "REAL", 0, "0.0", 0),
        ("total_tokens", "INTEGER", 0, "0", 0),
        ("timestamp", "REAL", 1, None, 0),
    ),
    "tool_call_scores": (
        ("id", "INTEGER", 0, None, 1),
        ("owner_key_hash", "TEXT", 1, None, 0),
        ("session_id", "TEXT", 1, None, 0),
        ("run_id", "TEXT", 1, "'__legacy_run__'", 0),
        ("turn_idx", "INTEGER", 1, None, 0),
        ("tool_name", "TEXT", 1, None, 0),
        ("success", "INTEGER", 0, "0", 0),
        ("retry_count", "INTEGER", 0, "0", 0),
        ("error_pattern", "TEXT", 0, "''", 0),
        ("output_quality", "REAL", 0, "0.0", 0),
        ("latency_ms", "REAL", 0, "0.0", 0),
        ("timestamp", "REAL", 1, None, 0),
    ),
    "rejection_turn_contributions": (
        ("id", "INTEGER", 0, None, 1),
        ("owner_key_hash", "TEXT", 1, None, 0),
        ("session_id", "TEXT", 1, None, 0),
        ("run_id", "TEXT", 1, "'__legacy_run__'", 0),
        ("turn_idx", "INTEGER", 1, None, 0),
        ("pattern", "TEXT", 1, None, 0),
        ("tool_name", "TEXT", 1, "''", 0),
        ("count", "INTEGER", 1, "1", 0),
        ("last_seen", "REAL", 1, None, 0),
    ),
    "quality_session_watermarks": (
        ("id", "INTEGER", 0, None, 1),
        ("owner_key_hash", "TEXT", 1, None, 0),
        ("session_id", "TEXT", 1, None, 0),
        ("run_id", "TEXT", 1, "'__legacy_run__'", 0),
        ("pruned_through_turn_idx", "INTEGER", 1, None, 0),
        ("pruned_through_timestamp", "REAL", 1, None, 0),
    ),
    "rejection_patterns": (
        ("id", "INTEGER", 0, None, 1),
        ("owner_key_hash", "TEXT", 1, None, 0),
        ("pattern", "TEXT", 1, None, 0),
        ("tool_name", "TEXT", 1, "''", 0),
        ("count", "INTEGER", 0, "1", 0),
        ("last_seen", "REAL", 1, None, 0),
        ("archived_count", "INTEGER", 1, "0", 0),
        ("archived_last_seen", "REAL", 0, None, 0),
        ("archive_exact", "INTEGER", 1, "1", 0),
    ),
    "high_score_examples": (
        ("id", "INTEGER", 0, None, 1),
        ("owner_key_hash", "TEXT", 1, None, 0),
        ("tool_name", "TEXT", 0, None, 0),
        ("description", "TEXT", 0, None, 0),
        ("score", "REAL", 0, "0.0", 0),
        ("timestamp", "REAL", 1, None, 0),
        ("source_session_id", "TEXT", 0, None, 0),
        ("source_run_id", "TEXT", 0, None, 0),
        ("source_turn_idx", "INTEGER", 0, None, 0),
        ("source_ordinal", "INTEGER", 0, None, 0),
    ),
}

_HIGH_SCORE_PROVENANCE_CHECK = " ".join(
    """
    CHECK (
        (source_session_id IS NULL AND source_run_id IS NULL
         AND source_turn_idx IS NULL AND source_ordinal IS NULL)
        OR
        (source_session_id IS NOT NULL AND source_run_id IS NOT NULL
         AND source_turn_idx IS NOT NULL AND source_ordinal IS NOT NULL
         AND source_ordinal >= 0)
    )
    """.upper().split()
)

_CANONICAL_UNIQUE_KEYS: dict[str, tuple[tuple[str, ...], ...]] = {
    "turn_scores": (("owner_key_hash", "session_id", "run_id", "turn_idx"),),
    "tool_call_scores": (),
    "rejection_turn_contributions": (
        (
            "owner_key_hash",
            "session_id",
            "run_id",
            "turn_idx",
            "pattern",
            "tool_name",
        ),
    ),
    "quality_session_watermarks": (("owner_key_hash", "session_id", "run_id"),),
    "rejection_patterns": (("owner_key_hash", "pattern", "tool_name"),),
    "high_score_examples": (
        (
            "owner_key_hash",
            "source_session_id",
            "source_run_id",
            "source_turn_idx",
            "source_ordinal",
        ),
    ),
}


@dataclass
class ToolCallScore:
    """Score for a single tool call."""

    tool_name: str
    success: bool
    retry_count: int = 0
    error_pattern: str = ""
    output_quality: float = 0.0  # 0.0-1.0
    latency_ms: float = 0.0


@dataclass
class TurnScore:
    """Score for a full agent turn."""

    session_id: str
    turn_idx: int
    model: str
    owner_key_hash: str = _LEGACY_OWNER
    run_id: str = _LEGACY_RUN
    tool_scores: list[ToolCallScore] = field(default_factory=list)
    hallucination_flags: list[str] = field(default_factory=list)
    total_tokens: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def overall_score(self) -> float:
        """Composite quality score (0.0-1.0)."""
        if not self.tool_scores:
            return 1.0
        success_rate = sum(1 for t in self.tool_scores if t.success) / len(self.tool_scores)
        retry_penalty = max(0, 1.0 - sum(t.retry_count for t in self.tool_scores) * 0.1)
        return min(1.0, success_rate * 0.6 + retry_penalty * 0.4)

    @property
    def hallucination_rate(self) -> float:
        return len(self.hallucination_flags) / max(len(self.tool_scores), 1)


class QualityScorer:
    """Scores agent output and maintains historical quality data."""

    def __init__(self, state_dir: Path) -> None:
        self.db_path = state_dir / "quality.db"
        self._init_db()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with db_connection(self.db_path) as conn:
            conn.execute("PRAGMA temp_store = FILE")
            conn.execute("BEGIN IMMEDIATE")
            try:
                self._prepare_turn_migration_winners(conn)
                self._prepare_tool_migration_choices(
                    conn,
                    self._migration_sources(conn, "tool_call_scores"),
                )
                rebuilt_tables: set[str] = set()
                for table_name in (
                    "turn_scores",
                    "tool_call_scores",
                    "rejection_turn_contributions",
                    "quality_session_watermarks",
                    "rejection_patterns",
                    "high_score_examples",
                ):
                    if self._ensure_canonical_table(conn, table_name):
                        rebuilt_tables.add(table_name)
                self._ensure_nonunique_index(
                    conn,
                    "idx_turn_scores_owner_recent",
                    "turn_scores",
                    (("owner_key_hash", False), ("timestamp", True), ("id", True)),
                )
                self._ensure_nonunique_index(
                    conn,
                    "idx_tool_scores_owner_turn",
                    "tool_call_scores",
                    (
                        ("owner_key_hash", False),
                        ("session_id", False),
                        ("run_id", False),
                        ("turn_idx", False),
                        ("timestamp", True),
                        ("id", True),
                    ),
                )
                self._ensure_nonunique_index(
                    conn,
                    "idx_tool_scores_owner_rejection",
                    "tool_call_scores",
                    (
                        ("owner_key_hash", False),
                        ("success", False),
                        ("error_pattern", False),
                        ("tool_name", False),
                        ("timestamp", True),
                    ),
                )
                self._ensure_nonunique_index(
                    conn,
                    "idx_rejection_contributions_signature",
                    "rejection_turn_contributions",
                    (
                        ("owner_key_hash", False),
                        ("pattern", False),
                        ("tool_name", False),
                        ("last_seen", True),
                    ),
                )
                self._ensure_nonunique_index(
                    conn,
                    "idx_rejection_contributions_turn",
                    "rejection_turn_contributions",
                    (
                        ("owner_key_hash", False),
                        ("session_id", False),
                        ("run_id", False),
                        ("turn_idx", False),
                    ),
                )
                self._ensure_nonunique_index(
                    conn,
                    "idx_quality_watermarks_owner_recent",
                    "quality_session_watermarks",
                    (
                        ("owner_key_hash", False),
                        ("pruned_through_timestamp", True),
                        ("id", True),
                    ),
                )
                self._ensure_nonunique_index(
                    conn,
                    "idx_rejections_owner_rank",
                    "rejection_patterns",
                    (("owner_key_hash", False), ("count", True), ("last_seen", True)),
                )
                self._ensure_nonunique_index(
                    conn,
                    "idx_examples_owner_rank",
                    "high_score_examples",
                    (("owner_key_hash", False), ("score", True), ("timestamp", True)),
                )
                if rebuilt_tables & {
                    "turn_scores",
                    "tool_call_scores",
                    "rejection_turn_contributions",
                    "rejection_patterns",
                    "high_score_examples",
                }:
                    self._normalize_rejection_patterns(conn)
                conn.execute(
                    "DROP TABLE IF EXISTS temp.echo_tool_migration_choices"
                )
                conn.execute(
                    "DROP TABLE IF EXISTS temp.echo_turn_migration_winners"
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    @staticmethod
    def _quote_identifier(identifier: str) -> str:
        return '"' + identifier.replace('"', '""') + '"'

    @classmethod
    def _table_exists(cls, conn: sqlite3.Connection, table_name: str) -> bool:
        return (
            conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (table_name,),
            ).fetchone()
            is not None
        )

    @classmethod
    def _table_columns(
        cls,
        conn: sqlite3.Connection,
        table_name: str,
    ) -> dict[str, tuple[Any, ...]]:
        quoted = cls._quote_identifier(table_name)
        return {
            str(row[1]): tuple(row)
            for row in conn.execute(f"PRAGMA table_xinfo({quoted})").fetchall()
        }

    @classmethod
    def _ensure_nonunique_index(
        cls,
        conn: sqlite3.Connection,
        index_name: str,
        table_name: str,
        columns: tuple[tuple[str, bool], ...],
    ) -> None:
        row = conn.execute(
            "SELECT tbl_name FROM sqlite_master WHERE type = 'index' AND name = ?",
            (index_name,),
        ).fetchone()
        valid = False
        if row is not None and str(row[0]) == table_name:
            index_list = conn.execute(
                f"PRAGMA index_list({cls._quote_identifier(table_name)})"
            ).fetchall()
            metadata = next(
                (item for item in index_list if str(item[1]) == index_name),
                None,
            )
            key_columns = [
                item
                for item in conn.execute(
                    f"PRAGMA index_xinfo({cls._quote_identifier(index_name)})"
                ).fetchall()
                if len(item) > 5 and bool(item[5])
            ]
            actual = tuple(
                (None if item[2] is None else str(item[2]), bool(item[3]))
                for item in key_columns
            )
            collations = tuple(str(item[4] or "").upper() for item in key_columns)
            valid = bool(
                metadata is not None
                and not bool(metadata[2])
                and not bool(metadata[4])
                and actual == columns
                and collations == tuple("BINARY" for _ in columns)
            )
        if valid:
            return
        if row is not None:
            conn.execute(f"DROP INDEX {cls._quote_identifier(index_name)}")
        column_sql = ", ".join(
            f"{cls._quote_identifier(name)}{' DESC' if descending else ''}"
            for name, descending in columns
        )
        conn.execute(
            f"CREATE INDEX {cls._quote_identifier(index_name)} "
            f"ON {cls._quote_identifier(table_name)}({column_sql})"
        )

    @classmethod
    def _unique_index_signatures(
        cls,
        conn: sqlite3.Connection,
        table_name: str,
    ) -> list[
        tuple[
            tuple[str | None, ...],
            bool,
            tuple[str, ...],
            tuple[bool, ...],
        ]
    ]:
        quoted = cls._quote_identifier(table_name)
        signatures: list[
            tuple[
                tuple[str | None, ...],
                bool,
                tuple[str, ...],
                tuple[bool, ...],
            ]
        ] = []
        for index in conn.execute(f"PRAGMA index_list({quoted})").fetchall():
            if not bool(index[2]):
                continue
            index_name = cls._quote_identifier(str(index[1]))
            key_columns = [
                row
                for row in conn.execute(
                    f"PRAGMA index_xinfo({index_name})"
                ).fetchall()
                if len(row) > 5 and bool(row[5])
            ]
            columns = tuple(
                None if row[2] is None else str(row[2])
                for row in key_columns
            )
            collations = tuple(str(row[4] or "").upper() for row in key_columns)
            descending = tuple(bool(row[3]) for row in key_columns)
            partial = bool(index[4]) if len(index) > 4 else False
            signatures.append((columns, partial, collations, descending))
        return signatures

    @classmethod
    def _is_canonical_table(
        cls,
        conn: sqlite3.Connection,
        table_name: str,
    ) -> bool:
        if not cls._table_exists(conn, table_name):
            return False
        schema_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
        if schema_row is None or schema_row[0] is None:
            return False
        normalized_schema = " ".join(str(schema_row[0]).upper().split())
        if "COLLATE" in normalized_schema:
            return False
        if (
            table_name == "high_score_examples"
            and _HIGH_SCORE_PROVENANCE_CHECK not in normalized_schema
        ):
            return False
        columns = cls._table_columns(conn, table_name)
        expected_columns = _CANONICAL_COLUMN_SPECS[table_name]
        if tuple(columns) != tuple(spec[0] for spec in expected_columns):
            return False
        for name, column_type, not_null, default, primary_key in expected_columns:
            column = columns[name]
            actual_default = None if column[4] is None else str(column[4])
            if (
                str(column[2]).upper() != column_type
                or int(column[3]) != not_null
                or actual_default != default
                or int(column[5]) != primary_key
                or (len(column) > 6 and int(column[6]) != 0)
            ):
                return False

        actual_unique = sorted(
            cls._unique_index_signatures(conn, table_name),
            key=repr,
        )
        expected_unique = sorted(
            [
                (
                    unique_columns,
                    False,
                    tuple("BINARY" for _ in unique_columns),
                    tuple(False for _ in unique_columns),
                )
                for unique_columns in _CANONICAL_UNIQUE_KEYS[table_name]
            ],
            key=repr,
        )
        return actual_unique == expected_unique

    @classmethod
    def _create_canonical_table(
        cls,
        conn: sqlite3.Connection,
        table_name: str,
        target_name: str,
    ) -> None:
        target = cls._quote_identifier(target_name)
        definitions = {
            "turn_scores": f"""
                CREATE TABLE {target} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_key_hash TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    run_id TEXT NOT NULL DEFAULT '__legacy_run__',
                    turn_idx INTEGER NOT NULL,
                    model TEXT,
                    overall_score REAL DEFAULT 0.0,
                    hallucination_rate REAL DEFAULT 0.0,
                    total_tokens INTEGER DEFAULT 0,
                    timestamp REAL NOT NULL,
                    UNIQUE(owner_key_hash, session_id, run_id, turn_idx)
                )
            """,
            "tool_call_scores": f"""
                CREATE TABLE {target} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_key_hash TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    run_id TEXT NOT NULL DEFAULT '__legacy_run__',
                    turn_idx INTEGER NOT NULL,
                    tool_name TEXT NOT NULL,
                    success INTEGER DEFAULT 0,
                    retry_count INTEGER DEFAULT 0,
                    error_pattern TEXT DEFAULT '',
                    output_quality REAL DEFAULT 0.0,
                    latency_ms REAL DEFAULT 0.0,
                    timestamp REAL NOT NULL
                )
            """,
            "rejection_turn_contributions": f"""
                CREATE TABLE {target} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_key_hash TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    run_id TEXT NOT NULL DEFAULT '__legacy_run__',
                    turn_idx INTEGER NOT NULL,
                    pattern TEXT NOT NULL,
                    tool_name TEXT NOT NULL DEFAULT '',
                    count INTEGER NOT NULL DEFAULT 1,
                    last_seen REAL NOT NULL,
                    UNIQUE(
                        owner_key_hash,
                        session_id,
                        run_id,
                        turn_idx,
                        pattern,
                        tool_name
                    )
                )
            """,
            "quality_session_watermarks": f"""
                CREATE TABLE {target} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_key_hash TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    run_id TEXT NOT NULL DEFAULT '__legacy_run__',
                    pruned_through_turn_idx INTEGER NOT NULL,
                    pruned_through_timestamp REAL NOT NULL,
                    UNIQUE(owner_key_hash, session_id, run_id)
                )
            """,
            "rejection_patterns": f"""
                CREATE TABLE {target} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_key_hash TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    tool_name TEXT NOT NULL DEFAULT '',
                    count INTEGER DEFAULT 1,
                    last_seen REAL NOT NULL,
                    archived_count INTEGER NOT NULL DEFAULT 0,
                    archived_last_seen REAL,
                    archive_exact INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(owner_key_hash, pattern, tool_name)
                )
            """,
            "high_score_examples": f"""
                CREATE TABLE {target} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_key_hash TEXT NOT NULL,
                    tool_name TEXT,
                    description TEXT,
                    score REAL DEFAULT 0.0,
                    timestamp REAL NOT NULL,
                    source_session_id TEXT,
                    source_run_id TEXT,
                    source_turn_idx INTEGER,
                    source_ordinal INTEGER,
                    UNIQUE(
                        owner_key_hash,
                        source_session_id,
                        source_run_id,
                        source_turn_idx,
                        source_ordinal
                    ),
                    CHECK (
                        (source_session_id IS NULL AND source_run_id IS NULL
                         AND source_turn_idx IS NULL AND source_ordinal IS NULL)
                        OR
                        (source_session_id IS NOT NULL
                         AND source_run_id IS NOT NULL
                         AND source_turn_idx IS NOT NULL
                         AND source_ordinal IS NOT NULL
                         AND source_ordinal >= 0)
                    )
                )
            """,
        }
        conn.execute(definitions[table_name])

    @classmethod
    def _migration_sources(
        cls,
        conn: sqlite3.Connection,
        table_name: str,
    ) -> list[str]:
        all_tables = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        candidates = [table_name, f"{table_name}_legacy"]
        candidates.extend(
            sorted(name for name in all_tables if name.startswith(f"{table_name}_echo2_"))
        )
        return [name for name in candidates if name in all_tables]

    @staticmethod
    def _migration_source_lineage(table_name: str, source_name: str) -> str:
        if source_name == table_name:
            return ""
        prefix = f"{table_name}_"
        if not source_name.startswith(prefix):
            raise ValueError(f"Unexpected migration source: {source_name}")
        return source_name[len(table_name) :]

    @classmethod
    def _prepare_turn_migration_winners(cls, conn: sqlite3.Connection) -> None:
        """Select one complete turn version before any source table is rebuilt."""
        conn.execute("DROP TABLE IF EXISTS temp.echo_turn_migration_winners")
        conn.execute(
            """
            CREATE TEMP TABLE echo_turn_migration_winners (
                owner_key_hash TEXT NOT NULL,
                session_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                turn_idx INTEGER NOT NULL,
                model TEXT,
                overall_score REAL,
                hallucination_rate REAL,
                total_tokens INTEGER,
                timestamp REAL NOT NULL,
                source_lineage TEXT NOT NULL,
                source_rank INTEGER NOT NULL,
                source_rowid INTEGER NOT NULL,
                PRIMARY KEY(owner_key_hash, session_id, run_id, turn_idx)
            ) WITHOUT ROWID
            """
        )
        required = {
            "session_id",
            "turn_idx",
            "model",
            "overall_score",
            "hallucination_rate",
            "total_tokens",
            "timestamp",
        }
        for source_rank, source_name in enumerate(
            cls._migration_sources(conn, "turn_scores")
        ):
            columns = cls._table_columns(conn, source_name)
            if not required.issubset(columns):
                missing = sorted(required - columns.keys())
                raise RuntimeError(
                    f"Cannot migrate {source_name}: missing columns "
                    f"{', '.join(missing)}"
                )
            owner_expression = (
                "COALESCE(NULLIF(owner_key_hash, ''), ?)"
                if "owner_key_hash" in columns
                else "?"
            )
            run_expression = (
                "COALESCE(NULLIF(run_id, ''), ?)" if "run_id" in columns else "?"
            )
            source = cls._quote_identifier(source_name)
            lineage = cls._migration_source_lineage("turn_scores", source_name)
            conn.execute(
                f"""
                INSERT INTO echo_turn_migration_winners
                    (owner_key_hash, session_id, run_id, turn_idx, model,
                     overall_score, hallucination_rate, total_tokens, timestamp,
                     source_lineage, source_rank, source_rowid)
                SELECT {owner_expression}, session_id, {run_expression}, turn_idx,
                       model, overall_score, hallucination_rate, total_tokens,
                       timestamp, ?, ?, rowid
                FROM {source}
                WHERE 1
                ON CONFLICT(owner_key_hash, session_id, run_id, turn_idx)
                DO UPDATE SET
                    model = excluded.model,
                    overall_score = excluded.overall_score,
                    hallucination_rate = excluded.hallucination_rate,
                    total_tokens = excluded.total_tokens,
                    timestamp = excluded.timestamp,
                    source_lineage = excluded.source_lineage,
                    source_rank = excluded.source_rank,
                    source_rowid = excluded.source_rowid
                WHERE excluded.timestamp > echo_turn_migration_winners.timestamp
                   OR (
                       excluded.timestamp = echo_turn_migration_winners.timestamp
                       AND excluded.source_rank
                           > echo_turn_migration_winners.source_rank
                   )
                   OR (
                       excluded.timestamp = echo_turn_migration_winners.timestamp
                       AND excluded.source_rank
                           = echo_turn_migration_winners.source_rank
                       AND excluded.source_rowid
                           > echo_turn_migration_winners.source_rowid
                   )
                """,
                (_LEGACY_OWNER, _LEGACY_RUN, lineage, source_rank),
            )

    @classmethod
    def _reset_tool_migration_choices(cls, conn: sqlite3.Connection) -> None:
        conn.execute("DROP TABLE IF EXISTS temp.echo_tool_migration_choices")
        conn.execute(
            """
            CREATE TEMP TABLE echo_tool_migration_choices (
                owner_key_hash TEXT NOT NULL,
                session_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                turn_idx INTEGER NOT NULL,
                source_lineage TEXT NOT NULL,
                preferred INTEGER NOT NULL,
                source_rank INTEGER NOT NULL,
                PRIMARY KEY(owner_key_hash, session_id, run_id, turn_idx)
            ) WITHOUT ROWID
            """
        )

    @classmethod
    def _prepare_tool_migration_choices(
        cls,
        conn: sqlite3.Connection,
        sources: list[str],
    ) -> None:
        """Choose one tool-source lineage per turn without losing lone snapshots."""
        cls._reset_tool_migration_choices(conn)
        required = {"session_id", "turn_idx"}
        for source_rank, source_name in enumerate(sources):
            columns = cls._table_columns(conn, source_name)
            if not required.issubset(columns):
                missing = sorted(required - columns.keys())
                raise RuntimeError(
                    f"Cannot migrate {source_name}: missing columns "
                    f"{', '.join(missing)}"
                )
            owner_expression = (
                "COALESCE(NULLIF(owner_key_hash, ''), ?)"
                if "owner_key_hash" in columns
                else "?"
            )
            run_expression = (
                "COALESCE(NULLIF(run_id, ''), ?)" if "run_id" in columns else "?"
            )
            source = cls._quote_identifier(source_name)
            lineage = cls._migration_source_lineage(
                "tool_call_scores",
                source_name,
            )
            conn.execute(
                f"""
                WITH source_identities AS (
                    SELECT DISTINCT {owner_expression} AS owner_key_hash,
                           session_id, {run_expression} AS run_id, turn_idx
                    FROM {source}
                )
                INSERT INTO echo_tool_migration_choices
                    (owner_key_hash, session_id, run_id, turn_idx,
                     source_lineage, preferred, source_rank)
                SELECT source_row.owner_key_hash, source_row.session_id,
                       source_row.run_id, source_row.turn_idx, ?,
                       CASE WHEN winner.source_lineage = ? THEN 1 ELSE 0 END,
                       ?
                FROM source_identities AS source_row
                LEFT JOIN echo_turn_migration_winners AS winner
                  ON winner.owner_key_hash = source_row.owner_key_hash
                 AND winner.session_id = source_row.session_id
                 AND winner.run_id = source_row.run_id
                 AND winner.turn_idx = source_row.turn_idx
                WHERE 1
                ON CONFLICT(owner_key_hash, session_id, run_id, turn_idx)
                DO UPDATE SET
                    source_lineage = excluded.source_lineage,
                    preferred = excluded.preferred,
                    source_rank = excluded.source_rank
                WHERE excluded.preferred
                          > echo_tool_migration_choices.preferred
                   OR (
                       excluded.preferred
                           = echo_tool_migration_choices.preferred
                       AND excluded.source_rank
                           > echo_tool_migration_choices.source_rank
                   )
                """,
                (
                    _LEGACY_OWNER,
                    _LEGACY_RUN,
                    lineage,
                    lineage,
                    source_rank,
                ),
            )

    @classmethod
    def _copy_source_rows(
        cls,
        conn: sqlite3.Connection,
        table_name: str,
        source_name: str,
        target_name: str,
    ) -> None:
        columns = cls._table_columns(conn, source_name)
        required_without_owner = {
            "turn_scores": {
                "session_id",
                "turn_idx",
                "model",
                "overall_score",
                "hallucination_rate",
                "total_tokens",
                "timestamp",
            },
            "tool_call_scores": {
                "session_id",
                "turn_idx",
                "tool_name",
                "success",
                "retry_count",
                "error_pattern",
                "output_quality",
                "latency_ms",
                "timestamp",
            },
            "rejection_turn_contributions": {
                "session_id",
                "turn_idx",
                "pattern",
                "tool_name",
                "count",
                "last_seen",
            },
            "quality_session_watermarks": {
                "session_id",
                "pruned_through_turn_idx",
                "pruned_through_timestamp",
            },
            "rejection_patterns": {"pattern", "tool_name", "count", "last_seen"},
            "high_score_examples": {"tool_name", "description", "score", "timestamp"},
        }[table_name]
        if not required_without_owner.issubset(columns):
            missing = sorted(required_without_owner - columns.keys())
            raise RuntimeError(
                f"Cannot migrate {source_name}: missing columns {', '.join(missing)}"
            )

        owner_expression = (
            "COALESCE(NULLIF(owner_key_hash, ''), ?)"
            if "owner_key_hash" in columns
            else "?"
        )
        run_expression = (
            "COALESCE(NULLIF(run_id, ''), ?)" if "run_id" in columns else "?"
        )
        source = cls._quote_identifier(source_name)
        target = cls._quote_identifier(target_name)
        source_lineage = cls._migration_source_lineage(table_name, source_name)
        if table_name == "turn_scores":
            conn.execute(
                f"""
                INSERT INTO {target}
                    (owner_key_hash, session_id, run_id, turn_idx, model,
                     overall_score, hallucination_rate, total_tokens, timestamp)
                SELECT {owner_expression}, session_id, {run_expression}, turn_idx, model,
                       overall_score, hallucination_rate, total_tokens, timestamp
                FROM {source}
                WHERE 1
                ON CONFLICT(owner_key_hash, session_id, run_id, turn_idx) DO UPDATE SET
                    model = excluded.model,
                    overall_score = excluded.overall_score,
                    hallucination_rate = excluded.hallucination_rate,
                    total_tokens = excluded.total_tokens,
                    timestamp = excluded.timestamp
                WHERE excluded.timestamp >= {target}.timestamp
                """,
                (_LEGACY_OWNER, _LEGACY_RUN),
            )
        elif table_name == "tool_call_scores":
            conn.execute(
                f"""
                WITH normalized AS (
                    SELECT {owner_expression} AS owner_key_hash,
                           session_id, {run_expression} AS run_id, turn_idx,
                           tool_name, success, retry_count, error_pattern,
                           output_quality, latency_ms, timestamp, rowid AS source_rowid,
                           ? AS source_lineage
                    FROM {source}
                ),
                source_ranked AS (
                    SELECT *,
                           ROW_NUMBER() OVER (
                               PARTITION BY owner_key_hash, session_id, run_id, turn_idx,
                                            tool_name, success, retry_count,
                                            error_pattern, output_quality,
                                            latency_ms, timestamp
                               ORDER BY source_rowid
                           ) AS occurrence
                    FROM normalized
                ),
                target_counts AS (
                    SELECT owner_key_hash, session_id, run_id, turn_idx, tool_name,
                           success, retry_count, error_pattern, output_quality,
                           latency_ms, timestamp, COUNT(*) AS existing_count
                    FROM {target}
                    GROUP BY owner_key_hash, session_id, run_id, turn_idx, tool_name,
                             success, retry_count, error_pattern, output_quality,
                             latency_ms, timestamp
                )
                INSERT INTO {target}
                    (owner_key_hash, session_id, run_id, turn_idx, tool_name,
                     success, retry_count, error_pattern, output_quality,
                     latency_ms, timestamp)
                SELECT source_row.owner_key_hash, source_row.session_id,
                       source_row.run_id, source_row.turn_idx, source_row.tool_name,
                       source_row.success, source_row.retry_count,
                       source_row.error_pattern, source_row.output_quality,
                       source_row.latency_ms, source_row.timestamp
                FROM source_ranked AS source_row
                LEFT JOIN target_counts AS target_row
                 ON target_row.owner_key_hash IS source_row.owner_key_hash
                 AND target_row.session_id IS source_row.session_id
                 AND target_row.run_id IS source_row.run_id
                 AND target_row.turn_idx IS source_row.turn_idx
                 AND target_row.tool_name IS source_row.tool_name
                 AND target_row.success IS source_row.success
                 AND target_row.retry_count IS source_row.retry_count
                 AND target_row.error_pattern IS source_row.error_pattern
                 AND target_row.output_quality IS source_row.output_quality
                 AND target_row.latency_ms IS source_row.latency_ms
                 AND target_row.timestamp IS source_row.timestamp
                JOIN echo_tool_migration_choices AS choice
                  ON choice.owner_key_hash = source_row.owner_key_hash
                 AND choice.session_id = source_row.session_id
                 AND choice.run_id = source_row.run_id
                 AND choice.turn_idx = source_row.turn_idx
                WHERE source_row.occurrence > COALESCE(target_row.existing_count, 0)
                  AND choice.source_lineage = source_row.source_lineage
                """,
                (_LEGACY_OWNER, _LEGACY_RUN, source_lineage),
            )
        elif table_name == "rejection_turn_contributions":
            conn.execute(
                f"""
                WITH normalized AS (
                    SELECT {owner_expression} AS owner_key_hash,
                           session_id, {run_expression} AS run_id, turn_idx,
                           pattern, COALESCE(tool_name, '') AS tool_name,
                           count, last_seen, ? AS source_lineage
                    FROM {source}
                ),
                authoritative_lineages AS (
                    SELECT winner.owner_key_hash, winner.session_id,
                           winner.run_id, winner.turn_idx,
                           COALESCE(
                               (
                                   SELECT choice.source_lineage
                                   FROM echo_tool_migration_choices AS choice
                                   WHERE choice.owner_key_hash
                                             = winner.owner_key_hash
                                     AND choice.session_id = winner.session_id
                                     AND choice.run_id = winner.run_id
                                     AND choice.turn_idx = winner.turn_idx
                                     AND EXISTS (
                                         SELECT 1
                                         FROM sqlite_master AS chosen_source
                                         WHERE chosen_source.type = 'table'
                                           AND chosen_source.name
                                               = ? || choice.source_lineage
                                     )
                               ),
                               CASE WHEN EXISTS (
                                   SELECT 1
                                   FROM sqlite_master AS turn_source
                                   WHERE turn_source.type = 'table'
                                     AND turn_source.name
                                         = ? || winner.source_lineage
                               ) THEN winner.source_lineage END
                           ) AS source_lineage
                    FROM echo_turn_migration_winners AS winner
                )
                INSERT INTO {target}
                    (owner_key_hash, session_id, run_id, turn_idx, pattern,
                     tool_name, count, last_seen)
                SELECT source_row.owner_key_hash, source_row.session_id,
                       source_row.run_id, source_row.turn_idx,
                       source_row.pattern, source_row.tool_name,
                       source_row.count, source_row.last_seen
                FROM normalized AS source_row
                LEFT JOIN authoritative_lineages AS authority
                  ON authority.owner_key_hash = source_row.owner_key_hash
                 AND authority.session_id = source_row.session_id
                 AND authority.run_id = source_row.run_id
                 AND authority.turn_idx = source_row.turn_idx
                WHERE authority.source_lineage IS NULL
                   OR authority.source_lineage = source_row.source_lineage
                ON CONFLICT(
                    owner_key_hash,
                    session_id,
                    run_id,
                    turn_idx,
                    pattern,
                    tool_name
                ) DO UPDATE SET
                    count = excluded.count,
                    last_seen = excluded.last_seen
                WHERE excluded.last_seen > {target}.last_seen
                   OR (
                       excluded.last_seen = {target}.last_seen
                       AND excluded.count > {target}.count
                   )
                """,
                (
                    _LEGACY_OWNER,
                    _LEGACY_RUN,
                    source_lineage,
                    table_name,
                    table_name,
                ),
            )
        elif table_name == "quality_session_watermarks":
            conn.execute(
                f"""
                INSERT INTO {target}
                    (owner_key_hash, session_id, run_id,
                     pruned_through_turn_idx, pruned_through_timestamp)
                SELECT {owner_expression}, session_id, {run_expression},
                       pruned_through_turn_idx, pruned_through_timestamp
                FROM {source}
                WHERE 1
                ON CONFLICT(owner_key_hash, session_id, run_id) DO UPDATE SET
                    pruned_through_turn_idx = MAX(
                        {target}.pruned_through_turn_idx,
                        excluded.pruned_through_turn_idx
                    ),
                    pruned_through_timestamp = MAX(
                        {target}.pruned_through_timestamp,
                        excluded.pruned_through_timestamp
                    )
                """,
                (_LEGACY_OWNER, _LEGACY_RUN),
            )
        elif table_name == "rejection_patterns":
            archived_count_expression = (
                "COALESCE(archived_count, 0)"
                if "archived_count" in columns
                else "0"
            )
            archived_last_seen_expression = (
                "archived_last_seen"
                if "archived_last_seen" in columns
                else "NULL"
            )
            archive_exact_expression = (
                "COALESCE(archive_exact, 0)"
                if "archive_exact" in columns
                else (
                    "CASE WHEN COALESCE(archived_count, 0) = 0 THEN 1 ELSE 0 END"
                    if "archived_count" in columns
                    else "1"
                )
            )
            conn.execute(
                f"""
                INSERT INTO {target}
                    (owner_key_hash, pattern, tool_name, count, last_seen,
                     archived_count, archived_last_seen, archive_exact)
                SELECT {owner_expression}, pattern, COALESCE(tool_name, ''), count,
                       last_seen, {archived_count_expression},
                       {archived_last_seen_expression}, {archive_exact_expression}
                FROM {source}
                WHERE 1
                ON CONFLICT(owner_key_hash, pattern, tool_name) DO UPDATE SET
                    count = MAX({target}.count, excluded.count),
                    last_seen = MAX({target}.last_seen, excluded.last_seen),
                    archived_count = MAX(
                        {target}.archived_count,
                        excluded.archived_count
                    ),
                    archived_last_seen = CASE
                        WHEN {target}.archived_last_seen IS NULL
                            THEN excluded.archived_last_seen
                        WHEN excluded.archived_last_seen IS NULL
                            THEN {target}.archived_last_seen
                        ELSE MAX(
                            {target}.archived_last_seen,
                            excluded.archived_last_seen
                        )
                    END,
                    archive_exact = MIN(
                        {target}.archive_exact,
                        excluded.archive_exact
                    )
                """,
                (_LEGACY_OWNER,),
            )
        else:
            has_complete_provenance_schema = {
                "source_session_id",
                "source_turn_idx",
                "source_ordinal",
            }.issubset(columns)
            valid_provenance = (
                "source_session_id IS NOT NULL "
                "AND source_turn_idx IS NOT NULL "
                "AND source_ordinal IS NOT NULL "
                "AND source_ordinal >= 0"
            )
            source_session_expression = (
                f"CASE WHEN {valid_provenance} THEN source_session_id END"
                if has_complete_provenance_schema
                else "NULL"
            )
            source_run_expression = (
                f"CASE WHEN {valid_provenance} "
                "THEN COALESCE(NULLIF(source_run_id, ''), ?) END"
                if has_complete_provenance_schema and "source_run_id" in columns
                else (
                    f"CASE WHEN {valid_provenance} THEN ? END"
                    if has_complete_provenance_schema
                    else "NULL"
                )
            )
            source_turn_expression = (
                f"CASE WHEN {valid_provenance} THEN source_turn_idx END"
                if has_complete_provenance_schema
                else "NULL"
            )
            source_ordinal_expression = (
                f"CASE WHEN {valid_provenance} THEN source_ordinal END"
                if has_complete_provenance_schema
                else "NULL"
            )
            high_score_params = (
                (_LEGACY_OWNER, _LEGACY_RUN)
                if has_complete_provenance_schema
                else (_LEGACY_OWNER,)
            )
            conn.execute(
                f"""
                WITH normalized AS (
                    SELECT {owner_expression} AS owner_key_hash,
                           tool_name, description, score, timestamp,
                           {source_session_expression} AS source_session_id,
                           {source_run_expression} AS source_run_id,
                           {source_turn_expression} AS source_turn_idx,
                           {source_ordinal_expression} AS source_ordinal,
                           ? AS source_lineage,
                           rowid AS source_rowid
                    FROM {source}
                ),
                authoritative_lineages AS (
                    SELECT winner.owner_key_hash, winner.session_id,
                           winner.run_id, winner.turn_idx,
                           COALESCE(
                               (
                                   SELECT choice.source_lineage
                                   FROM echo_tool_migration_choices AS choice
                                   WHERE choice.owner_key_hash
                                             = winner.owner_key_hash
                                     AND choice.session_id = winner.session_id
                                     AND choice.run_id = winner.run_id
                                     AND choice.turn_idx = winner.turn_idx
                                     AND EXISTS (
                                         SELECT 1
                                         FROM sqlite_master AS chosen_source
                                         WHERE chosen_source.type = 'table'
                                           AND chosen_source.name
                                               = ? || choice.source_lineage
                                     )
                               ),
                               CASE WHEN EXISTS (
                                   SELECT 1
                                   FROM sqlite_master AS turn_source
                                   WHERE turn_source.type = 'table'
                                     AND turn_source.name
                                         = ? || winner.source_lineage
                               ) THEN winner.source_lineage END
                           ) AS source_lineage
                    FROM echo_turn_migration_winners AS winner
                ),
                source_ranked AS (
                    SELECT *,
                           ROW_NUMBER() OVER (
                               PARTITION BY owner_key_hash, tool_name, description,
                                            score, timestamp, source_session_id,
                                            source_run_id, source_turn_idx,
                                            source_ordinal
                               ORDER BY source_rowid
                           ) AS occurrence
                    FROM normalized
                ),
                target_counts AS (
                    SELECT owner_key_hash, tool_name, description, score, timestamp,
                           source_session_id, source_run_id, source_turn_idx,
                           source_ordinal, COUNT(*) AS existing_count
                    FROM {target}
                    GROUP BY owner_key_hash, tool_name, description, score, timestamp,
                             source_session_id, source_run_id, source_turn_idx,
                             source_ordinal
                )
                INSERT INTO {target}
                    (owner_key_hash, tool_name, description, score, timestamp,
                     source_session_id, source_run_id, source_turn_idx,
                     source_ordinal)
                SELECT source_row.owner_key_hash, source_row.tool_name,
                       source_row.description, source_row.score, source_row.timestamp
                       , source_row.source_session_id, source_row.source_run_id,
                       source_row.source_turn_idx, source_row.source_ordinal
                FROM source_ranked AS source_row
                LEFT JOIN target_counts AS target_row
                  ON target_row.owner_key_hash IS source_row.owner_key_hash
                 AND target_row.tool_name IS source_row.tool_name
                 AND target_row.description IS source_row.description
                 AND target_row.score IS source_row.score
                 AND target_row.timestamp IS source_row.timestamp
                 AND target_row.source_session_id IS source_row.source_session_id
                 AND target_row.source_run_id IS source_row.source_run_id
                 AND target_row.source_turn_idx IS source_row.source_turn_idx
                 AND target_row.source_ordinal IS source_row.source_ordinal
                LEFT JOIN authoritative_lineages AS authority
                  ON authority.owner_key_hash = source_row.owner_key_hash
                 AND authority.session_id = source_row.source_session_id
                 AND authority.run_id = source_row.source_run_id
                 AND authority.turn_idx = source_row.source_turn_idx
                WHERE source_row.occurrence > COALESCE(target_row.existing_count, 0)
                  AND (
                      authority.source_lineage IS NULL
                      OR authority.source_lineage = source_row.source_lineage
                  )
                ON CONFLICT(
                    owner_key_hash,
                    source_session_id,
                    source_run_id,
                    source_turn_idx,
                    source_ordinal
                ) DO UPDATE SET
                    tool_name = excluded.tool_name,
                    description = excluded.description,
                    score = excluded.score,
                    timestamp = excluded.timestamp
                WHERE excluded.timestamp >= {target}.timestamp
                """,
                high_score_params + (source_lineage, table_name, table_name),
            )

    @classmethod
    def _ensure_canonical_table(
        cls,
        conn: sqlite3.Connection,
        table_name: str,
    ) -> bool:
        sources = cls._migration_sources(conn, table_name)
        orphan_sources = [name for name in sources if name != table_name]
        if cls._is_canonical_table(conn, table_name) and not orphan_sources:
            return False
        if not sources:
            cls._create_canonical_table(conn, table_name, table_name)
            return True

        target_name = f"{table_name}_echo2_rebuild"
        suffix = 0
        while cls._table_exists(conn, target_name):
            suffix += 1
            target_name = f"{table_name}_echo2_rebuild_{suffix}"
        cls._create_canonical_table(conn, table_name, target_name)
        if table_name == "turn_scores":
            target = cls._quote_identifier(target_name)
            conn.execute(
                f"""
                INSERT INTO {target}
                    (owner_key_hash, session_id, run_id, turn_idx, model,
                     overall_score, hallucination_rate, total_tokens, timestamp)
                SELECT owner_key_hash, session_id, run_id, turn_idx, model,
                       overall_score, hallucination_rate, total_tokens, timestamp
                FROM echo_turn_migration_winners
                """
            )
        else:
            for source_name in sources:
                cls._copy_source_rows(conn, table_name, source_name, target_name)
        for source_name in sources:
            conn.execute(f"DROP TABLE {cls._quote_identifier(source_name)}")
        conn.execute(
            f"ALTER TABLE {cls._quote_identifier(target_name)} "
            f"RENAME TO {cls._quote_identifier(table_name)}"
        )
        return True

    @staticmethod
    def _normalize_rejection_patterns(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            DELETE FROM rejection_turn_contributions AS contribution
            WHERE NOT EXISTS (
                SELECT 1
                FROM turn_scores AS turn_score
                WHERE turn_score.owner_key_hash = contribution.owner_key_hash
                  AND turn_score.session_id = contribution.session_id
                  AND turn_score.run_id = contribution.run_id
                  AND turn_score.turn_idx = contribution.turn_idx
            )
            """
        )
        conn.execute(
            """
            INSERT INTO rejection_turn_contributions
                (owner_key_hash, session_id, run_id, turn_idx, pattern,
                 tool_name, count, last_seen)
            SELECT tool.owner_key_hash, tool.session_id, tool.run_id,
                   tool.turn_idx, tool.error_pattern, tool.tool_name,
                   COUNT(*), MAX(tool.timestamp)
            FROM tool_call_scores AS tool
            JOIN turn_scores AS turn_score
             ON turn_score.owner_key_hash = tool.owner_key_hash
             AND turn_score.session_id = tool.session_id
             AND turn_score.run_id = tool.run_id
             AND turn_score.turn_idx = tool.turn_idx
             AND turn_score.timestamp = tool.timestamp
            WHERE tool.success = 0 AND tool.error_pattern <> ''
            GROUP BY tool.owner_key_hash, tool.session_id, tool.run_id,
                     tool.turn_idx, tool.error_pattern, tool.tool_name
            ON CONFLICT(
                owner_key_hash,
                session_id,
                run_id,
                turn_idx,
                pattern,
                tool_name
            ) DO UPDATE SET
                count = MAX(
                    rejection_turn_contributions.count,
                    excluded.count
                ),
                last_seen = MAX(
                    rejection_turn_contributions.last_seen,
                    excluded.last_seen
                )
            """
        )
        conn.execute(
            """
            CREATE TEMP TABLE echo_rejection_detail (
                owner_key_hash TEXT NOT NULL,
                pattern TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                detail_count INTEGER NOT NULL,
                detail_last_seen REAL NOT NULL,
                PRIMARY KEY(owner_key_hash, pattern, tool_name)
            ) WITHOUT ROWID
            """
        )
        conn.execute(
            """
            INSERT INTO echo_rejection_detail
                (owner_key_hash, pattern, tool_name,
                 detail_count, detail_last_seen)
            WITH contribution_detail AS (
                SELECT owner_key_hash, pattern, tool_name,
                       SUM(count) AS detail_count,
                       MAX(last_seen) AS detail_last_seen
                FROM rejection_turn_contributions
                GROUP BY owner_key_hash, pattern, tool_name
            ),
            tool_detail AS (
                SELECT owner_key_hash, error_pattern AS pattern, tool_name,
                       COUNT(*) AS detail_count,
                       MAX(timestamp) AS detail_last_seen
                FROM tool_call_scores AS tool_score
                WHERE success = 0 AND error_pattern <> ''
                  AND (
                    EXISTS (
                        SELECT 1
                        FROM turn_scores AS turn_score
                        WHERE turn_score.owner_key_hash = tool_score.owner_key_hash
                          AND turn_score.session_id = tool_score.session_id
                          AND turn_score.run_id = tool_score.run_id
                          AND turn_score.turn_idx = tool_score.turn_idx
                          AND turn_score.timestamp = tool_score.timestamp
                    )
                    OR NOT EXISTS (
                        SELECT 1
                        FROM turn_scores AS turn_score
                        WHERE turn_score.owner_key_hash = tool_score.owner_key_hash
                          AND turn_score.session_id = tool_score.session_id
                          AND turn_score.run_id = tool_score.run_id
                          AND turn_score.turn_idx = tool_score.turn_idx
                    )
                  )
                GROUP BY owner_key_hash, error_pattern, tool_name
            ),
            signatures AS (
                SELECT owner_key_hash, pattern, tool_name
                FROM contribution_detail
                UNION
                SELECT owner_key_hash, pattern, tool_name
                FROM tool_detail
            )
            SELECT signature.owner_key_hash, signature.pattern,
                   signature.tool_name,
                   MAX(
                       COALESCE(contribution.detail_count, 0),
                       COALESCE(tool.detail_count, 0)
                   ),
                   CASE
                       WHEN contribution.detail_last_seen IS NULL
                           THEN tool.detail_last_seen
                       WHEN tool.detail_last_seen IS NULL
                           THEN contribution.detail_last_seen
                       ELSE MAX(
                           contribution.detail_last_seen,
                           tool.detail_last_seen
                       )
                   END
            FROM signatures AS signature
            LEFT JOIN contribution_detail AS contribution
              ON contribution.owner_key_hash = signature.owner_key_hash
             AND contribution.pattern = signature.pattern
             AND contribution.tool_name = signature.tool_name
            LEFT JOIN tool_detail AS tool
              ON tool.owner_key_hash = signature.owner_key_hash
             AND tool.pattern = signature.pattern
             AND tool.tool_name = signature.tool_name
            """
        )
        conn.execute(
            """
            CREATE TEMP TABLE echo_rejection_normalized AS
            WITH joined AS (
                SELECT rejection.id,
                       rejection.count AS old_count,
                       rejection.last_seen AS old_last_seen,
                       rejection.archived_count AS old_archived_count,
                       rejection.archived_last_seen AS old_archived_last_seen,
                       rejection.archive_exact AS old_archive_exact,
                       COALESCE(detail.detail_count, 0) AS detail_count,
                       detail.detail_last_seen
                FROM rejection_patterns AS rejection
                LEFT JOIN echo_rejection_detail AS detail
                  ON detail.owner_key_hash = rejection.owner_key_hash
                 AND detail.pattern = rejection.pattern
                 AND detail.tool_name = rejection.tool_name
            ),
            archive_counts AS (
                SELECT *,
                       MAX(
                           old_count,
                           old_archived_count,
                           detail_count,
                           0
                       ) AS authoritative_total
                FROM joined
            ),
            archive_values AS (
                SELECT *,
                       MAX(authoritative_total - detail_count, 0)
                           AS normalized_archived_count,
                       CASE
                           WHEN old_count = old_archived_count + detail_count
                            AND old_archived_count <= authoritative_total
                            AND NOT (
                                old_archived_last_seen IS NOT NULL
                                AND authoritative_total - detail_count = 0
                            )
                               THEN 0
                           ELSE 1
                       END AS archive_conflict
                FROM archive_counts
            ),
            archive_metadata AS (
                SELECT *,
                       CASE
                           WHEN normalized_archived_count = 0 THEN NULL
                           WHEN old_archived_count = normalized_archived_count
                            AND old_archived_last_seen IS NOT NULL
                               THEN old_archived_last_seen
                           ELSE old_last_seen
                       END AS normalized_archived_last_seen,
                       CASE
                           WHEN archive_conflict = 1 THEN 0
                           ELSE old_archive_exact
                       END AS normalized_archive_exact
                FROM archive_values
            )
            SELECT id,
                   normalized_archived_count + detail_count AS total_count,
                   CASE
                       WHEN normalized_archived_last_seen IS NULL
                           THEN detail_last_seen
                       WHEN detail_last_seen IS NULL
                           THEN normalized_archived_last_seen
                       ELSE MAX(
                           normalized_archived_last_seen,
                           detail_last_seen
                       )
                   END AS total_last_seen,
                   normalized_archived_count AS archived_count,
                   normalized_archived_last_seen AS archived_last_seen,
                   normalized_archive_exact AS archive_exact
            FROM archive_metadata
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX echo_rejection_normalized_id
            ON echo_rejection_normalized(id)
            """
        )
        conn.execute(
            """
            DELETE FROM rejection_patterns
            WHERE id IN (
                SELECT id
                FROM echo_rejection_normalized
                WHERE total_count = 0 OR total_last_seen IS NULL
            )
            """
        )
        conn.execute(
            """
            UPDATE rejection_patterns
            SET count = (
                    SELECT total_count
                    FROM echo_rejection_normalized
                    WHERE id = rejection_patterns.id
                ),
                last_seen = (
                    SELECT total_last_seen
                    FROM echo_rejection_normalized
                    WHERE id = rejection_patterns.id
                ),
                archived_count = (
                    SELECT archived_count
                    FROM echo_rejection_normalized
                    WHERE id = rejection_patterns.id
                ),
                archived_last_seen = (
                    SELECT archived_last_seen
                    FROM echo_rejection_normalized
                    WHERE id = rejection_patterns.id
                ),
                archive_exact = (
                    SELECT archive_exact
                    FROM echo_rejection_normalized
                    WHERE id = rejection_patterns.id
                )
            WHERE id IN (SELECT id FROM echo_rejection_normalized)
            """
        )
        conn.execute(
            """
            INSERT INTO rejection_patterns
                (owner_key_hash, pattern, tool_name, count, last_seen,
                 archived_count, archived_last_seen, archive_exact)
            SELECT detail.owner_key_hash, detail.pattern, detail.tool_name,
                   detail.detail_count, detail.detail_last_seen, 0, NULL, 1
            FROM echo_rejection_detail AS detail
            WHERE NOT EXISTS (
                SELECT 1
                FROM rejection_patterns AS rejection
                WHERE rejection.owner_key_hash = detail.owner_key_hash
                  AND rejection.pattern = detail.pattern
                  AND rejection.tool_name = detail.tool_name
            )
            """
        )
        conn.execute("DROP TABLE echo_rejection_normalized")
        conn.execute("DROP TABLE echo_rejection_detail")

    @staticmethod
    def _reconcile_rejection_pattern(
        conn: sqlite3.Connection,
        owner_key_hash: str,
        pattern: str,
        tool_name: str,
    ) -> None:
        aggregate = conn.execute(
            """
            SELECT archived_count, archived_last_seen, archive_exact
            FROM rejection_patterns
            WHERE owner_key_hash = ? AND pattern = ? AND tool_name = ?
            """,
            (owner_key_hash, pattern, tool_name),
        ).fetchone()
        archived_count = int(aggregate[0] or 0) if aggregate is not None else 0
        archived_last_seen = (
            None
            if aggregate is None or aggregate[1] is None
            else float(aggregate[1])
        )
        archive_exact = int(aggregate[2]) if aggregate is not None else 1
        detail = conn.execute(
            """
            SELECT COALESCE(SUM(count), 0), MAX(last_seen)
            FROM rejection_turn_contributions
            WHERE owner_key_hash = ? AND pattern = ? AND tool_name = ?
            """,
            (owner_key_hash, pattern, tool_name),
        ).fetchone()
        detail_count = int(detail[0])
        detail_last_seen = None if detail[1] is None else float(detail[1])
        total_count = archived_count + detail_count
        timestamps = [
            value
            for value in (archived_last_seen, detail_last_seen)
            if value is not None
        ]
        if total_count == 0 or not timestamps:
            conn.execute(
                """
                DELETE FROM rejection_patterns
                WHERE owner_key_hash = ? AND pattern = ? AND tool_name = ?
                """,
                (owner_key_hash, pattern, tool_name),
            )
            return
        conn.execute(
            """
            INSERT INTO rejection_patterns
                (owner_key_hash, pattern, tool_name, count, last_seen,
                 archived_count, archived_last_seen, archive_exact)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_key_hash, pattern, tool_name) DO UPDATE SET
                count = excluded.count,
                last_seen = excluded.last_seen,
                archived_count = excluded.archived_count,
                archived_last_seen = excluded.archived_last_seen,
                archive_exact = excluded.archive_exact
            """,
            (
                owner_key_hash,
                pattern,
                tool_name,
                total_count,
                max(timestamps),
                archived_count,
                archived_last_seen,
                archive_exact,
            ),
        )

    @staticmethod
    def _capture_unarchived_rejection_baseline(
        conn: sqlite3.Connection,
        owner_key_hash: str,
        pattern: str,
        tool_name: str,
    ) -> None:
        aggregate = conn.execute(
            """
            SELECT count, last_seen, archived_count, archived_last_seen,
                   archive_exact
            FROM rejection_patterns
            WHERE owner_key_hash = ? AND pattern = ? AND tool_name = ?
            """,
            (owner_key_hash, pattern, tool_name),
        ).fetchone()
        if aggregate is None:
            return
        detail = conn.execute(
            """
            SELECT COALESCE(SUM(count), 0), MAX(last_seen)
            FROM rejection_turn_contributions
            WHERE owner_key_hash = ? AND pattern = ? AND tool_name = ?
            """,
            (owner_key_hash, pattern, tool_name),
        ).fetchone()
        detail_count = int(detail[0])
        detail_last_seen = None if detail[1] is None else float(detail[1])
        old_count = int(aggregate[0])
        old_last_seen = float(aggregate[1])
        archived_count = int(aggregate[2] or 0)
        archived_last_seen = (
            None if aggregate[3] is None else float(aggregate[3])
        )
        archive_exact = int(aggregate[4])
        authoritative_total = max(old_count, archived_count, detail_count)
        normalized_archived_count = max(authoritative_total - detail_count, 0)
        conflict = (
            old_count != archived_count + detail_count
            or archived_count > authoritative_total
            or (archived_last_seen is not None and normalized_archived_count == 0)
        )
        if normalized_archived_count == 0:
            normalized_archived_last_seen = None
        elif (
            archived_count == normalized_archived_count
            and archived_last_seen is not None
        ):
            normalized_archived_last_seen = archived_last_seen
        else:
            normalized_archived_last_seen = old_last_seen
        normalized_exact = archive_exact if not conflict else 0
        total_last_seen = max(
            value
            for value in (normalized_archived_last_seen, detail_last_seen)
            if value is not None
        )
        conn.execute(
            """
            UPDATE rejection_patterns
            SET count = ?, last_seen = ?, archived_count = ?,
                archived_last_seen = ?, archive_exact = ?
            WHERE owner_key_hash = ? AND pattern = ? AND tool_name = ?
            """,
            (
                authoritative_total,
                total_last_seen,
                normalized_archived_count,
                normalized_archived_last_seen,
                normalized_exact,
                owner_key_hash,
                pattern,
                tool_name,
            ),
        )

    def record_turn(self, score: TurnScore) -> None:
        """Persist the latest version of a turn and its derived aggregates."""
        if not math.isfinite(score.timestamp):
            raise ValueError("turn timestamp must be finite")
        owner_key_hash = score.owner_key_hash or _LEGACY_OWNER
        with db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                saturated = conn.execute(
                    """
                    SELECT 1
                    FROM quality_session_watermarks
                    WHERE owner_key_hash = ? AND session_id = ? AND run_id = ?
                    """,
                    (owner_key_hash, _SATURATED_SESSION, _SATURATED_RUN),
                ).fetchone()
                if saturated is not None:
                    conn.rollback()
                    return
                current = conn.execute(
                    """
                    SELECT timestamp
                    FROM turn_scores
                    WHERE owner_key_hash = ? AND session_id = ?
                      AND run_id = ? AND turn_idx = ?
                    """,
                    (owner_key_hash, score.session_id, score.run_id, score.turn_idx),
                ).fetchone()
                if current is not None and float(current[0]) >= score.timestamp:
                    conn.rollback()
                    return

                if current is None:
                    watermark = conn.execute(
                        """
                        SELECT pruned_through_turn_idx, pruned_through_timestamp
                        FROM quality_session_watermarks
                        WHERE owner_key_hash = ? AND session_id = ? AND run_id = ?
                        """,
                        (owner_key_hash, score.session_id, score.run_id),
                    ).fetchone()
                    if watermark is not None and (
                        score.turn_idx <= int(watermark[0])
                        or score.timestamp <= float(watermark[1])
                    ):
                        conn.rollback()
                        return

                old_contributions = conn.execute(
                    """
                    SELECT pattern, tool_name
                    FROM rejection_turn_contributions
                    WHERE owner_key_hash = ? AND session_id = ?
                      AND run_id = ? AND turn_idx = ?
                    """,
                    (owner_key_hash, score.session_id, score.run_id, score.turn_idx),
                ).fetchall()
                old_rejections = {
                    (str(pattern), str(tool_name))
                    for pattern, tool_name in old_contributions
                }

                new_rejections: Counter[tuple[str, str]] = Counter()
                new_examples: list[tuple[int, str, str, float, float]] = []
                for ordinal, tool_score in enumerate(score.tool_scores):
                    if not tool_score.success and tool_score.error_pattern:
                        new_rejections[
                            (tool_score.error_pattern, tool_score.tool_name)
                        ] += 1
                    if tool_score.success and tool_score.output_quality >= 0.8:
                        new_examples.append(
                            (
                                ordinal,
                                tool_score.tool_name,
                                tool_score.error_pattern or "high quality output",
                                tool_score.output_quality,
                                score.timestamp,
                            )
                        )

                affected_rejections = old_rejections | set(new_rejections)
                for pattern, tool_name in affected_rejections:
                    self._capture_unarchived_rejection_baseline(
                        conn,
                        owner_key_hash,
                        pattern,
                        tool_name,
                    )

                conn.execute(
                    """
                    DELETE FROM tool_call_scores
                    WHERE owner_key_hash = ? AND session_id = ?
                      AND run_id = ? AND turn_idx = ?
                    """,
                    (owner_key_hash, score.session_id, score.run_id, score.turn_idx),
                )
                conn.execute(
                    """
                    DELETE FROM rejection_turn_contributions
                    WHERE owner_key_hash = ? AND session_id = ?
                      AND run_id = ? AND turn_idx = ?
                    """,
                    (owner_key_hash, score.session_id, score.run_id, score.turn_idx),
                )
                conn.execute(
                    """
                    INSERT INTO turn_scores
                    (owner_key_hash, session_id, run_id, turn_idx, model,
                     overall_score, hallucination_rate, total_tokens, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(owner_key_hash, session_id, run_id, turn_idx)
                    DO UPDATE SET
                        model = excluded.model,
                        overall_score = excluded.overall_score,
                        hallucination_rate = excluded.hallucination_rate,
                        total_tokens = excluded.total_tokens,
                        timestamp = excluded.timestamp
                    """,
                    (
                        owner_key_hash,
                        score.session_id,
                        score.run_id,
                        score.turn_idx,
                        score.model,
                        score.overall_score,
                        score.hallucination_rate,
                        score.total_tokens,
                        score.timestamp,
                    ),
                )
                for tool_score in score.tool_scores:
                    conn.execute(
                        """
                        INSERT INTO tool_call_scores
                        (owner_key_hash, session_id, run_id, turn_idx, tool_name,
                         success, retry_count, error_pattern, output_quality,
                         latency_ms, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            owner_key_hash,
                            score.session_id,
                            score.run_id,
                            score.turn_idx,
                            tool_score.tool_name,
                            int(tool_score.success),
                            tool_score.retry_count,
                            tool_score.error_pattern,
                            tool_score.output_quality,
                            tool_score.latency_ms,
                            score.timestamp,
                        ),
                    )

                for (pattern, tool_name), count in new_rejections.items():
                    conn.execute(
                        """
                        INSERT INTO rejection_turn_contributions
                            (owner_key_hash, session_id, run_id, turn_idx,
                             pattern, tool_name, count, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            owner_key_hash,
                            score.session_id,
                            score.run_id,
                            score.turn_idx,
                            pattern,
                            tool_name,
                            count,
                            score.timestamp,
                        ),
                    )

                for pattern, tool_name in affected_rejections:
                    self._reconcile_rejection_pattern(
                        conn,
                        owner_key_hash,
                        pattern,
                        tool_name,
                    )

                conn.execute(
                    """
                    DELETE FROM high_score_examples
                    WHERE owner_key_hash = ? AND source_session_id = ?
                      AND source_run_id = ? AND source_turn_idx = ?
                    """,
                    (
                        owner_key_hash,
                        score.session_id,
                        score.run_id,
                        score.turn_idx,
                    ),
                )
                for ordinal, tool_name, description, quality, timestamp in new_examples:
                    conn.execute(
                        """
                        INSERT INTO high_score_examples
                            (owner_key_hash, tool_name, description, score, timestamp,
                             source_session_id, source_run_id, source_turn_idx,
                             source_ordinal)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            owner_key_hash,
                            tool_name,
                            description,
                            quality,
                            timestamp,
                            score.session_id,
                            score.run_id,
                            score.turn_idx,
                            ordinal,
                        ),
                    )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def get_rolling_stats(
        self,
        window: int = 20,
        *,
        owner_key_hash: str = _LEGACY_OWNER,
    ) -> dict[str, Any]:
        """Return rolling quality stats over the last N turns."""
        with db_connection(self.db_path) as conn:
            row = conn.execute(
                """
                SELECT AVG(overall_score), AVG(hallucination_rate), COUNT(*)
                FROM (
                    SELECT overall_score, hallucination_rate
                    FROM turn_scores
                    WHERE owner_key_hash = ?
                    ORDER BY timestamp DESC, id DESC
                    LIMIT ?
                ) AS recent_turns
                """,
                (owner_key_hash or _LEGACY_OWNER, window),
            ).fetchone()
        if row and row[0] is not None:
            return {
                "avg_score": round(row[0], 3),
                "avg_hallucination_rate": round(row[1] or 0, 3),
                "sample_size": row[2],
            }
        return {"avg_score": 1.0, "avg_hallucination_rate": 0.0, "sample_size": 0}

    def get_top_rejection_patterns(
        self,
        min_count: int = 2,
        limit: int = 5,
        *,
        owner_key_hash: str = _LEGACY_OWNER,
    ) -> list[dict[str, Any]]:
        """Extract recurring rejection reasons."""
        with db_connection(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT pattern, tool_name, count, last_seen
                FROM rejection_patterns
                WHERE owner_key_hash = ? AND count >= ?
                ORDER BY count DESC, last_seen DESC
                LIMIT ?
                """,
                (owner_key_hash or _LEGACY_OWNER, min_count, limit),
            ).fetchall()
        return [
            {"pattern": r[0], "tool_name": r[1], "count": r[2], "last_seen": r[3]}
            for r in rows
        ]

    def get_high_score_examples(
        self,
        limit: int = 5,
        *,
        owner_key_hash: str = _LEGACY_OWNER,
    ) -> list[dict[str, Any]]:
        """Return top-scoring output patterns."""
        with db_connection(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT tool_name, description, score, timestamp
                FROM high_score_examples
                WHERE owner_key_hash = ?
                ORDER BY score DESC, timestamp DESC
                LIMIT ?
                """,
                (owner_key_hash or _LEGACY_OWNER, limit),
            ).fetchall()
        return [
            {"tool_name": r[0], "description": r[1], "score": r[2], "timestamp": r[3]}
            for r in rows
        ]

    def build_learning_context(
        self,
        max_tokens: int = 800,
        *,
        owner_key_hash: str = _LEGACY_OWNER,
    ) -> str:
        """Build a compressed learning-context block for injection into system prompt.

        OpenHuman-style: includes corrections, rejection patterns, high-scoring
        examples, and a performance summary — all role-scoped and token-budgeted.
        """
        parts: list[str] = []
        stats = self.get_rolling_stats(
            window=20,
            owner_key_hash=owner_key_hash,
        )
        parts.append(
            f"[LEARNING CONTEXT] Rolling quality: score={stats['avg_score']:.2f}, "
            f"hallucination_rate={stats['avg_hallucination_rate']:.2f}, n={stats['sample_size']}"
        )

        # Rejection patterns
        patterns = self.get_top_rejection_patterns(
            min_count=2,
            limit=3,
            owner_key_hash=owner_key_hash,
        )
        if patterns:
            parts.append("Common failures:")
            for p in patterns:
                parts.append(f"  - {p['tool_name'] or 'general'}: {p['pattern']} (x{p['count']})")

        # High-score examples
        examples = self.get_high_score_examples(
            limit=3,
            owner_key_hash=owner_key_hash,
        )
        if examples:
            parts.append("High-quality patterns:")
            for e in examples:
                parts.append(f"  - {e['tool_name']}: {e['description'][:80]}")

        text = "\n".join(parts)
        # Hard token budget: ~4 chars per token
        max_chars = max_tokens * 4
        if len(text) > max_chars:
            text = text[:max_chars] + "\n... [truncated]"
        return text

    def prune(
        self,
        *,
        keep_turns_per_owner: int = 1_000,
        keep_tool_calls_per_turn: int = 100,
        keep_patterns_per_owner: int = 100,
        keep_examples_per_owner: int = 100,
    ) -> int:
        """Bound quality history independently for every owner partition."""
        limits = (
            keep_turns_per_owner,
            keep_tool_calls_per_turn,
            keep_patterns_per_owner,
            keep_examples_per_owner,
        )
        if any(limit < 1 for limit in limits):
            raise ValueError("quality retention limits must be positive")

        removed = 0
        with db_connection(self.db_path) as conn:
            conn.execute("PRAGMA temp_store = FILE")
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    CREATE TEMP TABLE echo_prune_turns AS
                    WITH ranked AS (
                        SELECT id, owner_key_hash, session_id, run_id, turn_idx,
                               timestamp,
                               ROW_NUMBER() OVER (
                                   PARTITION BY owner_key_hash
                                   ORDER BY timestamp DESC, id DESC
                               ) AS owner_rank
                        FROM turn_scores
                    )
                    SELECT id, owner_key_hash, session_id, run_id, turn_idx, timestamp
                    FROM ranked
                    WHERE owner_rank > ?
                    """,
                    (keep_turns_per_owner,),
                )
                conn.execute(
                    """
                    CREATE UNIQUE INDEX echo_prune_turns_id
                    ON echo_prune_turns(id)
                    """
                )
                conn.execute(
                    """
                    CREATE UNIQUE INDEX echo_prune_turns_identity
                    ON echo_prune_turns(owner_key_hash, session_id, run_id, turn_idx)
                    """
                )

                conn.execute(
                    """
                    CREATE TEMP TABLE echo_prune_rejections AS
                    SELECT contribution.owner_key_hash,
                           contribution.pattern,
                           contribution.tool_name,
                           SUM(contribution.count) AS removed_count,
                           MAX(contribution.last_seen) AS removed_last_seen
                    FROM rejection_turn_contributions AS contribution
                    JOIN echo_prune_turns AS prune_turn
                      ON prune_turn.owner_key_hash = contribution.owner_key_hash
                     AND prune_turn.session_id = contribution.session_id
                     AND prune_turn.run_id = contribution.run_id
                     AND prune_turn.turn_idx = contribution.turn_idx
                    GROUP BY contribution.owner_key_hash,
                             contribution.pattern,
                             contribution.tool_name
                    """
                )
                conn.execute(
                    """
                    INSERT INTO rejection_patterns
                        (owner_key_hash, pattern, tool_name, count, last_seen,
                         archived_count, archived_last_seen, archive_exact)
                    SELECT owner_key_hash, pattern, tool_name, removed_count,
                           removed_last_seen, removed_count, removed_last_seen, 1
                    FROM echo_prune_rejections
                    WHERE 1
                    ON CONFLICT(owner_key_hash, pattern, tool_name) DO UPDATE SET
                        archived_count = rejection_patterns.archived_count
                                         + excluded.archived_count,
                        archived_last_seen = CASE
                            WHEN rejection_patterns.archived_last_seen IS NULL
                                THEN excluded.archived_last_seen
                            ELSE MAX(
                                rejection_patterns.archived_last_seen,
                                excluded.archived_last_seen
                            )
                        END,
                        archive_exact = MIN(
                            rejection_patterns.archive_exact,
                            excluded.archive_exact
                        )
                    """
                )
                rejection_signatures = conn.execute(
                    """
                    SELECT owner_key_hash, pattern, tool_name
                    FROM echo_prune_rejections
                    """
                ).fetchall()
                conn.execute(
                    """
                    INSERT INTO quality_session_watermarks
                        (owner_key_hash, session_id, run_id,
                         pruned_through_turn_idx, pruned_through_timestamp)
                    SELECT owner_key_hash, session_id, run_id, MAX(turn_idx),
                           MAX(timestamp)
                    FROM echo_prune_turns AS prune_turn
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM quality_session_watermarks AS watermark
                        WHERE watermark.owner_key_hash = prune_turn.owner_key_hash
                          AND watermark.session_id = ?
                          AND watermark.run_id = ?
                    )
                    GROUP BY owner_key_hash, session_id, run_id
                    ON CONFLICT(owner_key_hash, session_id, run_id) DO UPDATE SET
                        pruned_through_turn_idx = MAX(
                            quality_session_watermarks.pruned_through_turn_idx,
                            excluded.pruned_through_turn_idx
                        ),
                        pruned_through_timestamp = MAX(
                            quality_session_watermarks.pruned_through_timestamp,
                            excluded.pruned_through_timestamp
                        )
                    """,
                    (_SATURATED_SESSION, _SATURATED_RUN),
                )
                conn.execute(
                    """
                    CREATE TEMP TABLE echo_saturated_quality_owners AS
                    SELECT owner_key_hash
                    FROM quality_session_watermarks
                    WHERE NOT (
                        session_id = ? AND run_id = ?
                    )
                    GROUP BY owner_key_hash
                    HAVING COUNT(*) > ?
                    """,
                    (
                        _SATURATED_SESSION,
                        _SATURATED_RUN,
                        _MAX_WATERMARKS_PER_OWNER,
                    ),
                )
                saturated_owners = [
                    str(row[0])
                    for row in conn.execute(
                        "SELECT owner_key_hash FROM echo_saturated_quality_owners"
                    ).fetchall()
                ]
                conn.execute(
                    """
                    DELETE FROM quality_session_watermarks
                    WHERE owner_key_hash IN (
                        SELECT owner_key_hash
                        FROM echo_saturated_quality_owners
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO quality_session_watermarks
                        (owner_key_hash, session_id, run_id,
                         pruned_through_turn_idx, pruned_through_timestamp)
                    SELECT owner_key_hash, ?, ?, 0, 0.0
                    FROM echo_saturated_quality_owners
                    """,
                    (_SATURATED_SESSION, _SATURATED_RUN),
                )
                conn.execute("DROP TABLE echo_saturated_quality_owners")
                conn.execute(
                    """
                    DELETE FROM rejection_turn_contributions
                    WHERE EXISTS (
                        SELECT 1
                        FROM echo_prune_turns AS prune_turn
                        WHERE prune_turn.owner_key_hash =
                                  rejection_turn_contributions.owner_key_hash
                          AND prune_turn.session_id =
                                  rejection_turn_contributions.session_id
                          AND prune_turn.run_id =
                                  rejection_turn_contributions.run_id
                          AND prune_turn.turn_idx =
                                  rejection_turn_contributions.turn_idx
                    )
                    """
                )
                removed += int(conn.execute("SELECT changes()").fetchone()[0])
                conn.execute(
                    """
                    DELETE FROM turn_scores
                    WHERE id IN (SELECT id FROM echo_prune_turns)
                    """
                )
                removed += int(conn.execute("SELECT changes()").fetchone()[0])

                conn.execute(
                    """
                    CREATE TEMP TABLE echo_prune_tool_ids (
                        id INTEGER PRIMARY KEY
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO echo_prune_tool_ids(id)
                    WITH ranked AS (
                        SELECT id,
                               ROW_NUMBER() OVER (
                                   PARTITION BY owner_key_hash, session_id, run_id,
                                                turn_idx
                                   ORDER BY timestamp DESC, id DESC
                               ) AS turn_rank
                        FROM tool_call_scores
                    )
                    SELECT id FROM ranked WHERE turn_rank > ?
                    """,
                    (keep_tool_calls_per_turn,),
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO echo_prune_tool_ids(id)
                    SELECT tool_score.id
                    FROM tool_call_scores AS tool_score
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM turn_scores AS turn_score
                        WHERE turn_score.owner_key_hash = tool_score.owner_key_hash
                          AND turn_score.session_id = tool_score.session_id
                          AND turn_score.run_id = tool_score.run_id
                          AND turn_score.turn_idx = tool_score.turn_idx
                    )
                    """
                )
                conn.execute(
                    """
                    DELETE FROM tool_call_scores
                    WHERE id IN (SELECT id FROM echo_prune_tool_ids)
                    """
                )
                removed += int(conn.execute("SELECT changes()").fetchone()[0])
                for owner_key_hash, pattern, tool_name in rejection_signatures:
                    self._reconcile_rejection_pattern(
                        conn,
                        str(owner_key_hash),
                        str(pattern),
                        str(tool_name),
                    )
                conn.execute("DROP TABLE echo_prune_tool_ids")
                conn.execute("DROP TABLE echo_prune_rejections")
                conn.execute("DROP TABLE echo_prune_turns")

                conn.execute(
                    """
                    CREATE TEMP TABLE echo_prune_pattern_signatures AS
                    WITH ranked AS (
                        SELECT owner_key_hash, pattern, tool_name,
                               ROW_NUMBER() OVER (
                                   PARTITION BY owner_key_hash
                                   ORDER BY count DESC, last_seen DESC, id DESC
                               ) AS owner_rank
                        FROM rejection_patterns
                    )
                    SELECT owner_key_hash, pattern, tool_name
                    FROM ranked
                    WHERE owner_rank > ?
                    """,
                    (keep_patterns_per_owner,),
                )
                conn.execute(
                    """
                    DELETE FROM tool_call_scores
                    WHERE success = 0
                      AND EXISTS (
                        SELECT 1
                        FROM echo_prune_pattern_signatures AS signature
                        WHERE signature.owner_key_hash =
                                  tool_call_scores.owner_key_hash
                          AND signature.pattern = tool_call_scores.error_pattern
                          AND signature.tool_name = tool_call_scores.tool_name
                    )
                    """
                )
                removed += int(conn.execute("SELECT changes()").fetchone()[0])
                conn.execute(
                    """
                    DELETE FROM rejection_turn_contributions
                    WHERE EXISTS (
                        SELECT 1
                        FROM echo_prune_pattern_signatures AS signature
                        WHERE signature.owner_key_hash =
                                  rejection_turn_contributions.owner_key_hash
                          AND signature.pattern =
                                  rejection_turn_contributions.pattern
                          AND signature.tool_name =
                                  rejection_turn_contributions.tool_name
                    )
                    """
                )
                removed += int(conn.execute("SELECT changes()").fetchone()[0])
                conn.execute(
                    """
                    DELETE FROM rejection_patterns
                    WHERE EXISTS (
                        SELECT 1
                        FROM echo_prune_pattern_signatures AS signature
                        WHERE signature.owner_key_hash =
                                  rejection_patterns.owner_key_hash
                          AND signature.pattern = rejection_patterns.pattern
                          AND signature.tool_name = rejection_patterns.tool_name
                    )
                    """
                )
                removed += int(conn.execute("SELECT changes()").fetchone()[0])
                conn.execute("DROP TABLE echo_prune_pattern_signatures")

                conn.execute(
                    """
                    WITH ranked AS (
                        SELECT id,
                               ROW_NUMBER() OVER (
                                   PARTITION BY owner_key_hash
                                   ORDER BY score DESC, timestamp DESC, id DESC
                               ) AS owner_rank
                        FROM high_score_examples
                    )
                    DELETE FROM high_score_examples
                    WHERE id IN (
                        SELECT id FROM ranked WHERE owner_rank > ?
                    )
                    """,
                    (keep_examples_per_owner,),
                )
                removed += int(conn.execute("SELECT changes()").fetchone()[0])
                conn.commit()
                for saturated_owner in saturated_owners:
                    logger.error(
                        "Quality replay watermark budget exhausted for owner %s; "
                        "future quality writes are fail-closed",
                        saturated_owner,
                    )
            except Exception:
                conn.rollback()
                raise
        return removed
