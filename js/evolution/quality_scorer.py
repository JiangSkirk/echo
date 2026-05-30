"""Quality scoring and self-learning闭环 (OpenHuman-inspired).

Tracks per-agent output quality, extracts rejection patterns, and builds
a learning-context block that is injected into the system prompt.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from js.utils.db import db_connection
from js.utils.log import get_logger

logger = get_logger("js.evolution.quality")


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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS turn_scores (
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
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tool_call_scores (
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
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rejection_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern TEXT NOT NULL,
                    tool_name TEXT,
                    count INTEGER DEFAULT 1,
                    last_seen REAL NOT NULL,
                    UNIQUE(pattern, tool_name)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS high_score_examples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool_name TEXT,
                    description TEXT,
                    score REAL DEFAULT 0.0,
                    timestamp REAL NOT NULL
                )
            """)

    def record_turn(self, score: TurnScore) -> None:
        """Persist a turn score."""
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO turn_scores
                (session_id, turn_idx, model, overall_score, hallucination_rate, total_tokens, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    score.session_id,
                    score.turn_idx,
                    score.model,
                    score.overall_score,
                    score.hallucination_rate,
                    score.total_tokens,
                    score.timestamp,
                ),
            )
            for tc in score.tool_scores:
                conn.execute(
                    """
                    INSERT INTO tool_call_scores
                    (session_id, turn_idx, tool_name, success, retry_count, error_pattern, output_quality, latency_ms, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        score.session_id,
                        score.turn_idx,
                        tc.tool_name,
                        int(tc.success),
                        tc.retry_count,
                        tc.error_pattern,
                        tc.output_quality,
                        tc.latency_ms,
                        score.timestamp,
                    ),
                )
                if not tc.success and tc.error_pattern:
                    conn.execute(
                        """
                        INSERT INTO rejection_patterns (pattern, tool_name, count, last_seen)
                        VALUES (?, ?, 1, ?)
                        ON CONFLICT(pattern, tool_name) DO UPDATE SET
                            count = count + 1,
                            last_seen = excluded.last_seen
                        """,
                        (tc.error_pattern, tc.tool_name, score.timestamp),
                    )
                if tc.success and tc.output_quality >= 0.8:
                    conn.execute(
                        """
                        INSERT INTO high_score_examples (tool_name, description, score, timestamp)
                        VALUES (?, ?, ?, ?)
                        """,
                        (tc.tool_name, tc.error_pattern or "high quality output", tc.output_quality, score.timestamp),
                    )
            conn.commit()

    def get_rolling_stats(self, window: int = 20) -> dict[str, Any]:
        """Return rolling quality stats over the last N turns."""
        with db_connection(self.db_path) as conn:
            row = conn.execute(
                """
                SELECT AVG(overall_score), AVG(hallucination_rate), COUNT(*)
                FROM turn_scores
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (window,),
            ).fetchone()
        if row and row[0] is not None:
            return {
                "avg_score": round(row[0], 3),
                "avg_hallucination_rate": round(row[1] or 0, 3),
                "sample_size": row[2],
            }
        return {"avg_score": 1.0, "avg_hallucination_rate": 0.0, "sample_size": 0}

    def get_top_rejection_patterns(self, min_count: int = 2, limit: int = 5) -> list[dict[str, Any]]:
        """Extract recurring rejection reasons."""
        with db_connection(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT pattern, tool_name, count, last_seen
                FROM rejection_patterns
                WHERE count >= ?
                ORDER BY count DESC, last_seen DESC
                LIMIT ?
                """,
                (min_count, limit),
            ).fetchall()
        return [
            {"pattern": r[0], "tool_name": r[1], "count": r[2], "last_seen": r[3]}
            for r in rows
        ]

    def get_high_score_examples(self, limit: int = 5) -> list[dict[str, Any]]:
        """Return top-scoring output patterns."""
        with db_connection(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT tool_name, description, score, timestamp
                FROM high_score_examples
                ORDER BY score DESC, timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {"tool_name": r[0], "description": r[1], "score": r[2], "timestamp": r[3]}
            for r in rows
        ]

    def build_learning_context(
        self,
        max_tokens: int = 800,
    ) -> str:
        """Build a compressed learning-context block for injection into system prompt.

        OpenHuman-style: includes corrections, rejection patterns, high-scoring
        examples, and a performance summary — all role-scoped and token-budgeted.
        """
        parts: list[str] = []
        stats = self.get_rolling_stats(window=20)
        parts.append(
            f"[LEARNING CONTEXT] Rolling quality: score={stats['avg_score']:.2f}, "
            f"hallucination_rate={stats['avg_hallucination_rate']:.2f}, n={stats['sample_size']}"
        )

        # Rejection patterns
        patterns = self.get_top_rejection_patterns(min_count=2, limit=3)
        if patterns:
            parts.append("Common failures:")
            for p in patterns:
                parts.append(f"  - {p['tool_name'] or 'general'}: {p['pattern']} (x{p['count']})")

        # High-score examples
        examples = self.get_high_score_examples(limit=3)
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

