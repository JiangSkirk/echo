"""Compression quality feedback loop.

Tracks compression events and correlates them with downstream task outcomes.
Auto-adjusts compression parameters when compression is suspected of causing failures.

Inspired by Hermes Agent's dual-layer compression with quality signals.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.utils.db import db_connection
from js.utils.log import get_logger

logger = get_logger("js.compression.feedback")


@dataclass
class CompressionEvent:
    """Record of a single compression operation."""

    id: str
    session_id: str
    original_tokens: int
    compressed_tokens: int
    level: str  # "gentle" or "full"
    original_messages: int
    compressed_messages: int
    identifiers_found: int
    timestamp: float


class CompressionFeedback:
    """Tracks compression quality and auto-adjusts parameters."""

    # How many turns after compression to check for failures
    FAILURE_WINDOW = 3

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.db_path = state_dir / "compression_feedback.db"
        self._init_db()

    def _init_db(self) -> None:
        with db_connection(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS compression_events (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    original_tokens INTEGER NOT NULL,
                    compressed_tokens INTEGER NOT NULL,
                    level TEXT NOT NULL,
                    original_messages INTEGER NOT NULL,
                    compressed_messages INTEGER NOT NULL,
                    identifiers_found INTEGER DEFAULT 0,
                    timestamp REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS task_outcomes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    turn_number INTEGER NOT NULL,
                    success INTEGER NOT NULL,
                    error_type TEXT,
                    timestamp REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS parameter_adjustments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    parameter TEXT NOT NULL,
                    old_value REAL NOT NULL,
                    new_value REAL NOT NULL,
                    reason TEXT NOT NULL,
                    adjusted_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_session ON compression_events(session_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_outcomes_session ON task_outcomes(session_id)
            """)
            conn.commit()

    def record_compression(
        self,
        session_id: str,
        original_tokens: int,
        compressed_tokens: int,
        level: str,
        original_messages: int,
        compressed_messages: int,
        identifiers_found: int = 0,
    ) -> str:
        """Record a compression event."""
        import uuid
        event_id = f"comp_{uuid.uuid4().hex[:8]}"
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO compression_events
                (id, session_id, original_tokens, compressed_tokens, level,
                 original_messages, compressed_messages, identifiers_found, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id, session_id, original_tokens, compressed_tokens, level,
                    original_messages, compressed_messages, identifiers_found, time.time(),
                ),
            )
            conn.commit()
        return event_id

    def record_outcome(
        self,
        session_id: str,
        turn_number: int,
        success: bool,
        error_type: str | None = None,
    ) -> None:
        """Record a task outcome for correlation analysis."""
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO task_outcomes (session_id, turn_number, success, error_type, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (session_id, turn_number, int(success), error_type, time.time()),
            )
            conn.commit()

    def analyze(self) -> dict[str, Any]:
        """Analyze compression quality and suggest parameter adjustments."""
        with db_connection(self.db_path) as conn:
            # Overall stats
            total_events = conn.execute("SELECT COUNT(*) FROM compression_events").fetchone()[0]
            if total_events == 0:
                return {"total_events": 0, "suggestions": []}

            # Success rate after compression by level
            level_stats = conn.execute("""
                SELECT ce.level,
                       COUNT(*) as count,
                       AVG(CASE WHEN to2.success = 1 THEN 1.0 ELSE 0.0 END) as success_rate
                FROM compression_events ce
                LEFT JOIN task_outcomes to2
                  ON ce.session_id = to2.session_id
                  AND to2.turn_number <= ?
                GROUP BY ce.level
            """, (self.FAILURE_WINDOW,)).fetchall()

            # Compression events followed by failure
            suspicious = conn.execute("""
                SELECT ce.id, ce.session_id, ce.level, ce.original_tokens, ce.compressed_tokens
                FROM compression_events ce
                JOIN task_outcomes to2
                  ON ce.session_id = to2.session_id
                  AND to2.turn_number <= ?
                  AND to2.success = 0
                GROUP BY ce.id
            """, (self.FAILURE_WINDOW,)).fetchall()

        suggestions = []
        for level, _count, rate in level_stats:
            if rate is not None and rate < 0.7:
                suggestions.append({
                    "issue": f"Low success rate ({rate*100:.0f}%) after {level} compression",
                    "suggestion": f"Consider increasing protect_tail_turns or reducing {level} compression aggressiveness",
                })

        return {
            "total_events": total_events,
            "level_stats": [
                {"level": level, "count": count, "success_rate": rate}
                for level, count, rate in level_stats
            ],
            "suspicious_count": len(suspicious),
            "suggestions": suggestions,
        }

    def get_adjustment_recommendations(self) -> dict[str, Any]:
        """Get specific parameter adjustment recommendations."""
        analysis = self.analyze()
        recommendations: dict[str, Any] = {}

        for suggestion in analysis["suggestions"]:
            if "protect_tail_turns" in suggestion["suggestion"]:
                recommendations["protect_tail_turns"] = {
                    "current": None,  # caller must provide
                    "recommended_delta": +2,
                    "reason": suggestion["issue"],
                }
            if "protect_head_messages" in suggestion["suggestion"]:
                recommendations["protect_head_messages"] = {
                    "current": None,
                    "recommended_delta": +1,
                    "reason": suggestion["issue"],
                }

        return {
            "needs_adjustment": len(recommendations) > 0,
            "recommendations": recommendations,
            "analysis": analysis,
        }

    def apply_adjustment(self, parameter: str, new_value: float, reason: str) -> None:
        """Record a parameter adjustment."""
        with db_connection(self.db_path) as conn:
            old_row = conn.execute(
                "SELECT new_value FROM parameter_adjustments WHERE parameter = ? ORDER BY adjusted_at DESC LIMIT 1",
                (parameter,),
            ).fetchone()
            old_value = old_row[0] if old_row else 0.0
            conn.execute(
                """
                INSERT INTO parameter_adjustments (parameter, old_value, new_value, reason, adjusted_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (parameter, old_value, new_value, reason, time.time()),
            )
            conn.commit()
        logger.info(f"Adjusted {parameter}: {old_value} -> {new_value} ({reason})")

    def get_stats(self) -> dict[str, Any]:
        """Get feedback statistics."""
        with db_connection(self.db_path) as conn:
            total_events = conn.execute("SELECT COUNT(*) FROM compression_events").fetchone()[0]
            total_outcomes = conn.execute("SELECT COUNT(*) FROM task_outcomes").fetchone()[0]
            total_adjustments = conn.execute("SELECT COUNT(*) FROM parameter_adjustments").fetchone()[0]
            avg_reduction = conn.execute(
                "SELECT AVG(original_tokens - compressed_tokens) FROM compression_events"
            ).fetchone()[0]

        return {
            "total_compression_events": total_events,
            "total_task_outcomes": total_outcomes,
            "total_adjustments": total_adjustments,
            "avg_token_reduction": round(avg_reduction or 0, 1),
        }
