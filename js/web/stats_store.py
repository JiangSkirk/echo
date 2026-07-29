"""Persistent token usage statistics storage."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

_DEFAULT_MAX_ROWS = 1_000


class TokenStatsStore:
    """SQLite-backed store for token usage statistics."""

    def __init__(self, state_dir: Path) -> None:
        self.db_path = state_dir / "token_stats.db"
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS token_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    run_id TEXT,
                    model TEXT NOT NULL,
                    provider TEXT,
                    prompt_tokens INTEGER DEFAULT 0,
                    completion_tokens INTEGER DEFAULT 0,
                    total_tokens INTEGER DEFAULT 0,
                    cost REAL DEFAULT 0.0,
                    cached_tokens INTEGER DEFAULT 0,
                    timestamp REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_token_usage_model ON token_usage(model)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_token_usage_timestamp ON token_usage(timestamp)
            """)
            conn.commit()

    def record(
        self,
        model: str,
        provider: str,
        prompt_tokens: int,
        completion_tokens: int,
        cost: float = 0.0,
        cached_tokens: int = 0,
        session_id: str = "",
        run_id: str = "",
    ) -> None:
        """Record a single usage entry."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO token_usage
                (session_id, run_id, model, provider, prompt_tokens, completion_tokens, total_tokens, cost, cached_tokens, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    run_id,
                    model,
                    provider,
                    prompt_tokens,
                    completion_tokens,
                    prompt_tokens + completion_tokens,
                    cost,
                    cached_tokens,
                    time.time(),
                ),
            )
            conn.commit()

    def prune(self, days: int = 90, max_rows: int = _DEFAULT_MAX_ROWS) -> int:
        """Apply the age window, then retain only the newest ``max_rows``."""
        if days < 0:
            raise ValueError("days must be non-negative")
        if max_rows < 0:
            raise ValueError("max_rows must be non-negative")

        since = time.time() - days * 86400
        with sqlite3.connect(self.db_path) as conn:
            changes_before = conn.total_changes
            conn.execute("DELETE FROM token_usage WHERE timestamp < ?", (since,))
            conn.execute(
                """
                DELETE FROM token_usage
                WHERE id IN (
                    SELECT id
                    FROM token_usage
                    ORDER BY timestamp DESC, id DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (max_rows,),
            )
            return conn.total_changes - changes_before

    def get_summary(self, days: int = 30) -> dict[str, Any]:
        """Get aggregated token usage summary."""
        since = time.time() - days * 86400
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            # Overall totals
            row = conn.execute(
                """
                SELECT
                    COUNT(*) as total_calls,
                    SUM(prompt_tokens) as total_prompt,
                    SUM(completion_tokens) as total_completion,
                    SUM(total_tokens) as total_tokens,
                    SUM(cost) as total_cost,
                    SUM(cached_tokens) as total_cached
                FROM token_usage
                WHERE timestamp > ?
                """,
                (since,),
            ).fetchone()

            # Per-model breakdown
            models = conn.execute(
                """
                SELECT
                    model,
                    COUNT(*) as calls,
                    SUM(prompt_tokens) as prompt_tokens,
                    SUM(completion_tokens) as completion_tokens,
                    SUM(total_tokens) as total_tokens,
                    SUM(cost) as cost,
                    SUM(cached_tokens) as cached_tokens
                FROM token_usage
                WHERE timestamp > ?
                GROUP BY model
                ORDER BY total_tokens DESC
                """,
                (since,),
            ).fetchall()

            # Daily trend (respects requested days window)
            daily = conn.execute(
                """
                SELECT
                    DATE(timestamp, 'unixepoch') as day,
                    COUNT(*) as calls,
                    SUM(total_tokens) as tokens,
                    SUM(cost) as cost
                FROM token_usage
                WHERE timestamp > ?
                GROUP BY day
                ORDER BY day DESC
                LIMIT ?
                """,
                (since, days),
            ).fetchall()

        total_calls = row["total_calls"] or 0
        total_prompt = row["total_prompt"] or 0
        total_cached = row["total_cached"] or 0
        cache_rate = (total_cached / total_prompt * 100) if total_prompt > 0 else 0.0

        return {
            "period_days": days,
            "total_calls": total_calls,
            "total_prompt_tokens": total_prompt,
            "total_completion_tokens": row["total_completion"] or 0,
            "total_tokens": row["total_tokens"] or 0,
            "total_cost": round(row["total_cost"] or 0, 6),
            "total_cached_tokens": total_cached,
            "cache_rate": round(cache_rate, 2),
            "models": [
                {
                    "model": m["model"],
                    "calls": m["calls"],
                    "prompt_tokens": m["prompt_tokens"],
                    "completion_tokens": m["completion_tokens"],
                    "total_tokens": m["total_tokens"],
                    "cost": round(m["cost"] or 0, 6),
                    "cached_tokens": m["cached_tokens"],
                    "cache_rate": round(
                        (m["cached_tokens"] / m["prompt_tokens"] * 100)
                        if m["prompt_tokens"]
                        else 0,
                        2,
                    ),
                }
                for m in models
            ],
            "daily": [
                {
                    "day": d["day"],
                    "calls": d["calls"],
                    "tokens": d["tokens"],
                    "cost": round(d["cost"] or 0, 6),
                }
                for d in daily
            ],
        }
