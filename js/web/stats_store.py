"""Persistent token usage statistics. Exclusive buckets are the ledger."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

from js.models.usage import ExclusiveUsageBuckets, buckets_from_usage_dict, coerce_usage_source

_ROLLUP_AFTER_DAYS = 7


class TokenStatsStore:
    """SQLite-backed store for token usage statistics."""

    def __init__(self, state_dir: Path) -> None:
        self.db_path = state_dir / "token_stats.db"
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
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
                    uncached_input INTEGER DEFAULT 0,
                    cache_read INTEGER DEFAULT 0,
                    cache_write INTEGER DEFAULT 0,
                    output INTEGER DEFAULT 0,
                    reasoning INTEGER DEFAULT 0,
                    input_total INTEGER DEFAULT 0,
                    usage_source TEXT DEFAULT 'unavailable',
                    prefix_id TEXT DEFAULT '',
                    bot_id TEXT DEFAULT '',
                    exclude_from_hit_rate INTEGER DEFAULT 0,
                    timestamp REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS token_usage_daily (
                    day TEXT NOT NULL,
                    model TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    calls INTEGER DEFAULT 0,
                    uncached_input INTEGER DEFAULT 0,
                    cache_read INTEGER DEFAULT 0,
                    cache_write INTEGER DEFAULT 0,
                    output INTEGER DEFAULT 0,
                    reasoning INTEGER DEFAULT 0,
                    input_total INTEGER DEFAULT 0,
                    cost REAL DEFAULT 0.0,
                    hit_read INTEGER DEFAULT 0,
                    hit_denom INTEGER DEFAULT 0,
                    PRIMARY KEY (day, model, provider)
                )
                """
            )
            self._ensure_columns(conn)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_token_usage_model ON token_usage(model)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_token_usage_timestamp ON token_usage(timestamp)"
            )
            conn.commit()

    @staticmethod
    def _ensure_columns(conn: sqlite3.Connection) -> None:
        existing = {row[1] for row in conn.execute("PRAGMA table_info(token_usage)").fetchall()}
        additions = {
            "uncached_input": "INTEGER DEFAULT 0",
            "cache_read": "INTEGER DEFAULT 0",
            "cache_write": "INTEGER DEFAULT 0",
            "output": "INTEGER DEFAULT 0",
            "reasoning": "INTEGER DEFAULT 0",
            "input_total": "INTEGER DEFAULT 0",
            "usage_source": "TEXT DEFAULT 'unavailable'",
            "prefix_id": "TEXT DEFAULT ''",
            "bot_id": "TEXT DEFAULT ''",
            "exclude_from_hit_rate": "INTEGER DEFAULT 0",
        }
        for name, decl in additions.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE token_usage ADD COLUMN {name} {decl}")
        daily_existing = {
            row[1] for row in conn.execute("PRAGMA table_info(token_usage_daily)").fetchall()
        }
        for name, decl in {
            "hit_read": "INTEGER DEFAULT 0",
            "hit_denom": "INTEGER DEFAULT 0",
        }.items():
            if name not in daily_existing:
                conn.execute(f"ALTER TABLE token_usage_daily ADD COLUMN {name} {decl}")

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
        *,
        uncached_input: int | None = None,
        cache_read: int | None = None,
        cache_write: int = 0,
        output: int | None = None,
        reasoning: int = 0,
        input_total: int | None = None,
        usage_source: str = "unavailable",
        prefix_id: str = "",
        bot_id: str = "",
        exclude_from_hit_rate: bool = False,
    ) -> None:
        """Record a single usage entry using exclusive buckets when provided."""

        read = cached_tokens if cache_read is None else cache_read
        write = cache_write
        out = completion_tokens if output is None else output
        if uncached_input is None:
            uncached = max(int(prompt_tokens) - int(read) - int(write), 0)
        else:
            uncached = uncached_input
        total_in = uncached + read + write if input_total is None else input_total
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO token_usage
                (session_id, run_id, model, provider, prompt_tokens, completion_tokens,
                 total_tokens, cost, cached_tokens, uncached_input, cache_read,
                 cache_write, output, reasoning, input_total, usage_source, prefix_id,
                 bot_id, exclude_from_hit_rate, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    run_id,
                    model,
                    provider,
                    total_in,
                    out,
                    total_in + out,
                    cost,
                    read,
                    uncached,
                    read,
                    write,
                    out,
                    reasoning,
                    total_in,
                    usage_source,
                    prefix_id,
                    bot_id,
                    1 if exclude_from_hit_rate else 0,
                    time.time(),
                ),
            )
            conn.commit()

    def record_buckets(
        self,
        buckets: ExclusiveUsageBuckets,
        *,
        model: str,
        provider: str,
        cost: float = 0.0,
        session_id: str = "",
        run_id: str = "",
        bot_id: str = "",
        exclude_from_hit_rate: bool = False,
    ) -> None:
        self.record(
            model,
            provider,
            buckets.input_total,
            buckets.output,
            cost=cost,
            cached_tokens=buckets.cache_read,
            session_id=session_id,
            run_id=run_id,
            uncached_input=buckets.uncached_input,
            cache_read=buckets.cache_read,
            cache_write=buckets.cache_write,
            output=buckets.output,
            reasoning=buckets.reasoning,
            input_total=buckets.input_total,
            usage_source=buckets.usage_source,
            prefix_id=buckets.prefix_id,
            bot_id=bot_id,
            exclude_from_hit_rate=exclude_from_hit_rate,
        )

    def prune(self, days: int = 90, max_rows: int = 0) -> int:
        """Apply the age window, then roll older days up. No silent 1000-row drop.

        ``max_rows`` stays available for explicit callers and tests. The default
        of 0 means "do not cap detail rows"; daily rollup shrinks the table.
        """

        if days < 0:
            raise ValueError("days must be non-negative")
        if max_rows < 0:
            raise ValueError("max_rows must be non-negative")

        since = time.time() - days * 86400
        rollup_before = time.time() - _ROLLUP_AFTER_DAYS * 86400
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("BEGIN")
            try:
                changes_before = conn.total_changes
                conn.execute("DELETE FROM token_usage WHERE timestamp < ?", (since,))
                conn.execute(
                    "DELETE FROM token_usage_daily WHERE day < date(?, 'unixepoch')", (since,)
                )
                self._rollup_older_than(conn, rollup_before)
                if max_rows > 0:
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
                conn.commit()
                return conn.total_changes - changes_before
            except Exception:
                conn.rollback()
                raise

    def _rollup_older_than(self, conn: sqlite3.Connection, before: float) -> None:
        rows = conn.execute(
            """
            SELECT DATE(timestamp, 'unixepoch') as day, model, provider,
                   COUNT(*) as calls,
                   SUM(uncached_input) as uncached_input,
                   SUM(cache_read) as cache_read,
                   SUM(cache_write) as cache_write,
                   SUM(output) as output,
                   SUM(reasoning) as reasoning,
                   SUM(input_total) as input_total,
                   SUM(cost) as cost,
                   SUM(CASE WHEN exclude_from_hit_rate = 0
                             AND usage_source = 'provider_actual'
                            THEN cache_read ELSE 0 END) as hit_read,
                   SUM(CASE WHEN exclude_from_hit_rate = 0
                             AND usage_source = 'provider_actual'
                            THEN input_total ELSE 0 END) as hit_denom
            FROM token_usage
            WHERE timestamp < ?
            GROUP BY day, model, provider
            """,
            (before,),
        ).fetchall()
        for row in rows:
            conn.execute(
                """
                INSERT INTO token_usage_daily (
                    day, model, provider, calls, uncached_input, cache_read,
                    cache_write, output, reasoning, input_total, cost,
                    hit_read, hit_denom
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(day, model, provider) DO UPDATE SET
                    calls = calls + excluded.calls,
                    uncached_input = uncached_input + excluded.uncached_input,
                    cache_read = cache_read + excluded.cache_read,
                    cache_write = cache_write + excluded.cache_write,
                    output = output + excluded.output,
                    reasoning = reasoning + excluded.reasoning,
                    input_total = input_total + excluded.input_total,
                    cost = cost + excluded.cost,
                    hit_read = hit_read + excluded.hit_read,
                    hit_denom = hit_denom + excluded.hit_denom
                """,
                tuple(row),
            )
        conn.execute("DELETE FROM token_usage WHERE timestamp < ?", (before,))

    def get_summary(self, days: int = 30) -> dict[str, Any]:
        """Aggregated usage. Hit rate is cache_read / input_total, never cached/prompt."""

        since = time.time() - days * 86400
        since_day = time.strftime("%Y-%m-%d", time.gmtime(since))
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            live = conn.execute(
                """
                SELECT
                    COUNT(*) as total_calls,
                    SUM(input_total) as input_total,
                    SUM(output) as output,
                    SUM(uncached_input) as uncached_input,
                    SUM(cache_read) as cache_read,
                    SUM(cache_write) as cache_write,
                    SUM(cost) as total_cost,
                    SUM(CASE WHEN exclude_from_hit_rate = 0
                              AND usage_source = 'provider_actual'
                             THEN cache_read ELSE 0 END) as hit_read,
                    SUM(CASE WHEN exclude_from_hit_rate = 0
                              AND usage_source = 'provider_actual'
                             THEN input_total ELSE 0 END) as hit_denom
                FROM token_usage
                WHERE timestamp > ?
                """,
                (since,),
            ).fetchone()
            rolled = conn.execute(
                """
                SELECT
                    SUM(calls) as total_calls,
                    SUM(input_total) as input_total,
                    SUM(output) as output,
                    SUM(uncached_input) as uncached_input,
                    SUM(cache_read) as cache_read,
                    SUM(cache_write) as cache_write,
                    SUM(cost) as total_cost,
                    SUM(hit_read) as hit_read,
                    SUM(hit_denom) as hit_denom
                FROM token_usage_daily
                WHERE day >= ?
                """,
                (since_day,),
            ).fetchone()
            models = conn.execute(
                """
                SELECT model,
                    COUNT(*) as calls,
                    SUM(input_total) as input_total,
                    SUM(output) as output,
                    SUM(cache_read) as cache_read,
                    SUM(cost) as cost
                FROM token_usage
                WHERE timestamp > ?
                GROUP BY model
                ORDER BY input_total DESC
                """,
                (since,),
            ).fetchall()
            daily = conn.execute(
                """
                SELECT DATE(timestamp, 'unixepoch') as day,
                    COUNT(*) as calls,
                    SUM(input_total + output) as tokens,
                    SUM(cost) as cost
                FROM token_usage
                WHERE timestamp > ?
                GROUP BY day
                ORDER BY day DESC
                LIMIT ?
                """,
                (since, days),
            ).fetchall()

        live_calls = int(live["total_calls"] or 0)
        rolled_calls = int((rolled["total_calls"] if rolled else 0) or 0)
        input_total = int(live["input_total"] or 0) + int(
            (rolled["input_total"] if rolled else 0) or 0
        )
        output = int(live["output"] or 0) + int((rolled["output"] if rolled else 0) or 0)
        cache_read = int(live["cache_read"] or 0) + int(
            (rolled["cache_read"] if rolled else 0) or 0
        )
        hit_read = int(live["hit_read"] or 0) + int((rolled["hit_read"] if rolled else 0) or 0)
        hit_denom = int(live["hit_denom"] or 0) + int((rolled["hit_denom"] if rolled else 0) or 0)
        cache_rate = (hit_read / hit_denom * 100) if hit_denom > 0 else 0.0
        total_cost = float(live["total_cost"] or 0) + float(
            (rolled["total_cost"] if rolled else 0) or 0
        )

        model_rows = [
            {
                "model": row["model"],
                "calls": row["calls"],
                "prompt_tokens": row["input_total"] or 0,
                "completion_tokens": row["output"] or 0,
                "total_tokens": (row["input_total"] or 0) + (row["output"] or 0),
                "cost": round(row["cost"] or 0, 6),
                "cached_tokens": row["cache_read"] or 0,
                "cache_rate": round(
                    ((row["cache_read"] or 0) / (row["input_total"] or 1) * 100)
                    if row["input_total"]
                    else 0.0,
                    2,
                ),
            }
            for row in models
        ]
        return {
            "period_days": days,
            "total_calls": live_calls + rolled_calls,
            "total_prompt_tokens": input_total,
            "total_completion_tokens": output,
            "total_tokens": input_total + output,
            "total_cost": round(total_cost, 6),
            "total_cached_tokens": cache_read,
            "cache_rate": round(cache_rate, 2),
            "models": model_rows,
            "per_model": model_rows,
            "daily": [
                {
                    "day": row["day"],
                    "calls": row["calls"],
                    "tokens": row["tokens"],
                    "cost": round(row["cost"] or 0, 6),
                }
                for row in daily
            ],
            "daily_trend": [
                {
                    "day": row["day"],
                    "calls": row["calls"],
                    "tokens": row["tokens"],
                    "cost": round(row["cost"] or 0, 6),
                }
                for row in daily
            ],
        }

    def bots_hit_rows(
        self,
        *,
        bot_id: str,
        prefix_id: str,
        days: int = 7,
    ) -> list[dict[str, Any]]:
        since = time.time() - days * 86400
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT cache_read, cache_write, uncached_input, input_total,
                       usage_source, exclude_from_hit_rate
                FROM token_usage
                WHERE bot_id = ? AND prefix_id = ? AND timestamp > ?
                ORDER BY timestamp ASC
                """,
                (bot_id, prefix_id, since),
            ).fetchall()
        return [dict(row) for row in rows]

    def bots_hit_rate(
        self,
        *,
        bot_id: str,
        prefix_id: str,
        days: int = 7,
    ) -> float:
        """Token-level hit rate for one (bot, prefix_id) after warmup exclusions."""

        from js.bots.prefix import warmup_excluded_hit_rate

        return warmup_excluded_hit_rate(
            self.bots_hit_rows(bot_id=bot_id, prefix_id=prefix_id, days=days)
        )

    def room_prefix_hit_summary(
        self,
        slices: list[tuple[str, str]],
        *,
        days: int = 7,
    ) -> dict[str, Any]:
        """Min warmup-excluded rate across current (bot, prefix_id) slices."""

        from js.bots.prefix import warmup_excluded_hit_rate_or_none

        per_bot: list[dict[str, Any]] = []
        rates: list[float] = []
        for bot_id, prefix_id in slices:
            rate = warmup_excluded_hit_rate_or_none(
                self.bots_hit_rows(bot_id=bot_id, prefix_id=prefix_id, days=days)
            )
            per_bot.append({"bot_id": bot_id, "prefix_id": prefix_id, "hit_rate": rate})
            if rate is not None:
                rates.append(rate)
        room_rate = min(rates) if rates else None
        return {
            "hit_rate": room_rate,
            "below_target": room_rate is not None and room_rate < 0.96,
            "per_bot": per_bot,
        }


def buckets_for_state(state: Any) -> ExclusiveUsageBuckets:
    usage = getattr(state, "usage_buckets", None)
    if isinstance(usage, dict):
        return buckets_from_usage_dict(
            usage,
            source=coerce_usage_source(str(getattr(state, "usage_source", "") or "")),
        )
    return ExclusiveUsageBuckets(
        uncached_input=max(
            int(getattr(state, "total_tokens", {}).get("input", 0) or 0)
            - int(getattr(state, "cached_tokens", 0) or 0),
            0,
        ),
        cache_read=int(getattr(state, "cached_tokens", 0) or 0),
        output=int(getattr(state, "total_tokens", {}).get("output", 0) or 0),
        usage_source=coerce_usage_source(
            str(getattr(state, "usage_source", "unavailable") or "unavailable")
        ),
    )
