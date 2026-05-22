"""Enhanced multi-layer memory system with dreaming, episodes, and semantic search."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.config import MemoryConfig
from js.memory.embeddings import Embedder, KeywordEmbedder, cosine_similarity
from js.utils.db import db_connection
from js.utils.log import get_logger

logger = get_logger("js.memory.enhanced")


@dataclass
class Episode:
    id: int
    session_id: str
    summary: str
    topics: list[str]
    tokens_used: int
    turn_count: int
    created_at: float
    importance: int


@dataclass
class SemanticMemory:
    id: int
    key: str
    value: str
    category: str
    confidence: float
    source: str
    created_at: float
    last_accessed: float
    access_count: int


class EnhancedMemoryStore:
    """Multi-layer memory: working -> episodic -> semantic, with dreaming consolidation."""

    def __init__(self, state_dir: Path, config: MemoryConfig, embedder: Embedder | None = None) -> None:
        self.state_dir = state_dir
        self.config = config
        self.db_path = state_dir / "memory_enhanced.db"
        self.embedder = embedder or KeywordEmbedder()
        self._init_db()
        from cachetools import TTLCache
        self._working_cache: TTLCache[str, dict[str, Any]] = TTLCache(maxsize=1000, ttl=3600)
        self._last_dream: float = 0.0

    def close(self) -> None:
        if hasattr(self, "embedder") and self.embedder and hasattr(self.embedder, "close"):
            self.embedder.close()

    def _init_db(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with db_connection(self.db_path) as conn:
            # Working memory: short-term, per-session
            conn.execute("""
                CREATE TABLE IF NOT EXISTS working_memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    category TEXT DEFAULT 'general',
                    importance INTEGER DEFAULT 5,
                    created_at REAL NOT NULL,
                    access_count INTEGER DEFAULT 0,
                    last_accessed REAL NOT NULL,
                    UNIQUE(session_id, key)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_working_session ON working_memories(session_id)
            """)

            # Episodic memory: session summaries
            conn.execute("""
                CREATE TABLE IF NOT EXISTS episodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE,
                    summary TEXT,
                    topics TEXT,
                    tokens_used INTEGER DEFAULT 0,
                    turn_count INTEGER DEFAULT 0,
                    created_at REAL NOT NULL,
                    importance INTEGER DEFAULT 5
                )
            """)

            # Semantic memory: extracted knowledge / preferences
            conn.execute("""
                CREATE TABLE IF NOT EXISTS semantic_memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    category TEXT DEFAULT 'fact',
                    confidence REAL DEFAULT 0.5,
                    source TEXT,
                    created_at REAL NOT NULL,
                    last_accessed REAL NOT NULL,
                    access_count INTEGER DEFAULT 0,
                    embedding TEXT,
                    UNIQUE(key)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_semantic_category ON semantic_memories(category)
            """)

            # Memory links: associations built during REM
            conn.execute("""
                CREATE TABLE IF NOT EXISTS memory_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_id INTEGER,
                    to_id INTEGER,
                    from_table TEXT,
                    to_table TEXT,
                    strength REAL DEFAULT 0.5,
                    link_type TEXT DEFAULT 'association',
                    created_at REAL NOT NULL
                )
            """)

            # Dream logs
            conn.execute("""
                CREATE TABLE IF NOT EXISTS dream_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    phase TEXT,
                    summary TEXT,
                    changes TEXT,
                    created_at REAL NOT NULL
                )
            """)

            # Session messages: full conversation history per session
            conn.execute("""
                CREATE TABLE IF NOT EXISTS session_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT,
                    created_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_session_messages_session
                ON session_messages(session_id)
            """)

            # Fix: add unique indexes for tables created before constraints were added
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_working_session_key
                ON working_memories(session_id, key)
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_semantic_key
                ON semantic_memories(key)
            """)

            # Migration: add quality-control columns for semantic memories
            migrations = [
                ("feedback_score", "REAL DEFAULT 0.0"),
                ("conflict_status", "TEXT DEFAULT ''"),
                ("importance", "INTEGER DEFAULT 5"),
            ]
            for col, dtype in migrations:
                try:
                    conn.execute(f"ALTER TABLE semantic_memories ADD COLUMN {col} {dtype}")
                except sqlite3.OperationalError:
                    pass  # Column already exists

            conn.commit()

    # ------------------------------------------------------------------
    # Working Memory (short-term, per-session)
    # ------------------------------------------------------------------

    def store_working(
        self,
        session_id: str,
        key: str,
        value: str,
        category: str = "general",
        importance: int = 5,
    ) -> None:
        import time as _time
        _start = _time.perf_counter()
        now = _time.time()
        cache_key = f"{session_id}:{key}"
        self._working_cache[cache_key] = {
            "session_id": session_id,
            "key": key,
            "value": value,
            "category": category,
            "importance": importance,
            "created_at": now,
            "access_count": 0,
            "last_accessed": now,
        }
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO working_memories (session_id, key, value, category, importance, created_at, access_count, last_accessed)
                VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                ON CONFLICT(session_id, key) DO UPDATE SET
                    value=excluded.value,
                    category=excluded.category,
                    importance=excluded.importance,
                    last_accessed=excluded.last_accessed
                """,
                (session_id, key, value, category, importance, now, now),
            )
            conn.commit()
        try:
            from js.utils.metrics import get_metrics
            get_metrics().memory_store_latency_seconds.labels(operation="store_working").observe(
                _time.perf_counter() - _start
            )
        except Exception:
            logger.warning('Operation failed', exc_info=True)

    def get_working(self, session_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM working_memories
                WHERE session_id = ?
                ORDER BY importance DESC, last_accessed DESC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_all_working(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent working memories across all sessions."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM working_memories
                ORDER BY last_accessed DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_all_semantic(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get all semantic memories ordered by recency."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM semantic_memories
                ORDER BY last_accessed DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Episodic Memory (session summaries)
    # ------------------------------------------------------------------

    def store_episode(
        self,
        session_id: str,
        summary: str,
        topics: list[str],
        tokens_used: int = 0,
        turn_count: int = 0,
        importance: int = 5,
    ) -> None:
        import time as _time
        _start = _time.perf_counter()
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO episodes (session_id, summary, topics, tokens_used, turn_count, created_at, importance)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    summary=excluded.summary,
                    topics=excluded.topics,
                    tokens_used=excluded.tokens_used,
                    turn_count=excluded.turn_count,
                    importance=excluded.importance
                """,
                (session_id, summary, json.dumps(topics), tokens_used, turn_count, _time.time(), importance),
            )
            conn.commit()
        try:
            from js.utils.metrics import get_metrics
            get_metrics().memory_store_latency_seconds.labels(operation="store_episode").observe(
                _time.perf_counter() - _start
            )
        except Exception:
            logger.warning('Operation failed', exc_info=True)

    def get_episodes(self, limit: int = 20) -> list[Episode]:
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM episodes
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            Episode(
                id=r["id"],
                session_id=r["session_id"],
                summary=r["summary"],
                topics=json.loads(r["topics"]) if r["topics"] else [],
                tokens_used=r["tokens_used"],
                turn_count=r["turn_count"],
                created_at=r["created_at"],
                importance=r["importance"],
            )
            for r in rows
        ]

    def list_sessions(self, limit: int = 30) -> list[dict[str, Any]]:
        """List recent conversation sessions that have at least one message."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT e.session_id, e.summary, e.created_at, e.turn_count,
                       (SELECT COUNT(*) FROM session_messages m WHERE m.session_id = e.session_id) as message_count
                FROM episodes e
                WHERE EXISTS (SELECT 1 FROM session_messages m WHERE m.session_id = e.session_id)
                ORDER BY e.created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "session_id": r["session_id"],
                "summary": r["summary"] or "",
                "created_at": r["created_at"],
                "turn_count": r["turn_count"] or 0,
                "message_count": r["message_count"] or 0,
            }
            for r in rows
        ]

    def cleanup_empty_sessions(self) -> int:
        """Remove episode records for sessions that have no messages."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            # Find session_ids in episodes that have no messages
            rows = conn.execute(
                """
                SELECT e.session_id FROM episodes e
                LEFT JOIN session_messages m ON m.session_id = e.session_id
                WHERE m.id IS NULL
                """
            ).fetchall()
            deleted = 0
            for row in rows:
                sid = row["session_id"]
                conn.execute("DELETE FROM episodes WHERE session_id = ?", (sid,))
                conn.execute("DELETE FROM working_memories WHERE session_id = ?", (sid,))
                conn.execute("DELETE FROM semantic_memories WHERE source = ?", (sid,))
                deleted += 1
            conn.commit()
        logger.info(f"Cleaned up {deleted} empty sessions")
        return deleted

    # ------------------------------------------------------------------
    # Session Messages (conversation history)
    # ------------------------------------------------------------------

    def store_messages(self, session_id: str, messages: list[dict[str, str]]) -> None:
        """Batch store messages for a session."""
        if not messages:
            return
        import time as _time
        _start = _time.perf_counter()
        now = _time.time()
        with db_connection(self.db_path) as conn:
            conn.executemany(
                """
                INSERT INTO session_messages (session_id, role, content, created_at)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (session_id, m["role"], m["content"], now)
                    for m in messages
                    if m.get("role") in ("user", "assistant") and m.get("content")
                ],
            )
            conn.commit()
        try:
            from js.utils.metrics import get_metrics
            get_metrics().memory_store_latency_seconds.labels(operation="store_messages").observe(
                _time.perf_counter() - _start
            )
        except Exception:
            logger.warning('Operation failed', exc_info=True)

    def get_session_messages(self, session_id: str) -> list[dict[str, Any]]:
        """Get all messages for a session, ordered by time."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT role, content, created_at
                FROM session_messages
                WHERE session_id = ?
                ORDER BY created_at ASC
                """,
                (session_id,),
            ).fetchall()
        return [
            {"role": r["role"], "content": r["content"], "created_at": r["created_at"]}
            for r in rows
        ]

    def delete_session(self, session_id: str) -> bool:
        """Delete all data for a session (messages, working memory, episode, semantic memory)."""
        with db_connection(self.db_path) as conn:
            conn.execute(
                "DELETE FROM session_messages WHERE session_id = ?", (session_id,)
            )
            conn.execute(
                "DELETE FROM working_memories WHERE session_id = ?", (session_id,)
            )
            conn.execute(
                "DELETE FROM episodes WHERE session_id = ?", (session_id,)
            )
            conn.execute(
                "DELETE FROM semantic_memories WHERE source = ?", (session_id,)
            )
            conn.commit()
        return True

    # ------------------------------------------------------------------
    # Semantic Memory (extracted knowledge)
    # ------------------------------------------------------------------

    def store_semantic(
        self,
        key: str,
        value: str,
        category: str = "fact",
        confidence: float = 0.5,
        source: str = "",
    ) -> dict[str, Any]:
        """Store a semantic memory, with conflict detection and eviction."""
        import time
        _start = time.perf_counter()
        now = time.time()
        try:
            embedding = self.embedder.embed(f"{key} {value}")
            embedding_json = self.embedder.to_json(embedding)
        except Exception:
            logger.warning("Primary embedding failed for semantic store, trying fallback", exc_info=True)
            # Always generate a keyword-based embedding so the memory is
            # never stored with an empty vector.
            try:
                fallback = KeywordEmbedder()
                embedding = fallback.embed(f"{key} {value}")
                embedding_json = fallback.to_json(embedding)
            except Exception:
                logger.error("Fallback embedding also failed, storing empty vector", exc_info=True)
                embedding_json = ""
        try:
            from js.utils.metrics import get_metrics
            get_metrics().memory_store_latency_seconds.labels(operation="store_semantic").observe(
                time.perf_counter() - _start
            )
        except Exception:
            logger.warning('Operation failed', exc_info=True)

        # Detect conflicts with existing similar memories
        conflicts = self._detect_conflict(key, value, category)
        conflict_status = "conflicting" if conflicts else ""

        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO semantic_memories
                    (key, value, category, confidence, source, created_at, last_accessed, access_count, embedding, conflict_status, importance)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 5)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value,
                    category=excluded.category,
                    confidence=excluded.confidence,
                    source=excluded.source,
                    last_accessed=?,
                    embedding=excluded.embedding,
                    conflict_status=excluded.conflict_status,
                    importance=excluded.importance
                """,
                (key, value, category, confidence, source, now, now, embedding_json, conflict_status, now),
            )
            conn.commit()

        # Run eviction after insert
        evicted = self._evict_semantic_if_needed()

        return {
            "conflicts": conflicts,
            "evicted": evicted,
        }

    def feedback(self, memory_id: int, helpful: bool) -> bool:
        """Record user feedback on a semantic memory's usefulness.

        Positive feedback increases the memory's weight, negative feedback
        decreases it.  Affects eviction priority.
        """
        delta = 1.0 if helpful else -1.0
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                UPDATE semantic_memories
                SET feedback_score = COALESCE(feedback_score, 0) + ?,
                    access_count = access_count + 1,
                    last_accessed = ?
                WHERE id = ?
                """,
                (delta, time.time(), memory_id),
            )
            updated = conn.total_changes > 0
            conn.commit()
        return updated

    def _detect_conflict(self, key: str, value: str, category: str, similarity_threshold: float = 0.7) -> list[int]:
        """Detect potentially conflicting memories.

        Simple heuristic: same category + similar key (substring overlap)
        but different value → potential conflict.
        """
        conflicts: list[int] = []
        key_lower = key.lower()
        value_lower = value.lower()
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, key, value FROM semantic_memories WHERE category = ?",
                (category,),
            ).fetchall()
        for r in rows:
            other_key = r["key"].lower()
            other_value = r["value"].lower()
            # Key similarity: shared words
            key_words = set(key_lower.split())
            other_words = set(other_key.split())
            if not key_words or not other_words:
                continue
            overlap = len(key_words & other_words) / max(len(key_words), len(other_words))
            if overlap >= similarity_threshold and other_value != value_lower:
                conflicts.append(r["id"])
        return conflicts

    def _evict_semantic_if_needed(
        self,
        strategy: str = "lru",
        max_memories: int = 1000,
    ) -> int:
        """Evict old or low-value semantic memories if count exceeds limit.

        Strategies:
        - lru: evict least recently accessed (but protect importance >= 8)
        - importance_weighted: score = importance * 2 + access_count + feedback_score*3;
          evict lowest score first
        """
        with db_connection(self.db_path) as conn:
            count_row = conn.execute("SELECT COUNT(*) FROM semantic_memories").fetchone()
            total = count_row[0] if count_row else 0

        if total <= max_memories:
            return 0

        to_evict = total - max_memories
        evicted = 0

        with db_connection(self.db_path) as conn:
            if strategy == "lru":
                # Protect high-importance memories
                rows = conn.execute(
                    """
                    SELECT id FROM semantic_memories
                    WHERE COALESCE(importance, 5) < 8
                    ORDER BY last_accessed ASC
                    LIMIT ?
                    """,
                    (to_evict,),
                ).fetchall()
            elif strategy == "importance_weighted":
                rows = conn.execute(
                    """
                    SELECT id FROM semantic_memories
                    ORDER BY (COALESCE(importance, 5) * 2 + access_count + COALESCE(feedback_score, 0) * 3) ASC
                    LIMIT ?
                    """,
                    (to_evict,),
                ).fetchall()
            else:
                rows = []

            for row in rows:
                conn.execute("DELETE FROM semantic_memories WHERE id = ?", (row[0],))
                evicted += 1
            conn.commit()

        if evicted:
            logger.info(f"Evicted {evicted} semantic memories (strategy={strategy}, limit={max_memories})")
        return evicted

    def get_conflicting_memories(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return all memories marked as conflicting."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM semantic_memories WHERE conflict_status = 'conflicting' LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_semantic(self, memory_id: int) -> bool:
        with db_connection(self.db_path) as conn:
            cur = conn.execute("DELETE FROM semantic_memories WHERE id = ?", (memory_id,))
            conn.commit()
            return cur.rowcount > 0

    def update_semantic(self, memory_id: int, value: str, category: str | None = None) -> bool:
        with db_connection(self.db_path) as conn:
            if category is not None:
                cur = conn.execute(
                    "UPDATE semantic_memories SET value = ?, category = ? WHERE id = ?",
                    (value, category, memory_id),
                )
            else:
                cur = conn.execute(
                    "UPDATE semantic_memories SET value = ? WHERE id = ?",
                    (value, memory_id),
                )
            conn.commit()
            return cur.rowcount > 0

    def retrieve_semantic(self, key: str) -> SemanticMemory | None:
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM semantic_memories WHERE key = ?", (key,)
            ).fetchone()
        if not row:
            return None
        return SemanticMemory(
            id=row["id"],
            key=row["key"],
            value=row["value"],
            category=row["category"],
            confidence=row["confidence"],
            source=row["source"],
            created_at=row["created_at"],
            last_accessed=row["last_accessed"],
            access_count=row["access_count"],
        )

    def search_semantic(self, query: str, category: str | None = None, limit: int = 10) -> list[SemanticMemory]:
        import time
        _start = time.perf_counter()
        fallback_reason = None
        try:
            query_vec = self.embedder.embed(query)
        except Exception:
            logger.warning("Query embedding failed, falling back to text search", exc_info=True)
            query_vec = None
            fallback_reason = "embedding_failed"

        # Phase 1: Fast pre-filter with LIKE to avoid loading all rows
        safe_query = query.replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{safe_query}%"
        candidate_limit = max(limit * 5, 50)

        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if category:
                rows = conn.execute(
                    """
                    SELECT * FROM semantic_memories
                    WHERE (key LIKE ? ESCAPE '\\' OR value LIKE ? ESCAPE '\\') AND category = ?
                    LIMIT ?
                    """,
                    (pattern, pattern, category, candidate_limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM semantic_memories
                    WHERE key LIKE ? ESCAPE '\\' OR value LIKE ? ESCAPE '\\'
                    LIMIT ?
                    """,
                    (pattern, pattern, candidate_limit),
                ).fetchall()

        # Phase 2: If no LIKE matches, scan recent entries by embedding
        if not rows:
            with db_connection(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM semantic_memories ORDER BY last_accessed DESC LIMIT ?",
                    (candidate_limit,),
                ).fetchall()

        # Phase 3: Score candidates by embedding similarity (or text match if no vec)
        scored: list[tuple[float, sqlite3.Row]] = []
        for r in rows:
            emb_raw = r["embedding"]
            score: float = 0.0
            if query_vec is not None and emb_raw:
                try:
                    vec = self.embedder.from_json(emb_raw)
                    score = cosine_similarity(query_vec, vec)
                except ValueError as dim_err:
                    # Dimension mismatch (e.g. old memories from a different
                    # embedder).  Fall back to keyword-based re-embedding of
                    # both query and stored text for a fair comparison.
                    if "dimension mismatch" in str(dim_err).lower():
                        try:
                            fallback = KeywordEmbedder()
                            qv = fallback.embed(query)
                            sv = fallback.embed(f"{r['key']} {r['value']}")
                            score = cosine_similarity(qv, sv)
                        except Exception:
                            score = 0.0
                    else:
                        score = 0.0
                except Exception:
                    score = 0.0
            else:
                # No query vector or empty stored embedding → text match
                q = query.lower()
                text = f"{r['key']} {r['value']}".lower()
                # Partial match scoring: overlap ratio
                q_words = set(q.split())
                t_words = set(text.split())
                if q_words and t_words:
                    overlap = len(q_words & t_words)
                    score = overlap / max(len(q_words), len(t_words))
                score = max(score, 1.0 if q in text else 0.0)
            scored.append((score, r))

        scored.sort(key=lambda x: x[0], reverse=True)

        # Record metrics on exit
        try:
            import time

            from js.utils.metrics import get_metrics
            get_metrics().memory_retrieve_latency_seconds.labels(operation="search_semantic").observe(
                time.perf_counter() - _start
            )
            if fallback_reason:
                get_metrics().memory_search_fallback_total.labels(reason=fallback_reason).inc()
            elif query_vec is None:
                get_metrics().memory_search_fallback_total.labels(reason="no_embedding").inc()
        except Exception:
            logger.warning('Operation failed', exc_info=True)

        return [
            SemanticMemory(
                id=r["id"],
                key=r["key"],
                value=r["value"],
                category=r["category"],
                confidence=r["confidence"],
                source=r["source"],
                created_at=r["created_at"],
                last_accessed=r["last_accessed"],
                access_count=r["access_count"],
            )
            for _score, r in scored[:limit]
        ]

    # ------------------------------------------------------------------
    # Context assembly for prompt injection
    # ------------------------------------------------------------------

    _VALID_MEMORY_FILES = {"identity", "user", "dreams"}

    def _read_memory_file(self, name: str) -> str:
        """Read a memory markdown file from state_dir/memory/."""
        if name not in self._VALID_MEMORY_FILES:
            raise ValueError(f"Invalid memory file name: {name}")
        path = self.state_dir / "memory" / f"{name}.md"
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8")

    def _is_mostly_template(self, content: str) -> bool:
        """Check if content is still mostly the default template.

        Uses a high threshold so that partial edits (e.g. only filling in Name)
        are still recognized as user-edited and injected into prompts.
        """
        template_markers = [
            "Fill this in during your first conversation",
            "Learn about the person you're helping",
            "Dreams are processed memories",
            "This isn't just metadata",
            "The more you know, the better you can help",
            "Build this over time",
            "Respect the difference",
            "What do they care about?",
            "What projects are they working on?",
            "What annoys them?",
            "What makes them laugh?",
        ]
        matches = sum(1 for m in template_markers if m in content)
        # If 8+ markers are still present, it's probably still mostly template.
        # This allows users to edit a few fields without losing prompt injection.
        return matches >= 8

    def get_context_string(
        self,
        query: str = "",
        session_id: str = "",
        max_chars: int = 4000,
    ) -> str:
        """Build rich context from all memory layers, optionally filtered by query relevance."""
        parts: list[str] = []
        used = 0

        # 0. Memory Files (IDENTITY.md, USER.md) — highest priority
        identity = self._read_memory_file("identity")
        if identity and not self._is_mostly_template(identity):
            block = "## AI Identity\n" + identity[:500] + "\n\n"
            if used + len(block) <= max_chars:
                parts.append(block)
                used += len(block)

        user_profile = self._read_memory_file("user")
        if user_profile and not self._is_mostly_template(user_profile):
            block = "## About User\n" + user_profile[:500] + "\n\n"
            if used + len(block) <= max_chars:
                parts.append(block)
                used += len(block)

        # 1. User profile (semantic, category = preference)
        prefs = self.search_semantic("", category="preference", limit=5)
        if prefs:
            block = "## 用户偏好\n" + "\n".join(f"- {p.key}: {p.value}" for p in prefs) + "\n\n"
            if used + len(block) <= max_chars:
                parts.append(block)
                used += len(block)

        # 2. Recent episodes (last 3) — disabled by default to avoid
        # polluting new conversations with stale session summaries.
        # Only inject if explicitly enabled via env var.
        if os.getenv("JS_AGENT_MEMORY_EPISODES", "").lower() in ("1", "true", "yes"):
            episodes = self.get_episodes(limit=3)
            if episodes:
                block = "## 近期会话\n" + "\n".join(
                    f"- [{time.strftime('%m-%d', time.localtime(e.created_at))}] {e.summary[:120]}"
                    for e in episodes
                ) + "\n\n"
                if used + len(block) <= max_chars:
                    parts.append(block)
                    used += len(block)

        # 3. Working memory for current session
        if session_id:
            working = self.get_working(session_id, limit=10)
            if working:
                block = "## 当前上下文\n" + "\n".join(
                    f"- [{m['category']}] {m['key']}: {m['value'][:100]}"
                    for m in working
                ) + "\n\n"
                if used + len(block) <= max_chars:
                    parts.append(block)
                    used += len(block)

        # 4. Query-relevant semantic memories
        if query:
            relevant = self.search_semantic(query, limit=5)
            if relevant:
                block = "## 相关知识\n" + "\n".join(
                    f"- [{r.category}] {r.key}: {r.value[:100]}"
                    for r in relevant
                ) + "\n\n"
                if used + len(block) <= max_chars:
                    parts.append(block)
                    used += len(block)

        # 5. Important facts
        facts = self.search_semantic("", category="fact", limit=5)
        if facts:
            block = "## 重要事实\n" + "\n".join(
                f"- {f.key}: {f.value[:100]}" for f in facts
            ) + "\n\n"
            if used + len(block) <= max_chars:
                parts.append(block)
                used += len(block)

        # 6. External fetched data
        external = self.search_semantic("", category="external", limit=5)
        if external:
            block = "## 外部数据\n" + "\n".join(
                f"- [{e.source}] {e.key}: {e.value[:100]}" for e in external
            ) + "\n\n"
            if used + len(block) <= max_chars:
                parts.append(block)
                used += len(block)

        return "\n".join(parts) or "暂无记忆。"

    # ------------------------------------------------------------------
    # Dreaming: consolidation pipeline
    # ------------------------------------------------------------------

    async def dream(self, llm_summarizer: Any | None = None) -> dict[str, Any]:
        """Run full dreaming cycle: light -> rem -> deep."""
        logger.info("Starting dreaming cycle")
        report: dict[str, Any] = {"phases": []}

        # Phase 1: Light Sleep - deduplicate working memories
        light = self._light_sleep()
        report["phases"].append({"phase": "light", "summary": light})
        self._log_dream("light", light)

        # Phase 2: REM Sleep - build associations
        rem = self._rem_sleep()
        report["phases"].append({"phase": "rem", "summary": rem})
        self._log_dream("rem", rem)

        # Phase 3: Deep Sleep - promote to semantic / episode
        deep = await self._deep_sleep(llm_summarizer)
        report["phases"].append({"phase": "deep", "summary": deep})
        self._log_dream("deep", deep)

        # Write dream report to DREAMS.md diary
        self._append_dream_diary(report)

        self._last_dream = time.time()
        logger.info("Dreaming cycle complete")
        return report

    def _append_dream_diary(self, report: dict[str, Any]) -> None:
        """Append the dream cycle report to DREAMS.md."""
        diary_path = self.state_dir / "memory" / "dreams.md"
        diary_path.parent.mkdir(parents=True, exist_ok=True)

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        lines = [f"\n## Dream Cycle — {timestamp}\n"]
        for phase in report.get("phases", []):
            pname = phase.get("phase", "unknown").capitalize()
            summary = phase.get("summary", "")
            lines.append(f"### {pname} Sleep")
            lines.append(summary)
            lines.append("")

        entry = "\n".join(lines) + "\n"
        with diary_path.open("a", encoding="utf-8") as f:
            f.write(entry)

    def _light_sleep(self) -> str:
        """Deduplicate and compress working memories."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM working_memories ORDER BY created_at DESC"
            ).fetchall()

        if not rows:
            return "No working memories to consolidate."

        # Simple dedup: remove entries with identical key+value, keep newest
        seen: set[tuple[str, str]] = set()
        duplicates: list[int] = []
        for r in rows:
            k = (r["key"], r["value"])
            if k in seen:
                duplicates.append(r["id"])
            else:
                seen.add(k)

        if duplicates:
            with db_connection(self.db_path) as conn:
                placeholders = ",".join("?" * len(duplicates))
                conn.execute(
                    f"DELETE FROM working_memories WHERE id IN ({placeholders})",
                    duplicates,
                )
                conn.commit()

        return f"Removed {len(duplicates)} duplicate working memories."

    # Common English stop-words to ignore when computing keyword overlap.
    _STOP_WORDS: frozenset[str] = frozenset({
        "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "will", "would", "could",
        "should", "may", "might", "must", "shall", "can", "need", "dare",
        "ought", "used", "to", "of", "in", "for", "on", "with", "at", "by",
        "from", "as", "into", "through", "during", "before", "after", "above",
        "below", "between", "under", "again", "further", "then", "once",
        "here", "there", "when", "where", "why", "how", "all", "any", "both",
        "each", "few", "more", "most", "other", "some", "such", "no", "nor",
        "not", "only", "own", "same", "so", "than", "too", "very", "just",
        "and", "but", "if", "or", "because", "until", "while", "about",
        "against", "among", "around", "behind", "beyond", "despite", "down",
        "except", "inside", "like", "near", "off", "out", "outside", "over",
        "past", "since", "till", "up", "upon", "within", "without",
    })

    def _rem_sleep(self) -> str:
        """Build simple keyword-based associations between memories."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            sem = conn.execute(
                "SELECT id, key, value FROM semantic_memories ORDER BY created_at DESC LIMIT 100"
            ).fetchall()

        links: list[tuple[int, int, str, str, float, str, float]] = []
        now = time.time()
        # Simple overlap: if two entries share significant (non stop-word) words, link them
        for i, a in enumerate(sem):
            words_a = {
                w.strip(".,!?;:\"'()")
                for w in (a["key"] + " " + a["value"]).lower().split()
                if w.strip(".,!?;:\"'()") not in self._STOP_WORDS and len(w) > 2
            }
            if not words_a:
                continue
            for b in sem[i + 1 :]:
                words_b = {
                    w.strip(".,!?;:\"'()")
                    for w in (b["key"] + " " + b["value"]).lower().split()
                    if w.strip(".,!?;:\"'()") not in self._STOP_WORDS and len(w) > 2
                }
                if not words_b:
                    continue
                overlap = len(words_a & words_b)
                if overlap >= 3:
                    links.append(
                        (a["id"], b["id"], "semantic_memories", "semantic_memories",
                         min(1.0, overlap / 10), "association", now)
                    )

        if links:
            with db_connection(self.db_path) as conn:
                conn.executemany(
                    """
                    INSERT INTO memory_links (from_id, to_id, from_table, to_table, strength, link_type, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT DO NOTHING
                    """,
                    links,
                )
                conn.commit()

        return f"Created {len(links)} associative links."

    async def _deep_sleep(self, llm_summarizer: Any | None = None) -> str:
        """Promote important working memories to semantic / episodic, with LLM insight generation."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM working_memories WHERE importance >= 7 ORDER BY created_at DESC LIMIT 20"
            ).fetchall()

        promoted = 0
        for r in rows:
            # Promote to semantic memory
            self.store_semantic(
                key=r["key"],
                value=r["value"],
                category=r["category"],
                confidence=0.7,
                source=r["session_id"],
            )
            promoted += 1

        insight = ""
        if llm_summarizer and rows:
            # Build a summary of promoted memories for LLM analysis
            memory_text = "\n".join(
                f"[{r['category']}] {r['key']}: {r['value'][:200]}"
                for r in rows
            )
            try:
                insight = await llm_summarizer(memory_text)
                if insight:
                    # Use nanosecond timestamp to avoid collisions when dream()
                    # is called multiple times within the same second.
                    self.store_semantic(
                        key=f"dream_insight_{time.time_ns()}",
                        value=insight,
                        category="insight",
                        confidence=0.85,
                        source="deep_sleep_llm",
                    )
            except Exception:
                logger.warning("LLM summarizer failed during deep sleep", exc_info=True)

        base = f"Promoted {promoted} important memories to long-term storage."
        if insight:
            base += f"\nInsight: {insight[:300]}"
        return base

    def _log_dream(self, phase: str, summary: str) -> None:
        with db_connection(self.db_path) as conn:
            conn.execute(
                "INSERT INTO dream_logs (phase, summary, changes, created_at) VALUES (?, ?, ?, ?)",
                (phase, summary, "", time.time()),
            )
            conn.commit()

    def get_dream_logs(self, limit: int = 20) -> list[dict[str, Any]]:
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM dream_logs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    async def maybe_dream(self, min_interval: float = 300.0) -> dict[str, Any] | None:
        """Trigger dreaming if enough time has passed."""
        if time.time() - self._last_dream >= min_interval:
            return await self.dream()
        return None
