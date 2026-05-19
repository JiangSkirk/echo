"""Enhanced multi-layer memory system with dreaming, episodes, and semantic search."""

from __future__ import annotations

import json
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
        self._working_cache: dict[str, dict[str, Any]] = {}
        self._last_dream: float = 0.0

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
        now = time.time()
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
                (session_id, summary, json.dumps(topics), tokens_used, turn_count, time.time(), importance),
            )
            conn.commit()

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
        now = time.time()
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
    ) -> None:
        now = time.time()
        embedding_json = self.embedder.to_json(self.embedder.embed(f"{key} {value}"))
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO semantic_memories (key, value, category, confidence, source, created_at, last_accessed, access_count, embedding)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value,
                    category=excluded.category,
                    confidence=excluded.confidence,
                    source=excluded.source,
                    last_accessed=?,
                    embedding=excluded.embedding
                """,
                (key, value, category, confidence, source, now, now, embedding_json, now),
            )
            conn.commit()

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
        query_vec = self.embedder.embed(query)

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

        # Phase 3: Score candidates by embedding similarity
        scored: list[tuple[float, sqlite3.Row]] = []
        for r in rows:
            emb_raw = r["embedding"]
            if emb_raw:
                try:
                    vec = self.embedder.from_json(emb_raw)
                    score = cosine_similarity(query_vec, vec)
                except Exception:
                    score = 0.0
            else:
                q = query.lower()
                text = f"{r['key']} {r['value']}".lower()
                score = 1.0 if q in text else 0.0
            scored.append((score, r))

        scored.sort(key=lambda x: x[0], reverse=True)

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

        # 2. Recent episodes (last 3)
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

    def _rem_sleep(self) -> str:
        """Build simple keyword-based associations between memories."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            sem = conn.execute(
                "SELECT id, key, value FROM semantic_memories ORDER BY created_at DESC LIMIT 100"
            ).fetchall()

        links: list[tuple[int, int, str, str, float, str, float]] = []
        now = time.time()
        # Simple overlap: if two entries share significant words, link them
        for i, a in enumerate(sem):
            words_a = set((a["key"] + " " + a["value"]).lower().split())
            for b in sem[i + 1 :]:
                words_b = set((b["key"] + " " + b["value"]).lower().split())
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
                    self.store_semantic(
                        key=f"dream_insight_{int(time.time())}",
                        value=insight,
                        category="insight",
                        confidence=0.85,
                        source="deep_sleep_llm",
                    )
            except Exception:
                logger.debug("LLM summarizer failed during deep sleep", exc_info=True)

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
