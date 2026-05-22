"""Persistent memory store with compression and retrieval."""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from js.config import MemoryConfig
from js.utils.db import db_connection
from js.utils.log import get_logger

logger = get_logger("js.memory")


@dataclass
class MemoryEntry:
    key: str
    value: str
    category: str
    importance: int  # 1-10
    created_at: float
    access_count: int
    last_accessed: float


class MemoryStore:
    """SQLite-backed memory with LRU eviction, compression, and dreaming consolidation."""

    def __init__(self, state_dir: Path, config: MemoryConfig, embedder: Any | None = None) -> None:
        self.state_dir = state_dir
        self.config = config
        self.db_path = state_dir / "memory.db"
        self._init_db()
        self._init_enhanced(embedder)

    def _init_enhanced(self, embedder: Any | None = None) -> None:
        from js.memory.enhanced_store import EnhancedMemoryStore

        self.enhanced = EnhancedMemoryStore(self.state_dir, self.config, embedder)
        self._ensure_memory_files()

    @property
    def embedder(self) -> Any:
        """Expose the embedder for health-check endpoints."""
        return self.enhanced.embedder

    def replace_embedder(self, embedder: Any) -> None:
        """Swap the underlying embedder at runtime (e.g. after recovery)."""
        if hasattr(self, "enhanced") and self.enhanced:
            self.enhanced.close()
        self._init_enhanced(embedder)

    def close(self) -> None:
        """Close enhanced store and release embedder resources."""
        if hasattr(self, "enhanced") and self.enhanced:
            self.enhanced.close()

    def _ensure_memory_files(self) -> None:
        """Create OpenClaw-style memory files if they don't exist."""
        memory_dir = self.state_dir / "memory"
        memory_dir.mkdir(parents=True, exist_ok=True)

        identity_path = memory_dir / "identity.md"
        if not identity_path.exists():
            identity_path.write_text(
                """# IDENTITY.md - Who Am I?

_Fill this in during your first conversation. Make it yours._

- **Name:** JS Agent
- **Creature:** AI assistant
- **Vibe:** Capable, concise, helpful
- **Emoji:** 🤖

---

This isn't just metadata. It's the start of figuring out who you are.
""",
                encoding="utf-8",
            )

        user_path = memory_dir / "user.md"
        if not user_path.exists():
            user_path.write_text(
                """# USER.md - About Your Human

_Learn about the person you're helping. Update this as you go._

- **Name:**
- **What to call them:**
- **Pronouns:** _(optional)_
- **Timezone:**
- **Notes:**

## Context

_(What do they care about? What projects are they working on? What annoys them? What makes them laugh? Build this over time.)_

---

The more you know, the better you can help. But remember — you're learning about a person, not building a dossier. Respect the difference.
""",
                encoding="utf-8",
            )

        dreams_path = memory_dir / "dreams.md"
        if not dreams_path.exists():
            dreams_path.write_text(
                """# Dream Diary

<!-- dreaming:diary:start -->

_Dreams are processed memories. Each entry represents a consolidation cycle._

<!-- dreaming:diary:end -->
""",
                encoding="utf-8",
            )

    def _init_db(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with db_connection(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS memories (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    category TEXT DEFAULT 'general',
                    importance INTEGER DEFAULT 5,
                    created_at REAL NOT NULL,
                    access_count INTEGER DEFAULT 0,
                    last_accessed REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mem_category ON memories(category)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mem_importance ON memories(importance)
            """)
            conn.commit()

    def store(
        self,
        key: str,
        value: str,
        category: str = "general",
        importance: int = 5,
    ) -> None:
        """Store a memory entry."""
        now = time.time()
        entry = MemoryEntry(
            key=key,
            value=value,
            category=category,
            importance=max(1, min(10, importance)),
            created_at=now,
            access_count=0,
            last_accessed=now,
        )

        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO memories (key, value, category, importance, created_at, access_count, last_accessed)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value,
                    category=excluded.category,
                    importance=excluded.importance,
                    access_count=memories.access_count + 1,
                    last_accessed=excluded.last_accessed
                """,
                (key, value, category, entry.importance, now, 0, now),
            )
            conn.commit()

    def retrieve(self, key: str) -> str | None:
        """Retrieve a memory by key."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM memories WHERE key = ?", (key,)
            ).fetchone()

        if row:
            with db_connection(self.db_path) as conn:
                conn.execute(
                    "UPDATE memories SET access_count = access_count + 1, last_accessed = ? WHERE key = ?",
                    (time.time(), key),
                )
                conn.commit()
            return cast("str", row["value"])

        return None

    def search(self, query: str, category: str | None = None, limit: int = 10) -> list[MemoryEntry]:
        """Search memories by content match."""
        # Escape SQL LIKE wildcards to prevent unexpected full-table scans
        safe_query = query.replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{safe_query}%"
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if category:
                rows = conn.execute(
                    """
                    SELECT * FROM memories
                    WHERE value LIKE ? ESCAPE '\\' AND category = ?
                    ORDER BY importance DESC, last_accessed DESC
                    LIMIT ?
                    """,
                    (pattern, category, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM memories
                    WHERE value LIKE ? ESCAPE '\\'
                    ORDER BY importance DESC, last_accessed DESC
                    LIMIT ?
                    """,
                    (pattern, limit),
                ).fetchall()

        return [
            MemoryEntry(
                key=r["key"],
                value=r["value"],
                category=r["category"],
                importance=r["importance"],
                created_at=r["created_at"],
                access_count=r["access_count"],
                last_accessed=r["last_accessed"],
            )
            for r in rows
        ]

    def get_context_string(self, max_chars: int = 4000, query: str = "", session_id: str = "") -> str:
        """Get rich context from all memory layers for injection into prompts."""
        # Use enhanced multi-layer memory if available
        if hasattr(self, "enhanced"):
            return self.enhanced.get_context_string(
                query=query, session_id=session_id, max_chars=max_chars
            )

        # Fallback to legacy flat memory
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT key, value, category FROM memories
                ORDER BY importance DESC, last_accessed DESC
                LIMIT 50
                """
            ).fetchall()

        parts: list[str] = []
        current_len = 0
        for r in rows:
            line = f"[{r['category']}] {r['key']}: {r['value']}\n"
            if current_len + len(line) > max_chars:
                break
            parts.append(line)
            current_len += len(line)

        return "\n".join(parts) or "No memories stored yet."

    def store_working(self, session_id: str, key: str, value: str, category: str = "general", importance: int = 5) -> None:
        """Store a working memory entry for the current session."""
        self.enhanced.store_working(session_id, key, value, category, importance)

    def store_episode(self, session_id: str, summary: str, topics: list[str], tokens_used: int = 0, turn_count: int = 0, importance: int = 5) -> None:
        """Store an episodic memory (session summary)."""
        self.enhanced.store_episode(session_id, summary, topics, tokens_used, turn_count, importance)

    async def dream(self, llm_summarizer: Any | None = None) -> dict[str, Any]:
        """Run memory consolidation (dreaming cycle)."""
        if hasattr(self, "enhanced"):
            return await self.enhanced.dream(llm_summarizer=llm_summarizer)
        return {"phases": []}

    def get_dream_logs(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get recent dream logs."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_dream_logs(limit)
        return []

    def get_episodes(self, limit: int = 20) -> list[Any]:
        """Get recent episodic memories."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_episodes(limit)
        return []

    def get_sessions(self, limit: int = 30) -> list[dict[str, Any]]:
        """List recent conversation sessions."""
        if hasattr(self, "enhanced"):
            return self.enhanced.list_sessions(limit)
        return []

    def cleanup_empty_sessions(self) -> int:
        """Remove episode records for sessions that have no messages."""
        if hasattr(self, "enhanced"):
            return self.enhanced.cleanup_empty_sessions()
        return 0

    def store_messages(self, session_id: str, messages: list[dict[str, str]]) -> None:
        """Store conversation messages in batch."""
        if hasattr(self, "enhanced"):
            self.enhanced.store_messages(session_id, messages)

    def get_session_messages(self, session_id: str) -> list[dict[str, Any]]:
        """Get all messages for a session."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_session_messages(session_id)
        return []

    def delete_session(self, session_id: str) -> bool:
        """Delete a session and all its data."""
        if hasattr(self, "enhanced"):
            return self.enhanced.delete_session(session_id)
        return False

    def get_working(self, session_id: str, limit: int = 50) -> list[dict[str, Any]]:
        """Get working memories for a session."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_working(session_id, limit)
        return []

    def get_all_working(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent working memories across all sessions."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_all_working(limit)
        return []

    def get_all_semantic(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get all semantic memories ordered by recency."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_all_semantic(limit)
        return []

    def store_semantic(self, key: str, value: str, category: str = "fact", confidence: float = 0.5, source: str = "") -> dict[str, Any]:
        """Store a semantic memory."""
        if hasattr(self, "enhanced"):
            return self.enhanced.store_semantic(key, value, category, confidence, source)
        return {"conflicts": [], "evicted": 0}

    def delete_semantic(self, memory_id: int) -> bool:
        """Delete a semantic memory by id."""
        if hasattr(self, "enhanced"):
            return self.enhanced.delete_semantic(memory_id)
        return False

    def update_semantic(self, memory_id: int, value: str, category: str | None = None) -> bool:
        """Update a semantic memory by id."""
        if hasattr(self, "enhanced"):
            return self.enhanced.update_semantic(memory_id, value, category)
        return False

    def search_semantic(self, query: str, category: str | None = None, limit: int = 10) -> list[Any]:
        """Search semantic memories."""
        if hasattr(self, "enhanced"):
            return self.enhanced.search_semantic(query, category, limit)
        return []

    # ------------------------------------------------------------------
    # Memory Files (IDENTITY.md, USER.md, DREAMS.md)
    # ------------------------------------------------------------------

    _VALID_MEMORY_FILES = {"identity", "user", "dreams"}

    def list_memory_files(self) -> list[str]:
        """List available memory files (basename without extension)."""
        memory_dir = self.state_dir / "memory"
        if not memory_dir.exists():
            return []
        files = []
        for path in sorted(memory_dir.glob("*.md")):
            files.append(path.stem)
        return files

    def _memory_file_path(self, name: str) -> Path:
        """Resolve memory file path, guarding against path traversal."""
        # Allow any .md file in the memory directory, not just the hardcoded set
        safe_name = Path(name).name
        if not safe_name or safe_name.startswith("."):
            raise ValueError(f"Invalid memory file name: {name}")
        return self.state_dir / "memory" / f"{safe_name}.md"

    def read_memory_file(self, name: str) -> str:
        """Read a memory file's content. Returns empty string if not found."""
        path = self._memory_file_path(name)
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8")

    def write_memory_file(self, name: str, content: str) -> None:
        """Write content to a memory file."""
        path = self._memory_file_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
