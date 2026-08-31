"""Persistent memory store with compression and retrieval."""

from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from js.config import MemoryConfig
from js.utils.db import db_connection
from js.utils.log import get_logger

logger = get_logger("js.memory")


def _reject_ambient_memory_under_enforce() -> None:
    from js.orin.stage_c import ambient_memory_blocked

    if ambient_memory_blocked():
        raise RuntimeError("ambient MemoryStore is unavailable under orin.enforce")


def _orin_write_taint(key: str, value: str) -> int:
    """Orin WP2 site 5: provenance record for memory writes.

    The legacy memories table has no taint column (that migration is P4,
    D §6.10); Stage A records the write's taint in the structured log so
    every memory write carries its source bits in the durable trail.
    """

    from js.orin.taint import (
        MEMORY_READ,
        current_tool_taint_snapshot,
        secret_hint,
    )

    taint = MEMORY_READ
    snapshot = current_tool_taint_snapshot()
    if snapshot is not None:
        taint |= snapshot.context_taint
    if secret_hint(value) or secret_hint(key):
        from js.orin.taint import SECRET

        taint |= SECRET
    logger.debug(
        "memory_write_taint",
        extra={"memory_key": key[:80], "orin_taint": taint},
    )
    return taint


# Word tokens for building safe FTS5 MATCH queries. ``\w+`` is Unicode-aware
# (covers CJK), and tokens carry no FTS operator characters so they are safe to
# embed in a MATCH expression without further quoting.
_FTS_WORD_RE = re.compile(r"\w+", re.UNICODE)


def _build_fts_match(query: str) -> str | None:
    """Turn a free-text query into a safe FTS5 prefix-match expression.

    Returns ``None`` when the query has no usable word tokens (caller should
    fall back to LIKE).  Each token is prefix-matched (``token*``) and combined
    with implicit AND.
    """
    tokens = _FTS_WORD_RE.findall(query)
    if not tokens:
        return None
    return " ".join(f"{t}*" for t in tokens)


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
                (
                    "# USER.md - About Your Human\n\n"
                    "_Learn about the person you're helping. Update this as you go._\n\n"
                    "- **Name:**\n"
                    "- **What to call them:**\n"
                    "- **Pronouns:** _(optional)_\n"
                    "- **Timezone:**\n"
                    "- **Notes:**\n\n"
                    "## Context\n\n"
                    "_(What do they care about? What projects are they working on? "
                    "What annoys them? What makes them laugh? Build this over time.)_\n\n"
                    "---\n\n"
                    "The more you know, the better you can help. But remember — "
                    "you're learning about a person, not building a dossier. "
                    "Respect the difference.\n"
                ),
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
            # Full-text index over memory values for fast content search.
            # Standalone FTS5 table kept in sync manually by store() — memories
            # has a TEXT primary key and a single write path (no deletes), so
            # triggers are unnecessary.  Falls back to LIKE if FTS5 is missing.
            self._fts_enabled = False
            try:
                conn.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts "
                    "USING fts5(key UNINDEXED, value, tokenize='unicode61')"
                )
                # Backfill rows that predate the FTS index (or a prior build).
                conn.execute(
                    "INSERT INTO memories_fts(key, value) "
                    "SELECT key, value FROM memories "
                    "WHERE key NOT IN (SELECT key FROM memories_fts)"
                )
                self._fts_enabled = True
            except sqlite3.OperationalError:
                logger.warning("FTS5 unavailable; memory search falls back to LIKE")
            conn.commit()

    def store(
        self,
        key: str,
        value: str,
        category: str = "general",
        importance: int = 5,
    ) -> None:
        """Store a memory entry."""
        _reject_ambient_memory_under_enforce()
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
                INSERT INTO memories (
                    key, value, category, importance, created_at, access_count, last_accessed
                )
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
            # Keep the full-text index in sync (upsert == delete + insert).
            if getattr(self, "_fts_enabled", False):
                conn.execute("DELETE FROM memories_fts WHERE key = ?", (key,))
                conn.execute("INSERT INTO memories_fts(key, value) VALUES (?, ?)", (key, value))
            conn.commit()

    def retrieve(self, key: str) -> str | None:
        """Retrieve a memory by key."""
        _reject_ambient_memory_under_enforce()
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM memories WHERE key = ?", (key,)).fetchone()

        if row:
            with db_connection(self.db_path) as conn:
                conn.execute(
                    "UPDATE memories SET access_count = access_count + 1,"
                    " last_accessed = ? WHERE key = ?",
                    (time.time(), key),
                )
                conn.commit()
            return cast("str", row["value"])

        return None

    def search(self, query: str, category: str | None = None, limit: int = 10) -> list[MemoryEntry]:
        """Search memories by content match.

        Uses the FTS5 full-text index for speed; falls back to a LIKE scan when
        FTS5 is unavailable or yields no hits (preserving substring-match recall
        for queries the tokenizer can't satisfy, e.g. mid-word fragments).
        """
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows: list[sqlite3.Row] = []

            # Fast path: FTS5 MATCH.
            match_expr = _build_fts_match(query) if getattr(self, "_fts_enabled", False) else None
            if match_expr:
                try:
                    if category:
                        rows = conn.execute(
                            """
                            SELECT m.* FROM memories m
                            JOIN memories_fts f ON f.key = m.key
                            WHERE memories_fts MATCH ? AND m.category = ?
                            ORDER BY m.importance DESC, m.last_accessed DESC
                            LIMIT ?
                            """,
                            (match_expr, category, limit),
                        ).fetchall()
                    else:
                        rows = conn.execute(
                            """
                            SELECT m.* FROM memories m
                            JOIN memories_fts f ON f.key = m.key
                            WHERE memories_fts MATCH ?
                            ORDER BY m.importance DESC, m.last_accessed DESC
                            LIMIT ?
                            """,
                            (match_expr, limit),
                        ).fetchall()
                except sqlite3.OperationalError:
                    rows = []  # malformed MATCH → fall through to LIKE

            # Fallback path: LIKE substring scan (also used when FTS misses).
            if not rows:
                safe_query = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                pattern = f"%{safe_query}%"
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

    def get_context_string(
        self,
        max_chars: int = 4000,
        query: str = "",
        session_id: str = "",
        owner_key_hash: str | None = None,
    ) -> str:
        """Get rich context from all memory layers for injection into prompts."""
        # Use enhanced multi-layer memory if available
        if hasattr(self, "enhanced"):
            return self.enhanced.get_context_string(
                query=query,
                session_id=session_id,
                max_chars=max_chars,
                owner_key_hash=owner_key_hash,
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

    def store_working(
        self,
        session_id: str,
        key: str,
        value: str,
        category: str = "general",
        importance: int = 5,
        owner_key_hash: str | None = None,
    ) -> None:
        """Store a working memory entry for the current session."""
        _reject_ambient_memory_under_enforce()
        _orin_write_taint(key, value)
        self.enhanced.store_working(
            session_id, key, value, category, importance, owner_key_hash=owner_key_hash
        )

    def store_episode(
        self,
        session_id: str,
        summary: str,
        topics: list[str],
        tokens_used: int = 0,
        turn_count: int = 0,
        importance: int = 5,
        owner_key_hash: str | None = None,
    ) -> None:
        """Store an episodic memory (session summary)."""
        _reject_ambient_memory_under_enforce()
        self.enhanced.store_episode(
            session_id,
            summary,
            topics,
            tokens_used,
            turn_count,
            importance,
            owner_key_hash=owner_key_hash,
        )

    async def dream(
        self,
        llm_summarizer: Any | None = None,
        *,
        propagate_summarizer_errors: bool = False,
    ) -> dict[str, Any]:
        """Run memory consolidation, optionally surfacing summarizer failures."""
        _reject_ambient_memory_under_enforce()
        if hasattr(self, "enhanced"):
            return await self.enhanced.dream(
                llm_summarizer=llm_summarizer,
                propagate_summarizer_errors=propagate_summarizer_errors,
            )
        return {"phases": []}

    def get_dream_logs(
        self, limit: int = 20, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """Get recent dream logs for one owner."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_dream_logs(limit, owner_key_hash=owner_key_hash)
        return []

    def get_episodes(self, limit: int = 20, owner_key_hash: str | None = None) -> list[Any]:
        """Get recent episodic memories."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_episodes(limit, owner_key_hash=owner_key_hash)
        return []

    def get_sessions(
        self, limit: int = 30, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """List recent conversation sessions."""
        if hasattr(self, "enhanced"):
            return self.enhanced.list_sessions(limit, owner_key_hash=owner_key_hash)
        return []

    def cleanup_empty_sessions(self) -> int:
        """Remove episode records for sessions that have no messages."""
        _reject_ambient_memory_under_enforce()
        if hasattr(self, "enhanced"):
            return self.enhanced.cleanup_empty_sessions()
        return 0

    def store_messages(
        self, session_id: str, messages: list[dict[str, str]], owner_key_hash: str | None = None
    ) -> None:
        """Store conversation messages in batch."""
        _reject_ambient_memory_under_enforce()
        if hasattr(self, "enhanced"):
            self.enhanced.store_messages(session_id, messages, owner_key_hash=owner_key_hash)

    def get_session_messages(
        self, session_id: str, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """Get all messages for a session."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_session_messages(session_id, owner_key_hash=owner_key_hash)
        return []

    def delete_session(self, session_id: str, owner_key_hash: str | None = None) -> bool:
        """Delete a session and all its data."""
        _reject_ambient_memory_under_enforce()
        if hasattr(self, "enhanced"):
            return self.enhanced.delete_session(session_id, owner_key_hash=owner_key_hash)
        return False

    def store_capsule(
        self,
        session_id: str,
        capsule_text: str,
        owner_key_hash: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Store or update a short context capsule for a session."""
        _reject_ambient_memory_under_enforce()
        if hasattr(self, "enhanced"):
            return self.enhanced.store_capsule(
                session_id, capsule_text, owner_key_hash=owner_key_hash, **kwargs
            )
        return {
            "session_id": session_id,
            "capsule_text": capsule_text,
            "owner_key_hash": owner_key_hash,
        }

    def get_capsule(
        self,
        session_id: str,
        owner_key_hash: str | None = None,
    ) -> dict[str, Any] | None:
        """Get the session capsule if it exists."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_capsule(session_id, owner_key_hash=owner_key_hash)
        return None

    def delete_capsule(
        self,
        session_id: str,
        owner_key_hash: str | None = None,
    ) -> bool:
        """Delete a session capsule."""
        _reject_ambient_memory_under_enforce()
        if hasattr(self, "enhanced"):
            return self.enhanced.delete_capsule(session_id, owner_key_hash=owner_key_hash)
        return False

    def get_working(
        self, session_id: str, limit: int = 50, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """Get working memories for a session."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_working(session_id, limit, owner_key_hash=owner_key_hash)
        return []

    def get_all_working(
        self, limit: int = 50, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """Get recent working memories across all sessions."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_all_working(limit, owner_key_hash=owner_key_hash)
        return []

    def get_all_semantic(
        self, limit: int = 50, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """Get all semantic memories ordered by recency."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_all_semantic(limit, owner_key_hash=owner_key_hash)
        return []

    def store_semantic(
        self,
        key: str,
        value: str,
        category: str = "fact",
        confidence: float = 0.5,
        source: str = "",
        memory_path: str | None = None,
        entity_type: str | None = None,
        entity_name: str | None = None,
        parent_id: int | None = None,
        relation_type: str | None = None,
        owner_key_hash: str | None = None,
        session_id: str = "",
        evidence: str = "",
    ) -> dict[str, Any]:
        """Store a semantic memory."""
        _reject_ambient_memory_under_enforce()
        _orin_write_taint(key, value)
        if hasattr(self, "enhanced"):
            return self.enhanced.store_semantic(
                key,
                value,
                category,
                confidence,
                source,
                memory_path,
                entity_type,
                entity_name,
                parent_id,
                relation_type,
                owner_key_hash=owner_key_hash,
                session_id=session_id,
                evidence=evidence,
            )
        return {"conflicts": [], "evicted": 0}

    def delete_semantic(
        self, memory_id: int, source: str = "", owner_key_hash: str | None = None
    ) -> bool:
        """Delete a semantic memory by id."""
        _reject_ambient_memory_under_enforce()
        if hasattr(self, "enhanced"):
            return self.enhanced.delete_semantic(
                memory_id, source=source, owner_key_hash=owner_key_hash
            )
        return False

    def update_semantic(
        self,
        memory_id: int,
        value: str,
        category: str | None = None,
        source: str = "",
        memory_path: str | None = None,
        entity_type: str | None = None,
        entity_name: str | None = None,
        parent_id: int | None = None,
        relation_type: str | None = None,
        owner_key_hash: str | None = None,
    ) -> bool:
        """Update a semantic memory by id."""
        _reject_ambient_memory_under_enforce()
        if hasattr(self, "enhanced"):
            return self.enhanced.update_semantic(
                memory_id,
                value,
                category,
                source,
                memory_path,
                entity_type,
                entity_name,
                parent_id,
                relation_type,
                owner_key_hash=owner_key_hash,
            )
        return False

    def search_semantic(
        self,
        query: str,
        category: str | None = None,
        limit: int = 10,
        path_prefix: str | None = None,
        block_priority: bool = True,
        owner_key_hash: str | None = None,
    ) -> list[Any]:
        """Search semantic memories."""
        if hasattr(self, "enhanced"):
            return self.enhanced.search_semantic(
                query,
                category,
                limit,
                path_prefix,
                block_priority,
                owner_key_hash=owner_key_hash,
            )
        return []

    def get_blocks(
        self, path_prefix: str | None = None, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """Get hierarchical block statistics."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_blocks(path_prefix, owner_key_hash=owner_key_hash)
        return []

    def get_by_block(
        self, path_prefix: str, limit: int = 50, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """Get memories under a path prefix."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_by_block(path_prefix, limit, owner_key_hash=owner_key_hash)
        return []

    def verify_semantic(
        self, memory_id: int, source: str = "user", owner_key_hash: str | None = None
    ) -> bool:
        """Mark a semantic memory as verified."""
        if hasattr(self, "enhanced"):
            return self.enhanced.verify_semantic(memory_id, source, owner_key_hash=owner_key_hash)
        return False

    # ── Proposed changes (staging queue) ──

    def propose_change(self, **kwargs: Any) -> dict[str, Any]:
        """Stage a proposed memory change (auto-applied or pending)."""
        _reject_ambient_memory_under_enforce()
        if hasattr(self, "enhanced"):
            return self.enhanced.propose_change(**kwargs)
        return {"proposal_id": None, "status": "disabled", "memory_id": None}

    def list_proposals(
        self, status: str = "pending", owner_key_hash: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """List staged proposals (owner-scoped)."""
        if hasattr(self, "enhanced"):
            return self.enhanced.list_proposals(status, owner_key_hash, limit)
        return []

    def approve_proposal(
        self,
        proposal_id: int,
        owner_key_hash: str | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Apply a pending proposal (optionally editing it first via overrides)."""
        _reject_ambient_memory_under_enforce()
        if hasattr(self, "enhanced"):
            return self.enhanced.approve_proposal(
                proposal_id, owner_key_hash=owner_key_hash, overrides=overrides
            )
        return {"success": False, "error": "disabled"}

    def reject_proposal(
        self, proposal_id: int, owner_key_hash: str | None = None
    ) -> dict[str, Any]:
        """Reject a pending proposal."""
        _reject_ambient_memory_under_enforce()
        if hasattr(self, "enhanced"):
            return self.enhanced.reject_proposal(proposal_id, owner_key_hash=owner_key_hash)
        return {"success": False, "error": "disabled"}

    def move_block(
        self, src_prefix: str, dst_prefix: str, owner_key_hash: str | None = None
    ) -> int:
        """Re-path memories from one block to another (owner-scoped)."""
        _reject_ambient_memory_under_enforce()
        if hasattr(self, "enhanced"):
            return self.enhanced.move_block(src_prefix, dst_prefix, owner_key_hash=owner_key_hash)
        return 0

    def merge_blocks(
        self, src_prefix: str, dst_prefix: str, owner_key_hash: str | None = None
    ) -> int:
        """Merge one block into another (owner-scoped)."""
        _reject_ambient_memory_under_enforce()
        if hasattr(self, "enhanced"):
            return self.enhanced.merge_blocks(src_prefix, dst_prefix, owner_key_hash=owner_key_hash)
        return 0

    # ------------------------------------------------------------------
    # Memory Files (IDENTITY.md, USER.md, DREAMS.md)
    # ------------------------------------------------------------------

    _VALID_MEMORY_FILES = frozenset({"identity", "user", "dreams"})

    def _require_valid_memory_file(self, name: str) -> str:
        """Accept only the three profile basenames; reject path fragments."""
        safe_name = Path(name).name
        if safe_name not in self._VALID_MEMORY_FILES:
            raise ValueError(f"Invalid memory file name: {name}")
        return safe_name

    def list_memory_files(self, owner_key_hash: str | None = None) -> list[str]:
        """List available memory files (basename without extension)."""
        memory_dir = self._memory_file_path("identity", owner_key_hash).parent
        if not memory_dir.exists():
            return []
        files = []
        for path in sorted(memory_dir.glob("*.md")):
            if path.stem in self._VALID_MEMORY_FILES:
                files.append(path.stem)
        return files

    def _memory_file_path(self, name: str, owner_key_hash: str | None = None) -> Path:
        """Resolve memory file path, guarding against path traversal."""
        from js.memory.profile_scope import scoped_profile_path

        return scoped_profile_path(
            self.state_dir, self._require_valid_memory_file(name), owner_key_hash
        )

    def read_memory_file(self, name: str, owner_key_hash: str | None = None) -> str:
        """Read a memory file's content. Returns empty string if not found."""
        path = self._memory_file_path(name, owner_key_hash)
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8")

    def get_audit_log(
        self,
        memory_id: int | None = None,
        table_name: str = "semantic",
        limit: int = 50,
        owner_key_hash: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve audit log for memory changes."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_audit_log(
                memory_id=memory_id,
                table_name=table_name,
                limit=limit,
                owner_key_hash=owner_key_hash,
            )
        return []

    def get_conflicting_memories(
        self, limit: int = 50, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """Retrieve all memories marked as conflicting."""
        if hasattr(self, "enhanced"):
            return self.enhanced.get_conflicting_memories(limit, owner_key_hash=owner_key_hash)
        return []

    def write_memory_file(
        self,
        name: str,
        content: str,
        owner_key_hash: str | None = None,
    ) -> None:
        """Write content to a memory file."""
        _reject_ambient_memory_under_enforce()
        path = self._memory_file_path(self._require_valid_memory_file(name), owner_key_hash)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    # ── R6 compression pipeline (lazy, production-owned) ──

    @property
    def compression_pipeline(self) -> Any:
        """Lazy R6 CompressionPipeline bound to memory_enhanced.db."""
        cached = getattr(self, "_compression_pipeline", None)
        if cached is not None:
            return cached
        from js.memory.compression import CompressionPipeline

        cached = CompressionPipeline(self.enhanced.db_path)
        self._compression_pipeline = cached
        return cached

    def create_compression_proposal(
        self,
        *,
        authority: Any,
        source_refs: tuple[Any, ...],
        proposed_summary: str,
    ) -> Any:
        return self.compression_pipeline.create_proposal(
            authority=authority,
            source_refs=source_refs,
            proposed_summary=proposed_summary,
        )

    def approve_compression_proposal(
        self,
        proposal_id: str,
        *,
        authority: Any,
    ) -> Any:
        return self.compression_pipeline.approve_proposal(
            proposal_id,
            authority=authority,
        )

    def reject_compression_proposal(
        self,
        proposal_id: str,
        *,
        authority: Any,
    ) -> Any:
        return self.compression_pipeline.reject_proposal(
            proposal_id,
            authority=authority,
        )

    def list_compression_proposals(
        self,
        *,
        scope: Any,
        status: str = "pending",
        limit: int = 50,
    ) -> Any:
        return self.compression_pipeline.list_proposals(
            scope=scope,
            status=status,
            limit=limit,
        )

    def rehydrate_compression_capsule(
        self,
        capsule_id: str,
        *,
        authority: Any,
    ) -> Any:
        return self.compression_pipeline.rehydrate_capsule(
            capsule_id,
            authority=authority,
        )
