"""Enhanced multi-layer memory system with dreaming, episodes, and semantic search."""

from __future__ import annotations

import contextlib
import inspect
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from js.config import MemoryConfig
from js.memory.embeddings import Embedder, KeywordEmbedder, cosine_similarity
from js.memory.enhanced_store.constants import (
    _DEFAULT_DREAM_LOG_RETENTION_DAYS,
    _DEFAULT_MAX_DREAM_DIARY_BYTES,
    _DEFAULT_MAX_DREAM_LOGS,
    _DEFAULT_MAX_DREAM_LOGS_GLOBAL,
    _DEFAULT_MAX_PROPOSALS_GLOBAL,
    _DEFAULT_MAX_PROPOSALS_PER_OWNER,
    _DEFAULT_MAX_SESSIONS_GLOBAL,
    _DEFAULT_MAX_SESSIONS_PER_OWNER,
    _DEFAULT_PROPOSAL_RETENTION_DAYS,
    _LEGACY_LOCAL_OWNER,
    _TERMINAL_PROPOSAL_STATUSES,
)
from js.memory.enhanced_store.models import Episode, SemanticMemory
from js.utils.db import db_connection as db_connection
from js.utils.log import get_logger

logger = get_logger("js.memory.enhanced")


def _reject_ambient_memory_under_enforce() -> None:
    from js.orin.stage_c import ambient_memory_blocked

    if ambient_memory_blocked():
        raise RuntimeError("ambient MemoryStore is unavailable under orin.enforce")


class EnhancedMemoryStore:
    """Multi-layer memory: working -> episodic -> semantic, with dreaming consolidation."""

    def __init__(
        self,
        state_dir: Path,
        config: MemoryConfig,
        embedder: Embedder | None = None,
    ) -> None:
        self.state_dir = state_dir
        self.config = config
        self.db_path = state_dir / "memory_enhanced.db"
        self.embedder = embedder or KeywordEmbedder()
        self._init_db()
        self._last_dream: float = 0.0
        self._layered: Any | None = None

    def close(self) -> None:
        if hasattr(self, "embedder") and self.embedder and hasattr(self.embedder, "close"):
            self.embedder.close()

    def _layered_store(self) -> Any:
        """Lazy LayeredMemoryStore sharing this enhanced DB path."""
        if self._layered is None:
            from js.memory.layered import LayeredMemoryStore

            self._layered = LayeredMemoryStore(self.db_path)
        return self._layered

    @property
    def _secrets(self) -> Any:
        """Lazy-loaded SecretManager for data-at-rest encryption."""
        if not hasattr(self, "_secrets_inst"):
            from js.security.secrets import SecretManager

            self._secrets_inst = SecretManager(self.state_dir)
        return self._secrets_inst

    @staticmethod
    def _owner_filter(owner_key_hash: str | None) -> tuple[str, list[Any]]:
        """Build a reusable owner-scoping SQL predicate.

        Returns ``(clause, params)``.  Authenticated owners see only their own
        rows.  ``None`` maps to the local/legacy NULL partition rather than an
        unfiltered query, so no-auth convenience mode cannot read or mutate
        authenticated users' semantic memory rows by accident.
        """
        if owner_key_hash is None:
            return "owner_key_hash IS NULL", []
        return "owner_key_hash = ?", [owner_key_hash]

    @staticmethod
    def _session_owner(owner_key_hash: str | None) -> str:
        """Normalize an owner key for session-scoped tables.

        Session-scoped tables store owner_key_hash as NOT NULL.  ``None``
        (no-auth / local / legacy) maps to a fixed sentinel so that composite
        unique constraints reliably isolate rows and authenticated owners can
        never accidentally read or overwrite legacy data.
        """
        return owner_key_hash if owner_key_hash is not None else _LEGACY_LOCAL_OWNER

    # Keyword → hierarchical block mapping for auto-classification.
    # Each tuple: (keyword_set, entity_type, memory_path, relation_type)
    _ENTITY_BLOCK_RULES: list[tuple[set[str], str, str, str]] = [
        # family → /people/family
        (
            {
                "wife",
                "husband",
                "spouse",
                "mom",
                "dad",
                "mother",
                "father",
                "son",
                "daughter",
                "brother",
                "sister",
                "parent",
                "grandma",
                "grandpa",
                "grandmother",
                "grandfather",
                "uncle",
                "aunt",
                "cousin",
                "nephew",
                "niece",
                "妻子",
                "老婆",
                "老公",
                "丈夫",
                "媳妇",
                "妈妈",
                "父亲",
                "母亲",
                "爸爸",
                "妈",
                "爸",
                "儿子",
                "女儿",
                "哥哥",
                "弟弟",
                "姐姐",
                "妹妹",
                "爷爷",
                "奶奶",
                "外公",
                "外婆",
                "叔叔",
                "阿姨",
                "侄子",
                "侄女",
                "亲戚",
                "家人",
                "家庭",
            },
            "family",
            "/people/family",
            "has",
        ),
        # friend → /people/friends
        (
            {
                "friend",
                "friends",
                "buddy",
                "pal",
                "bestie",
                "bff",
                "classmate",
                "roommate",
                "acquaintance",
                "neighbor",
                "朋友",
                "好友",
                "闺蜜",
                "哥们",
                "兄弟",
                "同学",
                "室友",
                "死党",
                "发小",
                "邻居",
                "熟人",
            },
            "friend",
            "/people/friends",
            "knows",
        ),
        # colleague → /work/colleagues
        (
            {
                "boss",
                "colleague",
                "coworker",
                "teammate",
                "peer",
                "manager",
                "lead",
                "supervisor",
                "mentor",
                "partner",
                "collaborator",
                "老板",
                "同事",
                "队友",
                "经理",
                "主管",
                "领导",
                "导师",
                "合伙人",
            },
            "colleague",
            "/work/colleagues",
            "works_with",
        ),
        # project → /work/projects
        (
            {
                "project",
                "sprint",
                "milestone",
                "deliverable",
                "roadmap",
                "backlog",
                "feature",
                "release",
                "版本",
                "发布",
                "项目",
                "冲刺",
                "里程碑",
                "交付物",
                "路线图",
                "需求",
                "功能",
            },
            "project",
            "/work/projects",
            "part_of",
        ),
        # company → /work/company
        (
            {
                "company",
                "office",
                "workplace",
                "employer",
                "organization",
                "org",
                "firm",
                "corporation",
                "startup",
                "enterprise",
                "department",
                "team",
                "公司",
                "办公室",
                "工作单位",
                "雇主",
                "企业",
                "创业",
                "部门",
                "团队",
            },
            "company",
            "/work/company",
            "works_for",
        ),
        # active plan / goal / todo → /plans/active
        (
            {
                "plan",
                "goal",
                "todo",
                "objective",
                "target",
                "intention",
                "aspiration",
                "resolution",
                "deadline",
                "task",
                "assignment",
                "计划",
                "目标",
                "打算",
                "待办",
                "想做",
                "准备",
                "截止日期",
                "任务",
                "安排",
                "规划",
                "愿望",
            },
            "plan",
            "/plans/active",
            "plans",
        ),
        # completed plan / history → /plans/history
        (
            {
                "completed",
                "finished",
                "achieved",
                "accomplished",
                "已完成",
                "完成了",
                "搞定",
                "达成",
                "结束了",
                "做完",
            },
            "plan",
            "/plans/history",
            "completed",
        ),
        # preference → /user/preferences
        (
            {
                "like",
                "prefer",
                "favorite",
                "enjoy",
                "hate",
                "dislike",
                "love",
                "want",
                "need",
                "wish",
                "avoid",
                "喜欢",
                "爱",
                "讨厌",
                "恨",
                "厌恶",
                "偏好",
                "想要",
                "需要",
                "希望",
                "感兴趣",
                "热衷",
                "回避",
                "口味",
                "习惯",
                "常用",
                "首选",
            },
            "preference",
            "/user/preferences",
            "prefers",
        ),
        # personality → /user/personality
        (
            {
                "personality",
                "character",
                "trait",
                "temperament",
                "introvert",
                "extrovert",
                "mbti",
                "enneagram",
                "values",
                "attitude",
                "mindset",
                "性格",
                "个性",
                "脾气",
                "价值观",
                "内向",
                "外向",
                "性情",
                "人格",
                "三观",
                "心态",
                "为人",
            },
            "personality",
            "/user/personality",
            "is",
        ),
        # body / health → /user/body
        (
            {
                "height",
                "weight",
                "blood",
                "allergy",
                "allergic",
                "medical",
                "health",
                "illness",
                "disease",
                "diagnosis",
                "medication",
                "fitness",
                "bmi",
                "身高",
                "体重",
                "血型",
                "过敏",
                "病史",
                "健康",
                "疾病",
                "体检",
                "身体",
                "用药",
                "病情",
                "体质",
            },
            "body",
            "/user/body",
            "has",
        ),
        # device → /user/devices
        (
            {
                "phone",
                "laptop",
                "computer",
                "device",
                "mac",
                "iphone",
                "ipad",
                "monitor",
                "keyboard",
                "mouse",
                "headphone",
                "earbud",
                "camera",
                "tablet",
                "watch",
                "console",
                "speaker",
                "router",
                "printer",
                "手机",
                "电脑",
                "笔记本",
                "台式机",
                "显示器",
                "键盘",
                "鼠标",
                "耳机",
                "音箱",
                "相机",
                "平板",
                "手表",
                "游戏机",
                "路由器",
                "打印机",
                "设备",
            },
            "device",
            "/user/devices",
            "owns",
        ),
        # identity → /user/identity
        (
            {
                "age",
                "birthday",
                "birth",
                "address",
                "email",
                "phone_number",
                "identity",
                "gender",
                "pronoun",
                "nationality",
                "language",
                "occupation",
                "title",
                "degree",
                "年龄",
                "生日",
                "出生",
                "地址",
                "邮箱",
                "电话",
                "性别",
                "代词",
                "国籍",
                "语言",
                "职业",
                "职位",
                "学位",
                "身份证",
            },
            "identity",
            "/user/identity",
            "is",
        ),
        # event → /user/events
        (
            {
                "schedule",
                "appointment",
                "meeting",
                "event",
                "trip",
                "travel",
                "vacation",
                "holiday",
                "conference",
                "reminder",
                "calendar",
                "日程",
                "约会",
                "会议",
                "活动",
                "旅行",
                "出行",
                "假期",
                "节日",
                "大会",
                "提醒",
                "日历",
                "行程",
            },
            "event",
            "/user/events",
            "attends",
        ),
        # location → /user/locations
        (
            {
                "location",
                "city",
                "country",
                "place",
                "home",
                "apartment",
                "house",
                "address",
                "neighborhood",
                "office_location",
                "site",
                "building",
                "room",
                "位置",
                "城市",
                "国家",
                "地点",
                "家",
                "公寓",
                "房子",
                "住址",
                "小区",
                "办公楼",
                "大厦",
                "房间",
                "住所",
            },
            "location",
            "/user/locations",
            "located_at",
        ),
        # chat history → /history/chats
        (
            {
                "conversation",
                "chat",
                "session",
                "discussion",
                "transcript",
                "会话",
                "聊天",
                "对话",
                "记录",
                "历史",
            },
            "chat",
            "/history/chats",
            "discussed",
        ),
    ]

    def _infer_entity_block(
        self,
        key: str,
        value: str,
        category: str,
        memory_path: str | None = None,
        entity_type: str | None = None,
        entity_name: str | None = None,
        relation_type: str | None = None,
    ) -> tuple[str, str, str, str]:
        """Auto-classify a memory into a hierarchical block.

        Returns (memory_path, entity_type, entity_name, relation_type).
        If any field is explicitly provided, it takes precedence over inference.
        """
        if memory_path and entity_type:
            return (
                memory_path,
                entity_type,
                entity_name or key.split("_")[0],
                relation_type or "has",
            )

        text = f"{key} {value}".lower()
        # Split on spaces, underscores, hyphens, and dots to handle compound keys
        import re

        raw_words = re.split(r"[\s_.-]+", text)
        words = {w.strip() for w in raw_words if w.strip()}

        best_match: tuple[str, str, str, str] | None = None
        best_score: tuple[int, int] = (0, 0)

        for rule_words, etype, path, rel in self._ENTITY_BLOCK_RULES:
            # Check exact word matches and substring containment for partial matches
            exact_overlap = words & rule_words
            partial_overlap = {rw for rw in rule_words if any(rw in w for w in words)}
            overlap = exact_overlap | partial_overlap
            if overlap:
                # Score by number of matched keywords (more matches = stronger signal).
                # Tie-break by fewer total rule words (more specific rules win).
                score = (len(overlap), -len(rule_words))
                if score > best_score:
                    best_score = score
                    best_match = (path, etype, key.split("_")[0], rel)

        if best_match:
            inferred_path, inferred_type, inferred_name, inferred_rel = best_match
        else:
            # Fallback based on category
            category_map = {
                "preference": ("/user/preferences", "preference", key.split("_")[0], "prefers"),
                "insight": ("/general/insights", "insight", key.split("_")[0], "has"),
                "external": ("/general/external", "external", key.split("_")[0], "has"),
            }
            inferred_path, inferred_type, inferred_name, inferred_rel = category_map.get(
                category, ("/general", "general", key.split("_")[0], "has")
            )

        return (
            memory_path or inferred_path,
            entity_type or inferred_type,
            entity_name or inferred_name,
            relation_type or inferred_rel,
        )

    def _init_db(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with db_connection(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")  # Writers no longer block readers
            # Working memory: short-term, per-session, owner-isolated.
            # v2 schema: added owner_key_hash so the same (session_id, key) can
            # coexist for different owners. Legacy pre-isolation rows are mapped
            # to the __legacy_local__ sentinel.
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
                    owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__',
                    UNIQUE(owner_key_hash, session_id, key)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_working_session
                ON working_memories(owner_key_hash, session_id)
            """)

            # Migration: owner-partitioned schema for working_memories.
            # Rebuild whenever owner_key_hash is not NOT NULL or the composite
            # unique key is missing.  Pre-isolation rows become __legacy_local__.
            wm_sql = (
                conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='working_memories'"
                ).fetchone()
                or [""]
            )[0] or ""
            wm_normalized = wm_sql.lower().replace(" ", "")
            needs_wm_rebuild = (
                "owner_key_hashtextnotnull" not in wm_normalized
                or "unique(owner_key_hash,session_id,key)" not in wm_normalized
            )
            if needs_wm_rebuild:
                old_cols = [
                    c[1] for c in conn.execute("PRAGMA table_info(working_memories)").fetchall()
                ]
                new_cols = {
                    "id",
                    "session_id",
                    "key",
                    "value",
                    "category",
                    "importance",
                    "created_at",
                    "access_count",
                    "last_accessed",
                    "owner_key_hash",
                }
                shared_cols = [c for c in old_cols if c in new_cols]
                col_list = ", ".join(shared_cols)
                conn.execute("DROP TABLE IF EXISTS working_memories_new")
                conn.execute("""
                    CREATE TABLE working_memories_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL,
                        key TEXT NOT NULL,
                        value TEXT NOT NULL,
                        category TEXT DEFAULT 'general',
                        importance INTEGER DEFAULT 5,
                        created_at REAL NOT NULL,
                        access_count INTEGER DEFAULT 0,
                        last_accessed REAL NOT NULL,
                        owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__',
                        UNIQUE(owner_key_hash, session_id, key)
                    )
                """)
                # Build SELECT matching the new column order so values line up
                # even when owner_key_hash is replaced with COALESCE.
                ordered_cols = [
                    "id",
                    "session_id",
                    "key",
                    "value",
                    "category",
                    "importance",
                    "created_at",
                    "access_count",
                    "last_accessed",
                    "owner_key_hash",
                ]
                select_items = []
                for col in ordered_cols:
                    if col in old_cols:
                        if col == "owner_key_hash":
                            select_items.append("COALESCE(owner_key_hash, '__legacy_local__')")
                        else:
                            select_items.append(col)
                    else:
                        select_items.append(
                            "'__legacy_local__'" if col == "owner_key_hash" else "NULL"
                        )
                insert_cols = ", ".join(ordered_cols)
                select_cols = ", ".join(select_items)
                conn.execute(
                    f"INSERT INTO working_memories_new ({insert_cols}) "
                    f"SELECT {select_cols} FROM working_memories"
                )
                conn.execute("DROP TABLE working_memories")
                conn.execute("ALTER TABLE working_memories_new RENAME TO working_memories")
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_working_session
                    ON working_memories(owner_key_hash, session_id)
                """)

            # Episodic memory: session summaries, owner-isolated.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS episodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    summary TEXT,
                    topics TEXT,
                    tokens_used INTEGER DEFAULT 0,
                    turn_count INTEGER DEFAULT 0,
                    created_at REAL NOT NULL,
                    importance INTEGER DEFAULT 5,
                    owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__',
                    UNIQUE(session_id, owner_key_hash)
                )
            """)
            # Migration: owner-partitioned schema for episodes.
            # Rebuild whenever owner_key_hash is not NOT NULL or the composite
            # unique key is missing (handles old UNIQUE(session_id) and
            # UNIQUE(session_id, key) intermediate schemas).
            ep_sql = (
                conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='episodes'"
                ).fetchone()
                or [""]
            )[0] or ""
            ep_normalized = ep_sql.lower().replace(" ", "")
            needs_ep_rebuild = (
                "owner_key_hashtextnotnull" not in ep_normalized
                or "unique(session_id,owner_key_hash)" not in ep_normalized
            )
            if needs_ep_rebuild:
                old_cols = [c[1] for c in conn.execute("PRAGMA table_info(episodes)").fetchall()]
                new_cols = {
                    "id",
                    "session_id",
                    "summary",
                    "topics",
                    "tokens_used",
                    "turn_count",
                    "created_at",
                    "importance",
                    "owner_key_hash",
                }
                shared_cols = [c for c in old_cols if c in new_cols]
                col_list = ", ".join(shared_cols)
                conn.execute("DROP TABLE IF EXISTS episodes_new")
                conn.execute("""
                    CREATE TABLE episodes_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL,
                        summary TEXT,
                        topics TEXT,
                        tokens_used INTEGER DEFAULT 0,
                        turn_count INTEGER DEFAULT 0,
                        created_at REAL NOT NULL,
                        importance INTEGER DEFAULT 5,
                        owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__',
                        UNIQUE(session_id, owner_key_hash)
                    )
                """)
                # Build SELECT matching the new column order so values line up
                # even when owner_key_hash is replaced with COALESCE.
                ordered_cols = [
                    "id",
                    "session_id",
                    "summary",
                    "topics",
                    "tokens_used",
                    "turn_count",
                    "created_at",
                    "importance",
                    "owner_key_hash",
                ]
                select_items = []
                for col in ordered_cols:
                    if col in old_cols:
                        if col == "owner_key_hash":
                            select_items.append("COALESCE(owner_key_hash, '__legacy_local__')")
                        else:
                            select_items.append(col)
                    else:
                        select_items.append(
                            "'__legacy_local__'" if col == "owner_key_hash" else "NULL"
                        )
                insert_cols = ", ".join(ordered_cols)
                select_cols = ", ".join(select_items)
                conn.execute(
                    f"INSERT INTO episodes_new ({insert_cols}) SELECT {select_cols} FROM episodes"
                )
                conn.execute("DROP TABLE episodes")
                conn.execute("ALTER TABLE episodes_new RENAME TO episodes")

            # Session capsules: short context summary for long conversations.
            # v2 schema: added metadata for quality tracking, lifecycle, drift detection.
            # v4 schema: owner_key_hash is NOT NULL; legacy NULL-owner rows are
            # migrated to the __legacy_local__ sentinel.  Composite unique
            # (session_id, owner_key_hash) guarantees one capsule per owner.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS session_capsules (
                    session_id TEXT NOT NULL,
                    capsule_text TEXT NOT NULL,
                    owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__',
                    updated_at REAL NOT NULL,
                    version INTEGER DEFAULT 1,
                    source_range TEXT,
                    generated_by_model TEXT,
                    recent_turns_kept INTEGER,
                    estimated_tokens_saved INTEGER,
                    refresh_reason TEXT,
                    fail_count INTEGER DEFAULT 0,
                    last_accessed REAL DEFAULT 0,
                    ttl_seconds INTEGER DEFAULT 0,
                    is_pinned INTEGER DEFAULT 0,
                    is_expired INTEGER DEFAULT 0,
                    drift_detected INTEGER DEFAULT 0,
                    drift_reason TEXT,
                    secrets_redacted INTEGER DEFAULT 0,
                    UNIQUE(session_id, owner_key_hash)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_session_capsules_owner
                ON session_capsules(owner_key_hash)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_session_capsules_accessed
                ON session_capsules(last_accessed DESC)
            """)

            # Migration: any schema that does not declare owner_key_hash as
            # NOT NULL (old single-key or v3 NULLable owner-partitioned) is
            # rebuilt into the v4 NOT NULL sentinel schema.
            capsule_sql = (
                conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='session_capsules'"
                ).fetchone()
                or [""]
            )[0] or ""
            if "owner_key_hash text not null" not in capsule_sql.lower():
                old_cols = [
                    c[1] for c in conn.execute("PRAGMA table_info(session_capsules)").fetchall()
                ]
                new_cols = {
                    "session_id",
                    "capsule_text",
                    "owner_key_hash",
                    "updated_at",
                    "version",
                    "source_range",
                    "generated_by_model",
                    "recent_turns_kept",
                    "estimated_tokens_saved",
                    "refresh_reason",
                    "fail_count",
                    "last_accessed",
                    "ttl_seconds",
                    "is_pinned",
                    "is_expired",
                    "drift_detected",
                    "drift_reason",
                    "secrets_redacted",
                }
                shared_cols = [c for c in old_cols if c in new_cols]
                col_list = ", ".join(shared_cols)
                conn.execute("DROP TABLE IF EXISTS session_capsules_new")
                conn.execute("""
                    CREATE TABLE session_capsules_new (
                        session_id TEXT NOT NULL,
                        capsule_text TEXT NOT NULL,
                        owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__',
                        updated_at REAL NOT NULL,
                        version INTEGER DEFAULT 1,
                        source_range TEXT,
                        generated_by_model TEXT,
                        recent_turns_kept INTEGER,
                        estimated_tokens_saved INTEGER,
                        refresh_reason TEXT,
                        fail_count INTEGER DEFAULT 0,
                        last_accessed REAL DEFAULT 0,
                        ttl_seconds INTEGER DEFAULT 0,
                        is_pinned INTEGER DEFAULT 0,
                        is_expired INTEGER DEFAULT 0,
                        drift_detected INTEGER DEFAULT 0,
                        drift_reason TEXT,
                        secrets_redacted INTEGER DEFAULT 0,
                        UNIQUE(session_id, owner_key_hash)
                    )
                """)
                # Build SELECT matching the new column order so values line up
                # even when owner_key_hash is replaced with COALESCE.
                ordered_cols = [
                    "session_id",
                    "capsule_text",
                    "owner_key_hash",
                    "updated_at",
                    "version",
                    "source_range",
                    "generated_by_model",
                    "recent_turns_kept",
                    "estimated_tokens_saved",
                    "refresh_reason",
                    "fail_count",
                    "last_accessed",
                    "ttl_seconds",
                    "is_pinned",
                    "is_expired",
                    "drift_detected",
                    "drift_reason",
                    "secrets_redacted",
                ]
                select_items = []
                for col in ordered_cols:
                    if col in old_cols:
                        if col == "owner_key_hash":
                            select_items.append("COALESCE(owner_key_hash, '__legacy_local__')")
                        else:
                            select_items.append(col)
                    else:
                        select_items.append(
                            "'__legacy_local__'" if col == "owner_key_hash" else "NULL"
                        )
                insert_cols = ", ".join(ordered_cols)
                select_cols = ", ".join(select_items)
                conn.execute(
                    f"INSERT INTO session_capsules_new ({insert_cols}) "
                    f"SELECT {select_cols} FROM session_capsules"
                )
                conn.execute("DROP TABLE session_capsules")
                conn.execute("ALTER TABLE session_capsules_new RENAME TO session_capsules")
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_session_capsules_owner
                    ON session_capsules(owner_key_hash)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_session_capsules_accessed
                    ON session_capsules(last_accessed DESC)
                """)
            # Migration: add v2 columns for existing databases
            v2_cols = [
                ("version", "INTEGER DEFAULT 1"),
                ("source_range", "TEXT"),
                ("generated_by_model", "TEXT"),
                ("recent_turns_kept", "INTEGER"),
                ("estimated_tokens_saved", "INTEGER"),
                ("refresh_reason", "TEXT"),
                ("fail_count", "INTEGER DEFAULT 0"),
                ("last_accessed", "REAL DEFAULT 0"),
                ("ttl_seconds", "INTEGER DEFAULT 0"),
                ("is_pinned", "INTEGER DEFAULT 0"),
                ("is_expired", "INTEGER DEFAULT 0"),
                ("drift_detected", "INTEGER DEFAULT 0"),
                ("drift_reason", "TEXT"),
                ("secrets_redacted", "INTEGER DEFAULT 0"),
            ]
            for col, dtype in v2_cols:
                with contextlib.suppress(sqlite3.OperationalError):
                    conn.execute(f"ALTER TABLE session_capsules ADD COLUMN {col} {dtype}")

            # Semantic memory: extracted knowledge / preferences.
            # NOTE: no table-level UNIQUE(key) — uniqueness is per-owner, enforced
            # by the composite index idx_semantic_key below, so the same key can
            # exist for different owners (multi-user isolation).
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
                    embedding TEXT
                )
            """)

            # One-time rebuild for legacy DBs that still carry a global
            # UNIQUE(key) table constraint.  We copy every shared column into a
            # constraint-free table so the same key can coexist per owner.
            # Runs at most once per DB (afterwards the table sql has no UNIQUE).
            table_sql = (
                conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='semantic_memories'"
                ).fetchone()
                or [""]
            )[0] or ""
            if "UNIQUE" in table_sql.upper():
                old_cols = [
                    c[1] for c in conn.execute("PRAGMA table_info(semantic_memories)").fetchall()
                ]
                conn.execute("DROP TABLE IF EXISTS semantic_memories_rebuild")
                conn.execute("""
                    CREATE TABLE semantic_memories_rebuild (
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
                        feedback_score REAL DEFAULT 0.0,
                        conflict_status TEXT DEFAULT '',
                        importance INTEGER DEFAULT 5,
                        memory_path TEXT DEFAULT '',
                        entity_type TEXT DEFAULT '',
                        entity_name TEXT DEFAULT '',
                        parent_id INTEGER DEFAULT NULL,
                        relation_type TEXT DEFAULT '',
                        last_verified_at REAL DEFAULT 0,
                        owner_key_hash TEXT DEFAULT NULL,
                        session_id TEXT DEFAULT '',
                        evidence TEXT DEFAULT ''
                    )
                """)
                canonical = {
                    "id",
                    "key",
                    "value",
                    "category",
                    "confidence",
                    "source",
                    "created_at",
                    "last_accessed",
                    "access_count",
                    "embedding",
                    "feedback_score",
                    "conflict_status",
                    "importance",
                    "memory_path",
                    "entity_type",
                    "entity_name",
                    "parent_id",
                    "relation_type",
                    "last_verified_at",
                    "owner_key_hash",
                    "session_id",
                    "evidence",
                }
                shared = [c for c in old_cols if c in canonical]
                col_list = ", ".join(shared)
                conn.execute(
                    f"INSERT INTO semantic_memories_rebuild ({col_list}) "
                    f"SELECT {col_list} FROM semantic_memories"
                )
                conn.execute("DROP TABLE semantic_memories")
                conn.execute("ALTER TABLE semantic_memories_rebuild RENAME TO semantic_memories")
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_semantic_category ON semantic_memories(category)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_semantic_created_at
                ON semantic_memories(created_at DESC)
            """)

            # Memory links: associations built during REM
            conn.execute("""
                CREATE TABLE IF NOT EXISTS memory_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_key_hash TEXT,
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
                    owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__',
                    phase TEXT,
                    summary TEXT,
                    changes TEXT,
                    created_at REAL NOT NULL
                )
            """)
            # Dream logs created before owner isolation cannot be attributed
            # safely. Keep them in the local legacy partition instead of
            # making authenticated owners able to read them.
            dream_log_cols = {
                row[1] for row in conn.execute("PRAGMA table_info(dream_logs)").fetchall()
            }
            if "owner_key_hash" not in dream_log_cols:
                conn.execute(
                    "ALTER TABLE dream_logs "
                    "ADD COLUMN owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__'"
                )
            conn.execute(
                """
                UPDATE dream_logs
                SET owner_key_hash = ?
                WHERE owner_key_hash IS NULL OR owner_key_hash = ''
                """,
                (_LEGACY_LOCAL_OWNER,),
            )
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_dream_logs_owner_created
                ON dream_logs(owner_key_hash, created_at DESC)
            """)

            # Session messages: full conversation history per session
            # v2: added owner_key_hash for per-session isolation at the message level.
            # v3: owner_key_hash is NOT NULL; legacy NULL rows migrate to the
            #     __legacy_local__ sentinel.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS session_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT,
                    created_at REAL NOT NULL,
                    owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__'
                )
            """)
            # Migration: rebuild session_messages if owner_key_hash is not NOT NULL.
            sm_sql = (
                conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='session_messages'"
                ).fetchone()
                or [""]
            )[0] or ""
            if "owner_key_hash text not null" not in sm_sql.lower():
                old_cols = [
                    c[1] for c in conn.execute("PRAGMA table_info(session_messages)").fetchall()
                ]
                new_cols = {"id", "session_id", "role", "content", "created_at", "owner_key_hash"}
                shared_cols = [c for c in old_cols if c in new_cols]
                col_list = ", ".join(shared_cols)
                conn.execute("DROP TABLE IF EXISTS session_messages_new")
                conn.execute("""
                    CREATE TABLE session_messages_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL,
                        role TEXT NOT NULL,
                        content TEXT,
                        created_at REAL NOT NULL,
                        owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__'
                    )
                """)
                # Build SELECT matching the new column order so values line up
                # even when owner_key_hash is replaced with COALESCE.
                ordered_cols = [
                    "id",
                    "session_id",
                    "role",
                    "content",
                    "created_at",
                    "owner_key_hash",
                ]
                select_items = []
                for col in ordered_cols:
                    if col in old_cols:
                        if col == "owner_key_hash":
                            select_items.append("COALESCE(owner_key_hash, '__legacy_local__')")
                        else:
                            select_items.append(col)
                    else:
                        select_items.append(
                            "'__legacy_local__'" if col == "owner_key_hash" else "NULL"
                        )
                insert_cols = ", ".join(ordered_cols)
                select_cols = ", ".join(select_items)
                conn.execute(
                    f"INSERT INTO session_messages_new ({insert_cols}) "
                    f"SELECT {select_cols} FROM session_messages"
                )
                conn.execute("DROP TABLE session_messages")
                conn.execute("ALTER TABLE session_messages_new RENAME TO session_messages")
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_session_messages_session
                ON session_messages(owner_key_hash, session_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_session_messages_time
                ON session_messages(owner_key_hash, session_id, created_at)
            """)

            # Fix: add unique indexes for tables created before constraints were added
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_working_session_key
                ON working_memories(owner_key_hash, session_id, key)
            """)

            # Migration: add quality-control columns for semantic memories
            migrations = [
                ("feedback_score", "REAL DEFAULT 0.0"),
                ("conflict_status", "TEXT DEFAULT ''"),
                ("importance", "INTEGER DEFAULT 5"),
                ("source", "TEXT"),
            ]
            for col, dtype in migrations:
                with contextlib.suppress(sqlite3.OperationalError):
                    conn.execute(f"ALTER TABLE semantic_memories ADD COLUMN {col} {dtype}")

            # Migration: add structured block columns for semantic memories
            block_migrations = [
                ("memory_path", "TEXT DEFAULT ''"),
                ("entity_type", "TEXT DEFAULT ''"),
                ("entity_name", "TEXT DEFAULT ''"),
                ("parent_id", "INTEGER DEFAULT NULL"),
                ("relation_type", "TEXT DEFAULT ''"),
                ("last_verified_at", "REAL DEFAULT 0"),
                # Per-user isolation + provenance for the hierarchical library.
                # owner_key_hash NULL == legacy/shared (visible to every owner).
                ("owner_key_hash", "TEXT DEFAULT NULL"),
                ("session_id", "TEXT DEFAULT ''"),
                ("evidence", "TEXT DEFAULT ''"),
            ]
            for col, dtype in block_migrations:
                with contextlib.suppress(sqlite3.OperationalError):
                    conn.execute(f"ALTER TABLE semantic_memories ADD COLUMN {col} {dtype}")

            # Legacy REM links predate owner isolation and had no uniqueness
            # constraint. Backfill their owner from the source memory, remove
            # unsafe cross-owner edges, then collapse duplicates before adding
            # the expression index (NULL is the legacy/local owner partition).
            memory_link_cols = {
                row[1] for row in conn.execute("PRAGMA table_info(memory_links)").fetchall()
            }
            if "owner_key_hash" not in memory_link_cols:
                conn.execute("ALTER TABLE memory_links ADD COLUMN owner_key_hash TEXT")
            conn.execute(
                """
                UPDATE memory_links
                SET owner_key_hash = (
                    SELECT source.owner_key_hash
                    FROM semantic_memories AS source
                    WHERE source.id = memory_links.from_id
                )
                WHERE from_table = 'semantic_memories'
                  AND EXISTS (
                      SELECT 1
                      FROM semantic_memories AS source
                      WHERE source.id = memory_links.from_id
                  )
                """
            )
            conn.execute(
                """
                DELETE FROM memory_links
                WHERE from_table = 'semantic_memories'
                  AND to_table = 'semantic_memories'
                  AND EXISTS (
                      SELECT 1
                      FROM semantic_memories AS source
                      JOIN semantic_memories AS target
                        ON target.id = memory_links.to_id
                      WHERE source.id = memory_links.from_id
                        AND COALESCE(source.owner_key_hash, '')
                            <> COALESCE(target.owner_key_hash, '')
                  )
                """
            )
            conn.execute(
                """
                WITH ranked_links AS (
                    SELECT
                        id,
                        ROW_NUMBER() OVER (
                            PARTITION BY
                                COALESCE(owner_key_hash, ''),
                                COALESCE(from_table, ''),
                                COALESCE(from_id, -1),
                                COALESCE(to_table, ''),
                                COALESCE(to_id, -1),
                                COALESCE(link_type, '')
                            ORDER BY created_at DESC, id DESC
                        ) AS duplicate_rank
                    FROM memory_links
                )
                DELETE FROM memory_links
                WHERE id IN (
                    SELECT id FROM ranked_links WHERE duplicate_rank > 1
                )
                """
            )
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_links_owner_edge
                ON memory_links(
                    COALESCE(owner_key_hash, ''),
                    COALESCE(from_table, ''),
                    COALESCE(from_id, -1),
                    COALESCE(to_table, ''),
                    COALESCE(to_id, -1),
                    COALESCE(link_type, '')
                )
                """
            )

            # Indexes for block-based queries
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_semantic_path ON semantic_memories(memory_path)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_semantic_entity ON semantic_memories(entity_type)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_semantic_parent ON semantic_memories(parent_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_semantic_owner
                ON semantic_memories(owner_key_hash, memory_path)
            """)
            # Per-owner key uniqueness (NULL owner == shared, mapped to '').
            # Created after the owner_key_hash column exists (added above).
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_semantic_key
                ON semantic_memories(key, COALESCE(owner_key_hash, ''))
            """)

            # One-time backfill: assign default memory_path for existing records.
            # Uses PRAGMA user_version to avoid scanning the entire table on
            # every startup — once migrated, the UPDATE is skipped forever.
            _current_schema_version = 5
            version_row = conn.execute("PRAGMA user_version").fetchone()
            current_version = version_row[0] if version_row else 0
            if current_version < _current_schema_version:
                try:
                    conn.execute("""
                        UPDATE semantic_memories
                        SET memory_path = CASE category
                            WHEN 'preference' THEN '/user/preferences'
                            WHEN 'insight' THEN '/general/insights'
                            WHEN 'external' THEN '/general/external'
                            ELSE '/general'
                        END,
                        entity_type = COALESCE(NULLIF(entity_type, ''), category)
                        WHERE memory_path = '' OR memory_path IS NULL
                    """)
                    # v5: family moved from /user/family to /people/family.
                    # Remap both the block itself and any nested sub-blocks.
                    conn.execute(
                        "UPDATE semantic_memories SET memory_path = '/people/family' "
                        "WHERE memory_path = '/user/family'"
                    )
                    conn.execute(
                        "UPDATE semantic_memories "
                        "SET memory_path = '/people/family' || substr(memory_path, length('/user/family') + 1) "
                        "WHERE memory_path LIKE '/user/family/%'"
                    )
                    conn.execute(f"PRAGMA user_version = {_current_schema_version}")
                    conn.commit()
                except Exception:
                    pass

            # Audit log for memory changes
            conn.execute("""
                CREATE TABLE IF NOT EXISTS memory_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    memory_id INTEGER,
                    table_name TEXT NOT NULL DEFAULT 'semantic',
                    action TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT,
                    source TEXT DEFAULT 'unknown',
                    owner_key_hash TEXT,
                    created_at REAL NOT NULL
                )
            """)
            try:
                audit_cols = {row[1] for row in conn.execute("PRAGMA table_info(memory_audit_log)")}
                if "owner_key_hash" not in audit_cols:
                    conn.execute("ALTER TABLE memory_audit_log ADD COLUMN owner_key_hash TEXT")
            except Exception:
                logger.warning("Failed to migrate memory_audit_log owner column", exc_info=True)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_memory
                ON memory_audit_log(memory_id, table_name)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_created
                ON memory_audit_log(created_at DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_owner_created
                ON memory_audit_log(owner_key_hash, created_at DESC)
            """)

            # Proposed memory changes: a staging queue for auto-extracted facts
            # awaiting (or bypassing) user confirmation.  Sensitive blocks
            # (identity/family/body) and low-confidence items stay 'pending';
            # everything else is applied immediately and recorded 'auto_applied'.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS proposed_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_key_hash TEXT,
                    action TEXT NOT NULL DEFAULT 'create',
                    target_memory_id INTEGER,
                    key TEXT,
                    value TEXT,
                    category TEXT DEFAULT 'fact',
                    memory_path TEXT DEFAULT '',
                    entity_type TEXT DEFAULT '',
                    entity_name TEXT DEFAULT '',
                    relation_type TEXT DEFAULT '',
                    confidence REAL DEFAULT 0.5,
                    source TEXT DEFAULT 'agent',
                    session_id TEXT DEFAULT '',
                    evidence TEXT DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at REAL NOT NULL,
                    decided_at REAL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_proposals_owner_status
                ON proposed_changes(owner_key_hash, status)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_proposals_created
                ON proposed_changes(created_at DESC)
            """)

            conn.commit()

    # ------------------------------------------------------------------
    # Audit Log
    # ------------------------------------------------------------------

    def _audit_log(
        self,
        memory_id: int | None,
        table_name: str,
        action: str,
        old_value: str | None = None,
        new_value: str | None = None,
        source: str = "unknown",
        owner_key_hash: str | None = None,
    ) -> None:
        """Write an audit log entry for a memory change."""
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO memory_audit_log
                    (memory_id, table_name, action, old_value, new_value, source, owner_key_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    memory_id,
                    table_name,
                    action,
                    old_value,
                    new_value,
                    source,
                    owner_key_hash,
                    time.time(),
                ),
            )
            # Prune per owner to prevent one busy owner from evicting another's
            # audit trail while still bounding local storage.
            conn.execute(
                """
                DELETE FROM memory_audit_log
                WHERE (
                    (owner_key_hash = ?)
                    OR (? IS NULL AND owner_key_hash IS NULL)
                )
                AND id NOT IN (
                    SELECT id FROM memory_audit_log
                    WHERE (
                        (owner_key_hash = ?)
                        OR (? IS NULL AND owner_key_hash IS NULL)
                    )
                    ORDER BY created_at DESC
                    LIMIT 5000
                )
                """,
                (owner_key_hash, owner_key_hash, owner_key_hash, owner_key_hash),
            )
            conn.commit()

    def get_audit_log(
        self,
        memory_id: int | None = None,
        table_name: str = "semantic",
        limit: int = 50,
        owner_key_hash: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve audit log entries scoped to one owner partition."""
        owner_clause, owner_params = self._owner_filter(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if memory_id is not None:
                rows = conn.execute(
                    f"""
                    SELECT * FROM memory_audit_log
                    WHERE memory_id = ? AND table_name = ? AND {owner_clause}
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (memory_id, table_name, *owner_params, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    f"""
                    SELECT * FROM memory_audit_log
                    WHERE table_name = ? AND {owner_clause}
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (table_name, *owner_params, limit),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_conflicting_memories(
        self, limit: int = 50, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """Retrieve all memories marked as conflicting (owner-scoped)."""
        owner_clause, owner_params = self._owner_filter(owner_key_hash)
        extra = f" AND {owner_clause}" if owner_clause else ""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"""
                SELECT * FROM semantic_memories
                WHERE conflict_status = 'conflicting'{extra}
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (*owner_params, limit),
            ).fetchall()
        return [dict(r) for r in rows]

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
        owner_key_hash: str | None = None,
    ) -> None:
        _reject_ambient_memory_under_enforce()
        # Sanitize secrets before persisting
        value = self._secrets.detect_and_redact(value, f"working:{session_id}:{key}")
        import time as _time

        _start = _time.perf_counter()
        now = _time.time()
        owner = self._session_owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO working_memories (
                    session_id, key, value, category, importance,
                    created_at, access_count, last_accessed, owner_key_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
                ON CONFLICT(owner_key_hash, session_id, key) DO UPDATE SET
                    value=excluded.value,
                    category=excluded.category,
                    importance=excluded.importance,
                    last_accessed=excluded.last_accessed
                """,
                (session_id, key, value, category, importance, now, now, owner),
            )
            conn.commit()
        try:
            from js.utils.metrics import get_metrics

            get_metrics().memory_store_latency_seconds.labels(operation="store_working").observe(
                _time.perf_counter() - _start
            )
        except Exception:
            logger.warning("Operation failed", exc_info=True)

    def get_working(
        self, session_id: str, limit: int = 50, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        owner = self._session_owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM working_memories
                WHERE owner_key_hash = ? AND session_id = ?
                ORDER BY importance DESC, last_accessed DESC
                LIMIT ?
                """,
                (owner, session_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_all_working(
        self, limit: int = 50, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """Get recent working memories across all sessions (owner-scoped)."""
        owner = self._session_owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM working_memories
                WHERE owner_key_hash = ?
                ORDER BY last_accessed DESC
                LIMIT ?
                """,
                (owner, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_all_semantic(
        self, limit: int = 50, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """Get all semantic memories ordered by recency (owner-scoped)."""
        owner_clause, owner_params = self._owner_filter(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"""
                SELECT * FROM semantic_memories
                {("WHERE " + owner_clause) if owner_clause else ""}
                ORDER BY last_accessed DESC
                LIMIT ?
                """,
                (*owner_params, limit),
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
        owner_key_hash: str | None = None,
    ) -> None:
        _reject_ambient_memory_under_enforce()
        # Sanitize secrets from summary before persisting
        summary = self._secrets.detect_and_redact(summary, f"episode:{session_id}")
        import time as _time

        _start = _time.perf_counter()
        owner = self._session_owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO episodes (
                    session_id, summary, topics, tokens_used, turn_count, created_at, importance, owner_key_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id, owner_key_hash) DO UPDATE SET
                    summary=excluded.summary,
                    topics=excluded.topics,
                    tokens_used=excluded.tokens_used,
                    turn_count=excluded.turn_count,
                    importance=excluded.importance,
                    owner_key_hash=excluded.owner_key_hash
                """,
                (
                    session_id,
                    summary,
                    json.dumps(topics),
                    tokens_used,
                    turn_count,
                    _time.time(),
                    importance,
                    owner,
                ),
            )
            conn.commit()
        try:
            from js.utils.metrics import get_metrics

            get_metrics().memory_store_latency_seconds.labels(operation="store_episode").observe(
                _time.perf_counter() - _start
            )
        except Exception:
            logger.warning("Operation failed", exc_info=True)

    def get_episodes(self, limit: int = 20, owner_key_hash: str | None = None) -> list[Episode]:
        owner = self._session_owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM episodes
                WHERE owner_key_hash = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (owner, limit),
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

    # ------------------------------------------------------------------
    # Session Capsules (lightweight context summary for long sessions)
    # ------------------------------------------------------------------

    def store_capsule(
        self,
        session_id: str,
        capsule_text: str,
        owner_key_hash: str | None = None,
        *,
        version: int = 1,
        source_range: str | None = None,
        generated_by_model: str | None = None,
        recent_turns_kept: int | None = None,
        estimated_tokens_saved: int | None = None,
        refresh_reason: str | None = None,
        run_quality_check: bool = True,
    ) -> dict[str, Any]:
        """Store or update a short context capsule for a session.

        Returns the stored capsule metadata dict.  If *run_quality_check* is True
        (default) the capsule is evaluated against the built-in quality rubric
        before storage; low-quality capsules are still stored but flagged with
        a warning in the returned metadata.
        """
        _reject_ambient_memory_under_enforce()
        import time as _time

        # 0. Owner partitioning: each owner gets its own capsule row for the
        #    same session_id.  No-auth / local / legacy requests map to the
        #    fixed sentinel so authenticated owners can never read or overwrite
        #    legacy/shared data.
        owner = self._session_owner(owner_key_hash)

        # 1. Secrets redaction (always)
        redacted = self._secrets.detect_and_redact(capsule_text, f"capsule:{session_id}")
        secrets_redacted = 1 if redacted != capsule_text else 0

        # 2. Quality assessment (optional but default)
        quality_score: dict[str, Any] | None = None
        if run_quality_check:
            try:
                from js.memory.capsule_quality import CapsuleQuality

                qa = CapsuleQuality()
                quality_score = qa.evaluate(redacted).to_dict()
            except Exception:
                # Quality module may be missing in minimal installs — degrade gracefully
                quality_score = None

        now = _time.time()
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO session_capsules (
                    session_id, capsule_text, owner_key_hash, updated_at,
                    version, source_range, generated_by_model, recent_turns_kept,
                    estimated_tokens_saved, refresh_reason, secrets_redacted
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id, owner_key_hash) DO UPDATE SET
                    capsule_text=excluded.capsule_text,
                    updated_at=excluded.updated_at,
                    version=excluded.version,
                    source_range=excluded.source_range,
                    generated_by_model=excluded.generated_by_model,
                    recent_turns_kept=excluded.recent_turns_kept,
                    estimated_tokens_saved=excluded.estimated_tokens_saved,
                    refresh_reason=excluded.refresh_reason,
                    secrets_redacted=excluded.secrets_redacted
                """,
                (
                    session_id,
                    redacted,
                    owner,
                    now,
                    version,
                    source_range,
                    generated_by_model,
                    recent_turns_kept,
                    estimated_tokens_saved,
                    refresh_reason,
                    secrets_redacted,
                ),
            )
            conn.commit()
        result: dict[str, Any] = {
            "session_id": session_id,
            "capsule_text": redacted,
            "owner_key_hash": owner,
            "updated_at": now,
            "version": version,
            "source_range": source_range,
            "generated_by_model": generated_by_model,
            "recent_turns_kept": recent_turns_kept,
            "estimated_tokens_saved": estimated_tokens_saved,
            "refresh_reason": refresh_reason,
            "secrets_redacted": secrets_redacted,
        }
        if quality_score is not None:
            result["quality_score"] = quality_score
            if not quality_score.get("passed", True):
                result["quality_warning"] = (
                    "Capsule quality check failed — summary may be missing key context. "
                    "Consider refreshing with a longer prompt or more recent turns."
                )
        return result

    def get_capsule(
        self,
        session_id: str,
        owner_key_hash: str | None = None,
    ) -> dict[str, Any] | None:
        """Retrieve a session capsule if it exists and belongs to the owner."""
        owner = self._session_owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT session_id, capsule_text, owner_key_hash, updated_at,
                       version, source_range, generated_by_model, recent_turns_kept,
                       estimated_tokens_saved, refresh_reason, secrets_redacted
                FROM session_capsules
                WHERE session_id = ? AND owner_key_hash = ?
                """,
                (session_id, owner),
            ).fetchone()
        if row is None:
            return None
        return {
            "session_id": row["session_id"],
            "capsule_text": row["capsule_text"],
            "owner_key_hash": row["owner_key_hash"],
            "updated_at": row["updated_at"],
            "version": row["version"],
            "source_range": row["source_range"],
            "generated_by_model": row["generated_by_model"],
            "recent_turns_kept": row["recent_turns_kept"],
            "estimated_tokens_saved": row["estimated_tokens_saved"],
            "refresh_reason": row["refresh_reason"],
            "secrets_redacted": row["secrets_redacted"],
        }

    def delete_capsule(
        self,
        session_id: str,
        owner_key_hash: str | None = None,
    ) -> bool:
        """Delete a session capsule. Returns True if a row was removed."""
        owner = self._session_owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            cursor = conn.execute(
                """
                DELETE FROM session_capsules
                WHERE session_id = ? AND owner_key_hash = ?
                """,
                (session_id, owner),
            )
            conn.commit()
            return cursor.rowcount > 0

    def list_sessions(
        self, limit: int = 30, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """List recent conversation sessions that have at least one message."""
        owner = self._session_owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT e.session_id, e.summary, e.created_at, e.turn_count,
                       (
                           SELECT COUNT(*)
                           FROM session_messages m
                           WHERE m.session_id = e.session_id
                             AND m.owner_key_hash = e.owner_key_hash
                       ) as message_count
                FROM episodes e
                WHERE EXISTS (
                    SELECT 1 FROM session_messages m
                    WHERE m.session_id = e.session_id
                      AND m.owner_key_hash = e.owner_key_hash
                )
                  AND e.owner_key_hash = ?
                ORDER BY e.created_at DESC
                LIMIT ?
                """,
                (owner, limit),
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

    def cleanup_empty_sessions(self, *, owner_key_hash: str | None = None) -> int:
        """Remove episode records for sessions that have no messages.

        Owner-scoped: only the partition for a given (session_id, owner) is
        removed when that owner has no messages left.  When ``owner_key_hash``
        is provided, only that owner's empty sessions are cleaned up.
        """
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if owner_key_hash is not None:
                rows = conn.execute(
                    "SELECT DISTINCT session_id, owner_key_hash FROM episodes WHERE owner_key_hash = ?",
                    (owner_key_hash,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT DISTINCT session_id, owner_key_hash FROM episodes"
                ).fetchall()
            deleted = 0
            for row in rows:
                sid = row["session_id"]
                owner = row["owner_key_hash"]
                msg = conn.execute(
                    "SELECT 1 FROM session_messages WHERE session_id = ? AND owner_key_hash = ? LIMIT 1",
                    (sid, owner),
                ).fetchone()
                if msg is None:
                    conn.execute(
                        "DELETE FROM episodes WHERE session_id = ? AND owner_key_hash = ?",
                        (sid, owner),
                    )
                    conn.execute(
                        "DELETE FROM working_memories WHERE session_id = ? AND owner_key_hash = ?",
                        (sid, owner),
                    )
                    conn.execute(
                        "DELETE FROM session_capsules WHERE session_id = ? AND owner_key_hash = ?",
                        (sid, owner),
                    )
                    deleted += 1
            conn.commit()
        logger.info(f"Cleaned up {deleted} empty sessions")
        return deleted

    def maintain_session_bounds(
        self,
        max_sessions_per_owner: int = _DEFAULT_MAX_SESSIONS_PER_OWNER,
        max_sessions_global: int = _DEFAULT_MAX_SESSIONS_GLOBAL,
        protected_sessions: set[tuple[str | None, str]] | None = None,
    ) -> int:
        """Delete oldest complete sessions until owner and global limits are met.

        A session is the owner-isolated ``(owner_key_hash, session_id)`` pair
        present in any session-scoped table. Its last activity is the newest
        timestamp found across messages, episodes, working memories, and the
        session capsule. Per-owner limits are applied before the global hard
        limit. Protected pairs count toward both limits but are never deleted.

        All four tables are pruned in one write transaction. Any failure rolls
        back the complete maintenance batch. The return value is the number of
        owner/session pairs deleted, not the number of rows removed.
        """
        if max_sessions_per_owner < 0:
            raise ValueError("max_sessions_per_owner must be non-negative")
        if max_sessions_global < 0:
            raise ValueError("max_sessions_global must be non-negative")

        protected = {
            (self._session_owner(owner_key_hash), session_id)
            for owner_key_hash, session_id in protected_sessions or set()
        }

        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("BEGIN IMMEDIATE")
                rows = conn.execute(
                    """
                    WITH activity_rows AS (
                        SELECT owner_key_hash, session_id,
                               MAX(created_at) AS last_activity
                        FROM session_messages
                        GROUP BY owner_key_hash, session_id
                        UNION ALL
                        SELECT owner_key_hash, session_id,
                               MAX(created_at) AS last_activity
                        FROM episodes
                        GROUP BY owner_key_hash, session_id
                        UNION ALL
                        SELECT owner_key_hash, session_id,
                               MAX(
                                   CASE
                                       WHEN last_accessed > created_at THEN last_accessed
                                       ELSE created_at
                                   END
                               ) AS last_activity
                        FROM working_memories
                        GROUP BY owner_key_hash, session_id
                        UNION ALL
                        SELECT owner_key_hash, session_id,
                               MAX(
                                   CASE
                                       WHEN COALESCE(last_accessed, 0) > updated_at
                                           THEN last_accessed
                                       ELSE updated_at
                                   END
                               ) AS last_activity
                        FROM session_capsules
                        GROUP BY owner_key_hash, session_id
                    )
                    SELECT owner_key_hash, session_id,
                           MAX(last_activity) AS last_activity
                    FROM activity_rows
                    GROUP BY owner_key_hash, session_id
                    ORDER BY last_activity ASC, owner_key_hash ASC, session_id ASC
                    """
                ).fetchall()

                sessions = [
                    (
                        str(row["owner_key_hash"]),
                        str(row["session_id"]),
                        float(row["last_activity"]),
                    )
                    for row in rows
                ]
                sessions_by_owner: dict[str, list[tuple[str, str, float]]] = {}
                for session in sessions:
                    sessions_by_owner.setdefault(session[0], []).append(session)

                delete_keys: set[tuple[str, str]] = set()
                for owner_sessions in sessions_by_owner.values():
                    excess = max(0, len(owner_sessions) - max_sessions_per_owner)
                    for owner, session_id, _last_activity in owner_sessions:
                        key = (owner, session_id)
                        if excess == 0:
                            break
                        if key in protected:
                            continue
                        delete_keys.add(key)
                        excess -= 1

                remaining = [
                    session for session in sessions if (session[0], session[1]) not in delete_keys
                ]
                global_excess = max(0, len(remaining) - max_sessions_global)
                for owner, session_id, _last_activity in remaining:
                    key = (owner, session_id)
                    if global_excess == 0:
                        break
                    if key in protected:
                        continue
                    delete_keys.add(key)
                    global_excess -= 1

                delete_order = [
                    (owner, session_id)
                    for owner, session_id, _last_activity in sessions
                    if (owner, session_id) in delete_keys
                ]
                if delete_order:
                    conn.execute(
                        """
                        CREATE TEMP TABLE session_prune_candidates (
                            owner_key_hash TEXT NOT NULL,
                            session_id TEXT NOT NULL,
                            PRIMARY KEY (owner_key_hash, session_id)
                        ) WITHOUT ROWID
                        """
                    )
                    conn.executemany(
                        """
                        INSERT INTO session_prune_candidates (owner_key_hash, session_id)
                        VALUES (?, ?)
                        """,
                        delete_order,
                    )
                    conn.execute(
                        """
                        DELETE FROM session_messages
                        WHERE EXISTS (
                            SELECT 1
                            FROM session_prune_candidates candidates
                            WHERE candidates.owner_key_hash = session_messages.owner_key_hash
                              AND candidates.session_id = session_messages.session_id
                        )
                        """
                    )
                    conn.execute(
                        """
                        DELETE FROM episodes
                        WHERE EXISTS (
                            SELECT 1
                            FROM session_prune_candidates candidates
                            WHERE candidates.owner_key_hash = episodes.owner_key_hash
                              AND candidates.session_id = episodes.session_id
                        )
                        """
                    )
                    conn.execute(
                        """
                        DELETE FROM working_memories
                        WHERE EXISTS (
                            SELECT 1
                            FROM session_prune_candidates candidates
                            WHERE candidates.owner_key_hash = working_memories.owner_key_hash
                              AND candidates.session_id = working_memories.session_id
                        )
                        """
                    )
                    conn.execute(
                        """
                        DELETE FROM session_capsules
                        WHERE EXISTS (
                            SELECT 1
                            FROM session_prune_candidates candidates
                            WHERE candidates.owner_key_hash = session_capsules.owner_key_hash
                              AND candidates.session_id = session_capsules.session_id
                        )
                        """
                    )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

        remaining_count = len(sessions) - len(delete_order)
        if remaining_count > max_sessions_global:
            logger.warning(
                "Protected memory sessions prevented the global limit: %d remain (limit %d)",
                remaining_count,
                max_sessions_global,
            )
        if delete_order:
            logger.info("Pruned %d complete memory sessions", len(delete_order))
        self.maintain_long_term_bounds()
        return len(delete_order)

    def maintain_long_term_bounds(
        self,
        dream_log_retention_days: float = _DEFAULT_DREAM_LOG_RETENTION_DAYS,
        max_dream_logs: int = _DEFAULT_MAX_DREAM_LOGS,
        proposal_retention_days: float = _DEFAULT_PROPOSAL_RETENTION_DAYS,
        max_proposals_per_owner: int = _DEFAULT_MAX_PROPOSALS_PER_OWNER,
        max_proposals_global: int = _DEFAULT_MAX_PROPOSALS_GLOBAL,
        max_dream_logs_global: int = _DEFAULT_MAX_DREAM_LOGS_GLOBAL,
    ) -> int:
        """Prune long-term records without deleting unresolved proposals.

        Dream logs are bounded per owner and globally. Proposal retention is
        owner-aware: age and hard-cap deletes are limited to terminal statuses,
        leaving pending or otherwise unresolved proposals available for review.
        All changes use one write transaction and the return value is the number
        of rows deleted.
        """
        limits = (
            ("dream_log_retention_days", dream_log_retention_days),
            ("max_dream_logs", max_dream_logs),
            ("proposal_retention_days", proposal_retention_days),
            ("max_proposals_per_owner", max_proposals_per_owner),
            ("max_proposals_global", max_proposals_global),
            ("max_dream_logs_global", max_dream_logs_global),
        )
        for name, value in limits:
            if value < 0:
                raise ValueError(f"{name} must be non-negative")

        now = time.time()
        dream_cutoff = now - dream_log_retention_days * 86_400
        proposal_cutoff = now - proposal_retention_days * 86_400
        terminal_statuses = tuple(sorted(_TERMINAL_PROPOSAL_STATUSES))
        status_placeholders = ", ".join("?" for _ in terminal_statuses)
        global_excess = 0

        with db_connection(self.db_path) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                deleted = conn.execute(
                    "DELETE FROM dream_logs WHERE created_at < ?", (dream_cutoff,)
                ).rowcount
                dream_log_ids = conn.execute(
                    """
                    SELECT id
                    FROM (
                        SELECT
                            id,
                            ROW_NUMBER() OVER (
                                PARTITION BY owner_key_hash
                                ORDER BY created_at DESC, id DESC
                            ) AS owner_rank
                        FROM dream_logs
                    )
                    WHERE owner_rank > ?
                    """,
                    (max_dream_logs,),
                ).fetchall()
                if dream_log_ids:
                    conn.executemany(
                        "DELETE FROM dream_logs WHERE id = ?",
                        ((row[0],) for row in dream_log_ids),
                    )
                    deleted += len(dream_log_ids)
                global_dream_log_ids = conn.execute(
                    """
                    SELECT id
                    FROM dream_logs
                    ORDER BY created_at DESC, id DESC
                    LIMIT -1 OFFSET ?
                    """,
                    (max_dream_logs_global,),
                ).fetchall()
                if global_dream_log_ids:
                    conn.executemany(
                        "DELETE FROM dream_logs WHERE id = ?",
                        ((row[0],) for row in global_dream_log_ids),
                    )
                    deleted += len(global_dream_log_ids)
                deleted += conn.execute(
                    f"""
                    DELETE FROM proposed_changes
                    WHERE status IN ({status_placeholders})
                      AND created_at < ?
                    """,
                    (*terminal_statuses, proposal_cutoff),
                ).rowcount

                owner_counts = conn.execute(
                    """
                    SELECT owner_key_hash, COUNT(*) AS proposal_count
                    FROM proposed_changes
                    GROUP BY owner_key_hash
                    """
                ).fetchall()
                terminal_rows = conn.execute(
                    f"""
                    SELECT id, owner_key_hash
                    FROM proposed_changes
                    WHERE status IN ({status_placeholders})
                    ORDER BY owner_key_hash ASC, created_at ASC, id ASC
                    """,
                    terminal_statuses,
                ).fetchall()

                terminal_by_owner: dict[str | None, list[int]] = {}
                for proposal_id, owner_key_hash in terminal_rows:
                    terminal_by_owner.setdefault(owner_key_hash, []).append(proposal_id)

                cap_candidate_ids: set[int] = set()
                for owner_key_hash, proposal_count in owner_counts:
                    owner_excess = max(0, proposal_count - max_proposals_per_owner)
                    cap_candidate_ids.update(
                        terminal_by_owner.get(owner_key_hash, [])[:owner_excess]
                    )

                remaining_count = sum(proposal_count for _, proposal_count in owner_counts)
                remaining_count -= len(cap_candidate_ids)
                global_excess = max(0, remaining_count - max_proposals_global)
                if global_excess:
                    global_candidates = conn.execute(
                        f"""
                        SELECT id
                        FROM proposed_changes
                        WHERE status IN ({status_placeholders})
                        ORDER BY created_at ASC, id ASC
                        """,
                        terminal_statuses,
                    ).fetchall()
                    for (proposal_id,) in global_candidates:
                        if proposal_id in cap_candidate_ids:
                            continue
                        cap_candidate_ids.add(proposal_id)
                        global_excess -= 1
                        if global_excess == 0:
                            break

                if cap_candidate_ids:
                    conn.execute(
                        """
                        CREATE TEMP TABLE proposal_prune_candidates (
                            id INTEGER PRIMARY KEY
                        ) WITHOUT ROWID
                        """
                    )
                    conn.executemany(
                        "INSERT INTO proposal_prune_candidates (id) VALUES (?)",
                        ((proposal_id,) for proposal_id in cap_candidate_ids),
                    )
                    deleted += conn.execute(
                        """
                        DELETE FROM proposed_changes
                        WHERE id IN (SELECT id FROM proposal_prune_candidates)
                        """
                    ).rowcount

                conn.commit()
            except Exception:
                conn.rollback()
                raise

        if global_excess:
            logger.warning(
                "Unresolved memory proposals prevented the global limit: %d excess remain",
                global_excess,
            )
        if deleted:
            logger.info("Pruned %d long-term memory maintenance rows", deleted)
        return deleted

    # ------------------------------------------------------------------
    # Session Messages (conversation history)
    # ------------------------------------------------------------------

    def store_messages(
        self, session_id: str, messages: list[dict[str, str]], owner_key_hash: str | None = None
    ) -> None:
        """Batch store messages for a session.  Content is encrypted at rest.

        v3: stores owner_key_hash at the message level for per-owner isolation.
            No-auth / local / legacy requests map to the __legacy_local__ sentinel.
        """
        if not messages:
            return
        _reject_ambient_memory_under_enforce()
        import time as _time

        _start = _time.perf_counter()
        now = _time.time()
        _enc = self._secrets.encrypt_blob
        owner = self._session_owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.executemany(
                """
                INSERT INTO session_messages (session_id, role, content, created_at, owner_key_hash)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (session_id, m["role"], _enc(m["content"].encode("utf-8")), now, owner)
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
            logger.warning("Operation failed", exc_info=True)

        # Prune old messages per owner/session to prevent unbounded DB growth.
        _max_msg_per_session = 500
        with db_connection(self.db_path) as conn:
            count_row = conn.execute(
                "SELECT COUNT(*) FROM session_messages WHERE session_id = ? AND owner_key_hash = ?",
                (session_id, owner),
            ).fetchone()
            if count_row and count_row[0] > _max_msg_per_session:
                excess = count_row[0] - _max_msg_per_session
                conn.execute(
                    "DELETE FROM session_messages WHERE id IN "
                    "(SELECT id FROM session_messages WHERE session_id = ? AND owner_key_hash = ? "
                    "ORDER BY created_at ASC LIMIT ?)",
                    (session_id, owner, excess),
                )
                conn.commit()

    def get_session_messages(
        self, session_id: str, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """Get all messages for a session, ordered by time.

        Owner isolation is strict: only rows matching the requested owner are
        returned.  There is no fallback to legacy/shared rows and the owner is
        never inferred from message content.
        """
        owner = self._session_owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT role, content, created_at
                FROM session_messages
                WHERE session_id = ? AND owner_key_hash = ?
                ORDER BY created_at ASC
                """,
                (session_id, owner),
            ).fetchall()
        _dec = self._secrets.decrypt_blob
        return [
            {
                "role": r["role"],
                "content": _dec(r["content"]).decode("utf-8", errors="replace")
                if isinstance(r["content"], bytes)
                else r["content"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def delete_session(self, session_id: str, owner_key_hash: str | None = None) -> bool:
        """Delete all session-scoped data for the current owner.

        Only rows belonging to ``owner_key_hash`` are removed:
        messages, working memory, episode, capsule.  Semantic memories with
        ``source = session_id`` are also removed for the same owner.

        Returns ``True`` if any row was deleted, ``False`` for a no-op/wrong owner.
        """
        owner = self._session_owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            total = 0
            cur = conn.execute(
                "DELETE FROM session_messages WHERE session_id = ? AND owner_key_hash = ?",
                (session_id, owner),
            )
            total += cur.rowcount
            cur = conn.execute(
                "DELETE FROM working_memories WHERE session_id = ? AND owner_key_hash = ?",
                (session_id, owner),
            )
            total += cur.rowcount
            cur = conn.execute(
                "DELETE FROM episodes WHERE session_id = ? AND owner_key_hash = ?",
                (session_id, owner),
            )
            total += cur.rowcount
            cur = conn.execute(
                "DELETE FROM session_capsules WHERE session_id = ? AND owner_key_hash = ?",
                (session_id, owner),
            )
            total += cur.rowcount
            cur = conn.execute(
                "DELETE FROM semantic_memories WHERE source = ? AND owner_key_hash = ?",
                (session_id, owner),
            )
            total += cur.rowcount
            conn.commit()
        return total > 0

    # ------------------------------------------------------------------
    # Semantic Memory (extracted knowledge)
    # ------------------------------------------------------------------

    def store_semantic(
        self,
        key: str,
        value: str,
        category: str = "fact",
        confidence: float | None = None,
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
        """Store a semantic memory, with auto-block classification,
        conflict detection, audit, and eviction.

        ``owner_key_hash`` scopes the memory to a user (NULL == shared/legacy);
        the same ``key`` may exist for different owners.  ``session_id`` and
        ``evidence`` record provenance for auto-extracted facts.
        """
        _reject_ambient_memory_under_enforce()
        # Sanitize secrets before persisting semantic memory
        value = self._secrets.detect_and_redact(value, f"semantic:{key}")
        import time

        _start = time.perf_counter()
        now = time.time()

        # Default confidence based on source
        if confidence is None:
            confidence_map = {
                "user": 1.0,
                "agent": 0.7,
                "dream": 0.5,
                "import": 0.8,
                "manual": 0.9,
            }
            confidence = confidence_map.get(source, 0.7)

        # Auto-infer hierarchical block (zero user intervention)
        inferred_path, inferred_type, inferred_name, inferred_rel = self._infer_entity_block(
            key=key,
            value=value,
            category=category,
            memory_path=memory_path,
            entity_type=entity_type,
            entity_name=entity_name,
            relation_type=relation_type,
        )

        # User-provided memories are considered verified at creation time
        last_verified = now if source == "user" else 0.0

        try:
            embedding = self.embedder.embed(f"{key} {value}")
            embedding_json = self.embedder.to_json(embedding)
        except Exception:
            logger.warning(
                "Primary embedding failed for semantic store, trying fallback",
                exc_info=True,
            )
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
            logger.warning("Operation failed", exc_info=True)

        # Detect and auto-resolve conflicts — user should never be bothered.
        # Conflict detection is scoped to the same owner partition so one user's
        # memory never collides with (or deletes) another's.
        conflicts = self._detect_conflict(key, value, category, owner_key_hash=owner_key_hash)
        if conflicts:
            # Try to resolve automatically; keep new memory only if it wins.
            keep_new = self._auto_resolve_conflicts(
                key=key,
                value=value,
                category=category,
                confidence=confidence,
                source=source,
                conflict_ids=conflicts,
                owner_key_hash=owner_key_hash,
            )
            if not keep_new:
                # Existing user-confirmed memory wins; drop this one silently.
                return {"conflicts": conflicts, "evicted": [], "memory_id": None, "dropped": True}

        with db_connection(self.db_path) as conn:
            # Upsert scoped to (key, owner): the same key may exist for other
            # owners, so we match on both rather than relying on a global
            # ON CONFLICT(key) (which no longer exists).
            existing = conn.execute(
                "SELECT id, value FROM semantic_memories "
                "WHERE key = ? AND COALESCE(owner_key_hash, '') = COALESCE(?, '')",
                (key, owner_key_hash),
            ).fetchone()

            if existing:
                conn.execute(
                    """
                    UPDATE semantic_memories SET
                        value = ?, category = ?, confidence = ?, source = ?,
                        last_accessed = ?, embedding = ?, conflict_status = '',
                        memory_path = ?, entity_type = ?, entity_name = ?,
                        parent_id = ?, relation_type = ?, last_verified_at = ?,
                        session_id = ?, evidence = ?
                    WHERE id = ?
                    """,
                    (
                        value,
                        category,
                        confidence,
                        source,
                        now,
                        embedding_json,
                        inferred_path,
                        inferred_type,
                        inferred_name,
                        parent_id,
                        inferred_rel,
                        last_verified,
                        session_id,
                        evidence,
                        existing[0],
                    ),
                )
                memory_id = existing[0]
            else:
                cur = conn.execute(
                    """
                    INSERT INTO semantic_memories (
                        key, value, category, confidence, source, created_at,
                        last_accessed, access_count, embedding, conflict_status,
                        importance, memory_path, entity_type, entity_name,
                        parent_id, relation_type, last_verified_at,
                        owner_key_hash, session_id, evidence
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, '', 5, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key,
                        value,
                        category,
                        confidence,
                        source,
                        now,
                        now,
                        embedding_json,
                        inferred_path,
                        inferred_type,
                        inferred_name,
                        parent_id,
                        inferred_rel,
                        last_verified,
                        owner_key_hash,
                        session_id,
                        evidence,
                    ),
                )
                memory_id = cur.lastrowid
            conn.commit()

        # Audit log
        if existing:
            self._audit_log(
                memory_id=memory_id,
                table_name="semantic",
                action="update",
                old_value=existing[1],
                new_value=value,
                source=source or "agent",
                owner_key_hash=owner_key_hash,
            )
        else:
            self._audit_log(
                memory_id=memory_id,
                table_name="semantic",
                action="create",
                new_value=value,
                source=source or "agent",
                owner_key_hash=owner_key_hash,
            )

        # Run eviction after insert (scoped to this owner's partition)
        evicted = self._evict_semantic_if_needed(owner_key_hash=owner_key_hash)

        layered_meta: dict[str, Any] | None = None
        if getattr(self.config, "layered_memory_dual_write", False) and memory_id is not None:
            layered_meta = self._layered_store().dual_write_semantic(
                owner_key_hash=owner_key_hash,
                key=key,
                value=value,
                category=category,
                confidence=float(confidence or 0.5),
                entity_type=inferred_type,
                entity_name=inferred_name,
                source_semantic_id=int(memory_id) if memory_id is not None else None,
                evidence=evidence,
                source=source or "agent",
            )

        return {
            "conflicts": conflicts,
            "evicted": evicted,
            "memory_id": memory_id,
            "memory_path": inferred_path,
            "entity_type": inferred_type,
            "layered": layered_meta,
        }

    def feedback(
        self,
        memory_id: int,
        helpful: bool,
        owner_key_hash: str | None = None,
    ) -> bool:
        """Record user feedback on a semantic memory's usefulness.

        Positive feedback increases the memory's weight, negative feedback
        decreases it.  Affects eviction priority.

        ``owner_key_hash`` follows the same convention as ``update_semantic``
        and ``delete_semantic``: a concrete hash only touches that owner's
        rows; ``None`` only touches shared/legacy NULL-owner rows.  Without
        this guard a second user could mutate another user's feedback by
        guessing the integer primary key.
        """
        delta = 1.0 if helpful else -1.0
        owner_clause, owner_params = self._owner_filter(owner_key_hash)
        guard = f" AND {owner_clause}" if owner_clause else ""
        with db_connection(self.db_path) as conn:
            cur = conn.execute(
                f"""
                UPDATE semantic_memories
                SET feedback_score = COALESCE(feedback_score, 0) + ?,
                    access_count = access_count + 1,
                    last_accessed = ?
                WHERE id = ?{guard}
                """,
                (delta, time.time(), memory_id, *owner_params),
            )
            updated = cur.rowcount > 0
            conn.commit()
        return updated

    def _detect_conflict(
        self,
        key: str,
        value: str,
        category: str,
        similarity_threshold: float = 0.7,
        owner_key_hash: str | None = None,
    ) -> list[int]:
        """Detect potentially conflicting memories.

        Uses a two-tier check:
        1. Keyword overlap on keys (fast)
        2. Embedding cosine similarity (semantic) for candidates

        Conflicts are memories with similar keys but different values.
        """
        conflicts: list[int] = []
        key_lower = key.lower()
        value_lower = value.lower()

        # Try to get an embedding for the new memory; fall back to None
        query_vec: Any | None = None
        try:
            query_vec = self.embedder.embed(f"{key} {value}")
        except Exception:
            logger.debug("Embedding unavailable for conflict detection, using keyword fallback")

        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            # Limit to recent 200 entries to avoid full-table scans.
            # Only consider the same owner's memories (exact match).  Legacy/shared
            # NULL-owner rows are never considered conflicts for authenticated
            # owners, and vice versa.
            params: list[Any] = [category]
            owner_clause = ""
            if owner_key_hash is not None:
                owner_clause = " AND owner_key_hash = ?"
                params.append(owner_key_hash)
            else:
                owner_clause = " AND owner_key_hash IS NULL"
            rows = conn.execute(
                f"""
                SELECT id, key, value, embedding FROM semantic_memories
                WHERE category = ?{owner_clause}
                ORDER BY created_at DESC
                LIMIT 200
                """,
                tuple(params),
            ).fetchall()

        for r in rows:
            other_key = r["key"].lower()
            other_value = r["value"].lower()
            if other_key == key_lower and other_value == value_lower:
                continue  # Exact duplicate (same key, same value) is not a conflict
            if other_key == key_lower:
                continue  # Same key with different value is an upsert, not a conflict

            # Tier 1: keyword overlap
            key_words = set(key_lower.split())
            other_words = set(other_key.split())
            keyword_overlap = 0.0
            if key_words and other_words:
                keyword_overlap = len(key_words & other_words) / max(
                    len(key_words), len(other_words)
                )

            # Tier 2: embedding similarity (if available)
            embedding_score = 0.0
            emb_raw = r["embedding"]
            if query_vec is not None and emb_raw:
                try:
                    vec = self.embedder.from_json(emb_raw)
                    embedding_score = cosine_similarity(query_vec, vec)
                except Exception:
                    pass

            # Conflict if either keyword overlap or embedding similarity is high
            if keyword_overlap >= similarity_threshold or embedding_score >= 0.85:
                conflicts.append(r["id"])

        return conflicts

    def _auto_resolve_conflicts(
        self,
        key: str,
        value: str,
        category: str,
        confidence: float,
        source: str,
        conflict_ids: list[int],
        owner_key_hash: str | None = None,
    ) -> bool:
        """Automatically resolve memory conflicts without bothering the user.

        Resolution rules (applied per conflicting memory):
        1. Deduplication: if values are ~identical (≥90% similar), keep the
           higher-confidence one and delete the other.
        2. User input wins: if an existing memory came from the user and the
           new one did not, discard the new memory silently.
        3. High-confidence override: if the new memory is significantly more
           trustworthy (>0.2 gap), overwrite the old one.
        4. Otherwise: keep both — they may be related but distinct facts.

        All deletions are guarded by ``owner_key_hash`` so auto-resolution can
        never delete another owner's memories.

        Returns True if the new memory should be kept (either by winning or
        by coexisting), False if it should be dropped.
        """
        import difflib

        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            placeholders = ",".join("?" * len(conflict_ids))
            owner_filter = ""
            delete_owner_filter = ""
            owner_params: list[Any] = []
            if owner_key_hash is not None:
                owner_filter = " AND owner_key_hash = ?"
                delete_owner_filter = "owner_key_hash = ?"
                owner_params.append(owner_key_hash)
            else:
                owner_filter = " AND owner_key_hash IS NULL"
                delete_owner_filter = "owner_key_hash IS NULL"
            rows = conn.execute(
                f"""
                SELECT id, key, value, confidence, source, created_at
                FROM semantic_memories
                WHERE id IN ({placeholders}){owner_filter}
                """,
                tuple(conflict_ids) + tuple(owner_params),
            ).fetchall()

        for r in rows:
            old_value = r["value"] or ""
            old_conf = r["confidence"] or 0.7
            old_source = r["source"] or ""
            old_id = r["id"]

            # Rule 1: near-duplicate values → dedupe, keep higher confidence
            similarity = difflib.SequenceMatcher(None, value.lower(), old_value.lower()).ratio()
            if similarity >= 0.9:
                if confidence >= old_conf:
                    # New is better (or equal), delete old
                    with db_connection(self.db_path) as conn:
                        conn.execute(
                            f"DELETE FROM semantic_memories WHERE id = ? AND {delete_owner_filter}",
                            (old_id, *owner_params),
                        )
                        conn.commit()
                    self._audit_log(
                        memory_id=old_id,
                        table_name="semantic",
                        action="delete",
                        old_value=old_value,
                        source="auto_resolve",
                        owner_key_hash=owner_key_hash,
                    )
                else:
                    # Old is better, drop new
                    return False
                continue

            # Rule 2: existing user memory is sacred
            if old_source == "user" and source != "user":
                return False

            # Rule 3: new memory is much more trustworthy → overwrite old
            if confidence >= old_conf + 0.2:
                with db_connection(self.db_path) as conn:
                    conn.execute(
                        f"DELETE FROM semantic_memories WHERE id = ? AND {delete_owner_filter}",
                        (old_id, *owner_params),
                    )
                    conn.commit()
                self._audit_log(
                    memory_id=old_id,
                    table_name="semantic",
                    action="delete",
                    old_value=old_value,
                    source="auto_resolve",
                    owner_key_hash=owner_key_hash,
                )
                continue

            # Rule 4: coexist — nothing to do

        return True

    def _evict_semantic_if_needed(
        self,
        strategy: str = "lru",
        max_memories: int = 1000,
        owner_key_hash: str | None = None,
    ) -> int:
        """Evict old or low-value semantic memories if count exceeds limit.

        Strategies:
        - lru: evict least recently accessed (but protect importance >= 8)
        - importance_weighted: score = importance * 2 + access_count + feedback_score*3;
          evict lowest score first

        When ``owner_key_hash`` is given, eviction is confined to that owner's
        own rows (exact match) so one user's writes never evict another user's
        — or the shared/NULL — memories.
        """
        # owner_filter applies an exact-owner predicate; shared (NULL) and other
        # owners are never touched by an owner-scoped eviction.
        owner_filter = ""
        owner_params: list[Any] = []
        if owner_key_hash is not None:
            owner_filter = " owner_key_hash = ? "
            owner_params = [owner_key_hash]

        with db_connection(self.db_path) as conn:
            where_count = f"WHERE{owner_filter}" if owner_filter else ""
            count_row = conn.execute(
                f"SELECT COUNT(*) FROM semantic_memories {where_count}",
                tuple(owner_params),
            ).fetchone()
            total = count_row[0] if count_row else 0

        if total <= max_memories:
            return 0

        to_evict = total - max_memories
        evicted = 0

        with db_connection(self.db_path) as conn:
            if strategy == "lru":
                # Protect high-importance memories
                lru_owner = f" AND{owner_filter}" if owner_filter else ""
                rows = conn.execute(
                    f"""
                    SELECT id FROM semantic_memories
                    WHERE COALESCE(importance, 5) < 8{lru_owner}
                    ORDER BY last_accessed ASC
                    LIMIT ?
                    """,
                    (*owner_params, to_evict),
                ).fetchall()
            elif strategy == "importance_weighted":
                iw_owner = f"WHERE{owner_filter}" if owner_filter else ""
                rows = conn.execute(
                    f"""
                    SELECT id FROM semantic_memories
                    {iw_owner}
                    ORDER BY (
                        COALESCE(importance, 5) * 2
                        + access_count
                        + COALESCE(feedback_score, 0) * 3
                    ) ASC
                    LIMIT ?
                    """,
                    (*owner_params, to_evict),
                ).fetchall()
            else:
                rows = []

            # Defense-in-depth: even though id selection above was already
            # confined to ``owner_filter``, the DELETE re-asserts the owner
            # predicate so a future refactor or a race on the integer PK
            # cannot delete another owner's row.
            delete_owner = f" AND{owner_filter}" if owner_filter else ""
            for row in rows:
                conn.execute(
                    f"DELETE FROM semantic_memories WHERE id = ?{delete_owner}",
                    (row[0], *owner_params),
                )
                evicted += 1
            conn.commit()

        if evicted:
            logger.info(
                f"Evicted {evicted} semantic memories (strategy={strategy}, limit={max_memories})"
            )
        return evicted

    def delete_semantic(
        self, memory_id: int, source: str = "user", owner_key_hash: str | None = None
    ) -> bool:
        owner_clause, owner_params = self._owner_filter(owner_key_hash)
        guard = f" AND {owner_clause}" if owner_clause else ""
        with db_connection(self.db_path) as conn:
            # Get old value for audit (also enforces the owner guard)
            row = conn.execute(
                f"SELECT value FROM semantic_memories WHERE id = ?{guard}",
                (memory_id, *owner_params),
            ).fetchone()
            old_value = row[0] if row else None

            cur = conn.execute(
                f"DELETE FROM semantic_memories WHERE id = ?{guard}",
                (memory_id, *owner_params),
            )
            conn.commit()
            deleted = cur.rowcount > 0

        if deleted:
            self._audit_log(
                memory_id=memory_id,
                table_name="semantic",
                action="delete",
                old_value=old_value,
                source=source,
                owner_key_hash=owner_key_hash,
            )
        return deleted

    def update_semantic(
        self,
        memory_id: int,
        value: str,
        category: str | None = None,
        source: str = "user",
        memory_path: str | None = None,
        entity_type: str | None = None,
        entity_name: str | None = None,
        parent_id: int | None = None,
        relation_type: str | None = None,
        owner_key_hash: str | None = None,
    ) -> bool:
        owner_clause, owner_params = self._owner_filter(owner_key_hash)
        guard = f" AND {owner_clause}" if owner_clause else ""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            # Get old values for audit (also enforces the owner guard)
            row = conn.execute(
                f"SELECT * FROM semantic_memories WHERE id = ?{guard}",
                (memory_id, *owner_params),
            ).fetchone()
            if not row:
                return False
            old_value = row["value"]
            old_category = row["category"]

            # Build dynamic UPDATE
            fields: list[str] = ["value = ?"]
            params: list[Any] = [value]
            if category is not None:
                fields.append("category = ?")
                params.append(category)
            if memory_path is not None:
                fields.append("memory_path = ?")
                params.append(memory_path)
            if entity_type is not None:
                fields.append("entity_type = ?")
                params.append(entity_type)
            if entity_name is not None:
                fields.append("entity_name = ?")
                params.append(entity_name)
            if parent_id is not None:
                fields.append("parent_id = ?")
                params.append(parent_id)
            if relation_type is not None:
                fields.append("relation_type = ?")
                params.append(relation_type)

            params.append(memory_id)
            params.extend(owner_params)
            # Owner guard on the UPDATE itself (not just the pre-check SELECT) so
            # the write can never touch another owner's row even under a race —
            # consistent with delete_semantic. With owner_key_hash=None the guard
            # targets only legacy NULL-owner rows.
            sql = f"UPDATE semantic_memories SET {', '.join(fields)} WHERE id = ?{guard}"
            cur = conn.execute(sql, params)
            conn.commit()
            updated = cur.rowcount > 0

        if updated:
            self._audit_log(
                memory_id=memory_id,
                table_name="semantic",
                action="update",
                old_value=f"value={old_value}, category={old_category}",
                new_value=f"value={value}, category={category or old_category}",
                source=source,
                owner_key_hash=owner_key_hash,
            )
        return updated

    def retrieve_semantic(
        self, key: str, owner_key_hash: str | None = None
    ) -> SemanticMemory | None:
        owner_clause, owner_params = self._owner_filter(owner_key_hash)
        guard = f" AND {owner_clause}" if owner_clause else ""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                f"SELECT * FROM semantic_memories WHERE key = ?{guard} "
                "ORDER BY (owner_key_hash IS NULL) ASC LIMIT 1",
                (key, *owner_params),
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
            memory_path=row["memory_path"] or "",
            entity_type=row["entity_type"] or "",
            entity_name=row["entity_name"] or "",
            parent_id=row["parent_id"],
            relation_type=row["relation_type"] or "",
            last_verified_at=row["last_verified_at"] or 0.0,
            evidence=row["evidence"] or "",
            session_id=row["session_id"] or "",
            owner_key_hash=row["owner_key_hash"],
        )

    def search_semantic(
        self,
        query: str,
        category: str | None = None,
        limit: int = 10,
        path_prefix: str | None = None,
        block_priority: bool = True,
        owner_key_hash: str | None = None,
    ) -> list[SemanticMemory]:
        import time

        _start = time.perf_counter()
        owner_clause, owner_params = self._owner_filter(owner_key_hash)
        fallback_reason = None
        try:
            query_vec = self.embedder.embed(query)
        except Exception:
            logger.warning("Query embedding failed, falling back to text search", exc_info=True)
            query_vec = None
            fallback_reason = "embedding_failed"

        # Infer target entity types from query for block-priority scoring
        target_entity_types: set[str] = set()
        if block_priority and query:
            _path, _etype, _name, _rel = self._infer_entity_block(query, query, "fact")
            if _etype:
                target_entity_types.add(_etype)

        # Phase 1: Fast pre-filter with LIKE to avoid loading all rows
        safe_query = query.replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{safe_query}%"
        candidate_limit = max(limit * 5, 50)

        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            conditions = []
            params: list[Any] = []
            if query:
                conditions.append("(key LIKE ? ESCAPE '\\' OR value LIKE ? ESCAPE '\\')")
                params.extend([pattern, pattern])
            if category:
                conditions.append("category = ?")
                params.append(category)
            if path_prefix:
                conditions.append("memory_path LIKE ?")
                params.append(f"{path_prefix}%")
            if owner_clause:
                conditions.append(owner_clause)
                params.extend(owner_params)

            where_clause = " AND ".join(conditions) if conditions else "1=1"
            sql = f"""
                SELECT * FROM semantic_memories
                WHERE {where_clause}
                LIMIT ?
            """
            params.append(candidate_limit)
            rows = conn.execute(sql, params).fetchall()

        # Phase 2: If no LIKE matches, scan recent entries by embedding
        if not rows and query:
            owner_extra = f" AND {owner_clause}" if owner_clause else ""
            with db_connection(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                if path_prefix:
                    rows = conn.execute(
                        f"""
                        SELECT * FROM semantic_memories
                        WHERE memory_path LIKE ?{owner_extra}
                        ORDER BY last_accessed DESC
                        LIMIT ?
                        """,
                        (f"{path_prefix}%", *owner_params, candidate_limit),
                    ).fetchall()
                else:
                    where_owner = f"WHERE {owner_clause}" if owner_clause else ""
                    rows = conn.execute(
                        f"SELECT * FROM semantic_memories {where_owner} "
                        "ORDER BY last_accessed DESC LIMIT ?",
                        (*owner_params, candidate_limit),
                    ).fetchall()

        # Phase 3: Score candidates by hybrid blend of:
        #   semantic (embedding) OR keyword (text overlap)  [base, 0..1]
        # + entity-block match boost                         [+0.1]
        # + recency decay (config-weighted)                  [+0..recency_weight]
        import math

        _now = time.time()
        recency_weight = float(getattr(self.config, "context_recency_weight", 0.0) or 0.0)
        half_life_days = max(
            float(getattr(self.config, "context_recency_half_life_days", 30.0) or 30.0), 0.1
        )
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

            # Block priority boost: +0.1 if entity_type matches query inference
            if block_priority and target_entity_types:
                mem_etype = (r["entity_type"] or "").lower()
                if mem_etype in target_entity_types:
                    score += 0.1

            # Recency boost: exponential decay on age in days.
            if recency_weight:
                created = r["created_at"] or _now
                age_days = max(0.0, (_now - created) / 86400.0)
                score += recency_weight * math.exp(-age_days / half_life_days)

            scored.append((score, r))

        scored.sort(key=lambda x: x[0], reverse=True)

        # Record metrics on exit
        try:
            from js.utils.metrics import get_metrics

            get_metrics().memory_retrieve_latency_seconds.labels(
                operation="search_semantic"
            ).observe(time.perf_counter() - _start)
            if fallback_reason:
                get_metrics().memory_search_fallback_total.labels(reason=fallback_reason).inc()
            elif query_vec is None:
                get_metrics().memory_search_fallback_total.labels(reason="no_embedding").inc()
        except Exception:
            logger.warning("Operation failed", exc_info=True)

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
                memory_path=r["memory_path"] or "",
                entity_type=r["entity_type"] or "",
                entity_name=r["entity_name"] or "",
                parent_id=r["parent_id"],
                relation_type=r["relation_type"] or "",
                last_verified_at=r["last_verified_at"] or 0.0,
                evidence=r["evidence"] or "",
                session_id=r["session_id"] or "",
                owner_key_hash=r["owner_key_hash"],
            )
            for _score, r in scored[:limit]
        ]

    # ------------------------------------------------------------------
    # Structured block-based memory queries
    # ------------------------------------------------------------------

    def get_blocks(
        self, path_prefix: str | None = None, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """Return hierarchical block statistics (owner-scoped).

        Groups memories by their top-level path segment and returns
        counts and last-accessed times for each block.
        """
        owner_clause, owner_params = self._owner_filter(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if path_prefix:
                # List sub-blocks under a given prefix
                # e.g. prefix="/user" → returns /user/preferences, /user/identity, ...
                extra = f" AND {owner_clause}" if owner_clause else ""
                rows = conn.execute(
                    f"""
                    SELECT
                        memory_path as block_path,
                        COUNT(*) as memory_count,
                        MAX(last_accessed) as last_accessed
                    FROM semantic_memories
                    WHERE memory_path LIKE ? AND memory_path != ?{extra}
                    GROUP BY memory_path
                    ORDER BY memory_count DESC
                    """,
                    (f"{path_prefix}/%", path_prefix, *owner_params),
                ).fetchall()
            else:
                # List top-level blocks
                extra = f" AND {owner_clause}" if owner_clause else ""
                rows = conn.execute(
                    f"""
                    SELECT
                        CASE
                            WHEN instr(substr(memory_path, 2), '/') > 0
                            THEN substr(memory_path, 1, instr(substr(memory_path, 2), '/'))
                            ELSE memory_path
                        END as block_path,
                        COUNT(*) as memory_count,
                        MAX(last_accessed) as last_accessed
                    FROM semantic_memories
                    WHERE memory_path != '' AND memory_path IS NOT NULL{extra}
                    GROUP BY block_path
                    ORDER BY memory_count DESC
                    """,
                    tuple(owner_params),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_by_block(
        self, path_prefix: str, limit: int = 50, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """Return all memories under a given path prefix (owner-scoped)."""
        owner_clause, owner_params = self._owner_filter(owner_key_hash)
        extra = f" AND {owner_clause}" if owner_clause else ""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"""
                SELECT * FROM semantic_memories
                WHERE memory_path LIKE ?{extra}
                ORDER BY last_accessed DESC
                LIMIT ?
                """,
                (f"{path_prefix}%", *owner_params, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def verify_semantic(
        self, memory_id: int, source: str = "user", owner_key_hash: str | None = None
    ) -> bool:
        """Mark a memory as verified (updates last_verified_at and writes audit)."""
        now = time.time()
        owner_clause, owner_params = self._owner_filter(owner_key_hash)
        guard = f" AND {owner_clause}" if owner_clause else ""
        with db_connection(self.db_path) as conn:
            cur = conn.execute(
                f"UPDATE semantic_memories SET last_verified_at = ? WHERE id = ?{guard}",
                (now, memory_id, *owner_params),
            )
            conn.commit()
            updated = cur.rowcount > 0

        if updated:
            self._audit_log(
                memory_id=memory_id,
                table_name="semantic",
                action="verify",
                source=source,
                owner_key_hash=owner_key_hash,
            )
        return updated

    # ------------------------------------------------------------------
    # Proposed changes (staging queue for auto-extracted memories)
    # ------------------------------------------------------------------

    _AUTO_APPLY_CONFIDENCE_DEFAULT = 0.75

    def _should_auto_apply(self, memory_path: str, confidence: float) -> bool:
        """Decide whether an extracted memory may be applied without asking.

        Sensitive blocks (configurable, default identity/family/body) and
        low-confidence items always require explicit user confirmation.
        """
        for p in getattr(self.config, "extract_confirm_paths", None) or []:
            p = str(p).rstrip("/")
            if memory_path == p or memory_path.startswith(p + "/"):
                return False
        threshold = float(
            getattr(self.config, "auto_apply_confidence", self._AUTO_APPLY_CONFIDENCE_DEFAULT)
        )
        return confidence >= threshold

    def _apply_proposal_row(self, row: dict[str, Any]) -> int | None:
        """Execute the memory mutation described by a proposal row."""
        action = row.get("action") or "create"
        owner = row.get("owner_key_hash")
        if action in ("create", "update"):
            res = self.store_semantic(
                key=row.get("key") or "",
                value=row.get("value") or "",
                category=row.get("category") or "fact",
                confidence=row.get("confidence"),
                source=row.get("source") or "agent",
                memory_path=(row.get("memory_path") or None),
                entity_type=(row.get("entity_type") or None),
                entity_name=(row.get("entity_name") or None),
                relation_type=(row.get("relation_type") or None),
                owner_key_hash=owner,
                session_id=row.get("session_id") or "",
                evidence=row.get("evidence") or "",
            )
            return res.get("memory_id")
        if action == "delete" and row.get("target_memory_id") is not None:
            self.delete_semantic(
                int(row["target_memory_id"]), source="proposal", owner_key_hash=owner
            )
            return int(row["target_memory_id"])
        return None

    def _has_pending_proposal(self, key: str, owner_key_hash: str | None) -> bool:
        """True if the same owner already has a pending proposal for ``key``."""
        with db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM proposed_changes WHERE key = ? AND status = 'pending' "
                "AND COALESCE(owner_key_hash, '') = COALESCE(?, '') LIMIT 1",
                (key, owner_key_hash),
            ).fetchone()
        return row is not None

    def propose_change(
        self,
        *,
        action: str = "create",
        key: str = "",
        value: str = "",
        category: str = "fact",
        memory_path: str = "",
        entity_type: str = "",
        entity_name: str = "",
        relation_type: str = "",
        confidence: float = 0.5,
        source: str = "agent",
        session_id: str = "",
        evidence: str = "",
        target_memory_id: int | None = None,
        owner_key_hash: str | None = None,
        auto_apply: bool | None = None,
        skip_if_pending: bool = False,
    ) -> dict[str, Any]:
        """Stage a proposed memory change.

        If it clears the auto-apply policy (non-sensitive block + sufficient
        confidence) it is applied immediately and recorded ``auto_applied``;
        otherwise it stays ``pending`` for the user to approve/reject.
        Returns ``{proposal_id, status, memory_id}``.

        When ``skip_if_pending`` is set, a create/update proposal whose
        ``key`` already has a pending proposal for the same owner is dropped
        (status ``"duplicate"``) — this keeps the inbox from filling with
        duplicates when manual + background extraction overlap.
        """
        # Deduplicate: don't re-stage a key that is already awaiting confirmation.
        if (
            skip_if_pending
            and action in ("create", "update")
            and key
            and self._has_pending_proposal(key, owner_key_hash)
        ):
            return {"proposal_id": None, "status": "duplicate", "memory_id": None}

        # Infer block when missing so the confirm-path policy can evaluate it.
        if action in ("create", "update") and (not memory_path or not entity_type):
            ip, it, iname, irel = self._infer_entity_block(
                key,
                value,
                category,
                memory_path=memory_path or None,
                entity_type=entity_type or None,
                entity_name=entity_name or None,
                relation_type=relation_type or None,
            )
            memory_path = memory_path or ip
            entity_type = entity_type or it
            entity_name = entity_name or iname
            relation_type = relation_type or irel

        # Redact secrets in staged content too.
        value = self._secrets.detect_and_redact(value, f"proposal:{key}")
        if evidence:
            evidence = self._secrets.detect_and_redact(evidence, f"proposal-ev:{key}")

        if auto_apply is None:
            auto_apply = action in ("create", "update") and self._should_auto_apply(
                memory_path, confidence
            )

        now = time.time()
        status = "pending"
        applied_memory_id: int | None = None

        row = {
            "owner_key_hash": owner_key_hash,
            "action": action,
            "target_memory_id": target_memory_id,
            "key": key,
            "value": value,
            "category": category,
            "memory_path": memory_path,
            "entity_type": entity_type,
            "entity_name": entity_name,
            "relation_type": relation_type,
            "confidence": confidence,
            "source": source,
            "session_id": session_id,
            "evidence": evidence,
        }
        if auto_apply:
            applied_memory_id = self._apply_proposal_row(row)
            status = "auto_applied"

        with db_connection(self.db_path) as conn:
            cur = conn.execute(
                """
                INSERT INTO proposed_changes (
                    owner_key_hash, action, target_memory_id, key, value, category,
                    memory_path, entity_type, entity_name, relation_type, confidence,
                    source, session_id, evidence, status, created_at, decided_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    owner_key_hash,
                    action,
                    target_memory_id or applied_memory_id,
                    key,
                    value,
                    category,
                    memory_path,
                    entity_type,
                    entity_name,
                    relation_type,
                    confidence,
                    source,
                    session_id,
                    evidence,
                    status,
                    now,
                    now if status == "auto_applied" else None,
                ),
            )
            proposal_id = cur.lastrowid
            conn.commit()
        return {"proposal_id": proposal_id, "status": status, "memory_id": applied_memory_id}

    def list_proposals(
        self, status: str = "pending", owner_key_hash: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """List staged proposals, newest first (owner-scoped)."""
        owner_clause, owner_params = self._owner_filter(owner_key_hash)
        conditions: list[str] = []
        params: list[Any] = []
        if status and status != "all":
            conditions.append("status = ?")
            params.append(status)
        if owner_clause:
            conditions.append(owner_clause)
            params.extend(owner_params)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"SELECT * FROM proposed_changes{where} ORDER BY created_at DESC LIMIT ?",
                (*params, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def _get_proposal(self, proposal_id: int, owner_key_hash: str | None) -> dict[str, Any] | None:
        owner_clause, owner_params = self._owner_filter(owner_key_hash)
        guard = f" AND {owner_clause}" if owner_clause else ""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                f"SELECT * FROM proposed_changes WHERE id = ?{guard}",
                (proposal_id, *owner_params),
            ).fetchone()
        return dict(row) if row else None

    _PROPOSAL_OVERRIDE_FIELDS = (
        "key",
        "value",
        "category",
        "memory_path",
        "entity_type",
        "entity_name",
        "relation_type",
    )

    def approve_proposal(
        self,
        proposal_id: int,
        owner_key_hash: str | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Apply a pending proposal and mark it approved (owner-scoped).

        ``overrides`` lets the user edit the staged content before it lands
        (value / category / path / entity). The edited value is re-redacted,
        and the proposal row is updated to reflect what was actually written.
        """
        row = self._get_proposal(proposal_id, owner_key_hash)
        if row is None:
            return {"success": False, "error": "proposal not found"}
        if row["status"] not in ("pending",):
            return {"success": False, "error": f"proposal is {row['status']}"}
        if overrides:
            for field in self._PROPOSAL_OVERRIDE_FIELDS:
                if overrides.get(field) is not None:
                    row[field] = str(overrides[field])
            if overrides.get("value") is not None:
                row["value"] = self._secrets.detect_and_redact(
                    row["value"], f"proposal:{row.get('key')}"
                )
        memory_id = self._apply_proposal_row(row)
        # User confirmation == verification: stamp last_verified_at so the
        # approved memory is treated as user-trusted in ranking and the UI.
        if memory_id is not None and row.get("action") in ("create", "update"):
            self.verify_semantic(memory_id, source="user", owner_key_hash=owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.execute(
                "UPDATE proposed_changes SET status = 'approved', decided_at = ?, "
                "key = ?, value = ?, category = ?, memory_path = ?, entity_type = ?, "
                "entity_name = ?, relation_type = ?, "
                "target_memory_id = COALESCE(target_memory_id, ?) WHERE id = ?",
                (
                    time.time(),
                    row.get("key"),
                    row.get("value"),
                    row.get("category"),
                    row.get("memory_path"),
                    row.get("entity_type"),
                    row.get("entity_name"),
                    row.get("relation_type"),
                    memory_id,
                    proposal_id,
                ),
            )
            conn.commit()
        return {"success": True, "memory_id": memory_id, "status": "approved"}

    def reject_proposal(
        self, proposal_id: int, owner_key_hash: str | None = None
    ) -> dict[str, Any]:
        """Mark a pending proposal as rejected (owner-scoped)."""
        row = self._get_proposal(proposal_id, owner_key_hash)
        if row is None:
            return {"success": False, "error": "proposal not found"}
        with db_connection(self.db_path) as conn:
            conn.execute(
                "UPDATE proposed_changes SET status = 'rejected', decided_at = ? WHERE id = ?",
                (time.time(), proposal_id),
            )
            conn.commit()
        return {"success": True, "status": "rejected"}

    # ------------------------------------------------------------------
    # Block operations (move / merge)
    # ------------------------------------------------------------------

    def move_block(
        self, src_prefix: str, dst_prefix: str, owner_key_hash: str | None = None
    ) -> int:
        """Re-path every memory under ``src_prefix`` to ``dst_prefix`` (owner-scoped).

        Both the block itself and nested sub-blocks are remapped.  Returns the
        number of memories moved.
        """
        src = src_prefix.rstrip("/")
        dst = dst_prefix.rstrip("/")
        if not src or not dst or src == dst:
            return 0
        owner_clause, owner_params = self._owner_filter(owner_key_hash)
        guard = f" AND {owner_clause}" if owner_clause else ""
        with db_connection(self.db_path) as conn:
            # Exact-block rows
            cur1 = conn.execute(
                f"UPDATE semantic_memories SET memory_path = ? WHERE memory_path = ?{guard}",
                (dst, src, *owner_params),
            )
            # Nested sub-block rows: replace the leading prefix.
            cur2 = conn.execute(
                f"UPDATE semantic_memories "
                f"SET memory_path = ? || substr(memory_path, ?) "
                f"WHERE memory_path LIKE ?{guard}",
                (dst, len(src) + 1, f"{src}/%", *owner_params),
            )
            conn.commit()
            moved = (cur1.rowcount or 0) + (cur2.rowcount or 0)
        if moved:
            self._audit_log(
                memory_id=None,
                table_name="semantic",
                action="move_block",
                old_value=src,
                new_value=dst,
                source="user",
                owner_key_hash=owner_key_hash,
            )
        return moved

    def merge_blocks(
        self, src_prefix: str, dst_prefix: str, owner_key_hash: str | None = None
    ) -> int:
        """Merge block ``src_prefix`` into ``dst_prefix`` (alias of move)."""
        return self.move_block(src_prefix, dst_prefix, owner_key_hash=owner_key_hash)

    # ------------------------------------------------------------------
    # Context assembly for prompt injection
    # ------------------------------------------------------------------

    _VALID_MEMORY_FILES = {"identity", "user", "dreams"}

    def _read_memory_file(self, name: str, owner_key_hash: str | None = None) -> str:
        """Read a memory markdown file from state_dir/memory/."""
        if name not in self._VALID_MEMORY_FILES:
            raise ValueError(f"Invalid memory file name: {name}")
        from js.memory.profile_scope import scoped_profile_path

        path = scoped_profile_path(self.state_dir, name, owner_key_hash)
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
        owner_key_hash: str | None = None,
    ) -> str:
        """Assemble prompt context *progressively* within a char budget.

        Tiers, cheapest first, so even a small budget yields a useful map
        instead of dumping raw rows until the budget runs out:

          1. block summaries  — the shape of what's known (1 compact line)
          2. key facts        — query-relevant + core /user blocks
          3. raw evidence     — only if budget remains

        Human-curated profile prose (IDENTITY.md / USER.md) is injected first
        as the highest-signal context.  All reads are owner-scoped.
        """
        parts: list[str] = []
        used = 0
        _clean = self._secrets.detect_and_redact

        def _add(block: str) -> bool:
            nonlocal used
            if block and used + len(block) <= max_chars:
                parts.append(block)
                used += len(block)
                return True
            return False

        # 0. Profile prose (IDENTITY.md / USER.md) — highest priority.
        identity = self._read_memory_file("identity", owner_key_hash)
        if identity and not self._is_mostly_template(identity):
            _add("## AI Identity\n" + identity[:500] + "\n\n")
        user_profile = self._read_memory_file("user", owner_key_hash)
        if user_profile and not self._is_mostly_template(user_profile):
            _add("## About User\n" + user_profile[:500] + "\n\n")

        # 0b. Optional layered claims (off by default — legacy path unchanged).
        if getattr(self.config, "layered_memory_retrieve", False):
            try:
                claim_block = self._layered_store().format_claims_context(
                    owner_key_hash=owner_key_hash,
                    query=query,
                    max_chars=max(200, max_chars // 5),
                )
                if claim_block:
                    _add(claim_block)
            except Exception:
                logger.warning("layered claim retrieve failed", exc_info=True)

        # 1. Block summaries — a compact map of the hierarchical library.
        try:
            blocks = self.get_blocks(owner_key_hash=owner_key_hash)
        except Exception:
            blocks = []
        if blocks:
            summary = " · ".join(f"{b['block_path']}({b['memory_count']})" for b in blocks[:12])
            _add("## 记忆区块\n" + summary + "\n\n")

        # 2. Working memory for the current session (already session-scoped).
        if session_id:
            working = self.get_working(session_id, limit=10, owner_key_hash=owner_key_hash)
            if working:
                _add(
                    "## 当前上下文\n"
                    + "\n".join(
                        f"- [{m['category']}] {m['key']}: {m['value'][:100]}" for m in working
                    )
                    + "\n\n"
                )

        # 3. Key facts: query-relevant first, then core user-facing blocks.
        #    Collect SemanticMemory objects (deduped) so evidence can follow.
        seen_ids: set[int] = set()
        key_facts: list[SemanticMemory] = []

        def _collect(mems: list[SemanticMemory]) -> None:
            for m in mems:
                if m.id not in seen_ids:
                    seen_ids.add(m.id)
                    key_facts.append(m)

        if query:
            _collect(self.search_semantic(query, limit=6, owner_key_hash=owner_key_hash))
        _collect(
            self.search_semantic("", category="preference", limit=4, owner_key_hash=owner_key_hash)
        )
        for core_path in ("/user/identity", "/user/personality"):
            _collect(
                self.search_semantic(
                    "", path_prefix=core_path, limit=3, owner_key_hash=owner_key_hash
                )
            )
        _collect(self.search_semantic("", category="fact", limit=4, owner_key_hash=owner_key_hash))
        _collect(
            self.search_semantic("", category="external", limit=3, owner_key_hash=owner_key_hash)
        )

        facts_added = False
        if key_facts:
            lines = []
            for m in key_facts:
                tag = m.memory_path or f"/{m.category}"
                conf = (
                    "✓" if (m.last_verified_at or 0) > 0 else f"{int((m.confidence or 0.5) * 100)}%"
                )
                lines.append(f"- [{tag}] {m.key}: {_clean(m.value[:200])} ({conf})")
            facts_added = _add("## 关键事实\n" + "\n".join(lines) + "\n\n")

        # 4. Raw evidence — the most expensive tier; only attached when the
        #    facts it supports were themselves injected and budget remains.
        if facts_added:
            evidence_lines = [
                f"- {m.key}: {_clean((m.evidence or '')[:160])}"
                for m in key_facts
                if (m.evidence or "").strip()
            ]
            if evidence_lines:
                _add("## 原始证据\n" + "\n".join(evidence_lines) + "\n\n")

        return "\n".join(parts) or "暂无记忆。"

    # ------------------------------------------------------------------
    # Dreaming: consolidation pipeline
    # ------------------------------------------------------------------

    async def dream(
        self,
        llm_summarizer: Any | None = None,
        *,
        propagate_summarizer_errors: bool = False,
    ) -> dict[str, Any]:
        """Run full dreaming cycle, optionally surfacing summarizer failures."""
        logger.info("Starting dreaming cycle")
        report: dict[str, Any] = {"phases": []}

        # Phase 1: Light Sleep - deduplicate working memories
        light = self._light_sleep()
        report["phases"].append({"phase": "light", "summary": light})
        maintenance_light = "Working-memory deduplication completed."
        self._log_dream("light", maintenance_light)

        # Phase 2: REM Sleep - build associations
        rem = self._rem_sleep()
        report["phases"].append({"phase": "rem", "summary": rem})
        maintenance_rem = "Association maintenance completed."
        self._log_dream("rem", maintenance_rem)

        # Phase 3: Deep Sleep - promote to semantic / episode, scoped per owner.
        # Without owner scoping, one user's working memories leak into the
        # shared semantic pool.
        with db_connection(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT owner_key_hash
                FROM working_memories
                WHERE owner_key_hash IS NOT NULL AND owner_key_hash <> ''
                """
            ).fetchall()
            owners = [str(row[0]) for row in rows]
        diary_maintenance = [
            {"phase": "light", "summary": maintenance_light},
            {"phase": "rem", "summary": maintenance_rem},
        ]
        for owner in owners:
            deep_summary = await self._deep_sleep(
                llm_summarizer,
                owner_key_hash=owner,
                propagate_summarizer_errors=propagate_summarizer_errors,
            )
            self._log_dream("deep", deep_summary, owner_key_hash=owner)
            self._append_dream_diary(
                {"phases": [*diary_maintenance, {"phase": "deep", "summary": deep_summary}]},
                owner_key_hash=owner,
            )

        # The caller is not an owner-scoped read surface. Do not return one
        # user's generated insight alongside another owner's result.
        deep = (
            f"Processed {len(owners)} owner partitions."
            if owners
            else "No working memories to promote."
        )
        report["phases"].append({"phase": "deep", "summary": deep})
        if not owners:
            self._log_dream("deep", deep)
            self._append_dream_diary({"phases": [*diary_maintenance, report["phases"][-1]]})

        self._last_dream = time.time()
        logger.info("Dreaming cycle complete")
        return report

    def _append_dream_diary(
        self,
        report: dict[str, Any],
        owner_key_hash: str | None = None,
        max_bytes: int = _DEFAULT_MAX_DREAM_DIARY_BYTES,
    ) -> None:
        """Atomically retain complete recent owner-scoped dream cycles."""
        from js.memory.profile_scope import scoped_profile_path

        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")

        diary_path = scoped_profile_path(self.state_dir, "dreams", owner_key_hash)
        diary_path.parent.mkdir(parents=True, exist_ok=True)

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        lines = [f"## Dream Cycle - {timestamp}"]
        for phase in report.get("phases", []):
            pname = phase.get("phase", "unknown").capitalize()
            summary = phase.get("summary", "")
            lines.append(f"### {pname} Sleep")
            lines.append(summary)
            lines.append("")
        lines.append("<!-- dreaming:cycle:end -->")

        entry = "\n".join(lines).rstrip() + "\n\n"
        if len(entry.encode("utf-8")) > max_bytes:
            raise ValueError("Dream cycle exceeds diary byte limit")

        existing = diary_path.read_text(encoding="utf-8") if diary_path.exists() else ""
        preamble, cycles = self._split_dream_diary(existing)
        cycles.append(entry)

        if preamble and not preamble.endswith("\n"):
            preamble += "\n"
        if len((preamble + entry).encode("utf-8")) > max_bytes:
            preamble = "# Dream Diary\n\n"
        if len((preamble + entry).encode("utf-8")) > max_bytes:
            preamble = ""

        selected_reversed: list[str] = []
        used_bytes = len(preamble.encode("utf-8"))
        for cycle in reversed(cycles):
            cycle_bytes = len(cycle.encode("utf-8"))
            if used_bytes + cycle_bytes > max_bytes:
                break
            selected_reversed.append(cycle)
            used_bytes += cycle_bytes

        content = preamble + "".join(reversed(selected_reversed))
        self._atomic_write_text(diary_path, content)

    @staticmethod
    def _split_dream_diary(content: str) -> tuple[str, list[str]]:
        """Split a diary without slicing inside a generated cycle."""
        preamble: list[str] = []
        cycles: list[str] = []
        current: list[str] | None = None
        for line in content.splitlines(keepends=True):
            if line.startswith("## Dream Cycle "):
                if current is not None:
                    cycles.append("".join(current))
                current = [line]
            elif current is None:
                preamble.append(line)
            else:
                current.append(line)
        if current is not None:
            cycles.append("".join(current))
        return "".join(preamble), cycles

    @staticmethod
    def _atomic_write_text(path: Path, content: str) -> None:
        """Replace a UTF-8 text file only after its complete bytes are durable."""
        _reject_ambient_memory_under_enforce()
        temp_path = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
        try:
            with temp_path.open("xb") as file_handle:
                file_handle.write(content.encode("utf-8"))
                file_handle.flush()
                os.fsync(file_handle.fileno())
            os.replace(temp_path, path)
        finally:
            with contextlib.suppress(FileNotFoundError):
                temp_path.unlink()

    def _light_sleep(self) -> str:
        """Deduplicate and compress working memories.

        Dedup is partitioned by ``owner_key_hash`` so two users (or a user
        and the ``__legacy_local__`` shared pool) that happen to write the
        same ``(key, value)`` never have one row's existence delete the
        other's.  The dedup key is ``(owner_key_hash, key, value)``.
        """
        with db_connection(self.db_path) as conn:
            # The old implementation fetched every row into Python and retained
            # allocator high-water memory as the table grew. Keep the sort and
            # duplicate selection inside SQLite, with temporary data on disk.
            conn.execute("PRAGMA temp_store = FILE")
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    WITH ranked AS (
                        SELECT
                            id,
                            ROW_NUMBER() OVER (
                                PARTITION BY owner_key_hash, key, value
                                ORDER BY created_at DESC, id DESC
                            ) AS duplicate_rank
                        FROM working_memories
                    )
                    DELETE FROM working_memories
                    WHERE id IN (
                        SELECT id FROM ranked WHERE duplicate_rank > 1
                    )
                    """
                )
                changed = conn.execute("SELECT changes()").fetchone()
                conn.commit()
            except Exception:
                conn.rollback()
                raise

        removed = int(changed[0]) if changed is not None else 0
        return f"Removed {removed} duplicate working memories."

    # Common English stop-words to ignore when computing keyword overlap.
    _STOP_WORDS: frozenset[str] = frozenset(
        {
            "the",
            "a",
            "an",
            "is",
            "are",
            "was",
            "were",
            "be",
            "been",
            "being",
            "have",
            "has",
            "had",
            "do",
            "does",
            "did",
            "will",
            "would",
            "could",
            "should",
            "may",
            "might",
            "must",
            "shall",
            "can",
            "need",
            "dare",
            "ought",
            "used",
            "to",
            "of",
            "in",
            "for",
            "on",
            "with",
            "at",
            "by",
            "from",
            "as",
            "into",
            "through",
            "during",
            "before",
            "after",
            "above",
            "below",
            "between",
            "under",
            "again",
            "further",
            "then",
            "once",
            "here",
            "there",
            "when",
            "where",
            "why",
            "how",
            "all",
            "any",
            "both",
            "each",
            "few",
            "more",
            "most",
            "other",
            "some",
            "such",
            "no",
            "nor",
            "not",
            "only",
            "own",
            "same",
            "so",
            "than",
            "too",
            "very",
            "just",
            "and",
            "but",
            "if",
            "or",
            "because",
            "until",
            "while",
            "about",
            "against",
            "among",
            "around",
            "behind",
            "beyond",
            "despite",
            "down",
            "except",
            "inside",
            "like",
            "near",
            "off",
            "out",
            "outside",
            "over",
            "past",
            "since",
            "till",
            "up",
            "upon",
            "within",
            "without",
        }
    )

    def _rem_sleep(self) -> str:
        """Build simple keyword-based associations between memories."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            sem = conn.execute(
                """
                SELECT id, key, value, owner_key_hash
                FROM semantic_memories
                ORDER BY created_at DESC
                LIMIT 100
                """
            ).fetchall()

        links: list[tuple[str | None, int, int, str, str, float, str, float]] = []
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
                if a["owner_key_hash"] != b["owner_key_hash"]:
                    continue
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
                        (
                            a["owner_key_hash"],
                            a["id"],
                            b["id"],
                            "semantic_memories",
                            "semantic_memories",
                            min(1.0, overlap / 10),
                            "association",
                            now,
                        )
                    )

        if links:
            with db_connection(self.db_path) as conn:
                conn.executemany(
                    """
                    INSERT INTO memory_links (
                        owner_key_hash, from_id, to_id, from_table, to_table,
                        strength, link_type, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT DO NOTHING
                    """,
                    links,
                )
                conn.commit()

        return f"Created {len(links)} associative links."

    async def _deep_sleep(
        self,
        llm_summarizer: Any | None = None,
        owner_key_hash: str | None = None,
        *,
        propagate_summarizer_errors: bool = False,
    ) -> str:
        """Promote important working memories to semantic / episodic,
        with LLM insight generation. Scoped to a single owner so promoted
        memories do not leak across users."""
        is_legacy = owner_key_hash is None or owner_key_hash == _LEGACY_LOCAL_OWNER
        query_owner = _LEGACY_LOCAL_OWNER if is_legacy else owner_key_hash
        semantic_owner = None if is_legacy else owner_key_hash

        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM working_memories
                WHERE importance >= 7 AND owner_key_hash = ?
                ORDER BY created_at DESC
                LIMIT 20
                """,
                (query_owner,),
            ).fetchall()

        promoted = 0
        for r in rows:
            # Promote to semantic memory, preserving owner isolation.
            self.store_semantic(
                key=r["key"],
                value=r["value"],
                category=r["category"],
                confidence=0.7,
                source=r["session_id"],
                owner_key_hash=semantic_owner,
            )
            promoted += 1

        insight = ""
        if llm_summarizer and rows:
            # Build a summary of promoted memories for LLM analysis
            memory_text = "\n".join(
                f"[{r['category']}] {r['key']}: {r['value'][:200]}" for r in rows
            )
            try:
                if self._summarizer_accepts_owner(llm_summarizer):
                    insight = await llm_summarizer(memory_text, owner_key_hash)
                elif is_legacy:
                    # Legacy local callers may retain the pre-isolation
                    # callback shape because no authenticated data is sent.
                    insight = await llm_summarizer(memory_text)
                else:
                    logger.warning(
                        "Skipping authenticated dream summarization: callback lacks owner context"
                    )
                if insight:
                    # Use nanosecond timestamp to avoid collisions when dream()
                    # is called multiple times within the same second.
                    self.store_semantic(
                        key=f"dream_insight_{time.time_ns()}",
                        value=insight,
                        category="insight",
                        confidence=0.85,
                        source="deep_sleep_llm",
                        owner_key_hash=semantic_owner,
                    )
            except Exception:
                logger.warning("LLM summarizer failed during deep sleep", exc_info=True)
                if propagate_summarizer_errors:
                    raise

        owner_label = owner_key_hash or "legacy"
        base = f"Promoted {promoted} important memories to long-term storage ({owner_label})."
        if insight:
            base += f"\nInsight: {insight[:300]}"
        return base

    @staticmethod
    def _summarizer_accepts_owner(llm_summarizer: Any) -> bool:
        """Return whether a dream callback accepts the required owner argument."""
        try:
            signature = inspect.signature(llm_summarizer)
        except (TypeError, ValueError):
            # Let an opaque callable receive the required arguments; it must
            # fail rather than causing authenticated data to use an unscoped
            # callback shape.
            return True
        try:
            signature.bind("memory", "owner")
        except TypeError:
            return False
        return True

    def _log_dream(self, phase: str, summary: str, owner_key_hash: str | None = None) -> None:
        owner = self._session_owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO dream_logs (owner_key_hash, phase, summary, changes, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (owner, phase, summary, "", time.time()),
            )
            conn.commit()

    def get_dream_logs(
        self, limit: int = 20, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """Return only the requesting owner's dream logs."""
        owner = self._session_owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT *
                FROM dream_logs
                WHERE owner_key_hash = ?
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (owner, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    async def maybe_dream(self, min_interval: float = 300.0) -> dict[str, Any] | None:
        """Trigger dreaming if enough time has passed."""
        if time.time() - self._last_dream >= min_interval:
            return await self.dream()
        return None
