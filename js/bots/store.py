"""Owner-partitioned SQLite store for bots, rooms, messages, and goal runs."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from js.bots.exceptions import BotsIsolationError, BotsNotFoundError, BotsStateError
from js.bots.identity import compile_bot_identity, slugify_bot_name
from js.bots.models import (
    BOT_STATUS_ACTIVE,
    BOT_STATUS_DRAFT,
    BOTS_PRODUCT_ID,
    ROOM_KIND_DM,
    BotRecord,
    GoalBudget,
    GoalContract,
    GoalRun,
    GoalTodo,
    RoomMessage,
    RoomRecord,
)
from js.utils.db import db_connection

_BOT_ID_PREFIX = "b"
_ROOM_ID_PREFIX = "r"
_GOAL_ID_PREFIX = "g"
_MSG_ID_PREFIX = "m"
_SCOPE_SQL = "owner_key_hash = ? AND product_id = ?"


def private_memory_session(bot_id: str) -> str:
    return f"bot:{bot_id}:private"


def room_transcript_session(room_id: str) -> str:
    return f"room:{room_id}"


def _new_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex}"


def _require_scope(owner_key_hash: str, product_id: str) -> tuple[str, str]:
    if not isinstance(owner_key_hash, str) or not owner_key_hash.strip():
        raise BotsIsolationError("owner context is required")
    if not isinstance(product_id, str) or not product_id.strip():
        raise BotsIsolationError("product context is required")
    if len(owner_key_hash) > 128 or len(product_id) > 128:
        raise BotsIsolationError("scope identity exceeds limit")
    return owner_key_hash, product_id


def _json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _json_load(raw: str | None, fallback: Any) -> Any:
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return fallback


class BotStore:
    """Fail-closed persistence. Every query binds owner + product."""

    def __init__(self, state_dir: Path) -> None:
        self.db_path = Path(state_dir) / "bots.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> Any:
        return db_connection(self.db_path, row_factory=sqlite3.Row)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS bots (
                    id TEXT PRIMARY KEY,
                    owner_key_hash TEXT NOT NULL,
                    product_id TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    slug TEXT NOT NULL,
                    status TEXT NOT NULL,
                    soul_text TEXT NOT NULL DEFAULT '',
                    persona_appendix TEXT NOT NULL DEFAULT '',
                    memory_session TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    UNIQUE(owner_key_hash, product_id, slug)
                );
                CREATE TABLE IF NOT EXISTS rooms (
                    id TEXT PRIMARY KEY,
                    owner_key_hash TEXT NOT NULL,
                    product_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    title TEXT NOT NULL,
                    transcript_session TEXT NOT NULL,
                    goal_run_id TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS room_members (
                    room_id TEXT NOT NULL,
                    bot_id TEXT NOT NULL,
                    owner_key_hash TEXT NOT NULL,
                    product_id TEXT NOT NULL,
                    PRIMARY KEY (room_id, bot_id)
                );
                CREATE TABLE IF NOT EXISTS room_messages (
                    id TEXT PRIMARY KEY,
                    owner_key_hash TEXT NOT NULL,
                    product_id TEXT NOT NULL,
                    room_id TEXT NOT NULL,
                    speaker_kind TEXT NOT NULL,
                    speaker_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    taint INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS goal_runs (
                    id TEXT PRIMARY KEY,
                    owner_key_hash TEXT NOT NULL,
                    product_id TEXT NOT NULL,
                    room_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    questions TEXT NOT NULL,
                    answers TEXT NOT NULL,
                    contract TEXT NOT NULL,
                    todos TEXT NOT NULL,
                    budget TEXT NOT NULL,
                    pause_reason TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_bots_scope
                    ON bots(owner_key_hash, product_id);
                CREATE INDEX IF NOT EXISTS idx_rooms_scope
                    ON rooms(owner_key_hash, product_id);
                CREATE INDEX IF NOT EXISTS idx_messages_room
                    ON room_messages(owner_key_hash, product_id, room_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_goals_scope
                    ON goal_runs(owner_key_hash, product_id, room_id);
                """
            )
            conn.commit()

    def create_bot(
        self,
        *,
        display_name: str,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
        soul_text: str = "",
        persona_appendix: str = "",
        status: str = BOT_STATUS_DRAFT,
    ) -> BotRecord:
        owner, product = _require_scope(owner_key_hash, product_id)
        name = display_name.strip()
        if not name or len(name) > 64:
            raise BotsStateError("display_name must be 1..64 characters")
        if status not in {BOT_STATUS_DRAFT, BOT_STATUS_ACTIVE}:
            raise BotsStateError("invalid bot status")
        compiled = compile_bot_identity(name)
        appendix = persona_appendix or compiled.persona_appendix
        now = time.time()
        bot_id = _new_id(_BOT_ID_PREFIX)
        slug = self._allocate_slug(compiled.slug, owner, product)
        record = BotRecord(
            id=bot_id,
            owner_key_hash=owner,
            product_id=product,
            display_name=name,
            slug=slug,
            status=status,
            soul_text=soul_text,
            persona_appendix=appendix,
            memory_session=private_memory_session(bot_id),
            created_at=now,
            updated_at=now,
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO bots (
                    id, owner_key_hash, product_id, display_name, slug, status,
                    soul_text, persona_appendix, memory_session, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.id,
                    record.owner_key_hash,
                    record.product_id,
                    record.display_name,
                    record.slug,
                    record.status,
                    record.soul_text,
                    record.persona_appendix,
                    record.memory_session,
                    record.created_at,
                    record.updated_at,
                ),
            )
            conn.commit()
        return record

    def _allocate_slug(self, base: str, owner: str, product: str) -> str:
        candidate = slugify_bot_name(base)
        with self._connect() as conn:
            for suffix in ("", *[f"-{index}" for index in range(2, 32)]):
                slug = f"{candidate}{suffix}"
                row = conn.execute(
                    f"SELECT 1 FROM bots WHERE {_SCOPE_SQL} AND slug = ?",
                    (owner, product, slug),
                ).fetchone()
                if row is None:
                    return slug
        digest = uuid.uuid4().hex[:8]
        return f"{candidate}-{digest}"

    def get_bot(
        self,
        bot_id: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> BotRecord | None:
        owner, product = _require_scope(owner_key_hash, product_id)
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT * FROM bots WHERE id = ? AND {_SCOPE_SQL}",
                (bot_id, owner, product),
            ).fetchone()
        return self._bot_from_row(row) if row is not None else None

    def require_bot(
        self,
        bot_id: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> BotRecord:
        bot = self.get_bot(bot_id, owner_key_hash=owner_key_hash, product_id=product_id)
        if bot is None:
            raise BotsNotFoundError("bot is not visible in this scope")
        return bot

    def get_bot_by_name_or_slug(
        self,
        token: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
        active_only: bool = False,
    ) -> BotRecord | None:
        owner, product = _require_scope(owner_key_hash, product_id)
        needle = token.strip()
        if not needle:
            return None
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM bots WHERE {_SCOPE_SQL}",
                (owner, product),
            ).fetchall()
        matches = [
            self._bot_from_row(row)
            for row in rows
            if row["slug"] == needle or row["display_name"] == needle
        ]
        if active_only:
            matches = [bot for bot in matches if bot.is_active()]
        return matches[0] if matches else None

    def list_bots(
        self,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
        status: str | None = None,
    ) -> list[BotRecord]:
        owner, product = _require_scope(owner_key_hash, product_id)
        query = f"SELECT * FROM bots WHERE {_SCOPE_SQL}"
        params: list[Any] = [owner, product]
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at ASC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._bot_from_row(row) for row in rows]

    def update_soul(
        self,
        bot_id: str,
        *,
        soul_text: str,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
        activate: bool = False,
        persona_appendix: str | None = None,
    ) -> BotRecord:
        owner, product = _require_scope(owner_key_hash, product_id)
        text = soul_text.strip()
        if not text or len(text) > 8_000:
            raise BotsStateError("soul_text must be 1..8000 characters")
        bot = self.require_bot(bot_id, owner_key_hash=owner, product_id=product)
        status = BOT_STATUS_ACTIVE if activate else bot.status
        appendix = bot.persona_appendix if persona_appendix is None else persona_appendix
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                f"""
                UPDATE bots
                SET soul_text = ?, persona_appendix = ?, status = ?, updated_at = ?
                WHERE id = ? AND {_SCOPE_SQL}
                """,
                (text, appendix, status, now, bot_id, owner, product),
            )
            if conn.total_changes < 1:
                raise BotsIsolationError("soul write refused outside owner scope")
            conn.commit()
        updated = self.get_bot(bot_id, owner_key_hash=owner, product_id=product)
        if updated is None:
            raise BotsIsolationError("soul write lost the owner row")
        return updated

    def create_room(
        self,
        *,
        title: str,
        member_bot_ids: list[str],
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
        kind: str = "group",
    ) -> RoomRecord:
        owner, product = _require_scope(owner_key_hash, product_id)
        heading = title.strip()
        if not heading or len(heading) > 128:
            raise BotsStateError("room title must be 1..128 characters")
        unique_ids = tuple(dict.fromkeys(member_bot_ids))
        if not unique_ids:
            raise BotsStateError("room requires at least one bot")
        members = [
            self.require_bot(bot_id, owner_key_hash=owner, product_id=product)
            for bot_id in unique_ids
        ]
        if any(not bot.is_active() for bot in members):
            raise BotsStateError("draft bots cannot join rooms")
        now = time.time()
        room_id = _new_id(_ROOM_ID_PREFIX)
        record = RoomRecord(
            id=room_id,
            owner_key_hash=owner,
            product_id=product,
            kind=kind,
            title=heading,
            member_bot_ids=unique_ids,
            transcript_session=room_transcript_session(room_id),
            goal_run_id=None,
            created_at=now,
            updated_at=now,
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO rooms (
                    id, owner_key_hash, product_id, kind, title,
                    transcript_session, goal_run_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.id,
                    record.owner_key_hash,
                    record.product_id,
                    record.kind,
                    record.title,
                    record.transcript_session,
                    record.goal_run_id,
                    record.created_at,
                    record.updated_at,
                ),
            )
            conn.executemany(
                """
                INSERT INTO room_members (room_id, bot_id, owner_key_hash, product_id)
                VALUES (?, ?, ?, ?)
                """,
                [(room_id, bot_id, owner, product) for bot_id in unique_ids],
            )
            conn.commit()
        return record

    def ensure_dm_room(
        self,
        bot_id: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> RoomRecord:
        bot = self.require_bot(bot_id, owner_key_hash=owner_key_hash, product_id=product_id)
        if not bot.is_active():
            raise BotsStateError("draft bots cannot join rooms")
        existing = [
            room
            for room in self.list_rooms(
                owner_key_hash=owner_key_hash,
                product_id=product_id,
            )
            if room.kind == ROOM_KIND_DM and room.member_bot_ids == (bot_id,)
        ]
        if existing:
            return existing[0]
        return self.create_room(
            title=bot.display_name,
            member_bot_ids=[bot_id],
            owner_key_hash=owner_key_hash,
            product_id=product_id,
            kind=ROOM_KIND_DM,
        )

    def get_room(
        self,
        room_id: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> RoomRecord | None:
        owner, product = _require_scope(owner_key_hash, product_id)
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT * FROM rooms WHERE id = ? AND {_SCOPE_SQL}",
                (room_id, owner, product),
            ).fetchone()
            if row is None:
                return None
            members = conn.execute(
                f"SELECT bot_id FROM room_members WHERE room_id = ? AND {_SCOPE_SQL}",
                (room_id, owner, product),
            ).fetchall()
        return self._room_from_row(row, tuple(item["bot_id"] for item in members))

    def require_room(
        self,
        room_id: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> RoomRecord:
        room = self.get_room(room_id, owner_key_hash=owner_key_hash, product_id=product_id)
        if room is None:
            raise BotsNotFoundError("room is not visible in this scope")
        return room

    def list_rooms(
        self,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> list[RoomRecord]:
        owner, product = _require_scope(owner_key_hash, product_id)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM rooms WHERE {_SCOPE_SQL} ORDER BY updated_at DESC",
                (owner, product),
            ).fetchall()
            rooms: list[RoomRecord] = []
            for row in rows:
                members = conn.execute(
                    f"SELECT bot_id FROM room_members WHERE room_id = ? AND {_SCOPE_SQL}",
                    (row["id"], owner, product),
                ).fetchall()
                rooms.append(self._room_from_row(row, tuple(item["bot_id"] for item in members)))
        return rooms

    def add_room_members(
        self,
        room_id: str,
        member_bot_ids: list[str],
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> RoomRecord:
        owner, product = _require_scope(owner_key_hash, product_id)
        room = self.require_room(room_id, owner_key_hash=owner, product_id=product)
        incoming = [
            self.require_bot(bot_id, owner_key_hash=owner, product_id=product)
            for bot_id in member_bot_ids
        ]
        if any(not bot.is_active() for bot in incoming):
            raise BotsStateError("draft bots cannot join rooms")
        now = time.time()
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR IGNORE INTO room_members
                (room_id, bot_id, owner_key_hash, product_id)
                VALUES (?, ?, ?, ?)
                """,
                [(room.id, bot.id, owner, product) for bot in incoming],
            )
            conn.execute(
                f"UPDATE rooms SET kind = 'group', updated_at = ? WHERE id = ? AND {_SCOPE_SQL}",
                (now, room.id, owner, product),
            )
            conn.commit()
        updated = self.get_room(room.id, owner_key_hash=owner, product_id=product)
        if updated is None:
            raise BotsIsolationError("room membership write lost the owner row")
        return updated

    def bind_goal_run(
        self,
        room_id: str,
        goal_run_id: str | None,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> RoomRecord:
        owner, product = _require_scope(owner_key_hash, product_id)
        self.require_room(room_id, owner_key_hash=owner, product_id=product)
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                f"UPDATE rooms SET goal_run_id = ?, updated_at = ? WHERE id = ? AND {_SCOPE_SQL}",
                (goal_run_id, now, room_id, owner, product),
            )
            if conn.total_changes < 1:
                raise BotsIsolationError("room bind refused outside owner scope")
            conn.commit()
        return self.require_room(room_id, owner_key_hash=owner, product_id=product)

    def append_message(
        self,
        room_id: str,
        *,
        speaker_kind: str,
        speaker_id: str,
        content: str,
        taint: int,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> RoomMessage:
        owner, product = _require_scope(owner_key_hash, product_id)
        room = self.require_room(room_id, owner_key_hash=owner, product_id=product)
        text = content.strip()
        if not text or len(text) > 16_000:
            raise BotsStateError("message content must be 1..16000 characters")
        now = time.time()
        message = RoomMessage(
            id=_new_id(_MSG_ID_PREFIX),
            owner_key_hash=owner,
            product_id=product,
            room_id=room.id,
            speaker_kind=speaker_kind,
            speaker_id=speaker_id,
            content=text,
            taint=int(taint),
            created_at=now,
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO room_messages (
                    id, owner_key_hash, product_id, room_id, speaker_kind,
                    speaker_id, content, taint, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message.id,
                    message.owner_key_hash,
                    message.product_id,
                    message.room_id,
                    message.speaker_kind,
                    message.speaker_id,
                    message.content,
                    message.taint,
                    message.created_at,
                ),
            )
            conn.execute(
                f"UPDATE rooms SET updated_at = ? WHERE id = ? AND {_SCOPE_SQL}",
                (now, room.id, owner, product),
            )
            conn.commit()
        return message

    def list_messages(
        self,
        room_id: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
        limit: int = 200,
    ) -> list[RoomMessage]:
        owner, product = _require_scope(owner_key_hash, product_id)
        self.require_room(room_id, owner_key_hash=owner, product_id=product)
        bound = min(max(int(limit), 1), 500)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM (
                    SELECT * FROM room_messages
                    WHERE room_id = ? AND {_SCOPE_SQL}
                    ORDER BY created_at DESC, id DESC
                    LIMIT ?
                ) newest
                ORDER BY created_at ASC, id ASC
                """,
                (room_id, owner, product, bound),
            ).fetchall()
        return [self._message_from_row(row) for row in rows]

    def create_goal_run(
        self,
        room_id: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
        questions: list[str] | None = None,
        contract: GoalContract | None = None,
        budget: GoalBudget | None = None,
    ) -> GoalRun:
        owner, product = _require_scope(owner_key_hash, product_id)
        room = self.require_room(room_id, owner_key_hash=owner, product_id=product)
        now = time.time()
        record = GoalRun(
            id=_new_id(_GOAL_ID_PREFIX),
            owner_key_hash=owner,
            product_id=product,
            room_id=room.id,
            phase="clarify",
            questions=tuple(questions or ()),
            answers=(),
            contract=contract or GoalContract(objective=""),
            todos=(),
            budget=budget or GoalBudget(),
            pause_reason="",
            created_at=now,
            updated_at=now,
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO goal_runs (
                    id, owner_key_hash, product_id, room_id, phase, questions,
                    answers, contract, todos, budget, pause_reason, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.id,
                    record.owner_key_hash,
                    record.product_id,
                    record.room_id,
                    record.phase,
                    _json_dump(list(record.questions)),
                    _json_dump(list(record.answers)),
                    _json_dump(record.contract.to_dict()),
                    _json_dump([item.to_dict() for item in record.todos]),
                    _json_dump(record.budget.to_dict()),
                    record.pause_reason,
                    record.created_at,
                    record.updated_at,
                ),
            )
            conn.execute(
                f"UPDATE rooms SET goal_run_id = ?, updated_at = ? WHERE id = ? AND {_SCOPE_SQL}",
                (record.id, now, room.id, owner, product),
            )
            conn.commit()
        return record

    def get_goal_run(
        self,
        goal_id: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> GoalRun | None:
        owner, product = _require_scope(owner_key_hash, product_id)
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT * FROM goal_runs WHERE id = ? AND {_SCOPE_SQL}",
                (goal_id, owner, product),
            ).fetchone()
        return self._goal_from_row(row) if row is not None else None

    def require_goal_run(
        self,
        goal_id: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> GoalRun:
        goal = self.get_goal_run(goal_id, owner_key_hash=owner_key_hash, product_id=product_id)
        if goal is None:
            raise BotsNotFoundError("goal run is not visible in this scope")
        return goal

    def save_goal_run(self, goal: GoalRun) -> GoalRun:
        owner, product = _require_scope(goal.owner_key_hash, goal.product_id)
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                f"""
                UPDATE goal_runs
                SET phase = ?, questions = ?, answers = ?, contract = ?,
                    todos = ?, budget = ?, pause_reason = ?, updated_at = ?
                WHERE id = ? AND {_SCOPE_SQL}
                """,
                (
                    goal.phase,
                    _json_dump(list(goal.questions)),
                    _json_dump(list(goal.answers)),
                    _json_dump(goal.contract.to_dict()),
                    _json_dump([item.to_dict() for item in goal.todos]),
                    _json_dump(goal.budget.to_dict()),
                    goal.pause_reason,
                    now,
                    goal.id,
                    owner,
                    product,
                ),
            )
            if conn.total_changes < 1:
                raise BotsIsolationError("goal write refused outside owner scope")
            conn.commit()
        updated = self.get_goal_run(goal.id, owner_key_hash=owner, product_id=product)
        if updated is None:
            raise BotsIsolationError("goal write lost the owner row")
        return updated

    def list_goal_runs(
        self,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
        limit: int = 100,
    ) -> list[GoalRun]:
        owner, product = _require_scope(owner_key_hash, product_id)
        bound = min(max(int(limit), 1), 200)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM goal_runs
                WHERE {_SCOPE_SQL}
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (owner, product, bound),
            ).fetchall()
        return [self._goal_from_row(row) for row in rows]

    @staticmethod
    def _bot_from_row(row: sqlite3.Row) -> BotRecord:
        return BotRecord(
            id=str(row["id"]),
            owner_key_hash=str(row["owner_key_hash"]),
            product_id=str(row["product_id"]),
            display_name=str(row["display_name"]),
            slug=str(row["slug"]),
            status=str(row["status"]),
            soul_text=str(row["soul_text"]),
            persona_appendix=str(row["persona_appendix"]),
            memory_session=str(row["memory_session"]),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
        )

    @staticmethod
    def _room_from_row(row: sqlite3.Row, member_bot_ids: tuple[str, ...]) -> RoomRecord:
        goal_run_id = row["goal_run_id"]
        return RoomRecord(
            id=str(row["id"]),
            owner_key_hash=str(row["owner_key_hash"]),
            product_id=str(row["product_id"]),
            kind=str(row["kind"]),
            title=str(row["title"]),
            member_bot_ids=member_bot_ids,
            transcript_session=str(row["transcript_session"]),
            goal_run_id=str(goal_run_id) if goal_run_id else None,
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
        )

    @staticmethod
    def _message_from_row(row: sqlite3.Row) -> RoomMessage:
        return RoomMessage(
            id=str(row["id"]),
            owner_key_hash=str(row["owner_key_hash"]),
            product_id=str(row["product_id"]),
            room_id=str(row["room_id"]),
            speaker_kind=str(row["speaker_kind"]),
            speaker_id=str(row["speaker_id"]),
            content=str(row["content"]),
            taint=int(row["taint"]),
            created_at=float(row["created_at"]),
        )

    @staticmethod
    def _goal_from_row(row: sqlite3.Row) -> GoalRun:
        contract = GoalContract.from_dict(_json_load(row["contract"], {}))
        todos_raw = _json_load(row["todos"], [])
        budget = GoalBudget.from_dict(_json_load(row["budget"], {}))
        return GoalRun(
            id=str(row["id"]),
            owner_key_hash=str(row["owner_key_hash"]),
            product_id=str(row["product_id"]),
            room_id=str(row["room_id"]),
            phase=str(row["phase"]),
            questions=tuple(str(item) for item in _json_load(row["questions"], [])),
            answers=tuple(str(item) for item in _json_load(row["answers"], [])),
            contract=contract,
            todos=tuple(GoalTodo.from_dict(item) for item in todos_raw if isinstance(item, dict)),
            budget=budget,
            pause_reason=str(row["pause_reason"] or ""),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
        )
