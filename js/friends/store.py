"""Owner-scoped SQLite store for Friends v1."""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.friends.protocol import FriendStatus
from js.utils.db import db_connection

_SCOPE = "owner = ?"


@dataclass(frozen=True, slots=True)
class StoredFriend:
    owner: str
    friend_id: str
    display_name: str
    public_key: str
    endpoint: str
    status: str
    key_rotation_epoch: int
    confirmed_at: float


@dataclass(frozen=True, slots=True)
class StoredInvite:
    owner: str
    request_id: str
    invite_code: str
    invitee_id: str
    status: str
    created_at: float


class FriendStore:
    def __init__(self, state_dir: Path) -> None:
        self.db_path = Path(state_dir) / "friends.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> Any:
        return db_connection(self.db_path, row_factory=sqlite3.Row)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS local_identity (
                    owner TEXT PRIMARY KEY,
                    friend_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS friends (
                    owner TEXT NOT NULL,
                    friend_id TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    key_rotation_epoch INTEGER NOT NULL,
                    confirmed_at REAL NOT NULL,
                    PRIMARY KEY (owner, friend_id)
                );
                CREATE TABLE IF NOT EXISTS invites (
                    owner TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    invite_code TEXT NOT NULL,
                    invitee_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (owner, request_id)
                );
                CREATE TABLE IF NOT EXISTS seen_ids (
                    owner TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    seen_at REAL NOT NULL,
                    PRIMARY KEY (owner, message_id)
                );
                CREATE TABLE IF NOT EXISTS messages (
                    owner TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    friend_id TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (owner, message_id)
                );
                """
            )
            conn.commit()

    def get_or_create_identity(self, owner: str, friend_id: str) -> str:
        if not owner.strip():
            raise ValueError("owner is required")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT friend_id FROM local_identity WHERE owner = ?",
                (owner,),
            ).fetchone()
            if row is not None:
                return str(row["friend_id"])
            conn.execute(
                "INSERT INTO local_identity (owner, friend_id) VALUES (?, ?)",
                (owner, friend_id),
            )
            conn.commit()
        return friend_id

    def owner_for_local_id(self, friend_id: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT owner FROM local_identity WHERE friend_id = ?",
                (friend_id,),
            ).fetchone()
        return str(row["owner"]) if row is not None else None

    def local_friend_id(self, owner: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT friend_id FROM local_identity WHERE owner = ?",
                (owner,),
            ).fetchone()
        return str(row["friend_id"]) if row is not None else None

    def put_invite(self, invite: StoredInvite) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO invites
                    (owner, request_id, invite_code, invitee_id, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    invite.owner,
                    invite.request_id,
                    invite.invite_code,
                    invite.invitee_id,
                    invite.status,
                    invite.created_at,
                ),
            )
            conn.commit()

    def get_invite_by_code(self, owner: str, invite_code: str) -> StoredInvite | None:
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT * FROM invites WHERE {_SCOPE} AND invite_code = ?",
                (owner, invite_code),
            ).fetchone()
        return _invite_from_row(row) if row is not None else None

    def mark_invite(self, owner: str, request_id: str, status: str) -> None:
        with self._connect() as conn:
            conn.execute(
                f"UPDATE invites SET status = ? WHERE {_SCOPE} AND request_id = ?",
                (status, owner, request_id),
            )
            conn.commit()

    def upsert_friend(self, friend: StoredFriend) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO friends (
                    owner, friend_id, display_name, public_key, endpoint,
                    status, key_rotation_epoch, confirmed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(owner, friend_id) DO UPDATE SET
                    display_name = excluded.display_name,
                    public_key = excluded.public_key,
                    endpoint = excluded.endpoint,
                    status = excluded.status,
                    key_rotation_epoch = excluded.key_rotation_epoch,
                    confirmed_at = excluded.confirmed_at
                """,
                (
                    friend.owner,
                    friend.friend_id,
                    friend.display_name,
                    friend.public_key,
                    friend.endpoint,
                    friend.status,
                    friend.key_rotation_epoch,
                    friend.confirmed_at,
                ),
            )
            conn.commit()

    def get_friend(self, owner: str, friend_id: str) -> StoredFriend | None:
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT * FROM friends WHERE {_SCOPE} AND friend_id = ?",
                (owner, friend_id),
            ).fetchone()
        return _friend_from_row(row) if row is not None else None

    def list_friends(self, owner: str) -> list[StoredFriend]:
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM friends WHERE {_SCOPE} ORDER BY confirmed_at DESC",
                (owner,),
            ).fetchall()
        return [_friend_from_row(row) for row in rows]

    def set_status(self, owner: str, friend_id: str, status: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE friends SET status = ? WHERE {_SCOPE} AND friend_id = ?",
                (status, owner, friend_id),
            )
            conn.commit()
            return int(cur.rowcount) > 0

    def bump_epoch(self, owner: str, friend_id: str) -> int:
        friend = self.get_friend(owner, friend_id)
        if friend is None or friend.status != FriendStatus.CONFIRMED:
            raise ValueError("cannot rotate key")
        nxt = friend.key_rotation_epoch + 1
        with self._connect() as conn:
            conn.execute(
                f"UPDATE friends SET key_rotation_epoch = ? WHERE {_SCOPE} AND friend_id = ?",
                (nxt, owner, friend_id),
            )
            conn.commit()
        return nxt

    def seen(self, owner: str, message_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT 1 FROM seen_ids WHERE {_SCOPE} AND message_id = ?",
                (owner, message_id),
            ).fetchone()
        return row is not None

    def mark_seen(self, owner: str, message_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO seen_ids (owner, message_id, seen_at) VALUES (?, ?, ?)",
                (owner, message_id, time.time()),
            )
            conn.commit()

    def add_message(
        self,
        owner: str,
        *,
        message_id: str,
        friend_id: str,
        direction: str,
        ciphertext: str,
        epoch: int,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO messages
                    (owner, message_id, friend_id, direction, ciphertext, epoch, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (owner, message_id, friend_id, direction, ciphertext, epoch, time.time()),
            )
            conn.commit()

    def list_messages(self, owner: str, friend_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
        bound = min(max(int(limit), 1), 200)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT message_id, friend_id, direction, epoch, created_at
                FROM messages
                WHERE {_SCOPE} AND friend_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (owner, friend_id, bound),
            ).fetchall()
        return [
            {
                "message_id": str(row["message_id"]),
                "friend_id": str(row["friend_id"]),
                "direction": str(row["direction"]),
                "epoch": int(row["epoch"]),
                "created_at": float(row["created_at"]),
            }
            for row in rows
        ]


def _friend_from_row(row: sqlite3.Row) -> StoredFriend:
    return StoredFriend(
        owner=str(row["owner"]),
        friend_id=str(row["friend_id"]),
        display_name=str(row["display_name"]),
        public_key=str(row["public_key"]),
        endpoint=str(row["endpoint"]),
        status=str(row["status"]),
        key_rotation_epoch=int(row["key_rotation_epoch"]),
        confirmed_at=float(row["confirmed_at"]),
    )


def _invite_from_row(row: sqlite3.Row) -> StoredInvite:
    return StoredInvite(
        owner=str(row["owner"]),
        request_id=str(row["request_id"]),
        invite_code=str(row["invite_code"]),
        invitee_id=str(row["invitee_id"]),
        status=str(row["status"]),
        created_at=float(row["created_at"]),
    )
