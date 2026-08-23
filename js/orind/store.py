"""orind state store (SQLite, WAL mode).

Per Stage A decision: lease state (issued / consumed / revoked) lives in the
single JSONL ledger owned by :class:`js.echo.capability.LeaseAuthority` —
there is deliberately NO revocations table here because it would fork the
truth. This store only holds what the ledger cannot:

- ``receipts`` — signed decision receipts (durable audit trail);
- ``canaries`` — honeytoken registry (populated by WP3);
- ``responder_state`` — escalation-ladder state per session (populated by WP3).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS receipts (
    receipt_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    verdict TEXT NOT NULL,
    lease_id TEXT NOT NULL DEFAULT '',
    policy_version INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    signature TEXT NOT NULL DEFAULT '',
    public_key TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_receipts_lease ON receipts(lease_id);
CREATE INDEX IF NOT EXISTS idx_receipts_created ON receipts(created_at);
CREATE TABLE IF NOT EXISTS canaries (
    token_hash TEXT PRIMARY KEY,
    session_id TEXT NOT NULL DEFAULT '',
    kind INTEGER NOT NULL DEFAULT 0,
    placed_at TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS responder_state (
    session_id TEXT PRIMARY KEY,
    level INTEGER NOT NULL DEFAULT 0,
    since INTEGER NOT NULL DEFAULT 0,
    evidence TEXT NOT NULL DEFAULT ''
);
"""


class OrinStore:
    """SQLite WAL store for receipts and (WP3) canaries / responder state."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self._ensure_canary_columns()
        self._conn.commit()

    def _ensure_canary_columns(self) -> None:
        cols = {str(row[1]) for row in self._conn.execute("PRAGMA table_info(canaries)").fetchall()}
        if "token" not in cols:
            self._conn.execute("ALTER TABLE canaries ADD COLUMN token TEXT NOT NULL DEFAULT ''")
        if "read_at" not in cols:
            self._conn.execute("ALTER TABLE canaries ADD COLUMN read_at INTEGER NOT NULL DEFAULT 0")

    def close(self) -> None:
        self._conn.close()

    # -- receipts -----------------------------------------------------------
    def record_receipt(self, receipt: dict[str, Any]) -> None:
        self._conn.execute(
            (
                "INSERT OR REPLACE INTO receipts"
                " (receipt_id, kind, verdict, lease_id, policy_version,"
                "  created_at, signature, public_key, payload_json)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
            ),
            (
                str(receipt.get("receipt_id", "")),
                str(receipt.get("kind", "")),
                str(receipt.get("verdict", "")),
                str(receipt.get("lease_id", "")),
                int(receipt.get("policy_version", 0)),
                int(receipt.get("created_at", 0)),
                str(receipt.get("signature", "")),
                str(receipt.get("public_key", "")),
                _stable_json(receipt),
            ),
        )
        self._conn.commit()

    def count_receipts(self, *, kind: str | None = None) -> int:
        if kind is None:
            row = self._conn.execute("SELECT COUNT(*) FROM receipts").fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM receipts WHERE kind = ?", (kind,)
            ).fetchone()
        return int(row[0]) if row else 0

    # -- canaries (WP3) -----------------------------------------------------
    def add_canary(
        self,
        *,
        token_hash: str,
        session_id: str,
        kind: int,
        placed_at: str,
        created_at: int,
        token: str = "",
    ) -> None:
        self._conn.execute(
            (
                "INSERT OR REPLACE INTO canaries"
                " (token_hash, session_id, kind, placed_at, created_at, token, read_at)"
                " VALUES (?, ?, ?, ?, ?, ?, 0)"
            ),
            (token_hash, session_id, kind, placed_at, created_at, token),
        )
        self._conn.commit()

    def known_canary_hashes(self) -> frozenset[str]:
        rows = self._conn.execute("SELECT token_hash FROM canaries").fetchall()
        return frozenset(str(row[0]) for row in rows)

    def canaries_for_session(self, session_id: str) -> list[tuple[str, str, int, int]]:
        """Return (token, token_hash, kind, read_at) rows for one session."""

        rows = self._conn.execute(
            "SELECT token, token_hash, kind, read_at FROM canaries WHERE session_id = ?",
            (session_id,),
        ).fetchall()
        return [(str(row[0]), str(row[1]), int(row[2]), int(row[3])) for row in rows]

    def mark_canary_read(self, *, token_hash: str, read_at: int) -> None:
        self._conn.execute(
            "UPDATE canaries SET read_at = ? WHERE token_hash = ? AND read_at = 0",
            (read_at, token_hash),
        )
        self._conn.commit()

    # -- responder state (WP3) ----------------------------------------------
    def responder_level(self, session_id: str) -> tuple[int, int, str]:
        row = self._conn.execute(
            "SELECT level, since, evidence FROM responder_state WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            return (0, 0, "")
        return (int(row[0]), int(row[1]), str(row[2]))

    def set_responder_level(
        self,
        *,
        session_id: str,
        level: int,
        since: int,
        evidence: str,
    ) -> None:
        self._conn.execute(
            (
                "INSERT OR REPLACE INTO responder_state"
                " (session_id, level, since, evidence) VALUES (?, ?, ?, ?)"
            ),
            (session_id, level, since, evidence),
        )
        self._conn.commit()


def _stable_json(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


__all__ = ["OrinStore", "SCHEMA_VERSION"]
