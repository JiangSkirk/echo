"""orind state store (SQLite, WAL mode).

Per Stage A decision: lease state (issued / consumed / revoked) lives in the
single JSONL ledger owned by :class:`js.echo.capability.LeaseAuthority` —
there is deliberately NO revocations table here because it would fork the
truth. This store only holds what the ledger cannot:

- ``receipts`` — signed decision receipts (durable audit trail);
- ``canaries`` — honeytoken registry (populated by WP3);
- ``responder_state`` — escalation-ladder state per session (populated by WP3).

Stage B adds (ORIN_STAGE_B_SPEC.md §3; lease truth still lives ONLY in the
JSONL ledger):

- ``intents`` — verified IntentEnvelopes (owner witness registry);
- ``handles`` — sealed OriginHandles minted by the broker;
- ``seeds`` — pre-registered handle candidates (contacts / history / cron).
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any, cast

from js.orind.private_paths import (
    PrivateSQLiteGuard,
    install_sqlite_guard,
    prepare_private_sqlite,
)

SCHEMA_VERSION = 4

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
CREATE TABLE IF NOT EXISTS intents (
    intent_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL DEFAULT '',
    owner_key_hash TEXT NOT NULL DEFAULT '',
    profile TEXT NOT NULL DEFAULT '',
    approval_policy TEXT NOT NULL DEFAULT '',
    issued_at_ms INTEGER NOT NULL DEFAULT 0,
    expires_at_ms INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    public_key TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_intents_task ON intents(task_id, revoked);
CREATE TABLE IF NOT EXISTS task_intent_signers (
    task_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS handles (
    handle_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL DEFAULT '',
    owner_key_hash TEXT NOT NULL DEFAULT '',
    expires_at_ms INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_handles_owner ON handles(owner_key_hash, kind);
CREATE TABLE IF NOT EXISTS export_passes (
    pass_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL DEFAULT '',
    payload_hash TEXT NOT NULL DEFAULT '',
    destinations_json TEXT NOT NULL DEFAULT '[]',
    witness_id TEXT NOT NULL DEFAULT '',
    expires_at_ms INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    profile TEXT NOT NULL DEFAULT 'personal',
    standing INTEGER NOT NULL DEFAULT 0,
    claimed_at_ms INTEGER NOT NULL DEFAULT 0,
    public_key TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_export_task ON export_passes(task_id, revoked);
CREATE TABLE IF NOT EXISTS exact_commit_approvals (
    approval_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    draft_id TEXT NOT NULL,
    witness_id TEXT NOT NULL,
    canonical_effect_hash TEXT NOT NULL,
    directory_handle_id TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    claimed_at_ms INTEGER NOT NULL DEFAULT 0,
    public_key TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exact_approval_task
ON exact_commit_approvals(task_id, claimed_at_ms, expires_at_ms);
CREATE INDEX IF NOT EXISTS idx_exact_approval_binding
ON exact_commit_approvals(
    task_id, draft_id, witness_id, canonical_effect_hash,
    directory_handle_id, claimed_at_ms, expires_at_ms
);
CREATE TABLE IF NOT EXISTS effect_drafts (
    draft_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    executor_id TEXT NOT NULL,
    canonical_effect_hash TEXT NOT NULL,
    context_taint INTEGER NOT NULL DEFAULT 0,
    clearance INTEGER NOT NULL DEFAULT 1,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_effect_drafts_task ON effect_drafts(task_id, expires_at_ms);
CREATE TABLE IF NOT EXISTS state_witnesses (
    witness_id TEXT PRIMARY KEY,
    draft_id TEXT NOT NULL,
    executor_id TEXT NOT NULL,
    canonical_effect_hash TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    is_current INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL,
    FOREIGN KEY(draft_id) REFERENCES effect_drafts(draft_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_state_witness_current
ON state_witnesses(draft_id) WHERE is_current = 1;
CREATE INDEX IF NOT EXISTS idx_state_witness_draft
ON state_witnesses(draft_id, expires_at_ms);
CREATE TABLE IF NOT EXISTS effect_budget_usage (
    task_id TEXT PRIMARY KEY,
    invocations INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    sequence INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS seeds (
    seed_id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL DEFAULT '',
    token TEXT NOT NULL DEFAULT '',
    label TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    added_at_ms INTEGER NOT NULL DEFAULT 0,
    UNIQUE(kind, token)
);
"""


class OrinStore:
    """SQLite WAL store for receipts and (WP3) canaries / responder state."""

    def __init__(self, path: Path, *, strict_paths: bool = False) -> None:
        self._path_guard: PrivateSQLiteGuard | None = None
        if strict_paths:
            self._path_guard = prepare_private_sqlite(path)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        if self._path_guard is not None:
            self._path_guard.verify()
            install_sqlite_guard(self._conn, self._path_guard)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._ensure_canary_columns()
        self._ensure_export_pass_columns()
        self._ensure_task_intent_signers()
        self._ensure_desktop_action_receipts()
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(SCHEMA_VERSION),),
        )
        self._conn.commit()
        if self._path_guard is not None:
            self._path_guard.verify()

    def _ensure_canary_columns(self) -> None:
        cols = {str(row[1]) for row in self._conn.execute("PRAGMA table_info(canaries)").fetchall()}
        if "token" not in cols:
            self._conn.execute("ALTER TABLE canaries ADD COLUMN token TEXT NOT NULL DEFAULT ''")
        if "read_at" not in cols:
            self._conn.execute("ALTER TABLE canaries ADD COLUMN read_at INTEGER NOT NULL DEFAULT 0")

    def _ensure_export_pass_columns(self) -> None:
        cols = {
            str(row[1]) for row in self._conn.execute("PRAGMA table_info(export_passes)").fetchall()
        }
        additions = {
            "profile": "TEXT NOT NULL DEFAULT 'personal'",
            "standing": "INTEGER NOT NULL DEFAULT 0",
            "claimed_at_ms": "INTEGER NOT NULL DEFAULT 0",
        }
        for name, declaration in additions.items():
            if name not in cols:
                self._conn.execute(f"ALTER TABLE export_passes ADD COLUMN {name} {declaration}")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_export_exact ON export_passes"
            " (task_id, payload_hash, destinations_json, witness_id, revoked, expires_at_ms)"
        )

    def _ensure_desktop_action_receipts(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS desktop_action_receipts (
                permit_id TEXT PRIMARY KEY,
                draft_id TEXT NOT NULL,
                before_digest TEXT NOT NULL,
                after_digest TEXT NOT NULL DEFAULT '',
                target_digest TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_desktop_action_draft "
            "ON desktop_action_receipts(draft_id)"
        )

    def record_desktop_action_receipt(
        self,
        *,
        permit_id: str,
        draft_id: str,
        before_digest: str,
        after_digest: str,
        target_digest: str,
        state: str,
        created_at_ms: int,
    ) -> None:
        if state not in {"committed", "unknown"}:
            raise ValueError("desktop action receipt state is invalid")
        self._conn.execute(
            """
            INSERT INTO desktop_action_receipts(
                permit_id, draft_id, before_digest, after_digest,
                target_digest, state, created_at_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(permit_id) DO UPDATE SET
                before_digest = excluded.before_digest,
                after_digest = excluded.after_digest,
                target_digest = excluded.target_digest,
                state = excluded.state
            """,
            (
                permit_id,
                draft_id,
                before_digest,
                after_digest,
                target_digest,
                state,
                created_at_ms,
            ),
        )
        self._conn.commit()

    def desktop_action_receipt(
        self,
        *,
        permit_id: str | None = None,
        draft_id: str | None = None,
    ) -> dict[str, Any] | None:
        if permit_id:
            row = self._conn.execute(
                "SELECT permit_id, draft_id, before_digest, after_digest, "
                "target_digest, state, created_at_ms FROM desktop_action_receipts "
                "WHERE permit_id = ?",
                (permit_id,),
            ).fetchone()
        elif draft_id:
            row = self._conn.execute(
                "SELECT permit_id, draft_id, before_digest, after_digest, "
                "target_digest, state, created_at_ms FROM desktop_action_receipts "
                "WHERE draft_id = ? ORDER BY created_at_ms DESC LIMIT 1",
                (draft_id,),
            ).fetchone()
        else:
            return None
        if row is None:
            return None
        return {
            "permit_id": str(row[0]),
            "draft_id": str(row[1]),
            "before_digest": str(row[2]),
            "after_digest": str(row[3]),
            "target_digest": str(row[4]),
            "state": str(row[5]),
            "created_at_ms": int(row[6]),
        }

    def _ensure_task_intent_signers(self) -> None:
        """Backfill only unambiguous historical task signers.

        A legacy task containing multiple or empty witness keys remains without
        a signer row and therefore cannot accept another intent after upgrade.
        """

        rows = self._conn.execute(
            "SELECT task_id, COUNT(DISTINCT public_key), MIN(public_key)"
            " FROM intents GROUP BY task_id"
        ).fetchall()
        for task_id, count, public_key in rows:
            key = str(public_key or "")
            if int(count) != 1 or not key:
                continue
            self._conn.execute(
                "INSERT OR IGNORE INTO task_intent_signers(task_id, public_key) VALUES (?, ?)",
                (str(task_id), key),
            )

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

    def all_canaries(self) -> list[tuple[str, str, str, int, int]]:
        """Return canary material only to the in-process authority scanner.

        Callers must never project the plaintext token into an ack or audit
        record; the store deliberately has no serialization helper for this
        privileged view.
        """

        rows = self._conn.execute(
            "SELECT session_id, token, token_hash, kind, read_at FROM canaries"
        ).fetchall()
        return [(str(row[0]), str(row[1]), str(row[2]), int(row[3]), int(row[4])) for row in rows]

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

    def record_export_pass(
        self,
        *,
        pass_id: str,
        payload: dict[str, Any],
        profile: str = "",
        standing: bool | None = None,
        public_key: str = "",
    ) -> str:
        """Persist a verified pass without allowing replay resurrection.

        The verification key is a registry column, never part of the signed
        payload.  ``INSERT OR IGNORE`` preserves a claimed/revoked row when
        the same pass is submitted again.
        """

        from js.orin.draft import export_pass_from_dict

        clean = dict(payload)
        legacy_key = str(clean.pop("_witness_public_key", ""))
        parsed = export_pass_from_dict(clean)
        if parsed.pass_id != pass_id:
            raise ValueError("export pass id does not match payload")
        destinations = _canonical_destinations(parsed.destination_handles)
        effective_profile = profile or ("work" if standing else "personal")
        if effective_profile not in {"personal", "work"}:
            raise ValueError("export pass profile must be personal or work")
        effective_standing = effective_profile == "work" if standing is None else standing
        if effective_standing != (effective_profile == "work"):
            raise ValueError("only Work export passes may be standing")
        payload_json = _stable_json(clean)
        key = public_key or legacy_key
        cursor = self._conn.execute(
            (
                "INSERT OR IGNORE INTO export_passes"
                " (pass_id, task_id, payload_hash, destinations_json, witness_id,"
                "  expires_at_ms, revoked, profile, standing, claimed_at_ms,"
                "  public_key, payload_json)"
                " VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, 0, ?, ?)"
            ),
            (
                pass_id,
                parsed.task_id,
                parsed.payload_hash,
                _stable_json(destinations),
                parsed.witness_id,
                parsed.expires_at_ms,
                effective_profile,
                int(effective_standing),
                key,
                payload_json,
            ),
        )
        self._conn.commit()
        if cursor.rowcount > 0:
            return "inserted"
        row = self._conn.execute(
            "SELECT payload_json, profile, standing, public_key FROM export_passes"
            " WHERE pass_id = ?",
            (pass_id,),
        ).fetchone()
        if row is not None and (str(row[0]), str(row[1]), int(row[2]), str(row[3])) == (
            payload_json,
            effective_profile,
            int(effective_standing),
            key,
        ):
            return "idempotent"
        return "conflict"

    def active_export_passes(self, task_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            (
                "SELECT payload_json FROM export_passes"
                " WHERE task_id = ? AND revoked = 0 AND expires_at_ms > ?"
            ),
            (task_id, int(time.time() * 1000)),
        ).fetchall()
        import json as _json

        return [_json.loads(str(row[0])) for row in rows]

    def active_exact_export_passes(
        self,
        task_id: str,
        payload_hash: str,
        destinations: tuple[str, ...] | list[str],
        witness_id: str,
        *,
        now_ms: int,
    ) -> list[dict[str, Any]]:
        canonical_destinations = _canonical_destinations(destinations)
        rows = self._conn.execute(
            (
                "SELECT payload_json FROM export_passes"
                " WHERE task_id = ? AND payload_hash = ? AND destinations_json = ?"
                " AND witness_id = ? AND revoked = 0 AND expires_at_ms > ?"
                " ORDER BY standing DESC, pass_id"
            ),
            (
                task_id,
                payload_hash,
                _stable_json(canonical_destinations),
                witness_id,
                now_ms,
            ),
        ).fetchall()
        import json

        return [cast("dict[str, Any]", json.loads(str(row[0]))) for row in rows]

    def claim_personal_export_pass(
        self,
        pass_id: str,
        task_id: str,
        payload_hash: str,
        destinations: tuple[str, ...] | list[str],
        witness_id: str,
        *,
        now_ms: int,
    ) -> bool:
        """Atomically claim one Personal pass for its exact binding."""

        canonical_destinations = _canonical_destinations(destinations)
        with self._conn:
            cursor = self._conn.execute(
                (
                    "UPDATE export_passes SET revoked = 1, claimed_at_ms = ?"
                    " WHERE pass_id = ? AND task_id = ? AND payload_hash = ?"
                    " AND destinations_json = ? AND witness_id = ?"
                    " AND profile = 'personal' AND standing = 0 AND revoked = 0"
                    " AND expires_at_ms > ?"
                ),
                (
                    now_ms,
                    pass_id,
                    task_id,
                    payload_hash,
                    _stable_json(canonical_destinations),
                    witness_id,
                    now_ms,
                ),
            )
        return cursor.rowcount == 1

    def revoke_export_pass(self, pass_id: str) -> bool:
        cursor = self._conn.execute(
            "UPDATE export_passes SET revoked = 1 WHERE pass_id = ? AND revoked = 0",
            (pass_id,),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    # -- stage B: Personal exact file-commit approvals -----------------------
    def record_exact_commit_approval(
        self,
        *,
        approval_id: str,
        payload: dict[str, Any],
        public_key: str,
    ) -> str:
        """Persist a verified approval without resurrecting a claimed row."""

        from js.orin.draft import exact_commit_approval_from_dict

        approval = exact_commit_approval_from_dict(payload)
        if approval.approval_id != approval_id:
            raise ValueError("exact approval id does not match payload")
        payload_json = _stable_json(approval.to_dict())
        cursor = self._conn.execute(
            (
                "INSERT OR IGNORE INTO exact_commit_approvals"
                " (approval_id, task_id, draft_id, witness_id, canonical_effect_hash,"
                "  directory_handle_id, created_at_ms, expires_at_ms, claimed_at_ms,"
                "  public_key, payload_json)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)"
            ),
            (
                approval.approval_id,
                approval.task_id,
                approval.draft_id,
                approval.witness_id,
                approval.canonical_effect_hash,
                approval.directory_handle_id,
                approval.created_at_ms,
                approval.expires_at_ms,
                public_key,
                payload_json,
            ),
        )
        self._conn.commit()
        if cursor.rowcount > 0:
            return "inserted"
        row = self._conn.execute(
            "SELECT payload_json, public_key FROM exact_commit_approvals WHERE approval_id = ?",
            (approval.approval_id,),
        ).fetchone()
        if row is not None and (str(row[0]), str(row[1])) == (payload_json, public_key):
            return "idempotent"
        return "conflict"

    def exact_commit_approvals_for_task(self, task_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT payload_json FROM exact_commit_approvals"
            " WHERE task_id = ? AND claimed_at_ms = 0 AND expires_at_ms > ?"
            " ORDER BY approval_id",
            (task_id, int(time.time() * 1000)),
        ).fetchall()
        import json

        return [cast("dict[str, Any]", json.loads(str(row[0]))) for row in rows]

    def active_exact_commit_approvals(
        self,
        *,
        task_id: str,
        draft_id: str,
        witness_id: str,
        canonical_effect_hash: str,
        directory_handle_id: str,
        now_ms: int,
        approval_id: str | None = None,
    ) -> list[dict[str, Any]]:
        sql = (
            "SELECT payload_json FROM exact_commit_approvals"
            " WHERE task_id = ? AND draft_id = ? AND witness_id = ?"
            " AND canonical_effect_hash = ? AND directory_handle_id = ?"
            " AND claimed_at_ms = 0 AND expires_at_ms > ?"
        )
        params: tuple[Any, ...] = (
            task_id,
            draft_id,
            witness_id,
            canonical_effect_hash,
            directory_handle_id,
            now_ms,
        )
        if approval_id is not None:
            sql += " AND approval_id = ?"
            params += (approval_id,)
        sql += " ORDER BY approval_id"
        rows = self._conn.execute(sql, params).fetchall()
        import json

        return [cast("dict[str, Any]", json.loads(str(row[0]))) for row in rows]

    def claim_personal_exact_commit_approval(
        self,
        *,
        approval_id: str,
        task_id: str,
        draft_id: str,
        witness_id: str,
        canonical_effect_hash: str,
        directory_handle_id: str,
        now_ms: int,
    ) -> bool:
        """Atomically claim one still-live approval for its exact binding."""

        with self._conn:
            cursor = self._conn.execute(
                (
                    "UPDATE exact_commit_approvals SET claimed_at_ms = ?"
                    " WHERE approval_id = ? AND task_id = ? AND draft_id = ?"
                    " AND witness_id = ? AND canonical_effect_hash = ?"
                    " AND directory_handle_id = ? AND claimed_at_ms = 0"
                    " AND expires_at_ms > ?"
                ),
                (
                    now_ms,
                    approval_id,
                    task_id,
                    draft_id,
                    witness_id,
                    canonical_effect_hash,
                    directory_handle_id,
                    now_ms,
                ),
            )
        return cursor.rowcount == 1

    # -- stage B: immutable drafts / current preflight witness ----------------
    def record_effect_draft(self, record: dict[str, Any]) -> str:
        """Insert one immutable draft record.

        Returns ``inserted`` for the first write, ``idempotent`` for an exact
        replay, and ``conflict`` when the id is reused with different bytes.
        The latter never overwrites the original authority record.
        """

        normalized = _normalize_effect_draft_record(record)
        payload_json = _stable_json(normalized)
        cursor = self._conn.execute(
            (
                "INSERT OR IGNORE INTO effect_drafts"
                " (draft_id, task_id, executor_id, canonical_effect_hash, context_taint,"
                "  clearance, created_at_ms, expires_at_ms, payload_json)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
            ),
            (
                normalized["draft_id"],
                normalized["task_id"],
                normalized["executor_id"],
                normalized["canonical_effect_hash"],
                normalized["context_taint"],
                normalized["clearance"],
                normalized["created_at_ms"],
                normalized["expires_at_ms"],
                payload_json,
            ),
        )
        self._conn.commit()
        if cursor.rowcount > 0:
            return "inserted"
        row = self._conn.execute(
            "SELECT payload_json FROM effect_drafts WHERE draft_id = ?",
            (normalized["draft_id"],),
        ).fetchone()
        if row is None:
            return "conflict"
        import json

        existing = cast("dict[str, Any]", json.loads(str(row[0])))
        if _draft_security_identity(existing) == _draft_security_identity(normalized):
            return "idempotent"
        return "conflict"

    def get_effect_draft(
        self, draft_id: str, *, now_ms: int | None = None
    ) -> dict[str, Any] | None:
        sql = "SELECT payload_json FROM effect_drafts WHERE draft_id = ?"
        params: tuple[Any, ...] = (draft_id,)
        if now_ms is not None:
            sql += " AND expires_at_ms > ?"
            params = (draft_id, now_ms)
        row = self._conn.execute(sql, params).fetchone()
        if row is None:
            return None
        import json

        return cast("dict[str, Any]", json.loads(str(row[0])))

    def record_state_witness(self, witness: Any) -> str:
        """Store one strictly parsed witness and make a new one current.

        Witness ids are immutable.  Replaying an older id never moves the
        current pointer backwards.
        """

        from js.orin.draft import StateWitness, witness_from_dict

        parsed = witness if isinstance(witness, StateWitness) else witness_from_dict(witness)
        if parsed.expires_at_ms <= parsed.created_at_ms:
            raise ValueError("state witness expiry must follow creation")
        payload_json = _stable_json(parsed.to_dict())
        with self._conn:
            existing = self._conn.execute(
                "SELECT payload_json, is_current FROM state_witnesses WHERE witness_id = ?",
                (parsed.witness_id,),
            ).fetchone()
            if existing is not None:
                if str(existing[0]) != payload_json:
                    return "conflict"
                return "idempotent" if int(existing[1]) == 1 else "stale"
            draft_row = self._conn.execute(
                "SELECT executor_id, canonical_effect_hash FROM effect_drafts WHERE draft_id = ?",
                (parsed.draft_id,),
            ).fetchone()
            if draft_row is None:
                return "conflict"
            if (
                str(draft_row[0]) != parsed.executor_id
                or str(draft_row[1]) != parsed.canonical_effect_hash
            ):
                return "conflict"
            current = self._conn.execute(
                "SELECT created_at_ms FROM state_witnesses WHERE draft_id = ? AND is_current = 1",
                (parsed.draft_id,),
            ).fetchone()
            if current is not None and parsed.created_at_ms <= int(current[0]):
                return "stale"
            self._conn.execute(
                "UPDATE state_witnesses SET is_current = 0 WHERE draft_id = ? AND is_current = 1",
                (parsed.draft_id,),
            )
            self._conn.execute(
                (
                    "INSERT INTO state_witnesses"
                    " (witness_id, draft_id, executor_id, canonical_effect_hash,"
                    "  created_at_ms, expires_at_ms, is_current, payload_json)"
                    " VALUES (?, ?, ?, ?, ?, ?, 1, ?)"
                ),
                (
                    parsed.witness_id,
                    parsed.draft_id,
                    parsed.executor_id,
                    parsed.canonical_effect_hash,
                    parsed.created_at_ms,
                    parsed.expires_at_ms,
                    payload_json,
                ),
            )
        return "inserted"

    def current_state_witness(
        self, draft_id: str, *, now_ms: int | None = None
    ) -> dict[str, Any] | None:
        sql = "SELECT payload_json FROM state_witnesses WHERE draft_id = ? AND is_current = 1"
        params: tuple[Any, ...] = (draft_id,)
        if now_ms is not None:
            sql += " AND expires_at_ms > ?"
            params = (draft_id, now_ms)
        row = self._conn.execute(sql, params).fetchone()
        return _json_object_or_none(row)

    def state_witness_by_id(
        self, witness_id: str, *, now_ms: int | None = None
    ) -> dict[str, Any] | None:
        sql = "SELECT payload_json FROM state_witnesses WHERE witness_id = ?"
        params: tuple[Any, ...] = (witness_id,)
        if now_ms is not None:
            sql += " AND expires_at_ms > ?"
            params = (witness_id, now_ms)
        row = self._conn.execute(sql, params).fetchone()
        return _json_object_or_none(row)

    def reserve_effect_budget(
        self,
        task_id: str,
        *,
        max_invocations: int,
        max_bytes_out: int,
        bytes_out: int,
    ) -> int | None:
        """Atomically reserve one WP8 invocation and return its sequence."""

        values = (max_invocations, max_bytes_out, bytes_out)
        if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            raise ValueError("budget values must be integers")
        if not task_id or any(value < 0 for value in values):
            raise ValueError("budget values and task_id must be non-negative")
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO effect_budget_usage(task_id) VALUES (?)",
                (task_id,),
            )
            row = self._conn.execute(
                "SELECT invocations, bytes_out, sequence FROM effect_budget_usage"
                " WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            assert row is not None
            invocations, used_bytes, sequence = (int(row[0]), int(row[1]), int(row[2]))
            if invocations + 1 > max_invocations or used_bytes + bytes_out > max_bytes_out:
                return None
            next_sequence = sequence + 1
            self._conn.execute(
                "UPDATE effect_budget_usage SET invocations = ?, bytes_out = ?, sequence = ?"
                " WHERE task_id = ?",
                (invocations + 1, used_bytes + bytes_out, next_sequence, task_id),
            )
        return next_sequence

    # -- stage B: intents / handles / seeds -----------------------------------
    def record_intent(
        self,
        *,
        intent_id: str,
        payload: dict[str, Any],
        public_key: str = "",
    ) -> str:
        """Persist one immutable intent under the task's historical witness key.

        A task id never changes signer, even after every intent has expired or
        been revoked.  Intent ids are immutable too: replay never resurrects a
        revoked row and conflicting bytes never replace the original record.
        """

        task_id = str(payload.get("task_id", ""))
        payload_json = _stable_json(payload)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            existing = self._conn.execute(
                "SELECT payload_json, public_key, revoked FROM intents WHERE intent_id = ?",
                (intent_id,),
            ).fetchone()
            if existing is not None:
                if (str(existing[0]), str(existing[1])) != (payload_json, public_key):
                    self._conn.rollback()
                    return "conflict"
                status = "revoked" if bool(existing[2]) else "idempotent"
                self._conn.commit()
                return status

            historical_keys = {
                str(row[0])
                for row in self._conn.execute(
                    "SELECT DISTINCT public_key FROM intents WHERE task_id = ?",
                    (task_id,),
                ).fetchall()
            }
            if historical_keys and historical_keys != {public_key}:
                self._conn.rollback()
                return "task_key_conflict"

            self._conn.execute(
                "INSERT OR IGNORE INTO task_intent_signers(task_id, public_key) VALUES (?, ?)",
                (task_id, public_key),
            )
            signer = self._conn.execute(
                "SELECT public_key FROM task_intent_signers WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if signer is None or str(signer[0]) != public_key:
                self._conn.rollback()
                return "task_key_conflict"

            self._conn.execute(
                (
                    "INSERT INTO intents"
                    " (intent_id, task_id, owner_key_hash, profile, approval_policy,"
                    "  issued_at_ms, expires_at_ms, revoked, public_key, payload_json)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)"
                ),
                (
                    intent_id,
                    task_id,
                    str(payload.get("subject", {}).get("owner_key_hash", "")),
                    str(payload.get("subject", {}).get("profile", "")),
                    str(payload.get("approval_policy", "")),
                    int(payload.get("issued_at_ms", 0)),
                    int(payload.get("expires_at_ms", 0)),
                    public_key,
                    payload_json,
                ),
            )
        except BaseException:
            self._conn.rollback()
            raise
        else:
            self._conn.commit()
            return "inserted"

    def active_intents_for_task(self, task_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            (
                "SELECT payload_json FROM intents"
                " WHERE task_id = ? AND revoked = 0"
                " ORDER BY issued_at_ms DESC, intent_id DESC"
            ),
            (task_id,),
        ).fetchall()
        import json

        return [cast("dict[str, Any]", json.loads(str(row[0]))) for row in rows]

    def intent_public_keys_for_task(self, task_id: str) -> tuple[str, ...]:
        """Return the task's signer history, including expired/revoked intents."""

        row = self._conn.execute(
            "SELECT signer.public_key, COUNT(DISTINCT intent.public_key),"
            " MIN(intent.public_key), MAX(intent.public_key)"
            " FROM task_intent_signers AS signer"
            " LEFT JOIN intents AS intent ON intent.task_id = signer.task_id"
            " WHERE signer.task_id = ? GROUP BY signer.task_id, signer.public_key",
            (task_id,),
        ).fetchone()
        if row is None:
            return ()
        signer = str(row[0])
        if int(row[1]) != 1 or str(row[2]) != signer or str(row[3]) != signer:
            return ()
        return (signer,)

    def intent_public_key(self, intent_id: str) -> str | None:
        """Return the exact witness key that verified one registered intent."""

        row = self._conn.execute(
            "SELECT public_key FROM intents WHERE intent_id = ? AND revoked = 0",
            (intent_id,),
        ).fetchone()
        if row is None:
            return None
        value = str(row[0])
        return value or None

    def revoke_intent(self, intent_id: str) -> bool:
        cursor = self._conn.execute(
            "UPDATE intents SET revoked = 1 WHERE intent_id = ?", (intent_id,)
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def frozen_sessions(self) -> tuple[str, ...]:
        """Sessions currently at L3+ (candidates for admin unfreeze)."""

        rows = self._conn.execute(
            "SELECT session_id FROM responder_state WHERE level >= ?",
            (3,),
        ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def witness_public_keys(self) -> tuple[str, ...]:
        rows = self._conn.execute(
            "SELECT DISTINCT public_key FROM intents WHERE public_key != ''"
        ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def record_handle(self, *, handle_id: str, kind: str, payload: dict[str, Any]) -> None:
        self._conn.execute(
            (
                "INSERT OR REPLACE INTO handles"
                " (handle_id, kind, owner_key_hash, expires_at_ms, created_at_ms, payload_json)"
                " VALUES (?, ?, ?, ?, ?, ?)"
            ),
            (
                handle_id,
                kind,
                str(payload.get("owner_key_hash", "")),
                int(payload.get("expires_at_ms", 0)),
                int(payload.get("created_at_ms", 0)),
                _stable_json(payload),
            ),
        )
        self._conn.commit()

    def record_handle_immutable(
        self,
        *,
        handle_id: str,
        kind: str,
        payload: dict[str, Any],
    ) -> str:
        """Record a Cell-derived handle without ever overwriting its identity.

        Identical replay is idempotent; reusing an id for different sealed
        content is a hard conflict.  This is deliberately separate from the
        Stage-B approval path, whose historical ``record_handle`` semantics
        remain unchanged.
        """

        payload_json = _stable_json(payload)
        with self._conn:
            cursor = self._conn.execute(
                (
                    "INSERT OR IGNORE INTO handles"
                    " (handle_id, kind, owner_key_hash, expires_at_ms, created_at_ms, payload_json)"
                    " VALUES (?, ?, ?, ?, ?, ?)"
                ),
                (
                    handle_id,
                    kind,
                    str(payload.get("owner_key_hash", "")),
                    int(payload.get("expires_at_ms", 0)),
                    int(payload.get("created_at_ms", 0)),
                    payload_json,
                ),
            )
            if cursor.rowcount == 1:
                return "stored"
            row = self._conn.execute(
                "SELECT kind, payload_json FROM handles WHERE handle_id = ?",
                (handle_id,),
            ).fetchone()
        if row is not None and (str(row[0]), str(row[1])) == (kind, payload_json):
            return "idempotent"
        return "conflict"

    def get_handle(self, handle_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT payload_json FROM handles WHERE handle_id = ?",
            (handle_id,),
        ).fetchone()
        if row is None:
            return None
        import json

        return cast("dict[str, Any]", json.loads(str(row[0])))

    def add_seed(self, *, kind: str, token: str, label: str, source: str, added_at_ms: int) -> bool:
        """Insert a seed candidate; returns False when it already existed."""

        cursor = self._conn.execute(
            (
                "INSERT OR IGNORE INTO seeds"
                " (kind, token, label, source, added_at_ms) VALUES (?, ?, ?, ?, ?)"
            ),
            (kind, token, label, source, added_at_ms),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def seed_candidates(self, kind: str | None = None) -> list[dict[str, Any]]:
        if kind is None:
            rows = self._conn.execute(
                "SELECT kind, token, label, source FROM seeds ORDER BY added_at_ms DESC LIMIT 256"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT kind, token, label, source FROM seeds WHERE kind = ?"
                " ORDER BY added_at_ms DESC LIMIT 256",
                (kind,),
            ).fetchall()
        return [
            {"kind": str(r[0]), "token": str(r[1]), "label": str(r[2]), "source": str(r[3])}
            for r in rows
        ]


def _stable_json(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _canonical_destinations(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)) or not 1 <= len(values) <= 32:
        raise ValueError("destination handles must contain 1..32 items")
    items = tuple(values)
    if any(not isinstance(item, str) or not item or len(item) > 512 for item in items):
        raise ValueError("destination handles must be bounded strings")
    if len(set(items)) != len(items):
        raise ValueError("duplicate destination handles are forbidden")
    return tuple(sorted(items))


def _normalize_effect_draft_record(record: dict[str, Any]) -> dict[str, Any]:
    from js.orin.draft import draft_from_dict

    if not isinstance(record, dict):
        raise ValueError("effect draft record must be an object")
    allowed = {
        "draft",
        "draft_id",
        "task_id",
        "effect_type",
        "executor_id",
        "canonical_effect_hash",
        "context_taint",
        "taint",
        "arg_taint",
        "clearance",
        "created_at_ms",
        "expires_at_ms",
    }
    unknown = set(record) - allowed
    if unknown:
        raise ValueError(f"unknown effect draft record fields {sorted(unknown)!r}")
    raw_draft = record.get("draft")
    if not isinstance(raw_draft, dict):
        raise ValueError("effect draft record requires a draft object")
    draft = draft_from_dict(raw_draft)
    draft_id = str(record.get("draft_id") or draft.draft_id)
    task_id = str(record.get("task_id") or draft.task_id)
    if draft_id != draft.draft_id or task_id != draft.task_id:
        raise ValueError("effect draft record identity mismatch")
    effect_type = str(record.get("effect_type") or draft.effect_type)
    if effect_type != draft.effect_type:
        raise ValueError("effect draft type mismatch")
    executor_id = record.get("executor_id")
    if not isinstance(executor_id, str) or not executor_id or len(executor_id) > 256:
        raise ValueError("effect draft executor_id must be a bounded string")
    digest = record.get("canonical_effect_hash")
    if (
        not isinstance(digest, str)
        or len(digest) != 71
        or not digest.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in digest[7:])
    ):
        raise ValueError("effect draft canonical hash must be sha256:<64 hex>")
    context_taint = record.get("context_taint", record.get("taint", 0))
    arg_taint = record.get("arg_taint", 0)
    clearance = record.get("clearance", 1)
    created_at_ms = record.get("created_at_ms")
    expires_at_ms = record.get("expires_at_ms")
    for name, value in {
        "context_taint": context_taint,
        "arg_taint": arg_taint,
        "clearance": clearance,
        "created_at_ms": created_at_ms,
        "expires_at_ms": expires_at_ms,
    }.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"effect draft {name} must be a non-negative integer")
    assert isinstance(context_taint, int)
    assert isinstance(arg_taint, int)
    assert isinstance(clearance, int)
    assert isinstance(created_at_ms, int)
    assert isinstance(expires_at_ms, int)
    if int(clearance) > 2:
        raise ValueError("effect draft clearance exceeds SECRET")
    if int(created_at_ms) <= 0 or int(expires_at_ms) <= int(created_at_ms):
        raise ValueError("effect draft expiry must follow positive creation time")
    return {
        "draft": draft.to_dict(),
        "draft_id": draft_id,
        "task_id": task_id,
        "effect_type": effect_type,
        "executor_id": executor_id,
        "canonical_effect_hash": digest,
        "context_taint": int(context_taint),
        "arg_taint": int(arg_taint),
        "clearance": int(clearance),
        "created_at_ms": int(created_at_ms),
        "expires_at_ms": int(expires_at_ms),
    }


def _json_object_or_none(row: Any) -> dict[str, Any] | None:
    if row is None:
        return None
    import json

    return cast("dict[str, Any]", json.loads(str(row[0])))


def _draft_security_identity(record: dict[str, Any]) -> str:
    content = dict(record)
    content.pop("created_at_ms", None)
    content.pop("expires_at_ms", None)
    return _stable_json(content)


__all__ = ["OrinStore", "SCHEMA_VERSION"]
