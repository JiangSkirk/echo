"""Proposal-only evolution cycle. Apply happens after an admin decision."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.utils.db import db_connection
from js.utils.log import get_logger

logger = get_logger("js.evolution.cycle")

STATUS_PROPOSED = "proposed"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_APPLIED = "applied"
STATUS_REGRESSED = "regressed"

BenchmarkFn = Callable[[], float]


@dataclass(frozen=True, slots=True)
class EvolutionProposal:
    proposal_id: str
    owner: str
    kind: str
    title: str
    payload: dict[str, Any]
    status: str
    created_at: float
    decided_by: str | None = None
    applied_path: str | None = None
    benchmark_after: float | None = None


class EvolutionCycle:
    """Owner-scoped proposal desk. Generate never applies."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = Path(state_dir)
        self.db_path = self.state_dir / "evolution_proposals.db"
        self.applied_dir = self.state_dir / "evolution" / "applied"
        self._init_db()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with db_connection(self.db_path, row_factory=sqlite3.Row) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evolution_proposals (
                    proposal_id TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    title TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    decided_by TEXT,
                    decided_at REAL,
                    applied_path TEXT,
                    benchmark_after REAL,
                    PRIMARY KEY (proposal_id, owner)
                )
                """
            )
            conn.commit()

    def generate(
        self,
        owner: str,
        *,
        learner: Any | None = None,
        max_proposals: int = 3,
    ) -> list[EvolutionProposal]:
        owner_key = owner.strip()
        if not owner_key:
            raise ValueError("owner is required")
        if max_proposals < 1:
            return []
        suggestions: list[str] = []
        if learner is not None and hasattr(learner, "suggest_improvements"):
            try:
                raw = learner.suggest_improvements(owner_key_hash=owner_key)
            except TypeError:
                raw = learner.suggest_improvements()
            if isinstance(raw, list):
                suggestions = []
                for item in raw[:max_proposals]:
                    if isinstance(item, dict):
                        suggestions.append(
                            str(item.get("suggestion") or item.get("title") or item)[:200]
                        )
                    else:
                        suggestions.append(str(item)[:200])
        if not suggestions:
            suggestions = ["Review recent low-scoring turns and propose a prompt tweak."]
        created: list[EvolutionProposal] = []
        now = time.time()
        with db_connection(self.db_path, row_factory=sqlite3.Row) as conn:
            open_count = conn.execute(
                "SELECT COUNT(*) FROM evolution_proposals WHERE owner = ? AND status = ?",
                (owner_key, STATUS_PROPOSED),
            ).fetchone()[0]
            budget = max(0, max_proposals - int(open_count))
            for title in suggestions[:budget]:
                proposal_id = uuid.uuid4().hex
                payload = {"suggestion": title, "auto_apply": False}
                conn.execute(
                    """
                    INSERT INTO evolution_proposals
                        (proposal_id, owner, kind, title, payload_json, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        proposal_id,
                        owner_key,
                        "prompt_variant",
                        title[:200],
                        json.dumps(payload, ensure_ascii=True, sort_keys=True),
                        STATUS_PROPOSED,
                        now,
                    ),
                )
                created.append(
                    EvolutionProposal(
                        proposal_id=proposal_id,
                        owner=owner_key,
                        kind="prompt_variant",
                        title=title[:200],
                        payload=payload,
                        status=STATUS_PROPOSED,
                        created_at=now,
                    )
                )
            conn.commit()
        logger.info(
            "evolution cycle generated proposals owner=%s count=%s", owner_key, len(created)
        )
        return created

    def list_proposals(self, owner: str, *, limit: int = 20) -> list[EvolutionProposal]:
        with db_connection(self.db_path, row_factory=sqlite3.Row) as conn:
            rows = conn.execute(
                """
                SELECT proposal_id, owner, kind, title, payload_json, status,
                       created_at, decided_by, applied_path, benchmark_after
                FROM evolution_proposals
                WHERE owner = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (owner, limit),
            ).fetchall()
        return [_row_to_proposal(row) for row in rows]

    def get(self, proposal_id: str, owner: str) -> EvolutionProposal | None:
        with db_connection(self.db_path, row_factory=sqlite3.Row) as conn:
            row = conn.execute(
                """
                SELECT proposal_id, owner, kind, title, payload_json, status,
                       created_at, decided_by, applied_path, benchmark_after
                FROM evolution_proposals
                WHERE proposal_id = ? AND owner = ?
                """,
                (proposal_id, owner),
            ).fetchone()
        return _row_to_proposal(row) if row is not None else None

    def reject(self, proposal_id: str, owner: str, *, decided_by: str) -> EvolutionProposal:
        proposal = self.get(proposal_id, owner)
        if proposal is None or proposal.status != STATUS_PROPOSED:
            raise ValueError("proposal is not open")
        self._set_status(proposal_id, owner, STATUS_REJECTED, decided_by=decided_by)
        updated = self.get(proposal_id, owner)
        if updated is None:
            raise RuntimeError("proposal vanished after reject")
        return updated

    def approve_and_apply(
        self,
        proposal_id: str,
        owner: str,
        *,
        decided_by: str,
        benchmark: BenchmarkFn | None = None,
        baseline_score: float | None = None,
    ) -> EvolutionProposal:
        proposal = self.get(proposal_id, owner)
        if proposal is None or proposal.status != STATUS_PROPOSED:
            raise ValueError("proposal is not open")
        self._set_status(proposal_id, owner, STATUS_APPROVED, decided_by=decided_by)
        applied_path = self._write_applied(proposal)
        score = 1.0 if benchmark is None else float(benchmark())
        threshold = load_baseline_score() if baseline_score is None else float(baseline_score)
        if score < threshold:
            self._rollback_file(applied_path)
            self._set_status(
                proposal_id,
                owner,
                STATUS_REGRESSED,
                decided_by=decided_by,
                applied_path=applied_path,
                benchmark_after=score,
            )
        else:
            self._set_status(
                proposal_id,
                owner,
                STATUS_APPLIED,
                decided_by=decided_by,
                applied_path=applied_path,
                benchmark_after=score,
            )
        updated = self.get(proposal_id, owner)
        if updated is None:
            raise RuntimeError("proposal vanished after apply")
        return updated

    def _write_applied(self, proposal: EvolutionProposal) -> str:
        self.applied_dir.mkdir(parents=True, exist_ok=True)
        path = self.applied_dir / f"{proposal.proposal_id}.json"
        path.write_text(
            json.dumps(
                {
                    "proposal_id": proposal.proposal_id,
                    "owner": proposal.owner,
                    "payload": proposal.payload,
                },
                ensure_ascii=True,
                indent=2,
            ),
            encoding="utf-8",
        )
        return str(path)

    def _rollback_file(self, applied_path: str) -> None:
        path = Path(applied_path)
        if path.is_file():
            path.unlink()

    def _set_status(
        self,
        proposal_id: str,
        owner: str,
        status: str,
        *,
        decided_by: str,
        applied_path: str | None = None,
        benchmark_after: float | None = None,
    ) -> None:
        with db_connection(self.db_path, row_factory=sqlite3.Row) as conn:
            conn.execute(
                """
                UPDATE evolution_proposals
                SET status = ?, decided_by = ?, decided_at = ?,
                    applied_path = COALESCE(?, applied_path),
                    benchmark_after = COALESCE(?, benchmark_after)
                WHERE proposal_id = ? AND owner = ?
                """,
                (
                    status,
                    decided_by,
                    time.time(),
                    applied_path,
                    benchmark_after,
                    proposal_id,
                    owner,
                ),
            )
            conn.commit()


def _row_to_proposal(row: sqlite3.Row) -> EvolutionProposal:
    payload = json.loads(str(row["payload_json"]))
    if not isinstance(payload, dict):
        payload = {}
    return EvolutionProposal(
        proposal_id=str(row["proposal_id"]),
        owner=str(row["owner"]),
        kind=str(row["kind"]),
        title=str(row["title"]),
        payload=payload,
        status=str(row["status"]),
        created_at=float(row["created_at"]),
        decided_by=row["decided_by"],
        applied_path=row["applied_path"],
        benchmark_after=row["benchmark_after"],
    )


def load_baseline_score(path: Path | None = None) -> float:
    """Read the mock-benchmark floor from benchmarks/baseline.json."""

    baseline_path = path or Path(__file__).resolve().parents[2] / "benchmarks" / "baseline.json"
    raw = json.loads(baseline_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError("benchmark baseline is not an object")
    score = raw.get("overall_score")
    if isinstance(score, bool) or not isinstance(score, int | float):
        raise RuntimeError("benchmark baseline overall_score is invalid")
    return float(score)


def run_mock_benchmark() -> float:
    """Run the deterministic mock benchmark and return the overall score."""

    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-m", "benchmarks.runner", "--mock"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(f"mock benchmark failed: {result.stderr[-400:]}")
    for line in reversed(result.stdout.splitlines()):
        if "Overall score:" in line:
            return float(line.split(":", 1)[1].strip().split()[0])
    raise RuntimeError("mock benchmark did not report an overall score")
