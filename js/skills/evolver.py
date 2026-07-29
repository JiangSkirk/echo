"""Self-optimizing skill evolution via LLM-powered rewriting and A/B testing."""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from js.utils.db import db_connection
from js.utils.log import get_logger

if TYPE_CHECKING:
    from js.skills.promotion_store import PromotionStore

logger = get_logger("js.skills.evolver")

# Type alias for LLM caller
LLMCaller = Callable[[str], Awaitable[str]]


def _is_protected_for_promote(skill_id: str, skill_path: Path | None) -> bool:
    """Return True if skill_id refers to a protected skill (builtin or Hermes).

    v0.1.4-alpha hardening: builtin and Hermes skills must never be overwritten
    by auto-promotion. We check by id prefix first (cheap) and fall back to
    parsing the SKILL.md frontmatter trust_level when a path is provided.
    Any parse failure is treated as "not protected" so the existing failure
    path in promote_variant still runs.
    """
    if skill_id.startswith("hermes:"):
        return True
    if skill_path is None:
        return False
    manifest = skill_path / "SKILL.md"
    if not manifest.exists():
        return False
    try:
        from js.skills.spec import TrustLevel, parse_skill_manifest

        spec = parse_skill_manifest(manifest)
        return spec.trust_level == TrustLevel.BUILTIN
    except Exception:
        return False


@dataclass
class SkillVariant:
    id: str
    skill_id: str
    code: str
    prompt: str
    test_cases: list[dict[str, Any]]
    success_count: int = 0
    total_count: int = 0
    avg_score: float = 0.0
    created_at: float = 0.0


class SkillEvolver:
    """Evolves skills by generating variants via LLM, A/B testing, and selecting winners."""

    AUTO_EVOLVE_THRESHOLD = 0.7  # Trigger evolution when success_rate drops below this
    MIN_EXECUTIONS = 5  # Minimum executions before considering evolution
    EVOLUTION_COOLDOWN_SECONDS = 3600  # Max 1 evolution per skill per hour

    def __init__(
        self,
        state_dir: Path,
        *,
        promotion_store: PromotionStore | None = None,
        proposals_dir: Path | None = None,
        owner_key_hash: str | None = None,
    ) -> None:
        self.state_dir = state_dir
        self.db_path = state_dir / "skill_evolution.db"
        self._init_db()
        self._variants: dict[str, SkillVariant] = {}
        self._last_evolution: dict[str, float] = {}
        # v0.1.5-alpha: when a promotion store is wired, ``promote_variant``
        # stops overwriting the entry file — it writes the candidate code into
        # ``proposals_dir / <variant_id> / <entry>`` and inserts a ``proposed``
        # row instead. Operators apply via ``SkillManager.apply_proposal``.
        self.promotion_store: PromotionStore | None = promotion_store
        self.proposals_dir: Path = proposals_dir or (state_dir / "skill_proposals")
        self._owner_key_hash: str | None = owner_key_hash
        # Filled by the most recent promote_variant call when a proposal is
        # created — lets callers surface the event_id without parsing logs.
        self.last_proposal_event_id: str | None = None

    def _init_db(self) -> None:
        with db_connection(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS skill_variants (
                    id TEXT PRIMARY KEY,
                    skill_id TEXT NOT NULL,
                    code TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    test_cases TEXT NOT NULL,
                    success_count INTEGER DEFAULT 0,
                    total_count INTEGER DEFAULT 0,
                    avg_score REAL DEFAULT 0.0,
                    created_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evolution_generations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    skill_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    parent_variant TEXT,
                    child_variant TEXT,
                    improvement REAL,
                    created_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS test_case_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    variant_id TEXT NOT NULL,
                    test_input TEXT NOT NULL,
                    expected TEXT,
                    actual TEXT,
                    passed INTEGER NOT NULL,
                    executed_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS skill_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    skill_id TEXT NOT NULL,
                    variant_id TEXT,
                    success INTEGER NOT NULL,
                    score REAL,
                    error_message TEXT,
                    context TEXT,
                    created_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_feedback_skill ON skill_feedback(skill_id)
            """)
            conn.commit()

    def create_variant(
        self,
        skill_id: str,
        code: str,
        prompt: str,
        test_cases: list[dict[str, Any]],
    ) -> SkillVariant:
        """Create a new variant for A/B testing."""
        import uuid

        variant_id = f"{skill_id}_{uuid.uuid4().hex[:8]}"
        variant = SkillVariant(
            id=variant_id,
            skill_id=skill_id,
            code=code,
            prompt=prompt,
            test_cases=test_cases,
            created_at=time.time(),
        )
        self._variants[variant_id] = variant
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO skill_variants (id, skill_id, code, prompt, test_cases, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (variant_id, skill_id, code, prompt, json.dumps(test_cases), variant.created_at),
            )
            conn.commit()
        return variant

    def record_result(self, variant_id: str, success: bool, score: float) -> None:
        """Record execution result for a variant."""
        variant = self._variants.get(variant_id)
        if variant:
            variant.total_count += 1
            if success:
                variant.success_count += 1
            variant.avg_score = (
                variant.avg_score * (variant.total_count - 1) + score
            ) / variant.total_count

        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                UPDATE skill_variants
                SET success_count = success_count + ?,
                    total_count = total_count + 1,
                    avg_score = (avg_score * total_count + ?) / (total_count + 1)
                WHERE id = ?
                """,
                (int(success), score, variant_id),
            )
            conn.commit()

    def select_best_variant(self, skill_id: str) -> SkillVariant | None:
        """Select the best variant based on success rate and score."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT * FROM skill_variants
                WHERE skill_id = ? AND total_count > 0
                ORDER BY (success_count * 1.0 / total_count) DESC, avg_score DESC
                LIMIT 1
                """,
                (skill_id,),
            ).fetchone()

        if row:
            return SkillVariant(
                id=row["id"],
                skill_id=row["skill_id"],
                code=row["code"],
                prompt=row["prompt"],
                test_cases=json.loads(row["test_cases"]),
                success_count=row["success_count"],
                total_count=row["total_count"],
                avg_score=row["avg_score"],
                created_at=row["created_at"],
            )
        return None

    async def generate_improved_code(
        self,
        skill_id: str,
        current_code: str,
        feedback: str,
        llm_caller: LLMCaller | None = None,
        *,
        propagate_llm_errors: bool = False,
    ) -> str:
        """Generate improved code, optionally surfacing model-call failures."""
        if not llm_caller:
            # Fallback: mark as needing evolution without LLM
            lines = current_code.splitlines()
            fallback_lines = [f"# Auto-evolved at {time.time()}"]
            fallback_lines.append(f"# Feedback incorporated: {feedback[:100]}...")
            fallback_lines.extend(lines)
            return "\n".join(fallback_lines)

        prompt = (
            f"You are an expert code optimization agent. A skill has been underperforming.\n\n"
            f"## Current Skill Code\n```python\n{current_code}\n```\n\n"
            f"## Recent Feedback / Errors\n{feedback}\n\n"
            f"## Instructions\n"
            f"Rewrite the skill code to fix the issues. Preserve the function signatures and overall structure. "
            f"Add error handling where appropriate. Return ONLY the improved code, no explanations."
        )
        try:
            improved = await llm_caller(prompt)
            # Basic validation: must contain some Python-like structure
            if "def " not in improved and "import " not in improved and "class " not in improved:
                logger.warning(f"LLM returned non-code output for skill {skill_id}, using fallback")
                return current_code
            return improved
        except Exception as e:
            logger.warning(f"LLM code evolution failed for {skill_id}: {e}")
            if propagate_llm_errors:
                raise
            return current_code

    async def evolve_skill(
        self,
        skill_id: str,
        current_code: str,
        llm_caller: LLMCaller | None = None,
        *,
        propagate_llm_errors: bool = False,
    ) -> SkillVariant | None:
        """Run one evolution cycle: collect feedback, generate improved variant, record."""
        # Check cooldown
        last = self._last_evolution.get(skill_id, 0)
        if time.time() - last < self.EVOLUTION_COOLDOWN_SECONDS:
            logger.debug(f"Evolution cooldown active for {skill_id}")
            return None

        feedback = self._collect_feedback(skill_id)
        if not feedback:
            return None

        # Check if evolution is warranted
        success_rate = self._get_skill_success_rate(skill_id)
        if success_rate is not None and success_rate >= self.AUTO_EVOLVE_THRESHOLD:
            logger.debug(
                f"Skill {skill_id} success rate {success_rate:.2f} above threshold, skipping evolution"
            )
            return None

        improved = await self.generate_improved_code(
            skill_id,
            current_code,
            feedback,
            llm_caller,
            propagate_llm_errors=propagate_llm_errors,
        )
        if improved == current_code:
            return None

        test_cases = self._extract_test_cases(skill_id)
        variant = self.create_variant(skill_id, improved, "auto-evolved", test_cases)

        # Record generation lineage
        parent = self.select_best_variant(skill_id)
        with db_connection(self.db_path) as conn:
            generation = (
                conn.execute(
                    "SELECT COUNT(*) FROM evolution_generations WHERE skill_id = ?",
                    (skill_id,),
                ).fetchone()[0]
                + 1
            )
            conn.execute(
                """
                INSERT INTO evolution_generations (skill_id, generation, parent_variant, child_variant, improvement, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (skill_id, generation, parent.id if parent else None, variant.id, 0.0, time.time()),
            )
            conn.commit()

        self._last_evolution[skill_id] = time.time()
        logger.info(
            f"Created evolution variant {variant.id} (gen {generation}) for skill {skill_id}"
        )
        return variant

    def should_evolve(self, skill_id: str) -> bool:
        """Check if a skill should be evolved based on recent performance."""
        return skill_id in self.should_evolve_many((skill_id,))

    def should_evolve_many(self, skill_ids: Iterable[str]) -> set[str]:
        """Return underperforming skills using one bounded database connection."""
        now = time.time()
        eligible = tuple(
            dict.fromkeys(
                skill_id
                for skill_id in skill_ids
                if now - self._last_evolution.get(skill_id, 0)
                >= self.EVOLUTION_COOLDOWN_SECONDS
            )
        )
        if not eligible:
            return set()

        aggregates: dict[str, tuple[int, int]] = {}
        with db_connection(self.db_path) as conn:
            for start in range(0, len(eligible), 500):
                chunk = eligible[start : start + 500]
                placeholders = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"""
                    SELECT skill_id, SUM(success_count), SUM(total_count)
                    FROM skill_variants
                    WHERE skill_id IN ({placeholders})
                    GROUP BY skill_id
                    """,
                    chunk,
                ).fetchall()
                for skill_id, successes, total in rows:
                    aggregates[str(skill_id)] = (int(successes or 0), int(total or 0))

        return {
            skill_id
            for skill_id, (successes, total) in aggregates.items()
            if total >= self.MIN_EXECUTIONS
            and float(successes) / float(total) < self.AUTO_EVOLVE_THRESHOLD
        }

    def _get_skill_success_rate(self, skill_id: str) -> float | None:
        """Get the current success rate for a skill."""
        with db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT SUM(success_count), SUM(total_count) FROM skill_variants WHERE skill_id = ?",
                (skill_id,),
            ).fetchone()
        if row and row[1] and row[1] >= self.MIN_EXECUTIONS:
            return float(row[0] or 0) / float(row[1])
        return None

    def record_execution_feedback(
        self,
        skill_id: str,
        success: bool,
        score: float,
        error_message: str = "",
        context: str = "",
        variant_id: str | None = None,
    ) -> None:
        """Record detailed feedback from a single skill execution."""
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO skill_feedback
                    (skill_id, variant_id, success, score, error_message, context, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (skill_id, variant_id, int(success), score, error_message, context, time.time()),
            )
            conn.commit()

    def _collect_feedback(self, skill_id: str) -> str:
        """Collect recent failure feedback for a skill.

        Returns a structured summary of recent errors and performance trends.
        """
        with db_connection(self.db_path) as conn:
            # Recent failures with error messages
            rows = conn.execute(
                """
                SELECT success, score, error_message, created_at
                FROM skill_feedback
                WHERE skill_id = ?
                ORDER BY created_at DESC
                LIMIT 20
                """,
                (skill_id,),
            ).fetchall()
            total = conn.execute(
                """
                SELECT COUNT(*), SUM(success) FROM skill_feedback
                WHERE skill_id = ? AND created_at > ?
                """,
                (skill_id, time.time() - 86400),
            ).fetchone()

        if not rows:
            return ""

        failures = [r for r in rows if not r[0] and r[2]]
        failure_msgs: list[str] = []
        seen: set[str] = set()
        for r in failures:
            msg = r[2].strip()
            if msg and msg not in seen:
                seen.add(msg)
                failure_msgs.append(msg)

        recent_rate = (total[1] or 0) / max(total[0] or 1, 1)
        parts: list[str] = []
        parts.append(
            f"Recent 24h success rate: {recent_rate:.1%} ({total[1] or 0}/{total[0] or 0})"
        )
        if failure_msgs:
            parts.append("Recent errors:")
            for msg in failure_msgs[:5]:
                parts.append(f"  - {msg[:200]}")
        return "\n".join(parts)

    def _extract_test_cases(self, skill_id: str) -> list[dict[str, Any]]:
        """Extract test cases from skill history."""
        with db_connection(self.db_path) as conn:
            rows = conn.execute(
                "SELECT test_cases FROM skill_variants WHERE skill_id = ? AND test_cases != '[]' ORDER BY created_at DESC LIMIT 1",
                (skill_id,),
            ).fetchall()
        if rows:
            try:
                parsed: list[dict[str, Any]] = json.loads(rows[0][0])
                return parsed
            except json.JSONDecodeError:
                logger.warning("Operation failed", exc_info=True)
        return [{"input": "example", "expected": "result"}]

    def promote_variant(
        self, skill_id: str, skill_path: Path | None = None, entry: str = "main.py"
    ) -> bool:
        """Promote the best variant for a skill.

        Legacy behaviour (``promotion_store is None``): writes the winning
        variant's code back to the skill's entry file and returns True.

        v0.1.5-alpha behaviour (``promotion_store`` wired): writes the variant
        code to ``proposals_dir/<variant_id>/<entry>``, inserts a ``proposed``
        promotion event with ``source="auto_evolver"``, and returns False
        (since trust / file mutation has NOT yet happened). The caller can
        read ``self.last_proposal_event_id`` if it needs the event id.

        v0.1.4-alpha hardening: builtin and Hermes skills are PROTECTED from
        automatic promotion. Even if a variant performs well, the original
        entry file is never overwritten and no proposal is ever recorded.
        """
        self.last_proposal_event_id = None

        if _is_protected_for_promote(skill_id, skill_path):
            logger.info(
                "Skipping auto-promote for protected skill %s (builtin or hermes)",
                skill_id,
            )
            return False

        best = self.select_best_variant(skill_id)
        if not best:
            return False

        if best.total_count < self.MIN_EXECUTIONS:
            logger.debug(
                "Variant %s has only %d executions, need %d for promotion",
                best.id,
                best.total_count,
                self.MIN_EXECUTIONS,
            )
            return False

        success_rate = best.success_count / best.total_count
        if success_rate < self.AUTO_EVOLVE_THRESHOLD:
            logger.debug(
                "Variant %s success rate %.2f below threshold %.2f, skipping promotion",
                best.id,
                success_rate,
                self.AUTO_EVOLVE_THRESHOLD,
            )
            return False

        if skill_path is None:
            logger.debug("No skill_path provided for %s, cannot promote", skill_id)
            return False

        entry_file = skill_path / entry
        if not entry_file.exists():
            logger.warning("Entry file not found for skill %s: %s", skill_id, entry_file)
            return False

        # v0.1.5-alpha: gated proposal path.
        if self.promotion_store is not None:
            try:
                artifact_dir = self.proposals_dir / best.id
                artifact_dir.mkdir(parents=True, exist_ok=True)
                artifact_path = artifact_dir / entry
                artifact_path.write_text(best.code, encoding="utf-8")
                reason = (
                    f"auto_evolver: variant {best.id} success_rate={success_rate:.2f} "
                    f"(score={best.avg_score:.2f}, runs={best.total_count})"
                )
                # to_level == from_level: evolver proposals don't change trust,
                # they only swap the entry file contents. The gate is what
                # actually decides whether the swap is safe.
                event_id = self.promotion_store.propose(
                    skill_id,
                    "evolver",  # synthetic placeholder; trust isn't moving
                    "evolver",
                    "auto_evolver",
                    reason,
                    owner_key_hash=self._owner_key_hash,
                    decided_by="auto",
                    variant_id=best.id,
                    artifact_path=str(artifact_path),
                    details={
                        "success_rate": success_rate,
                        "avg_score": best.avg_score,
                        "total_count": best.total_count,
                        "entry": entry,
                    },
                )
                self.last_proposal_event_id = event_id
                logger.info(
                    "Evolver proposed variant %s for skill %s (event=%s)",
                    best.id,
                    skill_id,
                    event_id,
                )
                # Proposal recorded; entry file unchanged. Caller treats
                # False as "no direct apply happened yet".
                return False
            except Exception:
                logger.warning(
                    "Failed to record evolver proposal for %s",
                    skill_id,
                    exc_info=True,
                )
                # Fall through — do NOT silently overwrite the entry file
                # when the gated path errored; legacy callers expect the
                # in-place write only when no store is wired.
                return False

        # Legacy: direct in-place overwrite (kept for tests / CLIs that
        # haven't wired a PromotionStore yet).
        try:
            entry_file.write_text(best.code, encoding="utf-8")
            logger.info(
                "Promoted variant %s (success_rate=%.2f) to skill %s (legacy direct path)",
                best.id,
                success_rate,
                skill_id,
            )
            return True
        except Exception as e:
            logger.warning("Failed to promote variant %s: %s", best.id, e)
            return False

    def get_evolution_report(self, skill_id: str) -> dict[str, Any]:
        """Get evolution statistics for a skill."""
        with db_connection(self.db_path) as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM skill_variants WHERE skill_id = ?", (skill_id,)
            ).fetchone()[0]
            best = conn.execute(
                """
                SELECT id, success_count, total_count, avg_score
                FROM skill_variants WHERE skill_id = ? AND total_count > 0
                ORDER BY (success_count * 1.0 / total_count) DESC LIMIT 1
                """,
                (skill_id,),
            ).fetchone()
            generations = (
                conn.execute(
                    "SELECT MAX(generation) FROM evolution_generations WHERE skill_id = ?",
                    (skill_id,),
                ).fetchone()[0]
                or 0
            )
            feedback_count = conn.execute(
                "SELECT COUNT(*) FROM skill_feedback WHERE skill_id = ?", (skill_id,)
            ).fetchone()[0]

        return {
            "skill_id": skill_id,
            "total_variants": total,
            "generations": generations,
            "feedback_count": feedback_count,
            "best_variant": best[0] if best else None,
            "best_success_rate": best[1] / best[2] if best and best[2] > 0 else 0,
            "best_score": best[3] if best else 0,
            "should_evolve": self.should_evolve(skill_id),
        }
