"""Self-optimizing skill evolution via LLM-powered rewriting and A/B testing."""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.utils.db import db_connection
from js.utils.log import get_logger

logger = get_logger("js.skills.evolver")

# Type alias for LLM caller
LLMCaller = Callable[[str], Awaitable[str]]


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

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.db_path = state_dir / "skill_evolution.db"
        self._init_db()
        self._variants: dict[str, SkillVariant] = {}
        self._last_evolution: dict[str, float] = {}

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
                (variant.avg_score * (variant.total_count - 1) + score) / variant.total_count
            )

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
    ) -> str:
        """Generate improved code based on feedback using LLM."""
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
            return current_code

    async def evolve_skill(
        self,
        skill_id: str,
        current_code: str,
        llm_caller: LLMCaller | None = None,
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
            logger.debug(f"Skill {skill_id} success rate {success_rate:.2f} above threshold, skipping evolution")
            return None

        improved = await self.generate_improved_code(skill_id, current_code, feedback, llm_caller)
        if improved == current_code:
            return None

        test_cases = self._extract_test_cases(skill_id)
        variant = self.create_variant(skill_id, improved, "auto-evolved", test_cases)

        # Record generation lineage
        parent = self.select_best_variant(skill_id)
        with db_connection(self.db_path) as conn:
            generation = conn.execute(
                "SELECT COUNT(*) FROM evolution_generations WHERE skill_id = ?",
                (skill_id,),
            ).fetchone()[0] + 1
            conn.execute(
                """
                INSERT INTO evolution_generations (skill_id, generation, parent_variant, child_variant, improvement, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (skill_id, generation, parent.id if parent else None, variant.id, 0.0, time.time()),
            )
            conn.commit()

        self._last_evolution[skill_id] = time.time()
        logger.info(f"Created evolution variant {variant.id} (gen {generation}) for skill {skill_id}")
        return variant

    def should_evolve(self, skill_id: str) -> bool:
        """Check if a skill should be evolved based on recent performance."""
        success_rate = self._get_skill_success_rate(skill_id)
        if success_rate is None:
            return False
        if success_rate >= self.AUTO_EVOLVE_THRESHOLD:
            return False
        last = self._last_evolution.get(skill_id, 0)
        return time.time() - last >= self.EVOLUTION_COOLDOWN_SECONDS

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

    def _collect_feedback(self, skill_id: str) -> str:
        """Collect recent failure feedback for a skill."""
        with db_connection(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT code, prompt FROM skill_variants
                WHERE skill_id = ? AND total_count > 0
                ORDER BY created_at DESC LIMIT 5
                """,
                (skill_id,),
            ).fetchall()
        if rows:
            return f"Based on {len(rows)} recent variant executions"
        return ""

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
                logger.warning('Operation failed', exc_info=True)
        return [{"input": "example", "expected": "result"}]

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
            generations = conn.execute(
                "SELECT MAX(generation) FROM evolution_generations WHERE skill_id = ?", (skill_id,)
            ).fetchone()[0] or 0

        return {
            "skill_id": skill_id,
            "total_variants": total,
            "generations": generations,
            "best_variant": best[0] if best else None,
            "best_success_rate": best[1] / best[2] if best and best[2] > 0 else 0,
            "best_score": best[3] if best else 0,
            "should_evolve": self.should_evolve(skill_id),
        }
