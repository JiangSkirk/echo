"""Autonomous prompt and strategy optimization with LLM-driven mutation."""

from __future__ import annotations

import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.utils.db import db_connection
from js.utils.log import get_logger

logger = get_logger("js.optimizer")

LLMCaller = Callable[[str], Awaitable[str]]

_DEFAULT_MAX_RESULTS = 1_000
_DEFAULT_MAX_VARIANTS_TOTAL = 1_000


@dataclass
class PromptVariant:
    id: str
    context: str
    prompt_template: str
    success_rate: float
    avg_score: float
    usage_count: int


class PromptOptimizer:
    """Optimizes prompts through A/B testing, epsilon-greedy exploration, and LLM-driven mutation."""

    EPSILON = 0.20  # 20% random exploration
    MAX_VARIANTS_PER_CONTEXT = 10

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.db_path = state_dir / "prompt_optimization.db"
        self._init_db()

    def _init_db(self) -> None:
        with db_connection(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS prompt_variants (
                    id TEXT PRIMARY KEY,
                    context TEXT NOT NULL,
                    prompt_template TEXT NOT NULL,
                    success_rate REAL DEFAULT 1.0,
                    avg_score REAL DEFAULT 1.0,
                    usage_count INTEGER DEFAULT 0,
                    mutation_type TEXT,
                    created_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS prompt_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    variant_id TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    score REAL NOT NULL,
                    context TEXT,
                    used_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_variants_context ON prompt_variants(context)
            """)
            # Migrate old tables missing mutation_type column
            cols = {row[1] for row in conn.execute("PRAGMA table_info(prompt_variants)")}
            if "mutation_type" not in cols:
                conn.execute("ALTER TABLE prompt_variants ADD COLUMN mutation_type TEXT")
            conn.commit()

    def register_variant(
        self,
        context: str,
        prompt_template: str,
        mutation_type: str = "manual",
    ) -> str:
        """Register a new prompt variant for testing."""
        import uuid

        variant_id = f"{context}_{uuid.uuid4().hex[:8]}"
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO prompt_variants (id, context, prompt_template, mutation_type, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (variant_id, context, prompt_template, mutation_type, time.time()),
            )
            conn.commit()
        return variant_id

    def record_result(
        self, variant_id: str, success: bool, score: float, context: str = ""
    ) -> None:
        """Record the result of using a prompt variant."""
        with db_connection(self.db_path) as conn:
            conn.execute(
                "INSERT INTO prompt_results (variant_id, success, score, context, used_at) VALUES (?, ?, ?, ?, ?)",
                (variant_id, int(success), score, context, time.time()),
            )
            # Update variant stats
            stats = conn.execute(
                "SELECT AVG(success), AVG(score), COUNT(*) FROM prompt_results WHERE variant_id = ?",
                (variant_id,),
            ).fetchone()
            if stats:
                conn.execute(
                    "UPDATE prompt_variants SET success_rate = ?, avg_score = ?, usage_count = ? WHERE id = ?",
                    (stats[0], stats[1], stats[2], variant_id),
                )
            conn.commit()

    def get_best_prompt(self, context: str) -> str | None:
        """Get the best performing prompt for a context."""
        with db_connection(self.db_path) as conn:
            row = conn.execute(
                """
                SELECT prompt_template FROM prompt_variants
                WHERE context = ? AND usage_count > 0
                ORDER BY success_rate DESC, avg_score DESC
                LIMIT 1
                """,
                (context,),
            ).fetchone()
        return row[0] if row else None

    def select_variant(self, context: str) -> tuple[str, str] | None:
        """Epsilon-greedy variant selection: 80% best-known, 20% random."""
        with db_connection(self.db_path) as conn:
            variants = conn.execute(
                "SELECT id, prompt_template FROM prompt_variants WHERE context = ?",
                (context,),
            ).fetchall()
        if not variants:
            return None

        if random.random() < self.EPSILON:
            # Exploration: random variant
            chosen = random.choice(variants)
            logger.debug(f"Exploration: selected random variant {chosen[0]}")
            return chosen[0], chosen[1]

        # Exploitation: best variant
        best = self.get_best_prompt(context)
        if best:
            for vid, pt in variants:
                if pt == best:
                    return vid, pt

        # Fallback to first variant
        return variants[0][0], variants[0][1]

    async def generate_variant(
        self,
        context: str,
        base_prompt: str,
        llm_caller: LLMCaller | None = None,
        recent_failures: list[str] | None = None,
    ) -> str:
        """Generate a new variant by mutating the base prompt using LLM."""
        if not llm_caller:
            # Fallback to simple mutations
            mutations = [
                (base_prompt + "\n\nBe concise and direct.", "add_constraint"),
                (base_prompt + "\n\nProvide step-by-step reasoning.", "add_reasoning"),
                ("You are an expert. " + base_prompt, "add_expertise"),
                (base_prompt.replace("helpful", "precise and thorough"), "word_replace"),
            ]
            variant, mutation_type = random.choice(mutations)
            self.register_variant(context, variant, mutation_type)
            return variant

        failure_context = ""
        if recent_failures:
            failure_context = "\n## Recent Failures\n" + "\n".join(
                f"- {f}" for f in recent_failures[:5]
            )

        prompt = (
            f"You are a prompt engineering expert. Improve the following prompt.\n\n"
            f"## Original Prompt\n{base_prompt}\n"
            f"{failure_context}\n\n"
            f"## Instructions\n"
            f"Generate 3 improved variants. For each, explain the mutation strategy used. "
            f"Use these mutation types: add_constraint, add_example, simplify, reorder_instructions, add_reasoning_chain.\n\n"
            f"Format your response as:\n"
            f"VARIANT 1 [mutation_type]: <improved prompt>\n"
            f"VARIANT 2 [mutation_type]: <improved prompt>\n"
            f"VARIANT 3 [mutation_type]: <improved prompt>"
        )
        try:
            response = await llm_caller(prompt)
            variants = self._parse_llm_variants(response)
            if variants:
                chosen = random.choice(variants)
                self.register_variant(context, chosen[0], chosen[1])
                return chosen[0]
        except Exception as e:
            logger.warning(f"LLM prompt mutation failed: {e}")

        # Fallback
        return base_prompt

    def _parse_llm_variants(self, response: str) -> list[tuple[str, str]]:
        """Parse variant prompts from LLM response."""
        variants: list[tuple[str, str]] = []
        for line in response.splitlines():
            if line.startswith("VARIANT") and "[" in line and "]" in line and ":" in line:
                bracket_start = line.index("[")
                bracket_end = line.index("]")
                colon_idx = line.index(":")
                mutation_type = line[bracket_start + 1 : bracket_end].strip()
                prompt_text = line[colon_idx + 1 :].strip()
                if prompt_text and len(prompt_text) > 20:
                    variants.append((prompt_text, mutation_type))
        return variants

    async def optimize_cycle(
        self,
        context: str,
        current_prompt: str,
        llm_caller: LLMCaller | None = None,
    ) -> str:
        """Run one optimization cycle: generate variant, return best or new."""
        # Generate a new LLM-driven variant
        await self.generate_variant(context, current_prompt, llm_caller)
        # Return best-known (may be the original or a past variant)
        best = self.get_best_prompt(context)
        return best or current_prompt

    def get_report(self) -> dict[str, Any]:
        """Get optimization report."""
        with db_connection(self.db_path) as conn:
            total_variants = conn.execute("SELECT COUNT(*) FROM prompt_variants").fetchone()[0]
            total_tests = conn.execute("SELECT COUNT(*) FROM prompt_results").fetchone()[0]
            best = conn.execute(
                """
                SELECT context, prompt_template, success_rate, usage_count
                FROM prompt_variants
                WHERE usage_count > 0
                ORDER BY success_rate DESC LIMIT 1
                """
            ).fetchone()
            contexts = conn.execute(
                "SELECT context, COUNT(*) FROM prompt_variants GROUP BY context"
            ).fetchall()

        return {
            "total_variants": total_variants,
            "total_tests": total_tests,
            "best_context": best[0] if best else None,
            "best_success_rate": best[2] if best else 0,
            "best_usage": best[3] if best else 0,
            "contexts": dict(contexts),
        }

    def prune(
        self,
        *,
        max_results: int = _DEFAULT_MAX_RESULTS,
        max_variants_per_context: int = MAX_VARIANTS_PER_CONTEXT,
        max_variants_total: int = _DEFAULT_MAX_VARIANTS_TOTAL,
    ) -> int:
        """Bound prompt experiments and recompute statistics from retained rows."""
        limits = {
            "max_results": max_results,
            "max_variants_per_context": max_variants_per_context,
            "max_variants_total": max_variants_total,
        }
        for name, value in limits.items():
            if value < 0:
                raise ValueError(f"{name} must be non-negative")

        with db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            changes_before = conn.total_changes
            conn.execute(
                """
                CREATE TEMP TABLE prompt_variant_prune_candidates AS
                WITH ranked AS (
                    SELECT id,
                           ROW_NUMBER() OVER (
                               PARTITION BY context
                               ORDER BY created_at DESC, id DESC
                           ) AS context_rank
                    FROM prompt_variants
                )
                SELECT id FROM ranked WHERE context_rank > ?
                """,
                (max_variants_per_context,),
            )
            conn.execute(
                """
                INSERT INTO prompt_variant_prune_candidates (id)
                SELECT id FROM prompt_variants
                WHERE id NOT IN (SELECT id FROM prompt_variant_prune_candidates)
                ORDER BY created_at DESC, id DESC
                LIMIT -1 OFFSET ?
                """,
                (max_variants_total,),
            )
            conn.execute(
                """
                DELETE FROM prompt_results
                WHERE variant_id IN (SELECT id FROM prompt_variant_prune_candidates)
                """
            )
            conn.execute(
                """
                DELETE FROM prompt_variants
                WHERE id IN (SELECT id FROM prompt_variant_prune_candidates)
                """
            )
            conn.execute(
                """
                DELETE FROM prompt_results
                WHERE id IN (
                    SELECT id FROM prompt_results
                    ORDER BY used_at DESC, id DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (max_results,),
            )
            removed = conn.total_changes - changes_before
            conn.execute(
                """
                UPDATE prompt_variants
                SET success_rate = COALESCE(
                        (SELECT AVG(success) FROM prompt_results
                         WHERE variant_id = prompt_variants.id),
                        1.0
                    ),
                    avg_score = COALESCE(
                        (SELECT AVG(score) FROM prompt_results
                         WHERE variant_id = prompt_variants.id),
                        1.0
                    ),
                    usage_count = (
                        SELECT COUNT(*) FROM prompt_results
                        WHERE variant_id = prompt_variants.id
                    )
                """
            )
            conn.commit()
            return removed
