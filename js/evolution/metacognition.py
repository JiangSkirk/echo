"""Metacognition loop: periodic system-wide reflection and auto-tuning.

Inspired by Hermes Agent's Autonomous Curator and OpenClaw's Dreaming Consolidation.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from js.compression.compressor import CompressionConfig
from js.compression.feedback import CompressionFeedback
from js.evolution.learner import SelfLearner
from js.evolution.optimizer import PromptOptimizer
from js.skills.auto_creator import AutoSkillCreator
from js.skills.evolver import SkillEvolver
from js.utils.db import db_connection
from js.utils.log import get_logger

if TYPE_CHECKING:
    from js.skills.composer import SkillComposer

logger = get_logger("js.metacognition")

_DEFAULT_MAX_REPORTS = 200
_DEFAULT_MAX_PROPOSALS = 1_000


@dataclass
class SystemReport:
    """A snapshot report of the agent's current state."""

    timestamp: float
    overall_health_score: float  # 0-1
    compression_quality: dict[str, Any]
    learning_stats: dict[str, Any]
    optimization_stats: dict[str, Any]
    evolution_stats: list[dict[str, Any]]
    proposals: list[dict[str, Any]]
    actions_taken: list[dict[str, Any]] = field(default_factory=list)


class MetacognitionLoop:
    """Periodic reflection scheduler that reviews all learning DBs.

    Generates "State of the System" reports with specific improvement proposals.
    Can operate in advisory mode (suggestions only) or auto-apply mode.
    """

    DEFAULT_INTERVAL = 10  # Run every N interactions (was 20, still too infrequent)

    def __init__(
        self,
        state_dir: Path,
        learner: SelfLearner | None = None,
        optimizer: PromptOptimizer | None = None,
        evolver: SkillEvolver | None = None,
        compression_feedback: CompressionFeedback | None = None,
        compression_config: CompressionConfig | None = None,
        composer: SkillComposer | None = None,
        auto_apply: bool = True,
    ) -> None:
        self.state_dir = state_dir
        self.db_path = state_dir / "metacognition.db"
        self.learner = learner
        self.optimizer = optimizer
        self.evolver = evolver
        self.compression_feedback = compression_feedback
        self.compression_config = compression_config
        self.composer = composer
        self.auto_creator = AutoSkillCreator(state_dir)
        self.auto_apply = auto_apply
        self._interaction_count = 0
        self._last_reflect_time: float = time.time()
        self._init_db()

    def _init_db(self) -> None:
        with db_connection(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    health_score REAL NOT NULL,
                    report_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS proposals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id INTEGER NOT NULL,
                    area TEXT NOT NULL,
                    proposal TEXT NOT NULL,
                    auto_applied INTEGER DEFAULT 0,
                    applied_at REAL
                )
            """)
            conn.commit()

    def tick(self) -> SystemReport | None:
        """Increment interaction counter and run reflection if interval reached.

        Triggers on either:
        - N interactions accumulated, OR
        - 30 minutes elapsed since last reflection (time-based fallback)
        """
        self._interaction_count += 1
        time_since_last = time.time() - self._last_reflect_time
        if self._interaction_count >= self.DEFAULT_INTERVAL or time_since_last >= 1800:
            self._interaction_count = 0
            return self.reflect()
        return None

    def reflect(self) -> SystemReport:
        """Generate a comprehensive system reflection report."""
        self._last_reflect_time = time.time()
        proposals: list[dict[str, Any]] = []
        actions_taken: list[dict[str, Any]] = []

        # 1. Analyze compression quality
        compression_quality = self._analyze_compression()
        for suggestion in compression_quality.get("suggestions", []):
            proposals.append(
                {
                    "area": "compression",
                    "issue": suggestion["issue"],
                    "proposal": suggestion["suggestion"],
                }
            )

        # 2. Analyze learning
        learning_stats = self._analyze_learning()
        for suggestion in learning_stats.get("suggestions", []):
            proposals.append(
                {
                    "area": "learning",
                    "issue": suggestion.get("area", "general"),
                    "proposal": suggestion["suggestion"],
                }
            )

        # 3. Analyze optimization
        optimization_stats = self._analyze_optimization()
        if optimization_stats.get("total_variants", 0) > 20:
            proposals.append(
                {
                    "area": "optimization",
                    "issue": f"{optimization_stats['total_variants']} prompt variants accumulated",
                    "proposal": "Prune low-performing variants to reduce DB size",
                }
            )

        # 4. Analyze skill evolution
        evolution_stats = self._analyze_evolution()
        for stat in evolution_stats:
            if stat.get("should_evolve"):
                proposals.append(
                    {
                        "area": "evolution",
                        "issue": f"Skill {stat['skill_id']} has low success rate",
                        "proposal": f"Trigger auto-evolution for {stat['skill_id']} (current best: {stat['best_success_rate'] * 100:.0f}%)",
                    }
                )

        # 5. Analyze composition chains
        composition_stats = self._analyze_composition()
        for chain in composition_stats.get("discovered", []):
            actions_taken.append(
                {
                    "area": "composition",
                    "action": f"Discovered chain: {chain.name}",
                    "chain_id": chain.id,
                }
            )

        # 6. Auto-generate skills from high-confidence patterns
        auto_skills = self._analyze_auto_skills()
        for spec in auto_skills:
            actions_taken.append(
                {
                    "area": "auto_skill",
                    "action": f"Created auto-skill: {spec.id}",
                    "skill_id": spec.id,
                }
            )

        # Compute overall health score
        scores: list[float] = []
        if compression_quality.get("total_events", 0) > 0:
            level_stats = compression_quality.get("level_stats", [])
            for stat in level_stats:
                if stat.get("success_rate") is not None:
                    scores.append(stat["success_rate"])

        for insight in learning_stats.get("insights", []):
            if "success_rate" in insight:
                scores.append(insight["success_rate"])

        overall_health = sum(scores) / len(scores) if scores else 1.0

        report = SystemReport(
            timestamp=time.time(),
            overall_health_score=overall_health,
            compression_quality=compression_quality,
            learning_stats=learning_stats,
            optimization_stats=optimization_stats,
            evolution_stats=evolution_stats,
            proposals=proposals,
            actions_taken=actions_taken,
        )

        # Auto-apply if enabled
        if self.auto_apply:
            actions_taken.extend(self._auto_apply_proposals(proposals))
            report.actions_taken = actions_taken

        # Persist report
        self._save_report(report)
        logger.info(
            f"Metacognition report generated: health={overall_health:.2f}, proposals={len(proposals)}, actions={len(actions_taken)}"
        )
        return report

    def _analyze_compression(self) -> dict[str, Any]:
        if self.compression_feedback:
            return self.compression_feedback.analyze()
        return {"total_events": 0, "suggestions": []}

    def _analyze_learning(self) -> dict[str, Any]:
        if self.learner:
            return {
                "stats": self.learner.get_stats(),
                "insights": self.learner.get_insights(limit=10),
                "suggestions": self.learner.suggest_improvements(),
            }
        return {"stats": {}, "insights": [], "suggestions": []}

    def _analyze_optimization(self) -> dict[str, Any]:
        if self.optimizer:
            return self.optimizer.get_report()
        return {}

    def _analyze_composition(self) -> dict[str, Any]:
        """Discover skill composition chains from transition logs."""
        if not self.composer:
            return {"discovered": []}
        try:
            chains = self.composer.discover_chains(min_frequency=3)
            return {"discovered": chains, "total_chains": len(chains)}
        except Exception:
            logger.warning("Composition analysis failed", exc_info=True)
            return {"discovered": []}

    def _analyze_auto_skills(self) -> list[Any]:
        """Create auto-skills from high-confidence learned patterns."""
        created: list[Any] = []
        if not self.learner:
            return created
        try:
            with db_connection(self.learner.db_path) as conn:
                rows = conn.execute(
                    """
                    SELECT pattern, frequency, success_rate
                    FROM learned_patterns
                    WHERE owner_key_hash = ?
                      AND frequency >= ? AND success_rate >= ?
                    ORDER BY frequency DESC, success_rate DESC
                    LIMIT 5
                    """,
                    (self.learner.default_owner_key_hash, 10, 0.8),
                ).fetchall()

            for pattern, frequency, success_rate in rows:
                if self.auto_creator.should_create(frequency, success_rate):
                    spec = self.auto_creator.create_from_pattern(pattern)
                    if spec:
                        created.append(spec)
        except Exception:
            logger.warning("Auto-skill analysis failed", exc_info=True)
        return created

    def _analyze_evolution(self) -> list[dict[str, Any]]:
        """Analyze skill evolution status by querying the evolver's DB."""
        if not self.evolver:
            return []
        # Query skill_variants table for skills with enough data
        try:
            with db_connection(self.evolver.db_path) as conn:
                rows = conn.execute("""
                    SELECT skill_id,
                           SUM(success_count) as total_success,
                           SUM(total_count) as total_executions,
                           COUNT(*) as variant_count
                    FROM skill_variants
                    GROUP BY skill_id
                    HAVING total_executions >= 5
                """).fetchall()
        except Exception:
            return []

        stats = []
        for skill_id, total_success, total_executions, variant_count in rows:
            success_rate = (
                float(total_success) / float(total_executions) if total_executions > 0 else 1.0
            )
            stats.append(
                {
                    "skill_id": skill_id,
                    "success_rate": success_rate,
                    "total_executions": total_executions,
                    "variant_count": variant_count,
                    "should_evolve": success_rate < 0.7,
                    "best_success_rate": success_rate,
                }
            )
        return stats

    def _auto_apply_proposals(self, proposals: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Auto-apply safe proposals."""
        actions: list[dict[str, Any]] = []
        for proposal in proposals:
            area = proposal["area"]
            if (
                area == "compression"
                and self.compression_feedback is not None
                and self.compression_config is not None
            ):
                # Auto-adjust compression parameters based on feedback
                recs = self.compression_feedback.get_adjustment_recommendations()
                if recs.get("needs_adjustment"):
                    for param, data in recs.get("recommendations", {}).items():
                        if hasattr(self.compression_config, param):
                            current = getattr(self.compression_config, param)
                            new_value = current + data.get("recommended_delta", 0)
                            setattr(self.compression_config, param, new_value)
                            self.compression_feedback.apply_adjustment(
                                param, new_value, data.get("reason", "")
                            )
                            actions.append(
                                {
                                    "area": area,
                                    "action": f"Adjusted {param} to {new_value}",
                                    "reason": data.get("reason"),
                                }
                            )
            elif area == "optimization":
                if self.optimizer:
                    # Mark as suggested; actual pruning would need an optimizer method
                    actions.append(
                        {
                            "area": area,
                            "action": "Suggested pruning old prompt variants",
                            "reason": proposal["issue"],
                        }
                    )
            elif area == "learning":
                # Learning proposals are advisory — no direct action needed
                actions.append(
                    {
                        "area": area,
                        "action": "Noted learning pattern for future prompts",
                        "reason": proposal["issue"],
                    }
                )
            # Evolution proposals are NOT auto-applied — they require async LLM calls
        return actions

    def _save_report(self, report: SystemReport) -> None:
        with db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO reports (timestamp, health_score, report_json) VALUES (?, ?, ?)",
                (report.timestamp, report.overall_health_score, json.dumps(report.__dict__)),
            )
            report_id = cursor.lastrowid
            for proposal in report.proposals:
                conn.execute(
                    "INSERT INTO proposals (report_id, area, proposal) VALUES (?, ?, ?)",
                    (report_id, proposal["area"], proposal["proposal"]),
                )
            conn.commit()

    def get_recent_reports(self, limit: int = 5) -> list[dict[str, Any]]:
        """Get recent metacognition reports."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT timestamp, health_score, report_json FROM reports ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        reports = []
        for r in rows:
            try:
                data = json.loads(r["report_json"])
                data["timestamp"] = r["timestamp"]
                data["health_score"] = r["health_score"]
                reports.append(data)
            except json.JSONDecodeError:
                logger.warning("Operation failed", exc_info=True)
        return reports

    def get_proposals(self, area: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        """Get pending or historical proposals."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if area:
                rows = conn.execute(
                    "SELECT * FROM proposals WHERE area = ? ORDER BY id DESC LIMIT ?",
                    (area, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM proposals ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [dict(r) for r in rows]

    def prune(
        self,
        *,
        max_reports: int = _DEFAULT_MAX_REPORTS,
        max_proposals: int = _DEFAULT_MAX_PROPOSALS,
    ) -> int:
        """Bound reflection reports and remove proposals without a retained report."""
        if max_reports < 0:
            raise ValueError("max_reports must be non-negative")
        if max_proposals < 0:
            raise ValueError("max_proposals must be non-negative")

        with db_connection(self.db_path) as conn:
            changes_before = conn.total_changes
            conn.execute(
                """
                DELETE FROM reports
                WHERE id IN (
                    SELECT id FROM reports
                    ORDER BY timestamp DESC, id DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (max_reports,),
            )
            conn.execute(
                """
                DELETE FROM proposals
                WHERE report_id NOT IN (SELECT id FROM reports)
                """
            )
            conn.execute(
                """
                DELETE FROM proposals
                WHERE id IN (
                    SELECT id FROM proposals
                    ORDER BY id DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (max_proposals,),
            )
            conn.commit()
            return conn.total_changes - changes_before
