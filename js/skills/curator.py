"""Autonomous Skill Curator Agent.

Scans all skills periodically: flags duplicates, quarantines unused skills,
promotes high-performing community skills, generates health reports.

Inspired by Hermes Agent's Autonomous Curator (7-day cycle).

v0.1.5-alpha: curator no longer mutates ``spec.trust_level`` directly when a
``PromotionStore`` (and ``SkillManager``) are wired in. Auto-promote becomes
``propose`` (operator approval required); auto-demote-to-quarantine routes
through ``SkillManager.trust_skill`` so the tool registry is correctly flipped
and an audit row is written. The pre-v0.1.5 direct-mutation path is preserved
for callers that haven't been wired up yet.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from js.skills.spec import SkillSpec, TrustLevel
from js.utils.db import db_connection
from js.utils.log import get_logger

if TYPE_CHECKING:
    from js.skills.manager import SkillManager
    from js.skills.promotion_store import PromotionStore

logger = get_logger("js.skills.curator")


@dataclass
class SkillHealth:
    """Health assessment for a single skill."""

    skill_id: str
    status: str  # "healthy", "stale", "duplicate", "underperforming"
    usage_count: int
    success_rate: float
    days_since_last_use: float
    recommendation: str


class SkillCurator:
    """Periodic skill health reviewer and maintenance agent."""

    STALE_DAYS = 30  # Skills unused for 30 days are flagged stale
    UNDERPERFORM_THRESHOLD = 0.5  # Success rate below 50% is underperforming

    def __init__(
        self,
        state_dir: Path,
        *,
        promotion_store: PromotionStore | None = None,
        skill_manager: SkillManager | None = None,
        owner_key_hash: str | None = None,
    ) -> None:
        self.state_dir = state_dir
        self.db_path = state_dir / "skills.db"  # Reuse skill manager DB
        self._last_run: float = 0.0
        # v0.1.5-alpha: when wired the curator no longer mutates spec.trust_level
        # for promotion/demotion. Promote becomes an auditable proposal; demote
        # routes through trust_skill so the tool registry is correctly flipped.
        self.promotion_store: PromotionStore | None = promotion_store
        self.skill_manager: SkillManager | None = skill_manager
        self._owner_key_hash: str | None = owner_key_hash

    def should_run(self, interval_seconds: float = 604800) -> bool:  # 7 days
        """Check if enough time has passed since last curation."""
        return time.time() - self._last_run >= interval_seconds

    def curate(
        self,
        skills: dict[str, SkillSpec],
        force: bool = False,
    ) -> dict[str, Any]:
        """Run full curation cycle."""
        if not force and not self.should_run():
            return {"status": "skipped", "reason": "Too soon since last run"}

        self._last_run = time.time()
        health_reports: list[SkillHealth] = []
        actions_taken: list[dict[str, Any]] = []

        # Load usage stats from DB
        usage_stats = self._load_usage_stats()

        # Find duplicates by name/description similarity
        duplicates = self._find_duplicates(skills)

        for skill_id, spec in skills.items():
            stats = usage_stats.get(skill_id, {"count": 0, "success_rate": 1.0, "last_used": 0.0})
            days_since = (
                (time.time() - stats["last_used"]) / 86400
                if stats["last_used"] > 0
                else float("inf")
            )

            # Determine health status
            if skill_id in duplicates:
                status = "duplicate"
                recommendation = f"Potential duplicate of: {', '.join(duplicates[skill_id])}"
            elif days_since > self.STALE_DAYS and stats["count"] > 0:
                status = "stale"
                recommendation = f"Unused for {days_since:.0f} days. Consider deprecation."
            elif stats["success_rate"] < self.UNDERPERFORM_THRESHOLD and stats["count"] >= 5:
                status = "underperforming"
                recommendation = f"Low success rate ({stats['success_rate'] * 100:.0f}%). Trigger evolution or review."
            else:
                status = "healthy"
                recommendation = "No action needed."

            health_reports.append(
                SkillHealth(
                    skill_id=skill_id,
                    status=status,
                    usage_count=stats["count"],
                    success_rate=stats["success_rate"],
                    days_since_last_use=days_since,
                    recommendation=recommendation,
                )
            )

            # Auto-actions for safe cases
            if status == "underperforming" and spec.trust_level == TrustLevel.COMMUNITY:
                # Downgrade community skills that underperform. Routes through
                # SkillManager.trust_skill when wired so the tool registry is
                # also unregistered — the legacy direct-mutate path failed to
                # do this and left quarantined skills callable until restart.
                self._demote_to_quarantine(spec, reason=recommendation)
                actions_taken.append(
                    {
                        "skill_id": skill_id,
                        "action": "quarantined",
                        "reason": recommendation,
                    }
                )
                logger.info(f"Curator quarantined underperforming skill: {skill_id}")

        # Promote high-performing community skills
        promoted = self._promote_skills(skills, usage_stats)
        actions_taken.extend(promoted)

        report = {
            "timestamp": self._last_run,
            "total_skills": len(skills),
            "healthy": sum(1 for h in health_reports if h.status == "healthy"),
            "stale": sum(1 for h in health_reports if h.status == "stale"),
            "duplicates": sum(1 for h in health_reports if h.status == "duplicate"),
            "underperforming": sum(1 for h in health_reports if h.status == "underperforming"),
            "health_reports": [self._health_to_dict(h) for h in health_reports],
            "actions_taken": actions_taken,
        }

        logger.info(
            f"Curation complete: {report['healthy']} healthy, {report['stale']} stale, "
            f"{report['duplicates']} duplicates, {report['underperforming']} underperforming"
        )
        return report

    def _load_usage_stats(self) -> dict[str, dict[str, Any]]:
        """Load usage statistics from the skills DB."""
        stats: dict[str, dict[str, Any]] = {}
        try:
            with db_connection(self.db_path) as conn:
                rows = conn.execute(
                    """
                    SELECT skill_id, COUNT(*), AVG(success), MAX(used_at)
                    FROM skill_usage
                    GROUP BY skill_id
                    """
                ).fetchall()
            for skill_id, count, success_rate, last_used in rows:
                stats[skill_id] = {
                    "count": count,
                    "success_rate": success_rate if success_rate is not None else 1.0,
                    "last_used": time.mktime(time.strptime(last_used, "%Y-%m-%d %H:%M:%S"))
                    if isinstance(last_used, str)
                    else (last_used or 0.0),
                }
        except Exception as e:
            logger.warning(f"Could not load usage stats: {e}")
        return stats

    def _find_duplicates(self, skills: dict[str, SkillSpec]) -> dict[str, list[str]]:
        """Find potential duplicate skills by name similarity."""
        duplicates: dict[str, list[str]] = {}
        seen: dict[str, str] = {}  # normalized_name -> skill_id

        for skill_id, spec in skills.items():
            norm_name = spec.name.lower().replace(" ", "_").replace("-", "_")
            if norm_name in seen:
                existing = seen[norm_name]
                duplicates.setdefault(skill_id, []).append(existing)
                duplicates.setdefault(existing, []).append(skill_id)
            else:
                seen[norm_name] = skill_id

        return duplicates

    def _promote_skills(
        self,
        skills: dict[str, SkillSpec],
        usage_stats: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Propose (or, legacy, directly promote) high-performing community skills.

        With ``promotion_store`` wired, this never mutates ``spec.trust_level``
        — it inserts a ``proposed`` event. An operator (or, later, a Web
        dashboard) flips it to ``applied`` via ``SkillManager.apply_proposal``.
        Existing open proposals for the same skill are skipped (cooldown).
        """
        actions: list[dict[str, Any]] = []
        for skill_id, stats in usage_stats.items():
            spec = skills.get(skill_id)
            if not spec:
                continue
            if (
                spec.trust_level == TrustLevel.COMMUNITY
                and stats["count"] >= 20
                and stats["success_rate"] >= 0.95
            ):
                reason = (
                    f"{stats['count']} executions with {stats['success_rate'] * 100:.0f}% success"
                )
                if self.promotion_store is not None:
                    # Dedup: skip if an open (proposed / approved) proposal exists.
                    try:
                        open_existing = self.promotion_store.list_open_for_skill(
                            skill_id, owner_key_hash=self._owner_key_hash
                        )
                    except Exception:
                        logger.warning("promotion_store.list_open_for_skill failed", exc_info=True)
                        open_existing = []
                    if open_existing:
                        actions.append(
                            {
                                "skill_id": skill_id,
                                "action": "promotion_already_proposed",
                                "reason": reason,
                            }
                        )
                        continue
                    try:
                        event_id = self.promotion_store.propose(
                            skill_id,
                            TrustLevel.COMMUNITY.value,
                            TrustLevel.TRUSTED.value,
                            "auto_curator",
                            reason,
                            owner_key_hash=self._owner_key_hash,
                            decided_by="auto",
                        )
                        actions.append(
                            {
                                "skill_id": skill_id,
                                "action": "promotion_proposed",
                                "event_id": event_id,
                                "reason": reason,
                            }
                        )
                        logger.info(
                            "Curator proposed promotion for skill %s (event=%s)",
                            skill_id,
                            event_id,
                        )
                    except Exception:
                        logger.warning(
                            "promotion_store.propose failed for %s",
                            skill_id,
                            exc_info=True,
                        )
                else:
                    # Legacy: direct mutate (kept for backward compatibility
                    # with tests / CLIs that haven't wired a PromotionStore).
                    spec.trust_level = TrustLevel.TRUSTED
                    actions.append(
                        {
                            "skill_id": skill_id,
                            "action": "promoted_to_trusted",
                            "reason": reason,
                        }
                    )
                    logger.info("Curator promoted skill to trusted (legacy path): %s", skill_id)
        return actions

    def _demote_to_quarantine(self, spec: SkillSpec, *, reason: str) -> None:
        """Route demotion through ``trust_skill`` when a manager is wired.

        Going through the manager matters because the legacy
        ``spec.trust_level = QUARANTINE`` did NOT unregister the skill from
        the tool registry — a quarantined skill stayed callable until the
        process restarted. trust_skill flips the registry AND writes the
        demotion as a promotion event + audit row.
        """
        if self.skill_manager is not None:
            try:
                self.skill_manager.trust_skill(
                    spec.id,
                    TrustLevel.QUARANTINE,
                    source="auto_curator_demote",
                    reason=reason,
                    decided_by="auto",
                )
                return
            except Exception:
                logger.warning("skill_manager.trust_skill failed in curator demote", exc_info=True)
        # Legacy / no-manager fallback (kept for tests that don't wire one).
        spec.trust_level = TrustLevel.QUARANTINE

    def _health_to_dict(self, health: SkillHealth) -> dict[str, Any]:
        return {
            "skill_id": health.skill_id,
            "status": health.status,
            "usage_count": health.usage_count,
            "success_rate": health.success_rate,
            "days_since_last_use": health.days_since_last_use,
            "recommendation": health.recommendation,
        }
