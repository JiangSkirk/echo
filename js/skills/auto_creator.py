"""Auto-generate skills from learned interaction patterns.

When the agent repeatedly succeeds at a particular type of task,
the SelfLearner extracts patterns. AutoSkillCreator converts
high-confidence patterns into reusable prompt skills.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from js.skills.spec import SkillSpec
from js.utils.log import get_logger

logger = get_logger("js.skills.auto")

AUTO_SKILL_PREFIX = "auto_"
MIN_FREQUENCY = 10
MIN_SUCCESS_RATE = 0.8


class AutoSkillCreator:
    """Creates prompt skills from observed successful task patterns."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.auto_dir = state_dir / "skills" / "auto_generated"
        self.auto_dir.mkdir(parents=True, exist_ok=True)

    def should_create(self, frequency: int, success_rate: float) -> bool:
        """Check if a pattern warrants auto-skill creation."""
        return frequency >= MIN_FREQUENCY and success_rate >= MIN_SUCCESS_RATE

    def create_from_pattern(
        self,
        pattern: str,
        examples: list[str] | None = None,
    ) -> SkillSpec | None:
        """Generate a prompt skill from a learned pattern.

        Returns the generated SkillSpec, or None if the skill already exists.
        """
        skill_id = f"{AUTO_SKILL_PREFIX}{self._hash_pattern(pattern)}"
        skill_dir = self.auto_dir / skill_id

        if skill_dir.exists():
            logger.debug(f"Auto-skill {skill_id} already exists")
            return None

        skill_dir.mkdir(parents=True, exist_ok=True)

        examples_text = ""
        if examples:
            examples_text = "\n## Examples\n\n" + "\n\n".join(
                f"- {ex}" for ex in examples[:5]
            )

        manifest = skill_dir / "SKILL.md"
        manifest.write_text(
            f"""---
id: {skill_id}
name: "Auto: {pattern[:40]}"
description: "Auto-generated skill from learned pattern: {pattern[:80]}"
version: 0.1.0
author: JS Agent (Auto)
type: prompt
category: auto-generated
trust_level: community
metadata:
  auto_generated: true
  source_pattern: "{pattern}"
---

# {pattern}

This skill was automatically generated because the agent repeatedly
succeeded at tasks matching this pattern.

## Instructions

Apply the following approach when handling requests related to:
"{pattern}"

1. Identify the core intent using the pattern keywords.
2. Apply the proven strategy that led to past successes.
3. Be concise and direct.{examples_text}
""",
            encoding="utf-8",
        )

        from js.skills.spec import parse_skill_manifest

        spec = parse_skill_manifest(manifest)
        spec.path = skill_dir
        logger.info(f"Created auto-skill: {skill_id} from pattern '{pattern[:40]}'")
        return spec

    def list_auto_skills(self) -> list[SkillSpec]:
        """List all existing auto-generated skills."""
        skills: list[SkillSpec] = []
        from js.skills.spec import parse_skill_manifest

        for subdir in sorted(self.auto_dir.iterdir()):
            manifest = subdir / "SKILL.md"
            if manifest.exists():
                try:
                    spec = parse_skill_manifest(manifest)
                    spec.path = subdir
                    skills.append(spec)
                except Exception:
                    logger.debug(f"Failed to parse auto-skill manifest: {manifest}")
        return skills

    @staticmethod
    def _hash_pattern(pattern: str) -> str:
        return hashlib.md5(pattern.encode(), usedforsecurity=False).hexdigest()[:12]
