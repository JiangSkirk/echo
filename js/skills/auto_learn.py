"""Auto-skill generation: close the learning loop.

When the agent successfully completes a novel task pattern,
this module generates a reusable skill from the interaction
and registers it for future use.

Inspired by Hermes Agent's GEPA self-evolution mechanism.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from js.skills.spec import SkillSpec, parse_skill_manifest
from js.utils.log import get_logger

logger = get_logger("js.skills.auto_learn")


class AutoSkillLearner:
    """Generates skills from successful agent runs."""

    MIN_TURNS = 3  # Need at least 3 turns to be worth a skill
    MAX_SKILL_LENGTH = 4000  # chars
    COOLDOWN_SECONDS = 600  # Don't generate skills more often than every 10 min

    def __init__(self, skills_dir: Path) -> None:
        self.skills_dir = skills_dir
        self.auto_dir = skills_dir / "auto"
        self.auto_dir.mkdir(parents=True, exist_ok=True)
        self._last_generation: float = 0.0
        self._seen_hashes: set[str] = set()

    def should_learn(
        self,
        user_input: str,
        state_status: str,
        turn_count: int,
    ) -> bool:
        """Check if this successful run warrants skill generation."""
        if state_status != "completed":
            return False
        if turn_count < self.MIN_TURNS:
            return False
        if time.time() - self._last_generation < self.COOLDOWN_SECONDS:
            return False
        # Reject trivial queries
        return len(user_input) >= 20

    def generate_skill(
        self,
        user_input: str,
        messages: list[Any],
    ) -> SkillSpec | None:
        """Generate a SkillSpec from a successful conversation."""
        # Build a deterministic hash of the user intent
        intent_hash = hashlib.sha256(user_input.lower().strip().encode()).hexdigest()[:12]
        if intent_hash in self._seen_hashes:
            return None
        self._seen_hashes.add(intent_hash)

        # Extract tool usage pattern
        tool_calls: list[dict[str, Any]] = []
        for msg in messages:
            if getattr(msg, "role", None) == "assistant" and getattr(msg, "tool_calls", None):
                for tc in msg.tool_calls:
                    func = tc.get("function", {}) if isinstance(tc, dict) else {}
                    tool_calls.append({
                        "name": func.get("name", "") if isinstance(func, dict) else "",
                        "arguments": func.get("arguments", "") if isinstance(func, dict) else "",
                    })

        if not tool_calls:
            return None  # No tool usage = nothing to generalize

        # Build a generic prompt from the conversation
        skill_prompt = self._build_skill_prompt(user_input, tool_calls, messages)
        if not skill_prompt:
            return None

        skill_id = f"auto_{intent_hash}"
        skill_dir = self.auto_dir / skill_id
        skill_dir.mkdir(parents=True, exist_ok=True)

        # Write SKILL.md manifest
        manifest_path = skill_dir / "SKILL.md"
        manifest_content = f"""# {skill_id}

## Description
Auto-generated skill from successful task execution.

## Type
prompt

## Tags
auto-generated, learned

## Instructions
{skill_prompt}
"""
        manifest_path.write_text(manifest_content, encoding="utf-8")

        # Write metadata
        meta_path = skill_dir / "meta.json"
        meta_path.write_text(
            json.dumps(
                {
                    "source_query": user_input[:200],
                    "generated_at": time.time(),
                    "tool_count": len(tool_calls),
                    "turn_count": len(messages),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        self._last_generation = time.time()
        logger.info(f"Auto-generated skill: {skill_id} ({len(tool_calls)} tools, {len(messages)} turns)")

        # Parse and return spec
        try:
            spec = parse_skill_manifest(manifest_path)
            spec.path = skill_dir
            from js.skills.spec import TrustLevel
            spec.trust_level = TrustLevel.COMMUNITY
            return spec
        except Exception as e:
            logger.warning(f"Failed to parse auto-generated skill: {e}")
            return None

    def _build_skill_prompt(
        self,
        user_input: str,
        tool_calls: list[dict[str, Any]],
        messages: list[Any],
    ) -> str:
        """Build a generic skill prompt from a successful conversation."""
        # Extract the successful reasoning chain
        parts: list[str] = []
        parts.append("When the user asks something similar to the following, use this workflow:")
        parts.append(f"\n**Example query**: {user_input[:200]}")
        parts.append("\n**Recommended steps**:")

        seen_tools: set[str] = set()
        for tc in tool_calls:
            name = tc.get("name", "")
            if not name or name in seen_tools:
                continue
            seen_tools.add(name)
            parts.append(f"1. Use `{name}` to gather necessary information.")

        parts.append("\n**Final response**: Provide a clear, structured answer.")

        prompt = "\n".join(parts)
        if len(prompt) > self.MAX_SKILL_LENGTH:
            prompt = prompt[: self.MAX_SKILL_LENGTH] + "\n... [truncated]"
        return prompt
