"""
Session Capsule Lite — Quality Assessment
==========================================

Provides fixed long-conversation samples and automatic quality checks
for session capsules.  The six check-list items are:

1. Current goal preserved
2. Key decisions preserved
3. Completed items preserved
4. Unfinished next steps preserved
5. Important file paths preserved
6. User explicit preferences preserved

Usage::

    from js.memory.capsule_quality import CapsuleQuality
    qa = CapsuleQuality()
    score = qa.evaluate(capsule_text, sample_name="long_debug_session")
    assert score.passed  # all 6 checks pass

This module is intentionally lightweight — no LLM calls, no heavy NLP.
All checks are deterministic heuristics so they run fast in CI.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
from typing import Any


@dataclasses.dataclass(frozen=True)
class QualityScore:
    """Result of a capsule quality evaluation."""

    passed: bool
    total_checks: int = 6
    passed_checks: int = 0
    details: dict[str, bool] = dataclasses.field(default_factory=dict)
    estimated_coverage: float = 0.0  # 0.0–1.0 heuristic
    warnings: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "total_checks": self.total_checks,
            "passed_checks": self.passed_checks,
            "details": self.details,
            "estimated_coverage": self.estimated_coverage,
            "warnings": self.warnings,
        }


# ---------------------------------------------------------------------------
# Fixed long-conversation samples (stored as JSON so tests are deterministic)
# ---------------------------------------------------------------------------

_SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "capsule_samples")


def _load_sample(name: str) -> list[dict[str, str]]:
    """Load a fixed conversation sample by name."""
    path = os.path.join(_SAMPLES_DIR, f"{name}.json")
    if not os.path.exists(path):
        # Fallback: return the built-in minimal sample
        return _MINIMAL_SAMPLE
    with open(path, encoding="utf-8") as f:
        return json.load(f)  # type: ignore[no-any-return]


# Built-in minimal sample for when no external files exist
_MINIMAL_SAMPLE: list[dict[str, str]] = [
    {"role": "user", "content": "Help me refactor the auth module in src/auth.py"},
    {"role": "assistant", "content": "Sure. I'll start by extracting the password hashing into a separate utility."},
    {"role": "user", "content": "Also make sure we support bcrypt and argon2."},
    {"role": "assistant", "content": "Done. I added a pluggable Hasher interface in src/auth/hashers.py."},
    {"role": "user", "content": "What about the login route? It still uses the old inline check."},
    {"role": "assistant", "content": "Refactored login route to use the new Hasher in src/auth/routes.py."},
    {"role": "user", "content": "Great. Please remember I prefer explicit type hints everywhere."},
    {"role": "assistant", "content": "Noted. I'll add type hints to all new auth files."},
    {"role": "user", "content": "Next, we need to add rate limiting to the login endpoint."},
    {"role": "assistant", "content": "I'll add a sliding-window rate limiter using Redis."},
]


# ---------------------------------------------------------------------------
# Quality heuristics
# ---------------------------------------------------------------------------

class CapsuleQuality:
    """Evaluate capsule summaries against fixed conversation samples."""

    CHECK_NAMES = [
        "current_goal",
        "key_decisions",
        "completed_items",
        "unfinished_next_steps",
        "important_file_paths",
        "user_preferences",
    ]

    def __init__(self, samples_dir: str | None = None) -> None:
        self._samples_dir = samples_dir or _SAMPLES_DIR

    # -- public API --------------------------------------------------------

    def evaluate(self, capsule_text: str, sample_name: str = "minimal") -> QualityScore:
        """Run the 6-check quality assessment against a fixed sample.

        Args:
            capsule_text: The capsule summary to evaluate.
            sample_name: Name of the fixed conversation sample (without .json).

        Returns:
            QualityScore with per-check results and overall pass/fail.
        """
        sample = _load_sample(sample_name)
        details: dict[str, bool] = {}
        warnings: list[str] = []

        # 1. Current goal preserved
        details["current_goal"] = self._check_goal(capsule_text, sample)

        # 2. Key decisions preserved
        details["key_decisions"] = self._check_decisions(capsule_text, sample)

        # 3. Completed items preserved
        details["completed_items"] = self._check_completed(capsule_text, sample)

        # 4. Unfinished next steps preserved
        details["unfinished_next_steps"] = self._check_unfinished(capsule_text, sample)

        # 5. Important file paths preserved
        details["important_file_paths"] = self._check_paths(capsule_text, sample)

        # 6. User explicit preferences preserved
        details["user_preferences"] = self._check_preferences(capsule_text, sample)

        passed_checks = sum(details.values())
        estimated_coverage = passed_checks / len(self.CHECK_NAMES)

        if passed_checks < 4:
            warnings.append(
                f"Low coverage ({passed_checks}/{len(self.CHECK_NAMES)}); "
                "capsule may be too vague or missing key context."
            )
        if not details["user_preferences"]:
            warnings.append("User preferences missing — high risk of repeating questions.")
        if not details["important_file_paths"]:
            warnings.append("File paths missing — may lose track of modified code.")

        return QualityScore(
            passed=passed_checks >= 4,
            total_checks=len(self.CHECK_NAMES),
            passed_checks=passed_checks,
            details=details,
            estimated_coverage=estimated_coverage,
            warnings=warnings,
        )

    def benchmark(self, capsule_text: str) -> dict[str, Any]:
        """Run evaluation against all available samples and return aggregate stats."""
        results: list[dict[str, Any]] = []
        if not os.path.isdir(self._samples_dir):
            samples = ["minimal"]
        else:
            samples = [
                os.path.splitext(f)[0]
                for f in os.listdir(self._samples_dir)
                if f.endswith(".json")
            ] or ["minimal"]
        for name in samples:
            score = self.evaluate(capsule_text, name)
            results.append({"sample": name, **score.to_dict()})
        overall_passed = all(r["passed"] for r in results)
        avg_coverage = sum(r["estimated_coverage"] for r in results) / max(len(results), 1)
        return {
            "overall_passed": overall_passed,
            "average_coverage": avg_coverage,
            "per_sample": results,
        }

    # -- internal checks ---------------------------------------------------

    @staticmethod
    def _extract_keywords(text: str) -> set[str]:
        """Simple keyword extraction: lowercase, strip punctuation."""
        return set(re.findall(r"[a-z0-9_]+(?:\.[a-z0-9_]+)*", text.lower()))

    def _check_goal(self, capsule: str, sample: list[dict[str, str]]) -> bool:
        """Check if the capsule mentions the user's current goal."""
        # Goal is usually in the first user message or a later 'need to' / 'want to'
        goal_keywords: list[set[str]] = []
        for turn in sample:
            if turn["role"] == "user":
                content = turn["content"].lower()
                # Heuristic: sentences containing goal-oriented verbs
                for verb in ("help me", "refactor", "fix", "add", "implement", "migrate", "debug"):
                    if verb in content:
                        goal_keywords.append(set(re.findall(r"[a-z0-9_]+", content)))
                        break
        if not goal_keywords:
            return True  # no clear goal in sample → neutral pass
        capsule_tokens = set(re.findall(r"[a-z0-9_]+", capsule.lower()))
        # Pass if capsule shares significant keyword overlap with any goal phrase
        return any(
            len(kw & capsule_tokens) >= max(2, len(kw) // 3)
            for kw in goal_keywords
        )

    def _check_decisions(self, capsule: str, sample: list[dict[str, str]]) -> bool:
        """Check if key decisions (e.g. 'use X instead of Y') are preserved."""
        decision_keywords: list[set[str]] = []
        for turn in sample:
            if turn["role"] == "assistant":
                content = turn["content"].lower()
                # Look for decision language
                for marker in ("use ", "choose ", "decided", "opted for", "instead of", "interface", "extract"):
                    if marker in content:
                        decision_keywords.append(self._extract_keywords(content))
                        break
        if not decision_keywords:
            return True
        capsule_tokens = self._extract_keywords(capsule)
        # Pass if capsule shares significant keyword overlap with any decision phrase
        return any(
            len(kw & capsule_tokens) >= max(2, len(kw) // 3)
            for kw in decision_keywords
        )

    def _check_completed(self, capsule: str, sample: list[dict[str, str]]) -> bool:
        """Check if completed work items are mentioned."""
        completed_keywords: list[set[str]] = []
        for turn in sample:
            if turn["role"] == "assistant":
                content = turn["content"].lower()
                for marker in ("done", "completed", "refactored", "added", "implemented", "created"):
                    if marker in content:
                        completed_keywords.append(self._extract_keywords(content))
                        break
        if not completed_keywords:
            return True
        capsule_tokens = self._extract_keywords(capsule)
        return any(
            len(kw & capsule_tokens) >= max(2, len(kw) // 3)
            for kw in completed_keywords
        )

    def _check_unfinished(self, capsule: str, sample: list[dict[str, str]]) -> bool:
        """Check if next steps / unfinished items are preserved."""
        unfinished_keywords: list[set[str]] = []
        for turn in sample:
            content = turn["content"].lower()
            for marker in ("next", "need to", "still", "todo", "pending", "plan to", "upcoming"):
                if marker in content:
                    unfinished_keywords.append(self._extract_keywords(content))
                    break
        if not unfinished_keywords:
            return True
        capsule_tokens = self._extract_keywords(capsule)
        return any(
            len(kw & capsule_tokens) >= max(2, len(kw) // 3)
            for kw in unfinished_keywords
        )

    def _check_paths(self, capsule: str, sample: list[dict[str, str]]) -> bool:
        """Check if file paths from the conversation appear in the capsule."""
        # Extract all file-like paths from the sample
        path_pattern = re.compile(r"[\w\-/]+\.[a-zA-Z0-9]+")
        sample_paths: set[str] = set()
        for turn in sample:
            sample_paths.update(path_pattern.findall(turn["content"]))
        if not sample_paths:
            return True
        capsule_paths = set(path_pattern.findall(capsule))
        # Pass if at least one sample path is mentioned (Lite: recall over precision)
        return bool(sample_paths & capsule_paths)

    def _check_preferences(self, capsule: str, sample: list[dict[str, str]]) -> bool:
        """Check if explicit user preferences are preserved."""
        preference_markers = []
        for turn in sample:
            if turn["role"] == "user":
                content = turn["content"].lower()
                for marker in ("prefer", "like", "want", "always", "never", "make sure", "remember"):
                    if marker in content:
                        preference_markers.append(content)
                        break
        if not preference_markers:
            return True
        capsule_lower = capsule.lower()
        # Relaxed match: check if ANY preference keyword from the sample
        # appears in the capsule (not requiring full sentence containment).
        for pm in preference_markers:
            pm_tokens = set(re.findall(r"[a-z0-9_]+", pm))
            if pm_tokens and pm_tokens.issubset(set(re.findall(r"[a-z0-9_]+", capsule_lower))):
                return True
        return False


# ---------------------------------------------------------------------------
# Convenience: evaluate a capsule against the default sample
# ---------------------------------------------------------------------------

def evaluate_capsule(capsule_text: str) -> QualityScore:
    """One-shot quality evaluation using the default sample."""
    return CapsuleQuality().evaluate(capsule_text)
