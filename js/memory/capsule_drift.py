"""
Session Capsule Lite — Drift Detection
======================================

Detects when a conversation has shifted goals or when the stored capsule
contradicts the most recent turns.  In Session Capsule Lite, drift detection
is warning-only: callers log the drift but continue injecting the capsule.
The primary goal is token savings, so stale summaries are not allowed to
block context injection.

Heuristics (deterministic, no LLM calls):

* Goal drift — keyword overlap between capsule and last N turns drops below
  a threshold.
* Contradiction — negation words ("not", "never", "changed my mind") appear in
  recent turns but are absent from the capsule.
* Topic switch — new domain keywords appear in recent turns that are not in the
  capsule at all.

Usage::

    from js.memory.capsule_drift import DriftDetector
    detector = DriftDetector()
    result = detector.check(capsule_text, recent_turns)
    if result.drift_detected:
        # log a warning; continue with capsule injection in Lite
        ...
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any


@dataclasses.dataclass(frozen=True)
class DriftResult:
    """Outcome of a drift check."""

    drift_detected: bool
    reason: str | None = None
    confidence: float = 0.0  # 0.0–1.0
    recent_turns_checked: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "drift_detected": self.drift_detected,
            "reason": self.reason,
            "confidence": self.confidence,
            "recent_turns_checked": self.recent_turns_checked,
        }


class DriftDetector:
    """Lightweight, deterministic drift detector for session capsules."""

    # Tunable thresholds
    GOAL_OVERLAP_THRESHOLD: float = 0.25  # Jaccard overlap below this → drift
    CONTRADICTION_BOOST: float = 0.3  # added to confidence if negation found
    TOPIC_SWITCH_BOOST: float = 0.2  # added if new domain keywords appear
    MIN_TURNS_FOR_CHECK: int = 3

    # Negation / reversal markers
    NEGATION_WORDS: set[str] = {
        "not",
        "never",
        "no",
        "none",
        "changed my mind",
        "don't",
        "doesn't",
        "didn't",
        "won't",
        "wouldn't",
        "shouldn't",
        "cancel",
        "undo",
        "revert",
        "stop",
        "drop",
    }

    # Domain keywords for topic-switch detection (expandable)
    DOMAIN_KEYWORDS: dict[str, set[str]] = {
        "code": {
            "refactor",
            "function",
            "class",
            "module",
            "import",
            "test",
            "bug",
            "fix",
            "commit",
        },
        "config": {"yaml", "json", "env", "config", "setting", "variable", "parameter"},
        "deploy": {"docker", "kubernetes", "deploy", "release", "pipeline", "ci", "cd"},
        "data": {"sql", "database", "csv", "table", "query", "schema", "migration"},
        "design": {"ui", "ux", "mockup", "wireframe", "figma", "css", "layout"},
        "docs": {"readme", "documentation", "docstring", "markdown", "wiki"},
    }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self,
        capsule_text: str,
        recent_turns: list[dict[str, str]],
        recent_turns_count: int = 6,
    ) -> DriftResult:
        """Check whether the capsule has drifted from the last *recent_turns_count* turns.

        Args:
            capsule_text: The stored capsule summary.
            recent_turns: Full list of conversation turns (oldest → newest).
            recent_turns_count: How many of the most recent turns to examine.

        Returns:
            DriftResult with drift_detected, reason, and confidence.
        """
        if len(recent_turns) < self.MIN_TURNS_FOR_CHECK:
            return DriftResult(
                drift_detected=False,
                reason="Too few recent turns to assess drift",
                confidence=0.0,
                recent_turns_checked=len(recent_turns),
            )

        last_n = recent_turns[-recent_turns_count:]
        recent_text = " ".join(t["content"] for t in last_n if t.get("content"))

        confidence = 0.0
        reasons: list[str] = []

        # 1. Goal overlap (Jaccard on content words)
        overlap = self._jaccard_overlap(capsule_text, recent_text)
        if overlap < self.GOAL_OVERLAP_THRESHOLD:
            confidence += 0.5
            reasons.append(f"Goal overlap low ({overlap:.2f} < {self.GOAL_OVERLAP_THRESHOLD})")

        # 2. Contradiction detection (negation in recent turns not in capsule)
        negation_score = self._contradiction_score(capsule_text, recent_text)
        if negation_score > 0:
            confidence += self.CONTRADICTION_BOOST
            reasons.append("Contradiction markers found in recent turns")

        # 3. Topic switch (new domain keywords)
        topic_switch = self._topic_switch_score(capsule_text, recent_text)
        if topic_switch > 0:
            confidence += self.TOPIC_SWITCH_BOOST
            reasons.append("Topic switch detected (new domain keywords)")

        drift_detected = confidence >= 0.5
        reason = "; ".join(reasons) if reasons else None

        return DriftResult(
            drift_detected=drift_detected,
            reason=reason,
            confidence=min(confidence, 1.0),
            recent_turns_checked=len(last_n),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @classmethod
    def _tokenize(cls, text: str) -> set[str]:
        """Extract lowercase alphanumeric tokens."""
        return set(re.findall(r"[a-z0-9_]+", text.lower()))

    @classmethod
    def _jaccard_overlap(cls, text_a: str, text_b: str) -> float:
        """Jaccard similarity between token sets."""
        tokens_a = cls._tokenize(text_a)
        tokens_b = cls._tokenize(text_b)
        if not tokens_a or not tokens_b:
            return 0.0
        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        return len(intersection) / len(union)

    @classmethod
    def _contradiction_score(cls, capsule_text: str, recent_text: str) -> float:
        """Return 1.0 if recent turns contain negation words absent from capsule."""
        capsule_lower = capsule_text.lower()
        recent_lower = recent_text.lower()
        for word in cls.NEGATION_WORDS:
            if word in recent_lower and word not in capsule_lower:
                return 1.0
        return 0.0

    @classmethod
    def _topic_switch_score(cls, capsule_text: str, recent_text: str) -> float:
        """Return 1.0 if a domain keyword set appears in recent but not capsule."""
        capsule_tokens = cls._tokenize(capsule_text)
        recent_tokens = cls._tokenize(recent_text)
        for _domain, keywords in cls.DOMAIN_KEYWORDS.items():
            recent_has = bool(recent_tokens & keywords)
            capsule_has = bool(capsule_tokens & keywords)
            if recent_has and not capsule_has:
                return 1.0
        return 0.0


def check_drift(
    capsule_text: str,
    recent_turns: list[dict[str, str]],
    recent_turns_count: int = 6,
) -> DriftResult:
    """Convenience one-shot drift check."""
    return DriftDetector().check(capsule_text, recent_turns, recent_turns_count)
