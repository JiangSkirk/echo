"""Intelligent task routing to appropriate agents."""

from __future__ import annotations

import re
from dataclasses import dataclass

from js.orchestration.fleet import AgentRole


@dataclass
class RoutingScore:
    role: AgentRole
    score: float
    reason: str


class TaskRouter:
    """Routes tasks to the most suitable agent role."""

    ROLE_PATTERNS: dict[AgentRole, list[str]] = {
        AgentRole.CODER: [
            r"write\s+(code|function|script|class|module)",
            r"implement",
            r"refactor",
            r"debug",
            r"fix\s+(bug|error|issue)",
            r"create\s+(api|endpoint|service)",
            r"programming",
            r"python|javascript|typescript|rust|go|java",
        ],
        AgentRole.REVIEWER: [
            r"review",
            r"audit",
            r"check\s+(quality|style|security)",
            r"code\s+review",
            r"evaluate",
        ],
        AgentRole.RESEARCHER: [
            r"research",
            r"find\s+(information|data|docs)",
            r"search",
            r"investigate",
            r"analyze\s+(trend|market|data)",
            r"summarize",
        ],
        AgentRole.TESTER: [
            r"test",
            r"write\s+tests",
            r"unit\s+test",
            r"integration\s+test",
            r"coverage",
            r"validate",
        ],
    }

    def route(self, task_description: str) -> RoutingScore:
        """Determine best role for a task."""
        desc_lower = task_description.lower()
        scores: list[RoutingScore] = []

        for role, patterns in self.ROLE_PATTERNS.items():
            score = 0.0
            matched = []
            for pattern in patterns:
                if re.search(pattern, desc_lower):
                    score += 1.0
                    matched.append(pattern)
            if score > 0:
                scores.append(RoutingScore(
                    role=role,
                    score=score,
                    reason=f"Matched patterns: {matched[:3]}",
                ))

        if scores:
            best = max(scores, key=lambda s: s.score)
            return best

        return RoutingScore(
            role=AgentRole.GENERALIST,
            score=0.5,
            reason="No specific patterns matched, using generalist",
        )

    def decompose(self, task_description: str) -> list[tuple[str, AgentRole]]:
        """Decompose a complex task into subtasks."""
        # Simple heuristic decomposition
        subtasks: list[tuple[str, AgentRole]] = []

        # Check if task mentions multiple phases
        phases = re.split(r"\n+|(?:and\s+then|first|second|third|finally|next)", task_description, flags=re.IGNORECASE)
        for phase in phases:
            phase = phase.strip()
            if len(phase) > 20:
                routed = self.route(phase)
                subtasks.append((phase, routed.role))

        if not subtasks:
            routed = self.route(task_description)
            subtasks.append((task_description, routed.role))

        return subtasks
