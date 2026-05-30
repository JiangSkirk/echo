"""Event models for agent observability and audit trails.

All agent behaviors are recorded as append-only events, enabling:
- Time-travel debugging
- Post-hoc analysis
- Metrics and cost tracking
- Security auditing
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class AgentEvent:
    """A single event in an agent's execution timeline."""

    event_type: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    session_id: str = ""
    run_id: str = ""
    agent_id: str = ""
    task_id: str = ""
    group_id: str = ""
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def task_started(
        cls,
        session_id: str,
        run_id: str,
        task_id: str = "",
        agent_id: str = "",
        description: str = "",
    ) -> AgentEvent:
        return cls(
            event_type="task_started",
            session_id=session_id,
            run_id=run_id,
            task_id=task_id,
            agent_id=agent_id,
            payload={"description": description},
        )

    @classmethod
    def model_called(
        cls,
        session_id: str,
        run_id: str,
        model: str = "",
        turn: int = 0,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
    ) -> AgentEvent:
        return cls(
            event_type="model_called",
            session_id=session_id,
            run_id=run_id,
            payload={
                "model": model,
                "turn": turn,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            },
        )

    @classmethod
    def tool_called(
        cls,
        session_id: str,
        run_id: str,
        tool_name: str = "",
        arguments: dict[str, Any] | None = None,
    ) -> AgentEvent:
        return cls(
            event_type="tool_called",
            session_id=session_id,
            run_id=run_id,
            payload={"tool_name": tool_name, "arguments": arguments or {}},
        )

    @classmethod
    def tool_result(
        cls,
        session_id: str,
        run_id: str,
        tool_name: str = "",
        success: bool = False,
        output_preview: str = "",
    ) -> AgentEvent:
        return cls(
            event_type="tool_result",
            session_id=session_id,
            run_id=run_id,
            payload={
                "tool_name": tool_name,
                "success": success,
                "output_preview": output_preview[:500],
            },
        )

    @classmethod
    def approval_requested(
        cls,
        session_id: str,
        run_id: str,
        tool_name: str = "",
        arguments: dict[str, Any] | None = None,
    ) -> AgentEvent:
        return cls(
            event_type="approval_requested",
            session_id=session_id,
            run_id=run_id,
            payload={"tool_name": tool_name, "arguments": arguments or {}},
        )

    @classmethod
    def approval_granted(
        cls,
        session_id: str,
        run_id: str,
        tool_name: str = "",
    ) -> AgentEvent:
        return cls(
            event_type="approval_granted",
            session_id=session_id,
            run_id=run_id,
            payload={"tool_name": tool_name},
        )

    @classmethod
    def approval_denied(
        cls,
        session_id: str,
        run_id: str,
        tool_name: str = "",
        reason: str = "",
    ) -> AgentEvent:
        return cls(
            event_type="approval_denied",
            session_id=session_id,
            run_id=run_id,
            payload={"tool_name": tool_name, "reason": reason},
        )

    @classmethod
    def checkpoint_saved(
        cls,
        session_id: str,
        run_id: str,
        turn: int = 0,
    ) -> AgentEvent:
        return cls(
            event_type="checkpoint_saved",
            session_id=session_id,
            run_id=run_id,
            payload={"turn": turn},
        )

    @classmethod
    def error(
        cls,
        session_id: str,
        run_id: str,
        error: str = "",
    ) -> AgentEvent:
        return cls(
            event_type="error",
            session_id=session_id,
            run_id=run_id,
            payload={"error": error},
        )

    @classmethod
    def task_completed(
        cls,
        session_id: str,
        run_id: str,
        task_id: str = "",
        status: str = "",
        result_preview: str = "",
    ) -> AgentEvent:
        return cls(
            event_type="task_completed",
            session_id=session_id,
            run_id=run_id,
            task_id=task_id,
            payload={"status": status, "result_preview": result_preview[:500]},
        )

    @classmethod
    def agent_spawned(
        cls,
        agent_id: str,
        name: str = "",
        role: str = "",
        model: str = "",
    ) -> AgentEvent:
        return cls(
            event_type="agent_spawned",
            agent_id=agent_id,
            payload={"name": name, "role": role, "model": model},
        )

    @classmethod
    def collaborate_started(
        cls,
        group_id: str,
        mode: str = "",
        main_task: str = "",
        agent_count: int = 0,
    ) -> AgentEvent:
        return cls(
            event_type="collaborate_started",
            group_id=group_id,
            payload={"mode": mode, "main_task": main_task, "agent_count": agent_count},
        )

    @classmethod
    def collaborate_completed(
        cls,
        group_id: str,
        mode: str = "",
        status: str = "",
    ) -> AgentEvent:
        return cls(
            event_type="collaborate_completed",
            group_id=group_id,
            payload={"mode": mode, "status": status},
        )
