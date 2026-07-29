"""Echo-owned ephemeral state for one agent turn."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from js.models.providers import ChatMessage
from js.tools.registry import ToolResult


@dataclass
class AgentState:
    """Mutable turn state owned by the Echo runtime."""

    session_id: str
    run_id: str
    turn_count: int = 0
    messages: list[ChatMessage] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
    total_tokens: dict[str, int] = field(default_factory=lambda: {"input": 0, "output": 0})
    cached_tokens: int = 0
    cost_estimate: float = 0.0
    status: str = "running"
    error_message: str = ""
    compression_stats: dict[str, Any] = field(default_factory=dict)
    model: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "run_id": self.run_id,
            "turn_count": self.turn_count,
            "messages": [
                {
                    "role": message.role,
                    "content": message.content,
                    "name": getattr(message, "name", None),
                    "tool_calls": getattr(message, "tool_calls", None),
                    "tool_call_id": getattr(message, "tool_call_id", None),
                    "reasoning_content": getattr(message, "reasoning_content", None),
                }
                for message in self.messages
            ],
            "tool_results": [
                {"success": result.success, "output": result.output, "error": result.error}
                for result in self.tool_results
            ],
            "total_tokens": self.total_tokens,
            "cached_tokens": self.cached_tokens,
            "cost_estimate": self.cost_estimate,
            "status": self.status,
            "error_message": self.error_message,
            "compression_stats": self.compression_stats,
            "model": self.model,
        }


__all__ = ["AgentState"]
