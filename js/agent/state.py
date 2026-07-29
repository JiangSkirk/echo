"""Agent run state + checkpoint persistence.

Holds the ephemeral ``AgentState`` dataclass and ``StateMixin`` (save/load/resume
of checkpoints).
"""

from __future__ import annotations

import asyncio
import uuid

from js.agent.base import AgentBase
from js.echo.state import AgentState as AgentState
from js.models.providers import ChatMessage
from js.tools.registry import ToolResult

__all__ = ["AgentState", "StateMixin"]


class StateMixin(AgentBase):
    """Checkpoint persistence + resume."""

    async def save_checkpoint(self, state: AgentState) -> None:
        """Persist agent state for resume."""
        data = state.to_dict()
        from js.echo.turn_context import current_owner_key_hash

        owner_key_hash = current_owner_key_hash()
        await asyncio.to_thread(
            self.state_store.save,
            session_id=data["session_id"],
            run_id=data["run_id"],
            turn_count=data["turn_count"],
            messages=data["messages"],
            tool_results=data["tool_results"],
            total_tokens=data["total_tokens"],
            cost_estimate=data["cost_estimate"],
            status=data["status"],
            error_message=data["error_message"],
            compression_stats=data["compression_stats"],
            model=data.get("model", ""),
            owner_key_hash=owner_key_hash,
        )

    async def load_checkpoint(self, session_id: str) -> AgentState | None:
        """Restore agent state from persistent store."""
        from js.echo.turn_context import current_owner_key_hash

        owner_key_hash = current_owner_key_hash()
        data = await asyncio.to_thread(self.state_store.load, session_id, owner_key_hash)
        if data is None:
            return None
        state = AgentState(
            session_id=data["session_id"],
            run_id=data["run_id"],
            turn_count=data.get("turn_count", 0),
            total_tokens=data.get("total_tokens", {"input": 0, "output": 0}),
            cost_estimate=data.get("cost_estimate", 0.0),
            status=data.get("status", "running"),
            error_message=data.get("error_message", ""),
            compression_stats=data.get("compression_stats", {}),
            model=data.get("model", ""),
        )
        for m in data.get("messages", []):
            state.messages.append(
                ChatMessage(
                    role=m.get("role", "user"),
                    content=m.get("content", ""),
                    name=m.get("name"),
                    tool_calls=m.get("tool_calls"),
                    tool_call_id=m.get("tool_call_id"),
                    reasoning_content=m.get("reasoning_content"),
                )
            )
        for r in data.get("tool_results", []):
            state.tool_results.append(
                ToolResult(
                    success=r.get("success", False),
                    output=r.get("output", ""),
                    error=r.get("error", ""),
                )
            )
        return state

    async def resume(self, session_id: str, user_input: str = "") -> AgentState:
        """Resume a session from its last checkpoint."""
        state = await self.load_checkpoint(session_id)
        if state is None:
            state = AgentState(session_id=session_id, run_id=str(uuid.uuid4()))
        if user_input:
            state.messages.append(ChatMessage(role="user", content=user_input))
        return await self.run(user_input, session_id=session_id, _resume_state=state)
