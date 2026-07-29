from __future__ import annotations

from typing import Any

import pytest

from js.agent.runner import RunnerMixin
from js.echo.state import AgentState


class _StreamingAgent(RunnerMixin):
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def run(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append({"args": args, "kwargs": kwargs})
        await kwargs["stream_callback"]("he")
        await kwargs["stream_callback"]("llo")
        return AgentState(session_id="session-1", run_id="run-1", status="completed")


@pytest.mark.asyncio
async def test_chat_stream_uses_echo_gated_run_path() -> None:
    agent = _StreamingAgent()

    tokens = [
        token
        async for token in agent.chat_stream(
            "hi",
            session_id="session-1",
            model="mock-model",
            attachments=["uploads/pending/note.txt"],
        )
    ]

    assert tokens == ["he", "llo"]
    assert len(agent.calls) == 1
    call = agent.calls[0]
    assert call["args"] == ("hi",)
    assert call["kwargs"]["session_id"] == "session-1"
    assert call["kwargs"]["model"] == "mock-model"
    assert call["kwargs"]["attachments"] == ["uploads/pending/note.txt"]
    assert call["kwargs"]["disable_tools"] is False
    assert callable(call["kwargs"]["stream_callback"])


@pytest.mark.asyncio
async def test_chat_stream_can_explicitly_disable_tools() -> None:
    agent = _StreamingAgent()

    tokens = [
        token
        async for token in agent.chat_stream(
            "hi",
            session_id="session-1",
            enable_tools=False,
        )
    ]

    assert tokens == ["he", "llo"]
    assert agent.calls[0]["kwargs"]["disable_tools"] is True
