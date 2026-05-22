"""Tests for cancel API, checkpoint/resume, and graceful shutdown."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from js.agent import AgentState, JSAgent
from js.config import JSSettings
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.persistence.state_store import StateStore


class SlowMockProvider(ModelProvider):
    """Mock provider with configurable per-response delay."""

    def __init__(self, responses: list[ChatResponse], delay: float = 0.05) -> None:
        self._responses = responses
        self._index = 0
        self.delay = delay
        self.calls: list[list[ChatMessage]] = []

    def set_responses(self, responses: list[ChatResponse]) -> None:
        self._responses = responses
        self._index = 0

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
    ) -> ChatResponse:
        await asyncio.sleep(self.delay)
        self.calls.append(messages)
        resp = self._responses[self._index % len(self._responses)]
        self._index += 1
        return resp

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        temperature: float = 0.7,
    ):
        for token in ("Mock", " stream"):
            yield token

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


class MockRouter:
    """Router that uses a SlowMockProvider without config file."""

    def __init__(self, provider: SlowMockProvider) -> None:
        self.settings = JSSettings()
        self._providers: dict[str, ModelProvider] = {"mock": provider}
        self._model_map = {}

    async def select_model(self, task_complexity: str = "medium", preferred: str | None = None) -> Any:
        from js.models.router import RoutingDecision
        return RoutingDecision(
            provider=self._providers["mock"],
            model="gpt",
            provider_name="mock",
            reason="mock",
        )

    async def chat(self, messages: list[ChatMessage], model: str | None = None, tools: list[dict[str, Any]] | None = None, temperature: float = 0.7) -> ChatResponse:
        provider = self._providers["mock"]
        return await provider.chat(messages, model or "gpt", tools, temperature)

    async def chat_stream(self, messages: list[ChatMessage], model: str | None = None, temperature: float = 0.7):
        provider = self._providers["mock"]
        async for token in provider.chat_stream(messages, model or "gpt", temperature):
            yield token

    def get_model_config(self, model: str | None = None):
        from js.config import ModelConfig
        return ModelConfig(id="mock", provider="mock")

    async def health_check(self):
        return {"mock": True}


@pytest.fixture
def mock_provider() -> SlowMockProvider:
    return SlowMockProvider([])


@pytest.fixture
def agent(tmp_path: Path, mock_provider: SlowMockProvider) -> JSAgent:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=10,
    )
    a = JSAgent(settings)
    a.router = MockRouter(mock_provider)
    return a


class TestCancelAPI:
    @pytest.mark.asyncio
    async def test_request_cancel_sets_event(self, agent: JSAgent) -> None:
        token = asyncio.Event()
        agent._cancel_tokens["sess-1"] = token
        ok = agent.request_cancel("sess-1")
        assert ok is True
        assert token.is_set()

    @pytest.mark.asyncio
    async def test_request_cancel_unknown_session(self, agent: JSAgent) -> None:
        ok = agent.request_cancel("nonexistent")
        assert ok is False

    @pytest.mark.asyncio
    async def test_run_cancels_between_turns(self, agent: JSAgent, mock_provider: SlowMockProvider) -> None:
        """Cancel is observed at the start of the next turn."""
        mock_provider.set_responses([
            ChatResponse(
                content="",
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "file_list", "arguments": '{"path": "."}'},
                }],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                finish_reason="tool_calls",
            ),
            ChatResponse(
                content="Should not reach",
                tool_calls=[],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
                finish_reason="stop",
            ),
        ])

        session_id = "test-cancel-session"
        run_task = asyncio.create_task(agent.run("List files", session_id=session_id))
        # Allow first turn to start and provider to be called
        await asyncio.sleep(0.02)
        # Cancel before second turn begins
        agent.request_cancel(session_id)
        state = await run_task

        assert state.status == "cancelled"
        assert state.error_message == "Run cancelled by user request"
        assert state.turn_count >= 1


class TestCheckpoint:
    @pytest.mark.asyncio
    async def test_save_and_load_checkpoint(self, agent: JSAgent) -> None:
        state = AgentState(session_id="s1", run_id="r1")
        state.turn_count = 3
        state.messages.append(ChatMessage(role="user", content="hello"))
        state.messages.append(ChatMessage(role="assistant", content="hi"))
        state.total_tokens = {"input": 10, "output": 5}
        state.cost_estimate = 0.001
        state.status = "running"

        await agent.save_checkpoint(state)
        loaded = await agent.load_checkpoint("s1")

        assert loaded is not None
        assert loaded.session_id == "s1"
        assert loaded.run_id == "r1"
        assert loaded.turn_count == 3
        assert len(loaded.messages) == 2
        assert loaded.messages[0].role == "user"
        assert loaded.messages[0].content == "hello"
        assert loaded.total_tokens == {"input": 10, "output": 5}
        assert loaded.cost_estimate == pytest.approx(0.001)
        assert loaded.status == "running"

    @pytest.mark.asyncio
    async def test_load_missing_checkpoint(self, agent: JSAgent) -> None:
        loaded = await agent.load_checkpoint("no-such-session")
        assert loaded is None

    @pytest.mark.asyncio
    async def test_resume_from_checkpoint(self, agent: JSAgent, mock_provider: SlowMockProvider) -> None:
        """Resume continues from saved state and completes."""
        # First run: one turn with tool call, then cancel
        mock_provider.set_responses([
            ChatResponse(
                content="",
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "file_list", "arguments": '{"path": "."}'},
                }],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                finish_reason="tool_calls",
            ),
            ChatResponse(
                content="Done",
                tool_calls=[],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
                finish_reason="stop",
            ),
        ])

        session_id = "resume-test"
        state = await agent.run("List files", session_id=session_id)
        assert state.status == "completed"
        assert state.turn_count == 2

        # Resume from checkpoint with new user input
        mock_provider.set_responses([
            ChatResponse(
                content="Resumed",
                tool_calls=[],
                model="mock",
                usage={"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4},
                finish_reason="stop",
            ),
        ])

        resumed = await agent.resume(session_id, user_input="Continue")
        assert resumed.status == "completed"
        assert any(m.role == "user" and m.content == "Continue" for m in resumed.messages)


class TestStateStore:
    def test_save_load_delete(self, tmp_path: Path) -> None:
        store = StateStore(tmp_path / "checkpoints.db")
        store.save(
            session_id="s1",
            run_id="r1",
            turn_count=2,
            messages=[{"role": "user", "content": "hi"}],
            tool_results=[{"success": True, "output": "ok"}],
            total_tokens={"input": 5, "output": 3},
            cost_estimate=0.001,
            status="running",
            error_message="",
            compression_stats={"level": "none"},
        )

        data = store.load("s1")
        assert data is not None
        assert data["run_id"] == "r1"
        assert data["turn_count"] == 2
        assert data["messages"][0]["content"] == "hi"

        store.delete("s1")
        assert store.load("s1") is None

    def test_list_sessions(self, tmp_path: Path) -> None:
        store = StateStore(tmp_path / "checkpoints.db")
        for i in range(3):
            store.save(
                session_id=f"sess-{i}",
                run_id=f"run-{i}",
                turn_count=i,
                messages=[],
                tool_results=[],
                total_tokens={},
                cost_estimate=0.0,
                status="running",
                error_message="",
                compression_stats={},
            )
        sessions = store.list_sessions()
        assert len(sessions) == 3
        assert "sess-0" in sessions

    def test_upsert(self, tmp_path: Path) -> None:
        store = StateStore(tmp_path / "checkpoints.db")
        store.save(
            session_id="s1", run_id="r1", turn_count=1,
            messages=[], tool_results=[], total_tokens={},
            cost_estimate=0.0, status="running", error_message="",
            compression_stats={},
        )
        store.save(
            session_id="s1", run_id="r1", turn_count=2,
            messages=[], tool_results=[], total_tokens={},
            cost_estimate=0.0, status="completed", error_message="",
            compression_stats={},
        )
        data = store.load("s1")
        assert data["turn_count"] == 2
        assert data["status"] == "completed"


class TestGracefulShutdown:
    @pytest.mark.asyncio
    async def test_close_cancels_active_sessions(self, agent: JSAgent, mock_provider: SlowMockProvider) -> None:
        """close() signals cancellation for active sessions."""
        mock_provider.set_responses([
            ChatResponse(
                content="",
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "file_list", "arguments": '{"path": "."}'},
                }],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                finish_reason="tool_calls",
            ),
        ])

        session_id = "shutdown-test"
        run_task = asyncio.create_task(agent.run("List files", session_id=session_id))
        await asyncio.sleep(0.02)  # Let run start

        # close() should signal cancellation
        await agent.close()

        state = await run_task
        assert state.status == "cancelled"
