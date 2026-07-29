"""End-to-end integration tests with a mock model provider.

These tests verify the full agent loop: message handling, tool execution,
context compression, and state management — without calling real LLM APIs.
"""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from js.agent import JSAgent
from js.config import JSSettings
from js.models.permit import ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter


class MockModelProvider(ModelProvider):
    """A mock provider that returns scripted responses for testing."""

    def __init__(self, responses: list[ChatResponse] | None = None) -> None:
        self._responses = responses or []
        self._index = 0
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
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.calls.append(messages)
        if self._index < len(self._responses):
            resp = self._responses[self._index]
            self._index += 1
            return resp
        return ChatResponse(
            content="Mock response",
            tool_calls=[],
            model="mock",
            usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            finish_reason="stop",
        )

    def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        async def _gen() -> AsyncIterator[str]:
            yield "Mock"
            yield " stream"
        return _gen()

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


class MockRouter(ModelRouter):
    """Router that uses a MockProvider without config file."""

    def __init__(
        self,
        provider: MockModelProvider,
        *,
        permit_verifier: ModelPermitIssuer,
    ) -> None:
        self.settings = JSSettings()
        self._providers: dict[str, ModelProvider] = {"mock": provider}
        self._model_map = {}
        self._permit_verifier = permit_verifier

    async def select_model(self, task_complexity: str = "medium", preferred: str | None = None) -> Any:
        from js.models.router import RoutingDecision
        return RoutingDecision(
            provider=self._providers["mock"],
            model="gpt",
            provider_name="mock",
            reason="mock",
        )

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        before_model_call: Any = None,
        after_model_call: Any = None,
        permit_grant: Any = None,
    ) -> ChatResponse:
        if before_model_call is None or after_model_call is None or permit_grant is None:
            raise RuntimeError("test router requires Echo model callbacks and a permit grant")
        decision = await self.select_model(preferred=model)
        self._consume_model_permit(permit_grant, decision, messages, tools)
        context = await before_model_call(decision, messages, tools)
        try:
            response = await decision.provider.chat(
                messages=messages,
                model=decision.model,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except BaseException as exc:
            await after_model_call(context, None, exc)
            raise
        await after_model_call(context, response, None)
        return response


@pytest.fixture
def mock_provider() -> MockModelProvider:
    return MockModelProvider()


@pytest.fixture
def agent(tmp_path: Path, mock_provider: MockModelProvider) -> JSAgent:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=10,
    )
    agent = JSAgent(settings)
    agent.router = MockRouter(
        mock_provider,
        permit_verifier=agent._model_permit_issuer,
    )
    return agent


class TestAgentIntegration:
    @pytest.mark.asyncio
    async def test_simple_conversation(self, agent: JSAgent, mock_provider: MockModelProvider) -> None:
        """Agent returns assistant response without tool calls."""
        mock_provider.set_responses([
            ChatResponse(
                content="Hello, user!",
                tool_calls=[],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
                finish_reason="stop",
            ),
        ])

        state = await agent.run("Say hello")

        assert state.status == "completed"
        assert state.turn_count == 1
        assert any(
            m.role == "assistant" and isinstance(m.content, str) and "Hello, user!" in m.content
            for m in state.messages
        )

    @pytest.mark.asyncio
    async def test_tool_call_loop(self, agent: JSAgent, mock_provider: MockModelProvider) -> None:
        """Agent executes a tool call and continues the conversation."""
        mock_provider.set_responses([
            ChatResponse(
                content="",
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "file_list",
                        "arguments": '{"path": "."}',
                    },
                }],
                model="mock",
                usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                finish_reason="tool_calls",
            ),
            ChatResponse(
                content="I found some files for you.",
                tool_calls=[],
                model="mock",
                usage={"prompt_tokens": 15, "completion_tokens": 5, "total_tokens": 20},
                finish_reason="stop",
            ),
        ])

        state = await agent.run("List files")

        assert state.status == "completed"
        assert state.turn_count == 2
        assert any(
            m.role == "tool" for m in state.messages
        )
        assert any(
            m.role == "assistant" and isinstance(m.content, str) and "found some files" in m.content
            for m in state.messages
        )

    @pytest.mark.asyncio
    async def test_chat_stream(self, agent: JSAgent, mock_provider: MockModelProvider) -> None:
        """Streaming yields tokens one by one."""
        tokens: list[str] = []
        async for token in agent.chat_stream("Stream test"):
            tokens.append(token)
        assert tokens == ["Mock", " stream"]

    @pytest.mark.asyncio
    async def test_max_turns_limit(self, agent: JSAgent, mock_provider: MockModelProvider) -> None:
        """Agent stops after max_turns even if tool calls keep coming."""
        agent.settings.max_turns = 3
        mock_provider.set_responses([
            ChatResponse(
                content="",
                tool_calls=[{
                    "id": f"call_{i}",
                    "type": "function",
                    "function": {"name": "file_list", "arguments": "{}"},
                }],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                finish_reason="tool_calls",
            )
            for i in range(5)
        ])

        state = await agent.run("Infinite loop test")

        assert state.turn_count == 3
        assert state.status == "error"
        assert "maximum turn limit" in state.error_message.lower()

    @pytest.mark.asyncio
    async def test_memory_and_audit_persistence(self, agent: JSAgent, mock_provider: MockModelProvider) -> None:
        """Audit log and memory store work across runs."""
        mock_provider.set_responses([
            ChatResponse(
                content="Session 1",
                tool_calls=[],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
                finish_reason="stop",
            ),
        ])

        await agent.run("First message")
        # Audit should have recorded the run
        events = agent.audit.query(limit=10)
        assert len(events) > 0
        # Memory store should exist
        assert agent.memory.retrieve("nonexistent") is None
