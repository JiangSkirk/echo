"""Tests for empty-response retry logic.

When a model returns finish_reason="stop" with empty/whitespace content,
the agent should retry instead of silently completing.
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


class MockEmptyProvider(ModelProvider):
    """Provider that returns scripted responses, including empty ones."""

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
            content="Default mock response",
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

        return _gen()

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


class MockRouter(ModelRouter):
    def __init__(
        self,
        provider: MockEmptyProvider,
        *,
        permit_verifier: ModelPermitIssuer,
    ) -> None:
        self.settings = JSSettings()
        self._providers: dict[str, ModelProvider] = {"mock": provider}
        self._model_map = {}
        self._permit_verifier = permit_verifier

    async def select_model(
        self, task_complexity: str = "medium", preferred: str | None = None
    ) -> Any:
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
def mock_provider() -> MockEmptyProvider:
    return MockEmptyProvider()


@pytest.fixture
def agent(tmp_path: Path, mock_provider: MockEmptyProvider) -> JSAgent:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=5,
        max_empty_response_retries=3,
    )
    agent = JSAgent(settings)
    agent.router = MockRouter(
        mock_provider,
        permit_verifier=agent._model_permit_issuer,
    )
    return agent


class TestEmptyResponseRetry:
    @pytest.mark.asyncio
    async def test_empty_response_retries_then_succeeds(
        self, agent: JSAgent, mock_provider: MockEmptyProvider
    ) -> None:
        """Empty responses should be retried until a non-empty one is received."""
        mock_provider.set_responses(
            [
                ChatResponse(
                    content="",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 5, "completion_tokens": 0, "total_tokens": 5},
                    finish_reason="stop",
                ),
                ChatResponse(
                    content="",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 5, "completion_tokens": 0, "total_tokens": 5},
                    finish_reason="stop",
                ),
                ChatResponse(
                    content="Got it!",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
                    finish_reason="stop",
                ),
            ]
        )

        state = await agent.run("Test retry")

        assert state.status == "completed"
        assert state.turn_count == 3
        assert any(m.role == "assistant" and m.content == "Got it!" for m in state.messages)
        # Empty assistant messages should have been popped, not retained
        assert not any(m.role == "assistant" and m.content == "" for m in state.messages)

    @pytest.mark.asyncio
    async def test_empty_response_exhausts_max_retries(
        self, agent: JSAgent, mock_provider: MockEmptyProvider
    ) -> None:
        """Consecutive empties should error after max_empty_response_retries, not max_turns."""
        mock_provider.set_responses(
            [
                ChatResponse(
                    content="",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 5, "completion_tokens": 0, "total_tokens": 5},
                    finish_reason="stop",
                ),
                ChatResponse(
                    content="",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 5, "completion_tokens": 0, "total_tokens": 5},
                    finish_reason="stop",
                ),
                ChatResponse(
                    content="",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 5, "completion_tokens": 0, "total_tokens": 5},
                    finish_reason="stop",
                ),
                ChatResponse(
                    content="Should not reach",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
                    finish_reason="stop",
                ),
            ]
        )

        state = await agent.run("Test exhaust")

        assert state.status == "error"
        assert state.turn_count == 3  # max_empty_response_retries=3
        assert len(mock_provider.calls) == 3
        assert state.error_message is not None
        assert (
            "maximum retries" in state.error_message.lower()
            or "empty" in state.error_message.lower()
        )
        # No empty assistant messages should remain
        assert not any(m.role == "assistant" and m.content == "" for m in state.messages)

    @pytest.mark.asyncio
    async def test_single_empty_then_success(
        self, agent: JSAgent, mock_provider: MockEmptyProvider
    ) -> None:
        """A single empty response followed by success."""
        mock_provider.set_responses(
            [
                ChatResponse(
                    content="  ",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 5, "completion_tokens": 0, "total_tokens": 5},
                    finish_reason="stop",
                ),
                ChatResponse(
                    content="OK",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
                    finish_reason="stop",
                ),
            ]
        )

        state = await agent.run("Test whitespace")

        assert state.status == "completed"
        assert state.turn_count == 2
        assert any(m.role == "assistant" and m.content == "OK" for m in state.messages)
