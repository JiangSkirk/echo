"""Echo T8-S3B/T9-A — agent prompt-path context runtime integration."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from js.agent import JSAgent
from js.config import JSSettings
from js.echo.context_runtime import (
    get_context_runtime_snapshot_for_tests,
    reset_context_runtime_for_tests,
)
from js.models.permit import ModelPermitError, ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter, RoutingDecision


class RecordingProvider(ModelProvider):
    def __init__(self) -> None:
        self.calls: list[tuple[list[ChatMessage], list[dict[str, Any]] | None]] = []

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.calls.append((messages, tools))
        return ChatResponse(
            content="Echo integration response",
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
            yield "Echo"

        return _gen()

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


class RecordingRouter(ModelRouter):
    def __init__(
        self,
        provider: RecordingProvider,
        *,
        permit_verifier: ModelPermitIssuer | None = None,
    ) -> None:
        self.settings = JSSettings()
        self._providers: dict[str, ModelProvider] = {"mock": provider}
        self._model_map: dict[str, str] = {}
        self._permit_verifier = permit_verifier or ModelPermitIssuer()

    async def select_model(
        self, task_complexity: str = "medium", preferred: str | None = None
    ) -> RoutingDecision:
        return RoutingDecision(
            provider=self._providers["mock"],
            model="mock",
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
            raise RuntimeError(
                "Echo requires before_model_call/after_model_call callbacks and "
                "a runtime-issued permit_grant for ModelRouter.chat(); direct "
                "provider chat is only available through the Echo turn runtime."
            )
        if self._permit_verifier is None:
            raise ModelPermitError(
                "ModelRouter has no Echo permit verifier; direct provider calls "
                "are only available through the Echo turn runtime."
            )

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
        except Exception as exc:
            await after_model_call(context, None, exc)
            raise
        await after_model_call(context, response, None)
        return response


@pytest.fixture
def provider() -> RecordingProvider:
    return RecordingProvider()


@pytest.fixture
def agent(tmp_path: Path, provider: RecordingProvider) -> JSAgent:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=3,
    )
    agent = JSAgent(settings)
    agent.router = RecordingRouter(provider, permit_verifier=agent._model_permit_issuer)
    return agent


@pytest.fixture(autouse=True)
def _reset_runtime() -> None:
    reset_context_runtime_for_tests()


@pytest.mark.asyncio
async def test_echo_records_context_metrics_without_changing_provider_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    provider_live = RecordingProvider()
    agent_live = JSAgent(JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state"))
    agent_live.router = RecordingRouter(
        provider_live,
        permit_verifier=agent_live._model_permit_issuer,
    )
    live_state = await agent_live.run("Say hello", session_id="same-session")
    live_payload = [(m.role, m.content) for m in provider_live.calls[0][0]]

    assert live_state.status == "completed"
    assert live_payload
    assert len(provider_live.calls) == 1
    echo_stats = live_state.compression_stats["echo_context_savings"]
    compression_stats = live_state.compression_stats["compression"]
    assert echo_stats["mode"] == "on"
    assert echo_stats["channel"] == "agent_turn"
    assert echo_stats["naive_tokens"] > 0
    assert echo_stats["new_cas_tokens"] > 0
    assert echo_stats["token_unit_id"]
    assert compression_stats["token_unit_id"] == echo_stats["token_unit_id"]
    assert (
        live_state.compression_stats["echo_budget"]["token_unit_id"]
        == compression_stats["token_unit_id"]
    )
    assert get_context_runtime_snapshot_for_tests().observation_count == 1


@pytest.mark.asyncio
async def test_echo_on_trims_long_history_before_provider_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    history = [
        {
            "role": "user" if index % 2 == 0 else "assistant",
            "content": f"long history message {index} " + ("x " * 80),
        }
        for index in range(40)
    ]

    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    provider_on = RecordingProvider()
    agent_on = JSAgent(
        JSSettings(workspace=tmp_path / "on_workspace", state_dir=tmp_path / "on_state")
    )
    agent_on.router = RecordingRouter(
        provider_on,
        permit_verifier=agent_on._model_permit_issuer,
    )
    agent_on.memory.store_messages("long-session", history)
    await agent_on.run("current question", session_id="long-session")
    on_payload_count = len(provider_on.calls[0][0])

    assert len(history) > 30
    assert on_payload_count <= 16
    assert on_payload_count < len(history)


@pytest.mark.asyncio
async def test_echo_context_runtime_failure_falls_back_to_legacy_provider(
    monkeypatch: pytest.MonkeyPatch,
    agent: JSAgent,
    provider: RecordingProvider,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("runtime adapter exploded")

    monkeypatch.setattr("js.echo.turn_loop.loop.observe_prompt_context", boom)

    state = await agent.run("Say hello", session_id="echo-context-unavailable-session")

    assert state.status == "completed"
    assert len(provider.calls) == 1
    echo_stats = state.compression_stats["echo_context_savings"]
    assert echo_stats["mode"] == "on"
    assert echo_stats["error"] == "RuntimeError: runtime adapter exploded"
