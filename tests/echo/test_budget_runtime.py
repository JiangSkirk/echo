from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from js.agent import JSAgent
from js.config import EchoBudgetConfig, JSSettings, MemoryConfig, ModelConfig
from js.echo.ledger.journal import FileEchoLedger
from js.echo.turn_loop import EchoBudgetExceededError
from js.models.providers import ChatMessage, ChatResponse, ModelProvider


class _Provider(ModelProvider):
    def __init__(self, response: ChatResponse) -> None:
        self.response = response
        self.calls = 0
        self.max_tokens: list[int | None] = []

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        del messages, model, tools, temperature
        self.calls += 1
        self.max_tokens.append(max_tokens)
        return self.response

    async def chat_stream(self, *args: Any, **kwargs: Any):
        del args, kwargs
        yield self.response.content

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        return None


def _agent(tmp_path: Path, budget: EchoBudgetConfig, response: ChatResponse) -> tuple[JSAgent, _Provider]:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=2,
        memory=MemoryConfig(capsule_enabled=False),
        echo_budget=budget,
    )
    agent = JSAgent(settings)
    provider = _Provider(response)
    agent.router.add_provider(
        "mock",
        provider,
        [ModelConfig(id="model", provider="mock", context_window=32_000)],
    )
    return agent, provider


@pytest.mark.asyncio
async def test_prompt_budget_blocks_before_provider_call(tmp_path: Path) -> None:
    agent, provider = _agent(
        tmp_path,
        EchoBudgetConfig(max_prompt_tokens=1),
        ChatResponse(
            content="must not run",
            model="model",
            usage={},
            tool_calls=[],
            finish_reason="stop",
        ),
    )
    try:
        state = await agent.run("hello", model="mock/model")
    finally:
        await agent.close()

    assert state.status == "error"
    assert state.error_message == "Echo budget exceeded: prompt_tokens_exceeded"
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_tool_budget_blocks_before_any_tool_handler(tmp_path: Path) -> None:
    agent, provider = _agent(
        tmp_path,
        EchoBudgetConfig(max_tool_calls=0),
        ChatResponse(
            content="",
            model="model",
            usage={"prompt_tokens": 10, "completion_tokens": 2},
            tool_calls=[
                {
                    "id": "call-1",
                    "type": "function",
                    "function": {"name": "file_read", "arguments": '{"path":"x"}'},
                }
            ],
            finish_reason="tool_calls",
        ),
    )
    calls_before = agent.registry.get_stats().get("file_read", 0)
    try:
        state = await agent.run("read x", model="mock/model")
    finally:
        await agent.close()

    assert provider.calls == 1
    assert agent.registry.get_stats().get("file_read", 0) == calls_before
    assert state.status == "error"
    assert state.error_message == "Echo budget exceeded: tool_calls_exceeded"


@pytest.mark.asyncio
async def test_background_model_call_enforces_prompt_budget_before_provider(
    tmp_path: Path,
) -> None:
    agent, provider = _agent(
        tmp_path,
        EchoBudgetConfig(max_prompt_tokens=1),
        ChatResponse(
            content="must not run",
            model="model",
            usage={},
            tool_calls=[],
            finish_reason="stop",
        ),
    )
    try:
        with pytest.raises(EchoBudgetExceededError, match="prompt_tokens_exceeded"):
            await agent.authorized_model_chat(
                [ChatMessage(role="user", content="background payload")],
                tenant_id="owner-a",
                run_id="dreaming:test",
                model="mock/model",
            )
    finally:
        await agent.close()

    assert provider.calls == 0


@pytest.mark.parametrize(
    "budget",
    [
        EchoBudgetConfig(max_prompt_tokens=1),
        EchoBudgetConfig(max_journal_appends=8),
    ],
)
@pytest.mark.asyncio
async def test_profile_runtime_blocks_prompt_or_journal_budget_before_provider(
    tmp_path: Path,
    budget: EchoBudgetConfig,
) -> None:
    agent, provider = _agent(
        tmp_path,
        budget,
        ChatResponse(
            content="must not run",
            model="model",
            usage={},
            tool_calls=[],
            finish_reason="stop",
        ),
    )
    try:
        with pytest.raises(EchoBudgetExceededError):
            await agent._auto_update_profiles(
                [
                    {
                        "user": "background payload",
                        "assistant": "reply",
                        "owner_key_hash": "owner-a",
                        "session_id": "session-a",
                    }
                ]
            )
    finally:
        await agent.close()

    assert provider.calls == 0


@pytest.mark.asyncio
async def test_completed_turn_exposes_consumed_budget(tmp_path: Path) -> None:
    agent, _provider = _agent(
        tmp_path,
        EchoBudgetConfig(),
        ChatResponse(
            content="ok",
            model="model",
            usage={"prompt_tokens": 10, "completion_tokens": 2},
            tool_calls=[],
            finish_reason="stop",
        ),
    )
    try:
        state = await agent.run("hello", model="mock/model")
    finally:
        await agent.close()

    assert state.status == "completed"
    assert state.compression_stats["echo_budget"]["prompt_tokens"] > 0
    assert state.compression_stats["echo_budget"]["completion_tokens"] == 2
    assert state.compression_stats["echo_budget"]["journal_appends"] == 9


def _receipt_statuses(agent: JSAgent, tenant_id: str, session_id: str) -> list[str]:
    records = FileEchoLedger(
        agent.echo_safety_service.journal_path_for_scope(
            tenant_id,
            product_id="js-agent",
            session_id=session_id,
        ),
        mac_key=agent.echo_safety_service.journal_key_for_scope(
            tenant_id,
            product_id="js-agent",
            session_id=session_id,
        ),
    ).records
    return [
        str(record.payload["status"])
        for record in records
        if record.record_type == "receipt"
    ]


@pytest.mark.asyncio
async def test_profile_runtime_preserves_completion_limit_and_failed_receipt(
    tmp_path: Path,
) -> None:
    agent, provider = _agent(
        tmp_path,
        EchoBudgetConfig(max_completion_tokens=3),
        ChatResponse(
            content="===USER===\nupdated\n===IDENTITY===\nupdated",
            model="model",
            usage={"prompt_tokens": 10, "completion_tokens": 4},
            tool_calls=[],
            finish_reason="stop",
        ),
    )
    try:
        with pytest.raises(
            EchoBudgetExceededError,
            match="completion_tokens_exceeded",
        ):
            await agent._auto_update_profiles(
                [
                    {
                        "user": "background payload",
                        "assistant": "reply",
                        "owner_key_hash": "owner-a",
                        "session_id": "session-a",
                    }
                ]
            )

        assert provider.max_tokens == [3]
        assert _receipt_statuses(agent, "owner-a", "session-a") == ["failed"]
        assert agent.memory.read_memory_file("user", owner_key_hash="owner-a") == ""
    finally:
        await agent.close()


@pytest.mark.asyncio
async def test_turn_completion_budget_is_provider_limit_and_hard_receipt_gate(
    tmp_path: Path,
) -> None:
    agent, provider = _agent(
        tmp_path,
        EchoBudgetConfig(max_completion_tokens=3),
        ChatResponse(
            content="provider ignored max_tokens",
            model="model",
            usage={"prompt_tokens": 10, "completion_tokens": 4},
            tool_calls=[],
            finish_reason="stop",
        ),
    )
    try:
        state = await agent.run("hello", model="mock/model")

        assert provider.max_tokens == [3]
        assert state.status == "error"
        assert state.error_message == "Echo budget exceeded: completion_tokens_exceeded"
        assert state.total_tokens["output"] == 0
        assert _receipt_statuses(agent, "local-user", state.session_id) == ["failed"]
    finally:
        await agent.close()


@pytest.mark.asyncio
async def test_background_completion_budget_is_provider_limit_and_hard_receipt_gate(
    tmp_path: Path,
) -> None:
    agent, provider = _agent(
        tmp_path,
        EchoBudgetConfig(max_completion_tokens=3),
        ChatResponse(
            content="provider ignored max_tokens",
            model="model",
            usage={"prompt_tokens": 10, "completion_tokens": 4},
            tool_calls=[],
            finish_reason="stop",
        ),
    )
    try:
        with pytest.raises(EchoBudgetExceededError, match="completion_tokens_exceeded"):
            await agent.authorized_model_chat(
                [ChatMessage(role="user", content="background payload")],
                tenant_id="owner-a",
                run_id="dreaming:test",
                model="mock/model",
            )

        assert provider.max_tokens == [3]
        assert _receipt_statuses(agent, "owner-a", "dreaming:test") == ["failed"]
    finally:
        await agent.close()
