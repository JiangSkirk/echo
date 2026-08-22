from __future__ import annotations

import asyncio
import gc
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from js.agent import JSAgent
from js.config import EchoBudgetConfig, JSSettings, MemoryConfig, ModelConfig
from js.echo.ledger.journal import FileEchoLedger
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.stream_events import StreamEvent


class _StreamingProvider(ModelProvider):
    def __init__(self, events: list[StreamEvent]) -> None:
        self.events = events
        self.max_tokens: list[int | None] = []

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        del messages, model, tools, temperature, max_tokens
        raise AssertionError("streaming test unexpectedly used non-streaming provider path")

    async def chat_stream(self, *args: Any, **kwargs: Any) -> AsyncIterator[str]:
        del args, kwargs
        raise AssertionError("streaming test unexpectedly used legacy stream path")
        yield ""  # pragma: no cover - keeps this an async iterator

    async def chat_stream_events(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[StreamEvent]:
        del messages, model, tools, temperature
        self.max_tokens.append(max_tokens)
        for event in self.events:
            yield event

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        return None


def _agent(
    tmp_path: Path,
    events: list[StreamEvent],
) -> tuple[JSAgent, _StreamingProvider]:
    agent = JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            max_turns=2,
            memory=MemoryConfig(capsule_enabled=False),
            echo_budget=EchoBudgetConfig(max_completion_tokens=3),
        )
    )
    provider = _StreamingProvider(events)
    agent.router.add_provider(
        "mock",
        provider,
        [ModelConfig(id="model", provider="mock", context_window=32_000)],
    )
    return agent, provider


def _receipts(agent: JSAgent, session_id: str) -> list[dict[str, Any]]:
    records = FileEchoLedger(
        agent.echo_safety_service.journal_path_for_scope(
            "local-user", product_id="js-agent", session_id=session_id
        ),
        mac_key=agent.echo_safety_service.journal_key_for_scope(
            "local-user", product_id="js-agent", session_id=session_id
        ),
    ).records
    return [dict(record.payload) for record in records if record.record_type == "receipt"]


@pytest.mark.asyncio
async def test_budget_abort_closes_stream_in_its_bound_context(tmp_path: Path) -> None:
    agent, _provider = _agent(
        tmp_path,
        [
            *(StreamEvent(kind="text_delta", text=token) for token in "abcdefghijklmnop"),
            StreamEvent(kind="done", finish_reason="stop"),
        ],
    )
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    unhandled: list[dict[str, Any]] = []
    loop.set_exception_handler(lambda _loop, context: unhandled.append(context))

    try:
        state = await agent.run(
            "stream a bounded answer",
            model="mock/model",
            stream_callback=lambda _token: _async_noop(),
            disable_tools=True,
        )
        gc.collect()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        assert state.status == "error"
        assert unhandled == []
    finally:
        loop.set_exception_handler(previous_handler)
        await agent.close()


@pytest.mark.asyncio
async def test_stream_without_usage_stops_before_completion_budget_and_fails_receipt(
    tmp_path: Path,
) -> None:
    agent, provider = _agent(
        tmp_path,
        [
            *(StreamEvent(kind="text_delta", text=token) for token in "abcdefghijklmnop"),
            StreamEvent(kind="done", finish_reason="stop"),
        ],
    )
    forwarded: list[str] = []

    async def on_token(token: str) -> None:
        forwarded.append(token)

    try:
        state = await agent.run(
            "stream a bounded answer",
            model="mock/model",
            stream_callback=on_token,
            disable_tools=True,
        )

        assert provider.max_tokens == [3]
        assert "".join(forwarded) == "abcdefghijkl"
        assert state.status == "error"
        assert state.error_message == "Echo budget exceeded: completion_tokens_exceeded"
        assert state.total_tokens["output"] == 0
        assert state.compression_stats["echo_budget"]["completion_tokens"] == 3
        assert state.compression_stats["echo_budget"]["completion_tokens_attempted"] == 4
        receipts = _receipts(agent, state.session_id)
        assert len(receipts) == 1
        assert receipts[0]["status"] == "failed"
        assert receipts[0]["token_totals"] == {
            "input": state.compression_stats["echo_budget"]["prompt_tokens"],
            "output": 4,
        }
        assert receipts[0]["token_source"] == "estimated"
    finally:
        await agent.close()


@pytest.mark.asyncio
async def test_stream_budget_is_independent_of_provider_chunk_boundaries(tmp_path: Path) -> None:
    agent, _provider = _agent(
        tmp_path,
        [
            *(StreamEvent(kind="text_delta", text=token) for token in "abcdefghijkl"),
            StreamEvent(kind="done", finish_reason="stop"),
        ],
    )
    forwarded: list[str] = []

    async def on_token(token: str) -> None:
        forwarded.append(token)

    try:
        state = await agent.run(
            "stream a bounded answer",
            model="mock/model",
            stream_callback=on_token,
            disable_tools=True,
        )

        assert state.status == "completed"
        assert "".join(forwarded) == "abcdefghijkl"
        assert state.total_tokens["output"] == 3
        assert _receipts(agent, state.session_id)[0]["token_totals"]["output"] == 3
    finally:
        await agent.close()


@pytest.mark.asyncio
async def test_stream_with_provider_usage_completes_without_double_counting(tmp_path: Path) -> None:
    agent, provider = _agent(
        tmp_path,
        [
            StreamEvent(kind="text_delta", text="a"),
            StreamEvent(kind="text_delta", text="b"),
            StreamEvent(
                kind="usage",
                usage={
                    "prompt_tokens": 11,
                    "completion_tokens": 2,
                    "total_tokens": 13,
                    "cached_tokens": 0,
                },
            ),
            StreamEvent(kind="done", finish_reason="stop"),
        ],
    )
    forwarded: list[str] = []

    async def on_token(token: str) -> None:
        forwarded.append(token)

    try:
        state = await agent.run(
            "stream a bounded answer",
            model="mock/model",
            stream_callback=on_token,
            disable_tools=True,
        )

        assert provider.max_tokens == [3]
        assert "".join(forwarded) == "ab"
        assert state.status == "completed"
        assert state.total_tokens["output"] == 2
        assert state.compression_stats["echo_budget"]["completion_tokens"] == 2
        assert _receipts(agent, state.session_id)[0]["status"] == "completed"
        assert _receipts(agent, state.session_id)[0]["token_totals"] == {
            "input": 11,
            "output": 2,
        }
        assert _receipts(agent, state.session_id)[0]["token_source"] == "provider_actual"
    finally:
        await agent.close()


@pytest.mark.asyncio
async def test_partial_stream_error_counts_conservative_completion_in_failed_receipt(
    tmp_path: Path,
) -> None:
    agent, _provider = _agent(
        tmp_path,
        [
            StreamEvent(kind="text_delta", text="abcdefgh"),
            StreamEvent(
                kind="usage",
                usage={
                    "prompt_tokens": 7,
                    "completion_tokens": 3,
                    "total_tokens": 10,
                    "cached_tokens": 0,
                },
            ),
            StreamEvent(kind="error", error="provider failed"),
        ],
    )

    try:
        state = await agent.run(
            "stream then fail",
            model="mock/model",
            stream_callback=lambda _token: _async_noop(),
            disable_tools=True,
        )

        assert state.status == "error"
        assert state.compression_stats["echo_budget"]["completion_tokens"] == 3
        receipts = _receipts(agent, state.session_id)
        assert len(receipts) == 1
        assert receipts[0]["status"] == "failed"
        assert receipts[0]["token_totals"]["output"] == 3
        assert receipts[0]["token_source"] == "provider_actual"
    finally:
        await agent.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "chunks",
    [
        ["abcdefghijkl"],
        ["a", "bc", "def", "ghijkl"],
    ],
)
async def test_provider_usage_below_text_estimate_uses_conservative_budget(
    tmp_path: Path,
    chunks: list[str],
) -> None:
    agent, _provider = _agent(
        tmp_path,
        [
            *(StreamEvent(kind="text_delta", text=chunk) for chunk in chunks),
            StreamEvent(
                kind="usage",
                usage={
                    "prompt_tokens": 7,
                    "completion_tokens": 1,
                    "total_tokens": 8,
                    "cached_tokens": 0,
                },
            ),
            StreamEvent(kind="done", finish_reason="stop"),
        ],
    )

    try:
        state = await agent.run(
            "stream conservatively",
            model="mock/model",
            stream_callback=lambda _token: _async_noop(),
            disable_tools=True,
        )

        assert state.status == "completed"
        assert state.total_tokens["output"] == 3
        assert state.compression_stats["echo_budget"]["completion_tokens"] == 3
        receipt = _receipts(agent, state.session_id)[0]
        assert receipt["token_totals"] == {"input": 7, "output": 3}
        assert receipt["token_source"] == "estimated"
    finally:
        await agent.close()


@pytest.mark.asyncio
async def test_failed_usage_consumption_reduces_fallback_turn_budget(tmp_path: Path) -> None:
    agent = JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            max_turns=2,
            memory=MemoryConfig(capsule_enabled=False),
            echo_budget=EchoBudgetConfig(max_completion_tokens=5),
        )
    )
    primary = _StreamingProvider(
        [
            StreamEvent(
                kind="usage",
                usage={
                    "prompt_tokens": 7,
                    "completion_tokens": 3,
                    "total_tokens": 10,
                    "cached_tokens": 0,
                },
            ),
            StreamEvent(kind="error", error="failed after reasoning"),
        ]
    )
    backup = _StreamingProvider(
        [
            StreamEvent(kind="text_delta", text="abcdefgh"),
            StreamEvent(kind="done", finish_reason="stop"),
        ]
    )
    agent.router.add_provider(
        "primary",
        primary,
        [ModelConfig(id="primary-model", provider="primary", context_window=32_000)],
    )
    agent.router.add_provider(
        "backup",
        backup,
        [ModelConfig(id="backup-model", provider="backup", context_window=32_000)],
    )

    try:
        state = await agent.run(
            "fallback within one completion budget",
            stream_callback=lambda _token: _async_noop(),
            disable_tools=True,
        )

        assert state.status == "completed"
        assert primary.max_tokens == [5]
        assert backup.max_tokens == [2]
        assert state.compression_stats["echo_budget"]["completion_tokens"] == 5
        receipts = _receipts(agent, state.session_id)
        assert [receipt["status"] for receipt in receipts] == ["failed", "completed"]
        assert [receipt["token_totals"]["output"] for receipt in receipts] == [3, 2]
        assert [receipt["token_source"] for receipt in receipts] == [
            "provider_actual",
            "estimated",
        ]
    finally:
        await agent.close()


@pytest.mark.asyncio
async def test_auto_selected_stream_primary_and_fallback_each_use_own_model_cap(
    tmp_path: Path,
) -> None:
    agent = JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            max_turns=2,
            memory=MemoryConfig(capsule_enabled=False),
            echo_budget=EchoBudgetConfig(max_completion_tokens=5),
        )
    )
    primary = _StreamingProvider(
        [
            StreamEvent(
                kind="usage",
                usage={
                    "prompt_tokens": 7,
                    "completion_tokens": 3,
                    "total_tokens": 10,
                    "cached_tokens": 0,
                },
            ),
            StreamEvent(kind="error", error="failed after reasoning"),
        ]
    )
    backup = _StreamingProvider(
        [
            StreamEvent(kind="text_delta", text="ok"),
            StreamEvent(kind="done", finish_reason="stop"),
        ]
    )
    agent.router.add_provider(
        "primary",
        primary,
        [
            ModelConfig(
                id="primary-model",
                provider="primary",
                context_window=32_000,
                max_tokens=4,
            )
        ],
    )
    agent.router.add_provider(
        "backup",
        backup,
        [
            ModelConfig(
                id="backup-model",
                provider="backup",
                context_window=32_000,
                max_tokens=1,
            )
        ],
    )

    try:
        state = await agent.run(
            "fallback within selected model caps",
            stream_callback=lambda _token: _async_noop(),
            disable_tools=True,
        )

        assert state.status == "completed"
        assert primary.max_tokens == [4]
        assert backup.max_tokens == [1]
        assert [receipt["status"] for receipt in _receipts(agent, state.session_id)] == [
            "failed",
            "completed",
        ]
        assert agent.echo_safety_service.health().claimed_effect_count == 0
    finally:
        await agent.close()


@pytest.mark.parametrize("raw_max_tokens", [True, False])
def test_model_config_rejects_boolean_max_tokens(raw_max_tokens: bool) -> None:
    with pytest.raises(ValidationError, match="max_tokens"):
        ModelConfig(
            id="model",
            provider="mock",
            context_window=32_000,
            max_tokens=raw_max_tokens,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("raw_max_tokens", [True, False])
async def test_raw_boolean_model_cap_does_not_clamp_provider_request(
    tmp_path: Path,
    raw_max_tokens: bool,
) -> None:
    agent = JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            max_turns=1,
            memory=MemoryConfig(capsule_enabled=False),
            echo_budget=EchoBudgetConfig(max_completion_tokens=5),
        )
    )
    provider = _StreamingProvider(
        [
            StreamEvent(kind="text_delta", text="ok"),
            StreamEvent(kind="done", finish_reason="stop"),
        ]
    )
    raw_config = ModelConfig(
        id="model",
        provider="mock",
        context_window=32_000,
        max_tokens=4,
    )
    raw_config.max_tokens = raw_max_tokens
    agent.router.add_provider("mock", provider, [raw_config])

    try:
        state = await agent.run(
            "preserve the request cap for a raw boolean config",
            stream_callback=lambda _token: _async_noop(),
            disable_tools=True,
        )

        assert state.status == "completed"
        assert provider.max_tokens == [5]
    finally:
        await agent.close()


@pytest.mark.asyncio
async def test_request_max_tokens_clamped_to_model_max_tokens(tmp_path: Path) -> None:
    """Echo completion budget is a hard ceiling; request max_tokens follows model cap."""
    agent = JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            max_turns=1,
            memory=MemoryConfig(capsule_enabled=False),
            echo_budget=EchoBudgetConfig(max_completion_tokens=32_768),
        )
    )
    provider = _StreamingProvider(
        [
            StreamEvent(kind="text_delta", text="ok"),
            StreamEvent(kind="done", finish_reason="stop"),
        ]
    )
    agent.router.add_provider(
        "mock",
        provider,
        [ModelConfig(id="model", provider="mock", context_window=32_000, max_tokens=128)],
    )
    try:
        state = await agent.run(
            "say ok",
            model="mock/model",
            stream_callback=lambda _token: _async_noop(),
            disable_tools=True,
        )
        assert state.status == "completed"
        assert provider.max_tokens == [128]
    finally:
        await agent.close()


async def _async_noop() -> None:
    return None
