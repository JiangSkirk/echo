"""Production compression and model budgets use one explicit offline token unit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import js.echo.context_tokenizer as context_tokenizer
from js.agent import JSAgent
from js.compression.compressor import CompressionConfig, CompressionLevel, ContextCompressor
from js.config import JSSettings, ModelConfig, ModelProviderConfig
from js.echo.context_tokenizer import BoundTokenCounter, tiktoken_counter_factory
from js.models.providers import ChatMessage


def test_vendored_counter_triggers_compression_for_cjk_that_char_heuristic_misses() -> None:
    counter = tiktoken_counter_factory("cl100k_base")
    compressor = ContextCompressor(
        CompressionConfig(
            max_tokens=120,
            warning_threshold=0.8,
            critical_threshold=0.9,
            protect_head_messages=0,
            protect_tail_turns=0,
            use_llm_summary=False,
        ),
        token_counter=counter,
    )
    old_context = ChatMessage(
        role="assistant", content="订单已经支付，请核对工具返回的客户编号。" * 6
    )
    latest_request = ChatMessage(role="user", content="继续")

    result = compressor.compress_sync([old_context, latest_request])

    assert result.level == CompressionLevel.FULL
    assert old_context not in result.messages
    assert latest_request in result.messages
    assert result.token_unit_id == counter.token_unit_id


def test_tool_schema_uses_injected_counter_for_compression_trigger() -> None:
    counter = tiktoken_counter_factory("cl100k_base")
    compressor = ContextCompressor(
        CompressionConfig(
            max_tokens=320,
            warning_threshold=0.5,
            critical_threshold=0.9,
            protect_head_messages=0,
            protect_tail_turns=0,
            use_llm_summary=False,
        ),
        token_counter=counter,
    )
    messages = [ChatMessage(role="user", content="查询")]
    tools = [
        {
            "type": "function",
            "function": {
                "name": "lookup_order",
                "description": "查询订单状态、付款信息和收货地址。" * 18,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "order_id": {
                            "type": "string",
                            "description": "必须完整保留的订单编号",
                        }
                    },
                    "required": ["order_id"],
                },
            },
        }
    ]

    without_tools = compressor.compress_sync(messages)
    with_tools = compressor.compress_sync(messages, tools=tools)

    assert without_tools.level == CompressionLevel.NONE
    assert with_tools.level != CompressionLevel.NONE
    assert with_tools.original_tokens > without_tools.original_tokens


def test_compression_result_and_stats_expose_the_injected_token_unit() -> None:
    counter = BoundTokenCounter(count=lambda payload: len(payload), token_unit_id="test:bytes:v1")
    compressor = ContextCompressor(
        CompressionConfig(max_tokens=10_000),
        token_counter=counter,
    )
    messages = [ChatMessage(role="user", content="hello")]

    result = compressor.compress_sync(messages)
    stats = compressor.get_stats(messages, result.messages)

    assert result.token_unit_id == "test:bytes:v1"
    assert stats["token_unit_id"] == "test:bytes:v1"


def test_model_counter_selection_binds_provider_model_and_encoding() -> None:
    modern = context_tokenizer.model_token_counter(provider_name="openai", model="gpt-4o")
    legacy = context_tokenizer.model_token_counter(provider_name="openai", model="gpt-4-turbo")

    assert modern.token_unit_id.startswith("provider-model:openai/gpt-4o:")
    assert "tiktoken:o200k_base" in modern.token_unit_id
    assert legacy.token_unit_id.startswith("provider-model:openai/gpt-4-turbo:")
    assert "tiktoken:cl100k_base" in legacy.token_unit_id
    assert modern.token_unit_id != legacy.token_unit_id


def test_tiktoken_counter_reuses_a_canonical_payload_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repeated canonical bytes must not run the verified encoder again."""

    class _Encoding:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def encode(self, text: str) -> list[int]:
            self.calls.append(text)
            return list(text.encode("utf-8"))

    encoding = _Encoding()
    monkeypatch.setattr(
        context_tokenizer,
        "_declared_tokenizer_resource",
        lambda _name: ("/verified/cache", "a" * 64),
    )
    import tiktoken

    monkeypatch.setattr(tiktoken, "get_encoding", lambda _name: encoding)
    counter = context_tokenizer.tiktoken_counter_factory("cl100k_base")
    first_payload = "订单已经支付".encode()
    second_payload = "订单尚未支付".encode()

    assert counter(first_payload) == len(first_payload)
    assert counter(first_payload) == len(first_payload)
    assert counter(second_payload) == len(second_payload)
    assert encoding.calls == [first_payload.decode(), second_payload.decode()]
    assert counter.token_unit_id == "tiktoken:cl100k_base"


def test_agent_reuses_verified_auto_counter_without_weakening_cjk_fallback(
    tmp_path: Path,
) -> None:
    """Auto routing keeps one conservative unit instead of rebuilding it each turn."""

    agent = JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            providers=[],
            models=[],
        )
    )
    first = agent._token_counter_for_model(None)
    second = agent._token_counter_for_model(None)
    reference = tiktoken_counter_factory("cl100k_base")
    cjk_payload = "订单已经支付，请继续处理。".encode()

    assert first is second
    assert first.token_unit_id == second.token_unit_id
    assert "conservative:max-vendored-bpe" in first.token_unit_id
    assert first(cjk_payload) >= reference(cjk_payload)


def test_unknown_provider_counter_is_named_and_never_undercounts_vendored_reference() -> None:
    fallback = context_tokenizer.model_token_counter(
        provider_name="private-cloud", model="vendor-model-v7"
    )
    reference = tiktoken_counter_factory("cl100k_base")
    corpus = (
        "纯中文上下文：订单已经支付，请继续处理。".encode(),
        json.dumps(
            {
                "type": "function",
                "function": {
                    "name": "lookup",
                    "description": "查询订单和客户资料",
                    "parameters": {"type": "object", "required": ["订单号"]},
                },
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode(),
        b'{"tool_calls":[{"id":"call_1","arguments":"{\\"id\\":42}"}]}',
    )

    assert fallback.token_unit_id.startswith(
        "provider-model:private-cloud/vendor-model-v7:conservative:max-vendored-bpe"
    )
    assert all(fallback(payload) >= reference(payload) for payload in corpus)


def test_conservative_counter_fails_closed_without_declared_resource(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    empty_cache = tmp_path / "empty-tokenizer-cache"
    empty_cache.mkdir()
    monkeypatch.setenv("TIKTOKEN_CACHE_DIR", str(empty_cache))

    with pytest.raises(RuntimeError, match="declared tokenizer resource"):
        context_tokenizer.conservative_counter_factory()


def test_agent_model_budget_uses_the_selected_provider_model_unit(tmp_path: Path) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        providers=[
            ModelProviderConfig(
                name="openai",
                base_url="https://example.invalid/v1",
                default_model="gpt-4o",
                models=[ModelConfig(id="gpt-4o", provider="openai")],
            )
        ],
    )
    agent = JSAgent(settings)

    budget = agent._new_echo_model_budget(model="gpt-4o")

    assert budget.token_unit_id.startswith("provider-model:openai/gpt-4o:")
    assert "tiktoken:o200k_base" in budget.token_unit_id
