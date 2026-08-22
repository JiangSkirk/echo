"""Tests for context compressor."""

from pathlib import Path

import pytest

from js.compression.compressor import (
    SUMMARY_PREFIX,
    CompressionConfig,
    CompressionLevel,
    ContextCompressor,
)
from js.echo.model_budget import EchoBudgetExceededError
from js.models.providers import ChatMessage


def _tool_call(call_id: str, name: str = "lookup") -> dict[str, object]:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": "{}"},
    }


def _tool_assistant(*call_ids: str) -> ChatMessage:
    return ChatMessage(
        role="assistant",
        content="",
        tool_calls=[_tool_call(call_id) for call_id in call_ids],
    )


def _assert_tool_protocol_is_complete(messages: list[ChatMessage]) -> None:
    """Assert the provider-visible assistant/tool ordering contract."""
    calls: dict[str, int] = {}
    results: set[str] = set()
    for index, message in enumerate(messages):
        if message.tool_calls:
            assert message.role == "assistant"
            for call in message.tool_calls:
                call_id = call.get("id")
                assert isinstance(call_id, str) and call_id
                assert call_id not in calls
                calls[call_id] = index
        if message.role == "tool":
            call_id = message.tool_call_id
            assert isinstance(call_id, str) and call_id
            assert call_id in calls
            assert call_id not in results
            assert calls[call_id] < index
            results.add(call_id)


def _full_config(*, max_tokens: int = 2_000) -> CompressionConfig:
    return CompressionConfig(
        max_tokens=max_tokens,
        warning_threshold=0.0,
        critical_threshold=0.0,
        protect_head_messages=2,
        protect_tail_turns=1,
        use_llm_summary=False,
    )


def _head_boundary_messages() -> list[ChatMessage]:
    return [
        ChatMessage(role="system", content="primary security policy"),
        _tool_assistant("head-a", "head-b"),
        ChatMessage(role="tool", content="result-a", tool_call_id="head-a"),
        ChatMessage(role="tool", content="result-b", tool_call_id="head-b"),
        ChatMessage(role="user", content="older question"),
        ChatMessage(role="assistant", content="older answer"),
        ChatMessage(role="user", content="latest question"),
        ChatMessage(role="assistant", content="latest answer"),
    ]


def _tail_boundary_messages() -> list[ChatMessage]:
    return [
        ChatMessage(role="system", content="primary security policy"),
        ChatMessage(role="user", content="older question"),
        ChatMessage(role="assistant", content="older answer"),
        ChatMessage(role="user", content="middle question"),
        _tool_assistant("tail-a", "tail-b"),
        ChatMessage(role="tool", content="result-a", tool_call_id="tail-a"),
        ChatMessage(role="tool", content="result-b", tool_call_id="tail-b"),
        ChatMessage(role="user", content="latest question"),
    ]


class TestContextCompressor:
    @pytest.fixture
    def compressor(self) -> ContextCompressor:
        return ContextCompressor(
            CompressionConfig(
                # Leaves room for the generated summary under the vendored cl100k
                # counter while still forcing the long-history fixture to compress.
                max_tokens=700,
                protect_head_messages=2,
                protect_tail_turns=2,
                enable_compression=True,
                use_llm_summary=False,
            )
        )

    @pytest.mark.asyncio
    async def test_no_compression_when_under_budget(self, compressor: ContextCompressor) -> None:
        messages = [
            ChatMessage(role="system", content="You are helpful"),
            ChatMessage(role="user", content="Hi"),
            ChatMessage(role="assistant", content="Hello"),
        ]
        result = await compressor.compress(messages)
        assert len(result.messages) == 3
        assert result.level == CompressionLevel.NONE

    @pytest.mark.asyncio
    async def test_compression_splits_head_middle_tail(self, compressor: ContextCompressor) -> None:
        messages = [
            ChatMessage(role="system", content="System prompt"),
            ChatMessage(role="user", content="Question 1"),
            ChatMessage(role="assistant", content="Answer 1" * 100),
            ChatMessage(role="user", content="Question 2"),
            ChatMessage(role="assistant", content="Answer 2" * 100),
            ChatMessage(role="user", content="Question 3"),
            ChatMessage(role="assistant", content="Answer 3" * 100),
            ChatMessage(role="user", content="Latest question"),
            ChatMessage(role="assistant", content="Latest answer"),
        ]
        result = await compressor.compress(messages)
        msgs = result.messages
        # Should have head + summary + tail
        assert len(msgs) < len(messages)
        # Head should be preserved
        assert msgs[0].role == "system"
        assert msgs[0].content == "System prompt"
        # Tail should be preserved (last 2 turns = 4 messages)
        assert msgs[-1].content == "Latest answer"
        # Middle should be summarized
        assert any("CONTEXT COMPACTION" in (m.content or "") for m in msgs)

    @pytest.mark.asyncio
    async def test_stats(self, compressor: ContextCompressor) -> None:
        messages = [
            ChatMessage(role="system", content="System"),
            ChatMessage(role="user", content="User" * 500),
            ChatMessage(role="assistant", content="Assistant" * 500),
            ChatMessage(role="user", content="Current request"),
            ChatMessage(role="assistant", content="Current answer"),
        ]
        result = await compressor.compress(messages)
        stats = compressor.get_stats(messages, result.messages)
        assert "original_tokens" in stats
        assert "compressed_tokens" in stats
        assert "reduction_pct" in stats

    def test_token_estimation(self, compressor: ContextCompressor) -> None:
        messages = [ChatMessage(role="user", content="Hello world")]
        tokens = compressor.estimate_tokens(messages)
        assert tokens > 0

    @pytest.mark.asyncio
    async def test_truncate_fallback(self) -> None:
        # Create messages that can't be split meaningfully
        config = CompressionConfig(
            max_tokens=100,
            protect_head_messages=10,  # larger than message count
            protect_tail_turns=10,
            use_llm_summary=False,
        )
        comp = ContextCompressor(config)
        messages = [
            ChatMessage(role="system", content="System"),
            ChatMessage(role="user", content="Old request" * 200),
            ChatMessage(role="assistant", content="Old answer" * 200),
            ChatMessage(role="user", content="Current request"),
        ]
        result = await comp.compress(messages)
        assert len(result.messages) <= len(messages)
        assert result.compressed_tokens <= config.max_tokens

    # ---- Dual-threshold compression tests ----

    def test_determine_level_none(self) -> None:
        config = CompressionConfig(max_tokens=1000, warning_threshold=0.5, critical_threshold=0.85)
        comp = ContextCompressor(config)
        assert comp._determine_level(400) == CompressionLevel.NONE

    def test_determine_level_gentle(self) -> None:
        config = CompressionConfig(max_tokens=1000, warning_threshold=0.5, critical_threshold=0.85)
        comp = ContextCompressor(config)
        assert comp._determine_level(600) == CompressionLevel.GENTLE

    def test_determine_level_full(self) -> None:
        config = CompressionConfig(max_tokens=1000, warning_threshold=0.5, critical_threshold=0.85)
        comp = ContextCompressor(config)
        assert comp._determine_level(900) == CompressionLevel.FULL

    @pytest.mark.asyncio
    async def test_gentle_compression_only_prunes_tool_outputs(self) -> None:
        config = CompressionConfig(
            max_tokens=500,
            warning_threshold=0.5,
            critical_threshold=0.9,
            protect_head_messages=1,
            protect_tail_turns=1,
            use_llm_summary=False,
        )
        comp = ContextCompressor(config)
        messages = [
            ChatMessage(role="system", content="System"),
            ChatMessage(role="user", content="User" * 200),
            ChatMessage(role="assistant", content="Assistant" * 200),
            ChatMessage(
                role="tool", content="Tool output" * 50, tool_call_id="tc1", name="test_tool"
            ),
            ChatMessage(role="user", content="Latest"),
            ChatMessage(role="assistant", content="Answer"),
        ]
        result = await comp.compress(messages)
        # At ~525 tokens with 500 max, should trigger gentle compression
        # Tool output should be pruned but no summary inserted
        tool_msgs = [m for m in result.messages if m.role == "tool"]
        for tm in tool_msgs:
            assert "truncated" in tm.content or len(tm.content) < 300

    # ---- Identifier preservation tests ----

    def test_extract_identifiers_uuid(self) -> None:
        comp = ContextCompressor()
        messages = [
            ChatMessage(role="user", content="File id: 550e8400-e29b-41d4-a716-446655440000"),
        ]
        ids = comp._extract_identifiers(messages)
        assert "550e8400-e29b-41d4-a716-446655440000" in ids

    def test_extract_identifiers_path(self) -> None:
        comp = ContextCompressor()
        messages = [
            ChatMessage(role="user", content="Check /Users/test/file.py"),
        ]
        ids = comp._extract_identifiers(messages)
        assert any("/Users/test/file.py" in i for i in ids)

    def test_extract_identifiers_tool_call_id(self) -> None:
        comp = ContextCompressor()
        messages = [
            ChatMessage(role="tool", content="result", tool_call_id="call_abc123"),
        ]
        ids = comp._extract_identifiers(messages)
        assert "call_abc123" in ids

    # ---- Sync compression ----

    def test_compress_sync_no_compression(self) -> None:
        comp = ContextCompressor(CompressionConfig(max_tokens=5000))
        messages = [
            ChatMessage(role="system", content="System"),
            ChatMessage(role="user", content="Hi"),
        ]
        result = comp.compress_sync(messages)
        assert len(result.messages) == 2
        assert result.level == CompressionLevel.NONE

    def test_compress_sync_full_compression(self) -> None:
        config = CompressionConfig(
            max_tokens=200,
            warning_threshold=0.5,
            critical_threshold=0.8,
            protect_head_messages=1,
            protect_tail_turns=1,
            use_llm_summary=False,
        )
        comp = ContextCompressor(config)
        messages = [
            ChatMessage(role="system", content="System prompt here"),
            ChatMessage(role="user", content="User question" * 50),
            ChatMessage(role="assistant", content="Assistant answer" * 50),
            ChatMessage(role="user", content="Latest"),
            ChatMessage(role="assistant", content="Answer"),
        ]
        result = comp.compress_sync(messages)
        msgs = result.messages
        assert len(msgs) < len(messages)
        assert any("CONTEXT COMPACTION" in (m.content or "") for m in msgs)

    @pytest.mark.asyncio
    async def test_async_keeps_multi_result_group_atomic_across_head_boundary(self) -> None:
        comp = ContextCompressor(_full_config())

        result = await comp.compress(_head_boundary_messages())

        _assert_tool_protocol_is_complete(result.messages)
        assert [message.tool_call_id for message in result.messages if message.role == "tool"] == [
            "head-a",
            "head-b",
        ]

    def test_sync_keeps_multi_result_group_atomic_across_head_boundary(self) -> None:
        comp = ContextCompressor(_full_config())

        result = comp.compress_sync(_head_boundary_messages())

        _assert_tool_protocol_is_complete(result.messages)
        assert [message.tool_call_id for message in result.messages if message.role == "tool"] == [
            "head-a",
            "head-b",
        ]

    @pytest.mark.asyncio
    async def test_async_keeps_multi_result_group_atomic_across_tail_boundary(self) -> None:
        comp = ContextCompressor(_full_config())

        result = await comp.compress(_tail_boundary_messages())

        _assert_tool_protocol_is_complete(result.messages)
        assert [message.tool_call_id for message in result.messages if message.role == "tool"] == [
            "tail-a",
            "tail-b",
        ]

    def test_sync_keeps_multi_result_group_atomic_across_tail_boundary(self) -> None:
        comp = ContextCompressor(_full_config())

        result = comp.compress_sync(_tail_boundary_messages())

        _assert_tool_protocol_is_complete(result.messages)
        assert [message.tool_call_id for message in result.messages if message.role == "tool"] == [
            "tail-a",
            "tail-b",
        ]

    @pytest.mark.asyncio
    async def test_async_discards_entire_group_with_missing_tool_result(self) -> None:
        comp = ContextCompressor(_full_config())
        messages = [
            ChatMessage(role="system", content="primary security policy"),
            _tool_assistant("complete", "missing"),
            ChatMessage(role="tool", content="result", tool_call_id="complete"),
            ChatMessage(role="user", content="older question"),
            ChatMessage(role="assistant", content="older answer"),
            ChatMessage(role="user", content="latest question"),
            ChatMessage(role="assistant", content="latest answer"),
        ]

        result = await comp.compress(messages)

        _assert_tool_protocol_is_complete(result.messages)
        assert not any(message.tool_calls for message in result.messages)
        assert not any(message.role == "tool" for message in result.messages)

    def test_sync_discards_entire_group_with_duplicate_tool_result(self) -> None:
        comp = ContextCompressor(_full_config())
        messages = [
            ChatMessage(role="system", content="primary security policy"),
            _tool_assistant("duplicate"),
            ChatMessage(role="tool", content="first", tool_call_id="duplicate"),
            ChatMessage(role="tool", content="second", tool_call_id="duplicate"),
            ChatMessage(role="user", content="older question"),
            ChatMessage(role="assistant", content="older answer"),
            ChatMessage(role="user", content="latest question"),
            ChatMessage(role="assistant", content="latest answer"),
        ]

        result = comp.compress_sync(messages)

        _assert_tool_protocol_is_complete(result.messages)
        assert not any(message.tool_calls for message in result.messages)
        assert not any(message.role == "tool" for message in result.messages)

    @pytest.mark.asyncio
    async def test_async_preserves_every_original_system_message_verbatim(self) -> None:
        comp = ContextCompressor(_full_config())
        messages = [
            ChatMessage(role="system", content="primary security policy"),
            ChatMessage(role="user", content="older question"),
            ChatMessage(role="system", content="secondary audit policy"),
            ChatMessage(role="assistant", content="older answer"),
            ChatMessage(role="user", content="latest question"),
            ChatMessage(role="assistant", content="latest answer"),
        ]

        result = await comp.compress(messages)

        original_systems = [message for message in messages if message.role == "system"]
        assert all(message in result.messages for message in original_systems)
        assert [message.content for message in result.messages if message in original_systems] == [
            "primary security policy",
            "secondary audit policy",
        ]

    def test_summary_shrinking_never_rewrites_original_system_message(self) -> None:
        config = _full_config(max_tokens=290)
        comp = ContextCompressor(config)
        security_message = ChatMessage(
            role="system",
            content=SUMMARY_PREFIX + "original security sentinel" + ("x" * 200),
        )
        generated_summary = ChatMessage(
            role="user",
            content=SUMMARY_PREFIX + "generated summary" + ("y" * 200),
            name="__js_context_compaction__",
        )
        messages = [
            security_message,
            generated_summary,
            ChatMessage(role="user", content="current request"),
        ]

        result = comp._shrink_summary_to_budget(messages)

        assert security_message in result
        assert generated_summary not in result

    @pytest.mark.asyncio
    async def test_async_postcondition_counts_tool_schema_and_meets_budget(self) -> None:
        config = _full_config(max_tokens=180)
        comp = ContextCompressor(config)
        messages = [
            ChatMessage(role="system", content="primary security policy"),
            ChatMessage(role="user", content="old request " * 120),
            ChatMessage(role="assistant", content="old response " * 120),
            ChatMessage(role="user", content="middle request " * 120),
            ChatMessage(role="assistant", content="middle response " * 120),
            ChatMessage(role="user", content="current request"),
        ]
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "lookup",
                    "description": "look up one item",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
        ]

        result = await comp.compress(messages, tools=tools)

        recounted = comp.estimate_tokens(result.messages, tools=tools)
        assert result.compressed_tokens == recounted
        assert recounted <= config.max_tokens
        assert messages[0] in result.messages
        assert messages[-1] in result.messages

    def test_sync_postcondition_meets_budget(self) -> None:
        config = _full_config(max_tokens=95)
        comp = ContextCompressor(config)
        messages = [
            ChatMessage(role="system", content="primary security policy"),
            ChatMessage(role="user", content="old request " * 120),
            ChatMessage(role="assistant", content="old response " * 120),
            ChatMessage(role="user", content="middle request " * 120),
            ChatMessage(role="assistant", content="middle response " * 120),
            ChatMessage(role="user", content="current request"),
        ]

        result = comp.compress_sync(messages)

        recounted = comp.estimate_tokens(result.messages)
        assert result.compressed_tokens == recounted
        assert recounted <= config.max_tokens
        assert messages[0] in result.messages
        assert messages[-1] in result.messages

    @pytest.mark.asyncio
    async def test_async_impossible_budget_fails_closed(self) -> None:
        comp = ContextCompressor(_full_config(max_tokens=10))
        messages = [
            ChatMessage(role="system", content="primary security policy"),
            ChatMessage(role="user", content="current request"),
        ]

        with pytest.raises(
            EchoBudgetExceededError,
            match="Echo budget exceeded: context_compression_postcondition",
        ):
            await comp.compress(messages)

    def test_sync_impossible_budget_fails_closed(self) -> None:
        comp = ContextCompressor(_full_config(max_tokens=10))
        messages = [
            ChatMessage(role="system", content="primary security policy"),
            ChatMessage(role="user", content="current request"),
        ]

        with pytest.raises(
            EchoBudgetExceededError,
            match="Echo budget exceeded: context_compression_postcondition",
        ):
            comp.compress_sync(messages)


def test_agent_wires_memory_threshold_and_compression_feedback(tmp_path: Path) -> None:
    """Memory compression_threshold and CompressionFeedback must reach the compressor."""
    from js.agent import JSAgent
    from js.compression.feedback import CompressionFeedback
    from js.config import JSSettings, MemoryConfig

    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        memory=MemoryConfig(compression_threshold=0.62),
    )
    agent = JSAgent(settings)
    assert agent.compressor.config.warning_threshold == pytest.approx(0.62)
    assert agent.compressor.config.critical_threshold == pytest.approx(0.85)
    assert isinstance(agent.compression_feedback, CompressionFeedback)
    assert agent.compressor._feedback is agent.compression_feedback
