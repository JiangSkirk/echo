"""Tests for context compressor."""

import pytest

from js.compression.compressor import (
    CompressionConfig,
    CompressionLevel,
    ContextCompressor,
)
from js.models.providers import ChatMessage


class TestContextCompressor:
    @pytest.fixture
    def compressor(self) -> ContextCompressor:
        return ContextCompressor(CompressionConfig(
            max_tokens=500,
            protect_head_messages=2,
            protect_tail_turns=2,
            enable_compression=True,
            use_llm_summary=False,
        ))

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
            ChatMessage(role="user", content="User" * 200),
        ]
        result = await comp.compress(messages)
        assert len(result.messages) <= len(messages)

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
            ChatMessage(role="tool", content="Tool output" * 50, tool_call_id="tc1", name="test_tool"),
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
