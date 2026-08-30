"""P3-1 LLMLingua-style compaction: default off, 10× cap, heuristic fallback."""

from __future__ import annotations

import ast
from pathlib import Path

from js.compression.compressor import CompressionConfig, ContextCompressor
from js.compression.llmlingua import (
    MAX_COMPRESSION_RATIO,
    compact_bytes,
    compact_text,
    gpu_available,
)
from js.echo.context_savings import (
    ContentAddressableStore,
    ContextBudget,
    ContextEntry,
    summarize_context,
)
from js.models.providers import ChatMessage


def test_default_config_does_not_enable_llmlingua() -> None:
    assert CompressionConfig().llmlingua_enabled is False
    assert CompressionConfig().llmlingua_max_ratio == MAX_COMPRESSION_RATIO
    assert gpu_available() is False


def test_llmlingua_module_does_not_import_gpu_stack() -> None:
    tree = ast.parse(Path("js/compression/llmlingua.py").read_text(encoding="utf-8"))
    forbidden = {"torch", "llmlingua", "transformers"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = {alias.name.split(".", 1)[0] for alias in node.names}
            assert names.isdisjoint(forbidden)
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".", 1)[0] not in forbidden


def test_compact_never_exceeds_10x() -> None:
    text = ("the and of to in " * 200) + "unique-identifier-xyz"
    compacted = compact_text(text, max_ratio=25.0)
    assert len(compacted) >= len(text) / MAX_COMPRESSION_RATIO


def test_compact_bytes_non_utf8_is_a_no_op() -> None:
    payload = b"\xff\xfe\x00not-utf8"
    assert compact_bytes(payload) == payload


def test_compressor_default_path_does_not_compact_tool_output() -> None:
    long_output = "line\n" * 80
    compressor = ContextCompressor(CompressionConfig(max_tokens=50_000))
    messages = [
        ChatMessage(role="user", content="hi"),
        ChatMessage(role="tool", content=long_output, name="file_read", tool_call_id="t1"),
    ]
    pruned = compressor._prune_tool_outputs(messages)
    assert "[Tool output truncated]" in str(pruned[1].content)
    short = "the and of unique-file-notes.txt"
    short_msgs = [ChatMessage(role="tool", content=short, name="file_read", tool_call_id="t2")]
    assert compressor._prune_tool_outputs(short_msgs)[0].content == short


def test_compressor_llmlingua_opt_in_compacts_tool_output() -> None:
    compressor = ContextCompressor(
        CompressionConfig(max_tokens=50_000, llmlingua_enabled=True, llmlingua_max_ratio=10.0)
    )
    body = "the and of " * 5 + "unique-file-notes.txt"
    messages = [ChatMessage(role="tool", content=body, name="file_read", tool_call_id="t1")]
    pruned = compressor._prune_tool_outputs(messages)
    content = str(pruned[0].content)
    assert "unique-file-notes.txt" in content
    assert len(content) >= len(body) / 10
    assert content != body


def test_context_savings_default_does_not_compact() -> None:
    payload = b"the and of unique-cas-payload"
    default_store = ContentAddressableStore()
    result = summarize_context(
        [ContextEntry(kind="doc", payload=payload)],
        ContextBudget(max_tokens=10_000),
        store=default_store,
    )
    record = default_store.get(result.digest_order[0])
    assert record is not None
    assert record.payload == payload
    enabled_store = ContentAddressableStore()
    enabled = summarize_context(
        [ContextEntry(kind="doc", payload=payload)],
        ContextBudget(max_tokens=10_000),
        store=enabled_store,
        llmlingua=True,
    )
    enabled_record = enabled_store.get(enabled.digest_order[0])
    assert enabled_record is not None
    assert enabled_record.payload != payload
    assert result.digest_order[0] != enabled.digest_order[0]


def test_production_callers_do_not_opt_in() -> None:
    agent_src = Path("js/agent/__init__.py").read_text(encoding="utf-8")
    assert "llmlingua_enabled=True" not in agent_src
    runtime_src = Path("js/echo/context_runtime.py").read_text(encoding="utf-8")
    assert "llmlingua=True" not in runtime_src
    assert "llmlingua_enabled=True" not in Path("js/echo/context_savings_harness.py").read_text(
        encoding="utf-8"
    )
