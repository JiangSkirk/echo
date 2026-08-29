"""Bots stable prefix is byte-stable. Warmup hit rate uses exclusive buckets."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from cachetools import TTLCache

from js.agent.prompt_builder import PromptBuilderMixin
from js.bots.persona import BotTurnBinding, bind_bot_turn, compute_prefix_id
from js.bots.prefix import warmup_excluded_hit_rate, warmup_excluded_hit_rate_or_none
from js.echo.turn_context import (
    RuntimeContext,
    reset_current_owner_key_hash,
    reset_runtime_context,
    set_current_owner_key_hash,
    set_runtime_context,
)
from js.models.usage import ExclusiveUsageBuckets, sorted_tools_schema, tools_schema_digest


def _builder() -> PromptBuilderMixin:
    builder = PromptBuilderMixin()
    builder.SYSTEM_PROMPT = "You are JS."
    builder.settings = SimpleNamespace(
        memory=SimpleNamespace(enabled=True, max_memory_chars=2000),
        product_id="js-agent",
    )
    builder.router = SimpleNamespace(is_local_model=lambda model: False)
    builder.memory = SimpleNamespace(
        get_context_string=lambda **kwargs: f"mem:{kwargs.get('query')}"
    )
    builder.secrets = SimpleNamespace(detect_and_redact=lambda value, source: value)
    builder.guard = SimpleNamespace(
        check_tool_result=lambda value: SimpleNamespace(
            decision=SimpleNamespace(value="allow"), reason=""
        )
    )
    builder.audit = MagicMock()
    builder.logger = MagicMock()
    builder.learner = None
    builder.optimizer = None
    builder._system_message_cache = TTLCache(maxsize=32, ttl=60)
    return builder


def test_stable_prefix_byte_equal_across_turns(tmp_path: Path) -> None:
    builder = _builder()
    context = RuntimeContext(
        product_id="js-agent",
        channel="bots",
        owner_key_hash="owner-a",
        session_id="room:r1",
        run_id="run-1",
        role="investigator",
        profile="default",
        capabilities=("file_read", "ask_user"),
        workspace=tmp_path,
        state_dir=tmp_path,
        fs_roots=(tmp_path,),
        surface="bots",
    )
    binding = BotTurnBinding(
        bot_id="b1",
        soul_text="我是调查bot，所以我先搜再读。",
        persona_appendix="【专长发挥】交叉验证",
        memory_session="bot:b1:private",
        prefix_id="abc",
    )
    owner_token = set_current_owner_key_hash("owner-a")
    runtime_token = set_runtime_context(context)
    try:
        with bind_bot_turn(binding):
            first = builder._build_system_message(query="第一问", session_id="room:r1")
            second = builder._build_system_message(query="第二问完全不同", session_id="room:r1")
            volatile = builder._build_volatile_context(query="第二问完全不同")
    finally:
        reset_runtime_context(runtime_token)
        reset_current_owner_key_hash(owner_token)
    assert first == second
    assert "我是调查bot" in first
    assert "第一问" not in first
    assert "第二问" not in first
    assert "mem:" not in first
    assert "run_id=" not in first
    assert "mem:" in volatile or "run_id=" in volatile


def test_tools_json_is_deterministic() -> None:
    schema = [
        {"function": {"name": "shell", "parameters": {"b": 1, "a": 2}}},
        {"function": {"name": "ask_user", "parameters": {"z": True}}},
    ]
    once = sorted_tools_schema(schema)
    twice = sorted_tools_schema(list(reversed(schema)))
    assert once == twice
    assert tools_schema_digest(once) == tools_schema_digest(twice)
    assert compute_prefix_id("b1", "soul", once) == compute_prefix_id("b1", "soul", twice)


def test_warmup_hit_rate_meets_96() -> None:
    rows = [
        ExclusiveUsageBuckets(
            uncached_input=0,
            cache_read=0,
            cache_write=1000,
            usage_source="provider_actual",
        )
    ]
    for _ in range(9):
        rows.append(
            ExclusiveUsageBuckets(
                uncached_input=20,
                cache_read=980,
                cache_write=0,
                usage_source="provider_actual",
            )
        )
    assert warmup_excluded_hit_rate(rows) >= 0.96
    assert warmup_excluded_hit_rate_or_none(rows[:1]) is None


def test_room_prefix_hit_summary_uses_exclusive_buckets(tmp_path: Path) -> None:
    from js.web.stats_store import TokenStatsStore

    store = TokenStatsStore(tmp_path)
    store.record(
        "claude",
        "anthropic",
        prompt_tokens=1000,
        completion_tokens=10,
        uncached_input=0,
        cache_read=0,
        cache_write=1000,
        output=10,
        input_total=1000,
        usage_source="provider_actual",
        prefix_id="pre-a",
        bot_id="bot-a",
        exclude_from_hit_rate=True,
    )
    for _ in range(9):
        store.record(
            "claude",
            "anthropic",
            prompt_tokens=1000,
            completion_tokens=10,
            uncached_input=20,
            cache_read=980,
            cache_write=0,
            output=10,
            input_total=1000,
            usage_source="provider_actual",
            prefix_id="pre-a",
            bot_id="bot-a",
        )
    summary = store.room_prefix_hit_summary([("bot-a", "pre-a")])
    assert summary["hit_rate"] is not None
    assert summary["hit_rate"] >= 0.96
    assert summary["below_target"] is False
