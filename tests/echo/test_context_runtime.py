"""Echo T8-S3B — real prompt context runtime observation tests."""

from __future__ import annotations

import threading
from collections.abc import Sequence
from typing import TYPE_CHECKING

import js.echo.context_runtime as context_runtime
from js.echo.context_runtime import (
    ContextRuntimeObservation,
    get_context_runtime_snapshot_for_tests,
    observe_prompt_context,
    reset_context_runtime_for_tests,
)
from js.echo.context_savings import (
    ContentAddressableStore,
    ContextBudget,
    ContextEntry,
    ContextSavingsResult,
)
from js.echo.context_tokenizer import BoundTokenCounter, TokenCounter
from js.models.providers import ChatMessage

if TYPE_CHECKING:
    import pytest


def _messages() -> list[ChatMessage]:
    return [
        ChatMessage(role="system", content="System prompt stays stable."),
        ChatMessage(role="user", content="Please inspect the tool output."),
        ChatMessage(
            role="assistant",
            content="I will call the tool.",
            tool_calls=[
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": '{"id": 42}'},
                }
            ],
        ),
        ChatMessage(
            role="tool",
            content='{"id": 42, "status": "paid"}',
            tool_call_id="call_1",
        ),
    ]


def _tools_schema() -> list[dict[str, object]]:
    return [
        {
            "type": "function",
            "function": {
                "name": "lookup",
                "description": "Lookup an order",
                "parameters": {
                    "type": "object",
                    "properties": {"id": {"type": "integer"}},
                    "required": ["id"],
                },
            },
        }
    ]


def test_echo_records_real_prompt_metrics(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    reset_context_runtime_for_tests()

    first = observe_prompt_context(
        channel="agent_turn",
        session_id="session-a",
        owner_key_hash="owner-a",
        run_id="run-a",
        turn=1,
        model="mock-model",
        messages=_messages(),
        tools_schema=_tools_schema(),
    )
    second = observe_prompt_context(
        channel="agent_turn",
        session_id="session-a",
        owner_key_hash="owner-a",
        run_id="run-b",
        turn=2,
        model="mock-model",
        messages=_messages(),
        tools_schema=_tools_schema(),
    )

    assert isinstance(first, ContextRuntimeObservation)
    assert isinstance(second, ContextRuntimeObservation)
    assert first.mode == "on"
    assert first.total_entries == 5  # 4 messages + 1 tool schema entry
    assert first.naive_tokens > 0
    assert first.saved_tokens > 0
    assert first.new_cas_tokens == first.saved_tokens
    assert first.unsent_prompt_tokens == 0
    assert second.new_cas_tokens == 0
    assert second.unsent_prompt_tokens == second.saved_tokens
    assert second.store_size == first.store_size
    assert second.token_unit_id == first.token_unit_id


def test_scope_isolated_by_owner_and_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    reset_context_runtime_for_tests()

    base = {
        "channel": "agent_turn",
        "run_id": "run-a",
        "turn": 1,
        "model": "mock-model",
        "messages": _messages(),
        "tools_schema": _tools_schema(),
    }
    first = observe_prompt_context(session_id="session-a", owner_key_hash="owner-a", **base)
    same_scope = observe_prompt_context(session_id="session-a", owner_key_hash="owner-a", **base)
    different_session = observe_prompt_context(
        session_id="session-b", owner_key_hash="owner-a", **base
    )
    different_owner = observe_prompt_context(
        session_id="session-a", owner_key_hash="owner-b", **base
    )

    assert first is not None
    assert same_scope is not None
    assert different_session is not None
    assert different_owner is not None
    assert same_scope.new_cas_tokens == 0
    assert different_session.new_cas_tokens == first.new_cas_tokens
    assert different_owner.new_cas_tokens == first.new_cas_tokens
    assert get_context_runtime_snapshot_for_tests().scope_count == 3


def test_scope_isolated_by_token_unit(monkeypatch: pytest.MonkeyPatch) -> None:
    reset_context_runtime_for_tests()
    base = {
        "channel": "agent_turn",
        "session_id": "session-a",
        "owner_key_hash": "owner-a",
        "turn": 1,
        "model": "mock-model",
        "messages": _messages(),
        "tools_schema": _tools_schema(),
    }
    counter_a = BoundTokenCounter(count=lambda payload: len(payload), token_unit_id="unit:a")
    counter_b = BoundTokenCounter(count=lambda payload: len(payload), token_unit_id="unit:b")

    first = observe_prompt_context(run_id="run-a", token_counter=counter_a, **base)
    second = observe_prompt_context(run_id="run-b", token_counter=counter_b, **base)

    assert first is not None
    assert second is not None
    assert first.scope_key != second.scope_key
    assert first.new_cas_tokens == first.saved_tokens
    assert second.new_cas_tokens == second.saved_tokens
    assert get_context_runtime_snapshot_for_tests().scope_count == 2


def test_default_retention_limits_bound_payload_and_scope_cardinality() -> None:
    assert context_runtime._MAX_SCOPES <= 256  # noqa: SLF001
    assert context_runtime._MAX_HARD_SCOPES >= context_runtime._MAX_SCOPES  # noqa: SLF001
    assert (  # noqa: SLF001
        context_runtime._MAX_HARD_OWNER_SCOPES
        >= context_runtime._MAX_OWNER_SCOPES
    )
    assert context_runtime._MAX_RETAINED_PAYLOAD_BYTES <= 128 * 1024 * 1024  # noqa: SLF001
    assert context_runtime._MAX_OWNER_RETAINED_PAYLOAD_BYTES > 0  # noqa: SLF001
    assert (  # noqa: SLF001
        context_runtime._MAX_OWNER_RETAINED_PAYLOAD_BYTES
        < context_runtime._MAX_RETAINED_PAYLOAD_BYTES
    )
    assert 0 < context_runtime._MAX_OWNER_SCOPES < context_runtime._MAX_SCOPES  # noqa: SLF001
    assert context_runtime._MAX_SCOPE_PAYLOAD_BYTES > 0  # noqa: SLF001
    assert 0 < context_runtime._MAX_SCOPE_RECORDS <= 256  # noqa: SLF001


def test_active_scope_registry_hard_limit_falls_back_without_retention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = context_runtime._ContextRuntime()  # noqa: SLF001
    monkeypatch.setattr(context_runtime, "_MAX_SCOPES", 1)
    monkeypatch.setattr(context_runtime, "_MAX_OWNER_SCOPES", 1)
    monkeypatch.setattr(context_runtime, "_MAX_HARD_SCOPES", 2)
    monkeypatch.setattr(context_runtime, "_MAX_HARD_OWNER_SCOPES", 2)

    with runtime._lock:  # noqa: SLF001
        for index in range(2):
            scope = runtime._new_scope(  # noqa: SLF001
                scope_key=f"p:owner:session-{index}:unit",
                owner_key="p:owner",
                token_unit_id="unit",
            )
            scope.active_observers = 1
            runtime._scopes[scope.scope_key] = scope  # noqa: SLF001

    observation = runtime.observe(
        mode="on",
        product_id="p",
        channel="agent_turn",
        session_id="overflow",
        owner_key_hash="owner",
        run_id="run-overflow",
        turn=1,
        model="model",
        messages=[{"role": "user", "content": "payload"}],
        tools_schema=None,
        token_counter=BoundTokenCounter(count=len, token_unit_id="unit"),
        budget=ContextBudget(max_tokens=10_000),
    )

    assert observation.error == "ContextCapacityFallback: scope metrics were not retained"
    assert runtime.snapshot().scope_count == 2


def test_context_runtime_partitions_same_owner_session_by_product() -> None:
    reset_context_runtime_for_tests()
    base = {
        "channel": "agent_turn",
        "session_id": "session-a",
        "owner_key_hash": "owner-a",
        "turn": 1,
        "model": "mock-model",
        "messages": _messages(),
        "tools_schema": _tools_schema(),
    }

    main = observe_prompt_context(product_id="js-agent", run_id="run-main", **base)
    work = observe_prompt_context(product_id="js-work", run_id="run-work", **base)

    assert main is not None
    assert work is not None
    assert main.product_id == "js-agent"
    assert work.product_id == "js-work"
    assert main.scope_key != work.scope_key
    assert work.new_cas_tokens == main.new_cas_tokens
    assert get_context_runtime_snapshot_for_tests().scope_count == 2


def test_context_runtime_bounds_scope_payload_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_context_runtime_for_tests()
    first_messages = [{"role": "user", "content": "A" * 64}]
    second_messages = [{"role": "user", "content": "B" * 64}]
    payload_size = len(
        context_runtime._build_context_entries(  # noqa: SLF001
            messages=first_messages,
            tools_schema=None,
        )[0].payload
    )
    monkeypatch.setattr(context_runtime, "_MAX_SCOPE_PAYLOAD_BYTES", payload_size + 1)
    monkeypatch.setattr(context_runtime, "_MAX_SCOPE_RECORDS", 10)

    base = {
        "channel": "agent_turn",
        "session_id": "session-a",
        "owner_key_hash": "owner-a",
        "turn": 1,
        "model": "mock-model",
        "tools_schema": None,
    }
    first = observe_prompt_context(run_id="run-a", messages=first_messages, **base)
    second = observe_prompt_context(run_id="run-b", messages=second_messages, **base)

    assert first is not None
    assert second is not None
    assert first.retained_payload_bytes == payload_size
    assert second.retained_payload_bytes <= payload_size + 1
    assert second.store_size == 1
    assert second.record_eviction_count == 1
    snapshot = get_context_runtime_snapshot_for_tests()
    assert snapshot.retained_payload_bytes == second.retained_payload_bytes
    assert snapshot.record_eviction_count == 1
    assert snapshot.eviction_count == (
        snapshot.scope_eviction_count + snapshot.record_eviction_count
    )


def test_context_runtime_rejects_payload_larger_than_scope_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_context_runtime_for_tests()
    messages = [{"role": "user", "content": "oversized"}]
    payload_size = len(
        context_runtime._build_context_entries(messages=messages, tools_schema=None)[0].payload  # noqa: SLF001
    )
    monkeypatch.setattr(context_runtime, "_MAX_SCOPE_PAYLOAD_BYTES", payload_size - 1)

    observation = observe_prompt_context(
        channel="agent_turn",
        session_id="session-a",
        owner_key_hash="owner-a",
        run_id="run-a",
        turn=1,
        model="mock-model",
        messages=messages,
        tools_schema=None,
    )

    assert observation is not None
    assert observation.store_size == 0
    assert observation.retained_payload_bytes == 0
    assert observation.retention_rejection_count == 1
    snapshot = get_context_runtime_snapshot_for_tests()
    assert snapshot.retained_payload_bytes == 0
    assert snapshot.retention_rejection_count == 1
    assert snapshot.rejected_payload_bytes == payload_size


def test_context_runtime_bounds_scope_record_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_context_runtime_for_tests()
    monkeypatch.setattr(context_runtime, "_MAX_SCOPE_PAYLOAD_BYTES", 1024 * 1024)
    monkeypatch.setattr(context_runtime, "_MAX_SCOPE_RECORDS", 2)
    base = {
        "channel": "agent_turn",
        "session_id": "session-a",
        "owner_key_hash": "owner-a",
        "turn": 1,
        "model": "mock-model",
        "tools_schema": None,
    }

    observations = [
        observe_prompt_context(
            run_id=f"run-{content}",
            messages=[{"role": "user", "content": content}],
            **base,
        )
        for content in ("alpha", "beta", "gamma")
    ]

    assert all(observation is not None for observation in observations)
    last = observations[-1]
    assert last is not None
    assert last.store_size == 2
    assert last.record_eviction_count == 1
    assert get_context_runtime_snapshot_for_tests().record_eviction_count == 1


def test_context_runtime_enforces_global_retained_payload_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_context_runtime_for_tests()
    messages = [{"role": "user", "content": "payload"}]
    payload_size = len(
        context_runtime._build_context_entries(messages=messages, tools_schema=None)[0].payload  # noqa: SLF001
    )
    monkeypatch.setattr(context_runtime, "_MAX_RETAINED_PAYLOAD_BYTES", payload_size * 2)
    monkeypatch.setattr(context_runtime, "_MAX_OWNER_RETAINED_PAYLOAD_BYTES", payload_size * 2)
    monkeypatch.setattr(context_runtime, "_MAX_SCOPES", 10)
    monkeypatch.setattr(context_runtime, "_MAX_OWNER_SCOPES", 10)
    monkeypatch.setattr(context_runtime, "_MAX_SCOPE_PAYLOAD_BYTES", payload_size * 2)
    monkeypatch.setattr(context_runtime, "_MAX_SCOPE_RECORDS", 10)

    for index in range(3):
        observation = observe_prompt_context(
            channel="agent_turn",
            session_id=f"session-{index}",
            owner_key_hash=f"owner-{index}",
            run_id=f"run-{index}",
            turn=1,
            model="mock-model",
            messages=messages,
            tools_schema=None,
        )
        assert observation is not None

    snapshot = get_context_runtime_snapshot_for_tests()
    assert snapshot.retained_payload_bytes <= payload_size * 2
    assert snapshot.scope_count == 2
    assert snapshot.scope_eviction_count == 1
    assert snapshot.eviction_count == 1
    assert snapshot.evicted_payload_bytes == payload_size


def test_concurrent_scopes_never_exceed_global_retained_payload_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_context_runtime_for_tests()
    messages = [{"role": "user", "content": "concurrent payload"}]
    payload_size = len(
        context_runtime._build_context_entries(messages=messages, tools_schema=None)[0].payload  # noqa: SLF001
    )
    thread_count = 8
    monkeypatch.setattr(context_runtime, "_MAX_RETAINED_PAYLOAD_BYTES", payload_size * 2)
    monkeypatch.setattr(
        context_runtime,
        "_MAX_OWNER_RETAINED_PAYLOAD_BYTES",
        payload_size * thread_count,
    )
    monkeypatch.setattr(context_runtime, "_MAX_SCOPES", thread_count)
    monkeypatch.setattr(context_runtime, "_MAX_OWNER_SCOPES", thread_count)
    monkeypatch.setattr(context_runtime, "_MAX_SCOPE_PAYLOAD_BYTES", payload_size * 2)
    barrier = threading.Barrier(thread_count)
    results: list[ContextRuntimeObservation | None] = []
    errors: list[Exception] = []
    result_lock = threading.Lock()

    def worker(index: int) -> None:
        try:
            barrier.wait(timeout=5)
            observation = observe_prompt_context(
                channel="agent_turn",
                session_id=f"session-{index}",
                owner_key_hash=f"owner-{index}",
                run_id=f"run-{index}",
                turn=1,
                model="mock-model",
                messages=messages,
                tools_schema=None,
            )
            with result_lock:
                results.append(observation)
        except Exception as exc:  # noqa: BLE001 - propagate worker failures to the test
            with result_lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert errors == []
    assert len(results) == thread_count
    snapshot = get_context_runtime_snapshot_for_tests()
    assert snapshot.observation_count == thread_count
    assert snapshot.retained_payload_bytes <= payload_size * 2


def test_context_runtime_enforces_owner_payload_quota_before_global_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_context_runtime_for_tests()
    messages = [{"role": "user", "content": "payload"}]
    payload_size = len(
        context_runtime._build_context_entries(messages=messages, tools_schema=None)[0].payload  # noqa: SLF001
    )
    monkeypatch.setattr(context_runtime, "_MAX_RETAINED_PAYLOAD_BYTES", payload_size * 10)
    monkeypatch.setattr(context_runtime, "_MAX_OWNER_RETAINED_PAYLOAD_BYTES", payload_size)
    monkeypatch.setattr(context_runtime, "_MAX_SCOPES", 10)
    monkeypatch.setattr(context_runtime, "_MAX_OWNER_SCOPES", 10)
    monkeypatch.setattr(context_runtime, "_MAX_SCOPE_PAYLOAD_BYTES", payload_size * 2)
    monkeypatch.setattr(context_runtime, "_MAX_SCOPE_RECORDS", 10)

    for owner, session in (
        ("owner-a", "session-a1"),
        ("owner-b", "session-b1"),
        ("owner-a", "session-a2"),
    ):
        observation = observe_prompt_context(
            channel="agent_turn",
            session_id=session,
            owner_key_hash=owner,
            run_id=f"run-{session}",
            turn=1,
            model="mock-model",
            messages=messages,
            tools_schema=None,
        )
        assert observation is not None

    snapshot = get_context_runtime_snapshot_for_tests()
    assert snapshot.retained_payload_bytes == payload_size * 2
    assert snapshot.scope_count == 2
    assert snapshot.scope_eviction_count == 1
    assert snapshot.evicted_payload_bytes == payload_size


def test_active_scope_is_pinned_during_concurrent_eviction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_context_runtime_for_tests()
    monkeypatch.setattr(context_runtime, "_MAX_SCOPES", 1)
    original_summarize = context_runtime.summarize_context
    entered = threading.Event()
    release = threading.Event()
    first_results: list[ContextRuntimeObservation | None] = []
    errors: list[Exception] = []

    def blocking_summarize(
        entries: Sequence[ContextEntry],
        budget: ContextBudget,
        *,
        store: ContentAddressableStore | None = None,
        token_counter: TokenCounter | None = None,
    ) -> ContextSavingsResult:
        if threading.current_thread().name == "active-scope-observer":
            entered.set()
            if not release.wait(timeout=5):
                raise RuntimeError("timed out waiting to release active scope")
        return original_summarize(
            entries,
            budget,
            store=store,
            token_counter=token_counter,
        )

    monkeypatch.setattr(context_runtime, "summarize_context", blocking_summarize)
    shared = {
        "channel": "agent_turn",
        "session_id": "session-a",
        "owner_key_hash": "owner-a",
        "turn": 1,
        "model": "mock-model",
        "messages": [{"role": "user", "content": "same payload"}],
        "tools_schema": None,
    }

    def observe_active_scope() -> None:
        try:
            first_results.append(observe_prompt_context(run_id="run-a1", **shared))
        except Exception as exc:  # noqa: BLE001 - propagate worker failures to the test
            errors.append(exc)

    thread = threading.Thread(target=observe_active_scope, name="active-scope-observer")
    thread.start()
    assert entered.wait(timeout=5)
    try:
        other = observe_prompt_context(
            channel="agent_turn",
            session_id="session-b",
            owner_key_hash="owner-b",
            run_id="run-b",
            turn=1,
            model="mock-model",
            messages=[{"role": "user", "content": "other payload"}],
            tools_schema=None,
        )
        second = observe_prompt_context(run_id="run-a2", **shared)
    finally:
        release.set()
        thread.join(timeout=5)

    assert not thread.is_alive()
    assert errors == []
    assert len(first_results) == 1
    first = first_results[0]
    assert first is not None
    assert other is not None
    assert second is not None
    assert first.new_cas_tokens + second.new_cas_tokens == second.saved_tokens
    snapshot = get_context_runtime_snapshot_for_tests()
    assert snapshot.scope_count == 1
    assert snapshot.observation_count == 3
    assert snapshot.scope_eviction_count >= 1


def test_context_runtime_bounds_session_scopes_with_lru(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_context_runtime_for_tests()
    monkeypatch.setattr(context_runtime, "_MAX_SCOPES", 2)
    base = {
        "channel": "agent_turn",
        "owner_key_hash": "owner-a",
        "turn": 1,
        "model": "mock-model",
        "messages": _messages(),
        "tools_schema": _tools_schema(),
    }

    first_a = observe_prompt_context(session_id="session-a", run_id="run-a", **base)
    observe_prompt_context(session_id="session-b", run_id="run-b", **base)
    hit_a = observe_prompt_context(session_id="session-a", run_id="run-a2", **base)
    observe_prompt_context(session_id="session-c", run_id="run-c", **base)

    snapshot = get_context_runtime_snapshot_for_tests()
    assert first_a is not None
    assert hit_a is not None
    assert hit_a.new_cas_tokens == 0
    assert snapshot.scope_count == 2
    assert snapshot.eviction_count == 1

    still_cached_a = observe_prompt_context(session_id="session-a", run_id="run-a3", **base)
    evicted_b = observe_prompt_context(session_id="session-b", run_id="run-b2", **base)
    assert still_cached_a is not None
    assert evicted_b is not None
    assert still_cached_a.new_cas_tokens == 0
    assert evicted_b.new_cas_tokens == first_a.new_cas_tokens


def test_context_observation_fail_opens_on_tokenizer_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    reset_context_runtime_for_tests()

    class BoomCounter:
        token_unit_id = "boom:v1"

        def __call__(self, payload: bytes) -> int:
            raise RuntimeError("tokenizer exploded")

    observation = observe_prompt_context(
        channel="agent_turn",
        session_id="session-a",
        owner_key_hash="owner-a",
        run_id="run-a",
        turn=1,
        model="mock-model",
        messages=_messages(),
        tools_schema=_tools_schema(),
        token_counter=BoomCounter(),
    )

    assert isinstance(observation, ContextRuntimeObservation)
    assert observation.error is not None
    assert "tokenizer exploded" in observation.error
    assert observation.naive_tokens == 0
    assert get_context_runtime_snapshot_for_tests().observation_count == 1


def test_tool_schema_serialization_is_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    reset_context_runtime_for_tests()
    schema_a = [{"function": {"name": "lookup", "parameters": {"b": 2, "a": 1}}}]
    schema_b = [{"function": {"parameters": {"a": 1, "b": 2}, "name": "lookup"}}]

    first = observe_prompt_context(
        channel="agent_turn",
        session_id="session-a",
        owner_key_hash="owner-a",
        run_id="run-a",
        turn=1,
        model="mock-model",
        messages=_messages(),
        tools_schema=schema_a,
    )
    second = observe_prompt_context(
        channel="agent_turn",
        session_id="session-a",
        owner_key_hash="owner-a",
        run_id="run-b",
        turn=2,
        model="mock-model",
        messages=_messages(),
        tools_schema=schema_b,
    )

    assert first is not None
    assert second is not None
    assert second.new_cas_tokens == 0


def test_observer_accepts_plain_mapping_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    reset_context_runtime_for_tests()
    messages = [
        {"role": "system", "content": "S"},
        {"role": "user", "content": [{"type": "text", "text": "hello"}]},
    ]

    observation = observe_prompt_context(
        channel="agent_turn",
        session_id="session-a",
        owner_key_hash=None,
        run_id="run-a",
        turn=1,
        model=None,
        messages=messages,
        tools_schema=None,
    )

    assert observation is not None
    assert observation.total_entries == 2
    assert observation.scope_key.endswith("session-a")
