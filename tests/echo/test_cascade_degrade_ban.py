"""P2-3: plan-commit / mid-turn dirty cannot degrade to a local model."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from js.config import EchoPlanCommitConfig, GatewayConfig, JSSettings, ModelCascadeConfig
from js.echo.ledger.service import EchoBlockedError
from js.echo.turn_context import reset_runtime_context, set_runtime_context
from js.echo.turn_loop.model_gate import _authorize_echo_model_call
from js.models.cascade import CascadeIntent, reset_cascade_intent, set_cascade_intent
from js.models.providers import ChatMessage
from js.orin.taint import reset_entry_source, set_entry_source
from tests.echo.plan_commit_fakes import LoopAgent, new_loop, runtime_context, text_response
from tests.models.test_cascade_routing import _dual_router


def test_authorize_rejects_local_on_heavy_path_when_cloud_exists() -> None:
    router = _dual_router(cascade=False)
    called = {"n": 0}

    def _authorize(**_kwargs: object) -> object:
        called["n"] += 1
        return object()

    agent = SimpleNamespace(
        settings=JSSettings(model_cascade=ModelCascadeConfig(enabled=False)),
        router=router,
        echo_safety_service=SimpleNamespace(authorize_model_call=_authorize),
    )
    token = set_cascade_intent(
        CascadeIntent(complexity="heavy", forbid_local=True, local_only_deny_write=False)
    )
    try:
        with pytest.raises(EchoBlockedError, match="cannot use a local model"):
            _authorize_echo_model_call(
                agent,
                tenant_id="t",
                run_id="r",
                provider_id="ollama",
                model_id="llama",
                messages=[],
                tools_schema=None,
            )
        assert called["n"] == 0
    finally:
        reset_cascade_intent(token)


def test_authorize_allows_cloud_on_heavy_path() -> None:
    router = _dual_router()
    sentinel = object()
    agent = SimpleNamespace(
        settings=JSSettings(),
        router=router,
        echo_safety_service=SimpleNamespace(authorize_model_call=lambda **_k: sentinel),
    )
    token = set_cascade_intent(
        CascadeIntent(complexity="heavy", forbid_local=True, local_only_deny_write=False)
    )
    try:
        context = _authorize_echo_model_call(
            agent,
            tenant_id="t",
            run_id="r",
            provider_id="cloud",
            model_id="gpt-test",
            messages=[],
            tools_schema=None,
        )
        assert context is sentinel
    finally:
        reset_cascade_intent(token)


@pytest.mark.asyncio
async def test_local_only_plan_commit_denies_write(tmp_path) -> None:
    agent = LoopAgent(
        tmp_path,
        gateway=GatewayConfig(enabled=True),
        plan_commit=EchoPlanCommitConfig(enabled=True),
    )
    agent.router = SimpleNamespace(
        get_model_config=lambda _model: None,
        has_non_local_backend=lambda: False,
        local_only_backends=lambda: True,
        is_local_model=lambda _model: True,
        _providers={"ollama": SimpleNamespace(_is_local=True)},
    )
    loop = new_loop(agent, user_input="save hello to notes.txt")
    calls = 0

    async def _get(
        _messages: list[ChatMessage],
        tools_schema: list[dict[str, object]] | None,
    ) -> object:
        nonlocal calls
        calls += 1
        if calls == 1:
            return text_response(
                '{"steps":[{"tool":"file_write","arguments":'
                '{"path":"notes.txt","content":"hello"}},'
                '{"tool":"file_read","arguments":{"path":"notes.txt"}}]}'
            )
        return text_response("done")

    loop._get_response = _get  # type: ignore[method-assign]
    entry = set_entry_source("gateway:telegram")
    token = set_runtime_context(runtime_context(tmp_path, channel="gateway:telegram"))
    try:
        await loop._run_loop()
    finally:
        reset_runtime_context(token)
        reset_entry_source(entry)

    assert "file_write" not in agent.echo_runtime.executed
    assert "file_read" in agent.echo_runtime.executed
    receipts = loop.state.compression_stats.get("plan_commit", {}).get("receipts", [])
    assert any(
        item.get("tool") == "file_write" and item.get("status") == "skipped" for item in receipts
    )


def test_midturn_dirty_forbids_local_when_cloud_exists(tmp_path) -> None:
    agent = LoopAgent(tmp_path, plan_commit=EchoPlanCommitConfig(enabled=True))
    agent.router = SimpleNamespace(
        get_model_config=lambda _model: None,
        has_non_local_backend=lambda: True,
        local_only_backends=lambda: False,
        is_local_model=lambda _model: False,
        _providers={
            "cloud": SimpleNamespace(_is_local=False),
            "ollama": SimpleNamespace(_is_local=True),
        },
    )
    loop = new_loop(agent, user_input="hello")
    loop._write_egress_narrowed = True
    intent = loop._cascade_intent_for_call()
    assert intent.complexity == "heavy"
    assert intent.forbid_local is True
    assert intent.local_only_deny_write is False


def test_cascade_intent_without_loop_state_uses_call_messages(tmp_path) -> None:
    agent = LoopAgent(tmp_path, plan_commit=EchoPlanCommitConfig(enabled=False))
    loop = new_loop(agent, user_input="hello")
    object.__delattr__(loop, "state")
    intent = loop._cascade_intent_for_call(
        [ChatMessage(role="user", content="hello")],
    )
    assert intent.complexity == "light"
    assert intent.forbid_local is False
