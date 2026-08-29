from __future__ import annotations

import asyncio
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from js.echo.effect_interpreter import EffectInterpreter, ModelEffect, ToolEffect
from js.echo.turn_context import RuntimeContext, current_runtime_context
from js.models.permit import ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse
from js.models.stream_events import StreamEvent
from js.tools.registry import ToolResult


class _TestRuntimeAuthority:
    def validate_effect_context(
        self,
        _context: RuntimeContext,
        *,
        effect_kind: str,
    ) -> None:
        assert effect_kind in {"model", "tool"}


def _interpreter(agent: Any) -> EffectInterpreter:
    authority = _TestRuntimeAuthority()
    agent.echo_runtime = authority
    return EffectInterpreter(agent, runtime_authority=authority)


def _context(
    tmp_path: Path,
    *,
    capabilities: tuple[str, ...] = (),
    deadline_ms: int | None = None,
) -> RuntimeContext:
    return RuntimeContext(
        product_id="js-agent",
        channel="test",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        role="user",
        profile="default",
        capabilities=capabilities,
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        fs_roots=(tmp_path / "workspace",),
        deadline_ms=(
            deadline_ms if deadline_ms is not None else int(time.monotonic() * 1000) + 900_000
        ),
    )


@pytest.mark.asyncio
async def test_model_effect_rejects_unsigned_context_on_real_echo_runtime(
    tmp_path: Path,
) -> None:
    from js.config import JSSettings
    from js.echo.turn_runtime import EchoRuntime

    async def authorized_model_chat(**_kwargs: Any) -> ChatResponse:
        return ChatResponse(
            content="ok",
            tool_calls=[],
            model="mock",
            usage={},
            finish_reason="stop",
        )

    settings = JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    agent = SimpleNamespace(
        settings=settings,
        authorized_model_chat=authorized_model_chat,
        _current_allowed_tools=set(),
        registry=None,
    )
    runtime = EchoRuntime(agent)
    agent.echo_runtime = runtime
    interpreter = EffectInterpreter(agent, runtime_authority=runtime)
    unsigned = _context(tmp_path)
    with pytest.raises(PermissionError, match="authority signature"):
        await interpreter.execute_model(
            ModelEffect(messages=(ChatMessage(role="user", content="hello"),)),
            unsigned,
        )


@pytest.mark.asyncio
async def test_model_effect_accepts_signed_real_echo_runtime_context(tmp_path: Path) -> None:
    from js.config import JSSettings
    from js.echo.turn_runtime import EchoRuntime

    observed: dict[str, Any] = {}

    async def authorized_model_chat(**kwargs: Any) -> ChatResponse:
        observed.update(kwargs)
        return ChatResponse(
            content="ok",
            tool_calls=[],
            model="mock",
            usage={},
            finish_reason="stop",
        )

    settings = JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    agent = SimpleNamespace(
        settings=settings,
        authorized_model_chat=authorized_model_chat,
        _current_allowed_tools=set(),
        registry=None,
    )
    runtime = EchoRuntime(agent)
    agent.echo_runtime = runtime
    interpreter = EffectInterpreter(agent, runtime_authority=runtime)
    context = runtime.build_context(
        channel="test",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        role="user",
        profile="default",
        capabilities=(),
    )
    response = await interpreter.execute_model(
        ModelEffect(messages=(ChatMessage(role="user", content="hello"),)),
        context,
    )
    assert response.content == "ok"
    assert observed["run_id"] == "run-a"


@pytest.mark.asyncio
async def test_effect_interpreter_rejects_direct_use_without_runtime_authority(
    tmp_path: Path,
) -> None:
    agent = SimpleNamespace(authorized_model_chat=AsyncMock())
    interpreter = EffectInterpreter(agent)

    with pytest.raises(RuntimeError, match="authority"):
        await interpreter.execute_model(
            ModelEffect(messages=(ChatMessage(role="user", content="hello"),)),
            _context(tmp_path),
        )

    agent.authorized_model_chat.assert_not_awaited()


@pytest.mark.asyncio
async def test_model_effect_uses_authorized_boundary_and_binds_context(tmp_path: Path) -> None:
    observed: dict[str, Any] = {}

    async def authorized_model_chat(**kwargs: Any) -> ChatResponse:
        observed.update(kwargs)
        observed["context"] = current_runtime_context()
        return ChatResponse(
            content="ok",
            tool_calls=[],
            model="mock",
            usage={},
            finish_reason="stop",
        )

    agent = SimpleNamespace(authorized_model_chat=authorized_model_chat)
    interpreter = _interpreter(agent)
    context = _context(tmp_path)

    response = await interpreter.execute_model(
        ModelEffect(messages=(ChatMessage(role="user", content="hello"),), model="mock"),
        context,
    )

    assert response.content == "ok"
    assert observed["tenant_id"] == "owner-a"
    assert observed["run_id"] == "run-a"
    assert observed["context"] == context
    assert current_runtime_context() is None


@pytest.mark.asyncio
async def test_stream_model_effect_owns_router_call_and_binds_context(tmp_path: Path) -> None:
    observed: dict[str, Any] = {}

    class Router:
        _permit_verifier = ModelPermitIssuer()

        async def chat_stream_events(self, **kwargs: Any):
            observed.update(kwargs)
            observed["context"] = current_runtime_context()
            yield StreamEvent(kind="text_delta", text="ok")
            yield StreamEvent(kind="done", finish_reason="stop")

    async def before_model_call(*_args: Any) -> object:
        return object()

    async def after_model_call(*_args: Any) -> None:
        return None

    interpreter = _interpreter(SimpleNamespace(router=Router()))
    context = _context(tmp_path)

    events = [
        event
        async for event in interpreter.execute_model_stream(
            ModelEffect(messages=(ChatMessage(role="user", content="hello"),), model="mock"),
            context,
            before_model_call=before_model_call,
            after_model_call=after_model_call,
        )
    ]

    assert [event.kind for event in events] == ["text_delta", "done"]
    assert observed["context"] == context
    assert observed["messages"][0].content == "hello"
    assert observed["model"] == "mock"
    assert observed["before_model_call"] is before_model_call
    assert observed["after_model_call"] is after_model_call
    assert current_runtime_context() is None


@pytest.mark.asyncio
async def test_model_effect_enforces_runtime_deadline_during_provider_call(
    tmp_path: Path,
) -> None:
    never = asyncio.Event()

    async def authorized_model_chat(**_kwargs: Any) -> ChatResponse:
        await never.wait()
        raise AssertionError("unreachable")

    interpreter = _interpreter(SimpleNamespace(authorized_model_chat=authorized_model_chat))
    context = _context(
        tmp_path,
        deadline_ms=int(time.monotonic() * 1000) + 40,
    )

    with pytest.raises(TimeoutError, match="deadline"):
        await asyncio.wait_for(
            interpreter.execute_model(
                ModelEffect(messages=(ChatMessage(role="user", content="hello"),)),
                context,
            ),
            timeout=0.5,
        )

    assert current_runtime_context() is None


@pytest.mark.asyncio
async def test_stream_model_effect_enforces_one_turn_deadline_while_waiting(
    tmp_path: Path,
) -> None:
    never = asyncio.Event()

    class Router:
        _permit_verifier = ModelPermitIssuer()

        async def chat_stream_events(self, **_kwargs: Any):
            await never.wait()
            yield StreamEvent(kind="done", finish_reason="stop")

    async def before_model_call(*_args: Any) -> object:
        return object()

    async def after_model_call(*_args: Any) -> None:
        return None

    interpreter = _interpreter(SimpleNamespace(router=Router()))
    context = _context(
        tmp_path,
        deadline_ms=int(time.monotonic() * 1000) + 40,
    )

    async def consume() -> None:
        async for _event in interpreter.execute_model_stream(
            ModelEffect(messages=(ChatMessage(role="user", content="hello"),)),
            context,
            before_model_call=before_model_call,
            after_model_call=after_model_call,
        ):
            pass

    with pytest.raises(TimeoutError, match="deadline"):
        await asyncio.wait_for(consume(), timeout=0.5)

    assert current_runtime_context() is None


@pytest.mark.asyncio
async def test_tool_effect_uses_leased_executor_and_runtime_capabilities(tmp_path: Path) -> None:
    execute = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="[]", name="file_list"),
            ToolResult(success=True, output="[]"),
        )
    )
    agent = SimpleNamespace(_execute_tool_call=execute)
    interpreter = _interpreter(agent)
    context = _context(tmp_path, capabilities=("file_list",))

    _message, result = await interpreter.execute_tool(
        ToolEffect.from_arguments(
            "file_list",
            {"path": "."},
            allowed_tools=("file_list",),
        ),
        context,
    )

    assert result.success
    call = execute.await_args
    assert call.args[1:4] == ("session-a", "run-a", "")
    assert call.kwargs["allowed_tools"] == {"file_list"}
    assert call.kwargs["owner_key_hash"] == "owner-a"


@pytest.mark.asyncio
async def test_tool_effect_enforces_runtime_deadline_during_handler_call(
    tmp_path: Path,
) -> None:
    never = asyncio.Event()

    async def execute(*_args: Any, **_kwargs: Any) -> tuple[ChatMessage, ToolResult]:
        await never.wait()
        raise AssertionError("unreachable")

    interpreter = _interpreter(SimpleNamespace(_execute_tool_call=execute))
    context = _context(
        tmp_path,
        capabilities=("file_list",),
        deadline_ms=int(time.monotonic() * 1000) + 40,
    )

    with pytest.raises(TimeoutError, match="deadline"):
        await asyncio.wait_for(
            interpreter.execute_tool(
                ToolEffect.from_arguments(
                    "file_list",
                    {"path": "."},
                    allowed_tools=("file_list",),
                ),
                context,
            ),
            timeout=0.5,
        )

    assert current_runtime_context() is None


@pytest.mark.asyncio
async def test_tool_effect_cannot_widen_runtime_capabilities(tmp_path: Path) -> None:
    agent = SimpleNamespace(_execute_tool_call=AsyncMock())
    interpreter = _interpreter(agent)

    with pytest.raises(PermissionError, match="outside"):
        await interpreter.execute_tool(
            ToolEffect.from_arguments("shell", {"command": "pwd"}),
            _context(tmp_path, capabilities=("file_list",)),
        )

    agent._execute_tool_call.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("context_capabilities", "effect_capabilities"),
    [
        ((), ("file_list",)),
        (("file_list",), ()),
    ],
)
async def test_tool_effect_denies_when_either_capability_set_is_empty(
    tmp_path: Path,
    context_capabilities: tuple[str, ...],
    effect_capabilities: tuple[str, ...],
) -> None:
    agent = SimpleNamespace(_execute_tool_call=AsyncMock())
    interpreter = _interpreter(agent)

    with pytest.raises(PermissionError, match="outside"):
        await interpreter.execute_tool(
            ToolEffect.from_arguments(
                "file_list",
                {"path": "."},
                allowed_tools=effect_capabilities,
            ),
            _context(tmp_path, capabilities=context_capabilities),
        )

    agent._execute_tool_call.assert_not_awaited()
