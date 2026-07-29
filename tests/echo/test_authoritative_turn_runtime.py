from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.agent.runner import RunnerMixin
from js.echo.ledger.service import EchoUnavailableError
from js.echo.state import AgentState
from js.echo.turn_context import current_runtime_context
from js.echo.turn_runtime import EchoRuntime, RuntimeContext, TurnRequest, run_echo_turn


@dataclass
class _PulseResult:
    admitted: bool = True


class _Pulse:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def observe(self, **kwargs: Any) -> _PulseResult:
        self.calls.append(kwargs)
        return _PulseResult()


class _Loop:
    def __init__(self, result: object, seen: list[RuntimeContext | None]) -> None:
        self._result = result
        self._seen = seen

    async def execute(self) -> object:
        self._seen.append(current_runtime_context())
        return self._result


@pytest.mark.asyncio
async def test_echo_runtime_executes_turn_loop_with_bound_context(tmp_path: Path) -> None:
    expected = object()
    seen: list[RuntimeContext | None] = []
    pulse = _Pulse()
    agent = SimpleNamespace(
        settings=SimpleNamespace(
            workspace=tmp_path,
            state_dir=tmp_path / "state",
            echo_engine="on",
            product_id="js-agent",
        ),
        _lane_executor=None,
    )
    runtime = EchoRuntime(
        agent,
        pulse_runtime=pulse,
        turn_loop_factory=lambda _agent, _request: _Loop(expected, seen),
    )
    context = runtime.build_context(
        channel="test",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        capabilities=(),
    )

    result = await runtime.run_turn(TurnRequest(message="hello", context=context))

    assert result is expected
    assert seen == [context]
    assert pulse.calls[0]["channel"].startswith("js-agent:test:")
    assert pulse.calls[0]["request_id"] == "run-a"
    assert current_runtime_context() is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value_factory"),
    [
        ("product_id", lambda root: "js-work"),
        ("workspace", lambda root: root / "other-workspace"),
        ("state_dir", lambda root: root / "other-state"),
        ("fs_roots", lambda root: (root.parent,)),
        ("network_allowlist", lambda root: ("example.com",)),
        ("deadline_ms", lambda root: None),
        ("cancel_token", lambda root: None),
    ],
)
async def test_echo_runtime_rejects_context_outside_its_agent_scope(
    tmp_path: Path,
    field: str,
    value_factory: Any,
) -> None:
    seen: list[RuntimeContext | None] = []
    agent = SimpleNamespace(
        settings=SimpleNamespace(
            workspace=tmp_path,
            state_dir=tmp_path / "state",
            echo_engine="on",
            product_id="js-agent",
        ),
        registry=SimpleNamespace(list_tools=lambda: []),
        _current_allowed_tools=set(),
        _lane_executor=None,
    )
    runtime = EchoRuntime(
        agent,
        pulse_runtime=_Pulse(),
        turn_loop_factory=lambda _agent, _request: _Loop(object(), seen),
    )
    context = runtime.build_context(
        channel="test",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
    )
    forged = replace(context, **{field: value_factory(tmp_path)})

    with pytest.raises(PermissionError, match="context scope"):
        await runtime.run_turn(TurnRequest(message="hello", context=forged))

    assert seen == []


def test_echo_runtime_rejects_capability_widening(tmp_path: Path) -> None:
    agent = SimpleNamespace(
        settings=SimpleNamespace(
            workspace=tmp_path,
            state_dir=tmp_path / "state",
            echo_engine="on",
            product_id="js-agent",
        ),
        registry=SimpleNamespace(
            list_tools=lambda: [SimpleNamespace(name="file_read")]
        ),
        _current_allowed_tools={"file_read"},
    )
    runtime = EchoRuntime(agent, pulse_runtime=_Pulse())

    with pytest.raises(PermissionError, match="capabilities"):
        runtime.build_context(
            channel="test",
            owner_key_hash="owner-a",
            capabilities=("file_read", "shell"),
        )


@pytest.mark.asyncio
async def test_run_echo_turn_rejects_duck_typed_runtime_bypass(tmp_path: Path) -> None:
    calls: list[dict[str, Any]] = []

    class Runtime:
        async def run_agent_turn(self, message: str, **kwargs: Any) -> str:
            calls.append({"message": message, **kwargs})
            return "echo-result"

    class Agent:
        settings = SimpleNamespace(workspace=tmp_path, state_dir=tmp_path / "state")
        echo_runtime = Runtime()

        async def run(self, *_args: Any, **_kwargs: Any) -> object:
            raise AssertionError("legacy agent.run must not be called")

    with pytest.raises(EchoUnavailableError, match="authoritative EchoRuntime"):
        await run_echo_turn(
            Agent(),
            "hello",
            channel="ws_stream",
            owner_key_hash="owner-a",
            session_id="session-a",
        )

    assert calls == []


@pytest.mark.asyncio
async def test_runner_mixin_rejects_duck_typed_runtime_bypass() -> None:
    calls: list[dict[str, Any]] = []

    class Runtime:
        async def run_agent_turn(self, message: str, **kwargs: Any) -> AgentState:
            calls.append({"message": message, **kwargs})
            return AgentState(
                session_id=kwargs["session_id"],
                run_id="run-a",
                status="completed",
            )

    runner = object.__new__(RunnerMixin)
    runner.echo_runtime = Runtime()  # type: ignore[attr-defined]

    with pytest.raises(EchoUnavailableError, match="authoritative EchoRuntime"):
        await runner.run("hello", session_id="session-a")

    assert calls == []


@pytest.mark.asyncio
async def test_runner_mixin_is_thin_facade_over_authoritative_runtime(
    tmp_path: Path,
) -> None:
    state = AgentState(session_id="session-a", run_id="run-a", status="completed")
    seen: list[RuntimeContext | None] = []
    runner = object.__new__(RunnerMixin)
    runner.settings = SimpleNamespace(  # type: ignore[attr-defined]
        workspace=tmp_path,
        state_dir=tmp_path / "state",
        product_id="js-agent",
    )
    runner._lane_executor = None  # type: ignore[attr-defined]
    runner.echo_runtime = EchoRuntime(  # type: ignore[attr-defined]
        runner,
        pulse_runtime=_Pulse(),
        turn_loop_factory=lambda _agent, _request: _Loop(state, seen),
    )
    bypass_calls: list[str] = []

    async def bypass(*_args: Any, **_kwargs: Any) -> AgentState:
        bypass_calls.append("called")
        raise AssertionError("instance-level runtime replacement must not run")

    runner.echo_runtime.run_agent_turn = bypass  # type: ignore[method-assign]

    result = await runner.run("hello", session_id="session-a")

    assert result is state
    assert bypass_calls == []
    assert seen[0] is not None
    assert seen[0].channel == "agent_api"
