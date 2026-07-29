from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.config import JSSettings
from js.echo.turn_context import current_runtime_context
from js.echo.turn_runtime import EchoRuntime


class _IdentityLoop:
    def __init__(self, _agent: Any, request: Any) -> None:
        self.request = request

    async def execute(self) -> Any:
        bound = current_runtime_context()
        assert bound is not None
        return SimpleNamespace(
            request_session=self.request.context.session_id,
            request_run=self.request.context.run_id,
            bound_session=bound.session_id,
            bound_run=bound.run_id,
        )


class _Pulse:
    def observe(self, **_kwargs: Any) -> Any:
        return SimpleNamespace(admitted=True)


@pytest.mark.asyncio
async def test_generated_session_and_run_identity_are_bound_once(tmp_path: Path) -> None:
    agent = SimpleNamespace(
        settings=JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state"),
        _role="local-user",
        _work_profile="default",
        _current_allowed_tools=set(),
        _lane_executor=None,
    )
    runtime = EchoRuntime(
        agent,
        pulse_runtime=_Pulse(),
        turn_loop_factory=lambda runtime_agent, request: _IdentityLoop(runtime_agent, request),
    )

    result = await runtime.run_agent_turn(
        "hello",
        channel="test",
        owner_key_hash="owner-a",
    )

    assert result.request_session
    assert result.request_run
    assert result.request_session == result.bound_session
    assert result.request_run == result.bound_run
