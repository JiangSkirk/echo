"""Owner isolation for the Fleet dashboard WebSocket."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from js.config import JSSettings, SecurityConfig
from js.models.providers import ChatMessage
from js.orchestration.fleet import AgentFleet, AgentInstance, AgentRole
from js.tools.registry import ToolResult
from js.web.auth import AuthManager
from js.web.runtime_context import WebRuntime, bind_web_runtime, clear_web_runtime
from js.web.server import create_app

if TYPE_CHECKING:
    from fastapi import FastAPI


def _websocket_app(
    tmp_path: Path,
    *,
    product_id: str,
) -> tuple[FastAPI, AgentFleet, str, str, str]:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        providers=[],
        security=SecurityConfig(api_key_required=False),
    )
    object.__setattr__(settings, "product_id", product_id)
    fleet = AgentFleet(settings, inherit_skills=False)
    echo_runtime = SimpleNamespace(
        build_context=MagicMock(
            side_effect=lambda **kwargs: SimpleNamespace(
                owner_key_hash=kwargs["owner_key_hash"]
            )
        ),
        execute_tool_effect=AsyncMock(),
    )
    agent = SimpleNamespace(settings=settings, echo_runtime=echo_runtime)

    auth = AuthManager(settings.state_dir)
    key_a = auth.create_key("admin-a", role="admin")
    key_b = auth.create_key("admin-b", role="admin")
    user_key = auth.create_key("user", role="user")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        runtime = WebRuntime(agent=agent, settings=settings, fleet=fleet)
        bind_web_runtime(app, runtime)
        try:
            yield
        finally:
            clear_web_runtime(app, runtime)

    app = create_app(
        lifespan_context=lifespan,
        title=f"{product_id} Fleet WebSocket Test",
        runtime_settings=settings,
    )
    app.state.test_agent = agent
    return app, fleet, key_a, key_b, user_key


def _add_worker(
    fleet: AgentFleet,
    *,
    product_id: str,
    owner_key_hash: str,
    worker_id: str,
) -> None:
    fleet.agents[worker_id] = AgentInstance(
        id=worker_id,
        name="worker",
        role=AgentRole.WORKER,
        agent=cast("Any", SimpleNamespace()),
        product_id=product_id,
        owner_key_hash=owner_key_hash,
        status="busy",
        current_task=f"task-{worker_id}",
    )


@pytest.mark.parametrize("product_id", ["js-agent", "js-work"])
def test_fleet_websocket_scopes_status_events_and_unsubscribe(
    tmp_path: Path,
    product_id: str,
) -> None:
    app, fleet, key_a, key_b, _user_key = _websocket_app(
        tmp_path,
        product_id=product_id,
    )
    auth = AuthManager(fleet.settings.state_dir)
    owner_a = str(auth.verify(key_a)["key_hash"])
    owner_b = str(auth.verify(key_b)["key_hash"])
    _add_worker(
        fleet,
        product_id=product_id,
        owner_key_hash=owner_a,
        worker_id="worker-a",
    )
    _add_worker(
        fleet,
        product_id=product_id,
        owner_key_hash=owner_b,
        worker_id="worker-b",
    )

    with (
        TestClient(app, base_url="http://localhost") as client,
        client.websocket_connect(
            "/ws/fleet",
            headers={
                "Host": "localhost",
                "Origin": "http://localhost",
                "X-API-Key": key_a,
            },
        ) as ws_a,
        client.websocket_connect(
            "/ws/fleet",
            headers={
                "Host": "localhost",
                "Origin": "http://localhost",
                "X-API-Key": key_b,
            },
        ) as ws_b,
    ):
        status_a = ws_a.receive_json()
        status_b = ws_b.receive_json()
        assert [item["id"] for item in status_a["data"]["agents"]] == ["worker-a"]
        assert [item["id"] for item in status_b["data"]["agents"]] == ["worker-b"]

        events_a = [
            {"type": "agent_start", "task_id": "task-a"},
            {
                "type": "collaborate_result",
                "session_id": "session-a",
                "final": "result-a",
            },
            {"type": "agent_thinking", "task_id": "task-a", "content": "thinking-a"},
            {
                "type": "agent_tool_call",
                "task_id": "task-a",
                "tool_name": "search",
            },
        ]
        for event in events_a:
            client.portal.call(
                partial(
                    fleet._emit,
                    event,
                    product_id=product_id,
                    owner_key_hash=owner_a,
                )
            )

        assert [ws_a.receive_json() for _ in events_a] == events_a
        ws_b.send_json({"type": "ping"})
        assert ws_b.receive_json() == {"type": "pong"}

        serialized = json.dumps(events_a)
        assert owner_a not in serialized
        assert owner_b not in serialized
        assert "owner_key_hash" not in serialized

        ws_a.send_json({"type": "status"})
        refreshed_status = ws_a.receive_json()
        assert [item["id"] for item in refreshed_status["data"]["agents"]] == ["worker-a"]

        collaborate = AsyncMock(
            return_value={"session_id": "session-a", "final": "ok", "subtasks": {}}
        )
        continue_session = AsyncMock(
            return_value={"session_id": "session-a", "final": "continued", "subtasks": {}}
        )
        fleet.collaborate = collaborate  # type: ignore[method-assign]
        fleet.continue_session = continue_session  # type: ignore[method-assign]

        async def execute_fleet_effect(effect: Any, context: Any) -> tuple[Any, ToolResult]:
            arguments = json.loads(effect.arguments_json)
            if effect.tool_name == "fleet_collaborate":
                result = await fleet.collaborate(
                    main_task=arguments["task"],
                    subtasks=arguments["subtasks"],
                    session_id=arguments["session_id"],
                    role_mapping=arguments["role_mapping"],
                    mode=arguments["mode"],
                    owner_key_hash=context.owner_key_hash,
                )
            else:
                result = await fleet.continue_session(
                    session_id=arguments["session_id"],
                    follow_up=arguments["follow_up"],
                    owner_key_hash=context.owner_key_hash,
                )
            return (
                ChatMessage(role="tool", content=str(result["final"]), name=effect.tool_name),
                ToolResult(
                    success=True,
                    output=str(result["final"]),
                    metadata={"session_id": str(result["session_id"])},
                ),
            )

        app.state.test_agent.echo_runtime.execute_tool_effect.side_effect = (
            execute_fleet_effect
        )
        ws_a.send_json({"type": "collaborate", "task": "owner A task"})
        assert ws_a.receive_json() == {"type": "ack", "action": "collaborate"}
        ws_a.send_json(
            {"type": "continue", "session_id": "session-a", "task": "owner A follow-up"}
        )
        assert ws_a.receive_json() == {"type": "ack", "action": "continue"}
        client.portal.call(partial(asyncio.sleep, 0.01))

        assert collaborate.await_args.kwargs["owner_key_hash"] == owner_a
        assert continue_session.await_args.kwargs["owner_key_hash"] == owner_a
        assert app.state.test_agent.echo_runtime.execute_tool_effect.await_count == 2
        effects = [
            call.args[0]
            for call in app.state.test_agent.echo_runtime.execute_tool_effect.await_args_list
        ]
        assert [effect.tool_name for effect in effects] == [
            "fleet_collaborate",
            "control_fleet_continue",
        ]

    assert fleet._event_callbacks == []


@pytest.mark.parametrize("credential", ["missing", "non-admin"])
def test_fleet_websocket_rejects_missing_or_non_admin_credentials(
    tmp_path: Path,
    credential: str,
) -> None:
    app, _fleet, _key_a, _key_b, user_key = _websocket_app(
        tmp_path,
        product_id="js-agent",
    )
    headers = {"Host": "localhost", "Origin": "http://localhost"}
    if credential == "non-admin":
        headers["X-API-Key"] = user_key

    with (
        TestClient(app, base_url="http://localhost") as client,
        pytest.raises(WebSocketDisconnect) as exc_info,
        client.websocket_connect(
            "/ws/fleet",
            headers=headers,
        ),
    ):
        pass

    assert exc_info.value.code == 1008


def test_fleet_websocket_rejects_query_string_admin_key(tmp_path: Path) -> None:
    app, _fleet, admin_key, _key_b, _user_key = _websocket_app(
        tmp_path,
        product_id="js-agent",
    )

    with (
        TestClient(app, base_url="http://localhost") as client,
        pytest.raises(WebSocketDisconnect) as exc_info,
        client.websocket_connect(
            f"/ws/fleet?x-api-key={admin_key}",
            headers={"Host": "localhost", "Origin": "http://localhost"},
        ),
    ):
        pass

    assert exc_info.value.code == 1008


def test_fleet_websocket_rejects_malformed_collaboration_before_echo(
    tmp_path: Path,
) -> None:
    app, _fleet, admin_key, _key_b, _user_key = _websocket_app(
        tmp_path,
        product_id="js-agent",
    )

    with (
        TestClient(app, base_url="http://localhost") as client,
        client.websocket_connect(
            "/ws/fleet",
            headers={
                "Host": "localhost",
                "Origin": "http://localhost",
                "X-API-Key": admin_key,
            },
        ) as websocket,
    ):
        assert websocket.receive_json()["type"] == "status"
        websocket.send_json(
            {
                "type": "collaborate",
                "task": ["not", "a", "string"],
                "subtasks": [7],
            }
        )
        assert websocket.receive_json() == {
            "type": "error",
            "message": "Invalid Fleet request",
        }

    app.state.test_agent.echo_runtime.execute_tool_effect.assert_not_awaited()
