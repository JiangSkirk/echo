"""Owner isolation for the Fleet dashboard WebSocket."""

from __future__ import annotations

import asyncio
import json
import threading
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
from js.orchestration.fleet import (
    AgentFleet,
    AgentInstance,
    AgentRole,
    bind_fleet_event_identity,
)
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


async def _emit_with_identity(
    fleet: AgentFleet,
    event: dict[str, Any],
    *,
    product_id: str,
    owner_key_hash: str,
    request_id: str,
    turn_id: str,
    session_id: str,
) -> None:
    with bind_fleet_event_identity(request_id, turn_id, session_id):
        await fleet._emit(
            event,
            product_id=product_id,
            owner_key_hash=owner_key_hash,
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
        event_identity = {
            "request_id": "request-a",
            "turn_id": "turn-a",
            "session_id": "session-a",
        }
        for event in events_a:
            client.portal.call(
                partial(
                    _emit_with_identity,
                    fleet,
                    event,
                    product_id=product_id,
                    owner_key_hash=owner_a,
                    **event_identity,
                )
            )

        assert [ws_a.receive_json() for _ in events_a] == [
            {**event, **event_identity} for event in events_a
        ]
        subscription_a = next(
            item for item in fleet._event_callbacks if item.owner_key_hash == owner_a
        )
        client.portal.call(
            partial(subscription_a.callback, {"type": "agent_start", "task_id": "missing"})
        )
        ws_a.send_json({"type": "ping"})
        assert ws_a.receive_json() == {"type": "pong"}
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
        ws_a.send_json(
            {
                "type": "collaborate",
                "task": "owner A task",
                "request_id": "request-collaborate",
                "turn_id": "turn-collaborate",
                "session_id": "session-a",
            }
        )
        assert ws_a.receive_json() == {"type": "ack", "action": "collaborate"}
        ws_a.send_json(
            {
                "type": "continue",
                "session_id": "session-a",
                "task": "owner A follow-up",
                "request_id": "request-continue",
                "turn_id": "turn-continue",
            }
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


@pytest.mark.parametrize(
    "identity",
    [
        {"request_id": "", "turn_id": "turn", "session_id": "session"},
        {"request_id": "request", "turn_id": " ", "session_id": "session"},
        {"request_id": "request", "turn_id": "turn", "session_id": "../session"},
        {"request_id": "r" * 129, "turn_id": "turn", "session_id": "session"},
    ],
)
def test_fleet_websocket_rejects_invalid_runtime_identity_before_echo(
    tmp_path: Path,
    identity: dict[str, str],
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
            {"type": "collaborate", "task": "must reject identity", **identity}
        )
        assert websocket.receive_json() == {
            "type": "error",
            "message": "Invalid Fleet request",
        }

    app.state.test_agent.echo_runtime.execute_tool_effect.assert_not_awaited()


def test_fleet_websocket_cancel_stops_inflight_effect(tmp_path: Path) -> None:
    app, _fleet, admin_key, _key_b, _user_key = _websocket_app(
        tmp_path,
        product_id="js-agent",
    )
    started = threading.Event()
    cancelled = threading.Event()

    async def blocking_effect(_effect: Any, _context: Any) -> tuple[Any, ToolResult]:
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise
        raise AssertionError("unreachable")

    app.state.test_agent.echo_runtime.execute_tool_effect.side_effect = blocking_effect
    identity = {
        "request_id": "fleet-request-cancel",
        "turn_id": "fleet-turn-cancel",
        "session_id": "fleet-session-cancel",
    }
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
                "task": "blocking fake Fleet tool",
                **identity,
            }
        )
        assert websocket.receive_json() == {"type": "ack", "action": "collaborate"}
        assert started.wait(1.0)
        websocket.send_json({"type": "cancel", **identity})
        assert websocket.receive_json() == {"type": "cancelled", **identity}
        assert cancelled.wait(1.0)

        successor_started = threading.Event()
        successor_cancelled = threading.Event()

        async def successor_effect(
            _effect: Any,
            _context: Any,
        ) -> tuple[Any, ToolResult]:
            successor_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                successor_cancelled.set()
                raise
            raise AssertionError("unreachable")

        app.state.test_agent.echo_runtime.execute_tool_effect.side_effect = successor_effect
        successor = {
            "request_id": "fleet-request-successor",
            "turn_id": "fleet-turn-successor",
            "session_id": "fleet-session-successor",
        }
        websocket.send_json(
            {"type": "collaborate", "task": "successor fake Fleet tool", **successor}
        )
        assert websocket.receive_json() == {"type": "ack", "action": "collaborate"}
        assert successor_started.wait(1.0)

        websocket.send_json({"type": "cancel", **identity})
        assert websocket.receive_json() == {
            "type": "cancel_rejected",
            "request_id": identity["request_id"],
            "turn_id": identity["turn_id"],
            "session_id": identity["session_id"],
        }
        assert not successor_cancelled.is_set()

        websocket.send_json({"type": "cancel", **successor})
        assert websocket.receive_json() == {"type": "cancelled", **successor}
        assert successor_cancelled.wait(1.0)


def test_fleet_websocket_effect_error_keeps_exact_runtime_identity(tmp_path: Path) -> None:
    app, _fleet, admin_key, _key_b, _user_key = _websocket_app(
        tmp_path,
        product_id="js-agent",
    )
    app.state.test_agent.echo_runtime.execute_tool_effect.return_value = (
        ChatMessage(role="tool", content="failed", name="fleet_collaborate"),
        ToolResult(success=False, error="failed"),
    )
    identity = {
        "request_id": "fleet-request-error",
        "turn_id": "fleet-turn-error",
        "session_id": "fleet-session-error",
    }

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
            {"type": "collaborate", "task": "fail safely", **identity}
        )
        assert websocket.receive_json() == {"type": "ack", "action": "collaborate"}
        assert websocket.receive_json() == {
            "type": "error",
            "message": "Fleet collaborate failed",
            **identity,
        }
