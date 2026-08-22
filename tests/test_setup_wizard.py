"""Tests for the enhanced setup wizard: diagnostics, model testing, reset."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from js.agent.tool_executor import CONTROL_SETUP_STATE_TOOL
from js.models.providers import ChatMessage
from js.tools.registry import ToolResult
from js.web.server import create_app


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    """Build a TestClient with mocked agent and isolated settings."""
    from js.config import JSSettings, SecurityConfig
    from js.web import server as web_server
    from js.web.deps import set_globals

    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        first_run_completed=False,
        security=SecurityConfig(api_key_required=False),
    )
    settings.security.api_key_required = False  # Allow unauthenticated access in tests

    mock_agent = MagicMock()
    mock_agent.settings = settings
    mock_agent.registry.get_stats.return_value = {}
    mock_agent.secrets.get_stats.return_value = {"stored_secrets": 0, "detected_leaks": 0}
    mock_agent.metacognition = MagicMock()
    mock_agent.learner = MagicMock()
    mock_agent.optimizer = MagicMock()
    mock_agent._run_evolution_cycle = AsyncMock(return_value={"ok": True})
    mock_agent.skills = MagicMock()
    mock_agent.memory = MagicMock()
    mock_agent.memory.get_context_string.return_value = ""
    mock_agent.memory.get_episodes.return_value = []
    mock_agent.memory.get_dream_logs.return_value = []
    mock_agent.memory.get_all_semantic.return_value = []
    mock_agent.memory.get_all_working.return_value = []
    mock_agent.memory.list_memory_files.return_value = []
    mock_agent.memory.get_sessions.return_value = []
    mock_agent.memory.cleanup_empty_sessions.return_value = 0
    mock_agent.memory.embedder.health.return_value = MagicMock(
        provider="test", active=True, fallback_provider=None, failure_count=0
    )

    # Model router mock
    mock_router = MagicMock()
    mock_agent.router = mock_router

    async def _authorized_model_chat(*, messages, model=None, tools=None, temperature=0.7, **_):
        decision = await mock_router.select_model(preferred=model)
        return await decision.provider.chat(
            messages=messages,
            model=decision.model,
            tools=tools,
            temperature=temperature,
        )

    from js.echo.turn_runtime import EchoRuntime

    mock_agent.authorized_model_chat = _authorized_model_chat
    mock_agent._current_allowed_tools = {CONTROL_SETUP_STATE_TOOL}
    mock_agent.echo_runtime = EchoRuntime(mock_agent)
    mock_agent.take_setup_admin_key = MagicMock(return_value=None)

    async def _execute_setup_state(effect, _context):
        assert effect.tool_name == CONTROL_SETUP_STATE_TOOL
        action = json.loads(effect.arguments_json)["action"]
        status_map = {
            "complete": "completed",
            "skip": "skipped",
            "start": "in_progress",
            "reset": "pending",
        }
        if action not in status_map:
            return (
                ChatMessage(role="tool", content="invalid", name=effect.tool_name),
                ToolResult(
                    success=False,
                    error="Invalid setup state action",
                    metadata={"status_code": 400},
                ),
            )
        settings.onboarding_status = status_map[action]
        settings.first_run_completed = status_map[action] in {"completed", "skipped"}
        return (
            ChatMessage(role="tool", content="updated", name=effect.tool_name),
            ToolResult(
                success=True,
                output="updated",
                metadata={
                    "first_run_completed": settings.first_run_completed,
                    "onboarding_status": settings.onboarding_status,
                },
            ),
        )

    mock_agent.echo_runtime.execute_tool_effect = AsyncMock(side_effect=_execute_setup_state)

    web_server._agent = mock_agent
    web_server._settings = settings
    set_globals(mock_agent, settings)
    app = create_app()
    from js.web.auth import AuthManager

    user_key = AuthManager(settings.state_dir).create_key("setup-wizard", role="user")
    return TestClient(app, headers={"X-API-Key": user_key})


class TestSetupFirstStart:
    """Tests for /api/setup/first-start diagnostics endpoint."""

    def test_get_does_not_probe_local_model_servers(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from js.models import discovery as discovery_module

        discovery = MagicMock(side_effect=AssertionError("GET must be side-effect free"))
        monkeypatch.setattr(discovery_module, "LocalModelDiscovery", discovery)

        res = client.get("/api/setup/first-start")

        assert res.status_code == 200
        assert res.json()["diagnostics"]["local_providers_detected"] == []
        discovery.assert_not_called()

    def test_returns_first_run_status(self, client: TestClient) -> None:
        res = client.get("/api/setup/first-start")
        assert res.status_code == 200
        data = res.json()
        assert "first_run_completed" in data
        assert data["first_run_completed"] is False

    def test_returns_diagnostics(self, client: TestClient) -> None:
        res = client.get("/api/setup/first-start")
        assert res.status_code == 200
        data = res.json()
        assert "diagnostics" in data
        diag = data["diagnostics"]
        assert "python_version" in diag
        assert "local_providers_detected" in diag
        assert isinstance(diag["local_providers_detected"], list)
        assert "has_configured_models" in diag
        assert isinstance(diag["has_configured_models"], bool)


class TestSetupComplete:
    """Tests for /api/setup/complete endpoint."""

    def test_marks_first_run_completed(self, client: TestClient) -> None:
        # Before
        res = client.get("/api/setup/first-start")
        assert res.json()["first_run_completed"] is False

        # Complete
        res = client.post("/api/setup/complete")
        assert res.status_code == 200
        assert res.json()["success"] is True

        # After
        res = client.get("/api/setup/first-start")
        assert res.json()["first_run_completed"] is True

        from js.web.deps import get_agent

        effect, context = get_agent().echo_runtime.execute_tool_effect.await_args.args
        assert effect.tool_name == CONTROL_SETUP_STATE_TOOL
        assert effect.allowed_tools == (CONTROL_SETUP_STATE_TOOL,)
        assert effect.arguments_json == '{"action":"complete"}'
        assert context.capabilities == (CONTROL_SETUP_STATE_TOOL,)


class TestSetupReset:
    """Tests for /api/setup/reset endpoint."""

    def test_resets_first_run_flag(self, client: TestClient) -> None:
        # Complete first
        client.post("/api/setup/complete")
        res = client.get("/api/setup/first-start")
        assert res.json()["first_run_completed"] is True

        # Reset
        res = client.post("/api/setup/reset")
        assert res.status_code == 200
        assert res.json()["success"] is True

        # Verify reset
        res = client.get("/api/setup/first-start")
        assert res.json()["first_run_completed"] is False


class TestSetupTestModel:
    """Tests for /api/setup/test-model endpoint."""

    def test_requires_model_id(self, client: TestClient) -> None:
        res = client.post("/api/setup/test-model", json={})
        assert res.status_code == 400
        assert "model_id" in res.text.lower() or "required" in res.text.lower()

    def _get_router(self, client: TestClient):
        """Get the mock router from the deps module."""
        from js.web import deps

        agent = deps.get_agent()
        return agent.router

    def test_model_not_found(self, client: TestClient) -> None:
        from js.models.router import RoutingDecision

        router = self._get_router(client)
        router.select_model = AsyncMock(
            return_value=RoutingDecision(provider=None, model="", provider_name="", reason="")
        )
        res = client.post("/api/setup/test-model", json={"model_id": "nonexistent"})
        assert res.status_code == 404

    def test_model_test_success(self, client: TestClient) -> None:
        from js.models.providers import ChatResponse
        from js.models.router import RoutingDecision

        mock_provider = MagicMock()
        mock_provider.chat = AsyncMock(
            return_value=ChatResponse(
                content="OK",
                tool_calls=[],
                model="test-model",
                usage={},
                finish_reason="stop",
            )
        )
        # Mark as local so API key check is skipped
        mock_provider._is_local = True

        router = self._get_router(client)
        router.select_model = AsyncMock(
            return_value=RoutingDecision(
                provider=mock_provider,
                model="test-model",
                provider_name="test",
                reason="test",
            )
        )
        mock_cfg = MagicMock()
        mock_cfg.context_window = 131072
        router.get_model_config = MagicMock(return_value=mock_cfg)
        from js.web import deps

        agent = deps.get_agent()
        original_build_context = agent.echo_runtime.build_context
        agent.echo_runtime.build_context = MagicMock(wraps=original_build_context)

        res = client.post("/api/setup/test-model", json={"model_id": "test/model"})
        second = client.post("/api/setup/test-model", json={"model_id": "test/model"})
        assert res.status_code == 200
        assert second.status_code == 200
        data = res.json()
        assert data["ok"] is True
        assert data["latency_ms"] >= 0
        assert data["error"] is None
        assert data["context_window"] == 131072
        assert data["provider"] == "test"
        assert "response_preview" in data
        contexts = agent.echo_runtime.build_context.call_args_list
        assert contexts[0].kwargs["run_id"] != contexts[1].kwargs["run_id"]
        assert contexts[0].kwargs["session_id"] != contexts[1].kwargs["session_id"]

    def test_model_test_failure(self, client: TestClient) -> None:
        from js.models.router import RoutingDecision

        mock_provider = MagicMock()
        mock_provider.chat = AsyncMock(side_effect=RuntimeError("Connection refused"))

        router = self._get_router(client)
        router.select_model = AsyncMock(
            return_value=RoutingDecision(
                provider=mock_provider,
                model="bad-model",
                provider_name="bad",
                reason="test",
            )
        )
        router.get_model_config = MagicMock(return_value=None)

        res = client.post("/api/setup/test-model", json={"model_id": "bad/model"})
        assert res.status_code == 200  # Returns failure info, not error
        data = res.json()
        assert data["ok"] is False
        assert "无法连接到模型服务" in data["error"]
        assert data["latency_ms"] >= 0

    def test_model_test_timeout(self, client: TestClient) -> None:
        import asyncio

        from js.models.router import RoutingDecision

        mock_provider = MagicMock()
        mock_provider.chat = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_provider._is_local = True

        router = self._get_router(client)
        router.select_model = AsyncMock(
            return_value=RoutingDecision(
                provider=mock_provider,
                model="slow-model",
                provider_name="slow",
                reason="test",
            )
        )
        router.get_model_config = MagicMock(return_value=None)

        res = client.post("/api/setup/test-model", json={"model_id": "slow/model"})
        assert res.status_code == 200
        data = res.json()
        assert data["ok"] is False
        assert "超时" in data["error"]
