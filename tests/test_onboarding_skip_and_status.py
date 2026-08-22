"""Regression: onboarding skip + versioned server-side status.

Fake provider only — no real API keys, no Accessibility, no personal data.
"""

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

ONBOARDING_STATUSES = ("pending", "in_progress", "completed", "skipped")


@pytest.fixture
def setup_env(tmp_path: Path):
    """Isolated settings + mocked agent; returns (client, settings, agent)."""
    from js.config import JSSettings, SecurityConfig
    from js.echo.turn_runtime import EchoRuntime
    from js.web import server as web_server
    from js.web.auth import AuthManager
    from js.web.deps import set_globals

    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        first_run_completed=False,
        onboarding_status="pending",
        security=SecurityConfig(api_key_required=False),
    )
    settings.security.api_key_required = False
    settings.providers = []  # no real providers / keys

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
    mock_agent.router = MagicMock()
    mock_agent.echo_runtime = EchoRuntime(mock_agent)
    mock_agent.take_setup_admin_key = MagicMock(return_value=None)
    mock_agent._current_allowed_tools = {CONTROL_SETUP_STATE_TOOL}

    async def _authorized_model_chat(*, messages, model=None, tools=None, temperature=0.7, **_):
        decision = await mock_agent.router.select_model(preferred=model)
        return await decision.provider.chat(
            messages=messages,
            model=decision.model,
            tools=tools,
            temperature=temperature,
        )

    mock_agent.authorized_model_chat = _authorized_model_chat

    def _apply_action(action: str) -> dict:
        if action == "complete":
            settings.onboarding_status = "completed"
            settings.first_run_completed = True
        elif action == "skip":
            settings.onboarding_status = "skipped"
            settings.first_run_completed = True
        elif action == "start":
            settings.onboarding_status = "in_progress"
            settings.first_run_completed = False
        elif action == "reset":
            settings.onboarding_status = "pending"
            settings.first_run_completed = False
        else:
            raise ValueError(f"bad action {action}")
        return {
            "first_run_completed": settings.first_run_completed,
            "onboarding_status": settings.onboarding_status,
        }

    async def _execute_setup_state(effect, _context):
        assert effect.tool_name == CONTROL_SETUP_STATE_TOOL
        action = json.loads(effect.arguments_json)["action"]
        if action not in {"complete", "reset", "skip", "start"}:
            return (
                ChatMessage(role="tool", content="invalid", name=effect.tool_name),
                ToolResult(
                    success=False,
                    error="Invalid setup state action",
                    metadata={"status_code": 400},
                ),
            )
        payload = _apply_action(action)
        return (
            ChatMessage(role="tool", content="updated", name=effect.tool_name),
            ToolResult(success=True, output="updated", metadata=payload),
        )

    mock_agent.echo_runtime.execute_tool_effect = AsyncMock(side_effect=_execute_setup_state)

    web_server._agent = mock_agent
    web_server._settings = settings
    set_globals(mock_agent, settings)
    app = create_app()
    user_key = AuthManager(settings.state_dir).create_key("onboarding-test", role="user")
    client = TestClient(app, headers={"X-API-Key": user_key})
    return client, settings, mock_agent


class TestOnboardingStatusSurface:
    def test_first_start_exposes_versioned_status(self, setup_env) -> None:
        client, settings, _ = setup_env
        res = client.get("/api/setup/first-start")
        assert res.status_code == 200
        data = res.json()
        assert data["first_run_completed"] is False
        assert data["onboarding_status"] == "pending"
        assert data["wizard_blocking"] is True
        assert data["onboarding_status"] in ONBOARDING_STATUSES
        # No synthetic providers from status read
        assert settings.providers == []

    def test_legacy_first_run_true_migrates_to_completed(self, tmp_path: Path) -> None:
        from js.config import JSSettings, SecurityConfig

        s = JSSettings(
            workspace=tmp_path / "ws",
            state_dir=tmp_path / "st",
            first_run_completed=True,
            # omit / default pending — validator must promote to completed
            security=SecurityConfig(api_key_required=False),
        )
        assert s.onboarding_status == "completed"
        assert s.first_run_completed is True


class TestOnboardingSkip:
    def test_skip_persists_without_providers_or_model_selection(self, setup_env) -> None:
        client, settings, agent = setup_env
        before_providers = list(settings.providers)

        res = client.post("/api/setup/skip")
        assert res.status_code == 200
        body = res.json()
        assert body["success"] is True
        assert body["onboarding_status"] == "skipped"
        assert body["first_run_completed"] is True

        assert settings.onboarding_status == "skipped"
        assert settings.first_run_completed is True
        assert settings.providers == before_providers
        assert settings.providers == []

        effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
        assert effect.tool_name == CONTROL_SETUP_STATE_TOOL
        assert json.loads(effect.arguments_json)["action"] == "skip"
        assert context.capabilities == (CONTROL_SETUP_STATE_TOOL,)

        # Reload semantics: first-start no longer blocks
        res2 = client.get("/api/setup/first-start")
        data = res2.json()
        assert data["onboarding_status"] == "skipped"
        assert data["first_run_completed"] is True
        assert data["wizard_blocking"] is False

    def test_skip_from_any_progress_state(self, setup_env) -> None:
        client, settings, _ = setup_env
        client.post("/api/setup/start")
        assert settings.onboarding_status == "in_progress"
        res = client.post("/api/setup/skip")
        assert res.status_code == 200
        assert settings.onboarding_status == "skipped"
        assert settings.first_run_completed is True

    def test_guest_cannot_skip(self, setup_env) -> None:
        client, settings, _ = setup_env
        # Re-bind anonymous guest client when api_key_required is false:
        # explicit key has user role; use a guest-role key.
        from js.web.auth import AuthManager
        from js.web.server import create_app

        guest_key = AuthManager(settings.state_dir).create_key("guest-onboard", role="guest")
        guest_client = TestClient(create_app(), headers={"X-API-Key": guest_key})
        res = guest_client.post("/api/setup/skip")
        assert res.status_code == 403
        assert settings.onboarding_status == "pending"


class TestOnboardingStartAndComplete:
    def test_start_marks_in_progress(self, setup_env) -> None:
        client, settings, _ = setup_env
        res = client.post("/api/setup/start")
        assert res.status_code == 200
        assert res.json()["onboarding_status"] == "in_progress"
        assert settings.first_run_completed is False
        assert client.get("/api/setup/first-start").json()["wizard_blocking"] is True

    def test_complete_marks_completed(self, setup_env) -> None:
        client, settings, _ = setup_env
        res = client.post("/api/setup/complete")
        assert res.status_code == 200
        assert settings.onboarding_status == "completed"
        assert settings.first_run_completed is True
        data = client.get("/api/setup/first-start").json()
        assert data["wizard_blocking"] is False
        assert data["onboarding_status"] == "completed"


class TestModelTestDoesNotLockOnboarding:
    def test_test_model_failure_leaves_status_and_allows_skip(self, setup_env) -> None:
        from js.models.router import RoutingDecision

        client, settings, agent = setup_env
        client.post("/api/setup/start")

        mock_provider = MagicMock()
        mock_provider.chat = AsyncMock(side_effect=RuntimeError("Connection refused"))
        mock_provider._is_local = True
        agent.router.select_model = AsyncMock(
            return_value=RoutingDecision(
                provider=mock_provider,
                model="fake-model",
                provider_name="fake",
                reason="test",
            )
        )
        agent.router.get_model_config = MagicMock(return_value=None)

        res = client.post("/api/setup/test-model", json={"model_id": "fake/model"})
        assert res.status_code == 200
        assert res.json()["ok"] is False
        # Status must remain in_progress — test failure is not a hard lock
        assert settings.onboarding_status == "in_progress"

        skip = client.post("/api/setup/skip")
        assert skip.status_code == 200
        assert settings.onboarding_status == "skipped"

    def test_test_model_timeout_does_not_complete_or_skip(self, setup_env) -> None:
        import asyncio

        from js.models.router import RoutingDecision

        client, settings, agent = setup_env
        mock_provider = MagicMock()
        mock_provider.chat = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_provider._is_local = True
        agent.router.select_model = AsyncMock(
            return_value=RoutingDecision(
                provider=mock_provider,
                model="slow",
                provider_name="fake",
                reason="test",
            )
        )
        agent.router.get_model_config = MagicMock(return_value=None)
        res = client.post("/api/setup/test-model", json={"model_id": "fake/slow"})
        assert res.status_code == 200
        assert res.json()["ok"] is False
        assert "超时" in (res.json().get("error") or "")
        assert settings.onboarding_status == "pending"
        assert settings.first_run_completed is False

    def test_missing_api_key_response_is_soft_failure(self, setup_env) -> None:
        from js.config import ModelProviderConfig
        from js.models.router import RoutingDecision

        client, settings, agent = setup_env
        settings.providers = [
            ModelProviderConfig(
                name="cloud-fake",
                base_url="https://example.invalid/v1",
                api_key="",
                default_model="m1",
            )
        ]
        mock_provider = MagicMock()
        mock_provider._is_local = False
        agent.router.select_model = AsyncMock(
            return_value=RoutingDecision(
                provider=mock_provider,
                model="m1",
                provider_name="cloud-fake",
                reason="test",
            )
        )
        agent.router.get_model_config = MagicMock(return_value=None)
        res = client.post("/api/setup/test-model", json={"model_id": "cloud-fake/m1"})
        assert res.status_code == 200
        data = res.json()
        assert data["ok"] is False
        assert data.get("needs_config") is True
        # Must not invent a key or flip onboarding
        assert settings.onboarding_status == "pending"
        assert not settings.providers[0].api_key


class TestWizardTemplateHasSkipExits:
    def test_index_html_offers_skip_on_welcome_and_later_steps(self) -> None:
        html = Path("js/web/templates/index.html").read_text(encoding="utf-8")
        assert "wizardSkip" in html or "wizard-skip" in html
        assert "一键跳过" in html or "稍后再配置" in html or "跳过设置" in html
        # Must not only hide via localStorage
        assert "setup-wizard" in html


class TestOnboardingConfigRoundTrip:
    def test_save_and_reload_skipped_status(self, tmp_path: Path) -> None:
        from js.config import JSSettings, SecurityConfig

        cfg_path = tmp_path / "config.yaml"
        s = JSSettings(
            workspace=tmp_path / "ws",
            state_dir=tmp_path / "st",
            first_run_completed=False,
            onboarding_status="pending",
            security=SecurityConfig(api_key_required=False),
        )
        s.onboarding_status = "skipped"
        s.first_run_completed = True
        s.save(cfg_path, fields=["onboarding_status", "first_run_completed"])

        loaded = JSSettings.from_file(cfg_path)
        assert loaded.onboarding_status == "skipped"
        assert loaded.first_run_completed is True
        # Skip must not invent providers
        assert loaded.providers == [] or all(
            not (p.api_key and p.api_key not in ("", "YOUR_API_KEY")) for p in loaded.providers
        )
