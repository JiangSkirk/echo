"""Tests for new web endpoints (setup wizard, model switch, memory CRUD)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from js.config import DefenseMode
from js.models.cloud_providers import DEEPSEEK_PRESET, build_provider_config
from js.web import server as web_server
from js.web.server import create_app


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    """Build a TestClient with a fully-mocked agent."""
    mock_agent = MagicMock()
    mock_agent.settings.workspace = tmp_path / "workspace"
    mock_agent.settings.state_dir = tmp_path / "state"
    mock_agent.settings.max_turns = 10
    mock_agent.settings.security.defense_mode = DefenseMode.ENFORCE
    mock_agent.settings.security.api_key_required = False
    mock_agent.settings.default_model = "test/model"
    mock_agent.settings.first_run_completed = False
    mock_provider = MagicMock()
    mock_provider.name = "test"
    mock_provider.base_url = "http://localhost:1234/v1"
    mock_model = MagicMock()
    mock_model.id = "model-a"
    mock_model.name = "Model A"
    mock_model.context_window = 4096
    mock_model.max_tokens = 2048
    mock_model.cost_input = 0.0
    mock_model.cost_output = 0.0
    mock_provider.models = [mock_model]
    mock_agent.settings.providers = [mock_provider]
    mock_agent.registry.get_stats.return_value = {}
    mock_agent.secrets.get_stats.return_value = {"stored_secrets": 0, "detected_leaks": 0}
    mock_agent.router.health_check = AsyncMock(return_value={"test": True})
    mock_agent.router.get_model_config.return_value = None
    mock_agent.router.add_provider = MagicMock()
    mock_agent.router.remove_provider = MagicMock()
    mock_agent.provider_manager.get_all.return_value = []
    mock_agent.provider_manager.add = MagicMock()
    mock_agent.provider_manager.remove = MagicMock()

    mock_memory = MagicMock()
    mock_memory.get_context_string.return_value = ""
    mock_memory.get_episodes.return_value = []
    mock_memory.get_dream_logs.return_value = []
    mock_memory.get_all_semantic.return_value = [
        MagicMock(id=1, key="k1", value="v1", category="fact", confidence=0.9, source="test"),
    ]
    mock_memory.get_all_working.return_value = []
    mock_memory.list_memory_files.return_value = []
    mock_memory.get_sessions.return_value = []
    mock_memory.cleanup_empty_sessions.return_value = 0
    mock_memory.delete_semantic.return_value = True
    mock_memory.update_semantic.return_value = True
    mock_agent.memory = mock_memory

    web_server._agent = mock_agent

    from js.web.deps import set_globals

    set_globals(mock_agent, mock_agent.settings)
    web_server._settings = mock_agent.settings
    web_server._active_model = ""
    app = create_app()
    return TestClient(app)


class TestSetupWizard:
    def test_first_start_returns_false_initially(self, client: TestClient) -> None:
        resp = client.get("/api/setup/first-start")
        assert resp.status_code == 200
        data = resp.json()
        assert data["first_run_completed"] is False

    def test_complete_first_start(self, client: TestClient) -> None:
        resp = client.post("/api/setup/complete")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True

        resp = client.get("/api/setup/first-start")
        assert resp.json()["first_run_completed"] is True


class TestModelSwitch:
    def test_models_returns_active_model(self, client: TestClient) -> None:
        resp = client.get("/api/models")
        assert resp.status_code == 200
        data = resp.json()
        assert "active_model" in data
        assert data["active_model"] == ""

    def test_switch_model_success(self, client: TestClient) -> None:
        resp = client.post("/api/models/switch", json={"model_id": "test/model-a"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["model_id"] == "test/model-a"

        resp = client.get("/api/models")
        assert resp.json()["active_model"] == "test/model-a"

    def test_switch_model_missing_id(self, client: TestClient) -> None:
        resp = client.post("/api/models/switch", json={})
        assert resp.status_code == 400

    def test_switch_model_invalid_id(self, client: TestClient) -> None:
        resp = client.post("/api/models/switch", json={"model_id": "invalid/model"})
        assert resp.status_code == 400

    def test_models_refreshes_lmstudio_models(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agent = web_server._agent
        agent.settings.providers[0].name = "lmstudio"
        agent.settings.providers[0].base_url = "http://127.0.0.1:1234/v1"

        discover = AsyncMock(
            return_value={
                "models": [
                    {"id": "loaded-model", "name": "Loaded Model"},
                ]
            }
        )
        monkeypatch.setattr(web_server.ProviderManager, "discover_models", discover)

        resp = client.get("/api/models")

        assert resp.status_code == 200
        data = resp.json()
        assert data["providers"][0]["models"][0]["id"] == "loaded-model"
        assert agent.settings.providers[0].default_model == "loaded-model"
        agent.router.add_provider.assert_called()


class TestProviderConnect:
    def test_connect_provider_sets_model_provider(self, client: TestClient) -> None:
        resp = client.post(
            "/api/providers/connect",
            json={
                "name": "custom",
                "base_url": "http://127.0.0.1:1234/v1",
                "api_key": "",
                "models": [{"id": "model-x", "name": "Model X"}],
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["provider"] == "custom"

        agent = web_server._agent
        saved_cfg = agent.provider_manager.add.call_args.args[0]
        assert saved_cfg.name == "custom"
        assert saved_cfg.models[0].id == "model-x"
        assert saved_cfg.models[0].provider == "custom"
        agent.router.add_provider.assert_called_once()

    def test_cloud_provider_preset_sets_model_provider(self) -> None:
        cfg = build_provider_config(DEEPSEEK_PRESET, "test-key")

        assert cfg.name == "deepseek"
        assert cfg.models
        assert all(model.provider == "deepseek" for model in cfg.models)


class TestMemorySemantic:
    def test_delete_semantic_memory(self, client: TestClient) -> None:
        resp = client.delete("/api/memory/semantic/1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True

    def test_update_semantic_memory(self, client: TestClient) -> None:
        resp = client.put("/api/memory/semantic/1", json={"value": "updated", "category": "insight"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True

    def test_update_semantic_memory_missing_value(self, client: TestClient) -> None:
        resp = client.put("/api/memory/semantic/1", json={"category": "insight"})
        assert resp.status_code == 400
