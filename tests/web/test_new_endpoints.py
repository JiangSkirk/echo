"""Tests for new web endpoints (setup wizard, model switch, memory CRUD)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from js.config import DefenseMode
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
