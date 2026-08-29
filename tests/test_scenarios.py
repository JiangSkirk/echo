"""Tests for scenario templates: loading, schema validation, API."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from js.scenarios.loader import load_builtin_scenarios
from js.scenarios.registry import ScenarioRegistry
from js.scenarios.schemas import Scenario, ScenarioRole
from js.web.server import create_app


class TestScenarioLoader:
    """Tests for builtin scenario loading."""

    def test_loads_all_builtin_scenarios(self) -> None:
        scenarios = load_builtin_scenarios()
        assert len(scenarios) >= 3
        ids = {s.id for s in scenarios}
        assert "code-review" in ids
        assert "research-report" in ids
        assert "personal-assistant" in ids

    def test_scenario_schema_valid(self) -> None:
        scenarios = load_builtin_scenarios()
        for s in scenarios:
            assert s.id
            assert s.name
            assert s.description
            assert s.roles
            assert s.default_mode in ("auto", "debate", "sequential", "manager")
            for r in s.roles:
                assert r.role
                assert r.name

    def test_to_dict_structure(self) -> None:
        scenarios = load_builtin_scenarios()
        for s in scenarios:
            d = s.to_dict()
            assert "id" in d
            assert "name" in d
            assert "roles" in d
            assert isinstance(d["roles"], list)
            assert "example_prompts" in d


class TestScenarioRegistry:
    """Tests for scenario registry."""

    def test_register_and_get(self) -> None:
        reg = ScenarioRegistry()
        s = Scenario(
            id="test",
            name="Test",
            description="desc",
            icon="fa-test",
            roles=[ScenarioRole(role="worker", name="Worker", description="Works")],
            default_mode="auto",
            suggested_skills=[],
        )
        reg.register(s)
        assert reg.get("test") == s
        assert reg.get("missing") is None

    def test_list_all(self) -> None:
        reg = ScenarioRegistry(load_builtin_scenarios())
        all_scenarios = reg.list_all()
        assert len(all_scenarios) >= 3


class TestScenarioGoalTemplate:
    def test_instantiate_creates_owner_scoped_goal(self, tmp_path: Path) -> None:
        from js.bots.store import BotStore
        from js.scenarios.instantiate import instantiate_scenario

        scenario = load_builtin_scenarios()[0]
        created = instantiate_scenario(
            scenario,
            owner_key_hash="owner-a",
            state_dir=tmp_path,
        )
        store = BotStore(tmp_path)
        goals = store.list_goal_runs(owner_key_hash="owner-a")
        assert [item.id for item in goals] == [created["goal_id"]]
        assert store.list_goal_runs(owner_key_hash="owner-b") == []


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    from js.web import server as web_server
    from js.web.deps import set_globals

    mock_agent = MagicMock()
    mock_agent.settings.workspace = tmp_path / "workspace"
    mock_agent.settings.state_dir = tmp_path / "state"
    mock_agent.settings.security.api_key_required = False
    mock_agent.skills.get.return_value = None

    web_server._agent = mock_agent
    web_server._settings = mock_agent.settings
    set_globals(mock_agent, mock_agent.settings)
    app = create_app()
    return TestClient(app)


class TestScenarioAPI:
    """Tests for scenario REST endpoints."""

    def test_list_scenarios(self, client: TestClient) -> None:
        res = client.get("/api/scenarios")
        assert res.status_code == 200
        data = res.json()
        assert "scenarios" in data
        assert len(data["scenarios"]) >= 3

    def test_get_scenario(self, client: TestClient) -> None:
        res = client.get("/api/scenarios/code-review")
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == "code-review"
        assert "roles" in data

    def test_get_missing_scenario(self, client: TestClient) -> None:
        res = client.get("/api/scenarios/nonexistent")
        assert res.status_code == 404

    def test_start_scenario(self, tmp_path: Path) -> None:
        from js.config import JSSettings
        from js.web.auth import AuthManager

        settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            first_run_completed=True,
            providers=[],
            models=[],
        )
        key = AuthManager(settings.state_dir).create_key("scenario-user", role="user")
        app = create_app(runtime_settings=settings)
        with TestClient(
            app,
            headers={"Host": "localhost", "Origin": "http://localhost", "X-API-Key": key},
        ) as client:
            res = client.post("/api/scenarios/code-review/start")
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["scenario_id"] == "code-review"
        assert "fleet_config" in data
        assert "example_prompts" in data
        assert data["goal_id"]
        assert data["room_id"]
        assert data["bot_ids"]
        assert data["goal"]["phase"] == "clarify"
