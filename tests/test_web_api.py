"""Tests for FastAPI web endpoints (diagnostics, evolution, etc.)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from js.config import DefenseMode
from js.skills.promotion_store import PromotionStore
from js.skills.spec import TrustLevel
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
    mock_agent.settings.security.api_key_required = False
    mock_agent.registry.get_stats.return_value = {}
    mock_agent.secrets.get_stats.return_value = {"stored_secrets": 0, "detected_leaks": 0}

    # Evolution subsystems
    mock_agent.metacognition = MagicMock()
    mock_agent.metacognition.get_recent_reports.return_value = []
    mock_agent.metacognition.get_proposals.return_value = []
    mock_agent.metacognition.reflect.return_value = MagicMock(
        overall_health_score=0.9, proposals=[], actions_taken=[], timestamp="2024-01-01T00:00:00"
    )
    mock_agent.learner = MagicMock()
    mock_agent.learner.get_stats.return_value = {}
    mock_agent.learner.get_insights.return_value = []
    mock_agent.learner.suggest_improvements.return_value = []
    mock_agent.optimizer = MagicMock()
    mock_agent.optimizer.get_report.return_value = {}
    mock_agent.compression_feedback = MagicMock()
    mock_agent.compression_feedback.get_stats.return_value = {}
    mock_agent.evolver = MagicMock()
    mock_agent.evolver.should_evolve.return_value = False

    mock_agent._run_evolution_cycle = AsyncMock(
        return_value={
            "profile_update": {"ok": True, "error": None},
            "dreaming": {"ok": True, "error": None},
            "skill_evolution": {"ok": True, "error": None, "evolved": []},
            "elapsed_seconds": 1.23,
        }
    )
    mock_agent._dream_scheduler = MagicMock()

    # Skills
    mock_skills = MagicMock()
    mock_skills.list_skills.return_value = []
    mock_skills.list_categories.return_value = []
    mock_skills.get_global_stats.return_value = {"skills_loaded": 0}
    mock_skills.view_skill.return_value = None
    mock_skills.get_all.return_value = {}
    mock_skills.apply_proposal = AsyncMock(
        return_value={"success": True, "event_id": "event-approve"}
    )
    mock_skills.revert_promotion.return_value = {
        "success": True,
        "event_id": "event-revert",
        "trust_reverted": True,
    }
    mock_agent.skills = mock_skills
    mock_agent.promotion_store = PromotionStore(mock_agent.settings.state_dir / "skill_promotions.db")

    # Router
    mock_router = MagicMock()
    mock_router.get_model_config.return_value = None
    mock_router.health_check.return_value = {"test": True}
    mock_agent.router = mock_router

    # Memory
    mock_memory = MagicMock()
    mock_memory.get_context_string.return_value = ""
    mock_memory.get_episodes.return_value = []
    mock_memory.get_dream_logs.return_value = []
    mock_memory.get_all_semantic.return_value = []
    mock_memory.get_all_working.return_value = []
    mock_memory.list_memory_files.return_value = []
    mock_memory.get_sessions.return_value = []
    mock_memory.get_audit_log.return_value = []
    mock_memory.cleanup_empty_sessions.return_value = 0
    mock_agent.memory = mock_memory

    mock_task_manager = MagicMock()
    mock_task_manager.list.return_value = []
    mock_task_manager.get.return_value = {"id": "task-1", "status": "running"}
    mock_task_manager.pause.return_value = True
    mock_task_manager.resume.return_value = True
    mock_task_manager.delete.return_value = True
    mock_agent.task_manager = mock_task_manager

    web_server._agent = mock_agent
    web_server._settings = mock_agent.settings

    from js.web.deps import set_globals

    set_globals(mock_agent, mock_agent.settings)
    app = create_app()

    # Create an admin API key so admin-only endpoints work in tests
    from js.web.auth import AuthManager

    auth_mgr = AuthManager(mock_agent.settings.state_dir)
    admin_key = auth_mgr.create_key("test-admin", role="admin")
    return TestClient(app, headers={"X-API-Key": admin_key})


@pytest.fixture
def user_client(client: TestClient) -> TestClient:
    """Return a client authenticated with a non-admin user key."""
    from js.web import server as web_server
    from js.web.auth import AuthManager

    mock_agent = web_server._agent
    auth_mgr = AuthManager(mock_agent.settings.state_dir)
    user_key = auth_mgr.create_key("test-user", role="user")
    return TestClient(client.app, headers={"X-API-Key": user_key})


class TestUserCannotModifyGlobalState:
    def test_user_cannot_update_provider(self, user_client: TestClient) -> None:
        resp = user_client.patch("/api/providers/test", json={"api_key": "leak"})
        assert resp.status_code == 403

    def test_user_cannot_delete_provider(self, user_client: TestClient) -> None:
        resp = user_client.delete("/api/providers/test")
        assert resp.status_code == 403

    def test_user_cannot_recover_embedder(self, user_client: TestClient) -> None:
        resp = user_client.post("/api/memory/embedder/recover")
        assert resp.status_code == 403

    def test_user_cannot_refresh_hermes(self, user_client: TestClient) -> None:
        resp = user_client.post("/api/skills/hermes/refresh")
        assert resp.status_code == 403

    def test_user_cannot_approve_skill_promotion(self, user_client: TestClient) -> None:
        resp = user_client.post("/api/skills/promotions/event-1/approve")
        assert resp.status_code == 403

    def test_user_cannot_reject_skill_promotion(self, user_client: TestClient) -> None:
        resp = user_client.post("/api/skills/promotions/event-1/reject", json={"reason": "no"})
        assert resp.status_code == 403

    def test_user_cannot_revert_skill_promotion(self, user_client: TestClient) -> None:
        resp = user_client.post("/api/skills/promotions/event-1/revert")
        assert resp.status_code == 403


class TestSkillPromotionAPI:
    def _seed_event(self, client: TestClient, *, skill_id: str = "api-skill") -> str:
        from js.web.auth import AuthManager, memory_owner

        auth = AuthManager(web_server._agent.settings.state_dir).verify(client.headers["X-API-Key"])
        owner = memory_owner(auth)
        store = web_server._agent.promotion_store
        return store.propose(
            skill_id,
            TrustLevel.COMMUNITY.value,
            TrustLevel.TRUSTED.value,
            "auto_curator",
            "20 runs / 95% success",
            owner_key_hash=owner,
        )

    def test_list_skill_promotions(self, client: TestClient) -> None:
        event_id = self._seed_event(client)

        resp = client.get("/api/skills/promotions")

        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["events"][0]["event_id"] == event_id
        assert data["events"][0]["skill_id"] == "api-skill"

    def test_show_skill_promotion(self, client: TestClient) -> None:
        event_id = self._seed_event(client)

        resp = client.get(f"/api/skills/promotions/{event_id}")

        assert resp.status_code == 200
        data = resp.json()
        assert data["event_id"] == event_id
        assert data["source"] == "auto_curator"
        assert data["reason"] == "20 runs / 95% success"

    def test_approve_skill_promotion_calls_manager(self, client: TestClient) -> None:
        resp = client.post("/api/skills/promotions/event-approve/approve")

        assert resp.status_code == 200
        assert resp.json()["success"] is True
        web_server._agent.skills.apply_proposal.assert_awaited_once()
        args = web_server._agent.skills.apply_proposal.await_args
        assert args.args == ("event-approve",)
        assert args.kwargs["decided_by"] == "web"
        assert args.kwargs["owner_key_hash"]

    def test_reject_skill_promotion_marks_event(self, client: TestClient) -> None:
        event_id = self._seed_event(client)

        resp = client.post(
            f"/api/skills/promotions/{event_id}/reject",
            json={"reason": "not safe enough"},
        )

        assert resp.status_code == 200
        assert resp.json()["success"] is True
        event = web_server._agent.promotion_store.get(event_id)
        if event is None:
            from js.web.auth import AuthManager, memory_owner

            auth = AuthManager(web_server._agent.settings.state_dir).verify(
                client.headers["X-API-Key"]
            )
            event = web_server._agent.promotion_store.get(
                event_id,
                owner_key_hash=memory_owner(auth),
            )
        assert event is not None
        assert event.status == "rejected"
        assert "not safe enough" in event.reason

    def test_revert_skill_promotion_calls_manager(self, client: TestClient) -> None:
        resp = client.post("/api/skills/promotions/event-revert/revert")

        assert resp.status_code == 200
        assert resp.json()["success"] is True
        web_server._agent.skills.revert_promotion.assert_called_once()
        args = web_server._agent.skills.revert_promotion.call_args
        assert args.args == ("event-revert",)
        assert args.kwargs["decided_by"] == "web"
        assert args.kwargs["owner_key_hash"]


class TestOriginRejection:
    def test_malicious_origin_rejected_for_state_methods(self, client: TestClient) -> None:
        endpoints = [
            ("post", "/api/chat", {"json": {"message": "hi"}}),
            ("post", "/api/cancel/sess-1", {}),
            ("post", "/api/upload", {}),
            ("delete", "/api/uploads/test.txt", {}),
            ("post", "/api/tasks/task-1/pause", {}),
            ("post", "/api/tasks/task-1/resume", {}),
            ("delete", "/api/tasks/task-1", {}),
            (
                "post",
                "/api/providers/connect",
                {"json": {"name": "x", "base_url": "http://x", "models": [{"id": "x"}]}},
            ),
            ("put", "/api/memory/semantic/1", {"json": {"value": "x"}}),
            ("patch", "/api/providers/test", {"json": {"api_key": "x"}}),
            ("delete", "/api/providers/test", {}),
        ]
        for method, path, kwargs in endpoints:
            resp = getattr(client, method)(
                path,
                headers={"Origin": "https://evil.example.com"},
                **kwargs,
            )
            assert resp.status_code == 403, (
                f"{method.upper()} {path} did not reject malicious Origin"
            )


class TestOptionalAuth:
    def test_bad_optional_api_key_returns_401(self, client: TestClient) -> None:
        bad_client = TestClient(client.app, headers={"X-API-Key": "bad-key"})
        resp = bad_client.get("/api/status")
        assert resp.status_code == 401


class TestOwnerPropagation:
    def test_memory_audit_passes_owner(self, client: TestClient) -> None:
        resp = client.get("/api/memory/audit")
        assert resp.status_code == 200
        kwargs = web_server._agent.memory.get_audit_log.call_args.kwargs
        assert kwargs["owner_key_hash"] is not None

    def test_task_state_methods_pass_owner(self, client: TestClient) -> None:
        resp = client.post("/api/tasks/task-1/pause")
        assert resp.status_code == 200
        pause_kwargs = web_server._agent.task_manager.pause.call_args.kwargs
        assert pause_kwargs["owner_key_hash"] is not None

        resp = client.post("/api/tasks/task-1/resume")
        assert resp.status_code == 200
        resume_kwargs = web_server._agent.task_manager.resume.call_args.kwargs
        assert resume_kwargs["owner_key_hash"] is not None

        resp = client.delete("/api/tasks/task-1")
        assert resp.status_code == 200
        delete_kwargs = web_server._agent.task_manager.delete.call_args.kwargs
        assert delete_kwargs["owner_key_hash"] is not None


class TestDiagEndpoint:
    def test_diag_returns_version_and_routes(self, client: TestClient) -> None:
        resp = client.get("/api/diag")
        assert resp.status_code == 200
        data = resp.json()
        assert "version" in data
        assert "routes" in data
        assert "subsystems" in data
        assert data["has_evolution_api"] is True
        routes = {r["path"] for r in data["routes"]}
        assert "/api/evolution/run" in routes

    def test_diag_subsystems_healthy(self, client: TestClient) -> None:
        resp = client.get("/api/diag")
        data = resp.json()
        subs = data["subsystems"]
        assert subs["metacognition"] is True
        assert subs["learner"] is True
        assert subs["optimizer"] is True
        assert subs["evolver"] is True


class TestEvolutionEndpoints:
    def test_evolution_run_success(self, client: TestClient) -> None:
        resp = client.post("/api/evolution/run")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "report" in data
        report = data["report"]
        assert report["profile_update"]["ok"] is True
        assert report["dreaming"]["ok"] is True
        assert report["elapsed_seconds"] == 1.23

    def test_evolution_reports(self, client: TestClient) -> None:
        resp = client.get("/api/evolution/reports?limit=5")
        assert resp.status_code == 200
        data = resp.json()
        assert "reports" in data

    def test_evolution_insights(self, client: TestClient) -> None:
        resp = client.get("/api/evolution/insights?limit=10")
        assert resp.status_code == 200
        data = resp.json()
        assert "learning" in data
        assert "optimization" in data

    def test_evolution_reflect(self, client: TestClient) -> None:
        resp = client.post("/api/evolution/reflect")
        assert resp.status_code == 200
        data = resp.json()
        assert "health_score" in data


class TestEvolutionRunErrors:
    def test_evolution_run_501_when_method_missing(self, tmp_path: Path) -> None:
        """If agent lacks _run_evolution_cycle, return 501."""
        mock_agent = MagicMock()
        mock_agent.settings.workspace = tmp_path / "workspace"
        mock_agent.settings.state_dir = tmp_path / "state"
        mock_agent.settings.max_turns = 10
        mock_agent.settings.security.defense_mode = DefenseMode.ENFORCE
        mock_agent.settings.security.api_key_required = False
        mock_agent.registry.get_stats.return_value = {}
        mock_agent.secrets.get_stats.return_value = {"stored_secrets": 0, "detected_leaks": 0}
        mock_agent.metacognition = MagicMock()
        mock_agent.learner = MagicMock()
        mock_agent.optimizer = MagicMock()
        mock_agent.evolver = MagicMock()
        # Deliberately omit _run_evolution_cycle
        if hasattr(mock_agent, "_run_evolution_cycle"):
            delattr(mock_agent, "_run_evolution_cycle")

        mock_memory = MagicMock()
        mock_memory.cleanup_empty_sessions.return_value = 0
        mock_agent.memory = mock_memory

        web_server._agent = mock_agent
        web_server._settings = mock_agent.settings

        from js.web.deps import set_globals

        set_globals(mock_agent, mock_agent.settings)
        app = create_app()

        from js.web.auth import AuthManager

        auth_mgr = AuthManager(mock_agent.settings.state_dir)
        admin_key = auth_mgr.create_key("test-admin", role="admin")
        client = TestClient(app, headers={"X-API-Key": admin_key})
        resp = client.post("/api/evolution/run")
        assert resp.status_code == 501
        assert "restart" in resp.json()["detail"].lower()

    def test_evolution_run_503_when_subsystem_missing(self, tmp_path: Path) -> None:
        """If a required subsystem is None, return 503."""
        mock_agent = MagicMock()
        mock_agent.settings.workspace = tmp_path / "workspace"
        mock_agent.settings.state_dir = tmp_path / "state"
        mock_agent.settings.max_turns = 10
        mock_agent.settings.security.defense_mode = DefenseMode.ENFORCE
        mock_agent.settings.security.api_key_required = False
        mock_agent.registry.get_stats.return_value = {}
        mock_agent.secrets.get_stats.return_value = {"stored_secrets": 0, "detected_leaks": 0}
        mock_agent.metacognition = None
        mock_agent.learner = MagicMock()
        mock_agent.optimizer = MagicMock()
        mock_agent.evolver = MagicMock()
        mock_agent._run_evolution_cycle = AsyncMock(return_value={})

        mock_memory = MagicMock()
        mock_memory.cleanup_empty_sessions.return_value = 0
        mock_agent.memory = mock_memory

        web_server._agent = mock_agent
        web_server._settings = mock_agent.settings

        from js.web.deps import set_globals

        set_globals(mock_agent, mock_agent.settings)
        app = create_app()

        from js.web.auth import AuthManager

        auth_mgr = AuthManager(mock_agent.settings.state_dir)
        admin_key = auth_mgr.create_key("test-admin", role="admin")
        client = TestClient(app, headers={"X-API-Key": admin_key})
        resp = client.post("/api/evolution/run")
        assert resp.status_code == 503
        assert "metacognition" in resp.json()["detail"].lower()
