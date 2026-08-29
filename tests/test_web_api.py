"""Tests for FastAPI web endpoints (diagnostics, evolution, etc.)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from js.config import DefenseMode, ModelConfig, ModelProviderConfig
from js.models.providers import ChatMessage
from js.skills.promotion_store import PromotionStore
from js.skills.spec import TrustLevel
from js.tools.registry import ToolResult
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
    mock_agent.settings.product_id = "js-agent"
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
    mock_agent.promotion_store = PromotionStore(
        mock_agent.settings.state_dir / "skill_promotions.db"
    )

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

    upload_commits: dict[str, tuple[str, str, Any]] = {}
    upload_payloads: dict[str, tuple[str, dict[str, Any]]] = {}
    upload_results: dict[str, tuple[str, dict[str, Any]]] = {}
    upload_sequence = 0

    def stage_upload_commit(owner: str, session_id: str, writer: Any) -> str:
        nonlocal upload_sequence
        upload_sequence += 1
        reference = f"upload-commit-{upload_sequence}"
        upload_commits[reference] = (owner, session_id, writer)
        return reference

    def discard_upload_commit(
        reference: str,
        owner: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> None:
        assert not product_id or product_id == "js-agent"
        entry = upload_commits.get(reference)
        if entry is not None and entry[0] == owner and (not session_id or entry[1] == session_id):
            upload_commits.pop(reference, None)

    def stage_upload_payload(
        owner: str,
        payload: dict[str, Any],
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        nonlocal upload_sequence
        assert product_id == "js-agent"
        assert session_id
        upload_sequence += 1
        reference = f"upload-payload-{upload_sequence}"
        upload_payloads[reference] = (owner, dict(payload))
        return reference

    def discard_upload_payload(
        reference: str,
        owner: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> None:
        assert product_id == "js-agent"
        assert session_id
        entry = upload_payloads.get(reference)
        if entry is not None and entry[0] == owner:
            upload_payloads.pop(reference, None)

    def take_upload_result(
        reference: str,
        owner: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any] | None:
        assert product_id == "js-agent"
        assert session_id
        entry = upload_results.get(reference)
        if entry is None or entry[0] != owner:
            return None
        upload_results.pop(reference, None)
        return dict(entry[1])

    async def execute_upload_effect(effect: Any, _context: Any) -> tuple[Any, ToolResult]:
        assert effect.tool_name == "control_upload_mutate"
        arguments = json.loads(effect.arguments_json)
        payload_ref = arguments["payload_ref"]
        if arguments["action"] == "commit":
            owner, _session_id, writer = upload_commits.pop(payload_ref)
            target = writer.commit()
            response = {
                "saved_as": target.name,
                "path": target.relative_to(mock_agent.settings.workspace).as_posix(),
                "size": writer.bytes_written,
            }
            result_ref = f"upload-result-{payload_ref}"
            upload_results[result_ref] = (owner, response)
            result = ToolResult(
                success=True,
                output="Upload commit completed",
                metadata={"result_ref": result_ref},
            )
        else:
            from js.echo.attachment_gate import delete_owned_upload_by_name

            owner, payload = upload_payloads.pop(payload_ref)
            deleted = delete_owned_upload_by_name(
                mock_agent.settings.workspace,
                owner,
                payload["filename"],
                payload["session_id"],
            )
            result = (
                ToolResult(success=True, output="Upload deletion completed")
                if deleted
                else ToolResult(
                    success=False,
                    error="File not found",
                    metadata={"status_code": 404},
                )
            )
        return (
            ChatMessage(role="tool", content=result.output, name=effect.tool_name),
            result,
        )

    mock_agent.stage_upload_commit = MagicMock(side_effect=stage_upload_commit)
    mock_agent.discard_upload_commit = MagicMock(side_effect=discard_upload_commit)
    mock_agent.stage_upload_mutation_payload = MagicMock(side_effect=stage_upload_payload)
    mock_agent.discard_upload_mutation_payload = MagicMock(side_effect=discard_upload_payload)
    mock_agent.take_upload_mutation_result = MagicMock(side_effect=take_upload_result)
    mock_agent.echo_runtime.execute_tool_effect = AsyncMock(side_effect=execute_upload_effect)

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
    @pytest.mark.parametrize(
        "endpoint",
        [
            "/api/stats/tokens",
            "/api/evolution/reports",
            "/api/evolution/proposals",
            "/api/evolution/insights",
        ],
    )
    def test_user_cannot_read_global_learning_or_usage_state(
        self,
        user_client: TestClient,
        endpoint: str,
    ) -> None:
        resp = user_client.get(endpoint)
        assert resp.status_code == 403

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

    def test_user_cannot_approve_evolution_proposal(self, user_client: TestClient) -> None:
        resp = user_client.post("/api/evolution/proposals/p1/approve")
        assert resp.status_code == 403

    def test_user_cannot_reject_evolution_proposal(self, user_client: TestClient) -> None:
        resp = user_client.post("/api/evolution/proposals/p1/reject")
        assert resp.status_code == 403

    def test_user_cannot_read_audit_log(self, user_client: TestClient) -> None:
        resp = user_client.get("/api/audit")
        assert resp.status_code == 403


def test_file_list_api_executes_through_echo_tool_effect(client: TestClient) -> None:
    agent = web_server._agent
    agent.registry.get_handler.side_effect = AssertionError("raw registry bypass")
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="[]", name="file_list"),
            ToolResult(success=True, output="[]"),
        )
    )

    response = client.get("/api/files", params={"path": "."})

    assert response.status_code == 200
    assert response.json()["success"] is True
    agent.echo_runtime.build_context.assert_called_once()
    agent.echo_runtime.execute_tool_effect.assert_awaited_once()
    agent.registry.get_handler.assert_not_called()


def test_search_api_executes_through_echo_tool_effect_and_preserves_shape(
    client: TestClient,
) -> None:
    agent = web_server._agent
    agent.search.search = AsyncMock(side_effect=AssertionError("raw search bypass"))
    runtime_context = MagicMock(capabilities=("web_search",))
    agent.echo_runtime.build_context.return_value = runtime_context
    structured_results = [
        {
            "title": "Echo result",
            "url": "https://example.com/echo",
            "snippet": "Leased search result",
            "source": "test",
        }
    ]
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="result", name="web_search"),
            ToolResult(success=True, output="result", metadata={"results": structured_results}),
        )
    )

    response = client.get("/api/search", params={"query": "echo", "max_results": 3})

    assert response.status_code == 200
    assert response.json() == {"results": structured_results}
    agent.search.search.assert_not_awaited()
    agent.echo_runtime.build_context.assert_called_once()
    agent.echo_runtime.execute_tool_effect.assert_awaited_once()
    effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert effect.tool_name == "web_search"
    assert effect.arguments_json == '{"max_results":3,"query":"echo"}'
    assert effect.allowed_tools == ("web_search",)
    assert context is runtime_context


def test_skill_install_api_executes_internal_echo_effect(client: TestClient) -> None:
    agent = web_server._agent
    agent.skills.install = AsyncMock(side_effect=AssertionError("raw skill install bypass"))
    runtime_context = MagicMock(capabilities=("control_skill_install",))
    agent.echo_runtime.build_context.return_value = runtime_context
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="installed", name="control_skill_install"),
            ToolResult(
                success=True,
                output="installed",
                metadata={
                    "skill_id": "new-skill",
                    "trust_level": "community",
                    "risk_flags": ["network"],
                },
            ),
        )
    )

    response = client.post(
        "/api/skills/install",
        json={"source": "https://github.com/example/new-skill.git", "skill_id": "new-skill"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "success": True,
        "skill_id": "new-skill",
        "trust_level": "community",
        "risk_flags": ["network"],
    }
    agent.skills.install.assert_not_awaited()
    agent.echo_runtime.execute_tool_effect.assert_awaited_once()
    effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert effect.tool_name == "control_skill_install"
    assert effect.allowed_tools == ("control_skill_install",)
    assert context is runtime_context


def test_skill_discover_api_executes_internal_echo_effect(client: TestClient) -> None:
    agent = web_server._agent
    agent._clawhub = MagicMock()
    agent._clawhub.fetch_index = AsyncMock(side_effect=AssertionError("raw ClawHub bypass"))
    runtime_context = MagicMock(capabilities=("control_clawhub_discover",))
    agent.echo_runtime.build_context.return_value = runtime_context
    results = [{"id": "example:skill", "name": "Example"}]
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="discovered", name="control_clawhub_discover"),
            ToolResult(
                success=True,
                output="discovered",
                metadata={"total": 1, "results": results},
            ),
        )
    )

    response = client.get("/api/skills/discover", params={"query": "example"})

    assert response.status_code == 200
    assert response.json() == {"success": True, "total": 1, "results": results}
    agent._clawhub.fetch_index.assert_not_awaited()
    agent.echo_runtime.execute_tool_effect.assert_awaited_once()
    effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert effect.tool_name == "control_clawhub_discover"
    assert effect.arguments_json == '{"query":"example"}'
    assert effect.allowed_tools == ("control_clawhub_discover",)
    assert context is runtime_context


def test_skill_discover_install_api_executes_internal_echo_effect(client: TestClient) -> None:
    agent = web_server._agent
    agent._clawhub = MagicMock()
    agent._clawhub.get_skill_source.side_effect = AssertionError("raw ClawHub source bypass")
    agent.skills.install = AsyncMock(side_effect=AssertionError("raw skill install bypass"))
    runtime_context = MagicMock(capabilities=("control_clawhub_install",))
    agent.echo_runtime.build_context.return_value = runtime_context
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="installed", name="control_clawhub_install"),
            ToolResult(
                success=True,
                output="installed",
                metadata={"skill_id": "example:skill", "trust_level": "community"},
            ),
        )
    )

    response = client.post(
        "/api/skills/discover/install",
        json={"skill_id": "example:skill"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "success": True,
        "skill_id": "example:skill",
        "trust_level": "community",
    }
    agent._clawhub.get_skill_source.assert_not_called()
    agent.skills.install.assert_not_awaited()
    agent.echo_runtime.execute_tool_effect.assert_awaited_once()
    effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert effect.tool_name == "control_clawhub_install"
    assert effect.arguments_json == '{"skill_id":"example:skill"}'
    assert effect.allowed_tools == ("control_clawhub_install",)
    assert context is runtime_context


def test_provider_discovery_executes_hidden_echo_effect_without_logging_api_key(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = web_server._agent
    direct_discover = AsyncMock(side_effect=AssertionError("raw provider discovery bypass"))
    monkeypatch.setattr(
        "js.models.provider_manager.ProviderManager.discover_models",
        direct_discover,
    )
    agent.stage_provider_discovery_key.return_value = "provider-key-ref"
    runtime_context = MagicMock(capabilities=("control_provider_discover",))
    agent.echo_runtime.build_context.return_value = runtime_context
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="discovered", name="control_provider_discover"),
            ToolResult(
                success=True,
                output="discovered",
                metadata={"models": [{"id": "model-a", "name": "Model A"}]},
            ),
        )
    )

    response = client.post(
        "/api/providers/discover",
        json={"base_url": "https://models.example/v1", "api_key": "super-secret-key"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "base_url": "https://models.example/v1",
        "models": [{"id": "model-a", "name": "Model A"}],
    }
    direct_discover.assert_not_awaited()
    agent.stage_provider_discovery_key.assert_called_once()
    stage_call = agent.stage_provider_discovery_key.call_args
    assert stage_call.args == ("super-secret-key",)
    assert stage_call.kwargs["owner_key_hash"]
    assert stage_call.kwargs["product_id"] == "js-agent"
    assert stage_call.kwargs["session_id"].startswith("provider-discovery-")
    agent.discard_provider_discovery_key.assert_called_once_with(
        "provider-key-ref",
        **stage_call.kwargs,
    )
    agent.echo_runtime.execute_tool_effect.assert_awaited_once()
    effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert effect.tool_name == "control_provider_discover"
    assert effect.allowed_tools == ("control_provider_discover",)
    assert "super-secret-key" not in effect.arguments_json
    assert "provider-key-ref" in effect.arguments_json
    agent.echo_runtime.build_context.assert_called_once()
    assert (
        agent.echo_runtime.build_context.call_args.kwargs["session_id"]
        == stage_call.kwargs["session_id"]
    )
    assert context is runtime_context


def test_fleet_config_executes_hidden_echo_effect_before_publishing_state(
    client: TestClient,
) -> None:
    agent = web_server._agent
    agent.settings.providers = [
        ModelProviderConfig(
            name="mock",
            base_url="https://models.example/v1",
            models=[ModelConfig(id="model-a", provider="mock")],
        )
    ]
    runtime_context = MagicMock(capabilities=("control_fleet_configure",))
    agent.echo_runtime.build_context.return_value = runtime_context
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="saved", name="control_fleet_configure"),
            ToolResult(success=True, output="saved", metadata={}),
        )
    )

    response = client.post(
        "/api/agents/config",
        json={"config": {"worker": "mock/model-a"}},
    )

    assert response.status_code == 200
    assert response.json()["config"]["worker"] == "mock/model-a"
    effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert effect.tool_name == "control_fleet_configure"
    assert effect.allowed_tools == ("control_fleet_configure",)
    assert effect.arguments_json == ('{"config":{"reviewer":"","worker":"mock/model-a"}}')
    assert context is runtime_context


def test_fleet_config_failure_preserves_published_state(client: TestClient) -> None:
    agent = web_server._agent
    agent.settings.providers = [
        ModelProviderConfig(
            name="mock",
            base_url="https://models.example/v1",
            models=[ModelConfig(id="model-a", provider="mock")],
        )
    ]
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="failed", name="control_fleet_configure"),
            ToolResult(
                success=False,
                error="Fleet configuration failed",
                metadata={"status_code": 503},
            ),
        )
    )

    response = client.post(
        "/api/agents/config",
        json={"config": {"worker": "mock/model-a"}},
    )

    assert response.status_code == 503
    assert client.app.state.agent_config_state.config["worker"] == ""


def test_provider_delete_rolls_back_fleet_config_when_provider_effect_fails(
    client: TestClient,
) -> None:
    agent = web_server._agent
    agent.stage_provider_discovery_key.return_value = "provider-key-ref"
    client.app.state.agent_config_state.config["worker"] = "mock/model-a"
    fleet_success = (
        ChatMessage(role="tool", content="saved", name="control_fleet_configure"),
        ToolResult(success=True, output="saved", metadata={}),
    )
    provider_failure = (
        ChatMessage(role="tool", content="failed", name="control_provider_mutate"),
        ToolResult(
            success=False,
            error="Provider could not be removed safely",
            metadata={"status_code": 500},
        ),
    )
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        side_effect=[fleet_success, provider_failure, fleet_success]
    )

    response = client.delete("/api/providers/mock")

    assert response.status_code == 500
    assert client.app.state.agent_config_state.config["worker"] == "mock/model-a"
    effects = [call.args[0] for call in agent.echo_runtime.execute_tool_effect.await_args_list]
    assert [effect.tool_name for effect in effects] == [
        "control_fleet_configure",
        "control_provider_mutate",
        "control_fleet_configure",
    ]
    assert '"worker":""' in effects[0].arguments_json
    assert '"worker":"mock/model-a"' in effects[2].arguments_json


@pytest.mark.parametrize(
    ("endpoint", "expected_status"),
    [
        ("/api/providers/test-cloud", 200),
        ("/api/providers/add-cloud", 200),
    ],
)
def test_cloud_provider_network_probe_uses_echo_control_effect(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str,
    expected_status: int,
) -> None:
    agent = web_server._agent
    direct_discover = AsyncMock(side_effect=AssertionError("raw cloud discovery bypass"))
    monkeypatch.setattr(
        "js.models.provider_manager.ProviderManager.discover_models",
        direct_discover,
    )
    agent.stage_provider_discovery_key.return_value = "cloud-key-ref"
    agent.settings.providers = []
    agent.provider_manager.get_all.return_value = []
    runtime_context = MagicMock(capabilities=("control_provider_discover",))
    agent.echo_runtime.build_context.return_value = runtime_context
    discovery_response = (
        ChatMessage(role="tool", content="discovered", name="control_provider_discover"),
        ToolResult(
            success=True,
            output="discovered",
            metadata={"models": [{"id": "deepseek-v4-pro", "name": "DeepSeek V4 Pro"}]},
        ),
    )
    mutation_response = (
        ChatMessage(role="tool", content="saved", name="control_provider_mutate"),
        ToolResult(
            success=True,
            output="saved",
            metadata={"provider": "deepseek", "models_added": 1},
        ),
    )
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        side_effect=(
            [discovery_response, mutation_response]
            if endpoint.endswith("/add-cloud")
            else [discovery_response]
        )
    )

    response = client.post(
        endpoint,
        json={"preset_id": "deepseek", "api_key": "cloud-super-secret"},
    )

    assert response.status_code == expected_status
    direct_discover.assert_not_awaited()
    expected_calls = 2 if endpoint.endswith("/add-cloud") else 1
    assert agent.stage_provider_discovery_key.call_count == expected_calls
    assert agent.discard_provider_discovery_key.call_count == expected_calls
    assert agent.echo_runtime.execute_tool_effect.await_count == expected_calls
    effects = [call.args[0] for call in agent.echo_runtime.execute_tool_effect.await_args_list]
    assert effects[0].tool_name == "control_provider_discover"
    assert all("cloud-super-secret" not in effect.arguments_json for effect in effects)
    if endpoint.endswith("/add-cloud"):
        assert effects[1].tool_name == "control_provider_mutate"
        assert "cloud-key-ref" in effects[1].arguments_json


def test_desktop_wizard_action_uses_echo_effect_not_raw_action(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Admin wizard actions must enter through Echo's leased tool boundary."""
    from js.tools.desktop import wizard

    raw_action = MagicMock(side_effect=AssertionError("raw wizard action bypass"))
    monkeypatch.setattr(wizard, "execute_action", raw_action)
    monkeypatch.setattr(
        wizard,
        "run_wizard",
        lambda: MagicMock(ready=False, overall_status="missing_deps", steps=[]),
    )
    agent = web_server._agent
    runtime_context = MagicMock(capabilities=("desktop_wizard_action",))
    agent.echo_runtime.build_context.return_value = runtime_context
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="{}", name="desktop_wizard_action"),
            ToolResult(success=True, output=json.dumps({"success": True, "message": "queued"})),
        )
    )

    response = client.post("/api/desktop/wizard/action", json={"action_type": "install"})

    assert response.status_code == 200
    assert response.json()["success"] is True
    raw_action.assert_not_called()
    agent.approvals.request_decision.assert_not_called()
    agent.echo_runtime.build_context.assert_called_once()
    agent.echo_runtime.execute_tool_effect.assert_awaited_once()
    effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert effect.tool_name == "desktop_wizard_action"
    assert effect.arguments_json == '{"action_type":"install"}'
    assert effect.allowed_tools == ("desktop_wizard_action",)
    assert context is runtime_context
    assert context.capabilities == ("desktop_wizard_action",)


def test_desktop_wizard_action_rejects_unregistered_action(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the fixed desktop wizard action allowlist may enter the runtime."""
    from js.tools.desktop import wizard

    raw_action = MagicMock(side_effect=AssertionError("raw wizard action bypass"))
    monkeypatch.setattr(wizard, "execute_action", raw_action)
    agent = web_server._agent

    response = client.post("/api/desktop/wizard/action", json={"action_type": "shell"})

    assert response.status_code == 200
    assert response.json()["success"] is False
    raw_action.assert_not_called()
    agent.echo_runtime.execute_tool_effect.assert_not_called()


def test_desktop_wizard_action_rejects_non_string_action(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Malformed action values must not escape the fixed action allowlist."""
    from js.tools.desktop import wizard

    raw_action = MagicMock(side_effect=AssertionError("raw wizard action bypass"))
    monkeypatch.setattr(wizard, "execute_action", raw_action)
    agent = web_server._agent

    response = client.post("/api/desktop/wizard/action", json={"action_type": ["install"]})

    assert response.status_code == 422
    raw_action.assert_not_called()
    agent.echo_runtime.execute_tool_effect.assert_not_called()


def test_desktop_toggle_uses_echo_control_effect_not_raw_mutation(
    client: TestClient,
) -> None:
    agent = web_server._agent
    agent.settings.desktop_control_enabled = False
    agent.settings.save = MagicMock(side_effect=AssertionError("raw settings bypass"))
    runtime_context = MagicMock(capabilities=("control_desktop_state",))
    agent.echo_runtime.build_context.return_value = runtime_context
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="enabled", name="control_desktop_state"),
            ToolResult(
                success=True,
                output="enabled",
                metadata={"enabled": True, "stage": "read_only", "tools_count": 7},
            ),
        )
    )

    response = client.post("/api/desktop/toggle")

    assert response.status_code == 200
    assert response.json()["enabled"] is True
    assert response.json()["stage"] == "read_only"
    agent.settings.save.assert_not_called()
    effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert effect.tool_name == "control_desktop_state"
    assert effect.arguments_json == '{"action":"toggle"}'
    assert effect.allowed_tools == ("control_desktop_state",)
    assert context is runtime_context


def test_cancel_session_uses_echo_control_effect_not_raw_cancel(
    client: TestClient,
) -> None:
    agent = web_server._agent
    agent.request_cancel = MagicMock(side_effect=AssertionError("raw cancel bypass"))
    runtime_context = MagicMock(capabilities=("control_session_mutate",))
    agent.echo_runtime.build_context.return_value = runtime_context
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="cancelled", name="control_session_mutate"),
            ToolResult(
                success=True,
                output="cancelled",
                metadata={"session_id": "sess-1", "cancelled": True},
            ),
        )
    )

    response = client.post("/api/cancel/sess-1")

    assert response.status_code == 200
    assert response.json() == {"session_id": "sess-1", "cancelled": True}
    agent.request_cancel.assert_not_called()
    effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert effect.tool_name == "control_session_mutate"
    assert effect.arguments_json == '{"action":"cancel","session_id":"sess-1"}'
    assert effect.allowed_tools == ("control_session_mutate",)
    assert context is runtime_context


def test_delete_session_uses_echo_control_effect_not_raw_memory_delete(
    client: TestClient,
) -> None:
    agent = web_server._agent
    agent.memory.delete_session = MagicMock(side_effect=AssertionError("raw memory bypass"))
    runtime_context = MagicMock(capabilities=("control_session_mutate",))
    agent.echo_runtime.build_context.return_value = runtime_context
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="deleted", name="control_session_mutate"),
            ToolResult(
                success=True,
                output="deleted",
                metadata={"session_id": "sess-1", "deleted": True},
            ),
        )
    )

    response = client.delete("/api/sessions/sess-1")

    assert response.status_code == 200
    assert response.json() == {"success": True, "session_id": "sess-1"}
    agent.memory.delete_session.assert_not_called()
    effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert effect.tool_name == "control_session_mutate"
    assert effect.arguments_json == '{"action":"delete","session_id":"sess-1"}'
    assert effect.allowed_tools == ("control_session_mutate",)
    assert context is runtime_context


def test_memory_delete_uses_opaque_echo_control_effect_not_raw_store(
    client: TestClient,
) -> None:
    agent = web_server._agent
    agent.memory.delete_semantic = MagicMock(side_effect=AssertionError("raw memory bypass"))
    agent.stage_memory_mutation_payload.return_value = "memory-payload-ref"
    agent.take_memory_mutation_result.return_value = {"success": True}
    runtime_context = MagicMock(capabilities=("control_memory_mutate",))
    agent.echo_runtime.build_context.return_value = runtime_context
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="completed", name="control_memory_mutate"),
            ToolResult(
                success=True,
                output="completed",
                metadata={"result_ref": "memory-result-ref"},
            ),
        )
    )

    response = client.delete("/api/memory/semantic/7")

    assert response.status_code == 200
    assert response.json() == {"success": True}
    agent.memory.delete_semantic.assert_not_called()
    agent.stage_memory_mutation_payload.assert_called_once()
    staged_owner, staged_payload = agent.stage_memory_mutation_payload.call_args.args
    assert staged_owner
    assert staged_payload == {"memory_id": 7}
    effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert effect.tool_name == "control_memory_mutate"
    assert effect.arguments_json == (
        '{"action":"semantic_delete","payload_ref":"memory-payload-ref"}'
    )
    assert effect.allowed_tools == ("control_memory_mutate",)
    assert "memory_id" not in effect.arguments_json
    assert context is runtime_context
    agent.take_memory_mutation_result.assert_called_once_with(
        "memory-result-ref",
        staged_owner,
        product_id=runtime_context.product_id,
        session_id=runtime_context.session_id,
    )


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
        agent = web_server._agent
        agent.stage_skill_mutation_payload.return_value = "skill-payload-ref"
        agent.take_skill_mutation_result.return_value = {"success": True}

        async def execute_approve(effect, _context):
            owner, payload = agent.stage_skill_mutation_payload.call_args.args
            response = await agent.skills.apply_proposal(
                payload["event_id"],
                decided_by="web",
                owner_key_hash=owner,
            )
            assert response["success"] is True
            return (
                ChatMessage(role="tool", content="completed", name=effect.tool_name),
                ToolResult(
                    success=True,
                    output="completed",
                    metadata={"result_ref": "skill-result-ref"},
                ),
            )

        agent.echo_runtime.execute_tool_effect = AsyncMock(side_effect=execute_approve)
        resp = client.post("/api/skills/promotions/event-approve/approve")

        assert resp.status_code == 200
        assert resp.json()["success"] is True
        web_server._agent.skills.apply_proposal.assert_awaited_once()
        args = web_server._agent.skills.apply_proposal.await_args
        assert args.args == ("event-approve",)
        assert args.kwargs["decided_by"] == "web"
        assert args.kwargs["owner_key_hash"]
        effect, _context = agent.echo_runtime.execute_tool_effect.await_args.args
        assert effect.tool_name == "control_skill_mutate"
        assert effect.arguments_json == (
            '{"action":"promotion_approve","payload_ref":"skill-payload-ref"}'
        )

    def test_reject_skill_promotion_marks_event(self, client: TestClient) -> None:
        event_id = self._seed_event(client)
        agent = web_server._agent
        agent.stage_skill_mutation_payload.return_value = "skill-payload-ref"
        agent.take_skill_mutation_result.return_value = {
            "success": True,
            "event_id": event_id,
            "status": "rejected",
        }
        direct_reject = agent.promotion_store.mark_rejected

        async def execute_reject(effect, _context):
            owner, payload = agent.stage_skill_mutation_payload.call_args.args
            assert direct_reject(
                payload["event_id"],
                owner_key_hash=owner,
                decided_by="web",
                reason=payload["reason"],
            )
            return (
                ChatMessage(role="tool", content="completed", name=effect.tool_name),
                ToolResult(
                    success=True,
                    output="completed",
                    metadata={"result_ref": "skill-result-ref"},
                ),
            )

        agent.echo_runtime.execute_tool_effect = AsyncMock(side_effect=execute_reject)

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
        effect, _context = agent.echo_runtime.execute_tool_effect.await_args.args
        assert effect.tool_name == "control_skill_mutate"
        assert effect.arguments_json == (
            '{"action":"promotion_reject","payload_ref":"skill-payload-ref"}'
        )
        assert "not safe enough" not in effect.arguments_json
        agent.take_skill_mutation_result.assert_called_once_with(
            "skill-result-ref",
            agent.stage_skill_mutation_payload.call_args.args[0],
            product_id=agent.echo_runtime.build_context.return_value.product_id,
            session_id=agent.echo_runtime.build_context.return_value.session_id,
        )

    def test_revert_skill_promotion_calls_manager(self, client: TestClient) -> None:
        agent = web_server._agent
        agent.stage_skill_mutation_payload.return_value = "skill-payload-ref"
        agent.take_skill_mutation_result.return_value = {"success": True}

        async def execute_revert(effect, _context):
            owner, payload = agent.stage_skill_mutation_payload.call_args.args
            response = agent.skills.revert_promotion(
                payload["event_id"],
                decided_by="web",
                owner_key_hash=owner,
            )
            assert response["success"] is True
            return (
                ChatMessage(role="tool", content="completed", name=effect.tool_name),
                ToolResult(
                    success=True,
                    output="completed",
                    metadata={"result_ref": "skill-result-ref"},
                ),
            )

        agent.echo_runtime.execute_tool_effect = AsyncMock(side_effect=execute_revert)
        resp = client.post("/api/skills/promotions/event-revert/revert")

        assert resp.status_code == 200
        assert resp.json()["success"] is True
        web_server._agent.skills.revert_promotion.assert_called_once()
        args = web_server._agent.skills.revert_promotion.call_args
        assert args.args == ("event-revert",)
        assert args.kwargs["decided_by"] == "web"
        assert args.kwargs["owner_key_hash"]
        effect, _context = agent.echo_runtime.execute_tool_effect.await_args.args
        assert effect.tool_name == "control_skill_mutate"
        assert effect.arguments_json == (
            '{"action":"promotion_revert","payload_ref":"skill-payload-ref"}'
        )


class TestOriginRejection:
    def test_malicious_origin_rejected_for_state_methods(self, client: TestClient) -> None:
        endpoints = [
            ("post", "/api/chat", {"json": {"message": "hi"}}),
            ("post", "/api/cancel/sess-1", {}),
            ("post", "/api/upload", {}),
            ("delete", "/api/uploads/test.txt", {}),
            ("post", "/api/cron/jobs", {"json": {"cron_expr": "0 8 * * *"}}),
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


class TestUploadIsolation:
    def test_upload_commit_uses_opaque_echo_effect(
        self,
        client: TestClient,
    ) -> None:
        agent = web_server._agent
        private_name = "private-customer-name.txt"
        private_bytes = b"synthetic private attachment"
        agent.stage_upload_commit.side_effect = None
        agent.stage_upload_commit.return_value = "upload-payload-ref"
        agent.take_upload_mutation_result.side_effect = None
        agent.take_upload_mutation_result.return_value = {
            "saved_as": private_name,
            "path": "uploads/opaque/partition/private-customer-name.txt",
            "size": len(private_bytes),
        }
        runtime_context = MagicMock(capabilities=("control_upload_mutate",))
        agent.echo_runtime.build_context.return_value = runtime_context
        agent.echo_runtime.execute_tool_effect = AsyncMock(
            return_value=(
                ChatMessage(
                    role="tool",
                    content="Upload commit completed",
                    name="control_upload_mutate",
                ),
                ToolResult(
                    success=True,
                    output="Upload commit completed",
                    metadata={"result_ref": "upload-result-ref"},
                ),
            )
        )

        response = client.post(
            "/api/upload",
            data={"session_id": "upload-session"},
            files={"file": (private_name, private_bytes, "text/plain")},
        )

        assert response.status_code == 200
        agent.stage_upload_commit.assert_called_once()
        agent.echo_runtime.execute_tool_effect.assert_awaited_once()
        effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
        assert effect.tool_name == "control_upload_mutate"
        assert effect.arguments_json == ('{"action":"commit","payload_ref":"upload-payload-ref"}')
        assert private_name not in effect.arguments_json
        assert private_bytes.decode() not in effect.arguments_json
        assert effect.allowed_tools == ("control_upload_mutate",)
        assert context is runtime_context

    def test_upload_delete_uses_private_opaque_echo_effect(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        agent = web_server._agent
        private_name = "private-customer-name.txt"
        agent.stage_upload_mutation_payload.side_effect = None
        agent.stage_upload_mutation_payload.return_value = "delete-payload-ref"
        runtime_context = MagicMock(capabilities=("control_upload_mutate",))
        agent.echo_runtime.build_context.return_value = runtime_context
        agent.echo_runtime.execute_tool_effect = AsyncMock(
            return_value=(
                ChatMessage(
                    role="tool",
                    content="Upload deletion completed",
                    name="control_upload_mutate",
                ),
                ToolResult(success=True, output="Upload deletion completed"),
            )
        )
        monkeypatch.setattr(
            web_server,
            "delete_owned_upload_by_name",
            MagicMock(side_effect=AssertionError("raw upload deletion bypass")),
            raising=False,
        )

        response = client.delete(
            f"/api/uploads/{private_name}",
            params={"session_id": "upload-session"},
        )

        assert response.status_code == 200
        effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
        assert effect.tool_name == "control_upload_mutate"
        assert effect.arguments_json == ('{"action":"delete","payload_ref":"delete-payload-ref"}')
        assert private_name not in effect.arguments_json
        assert effect.allowed_tools == ("control_upload_mutate",)
        assert context is runtime_context

    def test_anonymous_upload_is_rejected_for_read_only_guest(self, client: TestClient) -> None:
        """Guests (no credentials, auth optional) must not mutate state.

        Previously the anonymous context was admin and could upload; the
        partition mapping it used is still covered by memory_owner below.
        """
        from js.web.auth import memory_owner

        # The anonymous partition mapping is unchanged: no random per-request hash.
        assert memory_owner({"name": "anonymous"}) is None

        anonymous = TestClient(
            client.app,
            base_url="http://localhost",
            headers={"Origin": "http://localhost"},
        )

        response = anonymous.post(
            "/api/upload",
            data={"session_id": "anonymous-upload-session"},
            files={"file": ("note.txt", b"anonymous fixture", "text/plain")},
        )

        assert response.status_code == 403

    def test_upload_list_preview_delete_are_owner_and_session_scoped(
        self, client: TestClient
    ) -> None:
        session_id = "upload-session-a"
        resp = client.post(
            "/api/upload",
            data={"session_id": session_id},
            files={"file": ("note.txt", b"owner secret", "text/plain")},
        )
        assert resp.status_code == 200
        upload_path = resp.json()["path"]

        assert upload_path.startswith("uploads/")
        own_list = client.get("/api/uploads", params={"session_id": session_id})
        assert own_list.status_code == 200
        assert [item["path"] for item in own_list.json()["files"]] == [upload_path]
        own_preview = client.get(
            "/api/file-preview",
            params={"path": upload_path, "session_id": session_id},
        )
        assert own_preview.status_code == 200
        assert own_preview.json()["content"] == "owner secret"

        assert client.get("/api/uploads").status_code == 400
        assert client.get("/api/file-preview", params={"path": upload_path}).status_code == 400
        assert (
            client.get("/api/uploads", params={"session_id": "upload-session-b"}).json()["files"]
            == []
        )
        assert (
            client.get(
                "/api/file-preview",
                params={"path": upload_path, "session_id": "upload-session-b"},
            ).status_code
            == 403
        )
        assert (
            client.delete(
                "/api/uploads/note.txt",
                params={"session_id": "upload-session-b"},
            ).status_code
            == 404
        )

        from js.web.auth import AuthManager

        other_key = AuthManager(web_server._agent.settings.state_dir).create_key(
            "other-user", role="user"
        )
        other = TestClient(client.app, headers={"X-API-Key": other_key})

        other_list = other.get("/api/uploads", params={"session_id": session_id})
        assert other_list.status_code == 200
        assert other_list.json()["files"] == []
        other_preview = other.get(
            "/api/file-preview",
            params={"path": upload_path, "session_id": session_id},
        )
        assert other_preview.status_code == 403
        other_delete = other.delete(
            "/api/uploads/note.txt",
            params={"session_id": session_id},
        )
        assert other_delete.status_code == 404

        deleted = client.delete(
            "/api/uploads/note.txt",
            params={"session_id": session_id},
        )
        assert deleted.status_code == 200

    def test_upload_requires_session_id(self, client: TestClient) -> None:
        response = client.post(
            "/api/upload",
            files={"file": ("note.txt", b"owner secret", "text/plain")},
        )

        assert response.status_code == 400
        assert "session_id is required" in response.text

    def test_upload_rejects_symlinked_owner_session_directory(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        from js.echo.attachment_gate import upload_dir
        from js.web.auth import AuthManager, memory_owner

        auth = AuthManager(web_server._agent.settings.state_dir).verify(client.headers["X-API-Key"])
        session_id = "symlink-session"
        scoped_dir = upload_dir(
            web_server._agent.settings.workspace,
            memory_owner(auth),
            session_id,
        )
        scoped_dir.parent.mkdir(parents=True)
        outside = tmp_path / "upload-escape"
        outside.mkdir()
        scoped_dir.symlink_to(outside, target_is_directory=True)

        response = client.post(
            "/api/upload",
            data={"session_id": session_id},
            files={"file": ("escape.txt", b"must-not-escape", "text/plain")},
        )

        assert response.status_code == 409
        assert list(outside.iterdir()) == []

    def test_chat_rejects_cross_owner_upload_attachment(self, client: TestClient) -> None:
        session_id = "owner-session"
        resp = client.post(
            "/api/upload",
            data={"session_id": session_id},
            files={"file": ("note.txt", b"owner secret", "text/plain")},
        )
        assert resp.status_code == 200
        upload_path = resp.json()["path"]

        from js.web.auth import AuthManager

        other_key = AuthManager(web_server._agent.settings.state_dir).create_key(
            "other-chat-user", role="user"
        )
        other = TestClient(
            client.app,
            base_url="http://testserver",
            headers={"X-API-Key": other_key},
        )
        web_server._agent.run = AsyncMock()
        chat = other.post(
            "/api/chat",
            json={
                "message": "use attachment",
                "session_id": "other-session",
                "attachments": [upload_path],
            },
        )
        assert chat.status_code == 403
        assert web_server._agent.run.await_count == 0


class TestOwnerPropagation:
    def test_memory_audit_passes_owner(self, client: TestClient) -> None:
        resp = client.get("/api/memory/audit")
        assert resp.status_code == 200
        kwargs = web_server._agent.memory.get_audit_log.call_args.kwargs
        assert kwargs["owner_key_hash"] is not None

    def test_task_mutate_stays_read_only(
        self,
        client: TestClient,
    ) -> None:
        agent = web_server._agent
        agent.echo_runtime.execute_tool_effect = AsyncMock()
        assert client.post("/api/tasks/task-1/pause").status_code == 503
        assert client.post("/api/tasks/task-1/resume").status_code == 503
        assert client.delete("/api/tasks/task-1").status_code == 503
        agent.echo_runtime.execute_tool_effect.assert_not_called()


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
        agent = web_server._agent
        expected_report = {
            "profile_update": {"ok": True, "error": None},
            "dreaming": {"ok": True, "error": None},
            "skill_evolution": {"ok": True, "error": None, "evolved": []},
            "elapsed_seconds": 1.23,
        }
        agent.take_evolution_action_result.return_value = {
            "success": True,
            "message": "Evolution cycle completed",
            "report": expected_report,
        }
        agent.echo_runtime.execute_tool_effect = AsyncMock(
            return_value=(
                ChatMessage(role="tool", content="completed", name="control_evolution_action"),
                ToolResult(
                    success=True,
                    output="completed",
                    metadata={"result_ref": "evolution-result-ref"},
                ),
            )
        )
        resp = client.post("/api/evolution/run")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "report" in data
        report = data["report"]
        assert report["profile_update"]["ok"] is True
        assert report["dreaming"]["ok"] is True
        assert report["elapsed_seconds"] == 1.23
        assert report == expected_report
        agent._run_evolution_cycle.assert_not_awaited()
        effect, _context = agent.echo_runtime.execute_tool_effect.await_args.args
        assert effect.tool_name == "control_evolution_action"
        assert effect.arguments_json == '{"action":"run"}'

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
        agent = web_server._agent
        agent.take_evolution_action_result.return_value = {
            "health_score": 0.9,
            "proposals": 0,
            "actions_taken": 0,
            "timestamp": "2024-01-01T00:00:00",
        }
        agent.echo_runtime.execute_tool_effect = AsyncMock(
            return_value=(
                ChatMessage(role="tool", content="completed", name="control_evolution_action"),
                ToolResult(
                    success=True,
                    output="completed",
                    metadata={"result_ref": "evolution-result-ref"},
                ),
            )
        )
        resp = client.post("/api/evolution/reflect")
        assert resp.status_code == 200
        data = resp.json()
        assert "health_score" in data
        agent.metacognition.reflect.assert_not_called()

    def test_evolution_proposals_include_cycle_desk(self, client: TestClient) -> None:
        resp = client.get("/api/evolution/proposals")
        assert resp.status_code == 200
        data = resp.json()
        assert "proposals" in data
        assert data["cycle_proposals"] == []

    def test_evolution_approve_goes_through_echo(self, client: TestClient) -> None:
        agent = web_server._agent
        agent.take_evolution_action_result.return_value = {
            "proposal_id": "p1",
            "status": "applied",
            "owner": "admin",
        }
        agent.echo_runtime.execute_tool_effect = AsyncMock(
            return_value=(
                ChatMessage(role="tool", content="completed", name="control_evolution_action"),
                ToolResult(
                    success=True,
                    output="completed",
                    metadata={"result_ref": "evolution-result-ref"},
                ),
            )
        )
        resp = client.post("/api/evolution/proposals/p1/approve")
        assert resp.status_code == 200
        assert resp.json()["status"] == "applied"
        effect, _context = agent.echo_runtime.execute_tool_effect.await_args.args
        assert effect.tool_name == "control_evolution_action"
        assert effect.arguments_json == '{"action":"approve","proposal_id":"p1"}'

    @pytest.mark.parametrize("endpoint", ["/api/evolution/run", "/api/evolution/reflect"])
    def test_evolution_errors_do_not_expose_internal_exception(
        self,
        client: TestClient,
        endpoint: str,
    ) -> None:
        secret = "/Users/private/customer.xlsx secret-token"
        web_server._agent.echo_runtime.execute_tool_effect = AsyncMock(
            return_value=(
                ChatMessage(
                    role="tool",
                    content="Evolution action failed safely",
                    name="control_evolution_action",
                ),
                ToolResult(
                    success=False,
                    error="Evolution action failed safely",
                    metadata={"status_code": 500},
                ),
            )
        )

        resp = client.post(endpoint)

        assert resp.status_code == 500
        assert secret not in resp.text
        assert "/Users/private" not in resp.text
        if endpoint.endswith("/run"):
            web_server._agent._run_evolution_cycle.assert_not_awaited()
        else:
            web_server._agent.metacognition.reflect.assert_not_called()


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
