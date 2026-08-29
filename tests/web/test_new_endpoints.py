"""Tests for new web endpoints (setup wizard, model switch, memory CRUD)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from js.agent.tool_executor import CONTROL_MEMORY_MUTATE_TOOL, CONTROL_SETUP_STATE_TOOL
from js.config import DefenseMode, ModelConfig
from js.models.cloud_providers import DEEPSEEK_PRESET, build_provider_config
from js.models.providers import ChatMessage
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
    mock_agent.settings.security.api_key_required = False
    mock_agent.settings.default_model = "test/model"
    mock_agent.settings.product_id = "js-agent"
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
    setup_context = MagicMock(capabilities=(CONTROL_SETUP_STATE_TOOL,))
    setup_context.product_id = "js-agent"
    setup_context.session_id = "test-control"
    mock_agent.echo_runtime.build_context.return_value = setup_context
    mock_agent.take_setup_admin_key.return_value = None
    memory_payloads: dict[str, tuple[str, str, str, dict[str, Any]]] = {}
    memory_results: dict[str, tuple[str, str, str, dict[str, Any]]] = {}
    memory_sequence = 0

    def stage_memory_payload(
        owner: str,
        payload: dict[str, Any],
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        nonlocal memory_sequence
        assert product_id == "js-agent"
        assert session_id == "test-control"
        memory_sequence += 1
        reference = f"memory-payload-{memory_sequence}"
        memory_payloads[reference] = (owner, product_id, session_id, dict(payload))
        return reference

    def discard_memory_payload(
        reference: str,
        owner: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> None:
        entry = memory_payloads.get(reference)
        if entry is not None and entry[:3] == (owner, product_id, session_id):
            memory_payloads.pop(reference, None)

    def take_memory_result(
        reference: str,
        owner: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any] | None:
        entry = memory_results.get(reference)
        if entry is None or entry[:3] != (owner, product_id, session_id):
            return None
        memory_results.pop(reference, None)
        return dict(entry[3])

    mock_agent.stage_memory_mutation_payload = MagicMock(side_effect=stage_memory_payload)
    mock_agent.discard_memory_mutation_payload = MagicMock(side_effect=discard_memory_payload)
    mock_agent.take_memory_mutation_result = MagicMock(side_effect=take_memory_result)

    async def execute_control_effect(effect: Any, context: Any) -> tuple[Any, ToolResult]:
        arguments = json.loads(effect.arguments_json)
        if effect.tool_name == CONTROL_SETUP_STATE_TOOL:
            action = arguments["action"]
            mock_agent.settings.first_run_completed = action == "complete"
            return (
                ChatMessage(role="tool", content="updated", name=effect.tool_name),
                ToolResult(
                    success=True,
                    output="updated",
                    metadata={
                        "first_run_completed": mock_agent.settings.first_run_completed,
                    },
                ),
            )

        assert effect.tool_name == CONTROL_MEMORY_MUTATE_TOOL
        payload_ref = arguments["payload_ref"]
        owner, product_id, session_id, payload = memory_payloads.pop(payload_ref)
        assert product_id == context.product_id
        assert session_id == context.session_id
        action = arguments["action"]
        if action == "semantic_delete":
            assert mock_agent.memory.delete_semantic(
                payload["memory_id"], source="user", owner_key_hash=owner
            )
            response = {"success": True}
        elif action == "semantic_update":
            assert mock_agent.memory.update_semantic(
                payload["memory_id"],
                payload["value"],
                category=payload.get("category"),
                source="user",
                memory_path=payload.get("memory_path"),
                entity_type=payload.get("entity_type"),
                entity_name=payload.get("entity_name"),
                parent_id=payload.get("parent_id"),
                relation_type=payload.get("relation_type"),
                owner_key_hash=owner,
            )
            response = {"success": True}
        elif action == "organize":
            buffer = mock_agent._dream_scheduler.snapshot_buffer()
            if buffer:
                report = await mock_agent._extract_memories(buffer)
                response = {"success": True, "turns": len(buffer), **report}
            else:
                response = {
                    "success": True,
                    "turns": 0,
                    "proposed": 0,
                    "auto_applied": 0,
                    "pending": 0,
                    "skipped": "no recent conversation",
                }
        elif action == "proposal_approve":
            response = mock_agent.memory.approve_proposal(
                payload["proposal_id"],
                owner_key_hash=owner,
                overrides=payload.get("overrides"),
            )
        else:
            raise AssertionError(f"unsupported memory control action: {action}")
        result_ref = f"memory-result-{payload_ref}"
        memory_results[result_ref] = (
            owner,
            product_id,
            session_id,
            dict(response),
        )
        return (
            ChatMessage(role="tool", content="completed", name=effect.tool_name),
            ToolResult(
                success=True,
                output="completed",
                metadata={"result_ref": result_ref},
            ),
        )

    mock_agent.echo_runtime.execute_tool_effect = AsyncMock(side_effect=execute_control_effect)

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

    # Create an admin API key so admin-only endpoints work in tests
    from js.web.auth import AuthManager

    auth_mgr = AuthManager(mock_agent.settings.state_dir)
    admin_key = auth_mgr.create_key("test-admin", role="admin")

    return TestClient(app, headers={"X-API-Key": admin_key})


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

        agent = web_server._agent
        effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
        assert effect.tool_name == CONTROL_SETUP_STATE_TOOL
        assert effect.allowed_tools == (CONTROL_SETUP_STATE_TOOL,)
        assert context.capabilities == (CONTROL_SETUP_STATE_TOOL,)


class TestModelSwitch:
    def test_models_returns_active_model(self, client: TestClient) -> None:
        resp = client.get("/api/models")
        assert resp.status_code == 200
        data = resp.json()
        assert "active_model" in data
        assert data["active_model"] == ""

    def test_models_merges_only_configured_router_bindings(self, client: TestClient) -> None:
        """Dynamic router models are listed only for configured providers."""
        agent = web_server._agent
        dynamic = ModelConfig(
            id="dynamic-model",
            name="Dynamic Model",
            provider="test",
            context_window=8192,
        )
        leaked = ModelConfig(
            id="leaked-model",
            name="Leaked Model",
            provider="stale",
        )
        agent.router.get_model_bindings.return_value = (
            ("test", dynamic),
            ("stale", leaked),
        )

        resp = client.get("/api/models")
        assert resp.status_code == 200
        providers = resp.json()["providers"]
        test_provider = next(item for item in providers if item["name"] == "test")
        models = {item["id"]: item for item in test_provider["models"]}
        assert models["dynamic-model"]["name"] == "Dynamic Model"
        assert models["dynamic-model"]["provider"] == "test"
        assert all(item["name"] != "stale" for item in providers)
        assert "leaked-model" not in {
            model["id"] for provider in providers for model in provider["models"]
        }

    def test_switch_model_success(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        agent = web_server._agent
        runtime_context = MagicMock(capabilities=("control_model_switch",))
        agent.echo_runtime.build_context.return_value = runtime_context

        async def execute_model_switch(effect: Any, _context: Any) -> tuple[Any, ToolResult]:
            from js.web.deps import set_active_model

            set_active_model("test/model-a")
            return (
                ChatMessage(role="tool", content="switched", name=effect.tool_name),
                ToolResult(
                    success=True,
                    output="switched",
                    metadata={"model_id": "test/model-a"},
                ),
            )

        agent.echo_runtime.execute_tool_effect = AsyncMock(side_effect=execute_model_switch)
        monkeypatch.setattr(
            web_server,
            "_save_active_model",
            MagicMock(side_effect=AssertionError("raw active-model write bypass")),
        )
        resp = client.post("/api/models/switch", json={"model_id": "test/model-a"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["model_id"] == "test/model-a"

        resp = client.get("/api/models")
        assert resp.json()["active_model"] == "test/model-a"
        effect, context = agent.echo_runtime.execute_tool_effect.await_args.args
        assert effect.tool_name == "control_model_switch"
        assert effect.allowed_tools == ("control_model_switch",)
        assert effect.arguments_json == '{"model_id":"test/model-a"}'
        assert context is runtime_context

    def test_switch_model_rejects_unconfigured_preset_with_needs_config(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A preset model whose provider is not configured must NOT become active.

        The HTTP endpoint must return a structured client error (409) carrying
        ``needs_config=true`` and must not write ``active_model.txt``, change
        ``preferred_model``, or publish an active model.
        """
        agent = web_server._agent
        # Ensure no configured provider matches the preset we target.
        agent.settings.providers = []
        agent.router.preferred_model = ""
        agent.router.get_model_config.return_value = None

        # Give execute_tool_effect a normal success AsyncMock so the old
        # implementation can complete the effect and return 200 — the RED
        # must be on the target behaviour (409), not on a fixture assertion.
        runtime_context = MagicMock(capabilities=("control_model_switch",))
        agent.echo_runtime.build_context.return_value = runtime_context
        agent.echo_runtime.execute_tool_effect = AsyncMock(
            return_value=(
                ChatMessage(role="tool", content="switched", name="control_model_switch"),
                ToolResult(
                    success=True,
                    output="switched",
                    metadata={"model_id": "preset/unconfigured"},
                ),
            )
        )
        # Track raw persistence bypass.
        monkeypatch.setattr(
            web_server,
            "_save_active_model",
            MagicMock(side_effect=AssertionError("must not persist unconfigured preset")),
        )

        from js.models.cloud_providers import ALL_PRESETS

        preset = ALL_PRESETS[0]
        preset_model_id = f"{preset.id}/{preset.models[0].id}"

        resp = client.post("/api/models/switch", json={"model_id": preset_model_id})
        assert resp.status_code == 409
        body = resp.json()
        detail = body.get("detail", body)
        if isinstance(detail, dict):
            assert detail.get("needs_config") is True
        else:
            assert "needs_config" in str(detail).lower() or "config" in str(detail).lower()
        # execute_tool_effect must not have been called for an unconfigured preset.
        agent.echo_runtime.execute_tool_effect.assert_not_awaited()
        # Must not have become active.
        from js.web.deps import get_active_model

        assert get_active_model() == ""
        assert agent.router.preferred_model == ""

    def test_switch_model_rejects_router_mapping_when_provider_not_configured(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """HTTP must NOT trust a router mapping when the provider is not configured.

        Even if ``router.get_model_config`` returns non-None, the endpoint
        must return 400 and must not enter the effect layer.
        """
        agent = web_server._agent
        agent.settings.providers = []
        agent.router.preferred_model = ""
        fake_config = ModelConfig(id="dynamic-model", provider="stale")
        agent.router.get_model_config.return_value = fake_config
        agent.router.get_model_binding = MagicMock(return_value=("stale", fake_config))

        runtime_context = MagicMock(capabilities=("control_model_switch",))
        agent.echo_runtime.build_context.return_value = runtime_context
        agent.echo_runtime.execute_tool_effect = AsyncMock(
            return_value=(
                ChatMessage(role="tool", content="switched", name="control_model_switch"),
                ToolResult(
                    success=True, output="switched", metadata={"model_id": "stale/dynamic-model"}
                ),
            )
        )
        monkeypatch.setattr(
            web_server,
            "_save_active_model",
            MagicMock(side_effect=AssertionError("must not persist unconfigured provider")),
        )

        resp = client.post("/api/models/switch", json={"model_id": "stale/dynamic-model"})
        assert resp.status_code == 400
        agent.echo_runtime.execute_tool_effect.assert_not_awaited()

    def test_switch_model_rejects_unknown_model_on_configured_provider(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """HTTP must reject an unknown model on a configured provider.

        The provider is configured but the model is not declared in its
        settings.models and the router has no binding.  Must return 400
        and must not enter the effect layer.
        """
        agent = web_server._agent
        # The fixture already has provider "test" with model "model-a".
        agent.router.preferred_model = ""
        agent.router.get_model_config.return_value = None
        agent.router.get_model_binding = MagicMock(return_value=None)

        runtime_context = MagicMock(capabilities=("control_model_switch",))
        agent.echo_runtime.build_context.return_value = runtime_context
        agent.echo_runtime.execute_tool_effect = AsyncMock(
            return_value=(
                ChatMessage(role="tool", content="switched", name="control_model_switch"),
                ToolResult(success=True, output="switched", metadata={"model_id": "test/unknown"}),
            )
        )
        monkeypatch.setattr(
            web_server,
            "_save_active_model",
            MagicMock(side_effect=AssertionError("must not persist unknown model")),
        )

        resp = client.post("/api/models/switch", json={"model_id": "test/unknown-model"})
        assert resp.status_code == 400
        agent.echo_runtime.execute_tool_effect.assert_not_awaited()

    def test_switch_model_allows_configured_provider_with_router_binding(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """HTTP must allow a model backed by a router binding on a configured provider.

        The provider is configured and the router has a dynamic binding
        for a model not in settings.models.  Must succeed.
        """
        agent = web_server._agent
        agent.router.preferred_model = ""
        dynamic_config = ModelConfig(id="dynamic-model", provider="test")
        agent.router.get_model_config.return_value = dynamic_config
        agent.router.get_model_binding = MagicMock(return_value=("test", dynamic_config))

        runtime_context = MagicMock(capabilities=("control_model_switch",))
        agent.echo_runtime.build_context.return_value = runtime_context

        async def execute_model_switch(effect: Any, _context: Any) -> tuple[Any, ToolResult]:
            from js.web.deps import set_active_model

            set_active_model("test/dynamic-model")
            return (
                ChatMessage(role="tool", content="switched", name=effect.tool_name),
                ToolResult(
                    success=True,
                    output="switched",
                    metadata={"model_id": "test/dynamic-model"},
                ),
            )

        agent.echo_runtime.execute_tool_effect = AsyncMock(side_effect=execute_model_switch)
        monkeypatch.setattr(
            web_server,
            "_save_active_model",
            MagicMock(side_effect=AssertionError("raw active-model write bypass")),
        )

        resp = client.post("/api/models/switch", json={"model_id": "test/dynamic-model"})
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_switch_model_missing_id(self, client: TestClient) -> None:
        resp = client.post("/api/models/switch", json={})
        assert resp.status_code == 400

    def test_switch_model_rejects_non_string_id(self, client: TestClient) -> None:
        resp = client.post("/api/models/switch", json={"model_id": ["test/model-a"]})
        assert resp.status_code == 400

    def test_switch_model_invalid_id(self, client: TestClient) -> None:
        resp = client.post("/api/models/switch", json={"model_id": "invalid/model"})
        assert resp.status_code == 400

    def test_models_get_does_not_probe_or_mutate_local_provider_models(
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
        monkeypatch.setattr(
            "js.models.provider_manager.ProviderManager.discover_models",
            discover,
        )
        health_check = AsyncMock(return_value=True)
        cached_provider = MagicMock(
            _last_health_check=0.0,
            _health_status=False,
            health_check=health_check,
        )
        agent.router._providers = {"lmstudio": cached_provider}

        resp = client.get("/api/models")

        assert resp.status_code == 200
        data = resp.json()
        assert data["providers"][0]["models"][0]["id"] == "model-a"
        discover.assert_not_awaited()
        health_check.assert_not_awaited()
        agent.router.add_provider.assert_not_called()


class TestProviderConnect:
    def test_lan_scan_is_fail_closed_without_an_echo_network_effect(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        discovery = MagicMock(side_effect=AssertionError("LAN scanner must not start"))
        monkeypatch.setattr("js.models.discovery.LocalModelDiscovery", discovery)

        response = client.post("/api/providers/scan-lan", json={})

        assert response.status_code == 409
        assert "disabled" in response.text.lower()
        discovery.assert_not_called()

    def test_connect_provider_sets_model_provider(self, client: TestClient) -> None:
        agent = web_server._agent
        agent.stage_provider_discovery_key.return_value = "provider-key-ref"
        agent.echo_runtime.build_context.return_value = MagicMock(
            capabilities=("control_provider_mutate",)
        )
        agent.echo_runtime.execute_tool_effect = AsyncMock(
            return_value=(
                ChatMessage(role="tool", content="saved", name="control_provider_mutate"),
                ToolResult(
                    success=True,
                    output="saved",
                    metadata={"provider": "custom", "models_added": 1},
                ),
            )
        )
        resp = client.post(
            "/api/providers/connect",
            json={
                "name": "custom",
                "base_url": "http://127.0.0.1:1234/v1",
                "api_key": "connect-super-secret",
                "models": [{"id": "model-x", "name": "Model X"}],
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["provider"] == "custom"

        agent.provider_manager.add.assert_not_called()
        agent.router.add_provider.assert_not_called()
        agent.echo_runtime.execute_tool_effect.assert_awaited_once()
        effect, _context = agent.echo_runtime.execute_tool_effect.await_args.args
        assert effect.tool_name == "control_provider_mutate"
        assert "provider-key-ref" in effect.arguments_json
        assert "connect-super-secret" not in effect.arguments_json
        assert '"provider":"custom"' in effect.arguments_json

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
        resp = client.put(
            "/api/memory/semantic/1", json={"value": "updated", "category": "insight"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True

    def test_update_semantic_memory_missing_value(self, client: TestClient) -> None:
        resp = client.put("/api/memory/semantic/1", json={"category": "insight"})
        assert resp.status_code == 422


class TestMemoryInbox:
    def test_organize_empty_buffer(self, client: TestClient) -> None:
        agent = web_server._agent
        agent._dream_scheduler.snapshot_buffer.return_value = []
        resp = client.post("/api/memory/organize")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["turns"] == 0

    def test_organize_runs_extraction_over_buffer(self, client: TestClient) -> None:
        agent = web_server._agent
        agent._dream_scheduler.snapshot_buffer.return_value = [
            {
                "user": "我老婆叫小红",
                "assistant": "好的",
                "owner_key_hash": None,
                "session_id": "s1",
            },
        ]
        agent._extract_memories = AsyncMock(
            return_value={
                "ok": True,
                "skipped": False,
                "proposed": 1,
                "auto_applied": 0,
                "pending": 1,
                "error": None,
            }
        )
        resp = client.post("/api/memory/organize")
        assert resp.status_code == 200
        data = resp.json()
        assert data["turns"] == 1
        assert data["pending"] == 1
        agent._extract_memories.assert_awaited_once()

    def test_approve_forwards_overrides(self, client: TestClient) -> None:
        agent = web_server._agent
        agent.memory.approve_proposal.return_value = {
            "success": True,
            "memory_id": 7,
            "status": "approved",
        }
        resp = client.post(
            "/api/memory/proposals/3/approve",
            json={"value": "小芳", "memory_path": "/people/family"},
        )
        assert resp.status_code == 200
        _, kwargs = agent.memory.approve_proposal.call_args
        assert kwargs["overrides"] == {"value": "小芳", "memory_path": "/people/family"}

    def test_approve_without_body_has_no_overrides(self, client: TestClient) -> None:
        agent = web_server._agent
        agent.memory.approve_proposal.return_value = {
            "success": True,
            "memory_id": 7,
            "status": "approved",
        }
        resp = client.post("/api/memory/proposals/3/approve")
        assert resp.status_code == 200
        _, kwargs = agent.memory.approve_proposal.call_args
        assert kwargs["overrides"] is None
