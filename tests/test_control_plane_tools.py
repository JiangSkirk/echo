"""Echo control-plane tool regressions for Web search and skill management."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from js.agent.tool_executor import ToolExecutorMixin
from js.config import ModelConfig, ModelProviderConfig, ToolLimits
from js.echo.attachment_gate import SecureUploadWriter
from js.echo.durable_thread import EchoDurableExecutor
from js.echo.ledger.service import EchoSafetyService
from js.echo.turn_context import RuntimeContext, reset_runtime_context, set_runtime_context
from js.search.engines import SearchResult
from js.security.secrets import SecretManager
from js.tools.registry import ToolRegistry, ToolResult, ToolSpec, required_network_hosts

_TEST_DURABLE_EXECUTOR = EchoDurableExecutor(
    max_claim_pending=8,
    max_finish_pending=8,
    claim_workers=2,
    finish_workers=2,
    thread_name_prefix="echo-control-plane-test",
)
_TEST_SAFETY_SERVICES: list[EchoSafetyService] = []


@pytest.fixture(scope="module", autouse=True)
def _close_echo_test_resources() -> Any:
    yield
    for service in reversed(_TEST_SAFETY_SERVICES):
        service.close()
    _TEST_DURABLE_EXECUTOR.shutdown(wait=True)


class _NoopAudit:
    def log(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class _NoopEvents:
    def emit(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class _NoopGuard:
    def check_loop(self, *_args: Any, **_kwargs: Any) -> Any:
        return SimpleNamespace(decision=None, reason="")

    def check_tool_result(self, *_args: Any, **_kwargs: Any) -> Any:
        return SimpleNamespace(decision=None, reason="")

    def check_repeated_failure(self, *_args: Any, **_kwargs: Any) -> Any:
        return SimpleNamespace(decision="allow", reason="")


class _NoopDefense:
    def evaluate(self, _context: Any) -> Any:
        return SimpleNamespace(blocked=False, reason="")


class _NoApprovalQueue:
    def request_decision(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("admin control-plane effects must not enqueue another approval")

    def request(self, *_args: Any, **_kwargs: Any) -> bool:
        raise AssertionError("admin control-plane effects must not request another approval")


class _ControlExecutor(ToolExecutorMixin):
    def __init__(self, tmp_path: Path) -> None:
        workspace = tmp_path / "workspace"
        state_dir = tmp_path / "state"
        workspace.mkdir()
        state_dir.mkdir()
        self.settings = SimpleNamespace(
            echo_engine="on",
            product_id="js-agent",
            workspace=workspace,
            state_dir=state_dir,
            tools=ToolLimits(),
            security=SimpleNamespace(),
            providers=[],
        )
        self.guard = _NoopGuard()
        self.registry = ToolRegistry(self.settings.tools, self.guard)
        self.audit = _NoopAudit()
        self.event_store = _NoopEvents()
        self.defense_strategies = _NoopDefense()
        self.approvals = _NoApprovalQueue()
        self.secrets = SecretManager(state_dir)
        self._echo_durable_executor = _TEST_DURABLE_EXECUTOR
        self.echo_safety_service = EchoSafetyService(state_dir=state_dir)
        _TEST_SAFETY_SERVICES.append(self.echo_safety_service)
        self.logger = MagicMock()
        self._role = None
        self._current_allowed_tools: set[str] = set()
        self.search = SimpleNamespace(search=AsyncMock())
        installed = SimpleNamespace(
            id="example-skill",
            trust_level=SimpleNamespace(value="community"),
            risk_flags=["network"],
        )
        self.skills = SimpleNamespace(install=AsyncMock(return_value=installed))
        self.provider_manager = SimpleNamespace(
            discover_models=AsyncMock(
                return_value={
                    "models": [{"id": "model-a", "name": "Model A", "context_window": 4096}]
                }
            ),
            get_all=MagicMock(return_value=[]),
            get=MagicMock(return_value=None),
            add=MagicMock(),
            remove=MagicMock(return_value=False),
            update_api_key=MagicMock(return_value=False),
        )
        self.router = SimpleNamespace(
            add_provider=MagicMock(),
            remove_provider=MagicMock(),
        )
        self._clawhub = SimpleNamespace(
            fetch_index=AsyncMock(
                return_value=[
                    {
                        "id": "example-skill",
                        "name": "Example skill",
                        "source": "https://github.com/example/example-skill.git",
                    }
                ]
            ),
            search_index=MagicMock(
                return_value=[
                    {
                        "id": "example-skill",
                        "name": "Example skill",
                        "source": "https://github.com/example/example-skill.git",
                    }
                ]
            ),
            get_skill_source=MagicMock(return_value="https://github.com/example/example-skill.git"),
        )


def _network_runtime_context(
    executor: _ControlExecutor,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    run_id: str,
    session_id: str = "admin-control-plane",
) -> RuntimeContext:
    return RuntimeContext(
        product_id="js-agent",
        channel="test-control-plane",
        owner_key_hash="admin-owner",
        session_id=session_id,
        run_id=run_id,
        role="admin",
        profile="default",
        capabilities=(tool_name,),
        workspace=executor.settings.workspace,
        state_dir=executor.settings.state_dir,
        fs_roots=(executor.settings.workspace,),
        network_allowlist=required_network_hosts(tool_name, arguments),
        cancel_token=asyncio.Event(),
    )


def test_private_control_handoff_is_partitioned_by_product_owner_and_session(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    context_a = _network_runtime_context(
        executor,
        tool_name="control_memory_mutate",
        arguments={},
        run_id="scope-a",
    )
    context_b = RuntimeContext(
        **{
            **context_a.__dict__,
            "session_id": "different-session",
            "run_id": "scope-b",
        }
    )
    context_other_product = RuntimeContext(
        **{
            **context_a.__dict__,
            "product_id": "js-work",
            "run_id": "scope-other-product",
        }
    )
    token = set_runtime_context(context_a)
    try:
        reference = executor.stage_memory_mutation_payload(
            "admin-owner",
            {"synthetic": "private"},
        )
    finally:
        reset_runtime_context(token)

    token = set_runtime_context(context_b)
    try:
        assert executor.take_memory_mutation_payload(reference, "admin-owner") is None
    finally:
        reset_runtime_context(token)

    token = set_runtime_context(context_other_product)
    try:
        assert executor.take_memory_mutation_payload(reference, "admin-owner") is None
    finally:
        reset_runtime_context(token)

    token = set_runtime_context(context_a)
    try:
        assert executor.take_memory_mutation_payload(
            reference,
            "admin-owner",
        ) == {"synthetic": "private"}
    finally:
        reset_runtime_context(token)


def test_private_control_handoff_defaults_plain_js_settings_to_js_agent(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    del executor.settings.product_id

    reference = executor.stage_memory_mutation_payload(
        "admin-owner",
        {"synthetic": True},
        session_id="plain-js-session",
    )

    assert reference
    assert executor.take_memory_mutation_payload(
        reference,
        "admin-owner",
        product_id="js-agent",
        session_id="plain-js-session",
    ) == {"synthetic": True}


def test_secret_key_handoffs_are_partitioned_by_product_owner_and_session(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    provider_context = _network_runtime_context(
        executor,
        tool_name="control_provider_discover",
        arguments={"base_url": "https://example.invalid/v1"},
        run_id="provider-key-scope",
        session_id="provider-session-a",
    )
    other_session = RuntimeContext(
        **{
            **provider_context.__dict__,
            "session_id": "provider-session-b",
            "run_id": "provider-key-other-session",
        }
    )

    token = set_runtime_context(provider_context)
    try:
        provider_ref = executor.stage_provider_discovery_key("synthetic-key")
    finally:
        reset_runtime_context(token)

    token = set_runtime_context(other_session)
    try:
        assert executor.take_provider_discovery_key(provider_ref) is None
    finally:
        reset_runtime_context(token)

    token = set_runtime_context(provider_context)
    try:
        assert executor.take_provider_discovery_key(provider_ref) == "synthetic-key"
        setup_ref = executor.stage_setup_admin_key("synthetic-admin-key")
    finally:
        reset_runtime_context(token)

    other_product = RuntimeContext(
        **{
            **provider_context.__dict__,
            "product_id": "js-work",
            "run_id": "setup-key-other-product",
        }
    )
    token = set_runtime_context(other_product)
    try:
        assert executor.take_setup_admin_key(setup_ref) is None
    finally:
        reset_runtime_context(token)

    token = set_runtime_context(provider_context)
    try:
        assert executor.take_setup_admin_key(setup_ref) == "synthetic-admin-key"
    finally:
        reset_runtime_context(token)

    assert executor.stage_provider_discovery_key("unscoped-key") == ""
    assert executor.stage_setup_admin_key("unscoped-admin-key") == ""


@pytest.mark.asyncio
async def test_web_search_tool_returns_structured_results_metadata(
    tmp_path: Path,
    echo_tool_context: Any,
) -> None:
    executor = _ControlExecutor(tmp_path)
    executor.search.search.return_value = [
        SearchResult(
            title="Echo result",
            url="https://example.com/echo",
            snippet="Structured metadata",
            source="test",
        )
    ]
    executor._register_search_tool()
    arguments = {"query": "echo", "max_results": 2}

    result = await executor.registry.execute(
        "web-search-run",
        "web_search",
        arguments,
        execution_context=echo_tool_context(
            run_id="web-search-run",
            tool_name="web_search",
            arguments=arguments,
            network_policy="allow",
            network_hosts=required_network_hosts("web_search", arguments),
            registry=executor.registry,
        ),
    )

    assert result.success is True
    assert result.metadata == {
        "results": [
            {
                "title": "Echo result",
                "url": "https://example.com/echo",
                "snippet": "Structured metadata",
                "source": "test",
            }
        ]
    }


def test_control_plane_tools_are_registered_but_hidden_from_model_schema(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)

    executor._register_control_plane_tools()

    control_names = {
        "control_skill_install",
        "control_clawhub_discover",
        "control_clawhub_install",
        "control_provider_discover",
        "control_provider_mutate",
        "control_fleet_configure",
        "control_fleet_continue",
        "control_fleet_session_delete",
        "control_model_switch",
        "control_setup_state",
        "control_desktop_state",
        "control_session_mutate",
        "control_task_mutate",
        "control_memory_mutate",
        "control_skill_mutate",
        "control_evolution_action",
        "control_upload_mutate",
        "control_cron_mutate",
        "control_gateway_push",
    }
    registered = {tool.name: tool for tool in executor.registry.list_tools()}
    assert control_names <= registered.keys()
    assert all(registered[name].model_visible is False for name in control_names)
    model_names = {schema["function"]["name"] for schema in executor.registry.to_openai_schemas()}
    assert control_names.isdisjoint(model_names)


@pytest.mark.asyncio
async def test_provider_discovery_uses_one_time_in_memory_key_and_exact_host_lease(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    executor._register_control_plane_tools()
    key_ref = executor.stage_provider_discovery_key(
        "super-secret-key",
        owner_key_hash="admin-owner",
        product_id="js-agent",
        session_id="admin-control-plane",
    )
    arguments = {
        "base_url": "http://127.0.0.1:1234/v1",
        "api_key_ref": key_ref,
        "allow_private": False,
    }
    run_id = "provider-discovery-run"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_provider_discover",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "provider-discovery-call",
                "function": {
                    "name": "control_provider_discover",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Admin approved exact provider discovery",
            allowed_tools={"control_provider_discover"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    assert result.metadata["models"][0]["id"] == "model-a"
    executor.provider_manager.discover_models.assert_awaited_once_with(
        "http://127.0.0.1:1234/v1",
        "super-secret-key",
        allow_private=False,
    )
    assert (
        executor.take_provider_discovery_key(
            key_ref,
            owner_key_hash="admin-owner",
            product_id="js-agent",
            session_id="admin-control-plane",
        )
        is None
    )


@pytest.mark.asyncio
async def test_setup_completion_runs_inside_echo_and_hands_key_off_once(
    tmp_path: Path,
) -> None:
    from js.web.auth import AuthManager

    executor = _ControlExecutor(tmp_path)
    executor.settings.first_run_completed = False
    executor.settings.security.api_key_required = True
    executor.settings.save = MagicMock()
    executor._register_control_plane_tools()
    arguments = {"action": "complete"}
    run_id = "setup-complete-run"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_setup_state",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "setup-complete-call",
                "function": {
                    "name": "control_setup_state",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Complete setup safely",
            allowed_tools={"control_setup_state"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    assert executor.settings.first_run_completed is True
    assert executor.settings.onboarding_status == "completed"
    executor.settings.save.assert_called_once_with(
        fields=["first_run_completed", "onboarding_status"]
    )
    key_ref = result.metadata["admin_key_ref"]
    assert isinstance(key_ref, str) and key_ref
    assert "js_" not in result.output
    admin_key = executor.take_setup_admin_key(
        key_ref,
        owner_key_hash="admin-owner",
        product_id="js-agent",
        session_id="admin-control-plane",
    )
    assert admin_key is not None
    assert AuthManager(executor.settings.state_dir).verify(admin_key)["role"] == "admin"
    assert (
        executor.take_setup_admin_key(
            key_ref,
            owner_key_hash="admin-owner",
            product_id="js-agent",
            session_id="admin-control-plane",
        )
        is None
    )


@pytest.mark.asyncio
async def test_setup_completion_rolls_back_new_key_when_config_save_fails(
    tmp_path: Path,
) -> None:
    from js.web.auth import AuthManager

    executor = _ControlExecutor(tmp_path)
    executor.settings.first_run_completed = False
    executor.settings.security.api_key_required = True
    executor.settings.save = MagicMock(side_effect=OSError("synthetic disk failure"))
    executor._register_control_plane_tools()
    arguments = {"action": "complete"}
    run_id = "setup-rollback-run"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_setup_state",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "setup-rollback-call",
                "function": {
                    "name": "control_setup_state",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Complete setup with failing storage",
            allowed_tools={"control_setup_state"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is False
    assert result.metadata["status_code"] == 500
    assert executor.settings.first_run_completed is False
    assert AuthManager(executor.settings.state_dir).has_admin() is False


@pytest.mark.asyncio
async def test_session_cancel_control_tool_uses_immutable_echo_owner(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    executor.request_cancel = MagicMock(return_value=True)
    executor._register_control_plane_tools()
    arguments = {"action": "cancel", "session_id": "session-123"}
    run_id = "session-cancel-run"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_session_mutate",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "session-cancel-call",
                "function": {
                    "name": "control_session_mutate",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Cancel an owner-bound session",
            allowed_tools={"control_session_mutate"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    assert result.metadata == {"session_id": "session-123", "cancelled": True}
    executor.request_cancel.assert_called_once_with(
        "session-123",
        owner_key_hash="admin-owner",
    )


@pytest.mark.asyncio
async def test_session_delete_control_tool_uses_owner_partition(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    executor.memory = SimpleNamespace(delete_session=MagicMock(return_value=True))
    executor._cancel_tokens = {}
    executor._register_control_plane_tools()
    arguments = {"action": "delete", "session_id": "session-123"}
    run_id = "session-delete-run"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_session_mutate",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "session-delete-call",
                "function": {
                    "name": "control_session_mutate",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Delete an owner-bound session",
            allowed_tools={"control_session_mutate"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    assert result.metadata == {"session_id": "session-123", "deleted": True}
    executor.memory.delete_session.assert_called_once_with(
        "session-123",
        owner_key_hash="admin-owner",
    )


@pytest.mark.asyncio
async def test_desktop_enable_control_tool_registers_read_only_then_persists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from js.tools import desktop_tools as desktop_tools_module
    from js.tools.desktop import wizard

    executor = _ControlExecutor(tmp_path)
    executor.settings.desktop_control_enabled = False
    executor.settings.save = MagicMock()
    executor._desktop_tools = None
    desktop = MagicMock()
    desktop.available = True
    desktop.init_error = ""
    desktop.register_read_only.return_value = 7
    monkeypatch.setattr(
        wizard,
        "run_wizard",
        lambda: SimpleNamespace(ready=True),
    )
    monkeypatch.setattr(desktop_tools_module, "DesktopTools", MagicMock(return_value=desktop))
    executor._register_control_plane_tools()
    arguments = {"action": "enable_read_only"}
    run_id = "desktop-enable-run"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_desktop_state",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "desktop-enable-call",
                "function": {
                    "name": "control_desktop_state",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Enable read-only desktop tools",
            allowed_tools={"control_desktop_state"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    assert result.metadata["stage"] == "read_only"
    assert result.metadata["tools_count"] == 7
    desktop.register_read_only.assert_called_once_with(executor.registry)
    desktop.register_write_tools.assert_not_called()
    executor.settings.save.assert_called_once_with(fields=["desktop_control_enabled"])
    assert executor.settings.desktop_control_enabled is True
    assert executor._desktop_tools is desktop


@pytest.mark.asyncio
async def test_task_control_tool_uses_immutable_echo_owner(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    executor.task_manager = SimpleNamespace(pause=MagicMock(return_value=True))
    executor._register_control_plane_tools()
    arguments = {"action": "pause", "task_id": "task-123"}
    run_id = "task-pause-run"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_task_mutate",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "task-pause-call",
                "function": {
                    "name": "control_task_mutate",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Pause an owner-bound task",
            allowed_tools={"control_task_mutate"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    assert result.metadata == {"task_id": "task-123", "status": "paused"}
    executor.task_manager.pause.assert_called_once_with(
        "task-123",
        owner_key_hash="admin-owner",
    )


@pytest.mark.asyncio
async def test_memory_control_tool_keeps_private_payload_and_result_out_of_receipt(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    executor.memory = SimpleNamespace(
        store_semantic=MagicMock(
            return_value={
                "memory_id": 7,
                "memory_path": "/private/path",
                "entity_type": "fact",
            }
        )
    )
    executor._register_control_plane_tools()
    private_key = "private-memory-key"
    private_value = "private-memory-value"
    payload_ref = executor.stage_memory_mutation_payload(
        "admin-owner",
        {
            "key": private_key,
            "value": private_value,
            "category": "fact",
            "source": "user",
            "memory_path": None,
            "entity_type": None,
            "entity_name": None,
            "parent_id": None,
            "relation_type": None,
            "evidence": "",
        },
        session_id="admin-control-plane",
    )
    assert payload_ref
    arguments = {"action": "semantic_create", "payload_ref": payload_ref}
    run_id = "memory-create-run"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_memory_mutate",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "memory-create-call",
                "function": {
                    "name": "control_memory_mutate",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Create owner-bound memory through an opaque payload",
            allowed_tools={"control_memory_mutate"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    result_ref = result.metadata["result_ref"]
    assert private_key not in result.output
    assert private_value not in result.output
    assert private_key not in json.dumps(result.metadata)
    assert private_value not in json.dumps(result.metadata)
    assert (
        executor.take_memory_mutation_payload(
            payload_ref,
            "admin-owner",
            session_id="admin-control-plane",
        )
        is None
    )
    response = executor.take_memory_mutation_result(
        result_ref,
        "admin-owner",
        session_id="admin-control-plane",
    )
    assert response == {
        "success": True,
        "key": private_key,
        "memory_id": 7,
        "memory_path": "/private/path",
        "entity_type": "fact",
    }
    assert (
        executor.take_memory_mutation_result(
            result_ref,
            "admin-owner",
            session_id="admin-control-plane",
        )
        is None
    )
    executor.memory.store_semantic.assert_called_once_with(
        key=private_key,
        value=private_value,
        category="fact",
        source="user",
        memory_path=None,
        entity_type=None,
        entity_name=None,
        parent_id=None,
        relation_type=None,
        owner_key_hash="admin-owner",
        evidence="",
    )


@pytest.mark.asyncio
async def test_memory_control_reserves_result_capacity_before_mutation(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    executor.memory = SimpleNamespace(write_memory_file=MagicMock())
    executor._register_control_plane_tools()
    for index in range(64):
        assert executor.stage_memory_mutation_result(
            "admin-owner",
            {"slot": index},
            session_id="admin-control-plane",
        )
    payload_ref = executor.stage_memory_mutation_payload(
        "admin-owner",
        {"name": "synthetic.md", "content": "synthetic"},
        session_id="admin-control-plane",
    )
    arguments = {"action": "file_put", "payload_ref": payload_ref}
    run_id = "memory-result-capacity"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_memory_mutate",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "memory-capacity-call",
                "function": {
                    "name": "control_memory_mutate",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Store synthetic memory",
            allowed_tools={"control_memory_mutate"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is False
    assert result.error == "Memory result handoff is unavailable"
    executor.memory.write_memory_file.assert_not_called()


@pytest.mark.asyncio
async def test_memory_file_put_rejects_names_outside_allowlist(tmp_path: Path) -> None:
    executor = _ControlExecutor(tmp_path)
    executor.memory = SimpleNamespace(write_memory_file=MagicMock())
    executor._register_control_plane_tools()
    payload_ref = executor.stage_memory_mutation_payload(
        "admin-owner",
        {"name": "notes", "content": "synthetic"},
        session_id="admin-control-plane",
    )
    arguments = {"action": "file_put", "payload_ref": payload_ref}
    run_id = "memory-file-allowlist"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_memory_mutate",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "memory-allowlist-call",
                "function": {
                    "name": "control_memory_mutate",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Store synthetic memory",
            allowed_tools={"control_memory_mutate"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is False
    assert result.error == "Invalid memory file payload"
    executor.memory.write_memory_file.assert_not_called()


@pytest.mark.asyncio
async def test_embedder_recovery_falls_back_when_rebuild_raises(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    private_error = "/Users/private/embedder-config secret-token"
    health = SimpleNamespace(
        provider="fallback-provider",
        active=True,
        fallback_provider=None,
        failure_count=0,
    )
    existing_embedder = SimpleNamespace(
        force_recover=MagicMock(return_value=True),
        health=MagicMock(return_value=health),
    )
    executor.memory = SimpleNamespace(embedder=existing_embedder)
    executor._setup_embedder = MagicMock(side_effect=RuntimeError(private_error))
    executor._register_control_plane_tools()
    payload_ref = executor.stage_memory_mutation_payload(
        "admin-owner",
        {},
        session_id="admin-control-plane",
    )
    arguments = {"action": "embedder_recover", "payload_ref": payload_ref}
    run_id = "embedder-recover"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_memory_mutate",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "embedder-recover-call",
                "function": {
                    "name": "control_memory_mutate",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Recover the configured embedder",
            allowed_tools={"control_memory_mutate"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    serialized = json.dumps(
        {"output": result.output, "error": result.error, "metadata": result.metadata}
    )
    assert private_error not in serialized
    response = executor.take_memory_mutation_result(
        result.metadata["result_ref"],
        "admin-owner",
        session_id="admin-control-plane",
    )
    assert response == {
        "success": True,
        "provider": "fallback-provider",
        "active": True,
        "fallback_provider": None,
        "failure_count": 0,
        "recovered": True,
        "method": "force_recover",
    }
    existing_embedder.force_recover.assert_called_once_with()


@pytest.mark.asyncio
async def test_skill_rejection_control_keeps_reason_private_and_owner_bound(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    executor.promotion_store = SimpleNamespace(mark_rejected=MagicMock(return_value=True))
    executor._register_control_plane_tools()
    private_reason = "private operator security reason"
    payload_ref = executor.stage_skill_mutation_payload(
        "admin-owner",
        {"event_id": "event-123", "reason": private_reason},
        session_id="admin-control-plane",
    )
    arguments = {"action": "promotion_reject", "payload_ref": payload_ref}
    run_id = "skill-reject-run"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_skill_mutate",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "skill-reject-call",
                "function": {
                    "name": "control_skill_mutate",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Reject an owner-bound skill promotion",
            allowed_tools={"control_skill_mutate"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    assert private_reason not in result.output
    assert private_reason not in json.dumps(result.metadata)
    response = executor.take_skill_mutation_result(
        result.metadata["result_ref"],
        "admin-owner",
        session_id="admin-control-plane",
    )
    assert response == {
        "success": True,
        "event_id": "event-123",
        "status": "rejected",
    }
    executor.promotion_store.mark_rejected.assert_called_once_with(
        "event-123",
        owner_key_hash="admin-owner",
        decided_by="web",
        reason=private_reason,
    )


@pytest.mark.asyncio
async def test_evolution_control_stages_report_outside_echo_receipt(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    private_report = {
        "profile_update": {"ok": True, "private": "private-profile-detail"},
        "elapsed_seconds": 1.0,
    }
    executor.metacognition = MagicMock()
    executor.learner = MagicMock()
    executor.optimizer = MagicMock()
    executor.evolver = MagicMock()
    executor._dream_scheduler = SimpleNamespace(snapshot_buffer=MagicMock(return_value=[]))
    executor._run_evolution_cycle = AsyncMock(return_value=private_report)
    executor._register_control_plane_tools()
    arguments = {"action": "run"}
    run_id = "evolution-run"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_evolution_action",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "evolution-call",
                "function": {
                    "name": "control_evolution_action",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Run administrator-approved evolution",
            allowed_tools={"control_evolution_action"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    assert "private-profile-detail" not in result.output
    assert "private-profile-detail" not in json.dumps(result.metadata)
    response = executor.take_evolution_action_result(
        result.metadata["result_ref"],
        "admin-owner",
        session_id="admin-control-plane",
    )
    assert response == {
        "success": True,
        "message": "Evolution cycle completed",
        "report": private_report,
    }
    executor._run_evolution_cycle.assert_awaited_once_with([])


@pytest.mark.asyncio
async def test_evolution_control_sanitizes_internal_exception_receipt(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    private_error = "/Users/private/customer.xlsx secret-token"
    executor.metacognition = MagicMock()
    executor.learner = MagicMock()
    executor.optimizer = MagicMock()
    executor.evolver = MagicMock()
    executor._dream_scheduler = SimpleNamespace(snapshot_buffer=MagicMock(return_value=[]))
    executor._run_evolution_cycle = AsyncMock(side_effect=RuntimeError(private_error))
    executor._register_control_plane_tools()
    arguments = {"action": "run"}
    run_id = "evolution-error"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_evolution_action",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "evolution-error-call",
                "function": {
                    "name": "control_evolution_action",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Run administrator-approved evolution",
            allowed_tools={"control_evolution_action"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is False
    assert result.error == "Evolution action failed safely"
    serialized = json.dumps(
        {"output": result.output, "error": result.error, "metadata": result.metadata}
    )
    assert private_error not in serialized
    assert "/Users/private" not in serialized


@pytest.mark.asyncio
async def test_upload_control_commits_private_bytes_outside_echo_receipt(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    executor._register_control_plane_tools()
    private_bytes = b"private synthetic attachment bytes"
    private_name = "private-customer-name.txt"

    with SecureUploadWriter(
        executor.settings.workspace,
        "admin-owner",
        "upload-session",
        private_name,
    ) as writer:
        writer.write(private_bytes)
        payload_ref = executor.stage_upload_commit(
            "admin-owner",
            "upload-session",
            writer,
        )
        arguments = {"action": "commit", "payload_ref": payload_ref}
        run_id = "upload-commit"
        token = set_runtime_context(
            _network_runtime_context(
                executor,
                tool_name="control_upload_mutate",
                arguments=arguments,
                run_id=run_id,
                session_id="upload-session",
            )
        )
        try:
            _message, result = await executor._execute_tool_call(
                {
                    "id": "upload-commit-call",
                    "function": {
                        "name": "control_upload_mutate",
                        "arguments": json.dumps(arguments),
                    },
                },
                session_id="upload-session",
                run_id=run_id,
                user_input="Commit an owner-bound upload",
                allowed_tools={"control_upload_mutate"},
                owner_key_hash="admin-owner",
            )
        finally:
            reset_runtime_context(token)
            executor.discard_upload_commit(
                payload_ref,
                "admin-owner",
                session_id="upload-session",
            )

    assert result.success is True
    serialized = json.dumps(
        {"output": result.output, "error": result.error, "metadata": result.metadata}
    )
    assert private_name not in serialized
    assert private_bytes.decode() not in serialized
    response = executor.take_upload_mutation_result(
        result.metadata["result_ref"],
        "admin-owner",
        session_id="upload-session",
    )
    assert response is not None
    assert response["size"] == len(private_bytes)
    target = executor.settings.workspace / response["path"]
    assert target.read_bytes() == private_bytes


@pytest.mark.asyncio
async def test_cron_control_keeps_job_payload_outside_echo_receipt(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    executor._daemon = SimpleNamespace(add_job=MagicMock())
    executor._register_control_plane_tools()
    private_name = "private customer schedule"
    private_prompt = "private synthetic scheduled prompt"
    payload_ref = executor.stage_cron_mutation_payload(
        "admin-owner",
        {
            "name": private_name,
            "cron_expr": "0 8 * * *",
            "task_type": "chat",
            "payload": {"prompt": private_prompt},
        },
        session_id="admin-control-plane",
    )
    arguments = {"action": "create", "payload_ref": payload_ref}
    run_id = "cron-create"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_cron_mutate",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "cron-create-call",
                "function": {
                    "name": "control_cron_mutate",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Create an owner-bound scheduled job",
            allowed_tools={"control_cron_mutate"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    serialized = json.dumps(
        {"output": result.output, "error": result.error, "metadata": result.metadata}
    )
    assert private_name not in serialized
    assert private_prompt not in serialized
    response = executor.take_cron_mutation_result(
        result.metadata["result_ref"],
        "admin-owner",
        session_id="admin-control-plane",
    )
    assert response is not None
    assert response["job"]["name"] == private_name
    created = executor._daemon.add_job.call_args.args[0]
    assert created.owner_key_hash == "admin-owner"
    assert created.product_id == "js-agent"
    assert created.session_id == f"cron:{created.id}"


@pytest.mark.asyncio
async def test_cron_update_validates_all_changes_before_mutating_job(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    job = SimpleNamespace(
        name="Original",
        description="",
        cron_expr="0 8 * * *",
        enabled=True,
        task_type="custom",
        payload={},
        notify_on_success=False,
        notify_on_failure=True,
        updated_at=0.0,
        next_run_at=None,
        to_dict=MagicMock(return_value={"name": "Original"}),
    )
    executor._daemon = SimpleNamespace(
        get_job=MagicMock(return_value=job),
        _persist_job=MagicMock(),
    )
    executor._register_control_plane_tools()
    payload_ref = executor.stage_cron_mutation_payload(
        "admin-owner",
        {
            "job_id": "job-1",
            "changes": {"name": "Partially updated", "cron_expr": "invalid"},
        },
        session_id="admin-control-plane",
    )
    arguments = {"action": "update", "payload_ref": payload_ref}
    run_id = "cron-update-invalid"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_cron_mutate",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "cron-update-invalid-call",
                "function": {
                    "name": "control_cron_mutate",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Reject an invalid scheduled-job update atomically",
            allowed_tools={"control_cron_mutate"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is False
    assert result.metadata["status_code"] == 400
    assert job.name == "Original"
    executor._daemon._persist_job.assert_not_called()


@pytest.mark.asyncio
async def test_cron_run_result_is_byte_bounded_without_losing_terminal_metadata(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    run_result = SimpleNamespace(
        success=True,
        status="completed",
        duration_ms=12.5,
        output="界" * 400_000,
        error="",
    )
    executor._daemon = SimpleNamespace(
        get_job=MagicMock(return_value=SimpleNamespace()),
        cron=SimpleNamespace(run_job_now=AsyncMock(return_value=run_result)),
    )
    executor._register_control_plane_tools()
    payload_ref = executor.stage_cron_mutation_payload(
        "admin-owner",
        {"job_id": "job-1"},
        session_id="admin-control-plane",
    )
    arguments = {"action": "run", "payload_ref": payload_ref}
    run_id = "cron-run-large-output"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_cron_mutate",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "cron-run-large-output-call",
                "function": {
                    "name": "control_cron_mutate",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Run an owner-bound synthetic job",
            allowed_tools={"control_cron_mutate"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    response = executor.take_cron_mutation_result(
        result.metadata["result_ref"],
        "admin-owner",
        session_id="admin-control-plane",
    )
    assert response is not None
    assert response["success"] is True
    assert response["duration_ms"] == 12.5
    assert response["output_truncated"] is True
    assert len(response["output"].encode("utf-8")) <= 262_144
    assert response["error_truncated"] is False


@pytest.mark.asyncio
async def test_skill_install_control_sanitizes_internal_exception(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    private_error = "/Users/private/customer-skill secret-token"
    executor.skills.install = AsyncMock(side_effect=RuntimeError(private_error))
    executor._register_control_plane_tools()
    arguments = {"source": "https://github.com/example/synthetic-skill.git"}
    run_id = "skill-install-error"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_skill_install",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "skill-install-error-call",
                "function": {
                    "name": "control_skill_install",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Install an administrator-selected synthetic skill",
            allowed_tools={"control_skill_install"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is False
    assert result.error == "Skill installation failed safely"
    assert private_error not in json.dumps(
        {"output": result.output, "error": result.error, "metadata": result.metadata}
    )


@pytest.mark.asyncio
async def test_provider_mutation_runs_inside_echo_and_consumes_opaque_key_once(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    executor._register_control_plane_tools()
    key_ref = executor.stage_provider_discovery_key(
        "super-secret-key",
        owner_key_hash="admin-owner",
        product_id="js-agent",
        session_id="admin-control-plane",
    )
    arguments = {
        "action": "upsert",
        "provider": {
            "name": "custom",
            "base_url": "https://models.example/v1",
            "default_model": "model-a",
            "models": [{"id": "model-a", "name": "Model A", "provider": "custom"}],
        },
        "api_key_ref": key_ref,
    }
    run_id = "provider-mutation-run"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_provider_mutate",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "provider-mutation-call",
                "function": {
                    "name": "control_provider_mutate",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Admin approved provider mutation",
            allowed_tools={"control_provider_mutate"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    saved = executor.provider_manager.add.call_args.args[0]
    assert saved.name == "custom"
    assert saved.api_key == "super-secret-key"
    assert executor.settings.providers == [saved]
    executor.router.add_provider.assert_called_once()
    assert (
        executor.take_provider_discovery_key(
            key_ref,
            owner_key_hash="admin-owner",
            product_id="js-agent",
            session_id="admin-control-plane",
        )
        is None
    )


@pytest.mark.asyncio
async def test_static_provider_key_is_encrypted_and_restart_hydratable(
    tmp_path: Path,
) -> None:
    from js.models.provider_manager import hydrate_static_provider_api_keys

    executor = _ControlExecutor(tmp_path)
    static_provider = ModelProviderConfig(
        name="static-provider",
        base_url="https://static.example/v1",
        default_model="model-a",
        models=[
            ModelConfig(
                id="model-a",
                name="Model A",
                provider="static-provider",
            )
        ],
    )
    executor.settings.providers = [static_provider]
    executor._register_control_plane_tools()
    key_ref = executor.stage_provider_discovery_key(
        "static-super-secret",
        owner_key_hash="admin-owner",
        product_id="js-agent",
        session_id="admin-control-plane",
    )
    arguments = {
        "action": "update_key",
        "name": "static-provider",
        "api_key_ref": key_ref,
    }
    run_id = "static-provider-key-run"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_provider_mutate",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "static-provider-key-call",
                "function": {
                    "name": "control_provider_mutate",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Admin approved static provider credential",
            allowed_tools={"control_provider_mutate"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    restarted = [static_provider.model_copy(update={"api_key": None})]
    hydrate_static_provider_api_keys(restarted, SecretManager(executor.settings.state_dir))
    assert restarted[0].api_key == "static-super-secret"


@pytest.mark.asyncio
async def test_fleet_configuration_mutation_runs_inside_echo(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    fleet = SimpleNamespace(update_agent_config=MagicMock())
    executor._fleet_getter = lambda: fleet
    executor._register_control_plane_tools()
    arguments = {"config": {"worker": "provider/model-a", "reviewer": ""}}
    run_id = "fleet-config-run"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_fleet_configure",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "fleet-config-call",
                "function": {
                    "name": "control_fleet_configure",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Admin approved Fleet model configuration",
            allowed_tools={"control_fleet_configure"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    fleet.update_agent_config.assert_called_once_with(arguments["config"])


@pytest.mark.asyncio
async def test_fleet_session_mutations_run_inside_echo(tmp_path: Path) -> None:
    executor = _ControlExecutor(tmp_path)
    fleet = SimpleNamespace(
        continue_session=AsyncMock(
            return_value={
                "session_id": "session-a",
                "final": "continued",
                "subtasks": {"review": "done"},
            }
        ),
        delete_session=MagicMock(return_value=True),
    )
    executor._fleet_getter = lambda: fleet
    executor._register_control_plane_tools()

    calls = [
        (
            "control_fleet_continue",
            {"session_id": "session-a", "follow_up": "Continue safely"},
        ),
        ("control_fleet_session_delete", {"session_id": "session-a"}),
    ]
    results: list[ToolResult] = []
    for index, (tool_name, arguments) in enumerate(calls):
        run_id = f"fleet-session-{index}"
        token = set_runtime_context(
            _network_runtime_context(
                executor,
                tool_name=tool_name,
                arguments=arguments,
                run_id=run_id,
            )
        )
        try:
            _message, result = await executor._execute_tool_call(
                {
                    "id": f"fleet-session-call-{index}",
                    "function": {
                        "name": tool_name,
                        "arguments": json.dumps(arguments),
                    },
                },
                session_id="admin-control-plane",
                run_id=run_id,
                user_input="Admin approved Fleet session mutation",
                allowed_tools={tool_name},
                owner_key_hash="admin-owner",
            )
        finally:
            reset_runtime_context(token)
        results.append(result)

    assert all(result.success for result in results)
    fleet.continue_session.assert_awaited_once_with("session-a", "Continue safely")
    fleet.delete_session.assert_called_once_with("session-a")


@pytest.mark.asyncio
async def test_model_switch_persists_and_publishes_inside_echo(tmp_path: Path) -> None:
    executor = _ControlExecutor(tmp_path)
    executor.settings.providers = [
        ModelProviderConfig(
            name="provider",
            base_url="https://models.example/v1",
            models=[ModelConfig(id="model-a", provider="provider")],
        )
    ]
    executor.router.preferred_model = ""
    executor.router._routing_cache = {"cached": "value"}
    executor._active_model_publisher = MagicMock()
    executor._register_control_plane_tools()
    arguments = {"model_id": "provider/model-a"}
    run_id = "model-switch-run"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_model_switch",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "model-switch-call",
                "function": {
                    "name": "control_model_switch",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Admin approved model switch",
            allowed_tools={"control_model_switch"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    assert (executor.settings.state_dir / "active_model.txt").read_text(
        encoding="utf-8"
    ) == "provider/model-a"
    assert executor.router.preferred_model == "provider/model-a"
    assert executor.router._routing_cache == {}
    executor._active_model_publisher.assert_called_once_with("provider/model-a")


@pytest.mark.asyncio
async def test_model_switch_rejects_unconfigured_preset_and_does_not_persist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """control_model_switch must reject a preset model whose provider is not configured.

    It must not write active_model.txt, not change preferred_model, and not
    publish an active model.  The failure must carry needs_config=true and a
    409 status code.  ``write_text_state`` must never be called (no transient
    writes) - the handler's internal ``from import`` receives the patch.
    """
    from js.models.cloud_providers import ALL_PRESETS
    from js.utils import atomic_state as _atomic_state
    from js.utils.atomic_state import write_text_state

    executor = _ControlExecutor(tmp_path)
    # Zero configured providers – only presets exist.
    executor.settings.providers = []
    executor.router.preferred_model = ""
    executor.router.get_model_config = MagicMock(return_value=None)
    # Use a normal MagicMock (no side_effect) so the old implementation can
    # actually succeed - the RED must be on the target behaviour (409 +
    # no side effects), not on an accidental publisher exception.
    executor._active_model_publisher = MagicMock()
    # Pre-write a valid old value so read_text_state succeeds.
    state_path = Path(executor.settings.state_dir) / "active_model.txt"
    write_text_state(state_path, "previous/model", max_bytes=512)
    executor._register_control_plane_tools()
    # After pre-writing the old file, patch write_text_state so the handler's
    # internal ``from js.utils.atomic_state import write_text_state`` receives
    # the mock.  A rejection must not cause any transient write.
    write_mock = MagicMock()
    monkeypatch.setattr(_atomic_state, "write_text_state", write_mock)

    preset = ALL_PRESETS[0]
    preset_model_id = f"{preset.id}/{preset.models[0].id}"
    arguments = {"model_id": preset_model_id}
    run_id = "model-switch-preset-reject"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_model_switch",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "model-switch-preset-call",
                "function": {
                    "name": "control_model_switch",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Switch to unconfigured preset",
            allowed_tools={"control_model_switch"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is False
    assert result.metadata.get("status_code") == 409
    assert result.metadata.get("needs_config") is True
    # active_model.txt must still hold the old value, not the preset.
    assert state_path.read_text(encoding="utf-8") == "previous/model"
    assert executor.router.preferred_model == ""
    executor._active_model_publisher.assert_not_called()
    write_mock.assert_not_called()


@pytest.mark.asyncio
async def test_model_switch_rejects_router_mapping_when_provider_not_configured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """control_model_switch must NOT trust a router mapping alone.

    Even if ``router.get_model_config`` returns a non-None value for the
    model_id, the tool must reject when the provider is not in
    ``settings.providers``.  Router mapping cannot prove configuration.
    It must not write active_model.txt, not change preferred_model, and
    not publish.  ``write_text_state`` must never be called (no transient
    writes) — the handler's internal ``from import`` receives the patch.
    """
    from js.utils import atomic_state as _atomic_state
    from js.utils.atomic_state import write_text_state

    executor = _ControlExecutor(tmp_path)
    executor.settings.providers = []
    executor.router.preferred_model = ""
    fake_config = ModelConfig(id="dynamic-model", provider="stale")
    executor.router.get_model_config = MagicMock(return_value=fake_config)
    executor.router.get_model_binding = MagicMock(return_value=("stale", fake_config))
    executor._active_model_publisher = MagicMock()
    state_path = Path(executor.settings.state_dir) / "active_model.txt"
    write_text_state(state_path, "previous/model", max_bytes=512)
    executor._register_control_plane_tools()
    # After pre-writing the old file, patch write_text_state so the handler's
    # internal ``from js.utils.atomic_state import write_text_state`` receives
    # the mock.  A rejection must not cause any transient write.
    write_mock = MagicMock()
    monkeypatch.setattr(_atomic_state, "write_text_state", write_mock)

    arguments = {"model_id": "stale/dynamic-model"}
    run_id = "model-switch-router-stale"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_model_switch",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "model-switch-router-stale-call",
                "function": {
                    "name": "control_model_switch",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Switch via stale router mapping",
            allowed_tools={"control_model_switch"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is False
    assert result.metadata.get("status_code") == 400
    assert state_path.read_text(encoding="utf-8") == "previous/model"
    assert executor.router.preferred_model == ""
    executor._active_model_publisher.assert_not_called()
    write_mock.assert_not_called()


@pytest.mark.asyncio
async def test_model_switch_rejects_unknown_model_on_configured_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """control_model_switch must reject an unknown model on a configured provider.

    The provider is configured, but the model is not declared in the
    provider's ``settings.models`` and the router has no binding for it.
    It must return 400 and not persist/publish.  ``write_text_state`` must
    never be called (no transient writes) — the handler's internal
    ``from import`` receives the patch.
    """
    from js.utils import atomic_state as _atomic_state
    from js.utils.atomic_state import write_text_state

    executor = _ControlExecutor(tmp_path)
    executor.settings.providers = [
        ModelProviderConfig(
            name="provider",
            base_url="https://models.example/v1",
            models=[ModelConfig(id="model-a", provider="provider")],
        )
    ]
    executor.router.preferred_model = ""
    executor.router.get_model_config = MagicMock(return_value=None)
    executor.router.get_model_binding = MagicMock(return_value=None)
    executor._active_model_publisher = MagicMock()
    state_path = Path(executor.settings.state_dir) / "active_model.txt"
    write_text_state(state_path, "provider/model-a", max_bytes=512)
    executor._register_control_plane_tools()
    # After pre-writing the old file, patch write_text_state so the handler's
    # internal ``from js.utils.atomic_state import write_text_state`` receives
    # the mock.  A rejection must not cause any transient write.
    write_mock = MagicMock()
    monkeypatch.setattr(_atomic_state, "write_text_state", write_mock)

    arguments = {"model_id": "provider/unknown-model"}
    run_id = "model-switch-unknown-model"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_model_switch",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "model-switch-unknown-model-call",
                "function": {
                    "name": "control_model_switch",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Switch to unknown model on configured provider",
            allowed_tools={"control_model_switch"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is False
    assert result.metadata.get("status_code") == 400
    assert state_path.read_text(encoding="utf-8") == "provider/model-a"
    assert executor.router.preferred_model == ""
    executor._active_model_publisher.assert_not_called()
    write_mock.assert_not_called()


@pytest.mark.asyncio
async def test_model_switch_allows_configured_provider_with_router_binding(
    tmp_path: Path,
) -> None:
    """control_model_switch must allow a model backed by a router binding.

    The provider is configured and ``router.get_model_binding`` returns a
    tuple whose provider matches and whose model id matches the requested
    model suffix.  This covers dynamically discovered models that are not
    in ``settings.models`` but were added at runtime.
    """
    from js.utils.atomic_state import write_text_state

    executor = _ControlExecutor(tmp_path)
    executor.settings.providers = [
        ModelProviderConfig(
            name="provider",
            base_url="https://models.example/v1",
            models=[ModelConfig(id="model-a", provider="provider")],
        )
    ]
    executor.router.preferred_model = ""
    dynamic_config = ModelConfig(id="dynamic-model", provider="provider")
    executor.router.get_model_config = MagicMock(return_value=dynamic_config)
    executor.router.get_model_binding = MagicMock(return_value=("provider", dynamic_config))
    executor.router._routing_cache = {}
    executor._active_model_publisher = MagicMock()
    state_path = Path(executor.settings.state_dir) / "active_model.txt"
    write_text_state(state_path, "provider/model-a", max_bytes=512)
    executor._register_control_plane_tools()

    arguments = {"model_id": "provider/dynamic-model"}
    run_id = "model-switch-dynamic-binding"
    token = set_runtime_context(
        _network_runtime_context(
            executor,
            tool_name="control_model_switch",
            arguments=arguments,
            run_id=run_id,
        )
    )
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "model-switch-dynamic-binding-call",
                "function": {
                    "name": "control_model_switch",
                    "arguments": json.dumps(arguments),
                },
            },
            session_id="admin-control-plane",
            run_id=run_id,
            user_input="Switch to dynamically discovered model",
            allowed_tools={"control_model_switch"},
            owner_key_hash="admin-owner",
        )
    finally:
        reset_runtime_context(token)

    assert result.success is True
    assert state_path.read_text(encoding="utf-8") == "provider/dynamic-model"
    assert executor.router.preferred_model == "provider/dynamic-model"
    executor._active_model_publisher.assert_called_once_with("provider/dynamic-model")


@pytest.mark.asyncio
async def test_control_plane_effects_get_one_time_network_lease_without_filesystem_grants(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    executor._register_control_plane_tools()
    captured_contexts: list[Any] = []
    execute = executor.registry.execute

    async def capture_execute(*args: Any, **kwargs: Any) -> ToolResult:
        captured_contexts.append(kwargs.get("execution_context"))
        return await execute(*args, **kwargs)

    executor.registry.execute = capture_execute  # type: ignore[method-assign]
    calls = [
        (
            "control_skill_install",
            {
                "source": "https://github.com/example/example-skill.git",
                "skill_id": "example-skill",
            },
        ),
        ("control_clawhub_discover", {"query": "example"}),
        ("control_clawhub_install", {"skill_id": "example-skill"}),
    ]

    for index, (tool_name, arguments) in enumerate(calls):
        run_id = f"control-run-{index}"
        token = set_runtime_context(
            _network_runtime_context(
                executor,
                tool_name=tool_name,
                arguments=arguments,
                run_id=run_id,
            )
        )
        try:
            _message, result = await executor._execute_tool_call(
                {
                    "id": f"control-{index}",
                    "function": {
                        "name": tool_name,
                        "arguments": json.dumps(arguments),
                    },
                },
                session_id="admin-control-plane",
                run_id=run_id,
                user_input="Admin approved control-plane request",
                allowed_tools={tool_name},
                owner_key_hash="admin-owner",
            )
        finally:
            reset_runtime_context(token)
        assert result.success is True

    assert len(captured_contexts) == 3
    for context in captured_contexts:
        assert context is not None
        assert context.network_policy == "allow"
        assert context.fs_roots == ()

    ledger_path = executor.settings.state_dir / "echo_tool_lease.jsonl"
    records = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
    assert [record["event_type"] for record in records].count("issue") == 3
    assert [record["event_type"] for record in records].count("consume") == 3
    issue_records = [record for record in records if record["event_type"] == "issue"]
    leases = [record["payload"]["lease"] for record in issue_records]
    assert all(lease["max_invocations"] == 1 for lease in leases)
    assert all(lease["network_policy"] == "allow" for lease in leases)
    assert all(lease["fs_roots"] == [] for lease in leases)
    assert [tuple(lease["network_hosts"]) for lease in leases] == [
        ("api.github.com", "codeload.github.com", "github.com"),
        ("api.github.com", "raw.githubusercontent.com"),
        ("api.github.com", "codeload.github.com", "github.com"),
    ]


@pytest.mark.asyncio
async def test_control_skill_install_grants_only_the_resolved_local_source(
    tmp_path: Path,
) -> None:
    executor = _ControlExecutor(tmp_path)
    executor._register_control_plane_tools()
    local_source = tmp_path / "approved-skill"
    local_source.mkdir()
    captured_contexts: list[Any] = []
    execute = executor.registry.execute

    async def capture_execute(*args: Any, **kwargs: Any) -> ToolResult:
        captured_contexts.append(kwargs["execution_context"])
        return await execute(*args, **kwargs)

    executor.registry.execute = capture_execute  # type: ignore[method-assign]
    _message, result = await executor._execute_tool_call(
        {
            "id": "local-skill-install",
            "function": {
                "name": "control_skill_install",
                "arguments": json.dumps({"source": str(local_source)}),
            },
        },
        session_id="admin-control-plane",
        run_id="local-skill-install",
        user_input="Admin approved local skill source",
        allowed_tools={"control_skill_install"},
        owner_key_hash="admin-owner",
    )

    assert result.success is True
    assert executor.skills.install.await_args.args == (str(local_source.resolve()), None)
    assert len(captured_contexts) == 1
    context = captured_contexts[0]
    assert context.network_policy == "deny"
    assert context.fs_roots == (str(local_source.resolve()),)


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["missing-skill", "approved/../approved"])
async def test_control_skill_install_rejects_invalid_local_source_before_lease(
    tmp_path: Path,
    source: str,
) -> None:
    executor = _ControlExecutor(tmp_path)
    executor._register_control_plane_tools()
    (executor.settings.workspace / "approved").mkdir()

    _message, result = await executor._execute_tool_call(
        {
            "id": "invalid-local-skill-install",
            "function": {
                "name": "control_skill_install",
                "arguments": json.dumps({"source": source}),
            },
        },
        session_id="admin-control-plane",
        run_id="invalid-local-skill-install",
        user_input="Admin approved local skill source",
        allowed_tools={"control_skill_install"},
        owner_key_hash="admin-owner",
    )

    assert result.success is False
    assert "local skill source" in result.error
    executor.skills.install.assert_not_awaited()
    assert not (executor.settings.state_dir / "echo_tool_lease.jsonl").exists()


@pytest.mark.parametrize(
    "source",
    [
        "https://gitlab.com/example/skill.git",
        "git@github.com:example/skill.git",
        "https://github.com/example/skill.git?ref=main",
    ],
)
def test_control_skill_install_rejects_non_exact_remote_sources_before_lease(
    tmp_path: Path,
    source: str,
) -> None:
    executor = _ControlExecutor(tmp_path)

    error, _arguments = executor._normalize_control_skill_install_arguments({"source": source})

    assert error is not None
    assert "remote skill source" in error.lower()


@pytest.mark.asyncio
async def test_tool_execution_context_max_bytes_uses_utf8_encoded_size(
    echo_tool_context: Any,
) -> None:
    registry = ToolRegistry(ToolLimits(), _NoopGuard())

    async def emoji_handler() -> ToolResult:
        return ToolResult(success=True, output="😀😀")

    registry.register(ToolSpec(name="emoji", description="emoji", parameters=[]), emoji_handler)
    result = await registry.execute(
        "emoji-run",
        "emoji",
        {},
        execution_context=echo_tool_context(
            run_id="emoji-run",
            tool_name="emoji",
            arguments={},
            max_bytes=7,
            registry=registry,
        ),
    )

    assert result.success is False
    assert result.error == "Echo execution context max_bytes exceeded"
