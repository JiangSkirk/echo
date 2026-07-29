from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.config import JSSettings, SecurityConfig
from js.echo.attachment_gate import (
    echo_attachment_scope_enabled,
    owner_slug,
    session_slug,
    validate_agent_attachment_path,
)
from js.echo.turn_context import current_owner_key_hash, runtime_partition_key
from js.echo.turn_runtime import (
    EchoBackpressureError,
    EchoRuntime,
    TurnRequest,
    run_echo_turn,
)


class _AdmitPulse:
    def __init__(self) -> None:
        self.channels: list[str] = []

    def observe(self, **_kwargs: Any) -> Any:
        self.channels.append(str(_kwargs.get("channel") or ""))
        return SimpleNamespace(admitted=True)


class _AgentLoop:
    def __init__(self, agent: _Agent, request: TurnRequest) -> None:
        self.agent = agent
        self.request = request

    async def execute(self) -> Any:
        return await self.agent.run(
            self.request.message,
            session_id=self.request.context.session_id,
            attachments=list(self.request.attachments),
        )


class _Agent:
    def __init__(self, tmp_path: Path, *, product_id: str = "js-agent") -> None:
        self.settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            echo_engine="on",
        )
        object.__setattr__(self.settings, "product_id", product_id)
        self.settings.workspace.mkdir(parents=True, exist_ok=True)
        self.calls: list[dict[str, Any]] = []
        self._lane_executor = None
        self.pulse = _AdmitPulse()
        self.echo_runtime = EchoRuntime(
            self,
            pulse_runtime=self.pulse,
            turn_loop_factory=lambda agent, request: _AgentLoop(agent, request),
        )

    async def run(self, message: str, **kwargs: Any) -> Any:
        self.calls.append(
            {
                "message": message,
                "kwargs": kwargs,
                "owner": current_owner_key_hash(),
            }
        )
        return SimpleNamespace(status="completed", session_id=kwargs.get("session_id"))


class _CaptureLane:
    def __init__(self) -> None:
        self.keys: list[str] = []

    async def submit(self, *, session_id: str, coro: Any, **_kwargs: Any) -> Any:
        self.keys.append(session_id)
        return await coro()


@pytest.mark.asyncio
async def test_run_echo_turn_sets_owner_and_allows_scoped_upload(tmp_path: Path) -> None:
    agent = _Agent(tmp_path)
    owner = "owner-a"
    session = "session-a"
    attachment = (
        agent.settings.workspace
        / "uploads"
        / owner_slug(owner)
        / session_slug(session)
        / "note.txt"
    )
    attachment.parent.mkdir(parents=True)
    attachment.write_text("hello", encoding="utf-8")
    relative = str(attachment.relative_to(agent.settings.workspace))

    state = await run_echo_turn(
        agent,
        "summarize",
        channel="unit",
        owner_key_hash=owner,
        session_id=session,
        attachments=[relative],
    )

    assert state.status == "completed"
    assert agent.calls[0]["owner"] == owner
    assert agent.calls[0]["kwargs"]["attachments"] == [relative]


@pytest.mark.asyncio
async def test_same_session_id_uses_distinct_owner_lanes(tmp_path: Path) -> None:
    agent = _Agent(tmp_path)
    lane = _CaptureLane()
    agent._lane_executor = lane

    await run_echo_turn(
        agent,
        "owner a",
        channel="unit",
        owner_key_hash="owner-a",
        session_id="shared-session",
    )
    await run_echo_turn(
        agent,
        "owner b",
        channel="unit",
        owner_key_hash="owner-b",
        session_id="shared-session",
    )

    assert len(lane.keys) == 2
    assert lane.keys[0] != lane.keys[1]
    assert agent.pulse.channels[0] != agent.pulse.channels[1]


@pytest.mark.asyncio
async def test_same_owner_and_session_use_distinct_product_partition_cancel_and_lane_keys(
    tmp_path: Path,
) -> None:
    owner = "owner-a"
    session = "shared-session"
    agent = _Agent(tmp_path / "agent", product_id="js-agent")
    work = _Agent(tmp_path / "work", product_id="js-work")
    agent_lane = _CaptureLane()
    work_lane = _CaptureLane()
    agent._lane_executor = agent_lane
    work._lane_executor = work_lane

    agent_partition = runtime_partition_key("js-agent", owner, session)
    work_partition = runtime_partition_key("js-work", owner, session)
    assert agent_partition != work_partition

    agent_cancel_tokens = {agent_partition: object()}
    work_cancel_tokens = {work_partition: object()}
    assert set(agent_cancel_tokens).isdisjoint(work_cancel_tokens)

    await run_echo_turn(
        agent,
        "agent request",
        channel="unit",
        owner_key_hash=owner,
        session_id=session,
    )
    await run_echo_turn(
        work,
        "work request",
        channel="unit",
        owner_key_hash=owner,
        session_id=session,
    )

    assert agent_lane.keys == [agent_partition]
    assert work_lane.keys == [work_partition]


@pytest.mark.asyncio
async def test_run_echo_turn_rejects_cross_session_upload(tmp_path: Path) -> None:
    agent = _Agent(tmp_path)
    owner = "owner-a"
    attachment = (
        agent.settings.workspace
        / "uploads"
        / owner_slug(owner)
        / session_slug("session-b")
        / "note.txt"
    )
    attachment.parent.mkdir(parents=True)
    attachment.write_text("hello", encoding="utf-8")

    with pytest.raises(PermissionError, match="session"):
        await run_echo_turn(
            agent,
            "summarize",
            channel="unit",
            owner_key_hash=owner,
            session_id="session-a",
            attachments=[str(attachment.relative_to(agent.settings.workspace))],
        )

    assert agent.calls == []


def test_attachment_scope_uses_safety_wrapper_when_echo_env_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")

    assert echo_attachment_scope_enabled() is True


def test_attachment_scope_rejects_plain_workspace_when_echo_on(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    plain_file = workspace / "note.txt"
    plain_file.write_text("secret", encoding="utf-8")

    with pytest.raises(PermissionError, match="workspace attachment access denied"):
        validate_agent_attachment_path(
            workspace=workspace,
            path="note.txt",
            owner_key_hash="owner-a",
            session_id="session-a",
        )


def test_build_context_without_explicit_capabilities_uses_registry_tools(
    tmp_path: Path,
) -> None:
    agent = SimpleNamespace(
        settings=JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
        ),
        registry=SimpleNamespace(
            list_tools=lambda: [
                SimpleNamespace(name="file_read"),
                SimpleNamespace(name="file_list"),
            ]
        ),
        _current_allowed_tools=set(),
    )
    runtime = EchoRuntime(agent, pulse_runtime=_AdmitPulse())

    inherited = runtime.build_context(channel="unit", owner_key_hash="owner-a")
    denied = runtime.build_context(
        channel="unit",
        owner_key_hash="owner-a",
        capabilities=(),
    )

    assert inherited.capabilities == ("file_list", "file_read")
    assert denied.capabilities == ()
    assert inherited.session_id
    assert inherited.deadline_ms is not None
    assert inherited.cancel_token is not None
    assert inherited.cancel_token.is_set() is False


def test_build_context_inherits_only_explicit_network_allowlist(tmp_path: Path) -> None:
    disabled_agent = SimpleNamespace(
        settings=JSSettings(
            workspace=tmp_path / "disabled-workspace",
            state_dir=tmp_path / "disabled-state",
            security=SecurityConfig(
                network_enabled=False,
                network_allowlist=["example.com"],
            ),
        ),
        registry=SimpleNamespace(list_tools=lambda: []),
        _current_allowed_tools=set(),
    )
    enabled_agent = SimpleNamespace(
        settings=JSSettings(
            workspace=tmp_path / "enabled-workspace",
            state_dir=tmp_path / "enabled-state",
            security=SecurityConfig(
                network_enabled=True,
                network_allowlist=["Example.COM."],
            ),
        ),
        registry=SimpleNamespace(list_tools=lambda: []),
        _current_allowed_tools=set(),
    )

    disabled = EchoRuntime(disabled_agent, pulse_runtime=_AdmitPulse()).build_context(
        channel="unit",
        owner_key_hash="owner-a",
    )
    enabled = EchoRuntime(enabled_agent, pulse_runtime=_AdmitPulse()).build_context(
        channel="unit",
        owner_key_hash="owner-a",
    )

    assert disabled.network_allowlist == ()
    assert enabled.network_allowlist == ("example.com",)


def test_build_context_enforces_worker_runtime_ceiling(tmp_path: Path) -> None:
    cancel_token = asyncio.Event()
    deadline_ms = int(time.monotonic() * 1000) + 30_000
    agent = SimpleNamespace(
        settings=JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            security=SecurityConfig(
                network_enabled=True,
                network_allowlist=["allowed.example", "blocked.example"],
            ),
        ),
        registry=SimpleNamespace(
            list_tools=lambda: [
                SimpleNamespace(name="file_read"),
                SimpleNamespace(name="file_write"),
            ]
        ),
        _current_allowed_tools=set(),
        _role="user",
        _work_profile="restricted",
        _echo_role_ceiling="user",
        _echo_profile_ceiling="restricted",
        _echo_capability_ceiling=frozenset({"file_read"}),
        _echo_network_allowlist_ceiling=frozenset({"allowed.example"}),
        _echo_deadline_ceiling_ms=deadline_ms,
        _echo_cancel_token=cancel_token,
    )
    runtime = EchoRuntime(agent, pulse_runtime=_AdmitPulse())

    context = runtime.build_context(channel="fleet", owner_key_hash="owner-a")

    assert context.role == "user"
    assert context.profile == "restricted"
    assert context.capabilities == ("file_read",)
    assert context.network_allowlist == ("allowed.example",)
    assert context.deadline_ms == deadline_ms
    assert context.cancel_token is cancel_token

    with pytest.raises(PermissionError, match="role"):
        runtime.build_context(
            channel="fleet",
            owner_key_hash="owner-a",
            role="admin",
        )
    with pytest.raises(PermissionError, match="profile"):
        runtime.build_context(
            channel="fleet",
            owner_key_hash="owner-a",
            profile="default",
        )
    with pytest.raises(PermissionError, match="capabilities"):
        runtime.build_context(
            channel="fleet",
            owner_key_hash="owner-a",
            capabilities=("file_write",),
        )


def test_runtime_rejects_mutated_context_identity_even_when_paths_match(
    tmp_path: Path,
) -> None:
    agent = SimpleNamespace(
        settings=JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
        ),
        registry=SimpleNamespace(list_tools=lambda: [SimpleNamespace(name="file_read")]),
        _current_allowed_tools=set(),
    )
    runtime = EchoRuntime(agent, pulse_runtime=_AdmitPulse())
    context = runtime.build_context(
        channel="unit",
        owner_key_hash="owner-a",
        role="user",
        capabilities=("file_read",),
    )

    with pytest.raises(PermissionError, match="authority"):
        runtime._validate_context_scope(replace(context, role="admin"))


@pytest.mark.parametrize(
    ("field_name", "oversized_value", "expected_error"),
    [
        ("channel", "x" * 513, "identity field exceeds"),
        (
            "capabilities",
            tuple(f"capability-{index}" for index in range(257)),
            "capability count exceeds",
        ),
        (
            "network_allowlist",
            tuple(f"host-{index}.example" for index in range(257)),
            "network host count exceeds",
        ),
        ("control_scope", "x" * 129, "control scope exceeds"),
    ],
)
def test_runtime_rejects_oversized_context_envelopes_before_authority_checks(
    tmp_path: Path,
    field_name: str,
    oversized_value: Any,
    expected_error: str,
) -> None:
    agent = SimpleNamespace(
        settings=JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
        ),
        registry=SimpleNamespace(list_tools=lambda: []),
        _current_allowed_tools=set(),
    )
    runtime = EchoRuntime(agent, pulse_runtime=_AdmitPulse())
    context = runtime.build_context(channel="unit", owner_key_hash="owner-a")

    with pytest.raises(PermissionError, match=expected_error):
        runtime._validate_context_scope(
            replace(context, **{field_name: oversized_value})
        )


def test_context_builder_refuses_oversized_identity_before_signing(
    tmp_path: Path,
) -> None:
    agent = SimpleNamespace(
        settings=JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
        ),
        registry=SimpleNamespace(list_tools=lambda: []),
        _current_allowed_tools=set(),
    )
    runtime = EchoRuntime(agent, pulse_runtime=_AdmitPulse())

    with pytest.raises(PermissionError, match="identity field exceeds"):
        runtime.build_context(
            channel="x" * 513,
            owner_key_hash="owner-a",
        )


def test_exact_provider_control_context_is_bound_and_single_use(tmp_path: Path) -> None:
    agent = SimpleNamespace(
        settings=JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
        ),
        registry=SimpleNamespace(
            list_tools=lambda: [SimpleNamespace(name="control_provider_discover")]
        ),
        _current_allowed_tools=set(),
    )
    runtime = EchoRuntime(agent, pulse_runtime=_AdmitPulse())
    arguments = {
        "base_url": "https://models.example/v1",
        "api_key_ref": "opaque-ref",
        "allow_private": False,
    }
    context = runtime.build_context(
        channel="provider-discover",
        owner_key_hash="owner-a",
        role="admin",
        capabilities=("control_provider_discover",),
        control_arguments=arguments,
    )

    runtime._validate_context_scope(context, consume_control_context=True)
    with pytest.raises(PermissionError, match="scope"):
        runtime._validate_context_scope(context, consume_control_context=True)


def test_provider_control_context_capacity_does_not_evict_live_authority(
    tmp_path: Path,
) -> None:
    agent = SimpleNamespace(
        settings=JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
        ),
        registry=SimpleNamespace(
            list_tools=lambda: [SimpleNamespace(name="control_provider_discover")]
        ),
        _current_allowed_tools=set(),
    )
    runtime = EchoRuntime(agent, pulse_runtime=_AdmitPulse())
    arguments = {
        "base_url": "https://models.example/v1",
        "api_key_ref": "opaque-ref",
        "allow_private": False,
    }
    contexts = [
        runtime.build_context(
            channel="provider-discover",
            owner_key_hash="owner-a",
            run_id=f"control-{index}",
            role="admin",
            capabilities=("control_provider_discover",),
            control_arguments=arguments,
        )
        for index in range(128)
    ]

    with pytest.raises(EchoBackpressureError, match="capacity"):
        runtime.build_context(
            channel="provider-discover",
            owner_key_hash="owner-a",
            run_id="control-overflow",
            role="admin",
            capabilities=("control_provider_discover",),
            control_arguments=arguments,
        )

    runtime._validate_context_scope(
        contexts[0],
        consume_control_context=True,
    )
    replacement = runtime.build_context(
        channel="provider-discover",
        owner_key_hash="owner-a",
        run_id="control-replacement",
        role="admin",
        capabilities=("control_provider_discover",),
        control_arguments=arguments,
    )
    runtime._validate_context_scope(replacement, consume_control_context=True)


def test_provider_control_context_stays_single_use_when_base_scope_matches(
    tmp_path: Path,
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
    )
    settings.security.network_enabled = True
    settings.security.network_allowlist = ["models.example"]
    agent = SimpleNamespace(
        settings=settings,
        registry=SimpleNamespace(
            list_tools=lambda: [SimpleNamespace(name="control_provider_discover")]
        ),
        _current_allowed_tools=set(),
    )
    runtime = EchoRuntime(agent, pulse_runtime=_AdmitPulse())
    arguments = {
        "base_url": "https://models.example/v1",
        "api_key_ref": "opaque-ref",
        "allow_private": False,
    }
    context = runtime.build_context(
        channel="provider-discover",
        owner_key_hash="owner-a",
        role="admin",
        capabilities=("control_provider_discover",),
        control_arguments=arguments,
    )

    runtime._validate_context_scope(context, consume_control_context=True)
    with pytest.raises(PermissionError, match="scope"):
        runtime._validate_context_scope(context, consume_control_context=True)
