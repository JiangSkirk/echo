"""Regression coverage for JS Agent Work fleet worker isolation."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from js.config import JSSettings
from js.echo.turn_context import RuntimeContext, reset_runtime_context, set_runtime_context
from js.orchestration.fleet import AgentInstance
from js_work.agent_factory import WORK_SYSTEM_APPENDIX, create_work_agent, create_work_fleet
from js_work.config import load_work_settings
from js_work.tools import WorkToolProfile, allowed_tools_for_profile

_PARENT_CAPABILITIES = {
    "file_read",
    "file_view",
    "file_list",
    "file_search",
    "code_search",
}


def test_create_work_fleet_rejects_main_settings(tmp_path: Path) -> None:
    settings = JSSettings(
        workspace=tmp_path / "main-workspace",
        state_dir=tmp_path / "main-state",
    )

    with pytest.raises(TypeError, match="WorkSettings"):
        create_work_fleet(  # type: ignore[arg-type]
            settings=settings,
            profile=WorkToolProfile.SAFE,
        )


def test_create_work_fleet_deep_copies_without_mutating_input(tmp_path: Path) -> None:
    settings = load_work_settings(home=tmp_path)
    settings.pipeline.enabled = True
    before = settings.model_dump()

    fleet = create_work_fleet(settings=settings, profile=WorkToolProfile.SAFE)

    assert settings.model_dump() == before
    assert fleet.settings is not settings
    assert fleet.settings.pipeline is not settings.pipeline


def test_create_work_fleet_revalidates_mutated_work_paths(tmp_path: Path) -> None:
    settings = load_work_settings(home=tmp_path)
    main_workspace = tmp_path / ".js" / "workspace"
    object.__setattr__(settings, "workspace", main_workspace)

    with pytest.raises(ValueError, match="overlap"):
        create_work_fleet(settings=settings, profile=WorkToolProfile.SAFE)

    assert not main_workspace.exists()


def _parent_context(tmp_path: Path, profile: WorkToolProfile) -> RuntimeContext:
    return RuntimeContext(
        product_id="js-work",
        channel="js_work_test",
        owner_key_hash="work-owner",
        session_id="work-session",
        run_id="work-run",
        role="local-user",
        profile=profile.value,
        capabilities=tuple(
            sorted(
                _PARENT_CAPABILITIES | {"file_write", "shell", "python", "desktop_click"}
            )
        ),
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
    )


def _spawn_work_worker(
    tmp_path: Path, profile: WorkToolProfile
) -> tuple[RuntimeContext, AgentInstance]:
    settings = load_work_settings(home=tmp_path)
    parent_agent = create_work_agent(settings=settings, profile=profile)
    context = _parent_context(tmp_path, profile)
    token = set_runtime_context(context)
    try:
        worker = create_work_fleet(
            settings=settings,
            profile=WorkToolProfile(cast("Any", parent_agent)._work_profile),
        )._spawn_worker()
    finally:
        reset_runtime_context(token)
    return context, worker


def test_safe_work_fleet_worker_preserves_work_identity_and_capability_intersection(
    tmp_path: Path,
) -> None:
    parent, worker = _spawn_work_worker(tmp_path, WorkToolProfile.SAFE)
    worker_agent = cast("Any", worker.agent)

    assert cast("Any", worker.agent.settings).product_id == parent.product_id
    assert worker_agent._work_profile == parent.profile
    assert worker_agent._fleet_parent_context == parent
    assert WORK_SYSTEM_APPENDIX.strip() in worker_agent.SYSTEM_PROMPT

    tool_names = {tool.name for tool in worker.agent.registry.list_tools()}
    expected = allowed_tools_for_profile(WorkToolProfile.SAFE) & set(parent.capabilities)
    assert tool_names == expected
    assert not {
        "file_write",
        "file_edit",
        "shell",
        "python",
        "browser_fetch",
        "desktop_click",
    } & tool_names


@pytest.mark.parametrize("profile", [WorkToolProfile.EXECUTE, WorkToolProfile.OFFICE])
def test_work_fleet_worker_never_broadens_parent_capabilities(
    tmp_path: Path,
    profile: WorkToolProfile,
) -> None:
    parent, worker = _spawn_work_worker(tmp_path, profile)
    worker_agent = cast("Any", worker.agent)

    tool_names = {tool.name for tool in worker.agent.registry.list_tools()}
    assert tool_names <= allowed_tools_for_profile(profile)
    assert tool_names <= set(parent.capabilities)
    assert worker.capabilities == sorted(tool_names)
    lineage: RuntimeContext = worker_agent._fleet_parent_context
    assert lineage.run_id == "work-run"
    assert lineage.owner_key_hash == "work-owner"
    assert lineage.session_id == "work-session"


def test_work_runtime_context_to_fleet_worker_is_nonempty_and_only_narrows(
    tmp_path: Path,
) -> None:
    settings = load_work_settings(home=tmp_path)
    parent_agent = create_work_agent(settings=settings, profile=WorkToolProfile.EXECUTE)
    context = parent_agent.echo_runtime.build_context(
        channel="js_work_real_run",
        owner_key_hash="work-owner",
        session_id="work-session",
        run_id="work-run",
    )

    token = set_runtime_context(context)
    try:
        worker = create_work_fleet(
            settings=parent_agent.settings,
            profile=WorkToolProfile.EXECUTE,
        )._spawn_worker()
    finally:
        reset_runtime_context(token)

    worker_tools = {tool.name for tool in worker.agent.registry.list_tools()}
    assert context.capabilities
    assert worker_tools
    assert worker_tools == set(worker.capabilities)
    assert worker_tools <= set(context.capabilities)


def test_authenticated_work_fleet_never_exposes_host_code_tools(tmp_path: Path) -> None:
    settings = load_work_settings(home=tmp_path)
    context = _parent_context(tmp_path, WorkToolProfile.EXECUTE)
    token = set_runtime_context(context)
    try:
        worker = create_work_fleet(
            settings=settings,
            profile=WorkToolProfile.EXECUTE,
            allow_host_code_tools=False,
        )._spawn_worker()
    finally:
        reset_runtime_context(token)

    worker_tools = {tool.name for tool in worker.agent.registry.list_tools()}
    assert "shell" not in worker_tools
    assert "python" not in worker_tools
