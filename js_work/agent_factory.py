"""Factory for isolated, Echo-backed JS Agent Work agents."""

from __future__ import annotations

import threading
from pathlib import Path

from js.agent import JSAgent
from js.echo.turn_context import RuntimeContext
from js.orchestration.fleet import AgentFleet, AgentRole
from js_work.config import WorkSettings, load_work_settings, work_feature_config
from js_work.document_tools import WorkDocumentTools
from js_work.file_scope import WorkOwnerFileScope
from js_work.routines.tools import WorkRoutineTools
from js_work.scoped_tools import install_work_file_scope
from js_work.tools import WorkToolProfile, allowed_tools_for_profile, apply_tool_profile

WORK_SYSTEM_APPENDIX = """

## JS Agent Work Boundary
You are running inside JS Agent Work, a work-focused Echo space.
- Do not use or mention JS Agent skills.
- Prefer search and built-in tools for work tasks.
- Use only root-relative Work file handles issued for this owner and session.
- Never submit absolute paths or access another owner/session; ask for an upload handle instead.
- For complex parallel work, use the fleet collaboration tool when it is available.
"""

_HOST_CODE_TOOLS = {"shell", "python"}


def _work_fs_roots(
    workspace: Path,
    owner_key_hash: str,
    session_id: str,
) -> tuple[Path, ...]:
    scope = WorkOwnerFileScope(
        workspace,
        owner=owner_key_hash,
        session_id=session_id,
    )
    return (scope.private_root, scope.owned_upload_root)


def _install_work_fs_roots_resolver(agent: JSAgent) -> None:
    workspace = Path(agent.settings.workspace)
    object.__setattr__(
        agent,
        "_echo_fs_roots_resolver",
        lambda owner_key_hash, session_id: _work_fs_roots(
            workspace,
            owner_key_hash,
            session_id,
        ),
    )


def remove_host_code_tools(agent: JSAgent) -> None:
    """Remove tools that cannot enforce per-owner operating-system isolation."""
    for tool_name in _HOST_CODE_TOOLS:
        agent.registry.unregister(tool_name)
    agent._current_allowed_tools = {tool.name for tool in agent.registry.list_tools()}


def _configure_work_fleet_worker(
    agent: JSAgent,
    role: AgentRole,
    parent_context: RuntimeContext | None,
    *,
    profile: WorkToolProfile,
    allow_host_code_tools: bool,
) -> None:
    """Apply the parent's Work identity and a non-expanding tool envelope."""
    effective_profile = profile
    allowed_tools = allowed_tools_for_profile(profile)

    if parent_context is not None:
        object.__setattr__(agent, "_fleet_parent_context", parent_context)
        if parent_context.product_id != str(getattr(agent.settings, "product_id", "js-agent")):
            allowed_tools = set()
        else:
            try:
                effective_profile = WorkToolProfile(parent_context.profile)
            except ValueError:
                allowed_tools = set()
            else:
                allowed_tools &= allowed_tools_for_profile(effective_profile)
                allowed_tools &= set(parent_context.capabilities)

    object.__setattr__(agent, "_work_profile", effective_profile.value)
    _install_work_fs_roots_resolver(agent)
    agent.SYSTEM_PROMPT = agent.SYSTEM_PROMPT + WORK_SYSTEM_APPENDIX
    WorkRoutineTools(
        workspace=agent.settings.workspace,
        state_dir=agent.settings.state_dir,
    ).register_all(agent.registry)
    WorkDocumentTools(workspace=agent.settings.workspace).register_all(agent.registry)
    install_work_file_scope(
        agent.registry,
        workspace=agent.settings.workspace,
        limits=agent.settings.tools,
    )
    apply_tool_profile(agent.registry, effective_profile)
    for tool in list(agent.registry.list_tools()):
        if tool.name not in allowed_tools:
            agent.registry.unregister(tool.name)
    if not allow_host_code_tools:
        remove_host_code_tools(agent)
    agent._current_allowed_tools = {tool.name for tool in agent.registry.list_tools()}


def create_work_fleet(
    *,
    settings: WorkSettings,
    profile: WorkToolProfile,
    allow_host_code_tools: bool = False,
) -> AgentFleet:
    """Create a Work-only fleet whose workers cannot exceed the parent envelope."""
    if not isinstance(settings, WorkSettings):
        raise TypeError("create_work_fleet accepts only WorkSettings")

    fleet_settings = settings.model_copy(deep=True)
    fleet_settings._validate_work_isolation()

    def _configure_worker(
        agent: JSAgent,
        role: AgentRole,
        parent_context: RuntimeContext | None,
    ) -> None:
        _configure_work_fleet_worker(
            agent,
            role,
            parent_context,
            profile=profile,
            allow_host_code_tools=allow_host_code_tools,
        )

    return AgentFleet(
        fleet_settings,
        max_workers=4,
        skills=None,
        inherit_skills=False,
        worker_configurer=_configure_worker,
    )


def create_work_agent(
    *,
    settings: WorkSettings | None = None,
    profile: WorkToolProfile = WorkToolProfile.EXECUTE,
    allow_host_code_tools: bool = False,
) -> JSAgent:
    """Create a Work agent with skills/evolution disabled and Echo gates enabled."""
    if settings is None:
        source_settings = load_work_settings()
    elif isinstance(settings, WorkSettings):
        source_settings = settings
    else:
        raise TypeError("create_work_agent accepts only WorkSettings or None")

    work_settings = source_settings.model_copy(deep=True)
    work_settings._validate_work_isolation()
    work_settings.features = work_feature_config()
    work_settings.pipeline.enabled = False
    work_settings.echo_engine = "on"

    agent = JSAgent(work_settings)
    object.__setattr__(agent, "_work_profile", profile.value)
    _install_work_fs_roots_resolver(agent)
    agent.SYSTEM_PROMPT = agent.SYSTEM_PROMPT + WORK_SYSTEM_APPENDIX

    work_fleet: AgentFleet | None = None
    work_fleet_lock = threading.Lock()

    def _fleet_factory() -> AgentFleet:
        nonlocal work_fleet
        if work_fleet is not None:
            return work_fleet
        with work_fleet_lock:
            if work_fleet is None:
                work_fleet = create_work_fleet(
                    settings=work_settings,
                    profile=profile,
                    allow_host_code_tools=allow_host_code_tools,
                )
        return work_fleet

    agent.register_fleet_tool(_fleet_factory)
    agent.set_fleet_getter(_fleet_factory)
    WorkRoutineTools(
        workspace=work_settings.workspace,
        state_dir=work_settings.state_dir,
    ).register_all(agent.registry)
    WorkDocumentTools(workspace=work_settings.workspace).register_all(agent.registry)
    install_work_file_scope(
        agent.registry,
        workspace=work_settings.workspace,
        limits=work_settings.tools,
    )
    apply_tool_profile(agent.registry, profile)
    if not allow_host_code_tools:
        remove_host_code_tools(agent)
    agent._current_allowed_tools = {tool.name for tool in agent.registry.list_tools()}
    return agent
