"""Web control-plane effects executed through Echo leases."""

from __future__ import annotations

import secrets
from typing import Any, cast

from fastapi import HTTPException

from js.agent.tool_executor import (
    CONTROL_EVOLUTION_ACTION_TOOL,
    CONTROL_SESSION_MUTATE_TOOL,
    CONTROL_SKILL_MUTATE_TOOL,
)
from js.config import ModelProviderConfig
from js.echo.effect_interpreter import ToolEffect
from js.tools.registry import ToolResult
from js.web.auth import memory_owner, runtime_owner
from js.web.runtime_context import web_channel


def _get_agent() -> Any:
    from js.web.server import get_agent

    return get_agent()


async def _execute_session_mutation(
    action: str,
    session_id: str,
    auth: dict[str, Any],
) -> ToolResult:
    """Run an owner-bound session mutation through the Echo tool boundary."""
    agent = _get_agent()
    runtime = agent.echo_runtime
    context = runtime.build_context(
        channel=web_channel(agent.settings, f"session_{action}"),
        owner_key_hash=runtime_owner(auth),
        role=str(auth.get("role") or "user"),
        capabilities=(CONTROL_SESSION_MUTATE_TOOL,),
    )
    _message, result = await runtime.execute_tool_effect(
        ToolEffect.from_arguments(
            CONTROL_SESSION_MUTATE_TOOL,
            {"action": action, "session_id": session_id},
            user_input=f"Apply owner-bound session action: {action}",
            allowed_tools=(CONTROL_SESSION_MUTATE_TOOL,),
        ),
        context,
    )
    return cast("ToolResult", result)


def _raise_session_mutation_error(result: ToolResult) -> None:
    if result.success:
        return
    status_code = result.metadata.get("status_code", 500)
    if not isinstance(status_code, int) or not 400 <= status_code <= 599:
        status_code = 500
    raise HTTPException(status_code, result.error or "Session update failed")


async def _execute_private_skill_mutation(
    action: str,
    payload: dict[str, Any],
    auth: dict[str, Any],
) -> dict[str, Any]:
    """Run a privileged skill mutation without journaling private payloads."""
    agent = _get_agent()
    if str(getattr(agent.settings, "product_id", "js-agent")) == "js-work":
        raise HTTPException(403, "Runtime skill mutation is disabled in JS Agent Work")
    owner = runtime_owner(auth)
    runtime = agent.echo_runtime
    context = runtime.build_context(
        channel=web_channel(agent.settings, f"skill_{action}"),
        owner_key_hash=owner,
        role=str(auth.get("role") or "admin"),
        capabilities=(CONTROL_SKILL_MUTATE_TOOL,),
    )
    payload_ref = agent.stage_skill_mutation_payload(
        owner,
        payload,
        product_id=context.product_id,
        session_id=context.session_id,
    )
    if not isinstance(payload_ref, str) or not payload_ref:
        raise HTTPException(503, "Skill mutation admission is unavailable")
    try:
        _message, result = await runtime.execute_tool_effect(
            ToolEffect.from_arguments(
                CONTROL_SKILL_MUTATE_TOOL,
                {"action": action, "payload_ref": payload_ref},
                user_input=f"Apply administrator-approved skill action: {action}",
                allowed_tools=(CONTROL_SKILL_MUTATE_TOOL,),
            ),
            context,
        )
    finally:
        agent.discard_skill_mutation_payload(
            payload_ref,
            owner,
            product_id=context.product_id,
            session_id=context.session_id,
        )
    if not result.success:
        status_code = result.metadata.get("status_code", 500)
        if not isinstance(status_code, int) or not 400 <= status_code <= 599:
            status_code = 500
        raise HTTPException(status_code, result.error or "Skill update failed")
    result_ref = result.metadata.get("result_ref")
    if not isinstance(result_ref, str) or not result_ref:
        raise HTTPException(500, "Skill result handoff failed")
    response = agent.take_skill_mutation_result(
        result_ref,
        owner,
        product_id=context.product_id,
        session_id=context.session_id,
    )
    if not isinstance(response, dict):
        raise HTTPException(500, "Skill result handoff failed")
    return response


async def _execute_evolution_action(
    action: str,
    auth: dict[str, Any],
    *,
    proposal_id: str = "",
) -> dict[str, Any]:
    """Execute one privileged evolution action through Echo."""
    agent = _get_agent()
    if str(getattr(agent.settings, "product_id", "js-agent")) == "js-work":
        raise HTTPException(403, "Evolution is disabled in JS Agent Work")
    owner = runtime_owner(auth)
    runtime = agent.echo_runtime
    context = runtime.build_context(
        channel=web_channel(agent.settings, f"evolution_{action}"),
        owner_key_hash=owner,
        role=str(auth.get("role") or "admin"),
        capabilities=(CONTROL_EVOLUTION_ACTION_TOOL,),
    )
    arguments: dict[str, Any] = {"action": action}
    if proposal_id:
        arguments["proposal_id"] = proposal_id
    _message, result = await runtime.execute_tool_effect(
        ToolEffect.from_arguments(
            CONTROL_EVOLUTION_ACTION_TOOL,
            arguments,
            user_input=f"Run administrator-approved evolution action: {action}",
            allowed_tools=(CONTROL_EVOLUTION_ACTION_TOOL,),
        ),
        context,
    )
    if not result.success:
        status_code = result.metadata.get("status_code", 500)
        if not isinstance(status_code, int) or not 400 <= status_code <= 599:
            status_code = 500
        raise HTTPException(status_code, result.error or "Evolution action failed")
    result_ref = result.metadata.get("result_ref")
    if not isinstance(result_ref, str) or not result_ref:
        raise HTTPException(500, "Evolution result handoff failed")
    response = agent.take_evolution_action_result(
        result_ref,
        owner,
        product_id=context.product_id,
        session_id=context.session_id,
    )
    if not isinstance(response, dict):
        raise HTTPException(500, "Evolution result handoff failed")
    return response


async def _execute_web_tool_effect(
    agent: Any,
    auth: dict[str, Any],
    *,
    channel: str,
    tool_name: str,
    arguments: dict[str, Any],
    user_input: str,
    control_arguments: dict[str, Any] | None = None,
    session_id: str = "",
) -> ToolResult:
    """Execute one Web control-plane action through Echo's leased tool boundary."""
    owner = memory_owner(auth) or "local-user"
    runtime = agent.echo_runtime
    runtime_context = runtime.build_context(
        channel=web_channel(agent.settings, channel),
        owner_key_hash=owner,
        session_id=session_id,
        role=str(auth.get("role") or "user"),
        capabilities=(tool_name,),
        control_arguments=control_arguments,
    )
    _message, result = await runtime.execute_tool_effect(
        ToolEffect.from_arguments(
            tool_name,
            arguments,
            user_input=user_input,
            allowed_tools=(tool_name,),
        ),
        runtime_context,
    )
    return cast("ToolResult", result)


async def _execute_provider_discovery_effect(
    agent: Any,
    auth: dict[str, Any],
    *,
    base_url: str,
    api_key: str,
    allow_private: bool,
    channel: str,
) -> ToolResult:
    """Run exact-endpoint model discovery without persisting its credential."""
    owner = memory_owner(auth) or "local-user"
    product_id = str(getattr(agent.settings, "product_id", "js-agent"))
    session_id = f"provider-discovery-{secrets.token_hex(16)}"
    api_key_ref = agent.stage_provider_discovery_key(
        api_key,
        owner_key_hash=owner,
        product_id=product_id,
        session_id=session_id,
    )
    if api_key and not api_key_ref:
        raise HTTPException(503, "Provider credential admission is unavailable")
    arguments = {
        "base_url": base_url,
        "api_key_ref": api_key_ref,
        "allow_private": allow_private,
    }
    try:
        return await _execute_web_tool_effect(
            agent,
            auth,
            channel=channel,
            tool_name="control_provider_discover",
            arguments=arguments,
            control_arguments=arguments,
            user_input="Discover models from an administrator-approved exact provider URL",
            session_id=session_id,
        )
    finally:
        agent.discard_provider_discovery_key(
            api_key_ref,
            owner_key_hash=owner,
            product_id=product_id,
            session_id=session_id,
        )


async def _execute_provider_mutation_effect(
    agent: Any,
    auth: dict[str, Any],
    *,
    action: str,
    provider: ModelProviderConfig | None = None,
    name: str = "",
    api_key: str | None = None,
    channel: str,
) -> ToolResult:
    """Run one provider write through Echo without serializing its credential."""
    owner = memory_owner(auth) or "local-user"
    product_id = str(getattr(agent.settings, "product_id", "js-agent"))
    session_id = f"provider-mutation-{secrets.token_hex(16)}"
    api_key_ref = agent.stage_provider_discovery_key(
        api_key or "",
        owner_key_hash=owner,
        product_id=product_id,
        session_id=session_id,
    )
    if api_key and not api_key_ref:
        raise HTTPException(503, "Provider credential admission is unavailable")
    arguments: dict[str, Any] = {
        "action": action,
        "name": name,
        "api_key_ref": api_key_ref,
    }
    if provider is not None:
        arguments["provider"] = provider.model_dump(
            mode="json",
            exclude={"api_key", "api_key_env"},
        )
    try:
        return await _execute_web_tool_effect(
            agent,
            auth,
            channel=channel,
            tool_name="control_provider_mutate",
            arguments=arguments,
            user_input="Apply an administrator-approved provider configuration mutation",
            session_id=session_id,
        )
    finally:
        agent.discard_provider_discovery_key(
            api_key_ref,
            owner_key_hash=owner,
            product_id=product_id,
            session_id=session_id,
        )


async def _execute_fleet_config_effect(
    agent: Any,
    auth: dict[str, Any],
    *,
    config: dict[str, str],
    channel: str,
) -> ToolResult:
    """Apply one runtime-owned Fleet configuration through Echo."""
    arguments = {"config": dict(config)}
    return await _execute_web_tool_effect(
        agent,
        auth,
        channel=channel,
        tool_name="control_fleet_configure",
        arguments=arguments,
        user_input="Apply an administrator-approved Fleet model configuration",
    )


def _raise_control_tool_error(result: ToolResult, *, default_status: int) -> None:
    if result.success:
        return
    status_code = result.metadata.get("status_code", default_status)
    if not isinstance(status_code, int) or status_code < 400 or status_code > 599:
        status_code = default_status
    raise HTTPException(status_code, result.error or "Echo control-plane tool failed")
