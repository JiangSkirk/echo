"""Desktop-control API router — status, toggle, and the setup wizard.

Extracted from ``server.py``.  macOS desktop automation (screenshot, click,
keyboard, window/app control) is opt-in and gated behind a setup wizard plus
per-action approval; these endpoints drive that flow.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.agent.tool_executor import (
    CONTROL_DESKTOP_STATE_TOOL,
    DESKTOP_WIZARD_ACTION_TOOL,
    DESKTOP_WIZARD_ACTIONS,
)
from js.echo.effect_interpreter import ToolEffect
from js.web.auth import require_admin, require_auth_dep, runtime_owner
from js.web.deps import get_agent, get_settings
from js.web.runtime_context import web_channel

router = APIRouter(tags=["desktop"])


def _forbid_work_desktop_endpoint() -> None:
    if str(getattr(get_settings(), "product_id", "js-agent")) == "js-work":
        raise HTTPException(
            status_code=403,
            detail="Desktop endpoints are unavailable in JS Agent Work",
        )


async def _mutate_desktop_state(
    action: str,
    auth: dict[str, Any],
) -> dict[str, Any]:
    """Run one administrator-confirmed desktop mutation through Echo."""
    agent = get_agent()
    runtime = agent.echo_runtime
    runtime_context = runtime.build_context(
        channel=web_channel(agent.settings, "desktop_state"),
        owner_key_hash=runtime_owner(auth),
        role=str(auth.get("role") or "admin"),
        capabilities=(CONTROL_DESKTOP_STATE_TOOL,),
    )
    _message, result = await runtime.execute_tool_effect(
        ToolEffect.from_arguments(
            CONTROL_DESKTOP_STATE_TOOL,
            {"action": action},
            user_input=f"Apply desktop state action: {action}",
            allowed_tools=(CONTROL_DESKTOP_STATE_TOOL,),
        ),
        runtime_context,
    )
    if not result.success:
        status_code = result.metadata.get("status_code", 500)
        if not isinstance(status_code, int) or not 400 <= status_code <= 599:
            status_code = 500
        raise HTTPException(status_code, result.error or "Desktop state update failed")
    return dict(result.metadata)


@router.get("/api/desktop/status")
async def desktop_status(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    _forbid_work_desktop_endpoint()
    agent = get_agent()
    from js.tools.desktop.permissions import PermissionChecker
    is_macos = PermissionChecker.is_macos()
    has_tools = (
        agent._desktop_tools is not None
        and getattr(agent._desktop_tools, 'available', False)
    )
    init_error = ""
    if agent._desktop_tools is not None:
        init_error = getattr(agent._desktop_tools, 'init_error', '')
    return {
        "enabled": agent.settings.desktop_control_enabled,
        "available": is_macos,
        "permissions": PermissionChecker.get_status() if is_macos else {},
        "tools_registered": has_tools,
        "init_error": init_error,
    }


@router.post("/api/desktop/toggle")
async def desktop_toggle(auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    _forbid_work_desktop_endpoint()
    metadata = await _mutate_desktop_state("toggle", auth)
    return {"success": True, **metadata}


@router.get("/api/desktop/wizard")
async def desktop_wizard(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """First-use setup wizard: detect deps + permissions, guide installation.

    This endpoint is designed to ALWAYS return 200 with actionable info,
    even when the server is in a degraded state.  The frontend relies on
    this to show specific guidance (missing deps, missing perms, etc.).
    """
    _forbid_work_desktop_endpoint()
    try:
        from js.tools.desktop.wizard import run_wizard
        state = run_wizard()
    except Exception as e:
        return {
            "ready": False, "overall_status": "error",
            "steps": [{"name": "error", "title": "向导引擎故障", "status": "error",
                       "detail": str(e)[:200], "action_label": "", "action_type": "none"}],
            "enabled": False, "write_tools_enabled": False,
            "can_install_cliclick": False, "install_summary": "",
        }

    try:
        agent = get_agent()
    except Exception:
        agent = None
    has_tools = agent is not None and agent._desktop_tools is not None
    enabled = agent is not None and agent.settings.desktop_control_enabled and has_tools
    write_enabled = (
        has_tools
        and agent is not None
        and agent._desktop_tools is not None
        and agent._desktop_tools.write_tools_registered
    )
    return {
        "ready": state.ready,
        "overall_status": state.overall_status,
        "steps": [
            {"name": s.name, "title": s.title, "status": s.status, "detail": s.detail,
             "action_label": s.action_label, "action_type": s.action_type}
            for s in state.steps
        ],
        "enabled": enabled,
        "write_tools_enabled": write_enabled,
        "can_install_cliclick": state.can_install_cliclick,
        "install_summary": state.install_summary,
    }


@router.post("/api/desktop/wizard/action")
async def desktop_wizard_action(payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    """Execute an admin-confirmed wizard action through the Echo tool boundary."""
    _forbid_work_desktop_endpoint()
    from js.tools.desktop.wizard import run_wizard

    agent = get_agent()
    action_type = payload.get("action_type", "")
    if not isinstance(action_type, str) or action_type not in DESKTOP_WIZARD_ACTIONS:
        return {"success": False, "error": "Unsupported desktop wizard action"}

    runtime = agent.echo_runtime
    runtime_context = runtime.build_context(
        channel=web_channel(agent.settings, "desktop_wizard"),
        owner_key_hash=runtime_owner(auth),
        role=str(auth.get("role") or "admin"),
        capabilities=(DESKTOP_WIZARD_ACTION_TOOL,),
    )
    _message, tool_result = await runtime.execute_tool_effect(
        ToolEffect.from_arguments(
            DESKTOP_WIZARD_ACTION_TOOL,
            {"action_type": action_type},
            user_input=f"Desktop wizard action: {action_type}",
            allowed_tools=(DESKTOP_WIZARD_ACTION_TOOL,),
        ),
        runtime_context,
    )
    if tool_result.success:
        try:
            result = json.loads(tool_result.output)
        except (TypeError, json.JSONDecodeError):
            result = {"success": False, "error": "Desktop wizard action returned invalid result"}
        if not isinstance(result, dict):
            result = {"success": False, "error": "Desktop wizard action returned invalid result"}
    else:
        result = {"success": False, "error": tool_result.error}

    # Re-run wizard to refresh state
    state = run_wizard()
    result["wizard"] = {
        "ready": state.ready,
        "overall_status": state.overall_status,
        "steps": [
            {"name": s.name, "status": s.status}
            for s in state.steps
        ],
    }
    return result


@router.post("/api/desktop/wizard/enable")
async def desktop_wizard_enable(auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    """Enable desktop control after wizard is ready.

    First stage: only read-only tools (screenshot, list, permissions, operation log).
    Write tools require separate explicit confirmation via /api/desktop/wizard/enable-writes.
    """
    _forbid_work_desktop_endpoint()
    metadata = await _mutate_desktop_state("enable_read_only", auth)
    count = metadata.get("tools_count", 0)
    return {
        "success": True,
        **metadata,
        "message": f"已启用 {count} 个只读/诊断工具。写操作工具需要二次确认。",
    }


@router.post("/api/desktop/wizard/enable-writes")
async def desktop_wizard_enable_writes(auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    """Explicit secondary confirmation to enable desktop write tools."""
    _forbid_work_desktop_endpoint()
    metadata = await _mutate_desktop_state("enable_writes", auth)
    count = metadata.get("write_tools", 0)
    return {
        "success": True,
        **metadata,
        "message": f"已启用 {count} 个写操作工具（点击、键盘、App、窗口）。所有写操作需要审批。",
    }


@router.get("/api/desktop/wizard/status")
async def desktop_wizard_status(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """Get full wizard status including write tools state."""
    _forbid_work_desktop_endpoint()
    from js.tools.desktop.wizard import run_wizard

    state = run_wizard()
    agent = get_agent()
    has_tools = agent._desktop_tools is not None
    write_enabled = (
        has_tools
        and agent._desktop_tools is not None
        and agent._desktop_tools.write_tools_registered
    )

    return {
        "ready": state.ready,
        "overall_status": state.overall_status,
        "steps": [{"name": s.name, "title": s.title, "status": s.status, "detail": s.detail,
                   "action_label": s.action_label, "action_type": s.action_type}
                  for s in state.steps],
        "enabled": agent.settings.desktop_control_enabled if has_tools else False,
        "write_tools_enabled": write_enabled,
        "can_install_cliclick": state.can_install_cliclick,
        "install_summary": state.install_summary,
    }
