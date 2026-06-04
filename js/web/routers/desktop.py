"""Desktop-control API router — status, toggle, and the setup wizard.

Extracted from ``server.py``.  macOS desktop automation (screenshot, click,
keyboard, window/app control) is opt-in and gated behind a setup wizard plus
per-action approval; these endpoints drive that flow.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from js.web.auth import require_admin, require_auth_dep
from js.web.deps import get_agent

router = APIRouter(tags=["desktop"])


@router.get("/api/desktop/status")
async def desktop_status(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
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
    agent = get_agent()
    new_state = not agent.settings.desktop_control_enabled
    agent.settings.desktop_control_enabled = new_state
    agent.settings.save(fields=["desktop_control_enabled"])

    if new_state:
        try:
            from js.tools.desktop_tools import DesktopTools
            dt = DesktopTools(approval_queue=agent.approvals)
            agent._desktop_tools = dt
            dt.register_all(agent.registry)

            if not dt.available:
                # Partial success: diagnostic tools registered, write tools unavailable
                return {
                    "success": True,
                    "enabled": True,
                    "warning": dt.init_error,
                    "action_required": "Install missing dependencies and restart",
                }
            return {"success": True, "enabled": True}
        except Exception as e:
            # Rollback on failure
            agent.settings.desktop_control_enabled = False
            agent.settings.save(fields=["desktop_control_enabled"])
            agent._desktop_tools = None
            return {"success": False, "error": str(e), "enabled": False}
    else:
        # Dynamic unregistration
        if agent._desktop_tools is not None:
            try:
                for spec in agent._desktop_tools.get_specs():
                    agent.registry.unregister(spec.name)
            except Exception:
                pass
            agent._desktop_tools = None
        return {"success": True, "enabled": False}


@router.get("/api/desktop/wizard")
async def desktop_wizard(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """First-use setup wizard: detect deps + permissions, guide installation.

    This endpoint is designed to ALWAYS return 200 with actionable info,
    even when the server is in a degraded state.  The frontend relies on
    this to show specific guidance (missing deps, missing perms, etc.).
    """
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
    """Execute a wizard action (install cliclick, open settings, etc.)."""
    from js.tools.desktop.wizard import execute_action, run_wizard
    action_type = payload.get("action_type", "")
    if not action_type:
        return {"success": False, "error": "action_type is required"}

    result = execute_action(action_type)
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
    from js.tools.desktop.wizard import run_wizard

    state = run_wizard()
    if not state.ready:
        return {"success": False, "error": "Desktop control is not ready. Complete the wizard first."}

    agent = get_agent()
    agent.settings.desktop_control_enabled = True
    agent.settings.save(fields=["desktop_control_enabled"])

    from js.tools.desktop_tools import DesktopTools
    dt = DesktopTools(approval_queue=agent.approvals)
    agent._desktop_tools = dt
    count = dt.register_read_only(agent.registry)

    return {
        "success": True, "enabled": True,
        "tools_count": count,
        "stage": "read_only",
        "message": f"已启用 {count} 个只读/诊断工具。写操作工具需要二次确认。",
    }


@router.post("/api/desktop/wizard/enable-writes")
async def desktop_wizard_enable_writes(auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    """Explicit secondary confirmation to enable desktop write tools."""
    agent = get_agent()

    if agent._desktop_tools is None:
        return {"success": False, "error": "Desktop control is not enabled. Enable it first."}

    count = agent._desktop_tools.register_write_tools(agent.registry)
    if count > 0:
        return {
            "success": True,
            "write_tools": count,
            "total_tools": len(agent._desktop_tools.get_specs()),
            "message": f"已启用 {count} 个写操作工具（点击、键盘、App、窗口）。所有写操作需要审批。",
        }
    return {"success": False, "error": "Write tools were already registered or registration failed."}


@router.get("/api/desktop/wizard/status")
async def desktop_wizard_status(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """Get full wizard status including write tools state."""
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
