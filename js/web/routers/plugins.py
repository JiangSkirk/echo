from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.web.auth import require_auth_dep
from js.web.deps import get_agent

router = APIRouter(prefix="/api/plugins", tags=["plugins"])


@router.get("/")
async def list_plugins(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """List all discovered plugins."""
    agent = get_agent()
    pm = getattr(agent, "plugins", None)
    if not pm:
        return {"plugins": [], "total": 0}
    return {"plugins": [p.to_dict() for p in pm.list_plugins()], "total": len(pm.list_plugins())}


@router.post("/{plugin_id}/enable")
async def enable_plugin(plugin_id: str, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    agent = get_agent()
    pm = getattr(agent, "plugins", None)
    if not pm:
        raise HTTPException(503, "Plugin system not initialized")
    if pm.enable(plugin_id):
        return {"success": True, "plugin_id": plugin_id, "status": "enabled"}
    raise HTTPException(400, f"Failed to enable plugin: {plugin_id}")


@router.post("/{plugin_id}/disable")
async def disable_plugin(plugin_id: str, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    agent = get_agent()
    pm = getattr(agent, "plugins", None)
    if not pm:
        raise HTTPException(503, "Plugin system not initialized")
    if pm.disable(plugin_id):
        return {"success": True, "plugin_id": plugin_id, "status": "disabled"}
    raise HTTPException(400, f"Failed to disable plugin: {plugin_id}")


@router.post("/install")
async def install_plugin(body: dict[str, Any], auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """Install a plugin from a remote URL.

    Body: {"url": "https://example.com/plugin.zip"}
    Supports .zip and .tar.gz archives.
    """
    agent = get_agent()
    pm = getattr(agent, "plugins", None)
    if not pm:
        raise HTTPException(503, "Plugin system not initialized")
    url = (body.get("url") or "").strip()
    if not url:
        raise HTTPException(400, "url is required")
    result = pm.install_from_url(url)
    if not result.get("success"):
        raise HTTPException(400, result.get("message", "Install failed"))
    return dict(result)


@router.delete("/{plugin_id}")
async def uninstall_plugin(plugin_id: str, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """Uninstall a plugin and remove its files."""
    agent = get_agent()
    pm = getattr(agent, "plugins", None)
    if not pm:
        raise HTTPException(503, "Plugin system not initialized")
    result = pm.uninstall(plugin_id)
    if not result.get("success"):
        raise HTTPException(400, result.get("message", "Uninstall failed"))
    return dict(result)
