from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.web.auth import require_admin, require_auth_dep
from js.web.deps import get_agent
from js.web.schemas import PluginInstallRequest

router = APIRouter(prefix="/api/plugins", tags=["plugins"])
_PLUGIN_MUTATION_DISABLED = (
    "Runtime Python plugin mutation is disabled; only release-shipped plugin "
    "metadata may be inspected"
)


@router.get("/")
async def list_plugins(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """List all discovered plugins."""
    agent = get_agent()
    pm = getattr(agent, "plugins", None)
    if not pm:
        return {"plugins": [], "total": 0}
    return {"plugins": [p.to_dict() for p in pm.list_plugins()], "total": len(pm.list_plugins())}


@router.post("/{plugin_id}/enable")
async def enable_plugin(
    plugin_id: str, auth: dict[str, Any] = Depends(require_admin)
) -> dict[str, Any]:
    del plugin_id, auth
    raise HTTPException(409, _PLUGIN_MUTATION_DISABLED)


@router.post("/{plugin_id}/disable")
async def disable_plugin(
    plugin_id: str, auth: dict[str, Any] = Depends(require_admin)
) -> dict[str, Any]:
    del plugin_id, auth
    raise HTTPException(409, _PLUGIN_MUTATION_DISABLED)


@router.post("/install")
async def install_plugin(
    body: PluginInstallRequest, auth: dict[str, Any] = Depends(require_admin)
) -> dict[str, Any]:
    """Fail closed until an Echo-wrapped, sandboxed plugin runtime exists."""
    del body, auth
    raise HTTPException(409, _PLUGIN_MUTATION_DISABLED)


@router.delete("/{plugin_id}")
async def uninstall_plugin(
    plugin_id: str, auth: dict[str, Any] = Depends(require_admin)
) -> dict[str, Any]:
    """Fail closed; release-shipped plugin files are immutable at runtime."""
    del plugin_id, auth
    raise HTTPException(409, _PLUGIN_MUTATION_DISABLED)
