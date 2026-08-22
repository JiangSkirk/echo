"""HTTP surface for AppShell workspace switching."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["appshell"])


@router.post("/api/appshell/switch")
async def appshell_switch() -> None:
    """Reject child-local mode changes; only the parent owns this contract."""
    raise HTTPException(410, {"code": "appshell_parent_required"})


@router.post("/api/workspace/switch")
async def workspace_switch() -> None:
    """Retired dual-host route retained only as a non-executable tombstone."""
    raise HTTPException(
        410,
        {
            "code": "legacy_workspace_switch_retired",
            "use": "/api/appshell/switch",
        },
    )
