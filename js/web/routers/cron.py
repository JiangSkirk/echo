"""Cron / Scheduled Tasks API router."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.agent.tool_executor import CONTROL_CRON_MUTATE_TOOL
from js.echo.effect_interpreter import ToolEffect
from js.web.auth import memory_owner, require_admin_write, require_auth_dep
from js.web.deps import get_agent
from js.web.runtime_context import web_channel

router = APIRouter(prefix="/api/cron", tags=["cron"])


def _owner(auth: dict[str, Any]) -> str:
    return memory_owner(auth) or "local-user"


async def _mutate_cron(
    action: str,
    payload: dict[str, Any],
    auth: dict[str, Any],
) -> dict[str, Any]:
    """Run one private cron mutation through Echo and consume its result."""
    agent = get_agent()
    owner = _owner(auth)
    runtime = agent.echo_runtime
    context = runtime.build_context(
        channel=web_channel(agent.settings, f"cron_{action}"),
        owner_key_hash=owner,
        role=str(auth.get("role") or "admin"),
        capabilities=(CONTROL_CRON_MUTATE_TOOL,),
    )
    payload_ref = agent.stage_cron_mutation_payload(
        owner,
        payload,
        product_id=context.product_id,
        session_id=context.session_id,
    )
    if not isinstance(payload_ref, str) or not payload_ref:
        raise HTTPException(503, "Cron mutation admission is unavailable")
    try:
        _message, result = await runtime.execute_tool_effect(
            ToolEffect.from_arguments(
                CONTROL_CRON_MUTATE_TOOL,
                {"action": action, "payload_ref": payload_ref},
                user_input=f"Apply owner-bound scheduled-job action: {action}",
                allowed_tools=(CONTROL_CRON_MUTATE_TOOL,),
            ),
            context,
        )
    finally:
        agent.discard_cron_mutation_payload(
            payload_ref,
            owner,
            product_id=context.product_id,
            session_id=context.session_id,
        )
    if not result.success:
        status_code = result.metadata.get("status_code", 500)
        if not isinstance(status_code, int) or not 400 <= status_code <= 599:
            status_code = 500
        raise HTTPException(status_code, result.error or "Cron mutation failed")
    result_ref = result.metadata.get("result_ref")
    if not isinstance(result_ref, str) or not result_ref:
        raise HTTPException(500, "Cron result handoff failed")
    response = agent.take_cron_mutation_result(
        result_ref,
        owner,
        product_id=context.product_id,
        session_id=context.session_id,
    )
    if not isinstance(response, dict):
        raise HTTPException(500, "Cron result handoff failed")
    return response


@router.get("/jobs")
async def cron_list_jobs(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """List all scheduled jobs."""
    agent = get_agent()
    daemon = getattr(agent, "_daemon", None)
    if not daemon:
        return {"jobs": [], "running": False}
    jobs = [j.to_dict() for j in daemon.list_jobs(owner_key_hash=_owner(auth))]
    return {"jobs": jobs, "running": daemon.cron._running}


@router.get("/jobs/{job_id}")
async def cron_get_job(
    job_id: str, auth: dict[str, Any] = Depends(require_auth_dep)
) -> dict[str, Any]:
    """Get a single job by ID."""
    agent = get_agent()
    daemon = getattr(agent, "_daemon", None)
    if not daemon:
        raise HTTPException(503, "Daemon not running")
    job = daemon.get_job(job_id, owner_key_hash=_owner(auth))
    if not job:
        raise HTTPException(404, f"Job not found: {job_id}")
    return {"job": job.to_dict()}


@router.post("/jobs")
async def cron_create_job(
    payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin_write)
) -> dict[str, Any]:
    """Create a new scheduled job."""
    return await _mutate_cron("create", payload, auth)


@router.put("/jobs/{job_id}")
async def cron_update_job(
    job_id: str,
    payload: dict[str, Any],
    auth: dict[str, Any] = Depends(require_admin_write),
) -> dict[str, Any]:
    """Update an existing job."""
    return await _mutate_cron(
        "update",
        {"job_id": job_id, "changes": payload},
        auth,
    )


@router.delete("/jobs/{job_id}")
async def cron_delete_job(
    job_id: str, auth: dict[str, Any] = Depends(require_admin_write)
) -> dict[str, Any]:
    """Delete a scheduled job."""
    return await _mutate_cron("delete", {"job_id": job_id}, auth)


@router.post("/jobs/{job_id}/run")
async def cron_run_job_now(
    job_id: str, auth: dict[str, Any] = Depends(require_admin_write)
) -> dict[str, Any]:
    """Manually trigger a job immediately."""
    return await _mutate_cron("run", {"job_id": job_id}, auth)


@router.get("/history")
async def cron_history(
    job_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Get execution history."""
    agent = get_agent()
    daemon = getattr(agent, "_daemon", None)
    if not daemon:
        return {"history": [], "total": 0}
    history = daemon.store.get_history(
        job_id=job_id,
        limit=limit,
        offset=offset,
        owner_key_hash=_owner(auth),
    )
    return {
        "history": [
            {
                "job_id": h.job_id,
                "run_at": h.run_at,
                "duration_ms": h.duration_ms,
                "success": h.success,
                "status": h.status,
                "output": h.output,
                "error": h.error,
                "output_truncated": h.output_truncated,
                "error_truncated": h.error_truncated,
            }
            for h in history
        ],
        "total": len(history),
    }


@router.get("/stats")
async def cron_stats(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """Get cron subsystem statistics."""
    agent = get_agent()
    daemon = getattr(agent, "_daemon", None)
    if not daemon:
        return {"running": False}
    stats: dict[str, Any] = daemon.store.get_stats()
    jobs = daemon.list_jobs(owner_key_hash=_owner(auth))
    stats["running"] = daemon.cron._running
    stats["jobs"] = [j.to_dict() for j in jobs]
    return stats


@router.get("/templates")
async def cron_templates(
    category: str | None = None, auth: dict[str, Any] = Depends(require_auth_dep)
) -> dict[str, Any]:
    """List available task templates."""
    from js.cron.templates import list_templates

    templates = list_templates(category=category)
    return {
        "templates": [
            {
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "task_type": t.task_type,
                "default_cron": t.default_cron,
                "icon": t.icon,
                "category": t.category,
            }
            for t in templates
        ]
    }


@router.post("/parse")
async def cron_parse_natural(
    payload: dict[str, Any], auth: dict[str, Any] = Depends(require_auth_dep)
) -> dict[str, Any]:
    """Parse natural language into cron expression."""
    from js.cron.nlp import parse_natural_language, suggest_cron_examples

    text = payload.get("text", "")
    if not text:
        return {"examples": suggest_cron_examples()}
    result = parse_natural_language(text)
    if result:
        return {"matched": True, **result}
    return {"matched": False, "examples": suggest_cron_examples()}
