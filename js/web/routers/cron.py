"""Cron / Scheduled Tasks API router."""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.web.auth import require_admin, require_auth_dep
from js.web.deps import get_agent

router = APIRouter(prefix="/api/cron", tags=["cron"])


@router.get("/jobs")
async def cron_list_jobs(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """List all scheduled jobs."""
    agent = get_agent()
    daemon = getattr(agent, "_daemon", None)
    if not daemon:
        return {"jobs": [], "running": False}
    jobs = [j.to_dict() for j in daemon.list_jobs()]
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
    job = daemon.get_job(job_id)
    if not job:
        raise HTTPException(404, f"Job not found: {job_id}")
    return {"job": job.to_dict()}


@router.post("/jobs")
async def cron_create_job(
    payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)
) -> dict[str, Any]:
    """Create a new scheduled job."""
    from js.cron.engine import CronExpression, ScheduledJob
    from js.cron.nlp import parse_natural_language
    from js.cron.templates import get_template

    agent = get_agent()
    daemon = getattr(agent, "_daemon", None)
    if not daemon:
        raise HTTPException(503, "Daemon not running. Start with 'js daemon' first.")

    # Support template-based creation
    template_id = payload.get("template_id")
    if template_id:
        template = get_template(template_id)
        if not template:
            raise HTTPException(400, f"Unknown template: {template_id}")
        job = ScheduledJob(
            name=payload.get("name", template.name),
            description=payload.get("description", template.description),
            cron_expr=payload.get("cron_expr", template.default_cron),
            task_type=template.task_type,
            payload={**template.default_payload, **payload.get("payload", {})},
        )
    else:
        # Raw creation
        cron_expr = payload.get("cron_expr", "")
        # Try natural language parsing if no cron expression
        if not cron_expr:
            nl = payload.get("natural_language", "")
            parsed = parse_natural_language(nl) if nl else None
            if parsed:
                cron_expr = parsed["cron_expr"]
            else:
                raise HTTPException(400, "Provide cron_expr, natural_language, or template_id")
        # Validate cron
        try:
            CronExpression(cron_expr)
        except ValueError as e:
            raise HTTPException(400, f"Invalid cron expression: {e}") from e
        job = ScheduledJob(
            name=payload.get("name", "Untitled Job"),
            description=payload.get("description", ""),
            cron_expr=cron_expr,
            task_type=payload.get("task_type", "custom"),
            payload=payload.get("payload", {}),
            schedule_summary=payload.get("schedule_summary", ""),
            notify_on_success=payload.get("notify_on_success", False),
            notify_on_failure=payload.get("notify_on_failure", True),
        )

    daemon.add_job(job)
    return {"success": True, "job": job.to_dict()}


@router.put("/jobs/{job_id}")
async def cron_update_job(
    job_id: str, payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)
) -> dict[str, Any]:
    """Update an existing job."""
    from js.cron.engine import CronExpression

    agent = get_agent()
    daemon = getattr(agent, "_daemon", None)
    if not daemon:
        raise HTTPException(503, "Daemon not running")
    job = daemon.get_job(job_id)
    if not job:
        raise HTTPException(404, f"Job not found: {job_id}")

    if "name" in payload:
        job.name = payload["name"]
    if "description" in payload:
        job.description = payload["description"]
    if "cron_expr" in payload:
        try:
            CronExpression(payload["cron_expr"])
        except ValueError as e:
            raise HTTPException(400, f"Invalid cron expression: {e}") from e
        job.cron_expr = payload["cron_expr"]
        # Recalculate next run
        cron = CronExpression(job.cron_expr)
        job.next_run_at = cron.next_run()
    if "enabled" in payload:
        job.enabled = payload["enabled"]
    if "task_type" in payload:
        job.task_type = payload["task_type"]
    if "payload" in payload:
        job.payload = payload["payload"]
    if "notify_on_success" in payload:
        job.notify_on_success = payload["notify_on_success"]
    if "notify_on_failure" in payload:
        job.notify_on_failure = payload["notify_on_failure"]
    job.updated_at = time.time()
    daemon._persist_job(job)
    return {"success": True, "job": job.to_dict()}


@router.delete("/jobs/{job_id}")
async def cron_delete_job(
    job_id: str, auth: dict[str, Any] = Depends(require_admin)
) -> dict[str, Any]:
    """Delete a scheduled job."""
    agent = get_agent()
    daemon = getattr(agent, "_daemon", None)
    if not daemon:
        raise HTTPException(503, "Daemon not running")
    if daemon.remove_job(job_id):
        return {"success": True}
    raise HTTPException(404, f"Job not found: {job_id}")


@router.post("/jobs/{job_id}/run")
async def cron_run_job_now(
    job_id: str, auth: dict[str, Any] = Depends(require_admin)
) -> dict[str, Any]:
    """Manually trigger a job immediately."""
    agent = get_agent()
    daemon = getattr(agent, "_daemon", None)
    if not daemon:
        raise HTTPException(503, "Daemon not running")
    try:
        result = await daemon.cron.run_job_now(job_id)
        return {
            "success": result.success,
            "duration_ms": result.duration_ms,
            "output": result.output,
            "error": result.error,
        }
    except ValueError as e:
        raise HTTPException(404, str(e)) from e


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
    history = daemon.store.get_history(job_id=job_id, limit=limit, offset=offset)
    return {
        "history": [
            {
                "job_id": h.job_id,
                "run_at": h.run_at,
                "duration_ms": h.duration_ms,
                "success": h.success,
                "output": h.output,
                "error": h.error,
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
    jobs = daemon.list_jobs()
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
