"""System API router."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, Request

from js import __version__
from js.utils.log import get_logger
from js.web.auth import require_auth_dep
from js.web.deps import get_agent, get_echo_safety_service, get_stats_store
from js.web.echo_status import echo_ledger_status, echo_status
from js.web.messages import health_summary

logger = get_logger("js.web")

router = APIRouter(tags=["system"])

SERVER_VERSION = f"{__version__}+evolution"

_STATUS_HEALTH_VERIFY_CACHE_SECONDS = 30.0


@router.get("/api/status")
async def status(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    agent = get_agent()
    await agent._check_degraded()
    event_store = getattr(agent, "event_store", None)
    try:
        event_store_health = (
            event_store.health()
            if event_store is not None and hasattr(event_store, "health")
            else {"ok": False, "last_error": "event store is unavailable"}
        )
    except Exception as exc:
        event_store_health = {
            "ok": False,
            "last_error": f"{type(exc).__name__}: {exc}",
        }
    # Presentation-layer Chinese health verdict for factory-floor users.
    # `degraded_reason` (English) is preserved below for developers/diagnostics.
    providers_configured = any(getattr(p, "models", None) for p in agent.settings.providers)
    summary = health_summary(degraded=agent.degraded, providers_configured=providers_configured)
    echo_health = get_echo_safety_service(agent.settings).health(
        max_verify_age_seconds=_STATUS_HEALTH_VERIFY_CACHE_SECONDS,
    )
    product_id = str(getattr(agent.settings, "product_id", "js-agent"))
    profile = str(
        getattr(agent, "_work_profile", None)
        or getattr(agent.settings, "work_profile", None)
        or "default"
    )
    return {
        "product_id": product_id,
        "profile": profile,
        "workspace": str(agent.settings.workspace),
        "state_dir": str(agent.settings.state_dir),
        "max_turns": agent.settings.max_turns,
        "defense_mode": agent.settings.security.defense_mode.value,
        "degraded": agent.degraded,
        "degraded_reason": agent.degraded_reason,
        "tool_stats": agent.registry.get_stats(),
        "secret_stats": agent.secrets.get_stats(),
        "event_store": event_store_health,
        "desktop_control_enabled": agent.settings.desktop_control_enabled,
        "echo": echo_status(agent.settings, health=echo_health),
        "echo_ledger": echo_ledger_status(echo_health),
        "hermes_bridge": {
            "enabled": bool(
                getattr(getattr(agent, "skills", None), "hermes_skills_enabled", False)
            ),
            "opt_in": bool(getattr(getattr(agent, "skills", None), "hermes_skills_enabled", False)),
            "skills_loaded": sum(
                1
                for s in (
                    agent.skills.get_all().values()
                    if getattr(agent, "skills", None) is not None
                    else ()
                )
                if s.id.startswith("hermes:")
            ),
        },
        **summary,
    }


# NOTE: /api/cancel/{session_id} is intentionally NOT defined here.
# The canonical handler lives in server.py and enforces owner_key_hash
# isolation (raises 403 if a caller tries to cancel another user's run).
# A second route here shadowed that handler (router routes register before
# the in-app routes), silently dropping the owner check.


@router.get("/api/capabilities")
async def capabilities(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """Authoritative product capability / navigation manifest."""
    from js.web.capability_manifest import build_capability_manifest

    agent = get_agent()
    return build_capability_manifest(agent.settings)


@router.get("/api/appshell/prefs")
async def appshell_prefs(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """Return chrome-level AppShell prefs (no secrets, no product memory)."""
    from js.appshell.global_prefs import load_global_prefs

    return load_global_prefs().as_dict()


@router.get("/api/diag")
async def diag(
    request: Request,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Diagnostic endpoint to verify server version, routes and subsystem health."""
    from js.web.runtime_context import current_web_runtime

    runtime = current_web_runtime() or getattr(request.app.state, "web_runtime", None)
    agent = runtime.agent if runtime is not None else get_agent()
    http_methods = {"get", "post", "put", "patch", "delete", "options", "head"}
    routes = [
        {
            "path": path,
            "methods": [method.upper() for method in operations if method in http_methods],
        }
        for path, operations in request.app.openapi().get("paths", {}).items()
    ]
    subsystems = {
        "metacognition": agent.metacognition is not None,
        "learner": agent.learner is not None,
        "optimizer": agent.optimizer is not None,
        "evolver": agent.evolver is not None,
        "compression_feedback": agent.compression_feedback is not None,
        "dream_scheduler": agent._dream_scheduler is not None,
    }
    embedder_health = agent.memory.embedder.health()

    # Hermes bridge stats (opt-in visibility)
    skills = getattr(agent, "skills", None)
    hermes_count = 0
    hermes_opt_in = False
    if skills is not None:
        hermes_opt_in = bool(getattr(skills, "hermes_skills_enabled", False))
        hermes_count = sum(1 for s in skills.get_all().values() if s.id.startswith("hermes:"))

    return {
        "version": SERVER_VERSION,
        "routes": sorted(routes, key=lambda x: x["path"]),
        "subsystems": subsystems,
        "has_evolution_api": any(r["path"] == "/api/evolution/run" for r in routes),
        "embedder": {
            "provider": embedder_health.provider,
            "active": embedder_health.active,
            "fallback": embedder_health.fallback_provider,
            "failures": embedder_health.failure_count,
        },
        "hermes_bridge": {
            "enabled": hermes_opt_in,
            "opt_in": hermes_opt_in,
            "skills_loaded": hermes_count,
        },
    }


@router.get("/api/dashboard")
async def dashboard(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """Real-time dashboard aggregating model status, providers, tokens, and system health."""
    agent = get_agent()
    health = await agent.router.health_check()

    # Provider details with circuit breaker state
    providers: list[dict[str, Any]] = []
    for p in agent.settings.providers:
        prov_health = health.get(p.name, False)
        # Try to get circuit breaker stats if available
        circuit_info: dict[str, Any] = {"state": "unknown"}
        try:
            prov = agent.router._providers.get(p.name)
            if prov and hasattr(prov, "circuit"):
                cb = prov.circuit
                can_exec = True
                try:
                    _can = cb.can_execute
                    if callable(_can):
                        can_exec = await _can() if asyncio.iscoroutinefunction(_can) else _can()
                except Exception:
                    pass
                # Get actual circuit state value (state is async method)
                try:
                    _state_val = (
                        await cb.state() if asyncio.iscoroutinefunction(cb.state) else cb.state
                    )
                except Exception:
                    _state_val = getattr(cb, "_state", "unknown")
                circuit_info = {
                    "state": _state_val.name if hasattr(_state_val, "name") else str(_state_val),
                    "failures": getattr(cb, "failure_count", getattr(cb, "_failures", 0)),
                    "last_failure": getattr(
                        cb, "last_failure_time", getattr(cb, "_last_failure_time", None)
                    ),
                    "can_execute": can_exec,
                }
        except Exception:
            pass

        latency = {"p50_ms": None, "p95_ms": None, "p99_ms": None, "count": 0}
        try:
            from prometheus_client import REGISTRY

            for family in REGISTRY.collect():
                if family.name == "model_latency_seconds":
                    for sample in family.samples:
                        if sample.labels.get("provider") == p.name and sample.name.endswith(
                            "_count"
                        ):
                            latency["count"] = int(sample.value)
                        if sample.labels.get("provider") == p.name and sample.name.endswith("_sum"):
                            pass
        except Exception:
            pass

        providers.append(
            {
                "name": p.name,
                "base_url": p.base_url,
                "healthy": prov_health,
                "default_model": p.default_model,
                "models_count": len(p.models),
                "circuit": circuit_info,
                "latency": latency,
            }
        )

    # Active model
    active_model = ""
    try:
        active_model = agent.settings.default_model or ""  # type: ignore[attr-defined]
    except Exception:
        pass

    # Token stats (today + total)
    token_stats: dict[str, Any] = {"today": {}, "total": {}}
    stats_store = get_stats_store()
    if stats_store is not None:
        try:
            total = stats_store.get_summary(days=30)
            token_stats["total"] = {
                "calls": total.get("total_calls", 0),
                "prompt_tokens": total.get("total_prompt_tokens", 0),
                "completion_tokens": total.get("total_completion_tokens", 0),
                "cost": round(total.get("total_cost", 0.0), 6),
                "cache_rate": total.get("cache_rate", 0.0),
            }
            token_stats["per_model"] = total.get("per_model", [])
            token_stats["daily_trend"] = total.get("daily_trend", [])
        except Exception:
            pass

    # Tool stats
    tool_stats = agent.registry.get_stats()

    # Session count
    session_count = 0
    try:
        session_count = len(agent.memory.get_sessions(limit=1000))
    except Exception:
        pass

    # Embedder health
    embedder_health = agent.memory.embedder.health()

    # Fleet status (if available)
    fleet_info: dict[str, Any] = {"enabled": False}
    try:
        from js.web.routers.fleet import get_fleet

        f = get_fleet()
        fleet_info = {
            "enabled": True,
            "agents": len(getattr(f, "agents", {})),
            "max_agents": getattr(f, "max_agents", 0),
        }
    except Exception:
        pass

    # Skill counts
    skill_counts = {"total": 0, "builtin": 0, "hermes": 0}
    try:
        all_skills = agent.skills.get_all()
        skill_counts["total"] = len(all_skills)
        skill_counts["hermes"] = sum(1 for s in all_skills.values() if s.id.startswith("hermes:"))
        skill_counts["builtin"] = sum(
            1
            for s in all_skills.values()
            if getattr(s, "trust_level", None) and getattr(s.trust_level, "value", "") == "builtin"
        )
    except Exception:
        pass

    return {
        "version": SERVER_VERSION,
        "active_model": active_model,
        "overall_healthy": any(p["healthy"] for p in providers),
        "degraded": agent.degraded,
        "providers": providers,
        "token_stats": token_stats,
        "tool_stats": tool_stats,
        "session_count": session_count,
        "embedder": {
            "provider": embedder_health.provider,
            "active": embedder_health.active,
            "fallback": embedder_health.fallback_provider,
            "failures": embedder_health.failure_count,
        },
        "fleet": fleet_info,
        "skills": skill_counts,
        "timestamp": asyncio.get_event_loop().time(),
    }


# NOTE: /api/setup/* endpoints have been moved to js/web/routers/setup.py
