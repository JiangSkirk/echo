"""System API router."""

from __future__ import annotations

import asyncio
import os
import signal
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException

from js import __version__
from js.agent import JSAgent
from js.config import JSSettings
from js.utils.log import get_logger
from js.web.auth import require_auth_dep
from js.web.deps import get_agent, get_settings, set_globals
from js.web.stats_store import TokenStatsStore

logger = get_logger("js.web")

router = APIRouter(tags=["system"])

SERVER_VERSION = f"{__version__}+evolution"

# Global state
_agent: JSAgent | None = None
_settings: JSSettings | None = None
_stats_store: TokenStatsStore | None = None


def _get_app_routes() -> list[dict[str, Any]]:
    return []

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"


def set_app_routes(func: Callable[[], list[dict[str, Any]]]) -> None:
    global _get_app_routes
    _get_app_routes = func


def _load_index_html() -> str:
    path = _TEMPLATE_DIR / "index.html"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return "<h1>Template not found</h1>"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:  # noqa: ARG001
    global _agent, _settings, _stats_store
    _settings = JSSettings.from_file()
    # Allow tests/CI to override state_dir without editing config files
    if state_dir_env := os.getenv("JS_STATE_DIR"):
        _settings.state_dir = Path(state_dir_env)
        _settings.state_dir.mkdir(parents=True, exist_ok=True)
    _agent = JSAgent(_settings)
    _agent.start_background_tasks()
    _stats_store = TokenStatsStore(_settings.state_dir)
    # Sync shared deps so routers can access agent and stats store
    set_globals(_agent, _settings, _stats_store)
    # Clean up empty sessions on startup
    try:
        cleaned = _agent.memory.cleanup_empty_sessions()
        if cleaned:
            logger.info(f"Cleaned up {cleaned} empty sessions on startup")
    except Exception:
        logger.debug("Failed to clean up empty sessions", exc_info=True)
    logger.info("Web UI agent initialized")

    # SIGTERM handler for graceful shutdown
    _shutdown_event = asyncio.Event()

    def _handle_sigterm() -> None:
        logger.info("SIGTERM received, initiating graceful shutdown")
        _shutdown_event.set()

    try:
        loop = asyncio.get_running_loop()
        try:
            loop.add_signal_handler(signal.SIGTERM, _handle_sigterm)
        except (NotImplementedError, ValueError, RuntimeError):
            pass  # Windows, non-main thread, or already closed loop
    except RuntimeError:
        pass  # No running loop

    try:
        yield
    finally:
        try:
            loop = asyncio.get_running_loop()
            try:
                loop.remove_signal_handler(signal.SIGTERM)
            except (NotImplementedError, ValueError, RuntimeError):
                pass
        except RuntimeError:
            pass
        if _agent:
            await _agent.close()
        _agent = None


@router.get("/api/status")
async def status(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    agent = get_agent()
    await agent._check_degraded()
    return {
        "workspace": str(agent.settings.workspace),
        "state_dir": str(agent.settings.state_dir),
        "max_turns": agent.settings.max_turns,
        "defense_mode": agent.settings.security.defense_mode.value,
        "degraded": agent.degraded,
        "degraded_reason": agent.degraded_reason,
        "tool_stats": agent.registry.get_stats(),
        "secret_stats": agent.secrets.get_stats(),
    }


@router.get("/api/metrics/providers")
async def provider_metrics(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """Return per-provider SLO metrics: health, latency percentiles, circuit state."""
    agent = get_agent()
    health = await agent.router.health_check()

    # Pull Prometheus samples for provider metrics
    from prometheus_client import REGISTRY

    def _latency_stats(model: str, provider: str) -> dict[str, float]:
        """Read P50/P95/P99 from histogram buckets (approximate)."""
        stats = {"count": 0.0, "sum": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0}
        try:
            for family in REGISTRY.collect():
                if family.name == "model_latency_seconds":
                    for sample in family.samples:
                        if sample.labels.get("model") == model and sample.labels.get("provider") == provider:
                            if sample.name.endswith("_count"):
                                stats["count"] = sample.value
                            elif sample.name.endswith("_sum"):
                                stats["sum"] = sample.value
                            elif sample.name.endswith("_bucket"):
                                # Find buckets for p50/p95/p99 approximations
                                le = sample.labels.get("le", "")
                                if le not in ("+Inf", ""):
                                    try:
                                        bound = float(le)
                                        if bound <= 0.5 and sample.value > 0:
                                            stats["p50"] = bound
                                        if bound <= 2.0 and sample.value > 0:
                                            stats["p95"] = bound
                                        if bound <= 5.0 and sample.value > 0:
                                            stats["p99"] = bound
                                    except ValueError:
                                        logger.debug("Operation failed", exc_info=True)
        except Exception:
            logger.debug("Operation failed", exc_info=True)
        return stats

    providers: list[dict[str, Any]] = []
    for p in agent.settings.providers:
        for m in p.models:
            lat = _latency_stats(m.id, p.name)
            providers.append({
                "name": p.name,
                "model": m.id,
                "healthy": health.get(p.name, False),
                "latency_p50_ms": round(lat["p50"] * 1000, 1) if lat["p50"] else None,
                "latency_p95_ms": round(lat["p95"] * 1000, 1) if lat["p95"] else None,
                "latency_p99_ms": round(lat["p99"] * 1000, 1) if lat["p99"] else None,
                "request_count": int(lat["count"]),
            })

    overall_healthy = any(p["healthy"] for p in providers)
    return {
        "overall_healthy": overall_healthy,
        "degraded": agent.degraded,
        "providers": providers,
    }


@router.post("/api/cancel/{session_id}")
async def cancel_session(
    session_id: str, auth: dict[str, Any] = Depends(require_auth_dep)
) -> dict[str, Any]:
    """Request cancellation of an active agent run for *session_id*."""
    agent = get_agent()
    ok = agent.request_cancel(session_id)
    if not ok:
        raise HTTPException(404, f"No active run for session {session_id}")
    return {"session_id": session_id, "cancelled": True}


@router.get("/api/diag")
async def diag(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """Diagnostic endpoint to verify server version, routes and subsystem health."""
    agent = get_agent()
    routes = _get_app_routes()
    subsystems = {
        "metacognition": agent.metacognition is not None,
        "learner": agent.learner is not None,
        "optimizer": agent.optimizer is not None,
        "evolver": agent.evolver is not None,
        "compression_feedback": agent.compression_feedback is not None,
        "dream_scheduler": agent._dream_scheduler is not None,
    }
    embedder_health = agent.memory.embedder.health()

    # Hermes bridge stats
    hermes_count: int = sum(
        1 for s in agent.skills.get_all().values()
        if s.id.startswith("hermes:")
    )

    return {
        "version": SERVER_VERSION,
        "routes": sorted(routes, key=lambda x: x["path"]),
        "subsystems": subsystems,
        "has_evolution_api": any(
            r["path"] == "/api/evolution/run" for r in routes
        ),
        "embedder": {
            "provider": embedder_health.provider,
            "active": embedder_health.active,
            "fallback": embedder_health.fallback_provider,
            "failures": embedder_health.failure_count,
        },
        "hermes_bridge": {
            "enabled": hermes_count > 0,
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
                    _state_val = await cb.state() if asyncio.iscoroutinefunction(cb.state) else cb.state
                except Exception:
                    _state_val = getattr(cb, '_state', 'unknown')
                circuit_info = {
                    "state": _state_val.name if hasattr(_state_val, "name") else str(_state_val),
                    "failures": getattr(cb, "failure_count", getattr(cb, "_failures", 0)),
                    "last_failure": getattr(cb, "last_failure_time", getattr(cb, "_last_failure_time", None)),
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
                        if sample.labels.get("provider") == p.name and sample.name.endswith("_count"):
                            latency["count"] = int(sample.value)
                        if sample.labels.get("provider") == p.name and sample.name.endswith("_sum"):
                            pass
        except Exception:
            pass

        providers.append({
            "name": p.name,
            "base_url": p.base_url,
            "healthy": prov_health,
            "default_model": p.default_model,
            "models_count": len(p.models),
            "circuit": circuit_info,
            "latency": latency,
        })

    # Active model
    active_model = ""
    try:
        active_model = agent.settings.default_model or ""  # type: ignore[attr-defined]
    except Exception:
        pass

    # Token stats (today + total)
    token_stats: dict[str, Any] = {"today": {}, "total": {}}
    if _stats_store is not None:
        try:
            total = _stats_store.get_summary(days=30)
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
        skill_counts["builtin"] = sum(1 for s in all_skills.values() if getattr(s, "trust_level", None) and getattr(s.trust_level, "value", "") == "builtin")
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


@router.get("/api/setup/first-start")
async def setup_first_start(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    settings = get_settings()
    return {"first_run_completed": settings.first_run_completed}


@router.post("/api/setup/complete")
async def setup_complete(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    settings = get_settings()
    settings.first_run_completed = True
    try:
        # Use field-restricted save so we don't clobber providers/models/paths
        await asyncio.to_thread(settings.save, None, ["first_run_completed"])
    except PermissionError:
        # Fallback: save to state_dir/config.yaml when home dir is not writable
        try:
            fallback = settings.state_dir / "config.yaml"
            await asyncio.to_thread(settings.save, fallback, ["first_run_completed"])
        except OSError as e:
            raise HTTPException(
                500,
                f"Unable to save settings: home directory and state directory are both read-only. {e}",
            ) from e
    except OSError as e:
        raise HTTPException(500, f"Unable to save settings: {e}") from e
    return {"success": True}
