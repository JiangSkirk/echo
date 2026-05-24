"""System API router."""

from __future__ import annotations

import asyncio
import os
import signal
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException

from js.agent import JSAgent
from js.config import JSSettings
from js.utils.log import get_logger
from js.web.auth import require_auth_dep
from js.web.deps import get_agent, set_globals
from js.web.stats_store import TokenStatsStore

if TYPE_CHECKING:
    from js.orchestration.fleet import AgentFleet

logger = get_logger("js.web")

router = APIRouter(tags=["system"])

SERVER_VERSION = "0.1.0+evolution"

# Global state
_agent: JSAgent | None = None
_settings: JSSettings | None = None
_stats_store: TokenStatsStore | None = None
_fleet: Any | None = None

_agent_config: dict[str, str] = {
    "orchestrator": "",
    "coder": "",
    "reviewer": "",
    "researcher": "",
    "tester": "",
}

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


def get_fleet() -> AgentFleet:
    global _fleet
    if _fleet is None:
        from js.orchestration.fleet import AgentFleet

        settings = _settings
        if settings is None:
            try:
                settings = JSSettings.from_file()
            except Exception as e:
                raise HTTPException(503, f"Settings not loaded: {e}") from e
        try:
            _fleet = AgentFleet(settings, agent_config=_agent_config)
        except Exception as e:
            raise HTTPException(500, f"Failed to initialize fleet: {e}") from e
    return _fleet


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


@router.get("/api/setup/first-start")
async def setup_first_start(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    if _settings is None:
        return {"first_run_completed": False}
    return {"first_run_completed": _settings.first_run_completed}


@router.post("/api/setup/complete")
async def setup_complete(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    if _settings is None:
        raise HTTPException(503, "Settings not initialized")
    _settings.first_run_completed = True
    try:
        # Use field-restricted save so we don't clobber providers/models/paths
        await asyncio.to_thread(_settings.save, None, ["first_run_completed"])
    except PermissionError:
        # Fallback: save to state_dir/config.yaml when home dir is not writable
        try:
            fallback = _settings.state_dir / "config.yaml"
            await asyncio.to_thread(_settings.save, fallback, ["first_run_completed"])
        except OSError as e:
            raise HTTPException(
                500,
                f"Unable to save settings: home directory and state directory are both read-only. {e}",
            ) from e
    except OSError as e:
        raise HTTPException(500, f"Unable to save settings: {e}") from e
    return {"success": True}
