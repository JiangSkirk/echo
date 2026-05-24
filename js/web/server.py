"""FastAPI Web server with WebSocket streaming."""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from js.orchestration.fleet import AgentFleet
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from prometheus_client import make_asgi_app

from js.agent import JSAgent
from js.config import JSSettings, ModelConfig, ModelProviderConfig
from js.models.provider_manager import ProviderManager
from js.models.providers import OpenAICompatibleProvider
from js.utils.log import get_logger
from js.web.auth import require_auth_dep

# Imported routers (extracted from this file)
from js.web.routers import cron, fleet
from js.web.routers import plugins as plugins_router
from js.web.stats_store import TokenStatsStore

HTTPXClientInstrumentor().instrument()

logger = get_logger("js.web")

# Server version (bump when adding new API surfaces)
SERVER_VERSION = "0.1.0+evolution"

# Global agent instance
_agent: JSAgent | None = None
_settings: JSSettings | None = None
_stats_store: TokenStatsStore | None = None
_fleet: Any | None = None
_active_model: str = ""

# Agent fleet model assignment config: role -> model_id
_agent_config: dict[str, str] = {
    "orchestrator": "",
    "coder": "",
    "reviewer": "",
    "researcher": "",
    "tester": "",
}


def get_agent() -> JSAgent:
    if _agent is None:
        raise HTTPException(503, "Agent not initialized yet. Please wait for startup to complete.")
    return _agent


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
    # Clean up empty sessions on startup
    try:
        cleaned = _agent.memory.cleanup_empty_sessions()
        if cleaned:
            logger.info(f"Cleaned up {cleaned} empty sessions on startup")
    except Exception:
        logger.warning("Failed to clean up empty sessions", exc_info=True)
    # Load Hermes skills asynchronously so the web server starts immediately
    try:
        asyncio.create_task(_agent.skills.load_hermes_async())
        logger.info("Hermes skill loading started in background")
    except Exception:
        logger.warning("Failed to start Hermes skill loading", exc_info=True)
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


def create_app() -> FastAPI:
    app = FastAPI(title="JS Agent Web UI", lifespan=lifespan)
    FastAPIInstrumentor.instrument_app(app)
    app.mount("/metrics", make_asgi_app())

    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    # Include extracted routers
    app.include_router(cron.router)
    app.include_router(plugins_router.router)
    app.include_router(fleet.router)

    @app.get("/", response_class=HTMLResponse)
    async def root() -> str:
        return _load_index_html()

    @app.get("/api/status")
    async def status() -> dict[str, Any]:
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

    @app.get("/api/metrics/providers")
    async def provider_metrics() -> dict[str, Any]:
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
                                            logger.warning('Operation failed', exc_info=True)
            except Exception:
                logger.warning('Operation failed', exc_info=True)
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

    @app.post("/api/cancel/{session_id}")
    async def cancel_session(session_id: str) -> dict[str, Any]:
        """Request cancellation of an active agent run for *session_id*."""
        agent = get_agent()
        ok = agent.request_cancel(session_id)
        if not ok:
            raise HTTPException(404, f"No active run for session {session_id}")
        return {"session_id": session_id, "cancelled": True}

    @app.get("/api/diag")
    async def diag() -> dict[str, Any]:
        """Diagnostic endpoint to verify server version, routes and subsystem health."""
        agent = get_agent()
        routes = []
        for r in app.routes:
            if hasattr(r, "methods") and hasattr(r, "path"):
                routes.append({"path": r.path, "methods": list(r.methods)})
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

    @app.get("/api/memory")
    async def memory() -> dict[str, Any]:
        agent = get_agent()
        return {"context": agent.memory.get_context_string(max_chars=4000)}

    @app.get("/api/memory/enhanced")
    async def memory_enhanced(session_id: str | None = None) -> dict[str, Any]:
        agent = get_agent()
        result: dict[str, Any] = {
            "context": agent.memory.get_context_string(max_chars=4000),
            "episodes": [
                {
                    "id": e.id,
                    "session_id": e.session_id,
                    "summary": e.summary,
                    "topics": e.topics,
                    "tokens_used": e.tokens_used,
                    "turn_count": e.turn_count,
                    "created_at": e.created_at,
                    "importance": e.importance,
                }
                for e in agent.memory.get_episodes(limit=20)
            ],
            "dream_logs": agent.memory.get_dream_logs(limit=10),
            "semantic_memories": agent.memory.get_all_semantic(limit=20),
            "working_memories": agent.memory.get_all_working(limit=20),
            "memory_files": agent.memory.list_memory_files(),
        }
        if session_id:
            result["session_working"] = agent.memory.get_working(session_id, limit=20)
        return result

    @app.get("/api/memory/files")
    async def memory_file_list() -> dict[str, Any]:
        agent = get_agent()
        return {"files": agent.memory.list_memory_files()}

    @app.get("/api/memory/files/{name}")
    async def memory_file_get(name: str) -> dict[str, Any]:
        agent = get_agent()
        try:
            content = agent.memory.read_memory_file(name)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        return {"name": name, "content": content}

    @app.put("/api/memory/files/{name}")
    async def memory_file_put(name: str, body: dict[str, Any]) -> dict[str, Any]:
        agent = get_agent()
        try:
            await asyncio.to_thread(agent.memory.write_memory_file, name, body.get("content", ""))
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        return {"name": name, "saved": True}

    @app.post("/api/memory/semantic")
    async def memory_semantic_post(body: dict[str, Any]) -> dict[str, Any]:
        agent = get_agent()
        key = (body.get("key") or "").strip()
        value = (body.get("value") or "").strip()
        category = (body.get("category") or "fact").strip()
        if not key or not value:
            raise HTTPException(400, "key and value are required")
        result = await asyncio.to_thread(
            agent.memory.store_semantic,
            key=key,
            value=value,
            category=category,
            confidence=0.9,
            source="manual",
        )
        return {"success": True, "key": key, **result}

    @app.delete("/api/memory/semantic/{memory_id}")
    async def memory_semantic_delete(memory_id: int) -> dict[str, Any]:
        agent = get_agent()
        ok = await asyncio.to_thread(agent.memory.delete_semantic, memory_id)
        if not ok:
            raise HTTPException(404, "memory not found")
        return {"success": True}

    @app.put("/api/memory/semantic/{memory_id}")
    async def memory_semantic_put(memory_id: int, body: dict[str, Any]) -> dict[str, Any]:
        agent = get_agent()
        value = (body.get("value") or "").strip()
        category = body.get("category")
        if not value:
            raise HTTPException(400, "value is required")
        ok = await asyncio.to_thread(
            agent.memory.update_semantic,
            memory_id,
            value,
            category=category,
        )
        if not ok:
            raise HTTPException(404, "memory not found")
        return {"success": True}

    @app.get("/api/setup/first-start")
    async def setup_first_start() -> dict[str, Any]:
        if _settings is None:
            return {"first_run_completed": False}
        return {"first_run_completed": _settings.first_run_completed}

    @app.post("/api/setup/complete")
    async def setup_complete() -> dict[str, Any]:
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

    @app.get("/api/audit")
    async def audit(limit: int = 50) -> dict[str, Any]:
        agent = get_agent()
        events = agent.audit.query(limit=limit)
        return {
            "events": [
                {
                    "timestamp": e.timestamp,
                    "type": e.event_type.value,
                    "actor": e.actor,
                    "action": e.action,
                }
                for e in events
            ]
        }

    @app.get("/api/files")
    async def list_files(path: str = ".") -> dict[str, Any]:
        agent = get_agent()
        # Validate path to prevent directory traversal
        try:
            resolved = (agent.settings.workspace / path).resolve()
            workspace_resolved = agent.settings.workspace.resolve()
            resolved.relative_to(workspace_resolved)
        except (ValueError, RuntimeError) as e:
            return {"success": False, "error": f"Invalid path: {e}"}

        handler = agent.registry.get_handler("file_list")
        if handler is None:
            return {"success": False, "error": "file_list tool not available"}
        result = await handler(path=path)
        return {"success": result.success, "output": result.output, "error": result.error}

    @app.get("/api/sessions")
    async def list_sessions(limit: int = 30) -> dict[str, Any]:
        agent = get_agent()
        sessions = agent.memory.get_sessions(limit=limit)
        return {"sessions": sessions}

    @app.get("/api/sessions/{session_id}/messages")
    async def session_messages(session_id: str) -> dict[str, Any]:
        agent = get_agent()
        messages = agent.memory.get_session_messages(session_id)
        return {"session_id": session_id, "messages": messages}

    @app.delete("/api/sessions/{session_id}")
    async def delete_session(session_id: str) -> dict[str, Any]:
        agent = get_agent()
        agent.memory.delete_session(session_id)
        return {"success": True, "session_id": session_id}

    @app.get("/api/models")
    async def models() -> dict[str, Any]:
        agent = get_agent()
        return {
            "providers": [
                {
                    "name": p.name,
                    "base_url": p.base_url,
                    "models": [
                        {
                            "id": m.id,
                            "name": m.name or m.id,
                            "context_window": m.context_window,
                            "max_tokens": m.max_tokens,
                            "cost_input": m.cost_input,
                            "cost_output": m.cost_output,
                        }
                        for m in p.models
                    ],
                }
                for p in agent.settings.providers
            ],
            "health": await agent.router.health_check(),
            "active_model": _active_model,
        }

    @app.post("/api/models/switch")
    async def models_switch(body: dict[str, Any]) -> dict[str, Any]:
        global _active_model
        model_id = (body.get("model_id") or "").strip()
        if not model_id:
            raise HTTPException(400, "model_id is required")
        agent = get_agent()
        valid_models = {
            f"{p.name}/{m.id}"
            for p in agent.settings.providers
            for m in p.models
        }
        if model_id not in valid_models:
            raise HTTPException(400, f"Invalid model '{model_id}'")
        _active_model = model_id
        return {"success": True, "model_id": model_id}

    def _validate_provider_name(name: str) -> None:
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", name):
            raise HTTPException(
                400,
                "Provider name must be 1-64 chars, alphanumeric, hyphen, or underscore",
            )

    def _validate_url(url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise HTTPException(400, "URL scheme must be http or https")
        if not parsed.netloc:
            raise HTTPException(400, "URL must have a host")

    @app.post("/api/providers/discover")
    async def discover_provider(
        payload: dict[str, Any],
        auth: dict[str, Any] = Depends(require_auth_dep),
    ) -> dict[str, Any]:
        base_url = payload.get("base_url", "").strip()
        api_key = payload.get("api_key") or None
        if not base_url:
            raise HTTPException(400, "base_url is required")
        _validate_url(base_url)
        result = await ProviderManager.discover_models(base_url, api_key)
        if "error" in result:
            raise HTTPException(502, result["error"])
        return {"base_url": base_url, "models": result["models"]}

    @app.post("/api/providers/connect")
    async def connect_provider(payload: dict[str, Any]) -> dict[str, Any]:
        name = payload.get("name", "").strip()
        base_url = payload.get("base_url", "").strip()
        api_key = payload.get("api_key", "").strip() or None
        model_ids = payload.get("models", [])

        if not name or not base_url:
            raise HTTPException(400, "name and base_url are required")
        _validate_provider_name(name)
        _validate_url(base_url)

        if not isinstance(model_ids, list) or not model_ids:
            raise HTTPException(400, "at least one model must be selected")
        if not all(isinstance(m, dict) and "id" in m for m in model_ids):
            raise HTTPException(400, "models must be a list of objects with 'id'")

        models = [ModelConfig(id=m["id"], name=m.get("name", m["id"])) for m in model_ids]
        cfg = ModelProviderConfig(
            name=name,
            base_url=base_url,
            api_key=api_key,
            default_model=models[0].id if models else "",
            models=models,
        )

        agent = get_agent()
        # Prevent overriding static config
        static_names = {p.name for p in agent.settings.providers}
        # Exclude dynamically-added ones to detect true static conflicts
        dyn_names = {p.name for p in agent.provider_manager.get_all()}
        true_static = static_names - dyn_names
        if name in true_static:
            raise HTTPException(
                409, f"Provider name '{name}' conflicts with static config"
            )

        try:
            # Persist
            agent.provider_manager.add(cfg)
            # Update settings + router in-memory (dedupe settings list first)
            agent.settings.providers = [
                p for p in agent.settings.providers if p.name != name
            ]
            agent.settings.providers.append(cfg)
            agent.router.add_provider(cfg.name, OpenAICompatibleProvider(cfg), models)
        except Exception as e:
            # Rollback: remove from manager if it was saved
            try:
                agent.provider_manager.remove(name)
            except Exception:
                logger.warning('Operation failed', exc_info=True)
            agent.settings.providers = [
                p for p in agent.settings.providers if p.name != name
            ]
            agent.router.remove_provider(name)
            raise HTTPException(500, f"Failed to connect provider: {e}") from e

        return {"success": True, "provider": name, "models_added": len(models)}

    @app.delete("/api/providers/{name}")
    async def delete_provider(name: str) -> dict[str, Any]:
        agent = get_agent()
        # Remove from dynamic provider_manager (if it was added at runtime)
        agent.provider_manager.remove(name)
        # Remove from static settings
        before = len(agent.settings.providers)
        agent.settings.providers = [p for p in agent.settings.providers if p.name != name]
        removed = len(agent.settings.providers) < before
        # Remove from router
        agent.router.remove_provider(name)
        if not removed:
            raise HTTPException(404, f"Provider '{name}' not found")
        # Persist config change
        try:
            agent.settings.save()
        except Exception as e:
            logger.warning(f"Failed to save config after provider removal: {e}")
        # Clean up agent fleet config if it references this provider
        prefix = f"{name}/"
        for role in _agent_config:
            if _agent_config[role].startswith(prefix):
                _agent_config[role] = ""
        return {"success": True}

    @app.get("/api/providers/cloud-presets")
    async def cloud_presets() -> dict[str, Any]:
        """List all built-in cloud provider presets."""
        from js.models.cloud_providers import list_presets
        return {"presets": list_presets()}

    @app.post("/api/providers/add-cloud")
    async def add_cloud_provider(payload: dict[str, Any]) -> dict[str, Any]:
        """One-click add a cloud provider from presets."""
        from js.models.cloud_providers import build_provider_config, get_preset

        preset_id = payload.get("preset_id", "").strip()
        api_key = payload.get("api_key", "").strip()

        if not preset_id:
            raise HTTPException(400, "preset_id is required")

        preset = get_preset(preset_id)
        if not preset:
            raise HTTPException(404, f"Unknown preset: {preset_id}")

        if not api_key:
            # Try to load from environment
            import os
            api_key = os.getenv(preset.api_key_env, "")
            if not api_key:
                raise HTTPException(
                    400,
                    f"API key required. Set {preset.api_key_env} environment variable or pass api_key in payload."
                )

        cfg = build_provider_config(preset, api_key)
        agent = get_agent()

        # Prevent overriding static config
        static_names = {p.name for p in agent.settings.providers}
        dyn_names = {p.name for p in agent.provider_manager.get_all()}
        true_static = static_names - dyn_names
        if preset_id in true_static:
            raise HTTPException(409, f"Provider '{preset_id}' conflicts with static config")

        try:
            agent.provider_manager.add(cfg)
            agent.settings.providers = [
                p for p in agent.settings.providers if p.name != preset_id
            ]
            agent.settings.providers.append(cfg)
            agent.router.add_provider(cfg.name, OpenAICompatibleProvider(cfg), cfg.models)
        except Exception as e:
            try:
                agent.provider_manager.remove(preset_id)
            except Exception:
                logger.warning('Operation failed', exc_info=True)
            agent.settings.providers = [
                p for p in agent.settings.providers if p.name != preset_id
            ]
            agent.router.remove_provider(preset_id)
            raise HTTPException(500, f"Failed to add provider: {e}") from e

        return {
            "success": True,
            "provider": preset_id,
            "name": preset.name,
            "models_added": len(cfg.models),
        }

    @app.post("/api/providers/scan-lan")
    async def scan_lan(
        payload: dict[str, Any] | None = None,
        auth: dict[str, Any] = Depends(require_auth_dep),
    ) -> dict[str, Any]:
        """Scan the local network for model servers."""
        from js.discovery.local_models import LocalModelDiscovery

        subnet = (payload or {}).get("subnet", "192.168")
        discovery = LocalModelDiscovery(timeout=2.0)
        try:
            discovered = await discovery.scan_lan(subnet_prefix=subnet)
            return {
                "success": True,
                "subnet": subnet,
                "found": len(discovered),
                "providers": [
                    {
                        "name": d.name,
                        "type": d.provider_type,
                        "base_url": d.base_url,
                        "models": [{"id": m.id, "name": m.name} for m in d.models],
                        "latency_ms": round(d.latency_ms, 1),
                    }
                    for d in discovered
                ],
            }
        except Exception as e:
            logger.error(f"LAN scan failed: {e}", exc_info=True)
            raise HTTPException(500, f"LAN scan failed: {e}") from e
        finally:
            await discovery.close()

    @app.get("/api/stats/tokens")
    async def token_stats(days: int = 30) -> dict[str, Any]:
        if _stats_store is None:
            raise HTTPException(503, "Stats store not initialized")
        return _stats_store.get_summary(days=days)

    @app.get("/api/evolution/reports")
    async def evolution_reports(limit: int = 10) -> dict[str, Any]:
        agent = get_agent()
        reports = agent.metacognition.get_recent_reports(limit=limit)
        return {"reports": reports}

    @app.get("/api/evolution/proposals")
    async def evolution_proposals(limit: int = 20) -> dict[str, Any]:
        agent = get_agent()
        proposals = agent.metacognition.get_proposals(limit=limit)
        return {"proposals": proposals}

    @app.get("/api/evolution/insights")
    async def evolution_insights(limit: int = 20) -> dict[str, Any]:
        agent = get_agent()
        return {
            "learning": {
                "stats": agent.learner.get_stats(),
                "insights": agent.learner.get_insights(limit=limit),
                "suggestions": agent.learner.suggest_improvements(),
            },
            "optimization": agent.optimizer.get_report() if agent.optimizer else {},
            "compression": agent.compression_feedback.get_stats() if agent.compression_feedback else {},
        }

    @app.post("/api/evolution/run")
    async def evolution_run() -> dict[str, Any]:
        agent = get_agent()

        # Pre-flight readiness check
        if not hasattr(agent, "_run_evolution_cycle"):
            raise HTTPException(
                501,
                "Agent does not support evolution cycles. Please restart the server with the latest code.",
            )
        missing = [
            name for name, ok in {
                "metacognition": agent.metacognition is not None,
                "learner": agent.learner is not None,
                "optimizer": agent.optimizer is not None,
                "evolver": agent.evolver is not None,
            }.items() if not ok
        ]
        if missing:
            raise HTTPException(
                503,
                f"Evolution subsystems not ready: {', '.join(missing)}. Please wait for startup to complete.",
            )

        try:
            report = await agent._run_evolution_cycle([])
            return {
                "success": True,
                "message": "Evolution cycle completed",
                "report": report,
            }
        except Exception as e:
            # If the exception already carries an HTTP-like code in its message,
            # surface a more specific error. Otherwise return generic 500.
            msg = str(e)
            if "404" in msg and "model" in msg.lower():
                raise HTTPException(
                    502,
                    "LLM API returned 404 (model not found). Check your model configuration in settings.",
                ) from e
            logger.error(f"Evolution cycle failed: {e}", exc_info=True)
            raise HTTPException(500, f"Evolution cycle failed: {e}") from e

    @app.post("/api/evolution/reflect")
    async def evolution_reflect() -> dict[str, Any]:
        """Trigger an immediate metacognition reflection."""
        agent = get_agent()
        if agent.metacognition is None:
            raise HTTPException(503, "Metacognition subsystem not ready")
        try:
            report = await asyncio.to_thread(agent.metacognition.reflect)
        except Exception as e:
            logger.error(f"Metacognition reflect failed: {e}", exc_info=True)
            raise HTTPException(500, f"Reflection failed: {e}") from e
        return {
            "health_score": report.overall_health_score,
            "proposals": len(report.proposals),
            "actions_taken": len(report.actions_taken),
            "timestamp": report.timestamp,
        }

    @app.get("/api/agents/config")
    async def get_agent_config() -> dict[str, Any]:
        agent = get_agent()
        # Build available models list for the UI
        available_models: list[dict[str, Any]] = []
        for p in agent.settings.providers:
            for m in p.models:
                available_models.append({
                    "id": f"{p.name}/{m.id}",
                    "provider": p.name,
                    "model_id": m.id,
                    "model_name": m.name or m.id,
                    "context_window": m.context_window,
                })
        return {
            "config": _agent_config,
            "available_models": available_models,
            "roles": list(_agent_config.keys()),
        }

    @app.post("/api/agents/config")
    async def set_agent_config(payload: dict[str, Any]) -> dict[str, Any]:
        global _agent_config
        new_config = payload.get("config", {})
        agent = get_agent()
        # Validate model IDs against available providers
        valid_models = {
            f"{p.name}/{m.id}"
            for p in agent.settings.providers
            for m in p.models
        }
        for role, model in new_config.items():
            if role in _agent_config:
                if model and model not in valid_models and model != "":
                    raise HTTPException(400, f"Invalid model '{model}' for role '{role}'")
                _agent_config[role] = model
        return {"success": True, "config": _agent_config}

    @app.get("/api/search")
    async def search_api(query: str, max_results: int = 5) -> dict[str, Any]:
        agent = get_agent()
        results = await agent.search.search(query, max_results)
        return {
            "results": [
                {"title": r.title, "url": r.url, "snippet": r.snippet, "source": r.source}
                for r in results
            ]
        }

    @app.get("/api/skills")
    async def skills_api(
        category: str | None = None,
        skill_type: str | None = None,
        query: str | None = None,
    ) -> dict[str, Any]:
        agent = get_agent()
        from js.skills.spec import SkillType
        st = SkillType(skill_type) if skill_type else None
        skills = agent.skills.list_skills(category=category, skill_type=st, query=query)
        return {
            "skills": skills,
            "categories": agent.skills.list_categories(),
            "global_stats": agent.skills.get_global_stats(),
        }

    @app.get("/api/skills/metrics")
    async def skills_metrics() -> dict[str, Any]:
        """Return skill execution metrics for observability dashboard."""
        agent = get_agent()
        all_skills = agent.skills.list_skills()
        per_skill: list[dict[str, Any]] = []
        for skill in all_skills:
            stats = agent.skills.get_stats(skill["id"])
            if stats:
                per_skill.append({
                    "id": stats["id"],
                    "name": stats["name"],
                    "type": stats.get("type", "unknown"),
                    "trust_level": stats.get("trust_level", "community"),
                    "usage_count": stats.get("usage_count", 0),
                    "success_rate": round(stats.get("success_rate", 1.0), 3),
                    "avg_latency_ms": round(stats.get("avg_latency_ms", 0.0), 1),
                    "prerequisites_ok": stats.get("prerequisites_ok", True),
                })
        per_skill.sort(key=lambda x: x["usage_count"], reverse=True)
        return {
            "global": agent.skills.get_global_stats(),
            "per_skill": per_skill,
        }

    @app.get("/api/memory/metrics")
    async def memory_metrics() -> dict[str, Any]:
        """Return memory subsystem metrics for observability dashboard."""
        agent = get_agent()
        embedder_health = agent.memory.embedder.health()

        # Pull Prometheus metric samples (best-effort)
        from prometheus_client import REGISTRY
        def _sample(name: str, label_filters: dict[str, str] | None = None) -> float:
            total = 0.0
            try:
                for family in REGISTRY.collect():
                    if family.name == name:
                        for sample in family.samples:
                            if label_filters is None or all(sample.labels.get(k) == v for k, v in label_filters.items()):
                                total += sample.value
            except Exception:
                logger.warning('Operation failed', exc_info=True)
            return total

        return {
            "embedder": {
                "provider": embedder_health.provider,
                "active": embedder_health.active,
                "fallback_provider": embedder_health.fallback_provider,
                "failure_count": embedder_health.failure_count,
            },
            "prometheus": {
                "memory_store_latency_seconds_count": _sample("memory_store_latency_seconds_count"),
                "memory_store_latency_seconds_sum": _sample("memory_store_latency_seconds_sum"),
                "memory_retrieve_latency_seconds_count": _sample("memory_retrieve_latency_seconds_count"),
                "memory_retrieve_latency_seconds_sum": _sample("memory_retrieve_latency_seconds_sum"),
                "memory_search_fallback_total": _sample("memory_search_fallback_total"),
            },
            "counts": {
                "episodes": len(agent.memory.get_episodes(limit=1000)),
                "semantic_memories": len(agent.memory.get_all_semantic(limit=1000)),
                "working_memories": len(agent.memory.get_all_working(limit=1000)),
                "dream_logs": len(agent.memory.get_dream_logs(limit=1000)),
            },
        }

    @app.post("/api/memory/embedder/recover")
    async def memory_embedder_recover() -> dict[str, Any]:
        """Manually trigger embedder recovery probe.

        First tries to re-instantiate a fresh embedder (catches cases where
        the provider became available after agent startup or the HTTP client
        is in a bad state).  If that fails, falls back to probing the
        existing embedder via force_recover().
        """
        agent = get_agent()
        # Attempt 1: rebuild from scratch — this handles provider configs
        # that changed after startup (e.g. LM Studio loaded an embedding
        # model) or a stale httpx client.
        try:
            new_embedder = await asyncio.to_thread(agent._setup_embedder)
            # If we got a KeywordEmbedder back, no provider supports embeddings.
            from js.memory.embeddings import KeywordEmbedder
            if not isinstance(new_embedder, KeywordEmbedder):
                # Fresh HybridEmbedder created — swap it in.
                agent.memory.replace_embedder(new_embedder)
                health = new_embedder.health()
                return {
                    "success": True,
                    "provider": health.provider,
                    "active": health.active,
                    "fallback_provider": health.fallback_provider,
                    "failure_count": health.failure_count,
                    "recovered": True,
                    "method": "rebuild",
                }
        except Exception:
            logger.warning('Operation failed', exc_info=True)

        # Attempt 2: probe the existing embedder.
        embedder = agent.memory.embedder
        if hasattr(embedder, "force_recover"):
            ok = embedder.force_recover()
            health = embedder.health()
            return {
                "success": ok,
                "provider": health.provider,
                "active": health.active,
                "fallback_provider": health.fallback_provider,
                "failure_count": health.failure_count,
                "recovered": ok,
                "method": "probe",
            }
        return {
            "success": False,
            "reason": "Current embedder does not support runtime recovery",
        }

    # Hermes-specific endpoints MUST be defined BEFORE /api/skills/{skill_id}
    # to avoid "hermes" being captured as a skill_id path parameter.
    @app.get("/api/skills/hermes")
    async def hermes_skills_list() -> dict[str, Any]:
        """List all Hermes skills with bridge diagnostics."""
        agent = get_agent()
        from js.skills.hermes_bridge import get_bridge_stats, is_hermes_skill

        hermes_skills = [
            s.to_summary_dict()
            for s in agent.skills.get_all().values()
            if is_hermes_skill(s.id)
        ]
        stats = get_bridge_stats()
        return {
            "skills": hermes_skills,
            "count": len(hermes_skills),
            "stats": stats.to_dict(),
        }

    @app.post("/api/skills/hermes/refresh")
    async def hermes_skills_refresh() -> dict[str, Any]:
        """Refresh Hermes skills from disk without restarting the server."""
        agent = get_agent()
        result = agent.skills.refresh_hermes_skills()
        if result.get("success"):
            return result
        raise HTTPException(500, result.get("error", "Refresh failed"))

    @app.get("/api/skills/{skill_id}")
    async def skill_detail(skill_id: str) -> dict[str, Any]:
        agent = get_agent()
        detail = agent.skills.view_skill(skill_id)
        if not detail:
            raise HTTPException(404, f"Skill '{skill_id}' not found")
        return detail

    @app.post("/api/skills/install")
    async def skill_install(payload: dict[str, Any]) -> dict[str, Any]:
        agent = get_agent()
        source = payload.get("source", "")
        skill_id = payload.get("skill_id")
        try:
            spec = await agent.skills.install(source, skill_id)
            return {
                "success": True,
                "skill_id": spec.id,
                "trust_level": spec.trust_level.value,
                "risk_flags": spec.risk_flags,
            }
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        except Exception as e:
            logger.error(f"Skill install failed: {e}", exc_info=True)
            raise HTTPException(500, f"Failed to install skill: {e}") from e

    @app.delete("/api/skills/{skill_id}")
    async def skill_uninstall(skill_id: str) -> dict[str, Any]:
        agent = get_agent()
        if await agent.skills.uninstall(skill_id):
            return {"success": True}
        raise HTTPException(404, "Skill not found or is built-in")

    @app.post("/api/skills/{skill_id}/trust")
    async def skill_trust(skill_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        from js.skills.spec import TrustLevel

        agent = get_agent()
        level = payload.get("level", "")
        try:
            trust_level = TrustLevel(level)
        except ValueError:
            raise HTTPException(400, f"Invalid trust level: {level}") from None
        if agent.skills.trust_skill(skill_id, trust_level):
            return {"success": True, "skill_id": skill_id, "trust_level": level}
        raise HTTPException(404, f"Skill '{skill_id}' not found")

    @app.get("/api/skills/discover")
    async def skill_discover(query: str = "") -> dict[str, Any]:
        """Search the ClawHub skill marketplace."""
        agent = get_agent()
        if not hasattr(agent, "_clawhub") or agent._clawhub is None:
            from js.skills.clawhub import ClawHubClient

            agent._clawhub = ClawHubClient(agent.settings.state_dir)

        try:
            index = await agent._clawhub.fetch_index()
        except Exception as e:
            logger.error(f"ClawHub fetch failed: {e}", exc_info=True)
            raise HTTPException(502, f"Failed to fetch ClawHub index: {e}") from e
        results = agent._clawhub.search_index(query) if query else index
        return {
            "success": True,
            "total": len(index),
            "results": results[:50],  # Limit to 50 results
        }

    @app.post("/api/skills/discover/install")
    async def skill_discover_install(payload: dict[str, Any]) -> dict[str, Any]:
        """Install a skill from the ClawHub marketplace."""
        from js.skills.clawhub import ClawHubClient

        skill_id = payload.get("skill_id", "")
        if not skill_id:
            raise HTTPException(400, "skill_id is required")

        agent = get_agent()
        clawhub = getattr(agent, "_clawhub", None) or ClawHubClient(agent.settings.state_dir)
        agent._clawhub = clawhub

        source = clawhub.get_skill_source(skill_id)
        if not source:
            raise HTTPException(404, f"Skill '{skill_id}' not found in ClawHub index")

        try:
            spec = await agent.skills.install(source, skill_id)
            return {
                "success": True,
                "skill_id": spec.id,
                "trust_level": spec.trust_level.value,
            }
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        except Exception as e:
            logger.error(f"ClawHub install failed: {e}", exc_info=True)
            raise HTTPException(500, f"Failed to install skill: {e}") from e

    @app.post("/api/upload")
    async def upload_file(file: UploadFile | None = None) -> dict[str, Any]:
        """Upload a file to the workspace/uploads directory."""
        if file is None:
            raise HTTPException(400, "No file provided")
        agent = get_agent()
        uploads_dir = agent.settings.workspace / "uploads"
        uploads_dir.mkdir(parents=True, exist_ok=True)

        # Sanitize filename: basename only, no path traversal
        from pathlib import PurePath
        safe_name = PurePath(file.filename or "unnamed").name
        if not safe_name or safe_name.startswith("."):
            safe_name = "unnamed"

        target_path = uploads_dir / safe_name
        # Handle duplicate names
        counter = 1
        stem = target_path.stem
        suffix = target_path.suffix
        while target_path.exists():
            target_path = uploads_dir / f"{stem}_{counter}{suffix}"
            counter += 1

        max_size = 100 * 1024 * 1024  # 100MB
        total = 0
        with target_path.open("wb") as f:
            while True:
                chunk = await file.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_size:
                    target_path.unlink(missing_ok=True)
                    raise HTTPException(413, "File too large (max 100MB)")
                f.write(chunk)

        rel_path = str(target_path.relative_to(agent.settings.workspace))
        return {
            "success": True,
            "filename": safe_name,
            "saved_as": target_path.name,
            "path": rel_path,
            "size": total,
            "content_type": file.content_type or "application/octet-stream",
        }

    @app.get("/api/uploads")
    async def list_uploads() -> dict[str, Any]:
        """List uploaded files in workspace/uploads."""
        agent = get_agent()
        uploads_dir = agent.settings.workspace / "uploads"
        if not uploads_dir.exists():
            return {"files": []}
        files = []
        for f in sorted(uploads_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if f.is_file():
                stat = f.stat()
                files.append({
                    "name": f.name,
                    "path": str(f.relative_to(agent.settings.workspace)),
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                })
        return {"files": files}

    @app.delete("/api/uploads/{filename}")
    async def delete_upload(filename: str) -> dict[str, Any]:
        """Delete an uploaded file."""
        agent = get_agent()
        from pathlib import PurePath
        safe_name = PurePath(filename).name
        target = agent.settings.workspace / "uploads" / safe_name
        try:
            target.relative_to(agent.settings.workspace / "uploads")
        except ValueError:
            raise HTTPException(400, "Invalid filename") from None
        if target.exists():
            target.unlink()
            return {"success": True}
        raise HTTPException(404, "File not found")

    @app.get("/api/file-preview")
    async def file_preview(path: str) -> dict[str, Any]:
        """Preview a file's content or metadata."""
        agent = get_agent()
        try:
            resolved = (agent.settings.workspace / path).resolve()
            resolved.relative_to(agent.settings.workspace.resolve())
        except (ValueError, RuntimeError) as e:
            raise HTTPException(400, f"Invalid path: {e}") from e

        if not resolved.exists():
            raise HTTPException(404, "File not found")

        result: dict[str, Any] = {
            "path": path,
            "name": resolved.name,
            "size": resolved.stat().st_size,
        }

        # Text files: return content preview
        text_suffixes = {".txt", ".md", ".py", ".js", ".json", ".yaml", ".yml", ".csv", ".html", ".css", ".xml", ".sh", ".log"}
        if resolved.suffix.lower() in text_suffixes:
            try:
                content = resolved.read_text(encoding="utf-8", errors="replace")
                result["type"] = "text"
                result["content"] = content[:5000]
                result["truncated"] = len(content) > 5000
            except Exception as e:
                result["type"] = "binary"
                result["error"] = str(e)
        else:
            result["type"] = "binary"

        return result

    @app.post("/api/chat")
    async def chat(
        payload: dict[str, Any],
        auth: dict[str, Any] = Depends(require_auth_dep),
    ) -> dict[str, Any]:
        agent = get_agent()
        message = payload.get("message", "")
        session_id = payload.get("session_id")
        model = payload.get("model")
        attachments = payload.get("attachments", [])

        try:
            state = await agent.run(message, session_id=session_id, model=model, attachments=attachments)
        except Exception as e:
            logger.error(f"Chat error: {e}", exc_info=True)
            raise HTTPException(500, f"Agent run failed: {e}") from e

        assistant_msg = ""
        for msg in reversed(state.messages):
            if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                assistant_msg = msg.content
                break

        return {
            "response": assistant_msg,
            "session_id": state.session_id,
            "turns": state.turn_count,
            "tokens": state.total_tokens,
            "status": state.status,
        }

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        # Authenticate WebSocket connection via X-API-Key header
        from js.exceptions import AuthRequiredError
        from js.web.auth import AuthManager
        api_key = websocket.headers.get("x-api-key", "")
        settings = get_agent().settings
        if settings.security.api_key_required:
            auth_mgr = AuthManager(settings.state_dir)
            if auth_mgr.has_admin():
                try:
                    auth_mgr.verify(api_key)
                except AuthRequiredError as e:
                    await websocket.close(code=1008, reason=str(e))
                    return
        await websocket.accept()
        agent = get_agent()
        session_id: str | None = None
        max_msg_bytes = 1024 * 1024  # 1MB
        ping_interval = 30.0

        async def _receive_with_limit() -> dict[str, Any]:
            raw = await websocket.receive()
            if isinstance(raw, str):
                if len(raw.encode("utf-8")) > max_msg_bytes:
                    raise ValueError("Message too large")
                return json.loads(raw)
            if isinstance(raw, bytes):
                if len(raw) > max_msg_bytes:
                    raise ValueError("Message too large")
                return json.loads(raw.decode("utf-8"))
            # WebSocket text frame from Starlette
            data = raw.get("text") or raw.get("bytes", b"").decode("utf-8")
            if len(data.encode("utf-8")) > max_msg_bytes:
                raise ValueError("Message too large")
            result: dict[str, Any] = json.loads(data)
            return result

        try:
            while True:
                # Receive with timeout to allow periodic ping checks
                try:
                    data = await asyncio.wait_for(_receive_with_limit(), timeout=ping_interval)
                except TimeoutError:
                    try:
                        await websocket.send_json({"type": "ping"})
                    except Exception:
                        break
                    continue

                msg_type = data.get("type", "message")

                if msg_type == "message":
                    user_msg = data.get("content", "")
                    session_id = data.get("session_id") or session_id
                    model = data.get("model") or _active_model or None
                    attachments = data.get("attachments", [])

                    await websocket.send_json({"type": "status", "content": "thinking..."})

                    state = await agent.run(user_msg, session_id=session_id, model=model, attachments=attachments)
                    session_id = state.session_id

                    assistant_msg = ""
                    for msg in reversed(state.messages):
                        if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                            assistant_msg = msg.content
                            break

                    # Record token usage
                    if _stats_store and state.total_tokens["input"] + state.total_tokens["output"] > 0:
                        _stats_store.record(
                            model=model or state.messages[-1].role or "unknown",
                            provider="",
                            prompt_tokens=state.total_tokens["input"],
                            completion_tokens=state.total_tokens["output"],
                            cost=state.cost_estimate,
                            session_id=session_id,
                            run_id=state.run_id,
                        )

                    await websocket.send_json(
                        {
                            "type": "response",
                            "content": assistant_msg,
                            "session_id": session_id,
                            "turns": state.turn_count,
                            "tokens": state.total_tokens,
                            "cost": round(state.cost_estimate, 6),
                            "status": state.status,
                            "compression": state.compression_stats,
                        }
                    )

                elif msg_type == "stream":
                    user_msg = data.get("content", "")
                    session_id = data.get("session_id") or session_id
                    model = data.get("model")
                    attachments = data.get("attachments", [])

                    await websocket.send_json({"type": "status", "content": "streaming..."})

                    # Native token-level streaming for the final assistant response.
                    # Tool-calling turns remain non-streaming (parsed atomically).
                    streamed = False

                    async def _send_token(token: str) -> None:
                        nonlocal streamed
                        streamed = True
                        await websocket.send_json({"type": "token", "content": token})

                    state = await agent.run(
                        user_msg,
                        session_id=session_id,
                        model=model,
                        attachments=attachments,
                        stream_callback=_send_token,
                    )
                    session_id = state.session_id

                    assistant_msg = ""
                    for msg in reversed(state.messages):
                        if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                            assistant_msg = msg.content
                            break

                    # Fallback: if streaming never fired (all tool turns or provider
                    # doesn't support streaming), send the full response in one go.
                    if not streamed and assistant_msg:
                        await websocket.send_json({"type": "response", "content": assistant_msg})

                    await websocket.send_json({
                        "type": "done",
                        "session_id": session_id,
                        "turns": state.turn_count,
                        "tokens": state.total_tokens,
                        "cost": round(state.cost_estimate, 6),
                        "status": state.status,
                        "compression": state.compression_stats,
                    })

                    # Store memories for stream path (same as run() path)
                    try:
                        redacted_msg = agent.secrets.detect_and_redact(user_msg, "user_input")
                        await asyncio.to_thread(
                            agent.memory.store_working,
                            session_id=session_id,
                            key="user_input",
                            value=redacted_msg[:500],
                            category="interaction",
                            importance=5,
                        )
                        await asyncio.to_thread(
                            agent.memory.store_episode,
                            session_id=session_id,
                            summary=f"User: {redacted_msg[:80]}... → Assistant: {assistant_msg[:80]}...",
                            topics=list({
                                word.lower() for word in (redacted_msg + " " + assistant_msg).split()
                                if len(word) > 4 and word.isalpha()
                            })[:5],
                            importance=5,
                        )
                        # Persist conversation messages
                        await asyncio.to_thread(
                            agent.memory.store_messages,
                            session_id,
                            [
                                {"role": "user", "content": redacted_msg},
                                {"role": "assistant", "content": assistant_msg},
                            ],
                        )
                        agent._dream_scheduler.notify_activity(user_msg, assistant_msg)
                    except Exception:
                        logger.warning("Stream memory storage failed", exc_info=True)

                elif msg_type == "ping":
                    await websocket.send_json({"type": "pong"})

        except WebSocketDisconnect:
            logger.info("WebSocket disconnected")
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            try:
                await websocket.send_json({"type": "error", "content": str(e)})
            except Exception:
                logger.warning("Failed to send error to websocket", exc_info=True)

    return app


_TEMPLATE_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"

def _load_index_html() -> str:
    path = _TEMPLATE_DIR / 'index.html'
    if path.exists():
        return path.read_text(encoding='utf-8')
    return '<h1>Template not found</h1>'

