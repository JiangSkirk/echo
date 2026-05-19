"""FastAPI Web server with WebSocket streaming."""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from js.orchestration.fleet import AgentFleet
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
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
from js.web.stats_store import TokenStatsStore

HTTPXClientInstrumentor().instrument()

logger = get_logger("js.web")

# Global agent instance
_agent: JSAgent | None = None
_settings: JSSettings | None = None
_stats_store: TokenStatsStore | None = None
_fleet: Any | None = None

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
        raise RuntimeError("Agent not initialized")
    return _agent


def get_fleet() -> AgentFleet:
    global _fleet
    if _fleet is None:
        from js.orchestration.fleet import AgentFleet

        _fleet = AgentFleet(_settings or JSSettings.from_file())
    return _fleet


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    global _agent, _settings, _stats_store
    _settings = JSSettings.from_file()
    _agent = JSAgent(_settings)
    _agent.start_background_tasks()
    _stats_store = TokenStatsStore(_settings.state_dir)
    # Clean up empty sessions on startup
    try:
        cleaned = _agent.memory.cleanup_empty_sessions()
        if cleaned:
            logger.info(f"Cleaned up {cleaned} empty sessions on startup")
    except Exception:
        logger.debug("Failed to clean up empty sessions", exc_info=True)
    logger.info("Web UI agent initialized")
    try:
        yield
    finally:
        if _agent:
            await _agent.close()
        _agent = None


def create_app() -> FastAPI:
    app = FastAPI(title="JS Agent Web UI", lifespan=lifespan)
    FastAPIInstrumentor.instrument_app(app)
    app.mount("/metrics", make_asgi_app())

    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def root() -> str:
        return _load_index_html()

    @app.get("/api/status")
    async def status() -> dict[str, Any]:
        agent = get_agent()
        return {
            "workspace": str(agent.settings.workspace),
            "state_dir": str(agent.settings.state_dir),
            "max_turns": agent.settings.max_turns,
            "defense_mode": agent.settings.security.defense_mode.value,
            "tool_stats": agent.registry.get_stats(),
            "secret_stats": agent.secrets.get_stats(),
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
        await asyncio.to_thread(
            agent.memory.store_semantic,
            key=key,
            value=value,
            category=category,
            confidence=0.9,
            source="manual",
        )
        return {"success": True, "key": key}

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
        }

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
    async def discover_provider(payload: dict[str, Any]) -> dict[str, Any]:
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
                pass
            agent.settings.providers = [
                p for p in agent.settings.providers if p.name != name
            ]
            agent.router.remove_provider(name)
            raise HTTPException(500, f"Failed to connect provider: {e}") from e

        return {"success": True, "provider": name, "models_added": len(models)}

    @app.delete("/api/providers/{name}")
    async def delete_provider(name: str) -> dict[str, Any]:
        agent = get_agent()
        removed = agent.provider_manager.remove(name)
        if not removed:
            raise HTTPException(404, f"Provider '{name}' not found")
        # Also remove from in-memory settings and router
        agent.settings.providers = [p for p in agent.settings.providers if p.name != name]
        agent.router.remove_provider(name)
        # Clean up agent fleet config if it references this provider
        prefix = f"{name}/"
        for role in _agent_config:
            if _agent_config[role].startswith(prefix):
                _agent_config[role] = ""
        return {"success": True}

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
        try:
            await agent._run_evolution_cycle([])
            return {"success": True, "message": "Evolution cycle completed"}
        except Exception as e:
            logger.error(f"Evolution cycle failed: {e}", exc_info=True)
            raise HTTPException(500, f"Evolution cycle failed: {e}") from e

    @app.post("/api/evolution/reflect")
    async def evolution_reflect() -> dict[str, Any]:
        """Trigger an immediate metacognition reflection."""
        agent = get_agent()
        report = await asyncio.to_thread(agent.metacognition.reflect)
        return {
            "health_score": report.overall_health_score,
            "proposals": len(report.proposals),
            "actions_taken": len(report.actions_taken),
            "timestamp": report.timestamp,
        }

    @app.get("/api/agents/config")
    async def get_agent_config() -> dict[str, Any]:
        return {"config": _agent_config}

    @app.post("/api/agents/config")
    async def set_agent_config(payload: dict[str, Any]) -> dict[str, Any]:
        global _agent_config
        new_config = payload.get("config", {})
        for role, model in new_config.items():
            if role in _agent_config:
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

    @app.get("/api/skills/{skill_id}")
    async def skill_detail(skill_id: str) -> dict[str, Any]:
        agent = get_agent()
        detail = agent.skills.view_skill(skill_id)
        if not detail:
            return {"error": "Skill not found"}
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
        except Exception as e:
            return {"success": False, "error": str(e)}

    @app.delete("/api/skills/{skill_id}")
    async def skill_uninstall(skill_id: str) -> dict[str, Any]:
        agent = get_agent()
        if await agent.skills.uninstall(skill_id):
            return {"success": True}
        return {"success": False, "error": "Skill not found or is built-in"}

    @app.post("/api/skills/{skill_id}/trust")
    async def skill_trust(skill_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        from js.skills.spec import TrustLevel

        agent = get_agent()
        level = payload.get("level", "")
        try:
            trust_level = TrustLevel(level)
        except ValueError:
            return {"success": False, "error": f"Invalid trust level: {level}"}
        if agent.skills.trust_skill(skill_id, trust_level):
            return {"success": True, "skill_id": skill_id, "trust_level": level}
        return {"success": False, "error": "Skill not found"}

    @app.get("/api/skills/discover")
    async def skill_discover(query: str = "") -> dict[str, Any]:
        """Search the ClawHub skill marketplace."""
        agent = get_agent()
        if not hasattr(agent, "_clawhub") or agent._clawhub is None:
            from js.skills.clawhub import ClawHubClient

            agent._clawhub = ClawHubClient(agent.settings.state_dir)

        index = await agent._clawhub.fetch_index()
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
            return {"success": False, "error": "skill_id is required"}

        agent = get_agent()
        clawhub = getattr(agent, "_clawhub", None) or ClawHubClient(agent.settings.state_dir)
        agent._clawhub = clawhub

        source = clawhub.get_skill_source(skill_id)
        if not source:
            return {"success": False, "error": f"Skill {skill_id} not found in ClawHub index"}

        try:
            spec = await agent.skills.install(source, skill_id)
            return {
                "success": True,
                "skill_id": spec.id,
                "trust_level": spec.trust_level.value,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    @app.post("/api/upload")
    async def upload_file(file: UploadFile | None = None) -> dict[str, Any]:
        if file is None:
            raise HTTPException(400, "No file provided")
        """Upload a file to the workspace/uploads directory."""
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
            return {"success": False, "error": "Invalid filename"}
        if target.exists():
            target.unlink()
            return {"success": True}
        return {"success": False, "error": "File not found"}

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
    async def chat(payload: dict[str, Any]) -> dict[str, Any]:
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
                    model = data.get("model")
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
                        }
                    )

                elif msg_type == "stream":
                    user_msg = data.get("content", "")
                    session_id = data.get("session_id") or session_id
                    model = data.get("model")
                    attachments = data.get("attachments", [])

                    await websocket.send_json({"type": "status", "content": "streaming..."})

                    assistant_msg = ""
                    async for token in agent.chat_stream(user_msg, session_id=session_id, model=model, attachments=attachments):
                        await websocket.send_json({"type": "token", "content": token})
                        assistant_msg += token

                    # Ensure session_id is stable for storage and client tracking
                    if not session_id:
                        session_id = str(uuid.uuid4())

                    await websocket.send_json({"type": "done", "session_id": session_id})

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
                        logger.debug("Stream memory storage failed", exc_info=True)

                elif msg_type == "ping":
                    await websocket.send_json({"type": "pong"})

        except WebSocketDisconnect:
            logger.info("WebSocket disconnected")
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            try:
                await websocket.send_json({"type": "error", "content": str(e)})
            except Exception:
                logger.debug("Failed to send error to websocket", exc_info=True)

    # ------------------------------------------------------------------
    # Fleet API
    # ------------------------------------------------------------------

    @app.get("/api/fleet/status")
    async def fleet_status() -> dict[str, Any]:
        fleet = get_fleet()
        return fleet.get_status()

    @app.post("/api/fleet/spawn")
    async def fleet_spawn(payload: dict[str, Any]) -> dict[str, Any]:
        from js.orchestration.fleet import AgentRole

        fleet = get_fleet()
        role = AgentRole(payload.get("role", "generalist"))
        agent = fleet.spawn(
            name=payload.get("name", f"agent-{role.value}"),
            role=role,
            model=payload.get("model"),
        )
        return {"success": True, "agent_id": agent.id, "role": role.value}

    @app.post("/api/fleet/dispatch")
    async def fleet_dispatch(payload: dict[str, Any]) -> dict[str, Any]:
        from js.orchestration.fleet import AgentRole, Task

        fleet = get_fleet()
        task = Task(
            id=str(uuid.uuid4()),
            description=payload.get("description", ""),
            role_hint=AgentRole(payload.get("role", "generalist")),
            priority=payload.get("priority", 5),
        )
        task_id = await fleet.dispatch(task)
        return {"success": True, "task_id": task_id}

    @app.post("/api/fleet/collaborate")
    async def fleet_collaborate(payload: dict[str, Any]) -> dict[str, Any]:
        from js.orchestration.fleet import AgentRole

        fleet = get_fleet()
        subtasks_raw = payload.get("subtasks", [])
        subtasks: list[tuple[str, AgentRole]] = []
        for st in subtasks_raw:
            subtasks.append((st.get("description", ""), AgentRole(st.get("role", "generalist"))))
        result = await fleet.collaborate(
            main_task=payload.get("task", ""),
            subtasks=subtasks,
        )
        return {"success": True, "result": result}

    @app.post("/api/fleet/broadcast")
    async def fleet_broadcast(payload: dict[str, Any]) -> dict[str, Any]:
        fleet = get_fleet()
        await fleet.broadcast(payload.get("message", ""))
        return {"success": True}

    return app



_TEMPLATE_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"

def _load_index_html() -> str:
    path = _TEMPLATE_DIR / 'index.html'
    if path.exists():
        return path.read_text(encoding='utf-8')
    return '<h1>Template not found</h1>'

