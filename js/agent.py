"""Core Agent engine: reasoning loop, delegation, and state management."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cachetools import TTLCache

from js.compression.compressor import CompressionConfig, ContextCompressor
from js.compression.feedback import CompressionFeedback
from js.config import JSSettings
from js.evolution.learner import SelfLearner
from js.evolution.metacognition import MetacognitionLoop
from js.evolution.optimizer import PromptOptimizer
from js.memory.embeddings import Embedder, HybridEmbedder, KeywordEmbedder, LLMEmbedder
from js.memory.scheduler import DreamScheduler
from js.memory.store import MemoryStore
from js.models.provider_manager import ProviderManager
from js.models.providers import ChatMessage, ChatResponse
from js.models.router import ModelRouter
from js.security.approvals import ApprovalMode, ApprovalQueue
from js.security.audit import AuditEventType, AuditLogger
from js.security.guard import BehaviorGuard
from js.security.sandbox import SandboxExecutor
from js.security.secrets import SecretManager
from js.security.strategies import build_default_strategies
from js.skills.composer import SkillComposer
from js.skills.curator import SkillCurator
from js.skills.evolver import SkillEvolver
from js.skills.manager import SkillManager
from js.tools.registry import ParallelToolExecutor, ToolRegistry, ToolResult
from js.utils.attachments import extract_excel_text, extract_pdf_text, format_size
from js.utils.log import get_logger
from js.utils.metrics import get_metrics, start_span


@dataclass
class AgentState:
    """Ephemeral state for a single agent run."""

    session_id: str
    run_id: str
    turn_count: int = 0
    messages: list[ChatMessage] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
    total_tokens: dict[str, int] = field(default_factory=lambda: {"input": 0, "output": 0})
    cached_tokens: int = 0
    cost_estimate: float = 0.0
    status: str = "running"  # running, completed, error, blocked
    error_message: str = ""
    compression_stats: dict[str, Any] = field(default_factory=dict)
    model: str = ""  # Actual model used for the last turn (provider/model_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "run_id": self.run_id,
            "turn_count": self.turn_count,
            "messages": [
                {
                    "role": m.role,
                    "content": m.content,
                    "name": getattr(m, "name", None),
                    "tool_calls": getattr(m, "tool_calls", None),
                    "tool_call_id": getattr(m, "tool_call_id", None),
                    "reasoning_content": getattr(m, "reasoning_content", None),
                }
                for m in self.messages
            ],
            "tool_results": [
                {"success": r.success, "output": r.output, "error": r.error}
                for r in self.tool_results
            ],
            "total_tokens": self.total_tokens,
            "cached_tokens": self.cached_tokens,
            "cost_estimate": self.cost_estimate,
            "status": self.status,
            "error_message": self.error_message,
            "compression_stats": self.compression_stats,
            "model": self.model,
        }


class JSAgent:
    """Main agent orchestrator."""

    SYSTEM_PROMPT = """You are JS, a helpful and capable AI assistant. You have access to tools for file operations, shell commands, code execution, and more.

Key rules:
1. Use tools when needed - don't guess about file contents or system state
2. Always check if a file exists before reading it
3. Prefer read-only tools for investigation before making changes
4. Explain your reasoning clearly
5. If a task is too complex, suggest breaking it down
6. Never expose secrets, API keys, or tokens in your responses
7. Respect the user's workspace - don't modify files outside it without permission

Programming workflow (critical for code tasks):
- STEP 1: EXPLORE. Use file_view to see directory structure, file_read or file_view to inspect code. Use code_search to find relevant code. Never write code blindly.
- STEP 2: PLAN. Think before editing. If the change is small and precise, use file_edit with an exact search/replace block. If the change is large or creates a new file, use file_write.
- STEP 3: EDIT. When editing existing files, prefer file_edit over file_write. The search block must match EXACTLY (including whitespace and newlines). If the search is ambiguous, read more context first.
- STEP 4: VERIFY. After making changes, run tests or lint checks using shell or python tools. If errors appear, fix them immediately. Do not declare success until verification passes.
- STEP 5: MINIMIZE. Make the smallest possible change to achieve the goal. Avoid rewriting entire files when a small edit suffices. This saves tokens and reduces error rates.

File tool guidelines:
- file_view: Use for browsing directories (tree view) or reading files WITH line numbers. Great for exploring project structure.
- file_read: Use for reading file content without line numbers.
- file_edit: Use for precise replacements. The "search" parameter must be a UNIQUE exact match in the file. Include enough surrounding lines to ensure uniqueness.
- file_write: Use for creating new files or complete rewrites only.
- code_search: Use to find where functions, classes, or variables are defined/used across the codebase.
- shell: Use for running tests (pytest, cargo test, npm test), linters, build commands, and git operations.

Web search tool:
- web_search: Search the web for current information, news, facts, or documentation. Returns top results with title, URL, and snippet. Use this when the user asks about recent events, current data, or anything you don't already know.

Browser automation tools (Kimi WebBridge — controls your real Chrome browser):
- web_navigate: Open a URL in the browser. Use new_tab=true on first navigation. Supports any website including those requiring login.
- web_snapshot: Capture the page accessibility tree with @e element references. ALWAYS use this after navigating to understand the page before clicking or filling.
- web_click: Click an element using @e reference (from snapshot) or CSS selector.
- web_fill: Fill input fields or textareas. Works on regular inputs and contenteditable editors.
- web_screenshot: Take a screenshot of the current page. Use when you need to "see" the page visually.
- web_evaluate: Execute JavaScript in the browser context. Use for complex interactions or extracting data.
- web_extract_text: Extract visible text from the page using JavaScript. CRITICAL FALLBACK: when web_snapshot returns an empty or very sparse tree (common on JavaScript-heavy sites like Douyin/TikTok, React/Vue SPAs), use this tool to get the actual page content.
- web_find_tab: Reuse an already-open tab instead of creating a new one.

Browser workflow (efficient — minimize steps):
1. Use web_navigate to open the site (or web_find_tab if already open)
2. Use web_snapshot to see the page structure
3. If the snapshot is too sparse (<200 chars), use web_extract_text ONCE to get the actual content
4. Use web_click/web_fill to interact ONLY when necessary
5. Use web_screenshot if visual confirmation is needed
6. Report findings and STOP. Do NOT navigate to the same URL repeatedly.

Search vs Fetch: Prefer web_search for finding information; use browser_fetch only when the user gives a specific URL. Do NOT use browser_fetch as a substitute for web_search.
"""

    def __init__(self, settings: JSSettings) -> None:
        self.settings = settings
        self.logger = get_logger("js.agent")
        self._role: str | None = None  # Set by AgentFleet.spawn() for role-based tool restrictions
        self._init_subsystems()

    def _init_subsystems(self) -> None:
        """Initialize all agent subsystems."""
        settings = self.settings

        # Core infrastructure
        self.router = ModelRouter(settings)
        # Load dynamically-added providers (skip if same name exists in static config)
        self.provider_manager = ProviderManager(settings.state_dir)
        static_names = {p.name for p in self.settings.providers}
        for dyn_cfg in self.provider_manager.get_all():
            if dyn_cfg.name in static_names:
                self.logger.warning(
                    f"Dynamic provider '{dyn_cfg.name}' skipped: "
                    "name conflicts with static config"
                )
                continue
            from js.models.providers import OpenAICompatibleProvider
            self.settings.providers.append(dyn_cfg)
            self.router.add_provider(
                dyn_cfg.name,
                OpenAICompatibleProvider(dyn_cfg),
                dyn_cfg.models,
            )
        self.guard = BehaviorGuard(settings.security, settings.workspace)
        self.audit = AuditLogger(settings.state_dir, settings.security.audit_retention_days)
        self.secrets = SecretManager(settings.state_dir)
        self.memory = MemoryStore(settings.state_dir, settings.memory, self._setup_embedder())
        self._dream_scheduler = DreamScheduler(self)

        # Plugin system
        self.plugins: Any = None
        self._init_plugins()

        # Tooling layer
        self.registry = ToolRegistry(settings.tools, self.guard)
        self.skills = SkillManager(settings.state_dir, settings.workspace)
        self.search = self._setup_search()

        # Learning & evolution
        self.learner = SelfLearner(settings.state_dir)
        self.optimizer = PromptOptimizer(settings.state_dir)
        self.evolver = SkillEvolver(settings.state_dir)
        self.composer = SkillComposer(settings.state_dir)
        self._clawhub: Any | None = None
        self.compression_config = CompressionConfig()
        self.compressor = ContextCompressor(self.compression_config, summarizer=self._summarize_context)
        self.compression_feedback = CompressionFeedback(settings.state_dir)
        self.metacognition = MetacognitionLoop(
            settings.state_dir,
            learner=self.learner,
            optimizer=self.optimizer,
            evolver=self.evolver,
            compression_feedback=self.compression_feedback,
            compression_config=self.compression_config,
            composer=self.composer,
        )
        self.curator = SkillCurator(settings.state_dir)

        # Execution & safety
        self.skills.set_composer(self.composer)
        self.skills.set_sandbox(SandboxExecutor(settings.workspace))
        self.skills.set_evolver(self.evolver)
        self.approvals = ApprovalQueue(default_mode=ApprovalMode.MANUAL)
        self.defense_strategies = build_default_strategies()
        self._setup_tools()

        # Register skills as callable tools
        self.skills.register_as_tools(self.registry)

        # Register default prompt variant for optimization
        self._init_default_prompt_variant()

        # Cancel & checkpoint support
        # Cancel-token storage: session_id -> (asyncio.Event, run_id)
        # The run_id guards against concurrent runs on the same session
        # popping each other's tokens.
        self._cancel_tokens: dict[str, tuple[asyncio.Event, str]] = {}
        self._shutdown_requested = False
        self._system_message_cache: TTLCache[tuple[str, str, str], str] = TTLCache(maxsize=100, ttl=60)
        self._degraded = False
        self.degraded_reason = ""
        self._current_allowed_tools: set[str] = set()
        self._consecutive_tool_failures: int = 0
        from js.persistence.state_store import StateStore
        self.state_store = StateStore(settings.state_dir / "checkpoints.db")
        from js.events.store import EventStore
        self.event_store = EventStore(settings.state_dir / "events")

        # Lane Queue: serial-by-default execution per session (OpenClaw-style)
        try:
            from js.orchestration.lane_queue import LaneExecutor
            self._lane_executor = LaneExecutor()
        except Exception:
            self._lane_executor = None  # type: ignore[assignment]

        # Quality scoring & self-learning闭环 (OpenHuman-style)
        try:
            from js.evolution.quality_scorer import QualityScorer
            self._quality_scorer = QualityScorer(settings.state_dir)
        except Exception:
            self._quality_scorer = None  # type: ignore[assignment]

        # Resource governance (started via start_background_tasks)
        self._governor: Any | None = None
        self._fleet_getter: Any | None = None

    @property
    def degraded(self) -> bool:
        return self._degraded

    def _get_tools_schema(self, model: str | None = None) -> list[dict[str, Any]] | None:
        """Return tool schemas, filtering network tools when degraded.

        If the selected model does not support function calling, returns None
        so the provider receives a plain text completion instead of tools.

        Trimming strategy:
        - Cloud models: keep all tools (they have large context windows).
        - Local models: aggressively trim to ~8 essentials to avoid context
          overflow and reduce reasoning burden on weak FC models.
        """
        # Check model capability first
        if model:
            cfg = self.router.get_model_config(model)
            if cfg and not cfg.supports_tools:
                return None

        schemas = self.registry.to_openai_schemas()

        context_window = 128_000
        is_local = False
        if model:
            cfg = self.router.get_model_config(model)
            if cfg:
                context_window = cfg.context_window
            is_local = self.router.is_local_model(model)

        # Local models: aggressively trim to avoid prompt > context errors
        # AND to reduce reasoning burden (weak FC models drown in too many tools).
        if is_local and len(schemas) > 7:
            # Local models struggle with browser_fetch (SPA sites, redirects)
            # and multi-step WebBridge workflows.  Keep only the essentials.
            _local_core = {
                "web_search",
                "file_read", "file_write", "file_edit", "file_view",
                "shell", "python",
            }
            trimmed = [s for s in schemas if s.get("function", {}).get("name", "") in _local_core]
            self.logger.info(
                f"Local-model tool trim {model or 'default'}: {len(schemas)} -> {len(trimmed)}"
            )
            schemas = trimmed
        elif context_window < 32_000 and len(schemas) > 15:
            # Small-context cloud models: trim skills/office but keep browser tools
            _cloud_core = {
                "web_search", "browser_fetch",
                "file_read", "file_write", "file_edit", "file_view", "file_list",
                "code_search", "shell", "python",
                "web_navigate", "web_snapshot", "web_click", "web_fill",
                "web_screenshot", "web_evaluate", "web_extract_text",
                "web_find_tab", "web_list_tabs",
            }
            trimmed = [s for s in schemas if s.get("function", {}).get("name", "") in _cloud_core]
            self.logger.debug(
                f"Cloud tool trim {model or 'default'}: {len(schemas)} -> {len(trimmed)}"
            )
            schemas = trimmed

        if not self._degraded:
            return schemas
        filtered = []
        for s in schemas or []:
            name = s.get("function", {}).get("name", "")
            if name in ("web_search", "browser_fetch", "browser_open", "fetch_url"):
                continue
            if name.startswith("web_"):
                continue
            filtered.append(s)
        return filtered

    def request_cancel(self, session_id: str) -> bool:
        """Request cancellation of an active run."""
        entry = self._cancel_tokens.get(session_id)
        if entry is None:
            return False
        entry[0].set()
        return True

    async def _check_degraded(self) -> None:
        """Check provider health and update degraded status."""
        try:
            health = await self.router.health_check()
            any_healthy = any(health.values()) if isinstance(health, dict) else bool(health)
            if any_healthy:
                self._degraded = False
                self.degraded_reason = ""
            else:
                self._degraded = True
                self.degraded_reason = "All providers unhealthy"
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self._degraded = True
            self.degraded_reason = f"Health check failed: {type(e).__name__}"

    async def save_checkpoint(self, state: AgentState) -> None:
        """Persist agent state for resume."""
        data = state.to_dict()
        await asyncio.to_thread(
            self.state_store.save,
            session_id=data["session_id"],
            run_id=data["run_id"],
            turn_count=data["turn_count"],
            messages=data["messages"],
            tool_results=data["tool_results"],
            total_tokens=data["total_tokens"],
            cost_estimate=data["cost_estimate"],
            status=data["status"],
            error_message=data["error_message"],
            compression_stats=data["compression_stats"],
            model=data.get("model", ""),
        )

    async def load_checkpoint(self, session_id: str) -> AgentState | None:
        """Restore agent state from persistent store."""
        data = await asyncio.to_thread(self.state_store.load, session_id)
        if data is None:
            return None
        state = AgentState(
            session_id=data["session_id"],
            run_id=data["run_id"],
            turn_count=data.get("turn_count", 0),
            total_tokens=data.get("total_tokens", {"input": 0, "output": 0}),
            cost_estimate=data.get("cost_estimate", 0.0),
            status=data.get("status", "running"),
            error_message=data.get("error_message", ""),
            compression_stats=data.get("compression_stats", {}),
            model=data.get("model", ""),
        )
        for m in data.get("messages", []):
            state.messages.append(
                ChatMessage(
                    role=m.get("role", "user"),
                    content=m.get("content", ""),
                    name=m.get("name"),
                    tool_calls=m.get("tool_calls"),
                    tool_call_id=m.get("tool_call_id"),
                    reasoning_content=m.get("reasoning_content"),
                )
            )
        for r in data.get("tool_results", []):
            state.tool_results.append(
                ToolResult(
                    success=r.get("success", False),
                    output=r.get("output", ""),
                    error=r.get("error", ""),
                )
            )
        return state

    async def resume(self, session_id: str, user_input: str = "") -> AgentState:
        """Resume a session from its last checkpoint."""
        state = await self.load_checkpoint(session_id)
        if state is None:
            state = AgentState(session_id=session_id, run_id=str(uuid.uuid4()))
        if user_input:
            state.messages.append(ChatMessage(role="user", content=user_input))
        return await self.run(user_input, session_id=session_id, _resume_state=state)

    async def _summarize_context(self, messages: list[ChatMessage], identifiers: list[str] | None = None) -> str:
        """Generate an LLM-powered summary of conversation turns."""
        from js.compression.compressor import _SUMMARY_SYSTEM_PROMPT
        prompt_text = (
            "Summarize the following conversation turns into a concise paragraph. "
            "Preserve key facts, decisions, and tool outputs. Be dense and omit filler.\n\n"
            + self._format_messages_for_summary(messages)
        )
        preserve_hint = ""
        if identifiers:
            preserve_hint = f"\n\nIMPORTANT: Preserve these identifiers exactly — do not summarize or alter them: {', '.join(identifiers[:20])}\n"
        summary_messages = [
            ChatMessage(role="system", content=_SUMMARY_SYSTEM_PROMPT + preserve_hint),
            ChatMessage(role="user", content=prompt_text),
        ]
        response = await self.router.chat(messages=summary_messages, model=None)
        if isinstance(response.content, str):
            return response.content
        return ""

    def _format_messages_for_summary(self, messages: list[ChatMessage]) -> str:
        """Format messages for the summarizer prompt."""
        parts: list[str] = []
        for msg in messages:
            if msg.role == "user":
                content = msg.content if isinstance(msg.content, str) else str(msg.content)
                parts.append(f"User: {content[:500]}")
            elif msg.role == "assistant":
                content = msg.content if isinstance(msg.content, str) else str(msg.content)
                parts.append(f"Assistant: {content[:500]}")
            elif msg.role == "tool":
                content = msg.content if isinstance(msg.content, str) else str(msg.content)
                parts.append(f"Tool ({msg.name}): {content[:300]}")
        return "\n---\n".join(parts)

    def _setup_search(self) -> Any:
        from js.search.engines import BingEngine, DuckDuckGoEngine, SearchManager, TavilyEngine
        manager = SearchManager()
        # Bing is more reliable in China-region networks (DDG often times out)
        manager.register(BingEngine(timeout=10.0), default=True)
        manager.register(DuckDuckGoEngine(timeout=8.0))
        # Try to load Tavily key from secrets
        tavily_key = self.secrets.retrieve("tavily_api_key")
        if tavily_key:
            manager.register(TavilyEngine(tavily_key))
        return manager

    def _setup_tools(self) -> None:
        from js.tools.browser import BrowserTool
        from js.tools.code import CodeTool
        from js.tools.files import FileTools
        from js.tools.office import OfficeTools
        from js.tools.shell import ShellTool

        file_tools = FileTools(self.settings.workspace, self.settings.tools, self.guard)
        file_tools.register_all(self.registry)

        shell_tool = ShellTool(self.settings.workspace, self.settings.tools, self.guard)
        shell_tool.register(self.registry)

        code_tool = CodeTool(self.settings.workspace, self.settings.tools, self.guard)
        code_tool.register(self.registry)

        self._browser_tool = BrowserTool(self.settings.tools, self.guard)
        self._browser_tool.register_all(self.registry)

        # Kimi WebBridge — real browser control (navigate, click, screenshot, etc.)
        try:
            from js.tools.webbridge import WebBridgeTool
            self._webbridge_tool = WebBridgeTool()
            self._webbridge_tool.register_all(self.registry)
        except Exception:
            self.logger.warning("WebBridge tools not available (daemon may not be running)", exc_info=True)

        office_tools = OfficeTools(self.settings.workspace, self.settings.tools, self.guard)
        office_tools.register_all(self.registry)

        # Register search as a tool
        self._register_search_tool()

        # TODO: Register code-type skills as tools (requires async handler wrapper)

    def register_fleet_tool(self, fleet_factory: Any) -> None:
        """Register the fleet collaboration tool (called from web layer)."""
        try:
            from js.tools.fleet_tools import FleetCollaborateTool
            fleet_tool = FleetCollaborateTool(fleet_factory)
            fleet_tool.register(self.registry)
            self.logger.info("Fleet collaboration tool registered")
        except Exception:
            self.logger.warning("Failed to register fleet collaboration tool", exc_info=True)

    def _init_plugins(self) -> None:
        """Discover and auto-enable builtin plugins."""
        try:
            from js.plugins.manager import PluginManager
            self.plugins = PluginManager(self, self.settings)
            self.plugins.discover()
            for p in self.plugins.list_plugins():
                if p.manifest.id.startswith("builtin-") or p.manifest.categories == ["demo"]:
                    self.plugins.enable(p.manifest.id)
            self.logger.info(f"Plugin system initialized: {len(self.plugins.list_plugins())} plugins discovered")
        except Exception as e:
            self.logger.warning(f"Plugin init failed: {e}")

    def _setup_embedder(self) -> Embedder:
        """Select the best available embedding provider.

        Only uses an LLM-based embedder when the user has explicitly
        configured ``embedding_model`` on a provider. Never auto-detects
        or probes models at startup — this keeps initialization fast and
        avoids "opening" unwanted models.

        HybridEmbedder wraps the primary so that runtime failures
        automatically fall back to KeywordEmbedder without crashing.
        """
        for cfg in self.settings.providers:
            if cfg.base_url and cfg.embedding_model:
                primary = LLMEmbedder(
                    base_url=cfg.base_url,
                    api_key=cfg.api_key or "dummy",
                    model=cfg.embedding_model,
                )
                hybrid = HybridEmbedder(
                    primary=primary,
                    fallback=KeywordEmbedder(),
                    failure_threshold=2,
                    recovery_timeout=60.0,
                )
                self.logger.info(
                    f"Using HybridEmbedder (primary={cfg.name}, model={cfg.embedding_model})"
                )
                return hybrid

        self.logger.info(
            "Using KeywordEmbedder (no embedding_model configured). "
            "Semantic memory will use keyword matching instead of vector similarity. "
            "To enable vector search, set embedding_model in your provider config."
        )
        return KeywordEmbedder()

    async def _build_attachment_context(self, attachments: list[str]) -> str:
        """Build context text describing uploaded attachments."""
        if not attachments:
            return ""

        parts: list[str] = ["\n\n## 附件文件\n"]
        for path_str in attachments:
            path = self.settings.workspace / path_str
            if not path.exists():
                parts.append(f"- `{path_str}`: (文件不存在)")
                continue

            suffix = path.suffix.lower()
            size = path.stat().st_size

            if suffix in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg"}:
                parts.append(f"- 📷 图片: `{path.name}` ({format_size(size)})")
            elif suffix in {".mp4", ".mov", ".avi", ".mkv", ".webm"}:
                parts.append(f"- 🎬 视频: `{path.name}` ({format_size(size)})")
            elif suffix in {".mp3", ".wav", ".ogg", ".m4a", ".flac"}:
                parts.append(f"- 🎵 音频: `{path.name}` ({format_size(size)})")
            elif suffix in {".xlsx", ".xls", ".csv"}:
                parts.append(f"- 📊 表格: `{path.name}` ({format_size(size)})")
                try:
                    content = (await asyncio.to_thread(extract_excel_text, path))[:5000]
                    if content:
                        parts.append(f"  提取内容:\n```\n{content}\n```")
                except Exception:
                    self.logger.warning('Operation failed', exc_info=True)
            elif suffix == ".pdf":
                parts.append(f"- 📑 PDF: `{path.name}` ({format_size(size)})")
                try:
                    content = (await asyncio.to_thread(extract_pdf_text, path))[:5000]
                    if content:
                        parts.append(f"  提取内容:\n```\n{content}\n```")
                except Exception:
                    self.logger.warning('Operation failed', exc_info=True)
            elif suffix in {".txt", ".md", ".py", ".js", ".json", ".yaml", ".yml", ".csv", ".html", ".css", ".xml", ".sh", ".log", ".docx"}:
                parts.append(f"- 📄 文档: `{path.name}` ({format_size(size)})")
                if suffix in {".txt", ".md", ".py", ".js", ".json", ".yaml", ".yml", ".csv", ".html", ".css", ".xml", ".sh", ".log"}:
                    try:
                        def _read_file(p: Path) -> str:
                            return p.read_text(encoding="utf-8", errors="replace")[:8000]

                        content = await asyncio.to_thread(_read_file, path)
                        parts.append(f"  预览:\n```\n{content}\n```")
                    except Exception:
                        self.logger.warning('Operation failed', exc_info=True)
            else:
                parts.append(f"- 📎 文件: `{path.name}` ({format_size(size)})")

        return "\n".join(parts)

    def _init_default_prompt_variant(self) -> None:
        """Register the base system prompt as a variant for A/B optimization."""
        if not self.optimizer:
            return
        try:
            variant = self.optimizer.select_variant("system")
            if variant is None:
                self.optimizer.register_variant("system", self.SYSTEM_PROMPT, "baseline")
        except Exception:
            self.logger.warning("Failed to register default prompt variant", exc_info=True)

    def _build_vision_content(
        self,
        user_input: str,
        attachments: list[str],
        supports_vision: bool,
    ) -> str | list[dict[str, Any]]:
        """Build user message content, using multimodal format for vision models."""
        if not supports_vision or not attachments:
            return ""

        from js.tools.images import create_image_message, is_image

        parts: list[dict[str, Any]] = [{"type": "text", "text": user_input}]
        for path_str in attachments:
            path = self.settings.workspace / path_str
            if path.exists() and is_image(path):
                try:
                    parts.append(create_image_message(path))
                except Exception as e:
                    self.logger.warning(f"Failed to encode image {path}: {e}")
        if len(parts) > 1:
            return parts
        return ""

    def _build_system_message(
        self,
        query: str = "",
        session_id: str = "",
        attachments: list[str] | None = None,
        model: str | None = None,
    ) -> str:
        """Build system message with rich multi-layer memory context."""
        cache_key = (query, session_id, model or "")
        cached = self._system_message_cache.get(cache_key)
        if cached is not None:
            return cached

        parts = [self.SYSTEM_PROMPT]

        # Local-model appendix: simplify instructions because weak FC models
        # struggle with long prompts and complex multi-step tool workflows.
        # We also strip WebBridge references so the model doesn't hallucinate
        # tools that have been removed from its schema.
        if model and self.router.is_local_model(model):
            parts = [
                "You are JS, a helpful AI assistant with access to a small set of tools.",
                "",
                "Available tools:",
                "- web_search: Search the web. Call it ONCE with your query, then answer.",
                "- file_read / file_view: Read files.",
                "- file_edit: Edit files with exact search/replace.",
                "- file_write: Create new files.",
                "- shell: Run shell commands.",
                "- python: Run Python code.",
                "",
                "CRITICAL RULES:",
                "1. Call web_search ONCE. Do NOT call it again.",
                "2. If a tool returns an error, STOP and tell the user.",
                "3. NEVER repeat the same tool call.",
                "4. After any tool result, answer immediately.",
            ]

        # Inject learned insights from past interactions
        if self.learner:
            hint = self.learner.generate_context_hint(query)
            if hint:
                parts.append(f"\n## Learned Insight\n{hint}")

        # A/B test prompt variant
        if self.optimizer:
            try:
                variant = self.optimizer.select_variant("system")
                if variant:
                    variant_id, prompt_template = variant
                    parts.append(f"\n## Optimization Variant\n{prompt_template}")
                    self._last_system_variant_id = variant_id
            except Exception:
                self.logger.warning("Failed to select prompt variant", exc_info=True)

        if self.settings.memory.enabled:
            try:
                # Cap memory context so system prompt + context stays well within
                # typical local model context windows (4k-8k). Base prompt is ~2.5k.
                max_memory = min(self.settings.memory.max_memory_chars, 2000)
                memory_context = self.memory.get_context_string(
                    query=query,
                    session_id=session_id,
                    max_chars=max_memory,
                )
                if memory_context:
                    # Security scan memory context before injection
                    memory_context = self.secrets.detect_and_redact(
                        memory_context, "memory_context"
                    )
                    scan = self.guard.check_tool_result(memory_context)
                    if scan.decision.value in ("block", "warn"):
                        self.logger.warning(
                            f"Memory context security scan {scan.decision.value}: {scan.reason}"
                        )
                        self.audit.log(
                            AuditEventType.SECURITY_ALERT,
                            session_id or "",
                            "",
                            "agent",
                            "memory_scan",
                            {"decision": scan.decision.value, "reason": scan.reason},
                        )
                        # Degrade to empty context on block
                        if scan.decision.value == "block":
                            memory_context = ""
                    if memory_context:
                        parts.append(f"\n## Relevant Context\n{memory_context}")
            except Exception:
                self.logger.warning("Failed to build memory context", exc_info=True)

        result = "\n".join(parts)
        # Hard cap total system prompt length to prevent context overflow
        if len(result) > 4000:
            result = result[:4000] + "\n...[truncated]"
        self._system_message_cache[cache_key] = result
        return result


    async def _execute_tool_call(
        self,
        tc: dict[str, Any],
        session_id: str,
        run_id: str,
        user_input: str,
        progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None = None,
    ) -> tuple[ChatMessage, ToolResult]:
        """Execute a single tool call and return the tool message plus raw result."""
        func = tc.get("function", {}) if isinstance(tc, dict) else {}
        tool_name = func.get("name", "") if isinstance(func, dict) else ""
        raw_args = func.get("arguments", "{}") if isinstance(func, dict) else "{}"
        raw_tool_call_id = tc.get("id", "") if isinstance(tc, dict) else ""
        # Deterministic fallback for prompt-cache consistency
        # (Hermes-style: same args → same ID across restarts)
        if not raw_tool_call_id:
            from js.utils.ids import tool_call_id as _det_tool_call_id
            raw_tool_call_id = _det_tool_call_id(
                tool_name=tool_name,
                arguments=raw_args,
                turn_idx=0,
                session_id=session_id,
            )
        tool_call_id = raw_tool_call_id
        if not tool_name:
            err_result = ToolResult(success=False, error="Tool call missing name")
            return (
                ChatMessage(role="tool", content=err_result.to_text(), tool_call_id=tool_call_id, name="unknown"),
                err_result,
            )

        # Hard block: model called a tool that is not in its allowed schema.
        # This catches hallucinated tool calls from weak FC models (e.g. local
        # models that infer tool names from the system prompt even when the
        # tool was trimmed from their schema).
        if self._current_allowed_tools and tool_name not in self._current_allowed_tools:
            err_result = ToolResult(
                success=False,
                error=f"Tool '{tool_name}' is not available for this model. "
                f"Available tools: {', '.join(sorted(self._current_allowed_tools))}. "
                "Use one of the available tools or answer directly.",
            )
            return (
                ChatMessage(role="tool", content=err_result.to_text(), tool_call_id=tool_call_id, name=tool_name),
                err_result,
            )

        try:
            arguments = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args if isinstance(raw_args, dict) else {})
        except json.JSONDecodeError as e:
            err_result = ToolResult(success=False, error=f"Invalid tool arguments JSON: {e}")
            return (
                ChatMessage(role="tool", content=err_result.to_text(), tool_call_id=tool_call_id, name=tool_name),
                err_result,
            )

        # Role-based tool permissions (least privilege)
        _role_tool_whitelist: dict[str, set[str]] = {
            "orchestrator": {"web_search", "browser_fetch", "file_read", "file_view", "web_navigate", "web_snapshot", "web_extract_text"},
            "coder": {"file_read", "file_write", "file_edit", "code_search", "shell", "python", "file_view", "file_list"},
            "reviewer": {"file_read", "code_search", "file_view", "file_list"},
            "researcher": {"web_search", "browser_fetch", "file_read", "file_view", "web_navigate", "web_snapshot", "web_click", "web_fill", "web_extract_text"},
            "tester": {"shell", "python", "file_read", "file_view", "code_search"},
            "generalist": {"file_read", "file_write", "file_edit", "shell", "python", "web_search", "code_search", "file_view", "file_list", "web_navigate", "web_snapshot", "web_click", "web_fill", "web_extract_text"},
            "architect": {"file_read", "code_search", "file_view", "file_list"},
            "designer": {"file_read", "file_view", "file_list"},
            "doc_writer": {"file_read", "file_write", "file_edit", "file_view", "file_list"},
            "security": {"file_read", "shell", "code_search", "file_view", "file_list", "web_navigate", "web_snapshot", "web_extract_text"},
            "performance": {"file_read", "shell", "python", "code_search", "file_view", "file_list"},
        }
        if self._role and tool_name not in _role_tool_whitelist.get(self._role, set()):
            denied_result = ToolResult(
                success=False,
                error=f"Permission denied: role '{self._role}' is not allowed to use tool '{tool_name}'",
            )
            return (
                ChatMessage(
                    role="tool",
                    content=denied_result.to_text(),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                ),
                denied_result,
            )

        # Strategy-based defense
        from js.security.strategies import DefenseContext
        defense_ctx = DefenseContext(
            tool_name=tool_name,
            arguments=arguments,
            session_id=session_id,
            run_id=run_id,
            user_input=user_input,
            config=self.settings.security,
        )
        defense_result = self.defense_strategies.evaluate(defense_ctx)
        if defense_result.blocked:
            blocked_result = ToolResult(success=False, error=f"Security blocked: {defense_result.reason}")
            return (
                ChatMessage(
                    role="tool",
                    content=blocked_result.to_text(),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                ),
                blocked_result,
            )

        # Approval check for dangerous tools (must be awaited, so runs inline)
        spec = self.registry.get(tool_name)
        if spec and spec.dangerous:
            from js.events.models import AgentEvent
            self.event_store.emit(
                AgentEvent.approval_requested(
                    session_id=session_id,
                    run_id=run_id,
                    tool_name=tool_name,
                    arguments=arguments,
                )
            )
            approved = await asyncio.to_thread(
                self.approvals.request,
                tool_name=tool_name,
                arguments=arguments,
                context="cli",
            )
            if not approved:
                self.event_store.emit(
                    AgentEvent.approval_denied(
                        session_id=session_id,
                        run_id=run_id,
                        tool_name=tool_name,
                        reason="approval required but not granted",
                    )
                )
                denied_result = ToolResult(success=False, error="Operation denied: approval required but not granted")
                return (
                    ChatMessage(
                        role="tool",
                        content=denied_result.to_text(),
                        tool_call_id=tool_call_id,
                        name=tool_name,
                    ),
                    denied_result,
                )
            self.event_store.emit(
                AgentEvent.approval_granted(
                    session_id=session_id,
                    run_id=run_id,
                    tool_name=tool_name,
                )
            )

        self.audit.log(
            AuditEventType.TOOL_CALL,
            session_id,
            run_id,
            "agent",
            tool_name,
            {"arguments": arguments},
        )
        from js.events.models import AgentEvent
        self.event_store.emit(
            AgentEvent.tool_called(
                session_id=session_id,
                run_id=run_id,
                tool_name=tool_name,
                arguments=arguments,
            )
        )

        result = await self.registry.execute(run_id, tool_name, arguments)

        # Notify progress callback (e.g. WebSocket frontend)
        if progress_callback:
            try:
                await progress_callback(tool_name, result)
            except Exception:
                self.logger.debug("Progress callback failed", exc_info=True)

        # Repeated failure guard (Hermes-style)
        fail_check = self.guard.check_repeated_failure(run_id, tool_name, result.success)
        if fail_check.decision == "block":
            result = ToolResult(success=False, error=f"Security: {fail_check.reason}")

        # Redact secrets in output
        if result.output:
            result.output = self.secrets.detect_and_redact(result.output, f"tool:{tool_name}")

        return (
            ChatMessage(
                role="tool",
                content=result.to_text(),
                tool_call_id=tool_call_id,
                name=tool_name,
            ),
            result,
        )


    async def _finalize_run(
        self,
        state: AgentState,
        session_id: str,
        run_id: str,
        user_input: str,
        history_ua_count: int,
    ) -> None:
        """Persist memory, audit logs, and learning data after a run completes."""
        # Extract assistant output for memory storage
        assistant_output = ""
        for msg in reversed(state.messages):
            if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                assistant_output = msg.content
                break

        # Persist conversation history FIRST to avoid empty sessions
        try:
            ua_messages = [
                msg
                for msg in state.messages
                if msg.role in ("user", "assistant") and isinstance(msg.content, str)
            ]
            new_messages: list[dict[str, str]] = [
                {"role": msg.role, "content": str(msg.content)}
                for msg in ua_messages[history_ua_count:]
            ]
            if new_messages:
                await asyncio.to_thread(
                    self.memory.store_messages,
                    session_id,
                    new_messages,
                )
        except Exception as e:
            self.logger.debug(f"Failed to store messages: {e}")

        # Store episodic memory second
        try:
            summary = f"User: {user_input[:80]}... → Assistant: {assistant_output[:80]}..."
            topics = list({
                word.lower() for word in (user_input + " " + assistant_output).split()
                if len(word) > 4 and word.isalpha()
            })[:5]
            await asyncio.to_thread(
                self.memory.store_episode,
                session_id=session_id,
                summary=summary,
                topics=topics,
                tokens_used=sum(state.total_tokens.values()),
                turn_count=state.turn_count,
                importance=7 if state.status == "completed" else 4,
            )
            try:
                self._dream_scheduler.notify_activity(user_input, assistant_output)
            except Exception as e:
                self.logger.debug(f"Failed to notify scheduler: {e}")
        except Exception as mem_err:
            self.logger.warning(f"Memory consolidation failed: {mem_err}")

        # Inject learning context into working memory (OpenHuman-style)
        if self._quality_scorer is not None:
            try:
                learning_ctx = self._quality_scorer.build_learning_context(
                    max_tokens=200,
                )
                if learning_ctx:
                    await asyncio.to_thread(
                        self.memory.store_working,
                        session_id=session_id,
                        key="learning_context",
                        value=learning_ctx,
                        category="meta",
                        importance=8,
                    )
            except Exception:
                self.logger.debug("Learning context injection failed", exc_info=True)

        # Reset guard counters
        try:
            self.guard.reset_loop_counters(run_id)
        except Exception:
            self.logger.warning("Failed to reset guard counters", exc_info=True)

        self.logger.info(
            "Run complete",
            extra={
                "run": run_id,
                "status": state.status,
                "turns": state.turn_count,
                "tokens": state.total_tokens,
            },
        )

        # Record for self-learning
        try:
            await asyncio.to_thread(
                self.learner.record_interaction,
                session_id=session_id,
                user_input=user_input,
                agent_output=assistant_output,
                tool_calls=[
                    {"name": r.metadata.get("tool_name", "unknown"), "success": r.success}
                    for r in state.tool_results
                ],
                success=state.status == "completed",
                latency_ms=0.0,
                tokens_used=sum(state.total_tokens.values()),
            )
        except Exception:
            self.logger.warning("Failed to record interaction", exc_info=True)

        # Record compression outcome for feedback loop
        try:
            await asyncio.to_thread(
                self.compression_feedback.record_outcome,
                session_id=session_id,
                turn_number=state.turn_count,
                success=state.status == "completed",
                error_type=state.error_message if state.status == "error" else None,
            )
        except Exception:
            self.logger.warning("Failed to record compression outcome", exc_info=True)

        # Record prompt optimization result
        try:
            if hasattr(self, "_last_system_variant_id"):
                await asyncio.to_thread(
                    self.optimizer.record_result,
                    self._last_system_variant_id,
                    state.status == "completed",
                    1.0 if state.status == "completed" else 0.0,
                    context="system",
                )
                delattr(self, "_last_system_variant_id")
        except Exception:
            self.logger.warning("Failed to record prompt optimization result", exc_info=True)

        # Trigger metacognition if interval reached
        try:
            await asyncio.to_thread(self.metacognition.tick)
        except Exception:
            self.logger.warning("Metacognition tick failed", exc_info=True)

        # Periodic skill curation
        try:
            if self.curator.should_run():
                curation_report = await asyncio.to_thread(
                    self.curator.curate, self.skills.get_all()
                )
                self.logger.info(
                    "Skill curation completed",
                    extra={
                        "healthy": curation_report.get("healthy", 0),
                        "underperforming": curation_report.get("underperforming", 0),
                    },
                )
        except Exception:
            self.logger.warning("Skill curation failed", exc_info=True)

        # Auto-evolve underperforming skills (fire-and-forget background tasks)
        try:
            if self.evolver:
                for skill_id, _spec in self.skills.get_all().items():
                    if self.evolver.should_evolve(skill_id):
                        self.logger.info(f"Triggering auto-evolution for skill {skill_id}")
                        asyncio.create_task(
                            self._run_skill_evolution_for(skill_id),
                            name=f"evolve-{skill_id}",
                        )
        except Exception:
            self.logger.warning("Auto-evolution check failed", exc_info=True)

    async def run(
        self,
        user_input: str,
        session_id: str | None = None,
        model: str | None = None,
        attachments: list[str] | None = None,
        _resume_state: AgentState | None = None,
        stream_callback: Callable[[str], Awaitable[None]] | None = None,
        progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None = None,
    ) -> AgentState:
        """Execute a full agent run.

        When a LaneExecutor is available, runs are serialised per session
        to prevent race conditions (OpenClaw Lane Queue pattern).
        """
        # Lane Queue: serialise per session
        if self._lane_executor is not None:
            result = await self._lane_executor.submit(
                session_id=session_id or "default",
                coro=lambda: self._do_run(
                    user_input, session_id, model, attachments,
                    _resume_state, stream_callback, progress_callback,
                ),
                task_id=f"run_{id(user_input)}",
                name="agent_run",
            )
            return result  # type: ignore[no-any-return]
        return await self._do_run(
            user_input, session_id, model, attachments,
            _resume_state, stream_callback, progress_callback,
        )

    async def _do_run(
        self,
        user_input: str,
        session_id: str | None = None,
        model: str | None = None,
        attachments: list[str] | None = None,
        _resume_state: AgentState | None = None,
        stream_callback: Callable[[str], Awaitable[None]] | None = None,
        progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None = None,
    ) -> AgentState:
        """Core agent run logic."""
        self._consecutive_tool_failures = 0
        session_id = session_id or str(uuid.uuid4())
        run_id = str(uuid.uuid4())
        if _resume_state:
            state = _resume_state
            # Preserve the original run_id for traceability; track the
            # resume chain via parent_run_id if we ever add it.
        else:
            state = AgentState(session_id=session_id, run_id=run_id)
        attachments = attachments or []
        self._cancel_tokens[session_id] = (asyncio.Event(), state.run_id)

        try:
            get_metrics().agent_runs_total.inc()
        except Exception:
            self.logger.warning("Suppressed error", exc_info=True)

        self.logger.info("Starting run", extra={"session": session_id, "run": run_id, "attachments": len(attachments)})
        self.audit.log(
            AuditEventType.USER_MESSAGE,
            session_id,
            run_id,
            "user",
            "message",
            {"content_length": len(user_input), "attachments": len(attachments)},
        )

        # Redact secrets from user input
        user_input = self.secrets.detect_and_redact(user_input, "user_input")

        # Build attachment context
        attachment_ctx = await self._build_attachment_context(attachments)

        if _resume_state is None:
            # Fresh run: load historical conversation context
            try:
                history = await asyncio.to_thread(
                    self.memory.get_session_messages, session_id
                )
                for m in history[-50:]:  # Keep last 50 messages to fit context window
                    if m.get("role") in ("user", "assistant") and m.get("content"):
                        state.messages.append(
                            ChatMessage(
                                role=m["role"],
                                content=m["content"],
                                reasoning_content=m.get("reasoning_content"),
                            )
                        )
            except Exception:
                self.logger.warning("Failed to load session history", exc_info=True)

            # Count historical user/assistant messages already persisted
            history_ua_count = sum(
                1 for m in state.messages
                if m.role in ("user", "assistant") and isinstance(m.content, str)
            )

            # Initialize conversation with rich memory context
            state.messages.insert(
                0,
                ChatMessage(
                    role="system",
                    content=self._build_system_message(
                        query=user_input, session_id=session_id, attachments=attachments, model=model
                    ),
                ),
            )

            # Build user message: support multimodal for vision models
            model_config = self.router.get_model_config(model or "")
            supports_vision = model_config.supports_vision if model_config else False
            vision_parts = self._build_vision_content(user_input, attachments, supports_vision)
            if isinstance(vision_parts, list):
                state.messages.append(ChatMessage(role="user", content=vision_parts))
            else:
                state.messages.append(ChatMessage(role="user", content=user_input + attachment_ctx))
        else:
            # Resuming from checkpoint: state already contains system + history + user messages.
            # Count how many user/assistant messages are already in the state
            # so that _finalize_run only persists the new ones.
            history_ua_count = sum(
                1 for m in state.messages
                if m.role in ("user", "assistant") and isinstance(m.content, str)
            )

        # Store working memory for this interaction
        await asyncio.to_thread(
            self.memory.store_working,
            session_id=session_id,
            key="user_input",
            value=user_input[:500],
            category="interaction",
            importance=5,
        )

        with start_span("agent.run"):
            try:
                while state.turn_count < self.settings.max_turns:
                    # Check for cancellation request (token or global shutdown)
                    cancel_entry = self._cancel_tokens.get(session_id)
                    if cancel_entry is not None:
                        cancel_event, token_run_id = cancel_entry
                        # Only honour the cancel token if it belongs to the current run
                        if token_run_id == state.run_id and cancel_event.is_set():
                            state.status = "cancelled"
                            state.error_message = "Run cancelled by user request"
                            break
                    if self._shutdown_requested:
                        state.status = "cancelled"
                        state.error_message = "Run cancelled by user request"
                        break

                    state.turn_count += 1
                    self.logger.debug(f"Turn {state.turn_count}", extra={"run": run_id})

                    # OpenClaw trap defense: hard cap on message count to prevent
                    # entropy death spiral (7,069 msg / 170k token per heartbeat).
                    _msg_hard_limit = 200
                    if len(state.messages) > _msg_hard_limit:
                        self.logger.warning(
                            f"Message count {len(state.messages)} exceeds hard limit {_msg_hard_limit}; "
                            f"truncating oldest non-system messages"
                        )
                        # Keep system + last 100 messages
                        trimmed = [m for m in state.messages if m.role == "system"]
                        trimmed.extend(state.messages[-100:])
                        state.messages = trimmed

                    turn_start = time.perf_counter()
                    turn_tool_scores: list[Any] = []
                    try:
                        # Adjust compressor budget to the actual model's context window
                        # (local 8k models need aggressive compression, cloud 128k models don't)
                        model_cfg = self.router.get_model_config(model or "")
                        if model_cfg and model_cfg.context_window:
                            self.compressor.config.max_tokens = model_cfg.context_window

                        # Get tools schema first so compression accounts for tool overhead
                        tools_schema = self._get_tools_schema(model)

                        # Compress context if needed (tools included in token estimate)
                        compression_result = await self.compressor.compress(
                            state.messages, tools=tools_schema
                        )
                        compressed_messages = compression_result.messages
                        if compression_result.level.value != "none":
                            self.logger.info(
                                f"Context compressed ({compression_result.level.value}): "
                                f"{compression_result.original_tokens} -> {compression_result.compressed_tokens} tokens"
                            )
                            self.compression_feedback.record_compression(
                                session_id=session_id,
                                original_tokens=compression_result.original_tokens,
                                compressed_tokens=compression_result.compressed_tokens,
                                level=compression_result.level.value,
                                original_messages=len(state.messages),
                                compressed_messages=len(compressed_messages),
                                identifiers_found=len(compression_result.identifiers_found),
                            )

                        # Get model response
                        self._current_allowed_tools = {
                            s.get("function", {}).get("name", "") for s in (tools_schema or [])
                        }
                        if stream_callback and not tools_schema:
                            # Stream final assistant response when no tools
                            decision = await self.router.select_model(preferred=model)
                            stream_text = ""
                            async for token in decision.provider.chat_stream(
                                messages=compressed_messages,
                                model=decision.model,
                            ):
                                stream_text += token
                                await stream_callback(token)

                            # Try to get accurate usage from provider; fallback to heuristic estimate
                            stream_usage = getattr(decision.provider, "_last_stream_usage", None)
                            if stream_usage:
                                prompt_tokens = stream_usage.get("prompt_tokens", 0)
                                completion_tokens = stream_usage.get("completion_tokens", 0)
                                cached_tokens = stream_usage.get("cached_tokens", 0)
                            else:
                                # Rough heuristic: ~4 chars per token + overhead per message
                                prompt_tokens = sum(len(str(m.content or "")) // 4 + 20 for m in compressed_messages) + 100
                                completion_tokens = len(stream_text) // 4 + 20
                                cached_tokens = 0

                            response = ChatResponse(
                                content=stream_text,
                                tool_calls=[],
                                model=decision.model,
                                usage={
                                    "prompt_tokens": prompt_tokens,
                                    "completion_tokens": completion_tokens,
                                    "total_tokens": prompt_tokens + completion_tokens,
                                    "cached_tokens": cached_tokens,
                                },
                                finish_reason="stop",
                            )
                        else:
                            response = await self.router.chat(
                                messages=compressed_messages,
                                model=model,
                                tools=tools_schema if tools_schema else None,
                            )

                        # Track model used
                        state.model = response.model

                        # Track usage
                        prompt_tokens = response.usage.get("prompt_tokens", 0)
                        completion_tokens = response.usage.get("completion_tokens", 0)
                        cached_tokens = response.usage.get("cached_tokens", 0)
                        state.total_tokens["input"] += prompt_tokens
                        state.total_tokens["output"] += completion_tokens
                        state.cached_tokens += cached_tokens

                        # Calculate cost (cached tokens billed at a discount when available)
                        model_config = self.router.get_model_config(response.model)
                        if model_config:
                            # If we know cached tokens, charge them at 10% of input rate
                            # (common discount across most providers). Otherwise full rate.
                            if cached_tokens > 0 and model_config.cost_input > 0:
                                effective_input_cost = (
                                    (prompt_tokens - cached_tokens) * model_config.cost_input +
                                    cached_tokens * model_config.cost_input * 0.10
                                )
                            else:
                                effective_input_cost = prompt_tokens * model_config.cost_input
                            state.cost_estimate += (
                                effective_input_cost +
                                completion_tokens * model_config.cost_output
                            )

                        self.audit.log(
                            AuditEventType.MODEL_RESPONSE,
                            session_id,
                            run_id,
                            "agent",
                            "chat",
                            {
                                "model": response.model,
                                "finish_reason": response.finish_reason,
                                "tool_calls": len(response.tool_calls),
                            },
                        )

                        # Emit event for observability
                        from js.events.models import AgentEvent
                        self.event_store.emit(
                            AgentEvent.model_called(
                                session_id=session_id,
                                run_id=run_id,
                                model=response.model,
                                turn=state.turn_count,
                                prompt_tokens=prompt_tokens,
                                completion_tokens=completion_tokens,
                            )
                        )

                        # Add assistant message
                        state.messages.append(
                            ChatMessage(
                                role="assistant",
                                content=response.content,
                                tool_calls=response.tool_calls if response.tool_calls else None,
                                reasoning_content=response.reasoning_content or None,
                            )
                        )

                        # Check if done
                        if not response.tool_calls:
                            # Local models occasionally return finish_reason="stop"
                            # with empty content — treat this as a model failure and
                            # retry (up to max_turns) rather than silently completing.
                            if not response.content or not response.content.strip():
                                self.logger.warning(
                                    f"Model returned empty content "
                                    f"(finish_reason={response.finish_reason}), retrying"
                                )
                                # Remove the empty assistant message so it doesn't
                                # pollute the context for the retry.
                                state.messages.pop()
                                if state.turn_count >= self.settings.max_turns:
                                    state.status = "error"
                                    state.error_message = "Model returned empty response after maximum retries"
                                    break
                                continue
                            state.status = "completed"
                            break

                        # Execute tools (parallel when safe)
                        parallel = ParallelToolExecutor()
                        batches = parallel.group(response.tool_calls)
                        self.logger.debug(
                            f"Tool batches: {len(batches)} for {len(response.tool_calls)} calls"
                        )
                        for batch in batches:
                            batch_tasks = [
                                self._execute_tool_call(tc, session_id, run_id, user_input, progress_callback)
                                for tc in batch
                            ]
                            _raw_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                            # unwrap any exceptions into error results so that one
                            # failed tool does not cancel the others
                            batch_results: list[tuple[ChatMessage, ToolResult]] = []
                            for tc, res in zip(batch, _raw_results, strict=True):
                                if isinstance(res, BaseException):
                                    err = ToolResult(success=False, error=f"Tool execution error: {res}")
                                    _tc_id = tc.get("id", "") if isinstance(tc, dict) else ""
                                    if not _tc_id:
                                        from js.utils.ids import tool_call_id as _det_tc_id
                                        _tc_id = _det_tc_id(
                                            tool_name=tc.get("function", {}).get("name", "") if isinstance(tc, dict) else "",
                                            arguments=str(tc.get("function", {}).get("arguments", "{}")) if isinstance(tc, dict) else "{}",
                                            turn_idx=0,
                                            session_id=session_id,
                                        )
                                    batch_results.append((
                                        ChatMessage(role="tool", content=err.to_text(), tool_call_id=_tc_id, name=tc.get("function", {}).get("name", "unknown") if isinstance(tc, dict) else "unknown"),
                                        err,
                                    ))
                                else:
                                    # mypy narrowing: res is the normal tuple result
                                    batch_results.append(res)
                            all_failed = True
                            for msg, tr in batch_results:
                                state.messages.append(msg)
                                state.tool_results.append(tr)
                                if tr.success:
                                    all_failed = False
                                # Quality scoring: record each tool call outcome
                                if self._quality_scorer is not None:
                                    from js.evolution.quality_scorer import ToolCallScore
                                    turn_tool_scores.append(
                                        ToolCallScore(
                                            tool_name=tr.error.split(":")[0] if tr.error else (msg.name or "unknown"),
                                            success=tr.success,
                                            error_pattern=tr.error or "",
                                        )
                                    )
                            # Dead-loop guard: if every tool in this batch failed,
                            # count consecutive failure rounds.  After 2 all-failure
                            # rounds we force-stop so weak local models don't spin.
                            if all_failed and batch_results:
                                self._consecutive_tool_failures += 1
                                if self._consecutive_tool_failures >= 2:
                                    self.logger.warning(
                                        f"Dead-loop guard triggered after {self._consecutive_tool_failures} "
                                        f"consecutive all-failure rounds (turn {state.turn_count})"
                                    )
                                    state.messages.append(
                                        ChatMessage(
                                            role="system",
                                            content="STOP calling tools. All recent tool calls failed. Answer the user directly with what you know.",
                                        )
                                    )
                                    # Do NOT break here — let the model see the
                                    # system message and produce a final answer.
                            else:
                                self._consecutive_tool_failures = 0

                            # Prevent unbounded growth of tool_results
                            if len(state.tool_results) > 200:
                                state.tool_results = state.tool_results[-200:]
                            # Auto-save checkpoint after each tool batch (fire-and-forget)
                            try:
                                await self.save_checkpoint(state)
                                from js.events.models import AgentEvent
                                self.event_store.emit(
                                    AgentEvent.checkpoint_saved(
                                        session_id=session_id,
                                        run_id=run_id,
                                        turn=state.turn_count,
                                    )
                                )
                            except Exception:
                                self.logger.warning("Checkpoint auto-save failed", exc_info=True)
                            # Emit tool_result events
                            from js.events.models import AgentEvent
                            for tr in state.tool_results[-len(batch_results):]:
                                self.event_store.emit(
                                    AgentEvent.tool_result(
                                        session_id=session_id,
                                        run_id=run_id,
                                        tool_name=tr.error.split(":")[0] if not tr.success and tr.error else "unknown",
                                        success=tr.success,
                                        output_preview=tr.output or tr.error or "",
                                    )
                                )
                    finally:
                        turn_latency = time.perf_counter() - turn_start
                        try:
                            get_metrics().agent_turn_duration_seconds.observe(turn_latency)
                        except Exception:
                            self.logger.warning("Suppressed error", exc_info=True)
                        # Record turn quality score (OpenHuman-style)
                        if self._quality_scorer is not None:
                            from js.evolution.quality_scorer import TurnScore
                            self._quality_scorer.record_turn(
                                TurnScore(
                                    session_id=session_id,
                                    turn_idx=state.turn_count,
                                    model=state.model or "",
                                    tool_scores=turn_tool_scores,
                                    total_tokens=state.total_tokens.get("input", 0) + state.total_tokens.get("output", 0),
                                )
                            )

            except Exception as e:
                state.status = "error"
                state.error_message = str(e)
                self.logger.error("Run failed", exc_info=True, extra={"run": run_id})
                self.audit.log(
                    AuditEventType.ERROR,
                    session_id,
                    run_id,
                    "agent",
                    "exception",
                    {"error": str(e)},
                )
                from js.events.models import AgentEvent
                self.event_store.emit(
                    AgentEvent.error(session_id=session_id, run_id=run_id, error=str(e))
                )
                await self._check_degraded()

            finally:
                await self._finalize_run(state, session_id, run_id, user_input, history_ua_count)
                # Only pop the token if it still belongs to this run, to avoid
                # racing with a newer run on the same session.
                entry = self._cancel_tokens.get(session_id)
                if entry is not None and entry[1] == state.run_id:
                    self._cancel_tokens.pop(session_id, None)

        return state

    def set_fleet_getter(self, getter: Any) -> None:
        """Provide a callable that returns the current AgentFleet instance.

        Used by ResourceGovernor to reap idle agents and monitor fleet health.
        """
        self._fleet_getter = getter

    def start_background_tasks(self) -> None:
        """Start background scheduling loops."""
        self._dream_scheduler.start()
        if self._governor is None:
            from js.runtime.governor import ResourceGovernor
            self._governor = ResourceGovernor(
                self,
                fleet_getter=self._fleet_getter,
                state_dir=self.settings.state_dir,
            )
        self._governor.start()

    def stop_background_tasks(self) -> None:
        """Stop background scheduling loops."""
        self._dream_scheduler.stop()
        if self._governor is not None:
            self._governor.stop()

    async def _run_evolution_cycle(
        self, conversation_buffer: list[dict[str, str]]
    ) -> dict[str, Any]:
        """Full background evolution: profile update + dreaming + skill evolution.

        Each step is wrapped in its own try/except so that a failure in one
        does not prevent the others from running.
        Returns an execution report dict for the API layer.
        """
        import time
        start = time.perf_counter()
        self.logger.info("Starting evolution cycle")
        report: dict[str, Any] = {
            "profile_update": {"ok": True, "skipped": True, "error": None},
            "dreaming": {"ok": False, "error": None},
            "skill_evolution": {"ok": False, "error": None, "evolved": []},
        }
        if conversation_buffer:
            try:
                await self._auto_update_profiles(conversation_buffer)
                report["profile_update"] = {"ok": True, "skipped": False, "error": None}
            except Exception as e:
                report["profile_update"] = {"ok": False, "skipped": False, "error": str(e)}
                self.logger.warning(f"Profile update failed: {e}", exc_info=True)
        try:
            await self._run_dreaming()
            report["dreaming"]["ok"] = True
        except Exception as e:
            report["dreaming"]["error"] = str(e)
            self.logger.warning(f"Dreaming failed: {e}", exc_info=True)
        # Trigger skill evolution for underperforming skills
        try:
            evolved = await self._run_skill_evolution()
            report["skill_evolution"]["ok"] = True
            report["skill_evolution"]["evolved"] = evolved
        except Exception as e:
            report["skill_evolution"]["error"] = str(e)
            self.logger.warning(f"Skill evolution failed: {e}", exc_info=True)
        elapsed = time.perf_counter() - start
        report["elapsed_seconds"] = round(elapsed, 2)
        self.logger.info(f"Evolution cycle completed in {elapsed:.2f}s")
        return report

    async def _auto_update_profiles(self, conversation_buffer: list[dict[str, str]]) -> None:
        """Use LLM to analyze recent conversation and update USER.md + IDENTITY.md."""
        try:
            current_user = self.memory.read_memory_file("user")
            current_identity = self.memory.read_memory_file("identity")
        except Exception as e:
            self.logger.warning(f"Failed to read profile files: {e}", exc_info=True)
            return

        transcript = "\n\n".join(
            f"User: {turn['user']}\nAssistant: {turn['assistant']}"
            for turn in conversation_buffer
        )

        prompt = (
            "You are an archive curator. Based on the recent conversation, "
            "update the two profile files below.\n\n"
            f"Current USER.md:\n{current_user}\n\n"
            f"Current IDENTITY.md:\n{current_identity}\n\n"
            f"Recent conversation:\n{transcript}\n\n"
            "Update rules:\n"
            "- USER.md: Extract new facts about the user (name, preferences, projects, habits). "
            "Add or modify entries. Do not remove existing facts unless contradicted.\n"
            "- IDENTITY.md: Reflect any evolution in the AI's self-understanding based on "
            "how the conversation went. Update tone, capabilities, or relationship notes.\n"
            "- Return ONLY the two files in this exact format:\n\n"
            "===USER===\n"
            "(updated USER.md content)\n"
            "===IDENTITY===\n"
            "(updated IDENTITY.md content)"
        )

        messages = [
            ChatMessage(role="system", content="You are a precise archive curator."),
            ChatMessage(role="user", content=prompt),
        ]
        def _parse_profile_update(text: str) -> tuple[str | None, str | None]:
            """Robustly extract USER and IDENTITY sections from LLM output."""
            user_start = text.find("===USER===")
            identity_start = text.find("===IDENTITY===")
            if user_start == -1 or identity_start == -1:
                return None, None
            user_content = text[
                user_start + len("===USER===") : identity_start
            ].strip()
            identity_content = text[
                identity_start + len("===IDENTITY===") :
            ].strip()
            return user_content, identity_content

        try:
            resp = await self.router.chat(messages, temperature=0.3)
            content = resp.content or ""
            user_content, identity_content = _parse_profile_update(content)
            if user_content:
                self.memory.write_memory_file("user", user_content)
            if identity_content:
                self.memory.write_memory_file("identity", identity_content)
            self.logger.info("Auto-updated memory files from conversation")
        except Exception as e:
            self.logger.warning(f"Auto-profile update failed: {e}", exc_info=True)

    async def _run_skill_evolution(self) -> list[str]:
        """Evolve underperforming skills using LLM-powered rewriting.

        Returns list of skill IDs that were evolved.
        """
        evolved: list[str] = []
        if not self.evolver:
            return evolved
        for skill_id, spec in self.skills.get_all().items():
            if not self.evolver.should_evolve(skill_id):
                continue
            await self._run_skill_evolution_for(skill_id, spec)
            evolved.append(skill_id)
        return evolved

    async def _run_skill_evolution_for(
        self, skill_id: str, spec: Any | None = None
    ) -> None:
        """Evolve a single skill in the background."""
        if not self.evolver:
            return
        if spec is None:
            spec = self.skills.get_all().get(skill_id)
            if spec is None:
                return
        self.logger.info(f"Triggering auto-evolution for skill {skill_id}")
        try:
            async def _llm_caller(prompt: str) -> str:
                messages = [
                    ChatMessage(role="system", content="You are an expert code optimizer."),
                    ChatMessage(role="user", content=prompt),
                ]
                resp = await self.router.chat(messages, temperature=0.3)
                return resp.content or ""

            variant = await self.evolver.evolve_skill(
                skill_id=skill_id,
                current_code=getattr(spec, "full_content", ""),
                llm_caller=_llm_caller,
            )
            if variant:
                self.logger.info(
                    f"Evolved skill {skill_id}: new variant {variant.id}"
                )
        except Exception as e:
            self.logger.warning(f"Evolution failed for {skill_id}: {e}")

    async def close(self) -> None:
        """Clean up resources: HTTP clients, DB connections, etc."""
        # Signal cancellation for all active runs
        self._shutdown_requested = True
        for event, _run_id in self._cancel_tokens.values():
            event.set()
        self.stop_background_tasks()
        resources = [
            ("router", getattr(self, "router", None)),
            ("search", getattr(self, "search", None)),
            ("_browser_tool", getattr(self, "_browser_tool", None)),
            ("_webbridge_tool", getattr(self, "_webbridge_tool", None)),
            ("memory", getattr(self, "memory", None)),
            ("audit", getattr(self, "audit", None)),
            ("skills", getattr(self, "skills", None)),
        ]
        for name, obj in resources:
            if obj is None:
                continue
            try:
                if hasattr(obj, "close"):
                    result = obj.close()
                    if asyncio.iscoroutine(result):
                        await result
            except Exception as e:
                self.logger.warning(f"Failed to close {name}: {e}")

    async def _run_dreaming(self) -> None:
        """Background task for memory consolidation with LLM insight generation."""
        try:

            async def summarizer(content: str) -> str:
                messages = [
                    ChatMessage(
                        role="system",
                        content=(
                            "You are a memory analyst. Analyze the following memory data and "
                            "extract concise, actionable insights. Focus on patterns, recurring themes, "
                            "and notable observations. Respond in the same language as the input."
                        ),
                    ),
                    ChatMessage(role="user", content=content),
                ]
                resp = await self.router.chat(
                    messages, temperature=0.3
                )
                return resp.content or ""

            report = await self.memory.dream(llm_summarizer=summarizer)
            if report and report.get("phases"):
                self.logger.info(
                    "Memory dreaming completed",
                    extra={"phases": [p["phase"] for p in report["phases"]]},
                )
        except Exception as e:
            self.logger.debug(f"Background dreaming failed: {e}")

    async def chat_stream(
        self,
        user_input: str,
        session_id: str | None = None,
        model: str | None = None,
        attachments: list[str] | None = None,
    ) -> AsyncIterator[str]:
        """Stream the agent response token by token."""
        session_id = session_id or str(uuid.uuid4())
        attachments = attachments or []

        user_input = self.secrets.detect_and_redact(user_input, "user_input")
        attachment_ctx = await self._build_attachment_context(attachments)

        messages: list[ChatMessage] = []
        # Load historical conversation context
        try:
            history = await asyncio.to_thread(
                self.memory.get_session_messages, session_id
            )
            for m in history[-50:]:
                if m.get("role") in ("user", "assistant") and m.get("content"):
                    messages.append(ChatMessage(role=m["role"], content=m["content"]))
        except Exception:
            self.logger.warning("Failed to load session history for stream", exc_info=True)

        messages.insert(
            0,
            ChatMessage(
                role="system",
                content=self._build_system_message(
                    query=user_input, session_id=session_id, attachments=attachments
                ),
            ),
        )
        messages.append(ChatMessage(role="user", content=user_input + attachment_ctx))

        decision = await self.router.select_model(preferred=model)
        async for token in decision.provider.chat_stream(
            messages=messages,
            model=decision.model,
        ):
            yield token


    def _register_search_tool(self) -> None:
        """Register web search as a tool."""
        from js.tools.registry import ToolParam, ToolResult, ToolSpec

        async def search_handler(query: str, max_results: int = 5) -> ToolResult:
            results = await self.search.search(query, max_results)
            if not results:
                return ToolResult(success=False, error="Search returned no results")
            output = "\n\n".join(
                f"[{i+1}] {r.title}\nURL: {r.url}\n{r.snippet}"
                for i, r in enumerate(results)
            )
            return ToolResult(success=True, output=output)

        spec = ToolSpec(
            name="web_search",
            description="Search the web for current information. Returns top results with snippets.",
            parameters=[
                ToolParam("query", "string", "Search query"),
                ToolParam("max_results", "integer", "Max results (1-10)", required=False),
            ],
        )
        self.registry.register(spec, search_handler)
