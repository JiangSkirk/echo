"""Core Agent engine: reasoning loop, delegation, and state management.

``JSAgent`` is assembled from focused mixins:
  * :class:`~js.agent.state.StateMixin` — checkpoint save/load/resume
  * :class:`~js.agent.prompt_builder.PromptBuilderMixin` — system/context prompts
  * :class:`~js.agent.tool_executor.ToolExecutorMixin` — tool schema + execution
  * :class:`~js.agent.finalizer.FinalizerMixin` — post-run persistence/learning
  * :class:`~js.agent.runner.RunnerMixin` — the run loop (via ``TurnExecutor``)

The residual orchestration (subsystem wiring, health, evolution, dreaming) lives
on ``JSAgent`` here.  ``AgentState`` is re-exported for backward compatibility:
``from js.agent import JSAgent, AgentState`` keeps working.
"""

from __future__ import annotations

import asyncio
from typing import Any

from cachetools import TTLCache

from js.agent.finalizer import FinalizerMixin
from js.agent.prompt_builder import PromptBuilderMixin
from js.agent.runner import RunnerMixin
from js.agent.state import AgentState, StateMixin
from js.agent.tool_executor import ToolExecutorMixin
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
from js.models.providers import ChatMessage
from js.models.router import ModelRouter
from js.security.approvals import ApprovalMode, ApprovalQueue
from js.security.audit import AuditLogger
from js.security.guard import BehaviorGuard
from js.security.sandbox import SandboxExecutor
from js.security.secrets import SecretManager
from js.security.strategies import build_default_strategies
from js.skills.composer import SkillComposer
from js.skills.curator import SkillCurator
from js.skills.evolver import SkillEvolver
from js.skills.manager import SkillManager
from js.skills.promotion_store import PromotionStore
from js.tools.registry import ToolRegistry
from js.utils.log import get_logger

__all__ = ["AgentState", "JSAgent"]


class JSAgent(
    StateMixin,
    PromptBuilderMixin,
    ToolExecutorMixin,
    FinalizerMixin,
    RunnerMixin,
):
    """Main agent orchestrator."""

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
                    f"Dynamic provider '{dyn_cfg.name}' skipped: name conflicts with static config"
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
        # Structured memory extraction (facts/people/plans → proposal queue).
        from js.memory.organizer import MemoryOrganizer

        self._organizer = MemoryOrganizer(self.memory, self.router, settings.memory)
        self._memory_bootstrapped = False

        # Plugin system
        self.plugins: Any = None
        self._init_plugins()

        # Tooling layer
        self.registry = ToolRegistry(settings.tools, self.guard)
        # v0.1.5-alpha: PromotionStore must be constructed before SkillManager
        # so trust changes / proposals can be audited from the very first
        # ``trust_skill`` call. Curator and Evolver share the same store.
        self.promotion_store = PromotionStore(settings.state_dir / "skill_promotions.db")
        self.skills = SkillManager(
            settings.state_dir,
            settings.workspace,
            promotion_store=self.promotion_store,
            audit_logger=self.audit,
        )
        self.search = self._setup_search()

        # Learning & evolution
        self.learner = SelfLearner(settings.state_dir)
        self.optimizer = PromptOptimizer(settings.state_dir)
        self.evolver = SkillEvolver(
            settings.state_dir,
            promotion_store=self.promotion_store,
        )
        self.composer = SkillComposer(settings.state_dir)
        self._clawhub: Any | None = None
        self.compression_config = CompressionConfig()
        self.compressor = ContextCompressor(
            self.compression_config, summarizer=self._summarize_context
        )
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
        self.curator = SkillCurator(
            settings.state_dir,
            promotion_store=self.promotion_store,
            skill_manager=self.skills,
        )

        # Execution & safety
        self.skills.set_composer(self.composer)
        self.skills.set_sandbox(SandboxExecutor(settings.workspace, strict_isolation=True))
        self.skills.set_evolver(self.evolver)
        self.approvals = ApprovalQueue(default_mode=ApprovalMode.MANUAL)
        self.defense_strategies = build_default_strategies()
        self._setup_tools()

        # Register skills as callable tools
        self.skills.register_as_tools(self.registry)

        # Register default prompt variant for optimization
        self._init_default_prompt_variant()

        # Cancel & checkpoint support
        # Cancel-token storage: session_id -> (asyncio.Event, run_id, owner_key_hash)
        # The run_id guards against concurrent runs on the same session
        # popping each other's tokens.
        # The owner_key_hash prevents users from cancelling other users' sessions.
        self._cancel_tokens: dict[str, tuple[asyncio.Event, str, str | None]] = {}
        self._shutdown_requested = False
        self._system_message_cache: TTLCache[tuple[str, str, str], str] = TTLCache(
            maxsize=100, ttl=60
        )
        self._degraded = False
        self.degraded_reason = ""
        self._current_allowed_tools: set[str] = set()
        self._consecutive_tool_failures: int = 0
        from js.persistence.lifecycle_store import SessionLifecycleStore
        from js.persistence.state_store import StateStore

        self.state_store = StateStore(settings.state_dir / "checkpoints.db")
        self.lifecycle_store = SessionLifecycleStore(settings.state_dir / "lifecycle.db")
        from js.persistence.review_store import ReviewStore

        self.review_store = ReviewStore(settings.state_dir / "review_capsules.db")
        try:
            # Startup recovery must sweep ALL owners — a crash kills every
            # in-flight run regardless of who owns it. The per-owner
            # ``recover_aborted_sessions`` would only sweep the legacy-local
            # partition and silently leave authenticated owners' stale rows
            # stuck in ``running`` forever.
            recovered = self.lifecycle_store.recover_all_aborted_sessions()
            if recovered:
                self.logger.info(
                    f"Recovered {len(recovered)} aborted sessions",
                    extra={"sessions": [sid for sid, _ in recovered]},
                )
        except Exception:
            self.logger.warning("Session recovery failed", exc_info=True)
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
        # Desktop control tools (set dynamically by web layer via desktop_toggle)
        self._desktop_tools: Any | None = None

    @property
    def degraded(self) -> bool:
        return self._degraded

    def request_cancel(self, session_id: str, owner_key_hash: str | None = None) -> bool:
        """Request cancellation of an active run.

        If owner_key_hash is provided, only cancel sessions owned by that key.
        """
        entry = self._cancel_tokens.get(session_id)
        if entry is None:
            return False
        _, _, session_owner = entry
        if session_owner and owner_key_hash and session_owner != owner_key_hash:
            raise PermissionError("Cannot cancel another user's session")
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

    async def _summarize_context(
        self, messages: list[ChatMessage], identifiers: list[str] | None = None
    ) -> str:
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
            self.logger.info(
                f"Plugin system initialized: {len(self.plugins.list_plugins())} plugins discovered"
            )
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
        self, conversation_buffer: list[dict[str, Any]]
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
            "memory_extraction": {"ok": True, "skipped": True, "error": None},
            "dreaming": {"ok": False, "error": None},
            "skill_evolution": {"ok": False, "error": None, "evolved": []},
        }
        # One-time bootstrap extraction once a model is connected & ready.
        await self._maybe_bootstrap_memory()
        if conversation_buffer:
            try:
                await self._auto_update_profiles(conversation_buffer)
                report["profile_update"] = {"ok": True, "skipped": False, "error": None}
            except Exception as e:
                report["profile_update"] = {"ok": False, "skipped": False, "error": str(e)}
                self.logger.warning(f"Profile update failed: {e}", exc_info=True)
            # Structured extraction → proposal queue (per-owner attribution).
            try:
                report["memory_extraction"] = await self._extract_memories(conversation_buffer)
            except Exception as e:
                report["memory_extraction"] = {"ok": False, "skipped": False, "error": str(e)}
                self.logger.warning(f"Memory extraction failed: {e}", exc_info=True)
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

    async def _extract_memories(self, conversation_buffer: list[dict[str, Any]]) -> dict[str, Any]:
        """Run structured extraction over the buffer, grouped by owner.

        Each buffered turn carries its ``owner_key_hash``/``session_id`` so
        extracted facts are staged under the correct user's partition.
        """
        if self._degraded or not getattr(self.settings.memory, "auto_extract", True):
            return {"ok": True, "skipped": "degraded_or_disabled", "error": None}
        groups: dict[str | None, list[dict[str, Any]]] = {}
        for turn in conversation_buffer:
            owner = turn.get("owner_key_hash")
            groups.setdefault(owner, []).append(turn)
        totals: dict[str, Any] = {
            "ok": True,
            "skipped": False,
            "proposed": 0,
            "auto_applied": 0,
            "pending": 0,
            "error": None,
        }
        for owner, turns in groups.items():
            sid = ""
            for t in reversed(turns):
                if t.get("session_id"):
                    sid = str(t["session_id"])
                    break
            res = await self._organizer.extract(turns, session_id=sid, owner_key_hash=owner)
            totals["proposed"] += res.get("proposed", 0)
            totals["auto_applied"] += res.get("auto_applied", 0)
            totals["pending"] += res.get("pending", 0)
            if res.get("error"):
                totals["error"] = res["error"]
        return totals

    async def _maybe_bootstrap_memory(self) -> None:
        """Seed the memory library from recent history once a model is ready.

        Runs at most once.  Skipped while the model is degraded (so it retries
        on a later cycle once a model connects), when auto-extract is disabled,
        or in multi-user mode where per-session owner attribution for historical
        sessions isn't available (the per-turn path handles attribution there).
        """
        if self._memory_bootstrapped:
            return
        if not getattr(self.settings.memory, "auto_extract", True):
            return
        if self._degraded:
            return  # no usable model yet — retry on a later cycle
        if self.settings.security.api_key_required:
            self._memory_bootstrapped = True
            return
        try:
            await self._organizer.bootstrap(owner_key_hash=None)
        except Exception:
            self.logger.debug("Memory bootstrap failed", exc_info=True)
        finally:
            self._memory_bootstrapped = True

    async def _auto_update_profiles(self, conversation_buffer: list[dict[str, Any]]) -> None:
        """Use LLM to analyze recent conversation and update USER.md + IDENTITY.md."""
        try:
            current_user = self.memory.read_memory_file("user")
            current_identity = self.memory.read_memory_file("identity")
        except Exception as e:
            self.logger.warning(f"Failed to read profile files: {e}", exc_info=True)
            return

        transcript = "\n\n".join(
            f"User: {turn['user']}\nAssistant: {turn['assistant']}" for turn in conversation_buffer
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
            user_content = text[user_start + len("===USER===") : identity_start].strip()
            identity_content = text[identity_start + len("===IDENTITY===") :].strip()
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

    async def _run_skill_evolution_for(self, skill_id: str, spec: Any | None = None) -> None:
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
                self.logger.info(f"Evolved skill {skill_id}: new variant {variant.id}")
        except Exception as e:
            self.logger.warning(f"Evolution failed for {skill_id}: {e}")

    async def close(self) -> None:
        """Clean up resources: HTTP clients, DB connections, etc."""
        # Signal cancellation for all active runs
        self._shutdown_requested = True
        for event, _run_id, _ in self._cancel_tokens.values():
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
                resp = await self.router.chat(messages, temperature=0.3)
                return resp.content or ""

            report = await self.memory.dream(llm_summarizer=summarizer)
            if report and report.get("phases"):
                self.logger.info(
                    "Memory dreaming completed",
                    extra={"phases": [p["phase"] for p in report["phases"]]},
                )
        except Exception as e:
            self.logger.debug(f"Background dreaming failed: {e}")
