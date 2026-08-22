"""Core Agent engine: reasoning loop, delegation, and state management.

``JSAgent`` is assembled from focused mixins:
  * :class:`~js.agent.state.StateMixin` — checkpoint save/load/resume
  * :class:`~js.agent.prompt_builder.PromptBuilderMixin` — system/context prompts
  * :class:`~js.agent.tool_executor.ToolExecutorMixin` — tool schema + execution
  * :class:`~js.agent.finalizer.FinalizerMixin` — post-run persistence/learning
  * :class:`~js.agent.runner.RunnerMixin` — public run/stream API facade over
    :class:`~js.echo.turn_runtime.EchoRuntime`

The residual orchestration (subsystem wiring, health, evolution, dreaming) lives
on ``JSAgent`` here.  ``AgentState`` is re-exported for backward compatibility:
``from js.agent import JSAgent, AgentState`` keeps working.
"""

from __future__ import annotations

import asyncio
import contextvars
import secrets
import threading
import uuid
from collections.abc import Callable
from enum import StrEnum
from typing import Any, cast

from cachetools import TTLCache

from js.agent.finalizer import FinalizerMixin
from js.agent.prompt_builder import PromptBuilderMixin
from js.agent.runner import RunnerMixin
from js.agent.state import AgentState, StateMixin
from js.agent.tool_executor import ToolExecutorMixin
from js.compression.compressor import CompressionConfig, ContextCompressor
from js.compression.feedback import CompressionFeedback
from js.config import JSSettings
from js.echo.context_tokenizer import TokenCounter, model_token_counter
from js.echo.durable_thread import (
    DurableClaim,
    EchoDurableExecutor,
    claim_to_thread,
    durable_to_thread,
)
from js.echo.effect_interpreter import ModelEffect
from js.echo.model_budget import EchoBudgetExceededError, EchoModelBudget
from js.echo.primitives import BudgetLimits
from js.echo.turn_context import RuntimeContext, current_owner_key_hash, current_runtime_context
from js.echo.turn_loop import (
    _authorize_echo_model_call,
    _finish_echo_model_call,
    _model_terminal_status,
    _router_supports_model_gate_callbacks,
)
from js.evolution.learner import SelfLearner
from js.evolution.metacognition import MetacognitionLoop
from js.evolution.optimizer import PromptOptimizer
from js.memory.embeddings import Embedder, HybridEmbedder, KeywordEmbedder, LLMEmbedder
from js.memory.scheduler import DreamScheduler
from js.memory.store import MemoryStore
from js.models.permit import ModelPermitIssuer
from js.models.provider_manager import ProviderManager, hydrate_static_provider_api_keys
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
from js.skills.promotion_store import PromotionStore
from js.tools.registry import ToolRegistry
from js.utils.log import get_logger

__all__ = ["AgentState", "JSAgent", "OwnedCancelResult"]


class OwnedCancelResult(StrEnum):
    """Fail-closed result for an owner-bound AppShell cancellation request."""

    CANCELLED = "cancelled"
    IDLE = "idle"
    DENIED = "denied"


_SUMMARY_TENANT: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "js_agent_summary_tenant",
    default=None,
)


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
        self._echo_durable_executor = EchoDurableExecutor(
            thread_name_prefix=f"echo-{getattr(settings, 'product_id', 'js-agent')}"
        )
        self._role: str | None = None  # Set by AgentFleet.spawn() for role-based tool restrictions
        self._init_subsystems()

    def _push_summary_tenant(self, tenant_id: str | None) -> contextvars.Token[str | None]:
        return _SUMMARY_TENANT.set(tenant_id)

    def _reset_summary_tenant(self, token: contextvars.Token[str | None]) -> None:
        _SUMMARY_TENANT.reset(token)

    def _init_subsystems(self) -> None:
        """Initialize all agent subsystems."""
        settings = self.settings
        features = settings.features

        # Core infrastructure
        static_provider_secrets = SecretManager(settings.state_dir)
        hydrate_static_provider_api_keys(
            self.settings.providers,
            static_provider_secrets,
        )
        # Unforgeable model-call permit issuer owned by this Echo runtime.
        # The router receives it as a verifier at construction time; there is
        # no public way to rebind authorization callbacks afterwards.
        self._model_permit_issuer = ModelPermitIssuer()
        self.router = ModelRouter(settings, permit_verifier=self._model_permit_issuer)
        from js.echo.ledger.service import EchoSafetyService

        self.echo_safety_service = EchoSafetyService.from_settings(settings)
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
        self.secrets = static_provider_secrets
        self.memory = MemoryStore(settings.state_dir, settings.memory, self._setup_embedder())
        self._dream_scheduler = DreamScheduler(self)
        # Structured memory extraction (facts/people/plans → proposal queue).
        from js.memory.organizer import MemoryOrganizer

        self._organizer = MemoryOrganizer(
            self.memory,
            self._memory_extraction_model_chat,
            settings.memory,
        )
        self._memory_bootstrapped = False

        # Plugin system
        self.plugins: Any = None
        if features.plugins_enabled:
            self._init_plugins()

        # Tooling layer
        self.registry = ToolRegistry(settings.tools, self.guard)
        self.promotion_store = None
        self.skills = None  # type: ignore[assignment]
        if features.skills_enabled:
            # v0.1.5-alpha: PromotionStore must be constructed before SkillManager
            # so trust changes / proposals can be audited from the very first
            # ``trust_skill`` call. Curator and Evolver share the same store.
            self.promotion_store = PromotionStore(settings.state_dir / "skill_promotions.db")
            self.skills = SkillManager(
                settings.state_dir,
                settings.workspace,
                promotion_store=self.promotion_store,
                audit_logger=self.audit,
                hermes_skills_enabled=features.hermes_skills_enabled,
            )
        self.search = self._setup_search()

        # Learning & evolution
        self.learner = None  # type: ignore[assignment]
        self.optimizer = None  # type: ignore[assignment]
        self.evolver = None  # type: ignore[assignment]
        self.composer = None  # type: ignore[assignment]
        self._clawhub: Any | None = None
        warning = float(settings.memory.compression_threshold)
        if warning >= 0.85:
            critical = min(0.95, warning + 0.05)
        else:
            critical = max(warning, 0.85)
        self.compression_config = CompressionConfig(
            warning_threshold=warning,
            critical_threshold=critical,
        )
        self.compression_feedback = CompressionFeedback(settings.state_dir)
        self.compressor = ContextCompressor(
            self.compression_config,
            summarizer=self._summarize_context,
            feedback=self.compression_feedback,
        )
        self._model_token_counters: dict[tuple[str, str], TokenCounter] = {}
        self._model_token_counter_lock = threading.Lock()
        self.metacognition = None  # type: ignore[assignment]
        self.curator = None  # type: ignore[assignment]
        if features.evolution_enabled:
            self.learner = SelfLearner(settings.state_dir)
            self.optimizer = PromptOptimizer(settings.state_dir)
            self.evolver = SkillEvolver(
                settings.state_dir,
                promotion_store=self.promotion_store,
            )
            self.composer = SkillComposer(settings.state_dir)
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
        if self.skills is not None:
            self.skills.set_composer(self.composer)
            self.skills.set_sandbox(SandboxExecutor(settings.workspace, strict_isolation=True))
            self.skills.set_evolver(self.evolver)
        self.approvals = ApprovalQueue(
            default_mode=ApprovalMode.MANUAL,
            ledger_path=settings.state_dir / "echo_approvals.jsonl",
        )
        # Unify the approval lifecycle into the authoritative EchoLedger; the
        # local JSONL file remains only a derived mirror.
        from js.security.approvals import wire_echo_approval_sink

        self.approvals.set_echo_event_sink(
            wire_echo_approval_sink(
                self.echo_safety_service,
                product_id=str(getattr(settings, "product_id", "js-agent")),
            )
        )
        self.defense_strategies = build_default_strategies()
        self._setup_tools()

        # Register skills as callable tools
        if self.skills is not None and features.skills_enabled and features.skill_tools_enabled:
            self.skills.register_as_tools(self.registry)

        # Register default prompt variant for optimization
        self._init_default_prompt_variant()

        # Cancel & checkpoint support
        # Cancel-token storage: partition -> (event, run_id, owner, session_id).
        # The plaintext session id is retained only in the trusted in-process
        # registry so AppShell can enumerate every departing-owner resource.
        # The run_id guards against concurrent runs on the same session
        # popping each other's tokens.
        # The owner_key_hash prevents users from cancelling other users' sessions.
        self._cancel_tokens: dict[
            str,
            tuple[asyncio.Event, str, str | None, str],
        ] = {}
        # Browser request identity is kept separately because Echo replaces
        # the provisional wire run id with its authoritative runtime run id.
        self._cancel_client_identity: dict[
            str,
            tuple[asyncio.Event, str, str],
        ] = {}
        self._active_run_tasks: dict[
            str,
            tuple[asyncio.Task[Any], str, str | None],
        ] = {}
        self._background_model_tasks: set[asyncio.Task[Any]] = set()
        self._shutdown_requested = False
        self._last_skill_evolution_check_monotonic: float | None = None
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

        from js.echo.turn_runtime import EchoRuntime

        self.echo_runtime = EchoRuntime(self)

        # Quality scoring & self-learning闭环 (OpenHuman-style)
        try:
            from js.evolution.quality_scorer import QualityScorer

            self._quality_scorer = QualityScorer(settings.state_dir)
        except Exception:
            self.logger.warning(
                "Quality scorer initialization failed; learning context is disabled",
                exc_info=True,
            )
            self._quality_scorer = None  # type: ignore[assignment]

        # Resource governance (started via start_background_tasks)
        self._governor: Any | None = None
        self._fleet_getter: Any | None = None
        # Desktop control tools (set dynamically by web layer via desktop_toggle)
        self._desktop_tools: Any | None = None

    @property
    def degraded(self) -> bool:
        return self._degraded

    def bind_cancel_token(
        self,
        session_id: str,
        token: asyncio.Event,
        *,
        owner_key_hash: str | None = None,
        run_id: str | None = None,
        request_id: str | None = None,
    ) -> None:
        """Register a connection-owned cancel token before lane admission."""
        from js.echo.turn_context import runtime_partition_key

        partition_key = runtime_partition_key(
            getattr(self.settings, "product_id", "js-agent"),
            owner_key_hash,
            session_id,
        )
        logical_run_id = run_id or f"conn-{secrets.token_hex(8)}"
        self._cancel_tokens[partition_key] = (
            token,
            logical_run_id,
            owner_key_hash,
            session_id,
        )
        if request_id:
            self._cancel_client_identity[partition_key] = (
                token,
                request_id,
                logical_run_id,
            )

    def owned_active_session_ids(self, *, owner_key_hash: str) -> tuple[str, ...]:
        """Snapshot active cancel-token sessions for one verified runtime owner."""
        if not isinstance(owner_key_hash, str) or not owner_key_hash.strip():
            raise ValueError("owner_key_hash must be a non-empty string")
        sessions: set[str] = set()
        for entry in tuple(self._cancel_tokens.values()):
            if not isinstance(entry, tuple) or len(entry) < 3:
                continue
            event, _run_id, entry_owner = entry[:3]
            if event.is_set() or not isinstance(entry_owner, str):
                continue
            if len(entry_owner) != len(owner_key_hash) or not secrets.compare_digest(
                entry_owner,
                owner_key_hash,
            ):
                continue
            if len(entry) < 4:
                raise RuntimeError("active cancel token lacks trusted session binding")
            session_id = entry[3]
            if isinstance(session_id, str) and session_id.strip():
                sessions.add(session_id)
        return tuple(sorted(sessions))

    def unbind_cancel_token(
        self,
        session_id: str,
        token: asyncio.Event,
        *,
        owner_key_hash: str | None = None,
    ) -> None:
        """Remove a connection-owned cancel token when it still matches ``token``."""
        from js.echo.turn_context import runtime_partition_key

        partition_key = runtime_partition_key(
            getattr(self.settings, "product_id", "js-agent"),
            owner_key_hash,
            session_id,
        )
        entry = self._cancel_tokens.get(partition_key)
        if entry is not None and entry[0] is token:
            self._cancel_tokens.pop(partition_key, None)
        identity = self._cancel_client_identity.get(partition_key)
        if identity is not None and identity[0] is token:
            self._cancel_client_identity.pop(partition_key, None)

    def request_cancel(
        self,
        session_id: str,
        owner_key_hash: str | None = None,
        *,
        expected_run_id: str | None = None,
        expected_request_id: str | None = None,
    ) -> bool:
        """Request cancellation of an active run.

        If owner_key_hash is provided, only cancel sessions owned by that key.
        """
        from js.echo.turn_context import runtime_partition_key

        partition_key = runtime_partition_key(
            getattr(self.settings, "product_id", "js-agent"),
            owner_key_hash,
            session_id,
        )
        entry = self._cancel_tokens.get(partition_key)
        if entry is None:
            return False
        identity_registry = getattr(self, "_cancel_client_identity", None)
        if identity_registry is not None and not isinstance(identity_registry, dict):
            return False
        client_identity = (
            identity_registry.get(partition_key)
            if isinstance(identity_registry, dict)
            else None
        )
        if client_identity is not None:
            if not isinstance(client_identity, tuple) or len(client_identity) != 3:
                return False
            identity_token, request_id, logical_run_id = client_identity
            if not isinstance(request_id, str) or not isinstance(logical_run_id, str):
                return False
            if identity_token is not entry[0]:
                return False
            if expected_run_id is None and expected_request_id is None:
                return False
            if expected_run_id is not None and not secrets.compare_digest(
                logical_run_id,
                expected_run_id,
            ):
                return False
            if expected_request_id is not None and not secrets.compare_digest(
                request_id,
                expected_request_id,
            ):
                return False
        elif expected_run_id is not None and not secrets.compare_digest(
            str(entry[1]),
            expected_run_id,
        ):
            return False
        _, run_id, session_owner = entry[:3]
        expected_owner = owner_key_hash or "local-user"
        if (session_owner or "local-user") != expected_owner:
            raise PermissionError("Cannot cancel another user's session")
        cancel_event = entry[0]
        if cancel_event.is_set():
            return True
        cancel_event.set()
        try:
            self.audit.log(
                AuditEventType.CANCELLED,
                session_id,
                run_id,
                "user",
                "cancel_requested",
                {"owner_bound": owner_key_hash is not None},
            )
        except Exception:
            self.logger.warning("Failed to record cancellation audit event", exc_info=True)
        active = self._active_run_tasks.get(partition_key)
        if active is not None and active[1] == run_id:
            task = active[0]
            if task is not asyncio.current_task() and not task.done():
                task.cancel()
        return True

    def request_owned_cancel(
        self,
        session_id: str,
        *,
        owner_key_hash: str,
    ) -> OwnedCancelResult:
        """Cancel exactly one owner/session or distinguish idle from cross-owner denial."""
        from js.echo.turn_context import runtime_partition_key

        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be a non-empty string")
        if not isinstance(owner_key_hash, str) or not owner_key_hash.strip():
            raise ValueError("owner_key_hash must be a non-empty string")

        product_id = str(getattr(self.settings, "product_id", "js-agent") or "js-agent")
        partition_key = runtime_partition_key(product_id, owner_key_hash, session_id)
        entry = self._cancel_tokens.get(partition_key)
        if entry is None:
            for candidate_key, candidate in self._cancel_tokens.items():
                if not isinstance(candidate, tuple) or len(candidate) < 3:
                    continue
                candidate_owner = candidate[2]
                if candidate_owner is not None and (
                    not isinstance(candidate_owner, str) or not candidate_owner
                ):
                    continue
                candidate_partition = runtime_partition_key(
                    product_id,
                    candidate_owner,
                    session_id,
                )
                if secrets.compare_digest(candidate_partition, candidate_key):
                    return OwnedCancelResult.DENIED
            return OwnedCancelResult.IDLE

        session_owner = entry[2]
        if (
            not isinstance(session_owner, str)
            or len(session_owner) != len(owner_key_hash)
            or not secrets.compare_digest(session_owner, owner_key_hash)
        ):
            return OwnedCancelResult.DENIED
        expected_identity: dict[str, str] = {"expected_run_id": str(entry[1])}
        identity_registry = getattr(self, "_cancel_client_identity", None)
        if identity_registry is not None and not isinstance(identity_registry, dict):
            return OwnedCancelResult.IDLE
        client_identity = (
            identity_registry.get(partition_key)
            if isinstance(identity_registry, dict)
            else None
        )
        if client_identity is not None:
            if not isinstance(client_identity, tuple) or len(client_identity) != 3:
                return OwnedCancelResult.IDLE
            identity_token, request_id, logical_run_id = client_identity
            if identity_token is not entry[0]:
                return OwnedCancelResult.IDLE
            if (
                not isinstance(request_id, str)
                or not request_id
                or not isinstance(logical_run_id, str)
                or not logical_run_id
            ):
                return OwnedCancelResult.IDLE
            expected_identity = {
                "expected_request_id": request_id,
                "expected_run_id": logical_run_id,
            }
        if not self.request_cancel(
            session_id,
            owner_key_hash=owner_key_hash,
            **expected_identity,
        ):
            return OwnedCancelResult.IDLE
        return OwnedCancelResult.CANCELLED

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
        self,
        messages: list[ChatMessage],
        identifiers: list[str] | None = None,
        *,
        runtime_context: RuntimeContext | None = None,
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
        context = runtime_context or current_runtime_context()
        if context is None:
            owner_key_hash = (
                _SUMMARY_TENANT.get() or current_owner_key_hash("local-user") or "local-user"
            )
            context = self.echo_runtime.build_context(
                channel="context_summary",
                owner_key_hash=owner_key_hash,
                session_id="background-summary",
            )
        response = await self.echo_runtime.execute_model_effect(
            ModelEffect(messages=tuple(summary_messages), model=None),
            context,
        )
        if isinstance(response.content, str):
            return response.content
        return ""

    async def _memory_extraction_model_chat(
        self,
        messages: list[ChatMessage],
        *,
        tenant_id: str = "local",
        run_id: str = "memory:background",
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        """Execute organizer model work through the authoritative Echo runtime."""
        budget = self._new_echo_model_budget()

        def _reserve_attempt() -> None:
            budget.reserve_attempt(messages, tools)

        def _reserve_completion(completion_tokens: int) -> None:
            budget.reserve_completion(completion_tokens)

        session_id = run_id.removeprefix("memory:") or "background"
        context = self.echo_runtime.build_context(
            channel="memory_extraction",
            owner_key_hash=tenant_id,
            session_id=session_id,
            run_id=run_id,
            capabilities=(),
        )
        completion_limit = budget.remaining_completion_tokens()
        if max_tokens is not None:
            completion_limit = min(completion_limit, max_tokens)
        return await self.echo_runtime.execute_model_effect(
            ModelEffect(
                messages=tuple(messages),
                model=model,
                tools_schema=tuple(tools or ()),
                temperature=temperature,
                max_tokens=completion_limit,
                before_model_attempt=_reserve_attempt,
                completion_budget_callback=_reserve_completion,
            ),
            context,
        )

    async def authorized_model_chat(
        self,
        messages: list[ChatMessage],
        *,
        tenant_id: str = "local",
        run_id: str = "background",
        session_id: str = "",
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        attachment_manifest: tuple[dict[str, Any], ...] = (),
        temperature: float = 0.7,
        max_tokens: int | None = None,
        budget_callback: Callable[[], None] | None = None,
        completion_budget_callback: Callable[[int], None] | None = None,
        model_budget: EchoModelBudget | None = None,
    ) -> ChatResponse:
        """Track every public background model call through graceful shutdown."""
        if self._shutdown_requested:
            raise RuntimeError("JSAgent is shutting down")
        task = asyncio.current_task()
        if task is not None:
            self._background_model_tasks.add(task)
        try:
            return await self._authorized_model_chat_impl(
                messages,
                tenant_id=tenant_id,
                run_id=run_id,
                session_id=session_id,
                model=model,
                tools=tools,
                attachment_manifest=attachment_manifest,
                temperature=temperature,
                max_tokens=max_tokens,
                budget_callback=budget_callback,
                completion_budget_callback=completion_budget_callback,
                model_budget=model_budget,
            )
        finally:
            if task is not None:
                self._background_model_tasks.discard(task)

    async def _authorized_model_chat_impl(
        self,
        messages: list[ChatMessage],
        *,
        tenant_id: str = "local",
        run_id: str = "background",
        session_id: str = "",
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        attachment_manifest: tuple[dict[str, Any], ...] = (),
        temperature: float = 0.7,
        max_tokens: int | None = None,
        budget_callback: Callable[[], None] | None = None,
        completion_budget_callback: Callable[[int], None] | None = None,
        model_budget: EchoModelBudget | None = None,
    ) -> ChatResponse:
        """Call the model through Echo's safety ledger."""

        effective_budget = model_budget
        if budget_callback is None and effective_budget is None:
            effective_budget = self._new_echo_model_budget(model=model)

        def _reserve_attempt(
            call_messages: list[ChatMessage],
            call_tools: list[dict[str, Any]] | None,
        ) -> None:
            if budget_callback is not None:
                budget_callback()
            elif effective_budget is not None:
                effective_budget.reserve_attempt(call_messages, call_tools)

        def _reserve_completion(response: ChatResponse) -> None:
            completion_tokens = int(response.usage.get("completion_tokens", 0) or 0)
            if completion_budget_callback is not None:
                completion_budget_callback(completion_tokens)
            elif effective_budget is not None:
                effective_budget.reserve_completion(completion_tokens)

        completion_limit = max_tokens
        if effective_budget is not None:
            budget_limit = effective_budget.remaining_completion_tokens()
            completion_limit = (
                budget_limit if completion_limit is None else min(completion_limit, budget_limit)
            )
        if completion_limit is not None and completion_limit <= 0:
            raise EchoBudgetExceededError("Echo budget exceeded: completion_tokens_exceeded")

        if _router_supports_model_gate_callbacks(self.router):

            async def _before(
                decision: Any, call_messages: list[ChatMessage], call_tools: Any
            ) -> Any:
                _reserve_attempt(call_messages, call_tools)
                return await claim_to_thread(
                    lambda: _authorize_echo_model_call(
                        self,
                        tenant_id=tenant_id,
                        run_id=run_id,
                        provider_id=str(getattr(decision, "provider_name", "")),
                        model_id=str(getattr(decision, "model", model or "default")),
                        messages=call_messages,
                        tools_schema=call_tools,
                        attachments_manifest=attachment_manifest,
                    ),
                    on_cancel=lambda context: _finish_echo_model_call(
                        self,
                        context,
                        assistant_text="model authorization cancelled",
                        status="cancelled",
                        token_totals={},
                    ),
                    executor=self._echo_durable_executor,
                )

            async def _after(
                context: Any,
                response: ChatResponse | None,
                error: BaseException | None,
            ) -> None:
                claimed_context = cast("DurableClaim[Any]", context)
                if response is None:
                    terminal_status = _model_terminal_status(error)
                    await durable_to_thread(
                        lambda: _finish_echo_model_call(
                            self,
                            claimed_context.value,
                            assistant_text=str(error) if error else "",
                            status=terminal_status,
                            token_totals={},
                        ),
                        claim=claimed_context,
                    )
                    return
                try:
                    _reserve_completion(response)
                except BaseException as exc:
                    error_text = str(exc)
                    await durable_to_thread(
                        lambda: _finish_echo_model_call(
                            self,
                            claimed_context.value,
                            assistant_text=error_text,
                            status="failed",
                            token_totals={},
                        ),
                        claim=claimed_context,
                    )
                    raise
                await durable_to_thread(
                    lambda: _finish_echo_model_call(
                        self,
                        claimed_context.value,
                        assistant_text=response.content,
                        status="completed",
                        token_totals={
                            "input": int(response.usage.get("prompt_tokens", 0) or 0),
                            "output": int(response.usage.get("completion_tokens", 0) or 0),
                        },
                        token_source=response.usage_source,
                    ),
                    claim=claimed_context,
                )

            _bind = getattr(self.router, "bind_echo_callbacks", None)
            if _bind is not None:
                raise RuntimeError(
                    "router exposes a rebindable callback API; refusing to run "
                    "the Echo model gate against an unforgeable-permit-less router"
                )

            def _permit_grant(
                decision: Any,
                call_messages: list[ChatMessage],
                call_tools: Any,
            ) -> Any:
                return self._model_permit_issuer.issue(
                    provider_name=str(getattr(decision, "provider_name", "")),
                    model=str(getattr(decision, "model", model or "default")),
                    messages=call_messages,
                    tools=call_tools,
                    owner_key_hash=tenant_id,
                    session_id=session_id,
                    run_id=run_id,
                )

            return await self.router.chat(
                messages=messages,
                model=model,
                tools=tools,
                temperature=temperature,
                max_tokens=completion_limit,
                before_model_call=_before,
                after_model_call=_after,
                permit_grant=_permit_grant,
            )

        from js.echo.ledger.service import EchoUnavailableError

        raise EchoUnavailableError(
            "Echo on-mode requires model gate callbacks and runtime permit support"
        )

    def _token_counter_for_model(self, model: str | None) -> TokenCounter:
        provider_name: str | None = None
        resolved_model = model or "auto"
        if model is not None:
            get_binding = getattr(self.router, "get_model_binding", None)
            if callable(get_binding):
                binding = get_binding(model)
                if binding is not None:
                    provider_name, model_config = binding
                    resolved_model = model_config.id
        cache_key = (provider_name or "auto", resolved_model)
        with self._model_token_counter_lock:
            cached = self._model_token_counters.get(cache_key)
            if cached is not None:
                return cached
            counter = model_token_counter(
                provider_name=provider_name,
                model=None if model is None else resolved_model,
            )
            self._model_token_counters[cache_key] = counter
            return counter

    def _new_echo_model_budget(self, *, model: str | None = None) -> EchoModelBudget:
        budget = self.settings.echo_budget
        token_counter = self._token_counter_for_model(model)
        return EchoModelBudget(
            limits=BudgetLimits(
                max_prompt_tokens=budget.max_prompt_tokens,
                max_completion_tokens=budget.max_completion_tokens,
                max_tool_calls=budget.max_tool_calls,
                max_journal_appends=budget.max_journal_appends,
                max_elapsed_ms=budget.max_elapsed_ms,
            ),
            estimate_prompt_tokens=lambda messages, tools: self.compressor.estimate_tokens(
                list(messages),
                tools=list(tools) if tools is not None else None,
                token_counter=token_counter,
            ),
            token_unit_id=token_counter.token_unit_id,
        )

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
        """Expose release-shipped plugin metadata without importing plugin code."""
        try:
            from js.plugins.manager import PluginManager

            self.plugins = PluginManager(self, self.settings)
            self.plugins.discover()
            self.logger.info(
                "Plugin metadata initialized: "
                f"{len(self.plugins.list_plugins())} release-shipped plugins discovered"
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

    def set_active_model_publisher(self, publisher: Any) -> None:
        """Publish an Echo-authorized model switch to the active channel state."""
        if not callable(publisher):
            raise TypeError("active model publisher must be callable")
        self._active_model_publisher = publisher

    def start_background_tasks(self) -> None:
        """Start background scheduling loops."""
        if self.settings.features.daemon_enabled:
            self._dream_scheduler.start()
            from js.daemon.core import build_default_daemon

            self._daemon = build_default_daemon(self.settings, agent=self)
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

        if not self.settings.features.evolution_enabled:
            return {
                "profile_update": {"ok": True, "skipped": True, "error": None},
                "memory_extraction": {"ok": True, "skipped": True, "error": None},
                "dreaming": {"ok": True, "skipped": True, "error": None},
                "skill_evolution": {"ok": True, "skipped": True, "error": None, "evolved": []},
                "elapsed_seconds": 0.0,
            }

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
        """Update profile files independently for every owner in the buffer."""
        owner_turns: dict[str | None, list[dict[str, Any]]] = {}
        for turn in conversation_buffer:
            raw_owner = turn.get("owner_key_hash")
            owner = str(raw_owner) if raw_owner else None
            owner_turns.setdefault(owner, []).append(turn)

        def _parse_profile_update(text: str) -> tuple[str | None, str | None]:
            """Robustly extract USER and IDENTITY sections from LLM output."""
            user_start = text.find("===USER===")
            identity_start = text.find("===IDENTITY===")
            if user_start == -1 or identity_start == -1:
                return None, None
            user_content = text[user_start + len("===USER===") : identity_start].strip()
            identity_content = text[identity_start + len("===IDENTITY===") :].strip()
            return user_content, identity_content

        for owner, turns in owner_turns.items():
            try:
                current_user = self.memory.read_memory_file("user", owner_key_hash=owner)
                current_identity = self.memory.read_memory_file("identity", owner_key_hash=owner)
                transcript = "\n\n".join(
                    f"User: {turn['user']}\nAssistant: {turn['assistant']}" for turn in turns
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
                session_id = next(
                    (str(turn["session_id"]) for turn in turns if turn.get("session_id")),
                    "profile-update",
                )
                owner_key_hash = owner or "local"
                model_budget = self._new_echo_model_budget()

                def _reserve_profile_attempt(
                    budget: EchoModelBudget = model_budget,
                    effect_messages: tuple[ChatMessage, ...] = tuple(messages),
                ) -> None:
                    budget.reserve_attempt(effect_messages, None)

                def _reserve_profile_completion(
                    completion_tokens: int,
                    budget: EchoModelBudget = model_budget,
                ) -> None:
                    budget.reserve_completion(completion_tokens)

                runtime_context = self.echo_runtime.build_context(
                    channel="profile_update",
                    owner_key_hash=owner_key_hash,
                    session_id=session_id,
                    run_id=f"profile:{session_id}:{uuid.uuid4()}",
                    capabilities=(),
                )
                resp = await self.echo_runtime.execute_model_effect(
                    ModelEffect(
                        messages=tuple(messages),
                        temperature=0.3,
                        max_tokens=model_budget.remaining_completion_tokens(),
                        before_model_attempt=_reserve_profile_attempt,
                        completion_budget_callback=_reserve_profile_completion,
                    ),
                    runtime_context,
                )
                content = resp.content or ""
                user_content, identity_content = _parse_profile_update(content)
                if user_content:
                    self.memory.write_memory_file("user", user_content, owner_key_hash=owner)
                if identity_content:
                    self.memory.write_memory_file(
                        "identity", identity_content, owner_key_hash=owner
                    )
                self.logger.info("Auto-updated owner-scoped memory files")
            except Exception as e:
                self.logger.warning(f"Auto-profile update failed: {e}", exc_info=True)
                raise

    async def _run_skill_evolution(self) -> list[str]:
        """Evolve underperforming skills using LLM-powered rewriting.

        Returns list of skill IDs that were evolved.
        """
        evolved: list[str] = []
        if not self.evolver or self.skills is None:
            return evolved
        skills = self.skills.get_all()
        batch_check = getattr(type(self.evolver), "should_evolve_many", None)
        if callable(batch_check):
            due = await asyncio.to_thread(
                self.evolver.should_evolve_many,
                tuple(skills),
            )
        else:
            due = {skill_id for skill_id in skills if self.evolver.should_evolve(skill_id)}
        for skill_id in due:
            spec = skills[skill_id]
            await self._run_skill_evolution_for(skill_id, spec)
            evolved.append(skill_id)
        return evolved

    async def _run_skill_evolution_for(self, skill_id: str, spec: Any | None = None) -> None:
        """Evolve a single skill in the background."""
        if not self.evolver or self.skills is None:
            return
        if spec is None:
            spec = self.skills.get_all().get(skill_id)
            if spec is None:
                return
        self.logger.info(f"Triggering auto-evolution for skill {skill_id}")
        try:
            model_budget = self._new_echo_model_budget()
            runtime_context = self.echo_runtime.build_context(
                channel="skill_evolution",
                owner_key_hash="local",
                session_id=skill_id,
                run_id=f"skill-evolution:{skill_id}",
                capabilities=(),
            )

            async def _llm_caller(prompt: str) -> str:
                messages = [
                    ChatMessage(role="system", content="You are an expert code optimizer."),
                    ChatMessage(role="user", content=prompt),
                ]

                def _reserve_skill_attempt() -> None:
                    model_budget.reserve_attempt(messages, None)

                def _reserve_skill_completion(completion_tokens: int) -> None:
                    model_budget.reserve_completion(completion_tokens)

                resp = await self.echo_runtime.execute_model_effect(
                    ModelEffect(
                        messages=tuple(messages),
                        temperature=0.3,
                        max_tokens=model_budget.remaining_completion_tokens(),
                        before_model_attempt=_reserve_skill_attempt,
                        completion_budget_callback=_reserve_skill_completion,
                    ),
                    runtime_context,
                )
                return resp.content or ""

            variant = await self.evolver.evolve_skill(
                skill_id=skill_id,
                current_code=getattr(spec, "full_content", ""),
                llm_caller=_llm_caller,
                propagate_llm_errors=True,
            )
            if variant:
                self.logger.info(f"Evolved skill {skill_id}: new variant {variant.id}")
        except Exception as e:
            self.logger.warning(f"Evolution failed for {skill_id}: {e}")
            raise

    async def close(self) -> None:
        """Clean up resources: HTTP clients, DB connections, etc."""
        # Signal cancellation for all active runs
        self._shutdown_requested = True
        for entry in self._cancel_tokens.values():
            entry[0].set()
        current_task = asyncio.current_task()
        active_tasks: set[asyncio.Task[Any]] = set()
        cancellable_tasks: set[asyncio.Task[Any]] = set()
        for partition_key, (task, run_id, _owner) in list(self._active_run_tasks.items()):
            if task is current_task or task.done():
                continue
            active_tasks.add(task)
            cancel_entry = self._cancel_tokens.get(partition_key)
            if cancel_entry is not None and cancel_entry[1] == run_id:
                cancellable_tasks.add(task)
        for task in cancellable_tasks:
            task.cancel()
        for task in tuple(self._background_model_tasks):
            if task is current_task or task.done():
                continue
            active_tasks.add(task)
            task.cancel()
        runtime = getattr(self, "echo_runtime", None)
        for task in tuple(getattr(runtime, "active_turn_tasks", ())):
            if task is current_task or task.done():
                continue
            active_tasks.add(task)
        if active_tasks:
            await asyncio.gather(*active_tasks, return_exceptions=True)
        governor = self._governor
        self.stop_background_tasks()
        if governor is not None and hasattr(governor, "wait_stopped"):
            try:
                wait_result = governor.wait_stopped()
                if asyncio.iscoroutine(wait_result):
                    await wait_result
            except Exception as e:
                self.logger.warning(f"Failed to stop resource governor: {e}")
        resources = [
            ("router", getattr(self, "router", None)),
            ("search", getattr(self, "search", None)),
            ("_browser_tool", getattr(self, "_browser_tool", None)),
            ("_webbridge_tool", getattr(self, "_webbridge_tool", None)),
            ("memory", getattr(self, "memory", None)),
            ("audit", getattr(self, "audit", None)),
            ("skills", getattr(self, "skills", None)),
            ("promotion_store", getattr(self, "promotion_store", None)),
            ("echo_safety_service", getattr(self, "echo_safety_service", None)),
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
        self._echo_durable_executor.shutdown(wait=True)

    async def _run_dreaming(self) -> None:
        """Background task for memory consolidation with LLM insight generation."""
        try:
            model_budget = self._new_echo_model_budget()

            async def summarizer(content: str, owner_key_hash: str | None) -> str:
                if owner_key_hash == "__legacy_local__":
                    tenant_id = "local"
                elif owner_key_hash:
                    tenant_id = owner_key_hash
                else:
                    raise ValueError(
                        "Refusing to summarize authenticated dream content without an owner"
                    )
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
                runtime_context = self.echo_runtime.build_context(
                    channel="dreaming",
                    owner_key_hash=tenant_id,
                    session_id="dreaming",
                    run_id=f"dreaming:{tenant_id}",
                    capabilities=(),
                )

                def _reserve_dream_attempt() -> None:
                    model_budget.reserve_attempt(messages, None)

                def _reserve_dream_completion(completion_tokens: int) -> None:
                    model_budget.reserve_completion(completion_tokens)

                resp = await self.echo_runtime.execute_model_effect(
                    ModelEffect(
                        messages=tuple(messages),
                        temperature=0.3,
                        max_tokens=model_budget.remaining_completion_tokens(),
                        before_model_attempt=_reserve_dream_attempt,
                        completion_budget_callback=_reserve_dream_completion,
                    ),
                    runtime_context,
                )
                return resp.content or ""

            report = await self.memory.dream(
                llm_summarizer=summarizer,
                propagate_summarizer_errors=True,
            )
            if report and report.get("phases"):
                self.logger.info(
                    "Memory dreaming completed",
                    extra={"phases": [p["phase"] for p in report["phases"]]},
                )
        except Exception as e:
            self.logger.debug(f"Background dreaming failed: {e}")
            raise
