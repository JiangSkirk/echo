"""Core Agent engine: reasoning loop, delegation, and state management."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from js.approvals.queue import ApprovalMode, ApprovalQueue
from js.compression.compressor import CompressionConfig, ContextCompressor
from js.compression.feedback import CompressionFeedback
from js.config import JSSettings
from js.evolution.learner import SelfLearner
from js.evolution.metacognition import MetacognitionLoop
from js.evolution.optimizer import PromptOptimizer
from js.memory.scheduler import DreamScheduler
from js.memory.store import MemoryStore
from js.models.provider_manager import ProviderManager
from js.models.providers import ChatMessage
from js.models.router import ModelRouter
from js.security.audit import AuditEventType, AuditLogger
from js.security.guard import BehaviorGuard
from js.security.sandbox import SandboxExecutor
from js.security.secrets import SecretManager
from js.security.strategies import build_default_strategies
from js.skills.composer import SkillComposer
from js.skills.curator import SkillCurator
from js.skills.evolver import SkillEvolver
from js.skills.manager import SkillManager
from js.tools.registry import ToolRegistry, ToolResult
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
    cost_estimate: float = 0.0
    status: str = "running"  # running, completed, error, blocked
    error_message: str = ""


class JSAgent:
    """Main agent orchestrator."""

    SYSTEM_PROMPT = """You are JS, a helpful and capable AI assistant. You have access to tools for file operations, shell commands, and more.

Key rules:
1. Use tools when needed - don't guess about file contents or system state
2. Always check if a file exists before reading it
3. Prefer read-only tools for investigation before making changes
4. Explain your reasoning clearly
5. If a task is too complex, suggest breaking it down
6. Never expose secrets, API keys, or tokens in your responses
7. Respect the user's workspace - don't modify files outside it without permission
"""

    def __init__(self, settings: JSSettings) -> None:
        self.settings = settings
        self.logger = get_logger("js.agent")
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
        self.memory = MemoryStore(settings.state_dir, settings.memory)
        self._dream_scheduler = DreamScheduler(self)

        # Tooling layer
        self.registry = ToolRegistry(settings.tools, self.guard)
        self.skills = SkillManager(settings.state_dir, settings.workspace)
        self.search = self._setup_search()

        # Learning & evolution
        self.learner = SelfLearner(settings.state_dir)
        self.optimizer = PromptOptimizer(settings.state_dir)
        self.evolver = SkillEvolver(settings.state_dir)
        self.composer = SkillComposer(settings.state_dir)
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
        from js.search.engines import DuckDuckGoEngine, SearchManager, TavilyEngine
        manager = SearchManager()
        manager.register(DuckDuckGoEngine(), default=True)
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

        office_tools = OfficeTools(self.settings.workspace, self.settings.tools, self.guard)
        office_tools.register_all(self.registry)

        # Register search as a tool
        self._register_search_tool()

        # TODO: Register code-type skills as tools (requires async handler wrapper)

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format byte size to human-readable string."""
        size = float(size_bytes)
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def _build_attachment_context(self, attachments: list[str]) -> str:
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
                parts.append(f"- 📷 图片: `{path.name}` ({self._format_size(size)})")
            elif suffix in {".mp4", ".mov", ".avi", ".mkv", ".webm"}:
                parts.append(f"- 🎬 视频: `{path.name}` ({self._format_size(size)})")
            elif suffix in {".mp3", ".wav", ".ogg", ".m4a", ".flac"}:
                parts.append(f"- 🎵 音频: `{path.name}` ({self._format_size(size)})")
            elif suffix in {".txt", ".md", ".py", ".js", ".json", ".yaml", ".yml", ".csv", ".html", ".css", ".xml", ".sh", ".log", ".pdf", ".docx"}:
                parts.append(f"- 📄 文档: `{path.name}` ({self._format_size(size)})")
                if suffix in {".txt", ".md", ".py", ".js", ".json", ".yaml", ".yml", ".csv", ".html", ".css", ".xml", ".sh", ".log"}:
                    try:
                        content = path.read_text(encoding="utf-8", errors="replace")[:2000]
                        parts.append(f"  预览:\n```\n{content}\n```")
                    except Exception:
                        pass
            else:
                parts.append(f"- 📎 文件: `{path.name}` ({self._format_size(size)})")

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
            self.logger.debug("Failed to register default prompt variant", exc_info=True)

    def _build_system_message(self, query: str = "", session_id: str = "", attachments: list[str] | None = None) -> str:
        """Build system message with rich multi-layer memory context."""
        parts = [self.SYSTEM_PROMPT]

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
                self.logger.debug("Failed to select prompt variant", exc_info=True)

        if self.settings.memory.enabled:
            memory_context = self.memory.get_context_string(
                query=query,
                session_id=session_id,
                max_chars=self.settings.memory.max_memory_chars,
            )
            if memory_context:
                parts.append(f"\n## Relevant Context\n{memory_context}")

        return "\n".join(parts)

    async def run(
        self,
        user_input: str,
        session_id: str | None = None,
        model: str | None = None,
        attachments: list[str] | None = None,
    ) -> AgentState:
        """Execute a full agent run."""
        session_id = session_id or str(uuid.uuid4())
        run_id = str(uuid.uuid4())
        state = AgentState(session_id=session_id, run_id=run_id)
        attachments = attachments or []

        try:
            get_metrics().agent_runs_total.inc()
        except Exception:
            self.logger.debug("Suppressed error", exc_info=True)

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
        attachment_ctx = self._build_attachment_context(attachments)

        # Load historical conversation context if continuing a session
        try:
            history = await asyncio.to_thread(
                self.memory.get_session_messages, session_id
            )
            for m in history[-50:]:  # Keep last 50 messages to fit context window
                if m.get("role") in ("user", "assistant") and m.get("content"):
                    state.messages.append(
                        ChatMessage(role=m["role"], content=m["content"])
                    )
        except Exception:
            self.logger.debug("Failed to load session history", exc_info=True)

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
                    query=user_input, session_id=session_id, attachments=attachments
                ),
            ),
        )
        state.messages.append(ChatMessage(role="user", content=user_input + attachment_ctx))

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
                    state.turn_count += 1
                    self.logger.debug(f"Turn {state.turn_count}", extra={"run": run_id})

                    turn_start = time.perf_counter()
                    try:
                        # Compress context if needed
                        compression_result = await self.compressor.compress(state.messages)
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
                        tools_schema = self.registry.to_openai_schemas()
                        response = await self.router.chat(
                            messages=compressed_messages,
                            model=model,
                            tools=tools_schema if tools_schema else None,
                        )

                        # Track usage
                        prompt_tokens = response.usage.get("prompt_tokens", 0)
                        completion_tokens = response.usage.get("completion_tokens", 0)
                        state.total_tokens["input"] += prompt_tokens
                        state.total_tokens["output"] += completion_tokens

                        # Calculate cost
                        model_config = self.router.get_model_config(response.model)
                        if model_config:
                            state.cost_estimate += (
                                prompt_tokens * model_config.cost_input +
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

                        # Add assistant message
                        state.messages.append(
                            ChatMessage(
                                role="assistant",
                                content=response.content,
                                tool_calls=response.tool_calls if response.tool_calls else None,
                            )
                        )

                        # Check if done
                        if not response.tool_calls:
                            state.status = "completed"
                            break

                        # Execute tools
                        tool_messages: list[ChatMessage] = []
                        for tc in response.tool_calls:
                            func = tc.get("function", {}) if isinstance(tc, dict) else {}
                            tool_name = func.get("name", "") if isinstance(func, dict) else ""
                            raw_args = func.get("arguments", "{}") if isinstance(func, dict) else "{}"
                            tool_call_id = tc.get("id", "") if isinstance(tc, dict) else ""
                            if not tool_name:
                                self.logger.warning("Tool call missing name, skipping")
                                continue
                            try:
                                arguments = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args if isinstance(raw_args, dict) else {})
                            except json.JSONDecodeError:
                                arguments = {}

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
                                result = ToolResult(
                                    success=False,
                                    error=f"Security blocked: {defense_result.reason}",
                                )
                                state.tool_results.append(result)
                                tool_messages.append(
                                    ChatMessage(
                                        role="tool",
                                        content=result.to_text(),
                                        tool_call_id=tool_call_id,
                                        name=tool_name,
                                    )
                                )
                                continue

                            # Approval check for dangerous tools
                            spec = self.registry.get(tool_name)
                            if spec and spec.dangerous:
                                approved = await asyncio.to_thread(
                                    self.approvals.request,
                                    tool_name=tool_name,
                                    arguments=arguments,
                                    context="cli",
                                )
                                if not approved:
                                    result = ToolResult(
                                        success=False,
                                        error="Operation denied: approval required but not granted",
                                    )
                                    state.tool_results.append(result)
                                    tool_messages.append(
                                        ChatMessage(
                                            role="tool",
                                            content=result.to_text(),
                                            tool_call_id=tool_call_id,
                                            name=tool_name,
                                        )
                                    )
                                    continue

                            self.audit.log(
                                AuditEventType.TOOL_CALL,
                                session_id,
                                run_id,
                                "agent",
                                tool_name,
                                {"arguments": arguments},
                            )

                            result = await self.registry.execute(run_id, tool_name, arguments)
                            state.tool_results.append(result)

                            # Redact secrets in output
                            if result.output:
                                result.output = self.secrets.detect_and_redact(result.output, f"tool:{tool_name}")

                            tool_messages.append(
                                ChatMessage(
                                    role="tool",
                                    content=result.to_text(),
                                    tool_call_id=tool_call_id,
                                    name=tool_name,
                                )
                            )

                        state.messages.extend(tool_messages)
                    finally:
                        turn_latency = time.perf_counter() - turn_start
                        try:
                            get_metrics().agent_turn_duration_seconds.observe(turn_latency)
                        except Exception:
                            self.logger.debug("Suppressed error", exc_info=True)

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

            finally:
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

                # Reset guard counters
                try:
                    self.guard.reset_loop_counters(run_id)
                except Exception:
                    self.logger.debug("Failed to reset guard counters", exc_info=True)

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
                    self.logger.debug("Failed to record interaction", exc_info=True)

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
                    self.logger.debug("Failed to record compression outcome", exc_info=True)

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
                    self.logger.debug("Failed to record prompt optimization result", exc_info=True)

                # Trigger metacognition if interval reached
                try:
                    await asyncio.to_thread(self.metacognition.tick)
                except Exception:
                    self.logger.debug("Metacognition tick failed", exc_info=True)

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
                    self.logger.debug("Skill curation failed", exc_info=True)

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
                    self.logger.debug("Auto-evolution check failed", exc_info=True)

        return state

    def start_background_tasks(self) -> None:
        """Start background scheduling loops."""
        self._dream_scheduler.start()

    def stop_background_tasks(self) -> None:
        """Stop background scheduling loops."""
        self._dream_scheduler.stop()

    async def _run_evolution_cycle(self, conversation_buffer: list[dict[str, str]]) -> None:
        """Full background evolution: profile update + dreaming + skill evolution.

        Each step is wrapped in its own try/except so that a failure in one
        does not prevent the others from running.
        """
        import time
        start = time.perf_counter()
        self.logger.info("Starting evolution cycle")
        if conversation_buffer:
            try:
                await self._auto_update_profiles(conversation_buffer)
            except Exception as e:
                self.logger.warning(f"Profile update failed: {e}", exc_info=True)
        try:
            await self._run_dreaming()
        except Exception as e:
            self.logger.warning(f"Dreaming failed: {e}", exc_info=True)
        # Trigger skill evolution for underperforming skills
        try:
            await self._run_skill_evolution()
        except Exception as e:
            self.logger.warning(f"Skill evolution failed: {e}", exc_info=True)
        elapsed = time.perf_counter() - start
        self.logger.info(f"Evolution cycle completed in {elapsed:.2f}s")

    async def _auto_update_profiles(self, conversation_buffer: list[dict[str, str]]) -> None:
        """Use LLM to analyze recent conversation and update USER.md + IDENTITY.md."""
        current_user = self.memory.read_memory_file("user")
        current_identity = self.memory.read_memory_file("identity")

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
            self.logger.debug(f"Auto-profile update failed: {e}", exc_info=True)

    async def _run_skill_evolution(self) -> None:
        """Evolve underperforming skills using LLM-powered rewriting."""
        if not self.evolver:
            return
        for skill_id, spec in self.skills.get_all().items():
            if not self.evolver.should_evolve(skill_id):
                continue
            await self._run_skill_evolution_for(skill_id, spec)

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
                current_code=getattr(spec, "content", ""),
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
        self.stop_background_tasks()
        resources = [
            ("router", getattr(self, "router", None)),
            ("search", getattr(self, "search", None)),
            ("_browser_tool", getattr(self, "_browser_tool", None)),
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
        attachment_ctx = self._build_attachment_context(attachments)

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
            self.logger.debug("Failed to load session history for stream", exc_info=True)

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

        decision = self.router.select_model(preferred=model)
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
