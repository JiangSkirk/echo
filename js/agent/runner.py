"""The agent reasoning loop.

``RunnerMixin`` exposes the public ``run``/``chat_stream`` entry points and the
thin ``_do_run`` that delegates to ``TurnExecutor`` — a dedicated class that
owns one run's multi-turn loop, with state setup, context compression, model
calls, and tool execution split into focused methods.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

from js.agent.base import AgentBase
from js.agent.state import AgentState
from js.models.providers import ChatMessage, ChatResponse
from js.security.audit import AuditEventType
from js.tools.registry import ParallelToolExecutor, ToolResult
from js.utils.metrics import get_metrics, start_span

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


class RunnerMixin(AgentBase):
    """Public run entry points; per-run loop lives in :class:`TurnExecutor`."""

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
        """Core agent run logic — delegates to :class:`TurnExecutor`."""
        executor = TurnExecutor(
            self, user_input, session_id, model, attachments,
            _resume_state, stream_callback, progress_callback,
        )
        return await executor.execute()

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
        from js.web.auth import _session_owner_hash
        owner = _session_owner_hash.get(None)
        try:
            history = await asyncio.to_thread(
                self.memory.get_session_messages, session_id, owner
            )
            for m in history[-50:]:
                if m.get("role") in ("user", "assistant") and m.get("content"):
                    messages.append(ChatMessage(role=m["role"], content=m["content"]))
        except PermissionError:
            raise
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


class TurnExecutor:
    """Drives one agent run: state setup → turn loop → finalize.

    The loop body is split into focused steps — state management
    (:meth:`_setup`, :meth:`_check_cancelled`, :meth:`_enforce_message_limit`),
    context compression (:meth:`_compress`), model calls
    (:meth:`_get_response`, :meth:`_record_response`), and tool execution
    (:meth:`_run_tools`) — while preserving the original behaviour exactly.
    """

    def __init__(
        self,
        agent: AgentBase,
        user_input: str,
        session_id: str | None,
        model: str | None,
        attachments: list[str] | None,
        resume_state: AgentState | None,
        stream_callback: Callable[[str], Awaitable[None]] | None,
        progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None,
    ) -> None:
        self.agent = agent
        self.user_input = user_input
        self.session_id = session_id or ""
        self.model = model
        self.attachments = attachments or []
        self.resume_state = resume_state
        self.stream_callback = stream_callback
        self.progress_callback = progress_callback
        self.run_id = ""
        self.history_ua_count = 0
        self.state: AgentState

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    async def execute(self) -> AgentState:
        await self._setup()
        with start_span("agent.run"):
            try:
                await self._run_loop()
            except Exception as e:
                state = self.state
                state.status = "error"
                state.error_message = str(e)
                self.agent.logger.error("Run failed", exc_info=True, extra={"run": self.run_id})
                self.agent.audit.log(
                    AuditEventType.ERROR,
                    self.session_id,
                    self.run_id,
                    "agent",
                    "exception",
                    {"error": str(e)},
                )
                from js.events.models import AgentEvent
                self.agent.event_store.emit(
                    AgentEvent.error(session_id=self.session_id, run_id=self.run_id, error=str(e))
                )
                await self.agent._check_degraded()
            finally:
                await self.agent._finalize_run(
                    self.state, self.session_id, self.run_id, self.user_input, self.history_ua_count
                )
                # Only pop the token if it still belongs to this run, to avoid
                # racing with a newer run on the same session.
                entry = self.agent._cancel_tokens.get(self.session_id)
                if entry is not None and entry[1] == self.state.run_id:
                    self.agent._cancel_tokens.pop(self.session_id, None)
        return self.state

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    async def _setup(self) -> None:
        """Initialise run state, load history, and seed the message list."""
        agent = self.agent
        agent._consecutive_tool_failures = 0
        self.session_id = self.session_id or str(uuid.uuid4())
        self.run_id = str(uuid.uuid4())
        if self.resume_state:
            state = self.resume_state
            # Preserve the original run_id for traceability; track the
            # resume chain via parent_run_id if we ever add it.
        else:
            state = AgentState(session_id=self.session_id, run_id=self.run_id)
        self.state = state
        # Capture owner for session isolation
        from js.web.auth import _session_owner_hash
        owner = _session_owner_hash.get(None)
        agent._cancel_tokens[self.session_id] = (asyncio.Event(), state.run_id, owner)

        try:
            get_metrics().agent_runs_total.inc()
        except Exception:
            agent.logger.warning("Suppressed error", exc_info=True)

        agent.logger.info(
            "Starting run",
            extra={"session": self.session_id, "run": self.run_id, "attachments": len(self.attachments)},
        )
        agent.audit.log(
            AuditEventType.USER_MESSAGE,
            self.session_id,
            self.run_id,
            "user",
            "message",
            {"content_length": len(self.user_input), "attachments": len(self.attachments)},
        )

        # Redact secrets from user input
        self.user_input = agent.secrets.detect_and_redact(self.user_input, "user_input")

        # Build attachment context
        attachment_ctx = await agent._build_attachment_context(self.attachments)

        if self.resume_state is None:
            # Fresh run: load historical conversation context
            try:
                history = await asyncio.to_thread(
                    agent.memory.get_session_messages, self.session_id, owner
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
            except PermissionError:
                agent._cancel_tokens.pop(self.session_id, None)
                raise
            except Exception:
                agent.logger.warning("Failed to load session history", exc_info=True)

            # Count historical user/assistant messages already persisted
            self.history_ua_count = sum(
                1 for m in state.messages
                if m.role in ("user", "assistant") and isinstance(m.content, str)
            )

            # Session Capsule: for long sessions, keep only recent turns verbatim
            # and inject a short capsule summary into the system message.
            capsule_text = ""
            if agent.settings.memory.capsule_enabled:
                try:
                    capsule = await asyncio.to_thread(
                        agent.memory.get_capsule, self.session_id, owner
                    )
                    if capsule:
                        capsule_text = capsule.get("capsule_text", "") or ""
                        if capsule_text:
                            recent_turns = agent.settings.memory.capsule_recent_turns
                            recent_messages = recent_turns * 2
                            kept = state.messages[-recent_messages:] if len(state.messages) > recent_messages else state.messages
                            state.messages = [
                                m for m in kept
                                if m.role in ("user", "assistant") and isinstance(m.content, str)
                            ]
                            self.history_ua_count = len(state.messages)
                except Exception:
                    agent.logger.warning("Failed to load session capsule", exc_info=True)
                    capsule_text = ""

            # Initialize conversation with rich memory context
            system_content = agent._build_system_message(
                query=self.user_input, session_id=self.session_id,
                attachments=self.attachments, model=self.model,
            )
            if capsule_text:
                system_content += f"\n\n## Session Capsule\n{capsule_text}\n\nOnly the most recent {agent.settings.memory.capsule_recent_turns} turns are shown verbatim; rely on the capsule for older context."
            state.messages.insert(
                0,
                ChatMessage(role="system", content=system_content),
            )

            # Build user message: support multimodal for vision models
            model_config = agent.router.get_model_config(self.model or "")
            supports_vision = model_config.supports_vision if model_config else False
            vision_parts = agent._build_vision_content(self.user_input, self.attachments, supports_vision)
            if isinstance(vision_parts, list):
                state.messages.append(ChatMessage(role="user", content=vision_parts))
            else:
                state.messages.append(ChatMessage(role="user", content=self.user_input + attachment_ctx))
        else:
            # Resuming from checkpoint: state already contains system + history + user messages.
            # Count how many user/assistant messages are already in the state
            # so that _finalize_run only persists the new ones.
            self.history_ua_count = sum(
                1 for m in state.messages
                if m.role in ("user", "assistant") and isinstance(m.content, str)
            )

        # Store working memory for this interaction
        await asyncio.to_thread(
            agent.memory.store_working,
            session_id=self.session_id,
            key="user_input",
            value=self.user_input[:500],
            category="interaction",
            importance=5,
        )

    def _check_cancelled(self) -> bool:
        """Return True (and mark the state cancelled) if a cancel was requested."""
        agent = self.agent
        state = self.state
        cancel_entry = agent._cancel_tokens.get(self.session_id)
        if cancel_entry is not None:
            cancel_event, token_run_id, _ = cancel_entry
            # Only honour the cancel token if it belongs to the current run
            if token_run_id == state.run_id and cancel_event.is_set():
                state.status = "cancelled"
                state.error_message = "Run cancelled by user request"
                return True
        if agent._shutdown_requested:
            state.status = "cancelled"
            state.error_message = "Run cancelled by user request"
            return True
        return False

    def _enforce_message_limit(self) -> None:
        """OpenClaw trap defense: hard cap message count to avoid entropy death spiral."""
        agent = self.agent
        state = self.state
        _msg_hard_limit = agent.settings.security.max_messages_hard_limit
        if len(state.messages) > _msg_hard_limit:
            agent.logger.warning(
                f"Message count {len(state.messages)} exceeds hard limit {_msg_hard_limit}; "
                f"truncating oldest non-system messages"
            )
            # Keep system + last 100 messages
            trimmed = [m for m in state.messages if m.role == "system"]
            trimmed.extend(state.messages[-100:])
            state.messages = trimmed

    # ------------------------------------------------------------------
    # Turn loop
    # ------------------------------------------------------------------

    async def _run_loop(self) -> None:
        agent = self.agent
        state = self.state
        while state.turn_count < agent.settings.max_turns:
            # Check for cancellation request (token or global shutdown)
            if self._check_cancelled():
                break

            state.turn_count += 1
            agent.logger.debug(f"Turn {state.turn_count}", extra={"run": self.run_id})

            self._enforce_message_limit()

            turn_start = time.perf_counter()
            turn_tool_scores: list[Any] = []
            try:
                tools_schema, compressed_messages = await self._compress()
                response = await self._get_response(compressed_messages, tools_schema)
                self._record_response(response)

                # Check if done
                if not response.tool_calls:
                    # Local models occasionally return finish_reason="stop"
                    # with empty content — treat this as a model failure and
                    # retry (up to max_turns) rather than silently completing.
                    if not response.content or not response.content.strip():
                        agent.logger.warning(
                            f"Model returned empty content "
                            f"(finish_reason={response.finish_reason}), retrying"
                        )
                        # Remove the empty assistant message so it doesn't
                        # pollute the context for the retry.
                        state.messages.pop()
                        if state.turn_count >= agent.settings.max_turns:
                            state.status = "error"
                            state.error_message = "Model returned empty response after maximum retries"
                            break
                        continue
                    state.status = "completed"
                    break

                await self._run_tools(response, turn_tool_scores)
            finally:
                self._record_turn_metrics(turn_start, turn_tool_scores)

    # ------------------------------------------------------------------
    # Compression
    # ------------------------------------------------------------------

    async def _compress(self) -> tuple[list[dict[str, Any]] | None, list[ChatMessage]]:
        """Adjust budget, fetch tool schemas, and compress context for this turn."""
        agent = self.agent
        state = self.state
        # Adjust compressor budget to the actual model's context window
        # (local 8k models need aggressive compression, cloud 128k models don't)
        model_cfg = agent.router.get_model_config(self.model or "")
        if model_cfg and model_cfg.context_window:
            agent.compressor.config.max_tokens = model_cfg.context_window

        # Get tools schema first so compression accounts for tool overhead
        tools_schema = agent._get_tools_schema(self.model)

        # Compress context if needed (tools included in token estimate)
        compression_result = await agent.compressor.compress(
            state.messages, tools=tools_schema
        )
        compressed_messages = compression_result.messages
        if compression_result.level.value != "none":
            agent.logger.info(
                f"Context compressed ({compression_result.level.value}): "
                f"{compression_result.original_tokens} -> {compression_result.compressed_tokens} tokens"
            )
            agent.compression_feedback.record_compression(
                session_id=self.session_id,
                original_tokens=compression_result.original_tokens,
                compressed_tokens=compression_result.compressed_tokens,
                level=compression_result.level.value,
                original_messages=len(state.messages),
                compressed_messages=len(compressed_messages),
                identifiers_found=len(compression_result.identifiers_found),
            )

        # Record which tools the model is allowed to call this turn
        agent._current_allowed_tools = {
            s.get("function", {}).get("name", "") for s in (tools_schema or [])
        }
        return tools_schema, compressed_messages

    # ------------------------------------------------------------------
    # Model call
    # ------------------------------------------------------------------

    async def _get_response(
        self, compressed_messages: list[ChatMessage], tools_schema: list[dict[str, Any]] | None
    ) -> ChatResponse:
        """Call the model — streaming when there are no tools, else a normal chat."""
        agent = self.agent
        if self.stream_callback and not tools_schema:
            # Stream final assistant response when no tools
            decision = await agent.router.select_model(preferred=self.model)
            stream_text = ""
            async for token in decision.provider.chat_stream(
                messages=compressed_messages,
                model=decision.model,
            ):
                stream_text += token
                await self.stream_callback(token)

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

            return ChatResponse(
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
        return await agent.router.chat(
            messages=compressed_messages,
            model=self.model,
            tools=tools_schema if tools_schema else None,
        )

    def _record_response(self, response: ChatResponse) -> None:
        """Track model/usage/cost, audit, emit event, and append the assistant message."""
        agent = self.agent
        state = self.state
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
        model_config = agent.router.get_model_config(response.model)
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

        agent.audit.log(
            AuditEventType.MODEL_RESPONSE,
            self.session_id,
            self.run_id,
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
        agent.event_store.emit(
            AgentEvent.model_called(
                session_id=self.session_id,
                run_id=self.run_id,
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

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    async def _run_tools(self, response: ChatResponse, turn_tool_scores: list[Any]) -> None:
        """Execute tool calls (parallel when safe) and fold results into state."""
        agent = self.agent
        state = self.state
        parallel = ParallelToolExecutor()
        batches = parallel.group(response.tool_calls)
        agent.logger.debug(
            f"Tool batches: {len(batches)} for {len(response.tool_calls)} calls"
        )
        for batch in batches:
            batch_tasks = [
                agent._execute_tool_call(tc, self.session_id, self.run_id, self.user_input, self.progress_callback)
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
                            session_id=self.session_id,
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
                if agent._quality_scorer is not None:
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
                agent._consecutive_tool_failures += 1
                if agent._consecutive_tool_failures >= 2:
                    agent.logger.warning(
                        f"Dead-loop guard triggered after {agent._consecutive_tool_failures} "
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
                agent._consecutive_tool_failures = 0

            # Prevent unbounded growth of tool_results
            if len(state.tool_results) > 200:
                state.tool_results = state.tool_results[-200:]
            # Auto-save checkpoint after each tool batch (fire-and-forget)
            try:
                asyncio.create_task(agent.save_checkpoint(state))
                from js.events.models import AgentEvent
                agent.event_store.emit(
                    AgentEvent.checkpoint_saved(
                        session_id=self.session_id,
                        run_id=self.run_id,
                        turn=state.turn_count,
                    )
                )
            except Exception:
                agent.logger.warning("Checkpoint auto-save failed", exc_info=True)
            # Emit tool_result events
            from js.events.models import AgentEvent
            for tr in state.tool_results[-len(batch_results):]:
                agent.event_store.emit(
                    AgentEvent.tool_result(
                        session_id=self.session_id,
                        run_id=self.run_id,
                        tool_name=tr.error.split(":")[0] if not tr.success and tr.error else "unknown",
                        success=tr.success,
                        output_preview=tr.output or tr.error or "",
                    )
                )

    def _record_turn_metrics(self, turn_start: float, turn_tool_scores: list[Any]) -> None:
        """Record per-turn latency + quality score (runs in the turn's finally)."""
        agent = self.agent
        state = self.state
        turn_latency = time.perf_counter() - turn_start
        try:
            get_metrics().agent_turn_duration_seconds.observe(turn_latency)
        except Exception:
            agent.logger.warning("Suppressed error", exc_info=True)
        # Record turn quality score (OpenHuman-style)
        if agent._quality_scorer is not None:
            from js.evolution.quality_scorer import TurnScore
            agent._quality_scorer.record_turn(
                TurnScore(
                    session_id=self.session_id,
                    turn_idx=state.turn_count,
                    model=state.model or "",
                    tool_scores=turn_tool_scores,
                    total_tokens=state.total_tokens.get("input", 0) + state.total_tokens.get("output", 0),
                )
            )
