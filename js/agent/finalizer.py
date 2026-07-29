"""Post-run finalization: persist memory, audit, learning, and trigger evolution."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

from js.agent.base import AgentBase

if TYPE_CHECKING:
    from js.agent.state import AgentState

_SKILL_EVOLUTION_SWEEP_INTERVAL_SECONDS = 300.0


class FinalizerMixin(AgentBase):
    """Persists conversation/episodic memory and records learning signals."""

    async def _finalize_run(
        self,
        state: AgentState,
        session_id: str,
        run_id: str,
        user_input: str,
        history_ua_count: int,
    ) -> None:
        """Persist memory, audit logs, and learning data after a run completes."""
        from js.echo.turn_context import (
            current_owner_key_hash,
            current_runtime_context,
            runtime_partition_key,
        )

        runtime_context = current_runtime_context()
        owner_key_hash = (
            runtime_context.owner_key_hash
            if runtime_context is not None
            else current_owner_key_hash()
        )
        product_id = (
            runtime_context.product_id
            if runtime_context is not None
            else getattr(self.settings, "product_id", "js-agent")
        )
        completed = state.status == "completed"

        # Persist the real terminal state; failures and cancellation are not successes.
        exit_reason = state.error_message or state.status
        try:
            terminal_status = state.status if state.status != "running" else "error"
            self.lifecycle_store.mark_terminal(
                session_id,
                terminal_status,
                exit_reason,
                owner_key_hash,
                run_id,
            )
            partition_key = runtime_partition_key(
                product_id,
                owner_key_hash,
                session_id,
            )
            cancel_entry = self._cancel_tokens.get(partition_key)
            if cancel_entry is not None and cancel_entry[1] == run_id:
                self._cancel_tokens.pop(partition_key, None)
        except Exception:
            self.logger.warning("Failed to mark session completed", exc_info=True)

        # Store deterministic Task Review Capsule (MVP, no LLM)
        try:
            from js.persistence.review_store import ReviewCapsule

            first_user = ""
            last_assistant = ""
            for msg in state.messages:
                if msg.role == "user" and isinstance(msg.content, str):
                    first_user = msg.content
                    break
            if completed:
                for msg in reversed(state.messages):
                    if msg.role == "assistant" and isinstance(msg.content, str):
                        last_assistant = msg.content
                        break
            tools_used = [
                {"name": r.metadata.get("tool_name", "unknown"), "success": r.success}
                for r in state.tool_results
            ]
            review = ReviewCapsule(
                session_id=session_id,
                run_id=run_id,
                first_user_message=self.secrets.detect_and_redact(first_user, "review_user"),
                last_assistant_message=self.secrets.detect_and_redact(
                    last_assistant, "review_assistant"
                ),
                tools_used=tools_used,
                total_tokens=sum(state.total_tokens.values()),
                turn_count=state.turn_count,
                status=state.status,
                error_message=state.error_message or "",
                owner_key_hash=owner_key_hash,
            )
            self.review_store.store(review)
        except Exception:
            self.logger.warning("Failed to store review capsule", exc_info=True)

        # Extract assistant output for memory storage
        assistant_output = ""
        if completed:
            for msg in reversed(state.messages):
                if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                    assistant_output = self.secrets.detect_and_redact(
                        msg.content, "assistant_output"
                    )
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
                if completed or msg.role == "user"
            ]
            if new_messages:
                redacted_messages = [
                    {
                        "role": m["role"],
                        "content": self.secrets.detect_and_redact(m["content"], "message"),
                    }
                    for m in new_messages
                ]
                await asyncio.to_thread(
                    self.memory.store_messages,
                    session_id,
                    redacted_messages,
                    owner_key_hash,
                )
        except Exception as e:
            self.logger.debug(f"Failed to store messages: {e}")

        if not completed:
            # A cancelled or failed turn may contain a provider response that
            # was never committed to the user.  Keep lifecycle/review/audit and
            # the user's message, but do not turn provisional assistant output
            # into episodic memory, learning data, capsules, or evolution work.
            try:
                self.guard.reset_loop_counters(run_id)
            except Exception:
                self.logger.warning("Failed to reset guard counters", exc_info=True)
            try:
                await asyncio.to_thread(
                    self.compression_feedback.record_outcome,
                    session_id=session_id,
                    turn_number=state.turn_count,
                    success=False,
                    error_type=state.error_message or state.status,
                    owner_key_hash=owner_key_hash,
                )
            except Exception:
                self.logger.warning("Failed to record compression outcome", exc_info=True)
            if self.optimizer is not None:
                try:
                    from js.agent.prompt_builder import consume_selected_prompt_variant_id

                    variant_id = consume_selected_prompt_variant_id()
                    if variant_id:
                        await asyncio.to_thread(
                            self.optimizer.record_result,
                            variant_id,
                            False,
                            0.0,
                            context="system",
                        )
                except Exception:
                    self.logger.warning(
                        "Failed to record prompt optimization result", exc_info=True
                    )
            self.logger.info(
                "Run complete",
                extra={
                    "run": run_id,
                    "status": state.status,
                    "turns": state.turn_count,
                    "tokens": state.total_tokens,
                },
            )
            return

        # Store episodic memory second
        try:
            safe_user_input = self.secrets.detect_and_redact(user_input, "user_input")
            summary = self.secrets.detect_and_redact(
                f"User: {safe_user_input[:80]}... → Assistant: {assistant_output[:80]}...",
                "episode_summary",
            )
            topics = list(
                {
                    word.lower()
                    for word in (user_input + " " + assistant_output).split()
                    if len(word) > 4 and word.isalpha()
                }
            )[:5]
            await asyncio.to_thread(
                self.memory.store_episode,
                session_id=session_id,
                summary=summary,
                topics=topics,
                tokens_used=sum(state.total_tokens.values()),
                turn_count=state.turn_count,
                importance=7 if state.status == "completed" else 4,
                owner_key_hash=owner_key_hash,
            )
            try:
                self._dream_scheduler.notify_activity(
                    user_input,
                    assistant_output,
                    owner_key_hash=owner_key_hash,
                    session_id=session_id,
                )
            except Exception as e:
                self.logger.debug(f"Failed to notify scheduler: {e}")
        except Exception as mem_err:
            self.logger.warning(f"Memory consolidation failed: {mem_err}")

        # Inject learning context into working memory (OpenHuman-style)
        if self._quality_scorer is not None:
            try:
                learning_ctx = self._quality_scorer.build_learning_context(
                    max_tokens=200,
                    owner_key_hash=owner_key_hash,
                )
                if learning_ctx:
                    await asyncio.to_thread(
                        self.memory.store_working,
                        session_id=session_id,
                        key="learning_context",
                        value=learning_ctx,
                        category="meta",
                        importance=8,
                        owner_key_hash=owner_key_hash,
                    )
            except Exception:
                self.logger.debug("Learning context injection failed", exc_info=True)

        # Session Capsule: summarize long conversations for cheaper follow-up turns
        if self.settings.memory.capsule_enabled:
            try:
                total_tokens = sum(state.total_tokens.values())
                threshold = self.settings.memory.capsule_token_threshold
                if total_tokens > threshold:
                    capsule_text = await self._summarize_context(state.messages)
                    if capsule_text:
                        capsule_text = self.secrets.detect_and_redact(capsule_text, "capsule")
                        await asyncio.to_thread(
                            self.memory.store_capsule,
                            session_id,
                            capsule_text,
                            owner_key_hash,
                        )
                        self.logger.info(
                            "Session capsule refreshed",
                            extra={"session": session_id, "tokens": total_tokens},
                        )
            except Exception:
                self.logger.warning("Failed to refresh session capsule", exc_info=True)

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
        if self.learner is not None:
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
                    owner_key_hash=owner_key_hash,
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
                owner_key_hash=owner_key_hash,
            )
        except Exception:
            self.logger.warning("Failed to record compression outcome", exc_info=True)

        # Record prompt optimization result
        if self.optimizer is not None:
            try:
                from js.agent.prompt_builder import consume_selected_prompt_variant_id

                variant_id = consume_selected_prompt_variant_id()
                if variant_id:
                    await asyncio.to_thread(
                        self.optimizer.record_result,
                        variant_id,
                        state.status == "completed",
                        1.0 if state.status == "completed" else 0.0,
                        context="system",
                    )
            except Exception:
                self.logger.warning("Failed to record prompt optimization result", exc_info=True)

        # Trigger metacognition if interval reached
        if self.metacognition is not None:
            try:
                await asyncio.to_thread(self.metacognition.tick)
            except Exception:
                self.logger.warning("Metacognition tick failed", exc_info=True)

        # Periodic skill curation
        if self.curator is not None and self.skills is not None:
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
        evolution_check_now = time.monotonic()
        last_evolution_check = getattr(
            self,
            "_last_skill_evolution_check_monotonic",
            None,
        )
        evolution_check_due = (
            last_evolution_check is None
            or evolution_check_now - last_evolution_check >= _SKILL_EVOLUTION_SWEEP_INTERVAL_SECONDS
        )
        if (
            self.evolver is not None
            and self.skills is not None
            and not getattr(self, "_shutdown_requested", False)
            and evolution_check_due
        ):
            self._last_skill_evolution_check_monotonic = evolution_check_now
            try:
                skills = self.skills.get_all()
                batch_check = getattr(type(self.evolver), "should_evolve_many", None)
                if callable(batch_check):
                    due = await asyncio.to_thread(
                        self.evolver.should_evolve_many,
                        tuple(skills),
                    )
                else:
                    due = {skill_id for skill_id in skills if self.evolver.should_evolve(skill_id)}
                if getattr(self, "_shutdown_requested", False):
                    return
                for skill_id in due:
                    self.logger.info(f"Triggering auto-evolution for skill {skill_id}")
                    task = asyncio.create_task(
                        self._run_skill_evolution_for(skill_id, skills[skill_id]),
                        name=f"evolve-{skill_id}",
                    )
                    self._background_model_tasks.add(task)

                    def _discard_evolution_task(
                        completed: asyncio.Task[None],
                    ) -> None:
                        self._background_model_tasks.discard(completed)
                        if completed.cancelled():
                            return
                        try:
                            completed.result()
                        except Exception:
                            self.logger.warning(
                                "Background skill evolution failed",
                                exc_info=True,
                            )

                    task.add_done_callback(_discard_evolution_task)
            except Exception:
                self.logger.warning("Auto-evolution check failed", exc_info=True)
