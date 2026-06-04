"""Post-run finalization: persist memory, audit, learning, and trigger evolution."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from js.agent.base import AgentBase

if TYPE_CHECKING:
    from js.agent.state import AgentState


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
                owner_key_hash=getattr(self, "_session_owner", None),
            )
            try:
                self._dream_scheduler.notify_activity(
                    user_input, assistant_output,
                    owner_key_hash=getattr(self, "_session_owner", None),
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
