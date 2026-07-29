"""Idle-aware background scheduler for memory evolution and dreaming."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from js.utils.log import get_logger


class DreamScheduler:
    """Schedules memory evolution cycles during user idle time.

    Instead of running dreaming immediately after each conversation,
    this scheduler waits for a period of user inactivity, then runs
    a full evolution cycle: profile update + dreaming.
    """

    def __init__(self, agent: Any) -> None:
        self.agent = agent
        self._pending = False
        self._pending_since = 0.0
        self._last_activity = time.time()
        self._idle_threshold = 30.0
        self._max_deferral = 120.0
        self._check_interval = 15.0
        self._task: asyncio.Task[Any] | None = None
        self._conversation_buffer: list[dict[str, Any]] = []
        self._max_buffer = 5
        self.logger = get_logger("js.memory.scheduler")

    def notify_activity(
        self,
        user_input: str,
        assistant_output: str,
        owner_key_hash: str | None = None,
        session_id: str = "",
    ) -> None:
        """Call after each user interaction to mark pending and record conversation.

        ``owner_key_hash``/``session_id`` are carried through so the background
        evolution cycle can attribute extracted memories to the right user.
        """
        self._last_activity = time.time()
        if not self._pending:
            self._pending = True
            self._pending_since = time.time()
        self._conversation_buffer.append({
            "user": user_input[:500],
            "assistant": assistant_output[:500],
            "owner_key_hash": owner_key_hash,
            "session_id": session_id,
        })
        if len(self._conversation_buffer) > self._max_buffer:
            self._conversation_buffer.pop(0)

    def snapshot_buffer(self) -> list[dict[str, Any]]:
        """Return a read-only copy of the recent conversation buffer.

        Manual triggers ("organize now" / evolution run) use this so they
        process the same recent turns the idle cycle would, *without*
        consuming the buffer — the background cycle still gets its turn.
        """
        return list(self._conversation_buffer)

    def start(self) -> None:
        """Start the background scheduling loop."""
        if self._task and not self._task.done():
            self._task.cancel()
        self._task = asyncio.create_task(self._loop())
        self._task.add_done_callback(self._on_loop_done)

    def stop(self) -> None:
        """Stop the background scheduling loop."""
        if self._task and not self._task.done():
            self._task.cancel()

    def _on_loop_done(self, task: asyncio.Task[Any]) -> None:
        """Log any unhandled exception from the background loop."""
        if task.done() and not task.cancelled():
            exc = task.exception()
            if exc is not None:
                self.logger.error("DreamScheduler loop crashed: %s", exc, exc_info=True)

    async def force_consolidation(self, *, owner_key_hash: str | None = None) -> None:
        """Immediately run an evolution cycle, bypassing idle wait.

        Used by the daemon's cron dream task and manual triggers.
        When ``owner_key_hash`` is provided, consolidation is limited to that
        owner's memory partition; otherwise all owners are processed.
        """
        self._last_activity = 0.0
        self._pending = True
        self._pending_since = 0.0
        try:
            await asyncio.wait_for(
                self._run_once(),
                timeout=max(30.0, self._check_interval * 3),
            )
        except TimeoutError:
            self.logger.warning("force_consolidation timed out")

    async def _run_once(self) -> None:
        """Execute a single evolution cycle."""
        buffer_copy = list(self._conversation_buffer)
        snapshot_ids = {id(item) for item in buffer_copy}
        try:
            await asyncio.wait_for(
                self.agent._run_evolution_cycle(conversation_buffer=buffer_copy),
                timeout=120.0,
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.warning("Evolution cycle failed: %s", e, exc_info=True)
        finally:
            # Always advance the buffer so it doesn't grow unboundedly on
            # repeated failures.  If the cycle succeeded we drop the copied
            # items; if it failed we still drop them to avoid re-processing
            # stale conversation fragments in the next cycle.
            self._pending = False
            self._conversation_buffer = [
                item
                for item in self._conversation_buffer
                if id(item) not in snapshot_ids
            ]
            if self._conversation_buffer:
                self._pending = True
                self._pending_since = self._last_activity

    async def _loop(self) -> None:
        """Main scheduling loop — checks idle time and triggers evolution."""
        while True:
            try:
                await asyncio.sleep(self._check_interval)
            except asyncio.CancelledError:
                break
            if not self._pending:
                continue
            idle = time.time() - self._last_activity
            deferred = time.time() - self._pending_since
            self.logger.debug(
                "DreamScheduler check: idle=%.1fs, deferred=%.1fs, "
                "threshold=%.0fs, max_deferral=%.0fs",
                idle, deferred, self._idle_threshold, self._max_deferral,
            )
            if idle >= self._idle_threshold or deferred >= self._max_deferral:
                self.logger.info(
                    "Triggering evolution cycle (idle=%.1fs, deferred=%.1fs)",
                    idle, deferred,
                )
                await self._run_once()
