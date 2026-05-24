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
        self._conversation_buffer: list[dict[str, str]] = []
        self._max_buffer = 5
        self.logger = get_logger("js.memory.scheduler")

    def notify_activity(self, user_input: str, assistant_output: str) -> None:
        """Call after each user interaction to mark pending and record conversation."""
        self._last_activity = time.time()
        if not self._pending:
            self._pending = True
            self._pending_since = time.time()
        self._conversation_buffer.append({
            "user": user_input[:500],
            "assistant": assistant_output[:500],
        })
        if len(self._conversation_buffer) > self._max_buffer:
            self._conversation_buffer.pop(0)

    def start(self) -> None:
        """Start the background scheduling loop."""
        if self._task and not self._task.done():
            self._task.cancel()
        self._task = asyncio.create_task(self._loop())
        self._task.add_done_callback(
            lambda t: t.exception() if t.done() and not t.cancelled() else None
        )

    def stop(self) -> None:
        """Stop the background scheduling loop."""
        if self._task and not self._task.done():
            self._task.cancel()

    async def force_consolidation(self) -> None:
        """Immediately run an evolution cycle, bypassing idle wait.

        Used by the daemon's cron dream task and manual triggers.
        """
        self._last_activity = 0.0  # Pretend we've been idle forever
        self._pending = True
        self._pending_since = 0.0
        # Wait up to 2 check intervals for the loop to pick it up
        for _ in range(2):
            await asyncio.sleep(self._check_interval)
            if not self._pending:
                break

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
                f"DreamScheduler check: idle={idle:.1f}s, deferred={deferred:.1f}s, "
                f"threshold={self._idle_threshold:.0f}s, max_deferral={self._max_deferral:.0f}s"
            )
            if idle >= self._idle_threshold or deferred >= self._max_deferral:
                self.logger.info(
                    f"Triggering evolution cycle (idle={idle:.1f}s, deferred={deferred:.1f}s)"
                )
                buffer_copy = list(self._conversation_buffer)
                try:
                    await self.agent._run_evolution_cycle(
                        conversation_buffer=buffer_copy
                    )
                except asyncio.CancelledError:
                    self._pending = False
                    self._conversation_buffer.clear()
                    raise
                except Exception as e:
                    self.logger.warning(f"Evolution cycle failed: {e}", exc_info=True)
                self._pending = False
                # Remove only entries that were in the copy (race-safe)
                self._conversation_buffer = self._conversation_buffer[len(buffer_copy):]
