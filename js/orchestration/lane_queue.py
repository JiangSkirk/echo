"""Lane Queue: serial-by-default execution to prevent race conditions.

Inspired by OpenClaw's Lane Queue pattern:
- Each session gets its own lane
- Serial execution by default (prevents race conditions)
- Parallel only for explicitly marked safe tasks
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from js.utils.log import get_logger

logger = get_logger("js.orchestration.lane_queue")


class ExecutionMode(StrEnum):
    SERIAL = "serial"
    PARALLEL = "parallel"


@dataclass
class LaneTask:
    """A task scheduled on a lane."""

    id: str
    coro: Callable[[], Awaitable[Any]]
    mode: ExecutionMode = ExecutionMode.SERIAL
    name: str = ""


@dataclass
class Lane:
    """A single execution lane for one session."""

    session_id: str
    _queue: asyncio.Queue[LaneTask] = field(default_factory=asyncio.Queue)
    _task: asyncio.Task[Any] | None = None
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _parallel_semaphore: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(4))

    async def submit(self, task: LaneTask) -> Any:
        """Submit a task and await its completion."""
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()

        async def _wrapper() -> None:
            try:
                result = await task.coro()
                future.set_result(result)
            except Exception as e:
                future.set_exception(e)

        wrapped = LaneTask(
            id=task.id,
            coro=_wrapper,
            mode=task.mode,
            name=task.name,
        )
        await self._queue.put(wrapped)
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())
        return await future

    async def _run(self) -> None:
        """Lane worker: process tasks from the queue."""
        while not self._queue.empty():
            task = await self._queue.get()
            try:
                if task.mode == ExecutionMode.PARALLEL:
                    async with self._parallel_semaphore:
                        await task.coro()
                else:
                    async with self._lock:
                        await task.coro()
            except Exception:
                logger.warning(f"Lane task {task.id} failed", exc_info=True)
            finally:
                self._queue.task_done()

    async def drain(self) -> None:
        """Wait for all pending tasks to complete."""
        if self._task and not self._task.done():
            try:
                await asyncio.wait_for(self._task, timeout=30.0)
            except TimeoutError:
                logger.warning(f"Lane {self.session_id} drain timed out")


class LaneExecutor:
    """Manages multiple lanes (one per session)."""

    def __init__(self) -> None:
        self._lanes: dict[str, Lane] = {}
        self._lock = asyncio.Lock()

    async def get_or_create_lane(self, session_id: str) -> Lane:
        async with self._lock:
            if session_id not in self._lanes:
                self._lanes[session_id] = Lane(session_id=session_id)
            return self._lanes[session_id]

    async def submit(
        self,
        session_id: str,
        coro: Callable[[], Awaitable[Any]],
        task_id: str,
        mode: ExecutionMode = ExecutionMode.SERIAL,
        name: str = "",
    ) -> Any:
        """Submit a coroutine to a session's lane."""
        lane = await self.get_or_create_lane(session_id)
        return await lane.submit(LaneTask(id=task_id, coro=coro, mode=mode, name=name))

    async def drain_session(self, session_id: str) -> None:
        """Drain a specific session's lane."""
        lane = self._lanes.get(session_id)
        if lane:
            await lane.drain()

    async def drain_all(self) -> None:
        """Drain all lanes (used during graceful shutdown)."""
        await asyncio.gather(*[lane.drain() for lane in self._lanes.values()], return_exceptions=True)

    def remove_lane(self, session_id: str) -> None:
        """Remove a lane (e.g., after session ends)."""
        self._lanes.pop(session_id, None)
