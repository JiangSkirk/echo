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
    future: asyncio.Future[Any] | None = None


@dataclass
class Lane:
    """A single execution lane for one session."""

    session_id: str
    _queue: asyncio.Queue[LaneTask] = field(default_factory=asyncio.Queue)
    _task: asyncio.Task[Any] | None = None
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _parallel_semaphore: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(4))
    _active_future: asyncio.Future[Any] | None = None

    async def submit(self, task: LaneTask) -> Any:
        """Submit a task and await its completion."""
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()

        async def _wrapper() -> None:
            if future.done():
                return
            try:
                result = await task.coro()
                if not future.done():
                    future.set_result(result)
            except asyncio.CancelledError:
                if not future.done():
                    future.cancel()
                raise
            except BaseException as exc:
                if not future.done():
                    future.set_exception(exc)

        wrapped = LaneTask(
            id=task.id,
            coro=_wrapper,
            mode=task.mode,
            name=task.name,
            future=future,
        )

        def _cancel_active_worker(completed: asyncio.Future[Any]) -> None:
            worker = self._task
            if (
                completed.cancelled()
                and self._active_future is completed
                and worker is not None
                and not worker.done()
            ):
                worker.cancel()

        future.add_done_callback(_cancel_active_worker)
        await self._queue.put(wrapped)
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())
        return await future

    async def _run(self) -> None:
        """Lane worker: process tasks from the queue."""
        while not self._queue.empty():
            task = await self._queue.get()
            try:
                if task.future is not None and task.future.done():
                    continue
                self._active_future = task.future
                if task.mode == ExecutionMode.PARALLEL:
                    async with self._parallel_semaphore:
                        if task.future is not None and task.future.done():
                            continue
                        await task.coro()
                else:
                    async with self._lock:
                        if task.future is not None and task.future.done():
                            continue
                        await task.coro()
            except asyncio.CancelledError:
                # Cancelling an active Echo turn must not kill the per-session
                # worker and strand work that was already queued behind it.
                # The wrapped task's Future is cancelled by _wrapper above.
                logger.debug("Lane task %s cancelled; continuing queued work", task.id)
            except BaseException:
                logger.warning(f"Lane task {task.id} failed", exc_info=True)
            finally:
                if self._active_future is task.future:
                    self._active_future = None
                self._queue.task_done()

    async def drain(self) -> None:
        """Wait for all pending tasks to complete."""
        if self._task and not self._task.done():
            try:
                await asyncio.wait_for(self._task, timeout=30.0)
            except TimeoutError:
                logger.warning(f"Lane {self.session_id} drain timed out")

    def is_idle(self) -> bool:
        """Return whether the worker and queue retain no live work."""
        return self._queue.empty() and (self._task is None or self._task.done())


class LaneExecutor:
    """Manages multiple lanes (one per session)."""

    def __init__(self) -> None:
        self._lanes: dict[str, Lane] = {}
        self._lane_users: dict[str, int] = {}
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
        lane = await self._acquire_lane(session_id)
        try:
            return await lane.submit(LaneTask(id=task_id, coro=coro, mode=mode, name=name))
        finally:
            await self._release_lane(session_id, lane)

    async def _acquire_lane(self, session_id: str) -> Lane:
        """Reserve one lane user before the caller can enqueue work."""
        async with self._lock:
            lane = self._lanes.get(session_id)
            if lane is None:
                lane = Lane(session_id=session_id)
                self._lanes[session_id] = lane
            self._lane_users[session_id] = self._lane_users.get(session_id, 0) + 1
            return lane

    async def _release_lane(self, session_id: str, lane: Lane) -> None:
        """Remove an idle lane after its final reserved submitter finishes."""
        async with self._lock:
            users = self._lane_users.get(session_id, 0)
            if users > 1:
                self._lane_users[session_id] = users - 1
                return
            self._lane_users.pop(session_id, None)

        # Lane.submit resolves its Future just before the worker marks the
        # queue item done. Waiting here closes that small lifecycle gap. A new
        # submitter may reserve the same lane while drain runs; the guarded
        # check below then keeps it alive.
        await lane.drain()
        async with self._lock:
            if (
                self._lane_users.get(session_id, 0) == 0
                and self._lanes.get(session_id) is lane
                and lane.is_idle()
            ):
                self._lanes.pop(session_id, None)

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
        self._lane_users.pop(session_id, None)
