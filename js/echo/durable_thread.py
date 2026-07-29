"""Cancellation-safe adapters for synchronous durable Echo service calls."""

from __future__ import annotations

import asyncio
import contextvars
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Literal


class EchoDurableExecutorBusyError(RuntimeError):
    """The bounded Echo durable lane cannot safely accept more work."""


class EchoDurableExecutorClosedError(RuntimeError):
    """The Echo durable executor has begun shutting down."""


@dataclass
class _ExecutorLane:
    executor: ThreadPoolExecutor
    max_pending: int
    pending: int = 0


@dataclass
class _FinishReservation:
    executor: EchoDurableExecutor
    state: Literal["reserved", "submitted", "released", "completed"] = "reserved"


@dataclass(frozen=True)
class DurableClaim[T]:
    """A claimed durable value carrying its reserved finish capacity."""

    value: T
    _reservation: _FinishReservation


class EchoDurableExecutor:
    """Bounded pools dedicated to claim and receipt persistence.

    Claim and finish work use separate lanes so a burst of new authorizations
    cannot consume the workers required to close already-issued claims.
    """

    def __init__(
        self,
        *,
        max_claim_pending: int = 64,
        max_finish_pending: int = 64,
        claim_workers: int = 4,
        finish_workers: int = 4,
        thread_name_prefix: str = "echo-durable",
    ) -> None:
        if max_claim_pending < 1 or max_finish_pending < 1:
            raise ValueError("durable pending limits must be positive")
        if claim_workers < 1 or finish_workers < 1:
            raise ValueError("durable worker counts must be positive")
        self._lock = threading.Lock()
        self._closed = False
        self._outstanding_claims = 0
        self._lanes = {
            "claim": _ExecutorLane(
                executor=ThreadPoolExecutor(
                    max_workers=min(claim_workers, max_claim_pending),
                    thread_name_prefix=f"{thread_name_prefix}-claim",
                ),
                max_pending=max_claim_pending,
            ),
            "finish": _ExecutorLane(
                executor=ThreadPoolExecutor(
                    max_workers=min(finish_workers, max_finish_pending),
                    thread_name_prefix=f"{thread_name_prefix}-finish",
                ),
                max_pending=max_finish_pending,
            ),
        }

    def submit_claim[T](
        self,
        call: Callable[[], T],
    ) -> tuple[asyncio.Future[T], _FinishReservation]:
        loop = asyncio.get_running_loop()
        context = contextvars.copy_context()
        with self._lock:
            if self._closed:
                raise EchoDurableExecutorClosedError("Echo durable executor is shut down")
            lane_state = self._lanes["claim"]
            if lane_state.pending >= lane_state.max_pending:
                raise EchoDurableExecutorBusyError("Echo durable claim lane is full")
            if self._outstanding_claims >= self._lanes["finish"].max_pending:
                raise EchoDurableExecutorBusyError("Echo durable finish capacity is full")
            lane_state.pending += 1
            self._outstanding_claims += 1
            reservation = _FinishReservation(executor=self)

            def invoke() -> T:
                try:
                    return context.run(call)
                finally:
                    self._release_pending("claim")

            try:
                return loop.run_in_executor(lane_state.executor, invoke), reservation
            except BaseException:
                lane_state.pending -= 1
                self._outstanding_claims -= 1
                reservation.state = "released"
                raise

    def submit_finish[T](
        self,
        call: Callable[[], T],
        *,
        reservation: _FinishReservation,
    ) -> asyncio.Future[T]:
        loop = asyncio.get_running_loop()
        context = contextvars.copy_context()
        with self._lock:
            if self._closed:
                raise EchoDurableExecutorClosedError("Echo durable executor is shut down")
            self._validate_reservation(reservation)
            lane_state = self._lanes["finish"]
            reservation.state = "submitted"
            lane_state.pending += 1

            def invoke() -> T:
                try:
                    return context.run(call)
                finally:
                    self._complete_finish(reservation)

            try:
                return loop.run_in_executor(lane_state.executor, invoke)
            except BaseException:
                lane_state.pending -= 1
                reservation.state = "reserved"
                raise

    def release_failed_claim(self, reservation: _FinishReservation) -> None:
        with self._lock:
            self._validate_reservation(reservation)
            reservation.state = "released"
            self._outstanding_claims -= 1

    def pending(self, lane: Literal["claim", "finish"] | None = None) -> int:
        with self._lock:
            if lane is not None:
                return self._lanes[lane].pending
            return sum(item.pending for item in self._lanes.values())

    @property
    def outstanding_claims(self) -> int:
        with self._lock:
            return self._outstanding_claims

    def shutdown(self, *, wait: bool) -> None:
        with self._lock:
            if self._closed:
                return
            if self._outstanding_claims:
                raise EchoDurableExecutorBusyError(
                    "Echo durable executor has outstanding claims"
                )
            self._closed = True
            executors = tuple(item.executor for item in self._lanes.values())
        for executor in executors:
            executor.shutdown(wait=wait, cancel_futures=False)

    def _release_pending(self, lane: Literal["claim", "finish"]) -> None:
        with self._lock:
            lane_state = self._lanes[lane]
            lane_state.pending -= 1

    def _complete_finish(self, reservation: _FinishReservation) -> None:
        with self._lock:
            if reservation.executor is not self or reservation.state != "submitted":
                raise RuntimeError("invalid Echo durable finish reservation state")
            self._lanes["finish"].pending -= 1
            self._outstanding_claims -= 1
            reservation.state = "completed"

    def _validate_reservation(self, reservation: _FinishReservation) -> None:
        if reservation.executor is not self or reservation.state != "reserved":
            raise RuntimeError("invalid Echo durable finish reservation")


async def durable_to_thread[T, ClaimT](
    call: Callable[[], T],
    *,
    claim: DurableClaim[ClaimT],
) -> T:
    """Run a durable synchronous call without abandoning it on cancellation."""
    task = claim._reservation.executor.submit_finish(
        call,
        reservation=claim._reservation,
    )
    cancellation = await _wait_for_task(task)
    result = task.result()
    if cancellation is not None:
        raise cancellation
    return result


async def claim_to_thread[T](
    claim: Callable[[], T],
    *,
    on_cancel: Callable[[T], None],
    executor: EchoDurableExecutor,
) -> DurableClaim[T]:
    """Claim in a thread and durably release a successful claim on cancellation."""
    task, reservation = executor.submit_claim(claim)
    cancellation = await _wait_for_task(task)
    try:
        value = task.result()
    except BaseException:
        executor.release_failed_claim(reservation)
        if cancellation is not None:
            raise cancellation from None
        raise
    if cancellation is None:
        return DurableClaim(value=value, _reservation=reservation)

    cleanup_task = executor.submit_finish(
        lambda: on_cancel(value),
        reservation=reservation,
    )
    await _wait_for_task(cleanup_task)
    cleanup_task.result()
    raise cancellation


async def _wait_for_task[T](task: asyncio.Future[T]) -> asyncio.CancelledError | None:
    """Wait for a shielded task, recording every caller cancellation until it ends."""
    cancellation: asyncio.CancelledError | None = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as exc:
            if cancellation is None:
                cancellation = exc
        except BaseException:
            # task.result() below retrieves and re-raises the actual failure.
            break
    return cancellation


__all__ = [
    "EchoDurableExecutor",
    "EchoDurableExecutorBusyError",
    "EchoDurableExecutorClosedError",
    "DurableClaim",
    "claim_to_thread",
    "durable_to_thread",
]
