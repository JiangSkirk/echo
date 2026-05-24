"""Circuit breaker pattern for model provider resilience."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from js.utils.log import get_logger

logger = get_logger("js.circuit")


class CircuitState(StrEnum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject fast
    HALF_OPEN = "half_open"  # Testing if recovered


@dataclass
class CircuitBreaker:
    """Circuit breaker for external service calls."""

    name: str
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_calls: int = 3

    def __post_init__(self) -> None:
        self._state = CircuitState.CLOSED
        self._failures = 0
        self._successes = 0
        self._last_failure_time: float = 0.0
        self._half_open_calls = 0
        self._lock = asyncio.Lock()

    async def state(self) -> CircuitState:
        async with self._lock:
            if self._state == CircuitState.OPEN and time.time() - self._last_failure_time > self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
                logger.info(f"Circuit {self.name} entering HALF_OPEN")
            return self._state

    async def record_success(self) -> None:
        async with self._lock:
            # Trigger state transition if needed
            if self._state == CircuitState.OPEN and time.time() - self._last_failure_time > self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
            if self._state == CircuitState.HALF_OPEN:
                # Any success in HALF_OPEN closes the circuit immediately
                self._state = CircuitState.CLOSED
                self._failures = 0
                self._successes += 1
                logger.info(f"Circuit {self.name} CLOSED (recovered)")
            else:
                self._failures = max(0, self._failures - 1)
                self._successes += 1

    async def record_failure(self) -> None:
        async with self._lock:
            self._failures += 1
            self._last_failure_time = time.time()

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                logger.warning(f"Circuit {self.name} OPEN (recovery failed)")
            elif self._failures >= self.failure_threshold:
                self._state = CircuitState.OPEN
                logger.warning(f"Circuit {self.name} OPEN ({self._failures} failures)")

    async def can_execute(self) -> bool:
        async with self._lock:
            if self._state == CircuitState.OPEN and time.time() - self._last_failure_time > self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
            state = self._state
            if state == CircuitState.CLOSED:
                return True
            if state == CircuitState.HALF_OPEN:
                if self._half_open_calls < self.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                return False
            return False

    async def execute(self, coro: Any) -> Any:
        """Execute a coroutine with circuit breaker protection.

        Automatically handles success/failure recording and releases
        half-open slots on cancellation.
        """
        async with self._lock:
            if self._state == CircuitState.OPEN and time.time() - self._last_failure_time > self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
            state = self._state
            if state == CircuitState.CLOSED:
                pass
            elif state == CircuitState.HALF_OPEN:
                if self._half_open_calls < self.half_open_max_calls:
                    self._half_open_calls += 1
                else:
                    raise RuntimeError(f"Circuit breaker OPEN for {self.name}")
            else:
                raise RuntimeError(f"Circuit breaker OPEN for {self.name}")

        try:
            result = await coro
        except asyncio.CancelledError:
            async with self._lock:
                if self._state == CircuitState.HALF_OPEN and self._half_open_calls > 0:
                    self._half_open_calls -= 1
            raise
        except Exception:
            await self.record_failure()
            raise
        else:
            await self.record_success()
            return result

    async def get_stats(self) -> dict[str, Any]:
        async with self._lock:
            # Inline can_execute logic to avoid recursive lock deadlock
            can_exec = False
            if self._state == CircuitState.CLOSED or self._state == CircuitState.HALF_OPEN and self._half_open_calls < self.half_open_max_calls:
                can_exec = True
            return {
                "name": self.name,
                "state": self._state.value,
                "failures": self._failures,
                "last_failure": self._last_failure_time,
                "can_execute": can_exec,
            }
