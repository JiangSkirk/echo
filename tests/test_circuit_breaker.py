"""Tests for circuit breaker pattern."""

from __future__ import annotations

import asyncio

import pytest

from js.models.circuit_breaker import CircuitBreaker, CircuitState


class TestCircuitBreakerStateTransitions:
    async def test_starts_closed(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=3, recovery_timeout=0.1)
        assert await cb.state() == CircuitState.CLOSED
        assert await cb.can_execute() is True

    async def test_opens_after_failures(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=10.0)
        await cb.record_failure()
        assert await cb.state() == CircuitState.CLOSED
        await cb.record_failure()
        assert await cb.state() == CircuitState.OPEN
        assert await cb.can_execute() is False

    async def test_half_open_after_timeout(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.05)
        await cb.record_failure()
        assert await cb.state() == CircuitState.OPEN
        await asyncio.sleep(0.1)
        assert await cb.state() == CircuitState.HALF_OPEN
        assert await cb.can_execute() is True

    async def test_closes_after_half_open_success(self) -> None:
        # Any success in HALF_OPEN immediately closes the circuit
        cb = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.05, half_open_max_calls=2)
        await cb.record_failure()
        await asyncio.sleep(0.1)
        assert await cb.state() == CircuitState.HALF_OPEN
        await cb.record_success()
        assert await cb.state() == CircuitState.CLOSED

    async def test_returns_to_open_on_half_open_failure(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.05)
        await cb.record_failure()
        await asyncio.sleep(0.1)
        assert await cb.state() == CircuitState.HALF_OPEN
        await cb.record_failure()
        assert await cb.state() == CircuitState.OPEN

    async def test_half_open_limits_calls(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.05, half_open_max_calls=1)
        await cb.record_failure()
        await asyncio.sleep(0.1)
        # First call consumes the half-open slot
        assert await cb.can_execute() is True
        # Second call should fail because slot is consumed
        assert await cb.can_execute() is False


class TestCircuitBreakerExecute:
    async def test_execute_success(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=3)
        result = await cb.execute(asyncio.sleep(0))
        assert result is None
        assert await cb.state() == CircuitState.CLOSED

    async def test_execute_failure_opens_circuit(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=1)

        async def _fail() -> None:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            await cb.execute(_fail())
        assert await cb.state() == CircuitState.OPEN

    async def test_execute_rejects_when_open(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=10.0)
        await cb.record_failure()
        assert await cb.state() == CircuitState.OPEN

        # Use an already-resolved Future so no unawaited coroutine warning
        future: asyncio.Future[None] = asyncio.Future()
        future.set_result(None)

        with pytest.raises(RuntimeError, match="Circuit breaker OPEN"):
            await cb.execute(future)

    async def test_execute_cancellation_releases_half_open_slot(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.05, half_open_max_calls=1)
        await cb.record_failure()
        await asyncio.sleep(0.1)

        async def _cancelled() -> None:
            raise asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            await cb.execute(_cancelled())

        # Slot should be released after cancellation
        assert await cb.can_execute() is True


class TestCircuitBreakerStats:
    async def test_get_stats(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=3)
        stats = await cb.get_stats()
        assert stats["name"] == "test"
        assert stats["state"] == "closed"
        assert stats["failures"] == 0
        assert stats["can_execute"] is True

    async def test_get_stats_when_open(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=1)
        await cb.record_failure()
        stats = await cb.get_stats()
        assert stats["state"] == "open"
        assert stats["failures"] == 1
        assert stats["can_execute"] is False
