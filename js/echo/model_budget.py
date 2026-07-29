"""Live model-call budgets shared by Echo turns and background jobs."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Any

from js.echo.primitives import BudgetClock, BudgetLimits, BudgetSnapshot

MODEL_CALL_JOURNAL_RECORDS = 9


class EchoBudgetExceededError(RuntimeError):
    """Raised before Echo permits work that would exceed a hard budget."""


class EchoModelBudget:
    """One logical background job's provider and ledger budget."""

    def __init__(
        self,
        *,
        limits: BudgetLimits,
        estimate_prompt_tokens: Callable[
            [Sequence[Any], Sequence[dict[str, Any]] | None], int
        ],
        token_unit_id: str,
    ) -> None:
        if not isinstance(token_unit_id, str) or not token_unit_id:
            raise ValueError("token_unit_id must be a non-empty str")
        self._limits = limits
        self._clock = BudgetClock(limits)
        self._estimate_prompt_tokens = estimate_prompt_tokens
        self._token_unit_id = token_unit_id
        self._started_at = time.perf_counter()
        self._elapsed_reserved_ms = 0

    @property
    def token_unit_id(self) -> str:
        return self._token_unit_id

    def reserve_attempt(
        self,
        messages: Sequence[Any],
        tools: Sequence[dict[str, Any]] | None,
    ) -> BudgetSnapshot:
        return self._reserve(
            prompt_tokens=max(0, int(self._estimate_prompt_tokens(messages, tools))),
            journal_appends=MODEL_CALL_JOURNAL_RECORDS,
        )

    def reserve_completion(self, completion_tokens: int) -> BudgetSnapshot:
        return self._reserve(completion_tokens=max(0, int(completion_tokens)))

    def snapshot(self) -> BudgetSnapshot:
        return self._clock.snapshot()

    def remaining_completion_tokens(self) -> int:
        return max(
            0,
            self._limits.max_completion_tokens - self.snapshot().completion_tokens,
        )

    def _reserve(
        self,
        *,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        journal_appends: int = 0,
    ) -> BudgetSnapshot:
        elapsed_now = int((time.perf_counter() - self._started_at) * 1000)
        elapsed_delta = max(0, elapsed_now - self._elapsed_reserved_ms)
        reservation = self._clock.reserve(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            journal_appends=journal_appends,
            elapsed_ms=elapsed_delta,
        )
        if not reservation.ok:
            raise EchoBudgetExceededError(f"Echo budget exceeded: {reservation.reason}")
        self._elapsed_reserved_ms = elapsed_now
        return reservation.snapshot


__all__ = [
    "EchoBudgetExceededError",
    "EchoModelBudget",
    "MODEL_CALL_JOURNAL_RECORDS",
]
