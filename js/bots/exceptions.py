"""Fail-closed errors for the Bots orchestration layer."""

from __future__ import annotations


class BotsError(ValueError):
    """Base error for the Bots surface."""


class BotsIsolationError(BotsError):
    """Owner or product scope is missing or does not match the row."""


class BotsNotFoundError(BotsError):
    """The requested bot, room, or goal run is not visible in this scope."""


class BotsStateError(BotsError):
    """The object exists but the requested transition is refused."""


class BotsBudgetError(BotsError):
    """A GoalRun hit a hard budget stop."""
