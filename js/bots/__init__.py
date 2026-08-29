"""Bots surface orchestration. Echo remains the only turn runtime."""

from __future__ import annotations

from js.bots.exceptions import (
    BotsBudgetError,
    BotsError,
    BotsIsolationError,
    BotsNotFoundError,
    BotsStateError,
)
from js.bots.identity import compile_bot_identity, fleet_persona_block, soul_digest
from js.bots.models import BotRecord, GoalRun, RoomRecord
from js.bots.service import BotService
from js.bots.store import BotStore

__all__ = [
    "BotsBudgetError",
    "BotsError",
    "BotsIsolationError",
    "BotsNotFoundError",
    "BotsStateError",
    "BotRecord",
    "BotService",
    "BotStore",
    "GoalRun",
    "RoomRecord",
    "compile_bot_identity",
    "fleet_persona_block",
    "soul_digest",
]
