"""Compatibility facade for ``js.gateway.channels.telegram``.

The Telegram Echo channel name remains ``telegram``.
"""

from __future__ import annotations

from js.gateway.channels.telegram import (
    _MAX_TELEGRAM_SESSIONS,
    _TELEGRAM_SESSION_TTL_SECONDS,
    TELEGRAM_ALLOWED_CHATS_ENV,
    TelegramBotIntegration,
)

__all__ = [
    "TELEGRAM_ALLOWED_CHATS_ENV",
    "TelegramBotIntegration",
    "_MAX_TELEGRAM_SESSIONS",
    "_TELEGRAM_SESSION_TTL_SECONDS",
]
