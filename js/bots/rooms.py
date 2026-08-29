"""Room speech, mention detection, and untrusted transcript wrapping."""

from __future__ import annotations

import re
from collections.abc import Iterable

from js.bots.models import BotRecord, RoomMessage
from js.orin import taint as orin_taint
from js.security.untrusted import wrap_untrusted_for_model

_MENTION_RE = re.compile(r"@([^\s@]{1,64})")
NO_REPLY = "NO_REPLY"


def mentioned_tokens(text: str) -> tuple[str, ...]:
    found = [match.group(1).strip() for match in _MENTION_RE.finditer(text)]
    return tuple(token for token in found if token)


def mentioned_bots(text: str, bots: Iterable[BotRecord]) -> tuple[BotRecord, ...]:
    haystack = text.strip()
    if not haystack:
        return ()
    tokens = {token.lower() for token in mentioned_tokens(haystack)}
    matched: list[BotRecord] = []
    seen: set[str] = set()
    for bot in bots:
        if not bot.is_active() or bot.id in seen:
            continue
        name = bot.display_name
        slug = bot.slug
        named = name in haystack or slug in haystack
        at_named = name.lower() in tokens or slug.lower() in tokens
        if named or at_named:
            matched.append(bot)
            seen.add(bot.id)
    return tuple(matched)


def should_speak(
    *,
    addressed: bool,
    can_add_evidence: bool = False,
    can_correct: bool = False,
) -> bool:
    return bool(addressed or can_add_evidence or can_correct)


def wrap_room_transcript(messages: Iterable[RoomMessage]) -> str:
    lines: list[str] = []
    for message in messages:
        speaker = message.speaker_id or message.speaker_kind
        lines.append(f"{message.speaker_kind}:{speaker}: {message.content}")
    body = "\n".join(lines)
    if not body:
        return ""
    return wrap_untrusted_for_model(body)


def room_message_taint(*, peer: bool) -> int:
    bits = orin_taint.ROOM_SHARED | orin_taint.USER_TURN
    if peer:
        bits |= orin_taint.BOT_PEER
    return bits


__all__ = [
    "NO_REPLY",
    "mentioned_bots",
    "mentioned_tokens",
    "room_message_taint",
    "should_speak",
    "wrap_room_transcript",
]
