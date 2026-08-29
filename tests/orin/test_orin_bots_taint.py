"""Bots taint bits 13–15 only tighten. They never authorize."""

from __future__ import annotations

from js.orin import taint as t
from js.orind.policy import VERDICT_APPROVAL, evaluate


def test_reserved_bits_are_named_and_tighten_writes() -> None:
    assert t.BOT_PEER == 1 << 13
    assert t.BOT_SOUL == 1 << 14
    assert t.ROOM_SHARED == 1 << 15
    assert t.RESERVED_MASK == t.BOT_PEER | t.BOT_SOUL | t.ROOM_SHARED
    assert "BOT_PEER" in t.describe(t.BOT_PEER)
    assert t.BOT_PEER & t.DIRTY_FOR_WRITE
    decision = evaluate(
        tool_name="file_write",
        context_taint=t.BOT_PEER | t.ROOM_SHARED,
        arg_taint_bits=t.BOT_PEER,
        profile="conservative",
    )
    assert decision.verdict == VERDICT_APPROVAL


def test_clean_taint_does_not_skip_policy() -> None:
    decision = evaluate(
        tool_name="shell",
        context_taint=0,
        arg_taint_bits=0,
        args_overlap_dirty=False,
        profile="conservative",
    )
    assert decision.verdict == VERDICT_APPROVAL


def test_secret_stays_sticky_through_compression() -> None:
    original = t.BOT_PEER | t.ROOM_SHARED | t.SECRET
    summary = t.compressed_summary_taint(original)
    assert summary & t.SECRET
    assert summary & t.MODEL_OUTPUT
    assert summary & t.COMPRESSED
    assert t.clearance_of(summary) == t.CLEARANCE_SECRET


def test_source_taint_for_bots_ask_is_peer_and_shared() -> None:
    bits = t.source_taint_for_tool("bots_ask")
    assert bits & t.TOOL_RESULT
    assert bits & t.BOT_PEER
    assert bits & t.ROOM_SHARED
    assert not bits & t.USER_TURN
