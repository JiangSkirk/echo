"""Patrol detectors: warmup, tighten-only, independent record-only switch."""

from __future__ import annotations

from js.orind.patrol import WARMUP_EVENTS, PatrolBoard


def test_warmup_emits_nothing() -> None:
    board = PatrolBoard()
    for index in range(WARMUP_EVENTS):
        advice = board.observe(
            session_id="s",
            now_ms=index * 10,
            host=f"h{index}.example",
            payload="x" * 80,
        )
        assert advice == []


def test_record_only_never_tightens() -> None:
    board = PatrolBoard(record_only=True)
    for index in range(WARMUP_EVENTS + 8):
        advice = board.observe(
            session_id="s",
            now_ms=index,
            host=f"unique-{index}.example.test",
            payload="A" * 200,
            failed=True,
        )
        assert advice == []


def test_detectors_can_advise_after_warmup() -> None:
    board = PatrolBoard()
    for index in range(WARMUP_EVENTS):
        board.observe(session_id="s", now_ms=index, host=f"h{index}.example.test")
    advice = board.observe(session_id="s", now_ms=1_000, host="extra.example.test")
    assert "egress_diversity" in advice
