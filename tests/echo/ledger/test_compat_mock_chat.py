from __future__ import annotations

import pathlib

from js.echo.ledger.compat import run_mock_chat_turn
from js.echo.ledger.journal import verify_file


def test_mock_chat_turn_exercises_full_echo_ledger_path(tmp_path: pathlib.Path) -> None:
    journal_path = tmp_path / "chat.jsonl"

    result = run_mock_chat_turn(
        tenant_id="tenant-a",
        run_id="run-1",
        user_text="hello",
        journal_path=journal_path,
        journal_key=b"journal-key",
        permit_key=b"permit-key",
    )

    assert result.response_text == "mock:hello"
    assert result.record_types == (
        "intake",
        "decision",
        "policy_decision",
        "permit",
        "model_privacy_envelope",
        "outbox",
        "receipt",
        "merge",
    )
    assert verify_file(journal_path, mac_key=b"journal-key").ok
