"""Local tip seal: rewind without touching the seal is fail-closed.

Replacing the journal and the seal together is out of scope — that would
be an external anchor, which this wave does not claim.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from js.echo.ledger.journal import FileEchoLedger
from js.echo.ledger.tip_seal import TipSealError, load_seal, seal_path_for


def _append(journal: FileEchoLedger, run_id: str) -> None:
    journal.append(
        record_type="intake",
        tenant_id="tenant",
        run_id=run_id,
        payload={"ok": True},
    )


def test_journal_rewind_without_seal_update_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "chat.jsonl"
    journal = FileEchoLedger(path, mac_key=b"journal-key-16bytes", local_tip_seal=True)
    _append(journal, "run-1")
    _append(journal, "run-2")
    original = path.read_bytes()
    assert load_seal(seal_path_for(path), b"journal-key-16bytes") is not None

    # Keep the first record only. Seal still names the later tip.
    first_line = original.splitlines(keepends=True)[0]
    path.write_bytes(first_line)

    with pytest.raises(TipSealError, match="rewind or fork"):
        FileEchoLedger(path, mac_key=b"journal-key-16bytes", local_tip_seal=True)


def test_journal_compact_bumps_counter_and_reloads(tmp_path: Path) -> None:
    path = tmp_path / "chat.jsonl"
    key = b"journal-key-16bytes"
    journal = FileEchoLedger(path, mac_key=key, local_tip_seal=True)
    for index in range(6):
        _append(journal, f"run-{index}")
    before = load_seal(seal_path_for(path), key)
    assert before is not None
    assert journal.compact(max_records=2) is True
    after = load_seal(seal_path_for(path), key)
    assert after is not None
    assert after.counter == before.counter + 1
    reloaded = FileEchoLedger(path, mac_key=key, local_tip_seal=True)
    assert reloaded.tip is not None
    assert reloaded.tip.record_hash == after.tip_hash
