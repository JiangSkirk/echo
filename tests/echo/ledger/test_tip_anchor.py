"""External tip-anchor v1: resist state_dir-only rewind."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.echo.capability import LeaseAuthority
from js.echo.ledger.tip_anchor import FileAnchorBackend, set_tip_anchor
from js.echo.ledger.tip_seal import TipSealError, bump_seal, load_seal, seal_path_for
from tests.echo.test_capability_lease import _TEST_KEY, _issue_default


@pytest.fixture
def file_anchor(tmp_path: Path) -> FileAnchorBackend:
    journal_dir = tmp_path / "state"
    journal_dir.mkdir()
    backend = FileAnchorBackend(tmp_path / "anchor.json", journal_dir=journal_dir)
    set_tip_anchor(backend)
    yield backend
    set_tip_anchor(None)


def test_file_anchor_rejects_journal_dir(tmp_path: Path) -> None:
    journal = tmp_path / "state"
    journal.mkdir()
    with pytest.raises(TipSealError, match="must not live under"):
        FileAnchorBackend(journal / "anchor.json", journal_dir=journal)


def test_rewind_journal_and_seal_is_rejected_by_anchor(
    tmp_path: Path, file_anchor: FileAnchorBackend
) -> None:
    del file_anchor
    journal_dir = tmp_path / "state"
    ledger_path = journal_dir / "echo_tool_lease.jsonl"
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)
    _issue_default(auth, run_id="run-1")
    auth.compact()
    _issue_default(auth, run_id="run-2")
    seal_path = seal_path_for(ledger_path)
    original_seal = seal_path.read_text(encoding="utf-8")
    original_ledger = ledger_path.read_text(encoding="utf-8")
    # Advance once more so the external counter moves forward.
    _issue_default(auth, run_id="run-3")
    ledger_path.write_text(original_ledger, encoding="utf-8")
    seal_path.write_text(original_seal, encoding="utf-8")
    with pytest.raises(TipSealError, match="external tip anchor"):
        LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)


def test_anchor_commit_is_monotonic(tmp_path: Path, file_anchor: FileAnchorBackend) -> None:
    path = tmp_path / "state" / "echo_tip_seal.json"
    first = bump_seal(path, _TEST_KEY, new_tip="sha256:" + "1" * 64)
    second = bump_seal(path, _TEST_KEY, new_tip="sha256:" + "2" * 64)
    assert second.counter > first.counter
    loaded = load_seal(path, _TEST_KEY)
    assert loaded is not None
    assert loaded.counter == second.counter
    record = file_anchor.read(str(path.resolve()))
    assert record is not None
    assert record.counter == second.counter
