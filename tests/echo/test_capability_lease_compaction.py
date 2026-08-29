"""LeaseAuthority snapshot compaction + local tip seal."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.echo.capability import LeaseAuthority, LeaseNonceReplay
from js.echo.ledger.tip_seal import TipSealError, load_seal, seal_path_for
from tests.echo.test_capability_lease import _TEST_KEY, _issue_default


def test_compact_then_issue_consume_revoke(tmp_path: Path) -> None:
    ledger_path = tmp_path / "echo_tool_lease.jsonl"
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)
    first = _issue_default(auth, run_id="run-1")
    auth.consume(first, now=0)
    snapshot_hash = auth.compact()
    assert snapshot_hash.startswith("sha256:")
    assert ledger_path.with_name(ledger_path.name + ".snapshot").is_file()
    seal = load_seal(seal_path_for(ledger_path), _TEST_KEY)
    assert seal is not None
    assert seal.lease_snapshot_hash == snapshot_hash

    restarted = LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)
    with pytest.raises(LeaseNonceReplay):
        restarted.consume(first, now=0)
    second = _issue_default(restarted, run_id="run-2")
    restarted.consume(second, now=0)
    restarted.revoke(second.lease_id)
    assert restarted.is_revoked(second.lease_id)

    again = LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)
    assert again.is_revoked(second.lease_id)
    assert first.lease_id in again.known_lease_ids()


def test_compact_snapshot_matches_full_replay(tmp_path: Path) -> None:
    ledger_path = tmp_path / "echo_tool_lease.jsonl"
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)
    first = _issue_default(auth, run_id="run-1")
    second = _issue_default(auth, run_id="run-2")
    auth.consume(first, now=0)
    full_ids = auth.known_lease_ids()
    auth.compact()
    compacted = LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)
    assert compacted.known_lease_ids() == full_ids
    assert compacted.is_revoked(first.lease_id) is False
    with pytest.raises(LeaseNonceReplay):
        compacted.consume(first, now=0)
    compacted.consume(second, now=0)


def test_maybe_compact_skips_below_threshold(tmp_path: Path) -> None:
    ledger_path = tmp_path / "echo_tool_lease.jsonl"
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)
    _issue_default(auth, run_id="run-1")
    assert auth.maybe_compact(trigger_records=10_000, trigger_bytes=10**9) is None
    assert auth.ledger_stats()["compact_skip_reason"] == "below_threshold"


def test_maybe_compact_runs_when_record_threshold_crossed(tmp_path: Path) -> None:
    ledger_path = tmp_path / "echo_tool_lease.jsonl"
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)
    _issue_default(auth, run_id="run-1")
    snapshot = auth.maybe_compact(trigger_records=1, trigger_bytes=10**9)
    assert snapshot is not None
    assert snapshot.startswith("sha256:")
    assert auth.ledger_stats()["compact_skip_reason"] == ""
    seal = load_seal(seal_path_for(ledger_path), _TEST_KEY)
    assert seal is not None
    assert seal.lease_snapshot_hash == snapshot


@pytest.mark.asyncio
async def test_governor_compacts_lease_ledger_on_hot_state(tmp_path: Path) -> None:
    from js.config import EchoLedgerConfig, JSSettings
    from js.runtime.governor import ResourceGovernor

    ledger_path = tmp_path / "echo_tool_lease.jsonl"
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)
    first = _issue_default(auth, run_id="run-1")
    auth.consume(first, now=0)
    for index in range(2, 9):
        _issue_default(auth, run_id=f"run-{index}")
    settings = JSSettings(
        workspace=tmp_path / "ws",
        state_dir=tmp_path / "st",
        echo_ledger=EchoLedgerConfig(
            lease_compact_trigger_records=8,
            lease_compact_trigger_bytes=10**9,
            lease_compact_trigger_full_reloads=99,
        ),
    )
    agent = type(
        "Agent",
        (),
        {
            "settings": settings,
            "_get_echo_tool_lease_authority": lambda self: auth,
        },
    )()
    governor = ResourceGovernor(agent, state_dir=tmp_path / "st")
    await governor._compact_lease_ledgers()
    assert (ledger_path.with_name(ledger_path.name + ".snapshot")).is_file()
    restarted = LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)
    with pytest.raises(LeaseNonceReplay):
        restarted.consume(first, now=0)


def test_rewind_journal_only_after_compact_is_rejected(tmp_path: Path) -> None:
    ledger_path = tmp_path / "echo_tool_lease.jsonl"
    auth = LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)
    _issue_default(auth, run_id="run-1")
    auth.compact()
    _issue_default(auth, run_id="run-2")
    ledger_path.write_text("", encoding="utf-8")
    with pytest.raises((TipSealError, ValueError)):
        LeaseAuthority(mac_key=_TEST_KEY, now_fn=lambda: 0, ledger_path=ledger_path)
