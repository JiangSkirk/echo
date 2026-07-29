"""M4: journal recovery UX — backup, readonly inspect, quarantine; no auto-repair."""

from __future__ import annotations

from pathlib import Path

import pytest  # noqa: TC002


def _state_with_missing_outbox_seal(tmp_path: Path) -> Path:
    from js.echo.ledger.service import EchoSafetyService

    state_dir = tmp_path / "state"
    state_dir.mkdir()
    service = EchoSafetyService(state_dir=state_dir)
    journal = service._default_state.journal
    journal.append(
        record_type="outbox",
        tenant_id="tenant-synthetic",
        run_id="run-synthetic",
        payload={
            "outbox_id": "outbox-synthetic-1",
            "effect_id": "effect-synthetic-1",
            # intentionally omit seal
        },
    )
    return state_dir


def test_inspect_detects_missing_outbox_seal_without_mutating(tmp_path: Path) -> None:
    from js.echo.ledger.journal_recovery import inspect_journal_readonly, ledger_root_for_state

    state_dir = _state_with_missing_outbox_seal(tmp_path)
    root = ledger_root_for_state(state_dir)
    before = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
    before_bytes = {rel: (root / rel).read_bytes() for rel in before}

    report = inspect_journal_readonly(state_dir)

    after = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
    assert after == before
    assert all((root / rel).read_bytes() == before_bytes[rel] for rel in before)
    assert report.ok is False
    assert report.error is not None
    assert "outbox seal is missing" in report.error
    assert any(
        "manual review" in opt.lower() or "quarantine" in opt.lower() for opt in report.options
    )
    assert any("automatic repair" in note.lower() for note in report.notes)


def test_prepare_recovery_backs_up_then_optionally_quarantines(tmp_path: Path) -> None:
    from js.echo.ledger.journal_recovery import (
        ledger_root_for_state,
        prepare_recovery,
    )

    state_dir = _state_with_missing_outbox_seal(tmp_path)
    backup_parent = tmp_path / "backups"
    report = prepare_recovery(
        state_dir,
        backup=True,
        quarantine=False,
        backup_parent=backup_parent,
    )
    assert report.backup_path is not None
    assert Path(report.backup_path).is_dir()
    assert ledger_root_for_state(state_dir).exists()
    assert report.ok is False

    report2 = prepare_recovery(
        state_dir,
        backup=True,
        quarantine=True,
        backup_parent=backup_parent,
        quarantine_parent=tmp_path / "quarantine",
    )
    assert report2.quarantine_path is not None
    assert Path(report2.quarantine_path).is_dir()
    assert not ledger_root_for_state(state_dir).exists()


def test_js_status_reports_recovery_options_when_journal_broken(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from js.ui import cli as cli_mod

    state_dir = _state_with_missing_outbox_seal(tmp_path)
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        "\n".join(
            [
                f"workspace: {tmp_path / 'ws'}",
                f"state_dir: {state_dir}",
                'echo_engine: "on"',
                "first_run_completed: true",
                "providers: []",
                "models: []",
                "security:",
                "  api_key_required: false",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "ws").mkdir()

    # status must not crash; it should print recovery guidance
    cli_mod.run_status(config=str(cfg), backup_journal=False)
    out = capsys.readouterr().out
    assert "Echo journal recovery" in out or "outbox seal is missing" in out
    assert "quarantine" in out.lower() or "manual" in out.lower()
