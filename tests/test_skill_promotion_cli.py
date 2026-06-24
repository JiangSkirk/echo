"""CLI tests for skill promotion gate controls."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from click.testing import CliRunner

from js.config import JSSettings
from js.skills.promotion_store import PromotionStore
from js.skills.spec import TrustLevel
from js.ui.cli import main


def _settings(tmp_path: Path) -> JSSettings:
    return JSSettings(state_dir=tmp_path / "state", workspace=tmp_path / "workspace")


def _seed_event(settings: JSSettings, *, skill_id: str = "skill-one") -> tuple[PromotionStore, str]:
    store = PromotionStore(settings.state_dir / "skill_promotions.db")
    event_id = store.propose(
        skill_id,
        TrustLevel.COMMUNITY.value,
        TrustLevel.TRUSTED.value,
        "auto_curator",
        "20 runs / 95% success",
    )
    return store, event_id


def test_skill_promote_list_shows_open_events(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    store, event_id = _seed_event(settings)
    applied_id = store.record_operator_apply(
        "already-applied",
        TrustLevel.COMMUNITY.value,
        TrustLevel.TRUSTED.value,
        decided_by="test",
    )
    monkeypatch.setattr("js.ui.cli.JSSettings.from_file", lambda _config=None: settings)

    result = CliRunner().invoke(main, ["skill", "promote", "list"])

    assert result.exit_code == 0, result.output
    assert event_id in result.output
    assert "skill-one" in result.output
    assert "proposed" in result.output
    assert applied_id not in result.output


def test_skill_promote_show_displays_event_details(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    _, event_id = _seed_event(settings)
    monkeypatch.setattr("js.ui.cli.JSSettings.from_file", lambda _config=None: settings)

    result = CliRunner().invoke(main, ["skill", "promote", "show", event_id])

    assert result.exit_code == 0, result.output
    assert event_id in result.output
    assert "skill-one" in result.output
    assert "auto_curator" in result.output
    assert "20 runs / 95% success" in result.output


def test_skill_promote_reject_marks_event_rejected(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    store, event_id = _seed_event(settings)
    monkeypatch.setattr("js.ui.cli.JSSettings.from_file", lambda _config=None: settings)

    result = CliRunner().invoke(
        main,
        ["skill", "promote", "reject", event_id, "--reason", "not ready"],
    )

    assert result.exit_code == 0, result.output
    assert "Rejected" in result.output
    event = store.get(event_id)
    assert event is not None
    assert event.status == "rejected"
    assert "not ready" in event.reason


def test_skill_promote_approve_calls_apply_proposal(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    _, event_id = _seed_event(settings)
    fake_skills = SimpleNamespace(
        apply_proposal=AsyncMock(return_value={"success": True, "event_id": event_id})
    )

    class FakeCLI:
        def __init__(self, _settings: JSSettings) -> None:
            self.agent = SimpleNamespace(skills=fake_skills)

        async def init(self) -> None:
            return None

    monkeypatch.setattr("js.ui.cli.JSSettings.from_file", lambda _config=None: settings)
    monkeypatch.setattr("js.ui.cli.JSCLI", FakeCLI)

    result = CliRunner().invoke(main, ["skill", "promote", "approve", event_id])

    assert result.exit_code == 0, result.output
    assert "Approved" in result.output
    fake_skills.apply_proposal.assert_awaited_once_with(event_id, decided_by="cli")


def test_skill_promote_revert_calls_revert_promotion(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    _, event_id = _seed_event(settings)
    fake_skills = SimpleNamespace(
        revert_promotion=lambda eid, *, decided_by: {
            "success": True,
            "event_id": eid,
            "trust_reverted": True,
        }
    )

    class FakeCLI:
        def __init__(self, _settings: JSSettings) -> None:
            self.agent = SimpleNamespace(skills=fake_skills)

        async def init(self) -> None:
            return None

    monkeypatch.setattr("js.ui.cli.JSSettings.from_file", lambda _config=None: settings)
    monkeypatch.setattr("js.ui.cli.JSCLI", FakeCLI)

    result = CliRunner().invoke(main, ["skill", "promote", "revert", event_id])

    assert result.exit_code == 0, result.output
    assert "Reverted" in result.output
