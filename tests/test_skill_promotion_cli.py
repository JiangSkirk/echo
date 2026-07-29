"""CLI tests for skill promotion gate controls."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from click.testing import CliRunner

from js.config import JSSettings
from js.skills.promotion_store import PromotionStore
from js.skills.spec import TrustLevel
from js.tools.registry import ToolResult
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
    mutate = AsyncMock(return_value={"success": True, "event_id": event_id})

    class FakeCLI:
        def __init__(self, _settings: JSSettings) -> None:
            self.agent = SimpleNamespace()

        async def init(self) -> None:
            return None

        async def _execute_private_skill_mutation(
            self,
            action: str,
            payload: dict[str, str],
        ) -> dict[str, object]:
            return await mutate(action, payload)

    monkeypatch.setattr("js.ui.cli.JSSettings.from_file", lambda _config=None: settings)
    monkeypatch.setattr("js.ui.cli.JSCLI", FakeCLI)

    result = CliRunner().invoke(
        main,
        ["skill", "promote", "reject", event_id, "--reason", "not ready"],
    )

    assert result.exit_code == 0, result.output
    assert "Rejected" in result.output
    event = store.get(event_id)
    assert event is not None
    assert event.status == "proposed"
    mutate.assert_awaited_once_with(
        "promotion_reject",
        {"event_id": event_id, "reason": "not ready"},
    )


def test_skill_promote_approve_calls_apply_proposal(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    _, event_id = _seed_event(settings)
    fake_skills = SimpleNamespace(
        apply_proposal=AsyncMock(side_effect=AssertionError("raw promotion bypass"))
    )
    mutate = AsyncMock(return_value={"success": True, "event_id": event_id})

    class FakeCLI:
        def __init__(self, _settings: JSSettings) -> None:
            self.agent = SimpleNamespace(skills=fake_skills)

        async def init(self) -> None:
            return None

        async def _execute_private_skill_mutation(
            self,
            action: str,
            payload: dict[str, str],
        ) -> dict[str, object]:
            return await mutate(action, payload)

    monkeypatch.setattr("js.ui.cli.JSSettings.from_file", lambda _config=None: settings)
    monkeypatch.setattr("js.ui.cli.JSCLI", FakeCLI)

    result = CliRunner().invoke(main, ["skill", "promote", "approve", event_id])

    assert result.exit_code == 0, result.output
    assert "Approved" in result.output
    fake_skills.apply_proposal.assert_not_awaited()
    mutate.assert_awaited_once_with("promotion_approve", {"event_id": event_id})


def test_skill_promote_revert_calls_revert_promotion(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    _, event_id = _seed_event(settings)
    fake_skills = SimpleNamespace(
        revert_promotion=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("raw promotion bypass")
        )
    )
    mutate = AsyncMock(
        return_value={
            "success": True,
            "event_id": event_id,
            "trust_reverted": True,
        }
    )

    class FakeCLI:
        def __init__(self, _settings: JSSettings) -> None:
            self.agent = SimpleNamespace(skills=fake_skills)

        async def init(self) -> None:
            return None

        async def _execute_private_skill_mutation(
            self,
            action: str,
            payload: dict[str, str],
        ) -> dict[str, object]:
            return await mutate(action, payload)

    monkeypatch.setattr("js.ui.cli.JSSettings.from_file", lambda _config=None: settings)
    monkeypatch.setattr("js.ui.cli.JSCLI", FakeCLI)

    result = CliRunner().invoke(main, ["skill", "promote", "revert", event_id])

    assert result.exit_code == 0, result.output
    assert "Reverted" in result.output
    mutate.assert_awaited_once_with("promotion_revert", {"event_id": event_id})


def test_skill_promote_help_lists_all_subcommands() -> None:
    """Smoke check that `js skill promote --help` enumerates the 5 subcommands.

    Guards against accidental decorator removal — if any one of list/show/
    approve/reject/revert disappears from the click group, the help output
    stops listing it and this assertion catches it before release.
    """
    result = CliRunner().invoke(main, ["skill", "promote", "--help"])
    assert result.exit_code == 0, result.output
    for sub in ("list", "show", "approve", "reject", "revert"):
        assert sub in result.output, f"missing subcommand `{sub}` in help"


def test_skill_install_cli_uses_echo_control_effect(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    raw_install = AsyncMock(side_effect=AssertionError("raw skill install bypass"))
    control = AsyncMock(
        return_value=ToolResult(
            success=True,
            output="installed",
            metadata={"skill_id": "synthetic-skill", "trust_level": "community"},
        )
    )

    class FakeCLI:
        def __init__(self, _settings: JSSettings) -> None:
            self.agent = SimpleNamespace(skills=SimpleNamespace(install=raw_install))

        async def init(self) -> None:
            return None

        async def _execute_control_effect(
            self,
            tool_name: str,
            arguments: dict[str, object],
            *,
            user_input: str,
        ) -> ToolResult:
            return await control(
                tool_name,
                arguments,
                user_input=user_input,
            )

    monkeypatch.setattr("js.ui.cli.JSSettings.from_file", lambda _config=None: settings)
    monkeypatch.setattr("js.ui.cli.JSCLI", FakeCLI)

    result = CliRunner().invoke(
        main,
        ["skill", "install", "https://github.com/example/synthetic-skill.git"],
    )

    assert result.exit_code == 0, result.output
    assert "Installed skill: synthetic-skill" in result.output
    raw_install.assert_not_awaited()
    control.assert_awaited_once()
    call = control.await_args
    assert call.args[:2] == (
        "control_skill_install",
        {
            "source": "https://github.com/example/synthetic-skill.git",
            "skill_id": None,
        },
    )


def test_skill_uninstall_cli_uses_private_echo_mutation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    settings = _settings(tmp_path)
    raw_uninstall = AsyncMock(side_effect=AssertionError("raw uninstall bypass"))
    mutate = AsyncMock(return_value={"success": True})

    class FakeCLI:
        def __init__(self, _settings: JSSettings) -> None:
            self.agent = SimpleNamespace(skills=SimpleNamespace(uninstall=raw_uninstall))

        async def init(self) -> None:
            return None

        async def _execute_private_skill_mutation(
            self,
            action: str,
            payload: dict[str, str],
        ) -> dict[str, object]:
            return await mutate(action, payload)

    monkeypatch.setattr("js.ui.cli.JSSettings.from_file", lambda _config=None: settings)
    monkeypatch.setattr("js.ui.cli.JSCLI", FakeCLI)

    result = CliRunner().invoke(
        main,
        ["skill", "uninstall", "synthetic-skill", "--yes"],
    )

    assert result.exit_code == 0, result.output
    assert "Uninstalled skill: synthetic-skill" in result.output
    raw_uninstall.assert_not_awaited()
    mutate.assert_awaited_once_with("uninstall", {"skill_id": "synthetic-skill"})


def test_skill_trust_cli_uses_private_echo_mutation(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    raw_trust = MagicMock(side_effect=AssertionError("raw trust bypass"))
    mutate = AsyncMock(
        return_value={
            "success": True,
            "skill_id": "synthetic-skill",
            "trust_level": "trusted",
        }
    )

    class FakeCLI:
        def __init__(self, _settings: JSSettings) -> None:
            self.agent = SimpleNamespace(skills=SimpleNamespace(trust_skill=raw_trust))

        async def init(self) -> None:
            return None

        async def _execute_private_skill_mutation(
            self,
            action: str,
            payload: dict[str, str],
        ) -> dict[str, object]:
            return await mutate(action, payload)

    monkeypatch.setattr("js.ui.cli.JSSettings.from_file", lambda _config=None: settings)
    monkeypatch.setattr("js.ui.cli.JSCLI", FakeCLI)

    result = CliRunner().invoke(
        main,
        ["skill", "trust", "synthetic-skill", "trusted"],
    )

    assert result.exit_code == 0, result.output
    assert "Trust level for synthetic-skill set to trusted" in result.output
    raw_trust.assert_not_called()
    mutate.assert_awaited_once_with(
        "trust",
        {"skill_id": "synthetic-skill", "level": "trusted"},
    )


def test_skill_discover_cli_uses_echo_network_effect(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    control = AsyncMock(
        return_value=ToolResult(
            success=True,
            output="discovered",
            metadata={
                "total": 1,
                "results": [
                    {
                        "id": "synthetic-skill",
                        "name": "Synthetic Skill",
                        "description": "Synthetic fixture",
                        "version": "1.0.0",
                        "author": "fixture",
                    }
                ],
            },
        )
    )

    class FakeCLI:
        def __init__(self, _settings: JSSettings) -> None:
            self.agent = SimpleNamespace()

        async def init(self) -> None:
            return None

        async def _execute_control_effect(
            self,
            tool_name: str,
            arguments: dict[str, object],
            *,
            user_input: str,
        ) -> ToolResult:
            return await control(
                tool_name,
                arguments,
                user_input=user_input,
            )

    monkeypatch.setattr("js.ui.cli.JSSettings.from_file", lambda _config=None: settings)
    monkeypatch.setattr("js.ui.cli.JSCLI", FakeCLI)
    monkeypatch.setattr(
        "js.skills.clawhub.ClawHubClient",
        MagicMock(side_effect=AssertionError("raw ClawHub network bypass")),
    )

    result = CliRunner().invoke(main, ["skill", "discover", "synthetic"])

    assert result.exit_code == 0, result.output
    assert "synthetic-skill" in result.output
    control.assert_awaited_once()
    assert control.await_args.args[:2] == (
        "control_clawhub_discover",
        {"query": "synthetic"},
    )


def test_skill_discover_install_cli_uses_echo_control_effect(
    tmp_path: Path,
    monkeypatch,
) -> None:
    settings = _settings(tmp_path)
    control = AsyncMock(
        return_value=ToolResult(
            success=True,
            output="installed",
            metadata={"skill_id": "synthetic-skill", "trust_level": "community"},
        )
    )

    class FakeCLI:
        def __init__(self, _settings: JSSettings) -> None:
            self.agent = SimpleNamespace()

        async def init(self) -> None:
            return None

        async def _execute_control_effect(
            self,
            tool_name: str,
            arguments: dict[str, object],
            *,
            user_input: str,
        ) -> ToolResult:
            return await control(
                tool_name,
                arguments,
                user_input=user_input,
            )

    monkeypatch.setattr("js.ui.cli.JSSettings.from_file", lambda _config=None: settings)
    monkeypatch.setattr("js.ui.cli.JSCLI", FakeCLI)
    monkeypatch.setattr(
        "js.skills.clawhub.ClawHubClient",
        MagicMock(side_effect=AssertionError("raw ClawHub install bypass")),
    )

    result = CliRunner().invoke(
        main,
        ["skill", "discover", "--install", "synthetic-skill"],
    )

    assert result.exit_code == 0, result.output
    assert "Installed synthetic-skill from ClawHub" in result.output
    assert control.await_args.args[:2] == (
        "control_clawhub_install",
        {"skill_id": "synthetic-skill"},
    )
