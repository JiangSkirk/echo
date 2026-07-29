"""Regression coverage: CLI routine draft/approve must go through Echo.

Every routine-control entry point must route through
``echo_runtime.execute_tool_effect`` so the ledger records the authorization.
In particular, the interactive ``/routine approve`` command must not call
``WorkRoutineStore.approve`` directly and silently enable a routine without an
Echo receipt.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner

from js.tools.registry import ToolResult
from js_work.cli import WORK_OWNER_KEY_HASH, WorkCLI
from js_work.cli import main as work_main
from js_work.routines import WorkRoutineStore
from js_work.routines.models import RoutineStatus


def _interactive_routine_store(cli: WorkCLI) -> WorkRoutineStore:
    return WorkRoutineStore(
        cli.settings.state_dir,
        owner_key_hash=WORK_OWNER_KEY_HASH,
        session_id="work-routine-cli",
    )


def _create_interactive_draft(store: WorkRoutineStore, routine_id: str) -> None:
    store.create_draft(
        routine_id=routine_id,
        name="interactive approval regression",
        trigger_phrases=["approve interactive routine"],
        routine_type="spreadsheet_template",
    )


def test_cli_routine_draft_goes_through_echo(tmp_path: Path) -> None:
    runner = CliRunner()
    captured: dict[str, str] = {}

    async def _capture_execute(*, settings: object, tool_name: str, arguments: object) -> object:
        captured["tool_name"] = tool_name
        from js.tools.registry import ToolResult

        return ToolResult(
            success=True,
            output="",
            metadata={"routine": {"routine_id": "r-test", "name": "test", "status": "draft"}},
        )

    import js_work.cli as cli_module

    with patch.object(
        cli_module, "_execute_routine_control_effect", new=_capture_execute
    ):
        result = runner.invoke(
            work_main,
            [
                "--home",
                str(tmp_path),
                "routine",
                "draft",
                "--name",
                "test",
                "--trigger",
                "test",
                "--mapping",
                '{"a": "b"}',
            ],
        )

    assert result.exit_code == 0, f"CLI failed: {result.output}"
    assert captured.get("tool_name") == "control_work_routine_draft", (
        f"draft did not go through Echo: {captured}"
    )


def test_cli_routine_approve_goes_through_echo(tmp_path: Path) -> None:
    runner = CliRunner()
    captured: dict[str, str] = {}

    async def _capture_execute(*, settings: object, tool_name: str, arguments: object) -> object:
        captured["tool_name"] = tool_name
        from js.tools.registry import ToolResult

        return ToolResult(
            success=True,
            output="",
            metadata={"routine": {"routine_id": "r-test", "status": "enabled"}},
        )

    import js_work.cli as cli_module

    with patch.object(
        cli_module, "_execute_routine_control_effect", new=_capture_execute
    ):
        result = runner.invoke(
            work_main,
            [
                "--home",
                str(tmp_path),
                "routine",
                "approve",
                "r-test",
            ],
        )

    assert result.exit_code == 0, f"CLI failed: {result.output}"
    assert captured.get("tool_name") == "control_work_routine_approve", (
        f"approve did not go through Echo: {captured}"
    )


@pytest.mark.asyncio
async def test_interactive_routine_approve_uses_echo_and_writes_success_receipt(
    tmp_path: Path,
) -> None:
    from js.echo.ledger.journal import FileEchoLedger, verify_file
    from js.echo.ledger.service import EchoSafetyService

    cli = WorkCLI(home=tmp_path)
    store = _interactive_routine_store(cli)
    routine_id = "interactive-real-effect"
    _create_interactive_draft(store, routine_id)

    await cli._handle_routine_command(["approve", routine_id])

    assert store.get(routine_id).status == RoutineStatus.ENABLED
    service = EchoSafetyService(state_dir=cli.settings.state_dir)
    journal_path = service.journal_path_for_scope(
        WORK_OWNER_KEY_HASH,
        product_id="js-work",
        session_id="work-routine-cli",
    )
    journal_key = service.journal_key_for_scope(
        WORK_OWNER_KEY_HASH,
        product_id="js-work",
        session_id="work-routine-cli",
    )
    assert verify_file(journal_path, mac_key=journal_key).ok
    records = FileEchoLedger(journal_path, mac_key=journal_key).records
    intake = next(record for record in records if record.record_type == "intake")
    receipt = next(record for record in records if record.record_type == "receipt")
    assert intake.payload["tool_effect"]["tool_name"] == "control_work_routine_approve"
    assert receipt.payload["status"] == "ok"
    assert any(record.record_type == "merge" for record in records)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("effect_result", "expected_error"),
    [
        (ToolResult(success=False, error="approval denied"), "approval denied"),
        (
            ToolResult(success=True, metadata={"routine": "not-an-object"}),
            "routine control returned invalid data",
        ),
        (
            ToolResult(
                success=True,
                metadata={
                    "routine": {
                        "routine_id": "different-routine",
                        "status": "draft",
                    }
                },
            ),
            "routine control returned invalid data",
        ),
    ],
)
async def test_interactive_routine_approve_leaves_draft_on_rejected_effect_result(
    tmp_path: Path,
    effect_result: ToolResult,
    expected_error: str,
) -> None:
    cli = WorkCLI(home=tmp_path)
    store = _interactive_routine_store(cli)
    routine_id = "interactive-rejected-effect"
    _create_interactive_draft(store, routine_id)

    async def _reject_effect(*, settings: object, tool_name: str, arguments: object) -> ToolResult:
        assert settings is cli.settings
        assert tool_name == "control_work_routine_approve"
        assert arguments == {"routine_id": routine_id}
        return effect_result

    import js_work.cli as cli_module

    with (
        patch.object(cli_module, "_execute_routine_control_effect", new=_reject_effect),
        pytest.raises(click.ClickException, match=expected_error),
    ):
        await cli._handle_routine_command(["approve", routine_id])

    assert store.get(routine_id).status == RoutineStatus.DRAFT


@pytest.mark.asyncio
async def test_interactive_routine_approve_leaves_draft_when_effect_is_cancelled(
    tmp_path: Path,
) -> None:
    cli = WorkCLI(home=tmp_path)
    store = _interactive_routine_store(cli)
    routine_id = "interactive-cancelled-effect"
    _create_interactive_draft(store, routine_id)

    async def _cancel_effect(*, settings: object, tool_name: str, arguments: object) -> ToolResult:
        assert settings is cli.settings
        assert tool_name == "control_work_routine_approve"
        assert arguments == {"routine_id": routine_id}
        raise asyncio.CancelledError("cancel interactive approval")

    import js_work.cli as cli_module

    with (
        patch.object(cli_module, "_execute_routine_control_effect", new=_cancel_effect),
        pytest.raises(asyncio.CancelledError, match="cancel interactive approval"),
    ):
        await cli._handle_routine_command(["approve", routine_id])

    assert store.get(routine_id).status == RoutineStatus.DRAFT
