from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import click
import pytest

from js_work.cli import WorkCLI
from js_work.tools import WorkToolProfile


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "error_message", "expected_message"),
    [
        ("error", "provider failed", "处理你的请求"),
        ("cancelled", "Run cancelled by user request", "已取消"),
        ("failed", "", "Echo turn ended with status failed"),
    ],
)
async def test_work_cli_run_message_raises_for_echo_terminal_failure(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    error_message: str,
    expected_message: str,
) -> None:
    cli = object.__new__(WorkCLI)
    cli.settings = SimpleNamespace(providers=[object()])
    cli.profile = WorkToolProfile.EXECUTE
    cli.agent = object()
    cli._agent_profile = WorkToolProfile.EXECUTE
    cli.session_id = None
    cli.intent_router = SimpleNamespace(prepare_message=lambda message: message)
    state = SimpleNamespace(
        session_id="session-1",
        status=status,
        error_message=error_message,
        messages=[],
    )
    monkeypatch.setattr("js_work.cli.run_echo_turn", AsyncMock(return_value=state))

    with pytest.raises(click.ClickException, match=expected_message) as exc_info:
        await cli.run_message("hello")

    assert exc_info.value.exit_code == 1
    assert cli.session_id == "session-1"


@pytest.mark.asyncio
async def test_work_cli_run_message_sanitizes_unexpected_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_detail = "/Users/private/Documents/customer.xlsx secret-token"
    cli = object.__new__(WorkCLI)
    cli.settings = SimpleNamespace(providers=[object()])
    cli.profile = WorkToolProfile.EXECUTE
    cli.agent = object()
    cli._agent_profile = WorkToolProfile.EXECUTE
    cli.session_id = None
    cli.intent_router = SimpleNamespace(prepare_message=lambda message: message)
    cli.logger = MagicMock()
    monkeypatch.setattr(
        "js_work.cli.run_echo_turn",
        AsyncMock(side_effect=RuntimeError(private_detail)),
    )

    with pytest.raises(click.ClickException) as exc_info:
        await cli.run_message("hello")

    assert private_detail not in str(exc_info.value)


@pytest.mark.asyncio
async def test_interactive_routine_run_awaits_effect_inside_running_event_loop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    cli = object.__new__(WorkCLI)
    cli.settings = SimpleNamespace(state_dir=tmp_path)
    cli.profile = WorkToolProfile.OFFICE
    execute_effect = AsyncMock(return_value={"status": "passed"})
    monkeypatch.setattr("js_work.cli._execute_routine_tool_effect", execute_effect)

    def reject_nested_event_loop(awaitable: object) -> None:
        close = getattr(awaitable, "close", None)
        if close is not None:
            close()
        pytest.fail("interactive routine handler must not call asyncio.run")

    monkeypatch.setattr("js_work.cli.asyncio.run", reject_nested_event_loop)

    should_exit = await cli._handle_command(
        "/routine run routine-1 source.xlsx template.xlsx output.xlsx"
    )

    assert should_exit is False
    execute_effect.assert_awaited_once_with(
        settings=cli.settings,
        routine_id="routine-1",
        source_path="source.xlsx",
        template_path="template.xlsx",
        output_path="output.xlsx",
        dry_run=False,
    )


@pytest.mark.asyncio
async def test_work_cli_reuses_same_profile_and_closes_before_switch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_agent = SimpleNamespace(close=AsyncMock())
    new_agent = SimpleNamespace(close=AsyncMock(), start_background_tasks=MagicMock())
    created: list[WorkToolProfile] = []

    def create_agent(*, settings, profile, allow_host_code_tools):
        del settings
        assert allow_host_code_tools is True
        created.append(profile)
        return new_agent

    monkeypatch.setattr("js_work.cli.create_work_agent", create_agent)
    cli = object.__new__(WorkCLI)
    cli.settings = SimpleNamespace()
    cli.profile = WorkToolProfile.EXECUTE
    cli.agent = old_agent
    cli._agent_profile = WorkToolProfile.EXECUTE

    await cli.init(profile=WorkToolProfile.EXECUTE)
    assert created == []

    await cli.init(profile=WorkToolProfile.SAFE)
    old_agent.close.assert_awaited_once()
    assert created == [WorkToolProfile.SAFE]
    assert cli.agent is new_agent
    new_agent.start_background_tasks.assert_called_once_with()

    await cli.close()
    new_agent.close.assert_awaited_once_with()
    assert cli.agent is None
