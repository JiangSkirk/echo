from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from js.ui.cli import JSCLI


@pytest.mark.asyncio
async def test_cli_starts_background_maintenance_and_closes_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = SimpleNamespace(
        start_background_tasks=MagicMock(),
        close=AsyncMock(),
    )
    monkeypatch.setattr("js.ui.cli.JSAgent", lambda _settings: agent)
    cli = JSCLI(settings=SimpleNamespace())  # type: ignore[arg-type]

    await cli.init()
    await cli.close()

    agent.start_background_tasks.assert_called_once_with()
    agent.close.assert_awaited_once_with()
    assert cli.agent is None


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["state", "exception"])
async def test_cli_message_error_does_not_echo_private_detail(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    private_detail = "/Users/private/Documents/customer.xlsx secret-token"
    cli = JSCLI(settings=SimpleNamespace(display=SimpleNamespace(show_cost=False)))  # type: ignore[arg-type]
    cli.agent = object()  # type: ignore[assignment]
    fake_console = MagicMock()
    monkeypatch.setattr("js.ui.cli.console", fake_console)
    if mode == "state":
        state = SimpleNamespace(
            session_id="session-a",
            status="error",
            error_message=private_detail,
        )
        monkeypatch.setattr("js.ui.cli.run_echo_turn", AsyncMock(return_value=state))
    else:
        monkeypatch.setattr(
            "js.ui.cli.run_echo_turn",
            AsyncMock(side_effect=RuntimeError(private_detail)),
        )

    await cli._process_message("hello")

    assert private_detail not in str(fake_console.mock_calls)
