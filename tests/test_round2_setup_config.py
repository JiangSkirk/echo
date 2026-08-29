"""Round 2 tests: setup exit code and retired browser CLI.

1. Setup wizard must raise SystemExit(1) when any step fails (was: only
   ``logger.warning`` and then printed "Setup complete!").
2. ``js web`` / ``js open`` must fail closed. The local Host is ``js appshell``,
   which must pass ``personal_config`` into ``create_appshell_app``.
"""

from __future__ import annotations

import inspect

import pytest
from click.testing import CliRunner


def test_setup_wizard_raises_on_step_failure() -> None:
    """A failed setup step must abort with SystemExit(1), not continue."""
    from js.setup_wizard import SetupWizard

    wiz = SetupWizard()

    # Patch _setup_directories to raise.
    async def _boom(non_interactive: bool = False) -> None:
        raise OSError("disk full")

    wiz._setup_directories = _boom  # type: ignore[method-assign]
    with pytest.raises(SystemExit) as exc_info:
        import asyncio

        asyncio.run(wiz.run(non_interactive=True))
    assert exc_info.value.code == 1


@pytest.mark.parametrize("args", [["web"], ["open"], ["web", "start"], ["web", "stop"]])
def test_browser_ui_commands_refuse(args: list[str]) -> None:
    from js.ui.cli import BROWSER_UI_RETIRED, main

    result = CliRunner().invoke(main, args)
    assert result.exit_code != 0
    assert BROWSER_UI_RETIRED in (result.output or "") + (
        result.exception and str(result.exception) or ""
    )


def test_appshell_passes_personal_config() -> None:
    """js appshell must pass the config path into create_appshell_app."""
    from js.ui import cli

    callback = cli.appshell_cmd.callback
    assert callback is not None
    source = inspect.getsource(callback)
    assert "personal_config=personal_config" in source
    assert "create_appshell_app" in source
    assert "webbrowser" not in source
    assert not hasattr(cli, "_launch_web")
    assert not hasattr(cli, "_bootstrap_browser_url")
