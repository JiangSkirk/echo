"""Round 2 tests: setup exit code and web --config wiring.

1. Setup wizard must raise SystemExit(1) when any step fails (was: only
   ``logger.warning`` and then printed "Setup complete!").
2. ``_launch_web`` must actually pass the config path to ``JSSettings`` /
   ``create_app`` (was: parameter named ``_config`` and ignored).
"""

from __future__ import annotations

import inspect

import pytest


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


def test_launch_web_uses_config_parameter() -> None:
    """_launch_web must not ignore the config argument."""
    from js.ui import cli
    source = inspect.getsource(cli._launch_web)
    # The old code had ``_config`` (underscore-prefixed = intentionally unused).
    assert "_config: str | None" not in source, (
        "_launch_web still names the config parameter as _config (unused)."
    )
    # The new code must reference the config parameter to load settings.
    assert "runtime_settings = JSSettings.from_file(config)" in source or \
           "JSSettings.from_file(config)" in source, (
        "_launch_web must pass config to JSSettings.from_file()."
    )
