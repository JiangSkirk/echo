"""echo_minimal_os carrier is optional and not official TCC evidence."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.appshell.launcher import launch_appshell
from js.orin.echo_os import (
    echo_minimal_os_carrier_available,
    require_echo_minimal_os_carrier,
    worker_module_name,
)


def test_echo_minimal_os_defaults_off_and_names_the_c1_worker() -> None:
    from js.config import OrinConfig

    assert OrinConfig().echo_minimal_os is False
    assert worker_module_name() == "js.echo.c1_worker"


def test_restricted_echo_environment_strips_tokens() -> None:
    from js.orin.echo_os import restricted_echo_environment

    env = restricted_echo_environment({"OPENAI_API_KEY": "sk", "PATH": "/bin"})
    assert "OPENAI_API_KEY" not in env
    assert env["PATH"] == "/bin"


def test_launcher_echo_minimal_os_fails_closed_without_carrier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "js.orin.echo_os.echo_minimal_os_carrier_available",
        lambda: False,
    )
    with pytest.raises(RuntimeError, match="carrier unavailable"):
        require_echo_minimal_os_carrier()
    with pytest.raises(RuntimeError, match="carrier unavailable"):
        launch_appshell(echo_minimal_os=True, open_browser=False, prefs_path=tmp_path / "prefs")


def test_carrier_probe_is_boolean_not_tcc_claim() -> None:
    available = echo_minimal_os_carrier_available()
    assert available in {True, False}
