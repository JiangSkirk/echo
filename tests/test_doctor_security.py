"""js doctor --security is a local audit, not a Host startup path."""

from __future__ import annotations

from click.testing import CliRunner

from js.ui.cli import main


def test_doctor_without_flag_exits_usage() -> None:
    result = CliRunner().invoke(main, ["doctor"])
    assert result.exit_code == 2
    assert "js doctor --security" in result.output


def test_doctor_security_runs() -> None:
    result = CliRunner().invoke(main, ["doctor", "--security", "--bind-host", "127.0.0.1"])
    assert result.exit_code in {0, 1}
    assert "isolation_posture" in result.output or "posture" in result.output
