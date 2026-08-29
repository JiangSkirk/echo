"""Tests for the macOS one-click start script (``scripts/macos_start.sh``).

Mirrors ``test_install_script.py``: the start script is the README's primary
prep path for ordinary users, so it must parse, run a side-effect-free
``DRY_RUN`` check, and point users at the desktop app (not a browser).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

START_SCRIPT = Path(__file__).parent.parent / "scripts" / "macos_start.sh"

# Restricted but realistic PATH + throwaway HOME so the dry run never touches
# the developer's real config or venv.
_DRY_ENV = {
    "DRY_RUN": "1",
    "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp/js-agent-start-test-home",
}


def _dry_run() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(START_SCRIPT)],
        capture_output=True,
        text=True,
        env=_DRY_ENV,
        cwd=str(START_SCRIPT.parent.parent),
    )


class TestStartScript:
    """Smoke tests for macos_start.sh."""

    def test_script_exists(self) -> None:
        assert START_SCRIPT.exists(), f"Start script not found at {START_SCRIPT}"
        assert START_SCRIPT.stat().st_mode & 0o111, "Start script not executable"

    def test_script_syntax(self) -> None:
        """bash -n should parse the script without errors."""
        result = subprocess.run(
            ["bash", "-n", str(START_SCRIPT)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Syntax error: {result.stderr}"

    def test_dry_run(self) -> None:
        """DRY_RUN=1 should complete cleanly without installing or launching."""
        result = _dry_run()
        assert result.returncode == 0, f"Dry run failed: {result.stderr}\nstdout: {result.stdout}"
        assert "干运行模式" in result.stdout or "所有前置检查通过" in result.stdout

    def test_detects_python(self) -> None:
        """The environment check should report a usable Python."""
        result = _dry_run()
        assert result.returncode == 0
        assert "Python" in result.stdout

    def test_dry_run_does_not_launch(self) -> None:
        """The dry run must exit before the install/launch steps run."""
        result = _dry_run()
        assert "正在启动" not in result.stdout
        assert "安装/更新依赖" not in result.stdout


class TestStartScriptContent:
    """Static guards on key user-facing guidance (no execution)."""

    def test_points_to_desktop_app(self) -> None:
        text = START_SCRIPT.read_text(encoding="utf-8")
        assert "请打开 JS Agent 桌面应用" in text
        assert "js open" not in text
        assert "js web" not in text
        assert "bootstrap_admin_key.txt" not in text

    def test_supports_dry_run_flag(self) -> None:
        text = START_SCRIPT.read_text(encoding="utf-8")
        assert "DRY_RUN" in text
