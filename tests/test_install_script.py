"""Tests for the macOS one-click install script."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

INSTALL_SCRIPT = Path(__file__).parent.parent / "scripts" / "install.sh"


def _dry_run_env() -> dict[str, str]:
    # DRY_RUN now validates uv + uv.lock; keep a PATH that can resolve uv.
    path = os.environ.get("PATH", "/usr/bin:/bin")
    return {
        "DRY_RUN": "1",
        "PATH": path,
        "HOME": "/tmp/js-agent-test-home",
    }


class TestInstallScript:
    """Smoke tests for install.sh."""

    def test_script_exists(self) -> None:
        assert INSTALL_SCRIPT.exists(), f"Install script not found at {INSTALL_SCRIPT}"
        assert INSTALL_SCRIPT.stat().st_mode & 0o111, "Install script not executable"

    def test_script_syntax(self) -> None:
        """bash -n should parse the script without errors."""
        result = subprocess.run(
            ["bash", "-n", str(INSTALL_SCRIPT)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Syntax error: {result.stderr}"

    def test_dry_run(self) -> None:
        """Running with DRY_RUN=1 should complete without errors."""
        result = subprocess.run(
            ["bash", str(INSTALL_SCRIPT)],
            capture_output=True,
            text=True,
            env=_dry_run_env(),
            cwd=str(INSTALL_SCRIPT.parent.parent),
        )
        assert result.returncode == 0, f"Dry run failed: {result.stderr}\nstdout: {result.stdout}"
        assert (
            "干运行模式" in result.stdout
            or "dry run" in result.stdout.lower()
            or "所有前置检查通过" in result.stdout
        )

    def test_detects_python(self) -> None:
        """Script should detect Python 3.12+ in dry-run mode."""
        result = subprocess.run(
            ["bash", str(INSTALL_SCRIPT)],
            capture_output=True,
            text=True,
            env=_dry_run_env(),
            cwd=str(INSTALL_SCRIPT.parent.parent),
        )
        assert result.returncode == 0
        # Should either succeed (Python found) or fail with a clear Python error
        if result.returncode == 0:
            assert "Python" in result.stdout

    def test_output_contains_key_steps(self) -> None:
        """Dry run output should mention key installation steps."""
        result = subprocess.run(
            ["bash", str(INSTALL_SCRIPT)],
            capture_output=True,
            text=True,
            env=_dry_run_env(),
            cwd=str(INSTALL_SCRIPT.parent.parent),
        )
        output = result.stdout
        # Should mention at least some of these key steps
        key_indicators = [
            "Python",
            "检查",
            "uv",
        ]
        found = sum(1 for indicator in key_indicators if indicator in output)
        assert found >= 2, f"Expected more step indicators in output, got: {output[:500]}"
