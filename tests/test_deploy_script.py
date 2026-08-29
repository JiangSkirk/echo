"""Guards for ``scripts/deploy.sh`` resolving the repository root."""

from __future__ import annotations

import subprocess
from pathlib import Path

DEPLOY_SCRIPT = Path(__file__).parent.parent / "scripts" / "deploy.sh"
REPO_ROOT = DEPLOY_SCRIPT.parent.parent


def test_deploy_script_exists_and_is_executable() -> None:
    assert DEPLOY_SCRIPT.exists()
    assert DEPLOY_SCRIPT.stat().st_mode & 0o111


def test_deploy_script_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", str(DEPLOY_SCRIPT)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_deploy_script_uses_repository_root() -> None:
    """uv.lock and pyproject.toml live at the repo root, not under scripts/."""
    text = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    header = text.split("cat >", 1)[0]
    assert '"$SCRIPT_DIR/.."' in header
    assert "$PROJECT_DIR/uv.lock" in header
    assert 'PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"' not in header
    assert (REPO_ROOT / "uv.lock").is_file()
    assert (REPO_ROOT / "pyproject.toml").is_file()
    assert "js web" not in text
