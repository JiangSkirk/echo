from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON = REPO_ROOT / ".venv" / "bin" / "python"


def test_auth_import_does_not_eagerly_import_full_web_server() -> None:
    script = """
import sys
import js.web.auth
assert 'js.web.server' not in sys.modules
from js.web import create_app
assert callable(create_app)
assert 'js.web.server' in sys.modules
"""
    completed = subprocess.run(
        [str(PYTHON), "-c", script],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
