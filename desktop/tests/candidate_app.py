from __future__ import annotations

import os
from pathlib import Path


def resolve_candidate_app() -> Path:
    raw_path = os.environ.get("JS_AGENT_APP_PATH")
    if not raw_path:
        raise AssertionError("JS_AGENT_APP_PATH must be set explicitly")

    app = Path(raw_path)
    if not app.is_absolute():
        raise AssertionError("JS_AGENT_APP_PATH must be an absolute path")
    if app.suffix != ".app" or not app.is_dir():
        raise AssertionError("JS_AGENT_APP_PATH must be an existing .app directory")
    return app
