"""Playwright configuration for E2E tests."""

from pathlib import Path

import pytest

SYSTEM_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
USE_SYSTEM_CHROME = Path(SYSTEM_CHROME).exists()


@pytest.fixture(scope="session")
def browser_type_launch_args():
    """Override browser launch to use system Chrome on macOS."""
    if USE_SYSTEM_CHROME:
        return {"executable_path": SYSTEM_CHROME, "headless": True}
    return {}
