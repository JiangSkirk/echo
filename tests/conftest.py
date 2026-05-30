"""Playwright configuration to use system Chrome when Playwright browsers are not installed."""

from pathlib import Path

import pytest

SYSTEM_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
USE_SYSTEM_CHROME = Path(SYSTEM_CHROME).exists()


@pytest.fixture(autouse=True)
def reset_web_globals():
    """Keep mocked web agents from leaking between tests."""
    from js.web import deps, server
    from js.web.routers import system

    for module in (deps, server, system):
        if hasattr(module, "_agent"):
            module._agent = None
        if hasattr(module, "_settings"):
            module._settings = None
        if hasattr(module, "_stats_store"):
            module._stats_store = None
    deps.set_active_model("")
    yield
    for module in (deps, server, system):
        if hasattr(module, "_agent"):
            module._agent = None
        if hasattr(module, "_settings"):
            module._settings = None
        if hasattr(module, "_stats_store"):
            module._stats_store = None
    deps.set_active_model("")


@pytest.fixture(scope="session")
def browser_type_launch_args():
    """Override browser launch to use system Chrome on macOS."""
    if USE_SYSTEM_CHROME:
        return {"executable_path": SYSTEM_CHROME, "headless": True}
    return {}
