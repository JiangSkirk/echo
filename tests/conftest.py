"""Global test fixtures."""

import pytest


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
