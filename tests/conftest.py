"""Global test fixtures."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from js.echo import stable_payload_hash
from js.echo.capability import LeaseAuthority, sign_tool_execution_context
from js.tools.registry import ToolExecutionContext, ToolRegistry

_SHARED_TOOL_AUTHORITY = LeaseAuthority(
    mac_key=b"test-tool-lease-key-32-bytes!!",
    now_fn=lambda: 1_000,
)


def _shared_consume_context(execution_context: ToolExecutionContext) -> str | None:
    try:
        _SHARED_TOOL_AUTHORITY.consume_execution_context(execution_context, now=1_000)
    except Exception as exc:
        return f"Echo execution context lease denied: {type(exc).__name__}"
    return None


@pytest.fixture
def echo_tool_context() -> Callable[..., ToolExecutionContext]:
    """Issue a signed Echo context bound to the exact test tool call."""

    authority = _SHARED_TOOL_AUTHORITY

    def _issue(
        *,
        run_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        owner_key_hash: str = "echo-test-owner",
        resource_scope: str = "test-scope",
        fs_roots: tuple[str, ...] = (),
        network_policy: str = "deny",
        network_hosts: tuple[str, ...] = (),
        max_bytes: int = 10_000,
        max_duration_ms: int = 1_000,
        registry: ToolRegistry,
    ) -> ToolExecutionContext:
        context = ToolExecutionContext(
            owner_key_hash=owner_key_hash,
            run_id=run_id,
            tool_name=tool_name,
            args_hash=stable_payload_hash(arguments),
            fs_roots=fs_roots,
            network_policy=network_policy,
            network_hosts=network_hosts,
            max_bytes=max_bytes,
            max_duration_ms=max_duration_ms,
            resource_scope=resource_scope,
        )
        lease = authority.issue(
            owner_key_hash=context.owner_key_hash,
            run_id=context.run_id,
            tool_name=context.tool_name,
            args_schema=context.args_hash,
            resource_scope=context.resource_scope,
            fs_roots=context.fs_roots,
            network_policy=context.network_policy,
            network_hosts=context.network_hosts,
            max_bytes=context.max_bytes,
            max_duration_ms=context.max_duration_ms,
            ttl_ms=60_000,
        )
        signed = sign_tool_execution_context(
            context,
            lease=lease,
            authority=authority,
            now=1_000,
        )

        registry.install_echo_context_verifier(_shared_consume_context)
        return signed

    return _issue


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


@pytest.fixture(autouse=True)
def reset_structlog_config():
    """Restore structlog defaults after tests that call configure_logging().

    CLI-style tests invoke ``configure_logging`` which permanently switches
    structlog to the stdlib logger factory; subsequent capsys-based tests
    then stop seeing log output.  Resetting after each test keeps logging
    configuration test-local.
    """
    yield
    import structlog

    structlog.reset_defaults()
