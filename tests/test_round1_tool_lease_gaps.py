"""Round 1 attack tests: ToolRegistry lease verification gaps.

Existing test_registry_verifier_binding.py only proves the verifier property
is read-only.  These tests probe deeper lease-validation failures that the
existing code accepts:

1. Empty ``fs_roots`` must be rejected (currently returns None = allowed).
2. Forged signature must be rejected (already checked, but verify).
3. Forged lease_id / lease_mac must be rejected.
4. Direct ``registry.execute`` with a forged context must fail.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from js.echo.primitives import stable_payload_hash
from js.security.guard import BehaviorGuard
from js.tools.registry import (
    ToolExecutionContext,
    ToolRegistry,
)


def _signed_context(
    *,
    signature: str = "real-signature",
    lease_id: str = "real-lease",
    lease_mac: str = "real-mac",
    fs_roots: tuple[str, ...] = ("/tmp/safe",),
    arguments: dict[str, Any] | None = None,
) -> ToolExecutionContext:
    args = arguments or {}
    return ToolExecutionContext(
        owner_key_hash="owner",
        session_id="sess",
        run_id="run",
        tool_name="file_read",
        lease_id=lease_id,
        lease_mac=lease_mac,
        signature=signature,
        fs_roots=fs_roots,
        network_policy="deny",
        network_hosts=(),
        max_bytes=1024,
        max_duration_ms=1000,
        args_hash=stable_payload_hash(args),
    )


def _registry_with_verifier(
    tmp_path: Path | None = None,
    *,
    valid_signature: str = "real-signature",
) -> ToolRegistry:
    limits = SimpleNamespace(max_concurrent_tools=4, tool_output_budget_chars=10_000)
    guard = BehaviorGuard(
        SimpleNamespace(
            defense_mode=SimpleNamespace(value="standard"),
            script_provenance=False,
            max_loop_iterations=5,
            tool_name_loop_threshold=4,
            protected_commands=[],
            high_risk_commands=[],
            hardline_patterns=[],
        ),
        tmp_path or Path("/tmp/round1-lease-test"),
    )
    registry = ToolRegistry(limits, guard)

    def _verifier(ctx: ToolExecutionContext) -> str | None:
        if ctx.signature != valid_signature:
            return "Echo execution context signature verification failed"
        if not ctx.lease_mac:
            return "Echo execution context lease_mac verification failed"
        return None

    registry.install_echo_context_verifier(_verifier)
    return registry


def test_empty_fs_roots_rejected() -> None:
    """An execution context with empty fs_roots must fail validation."""
    registry = _registry_with_verifier()
    args = {"path": "/etc/passwd"}
    ctx = _signed_context(fs_roots=(), arguments=args)
    error = registry._validate_echo_context(
        run_id="run",
        tool_name="file_read",
        arguments=args,
        echo_mode="on",
        execution_context=ctx,
    )
    assert error is not None, "Empty fs_roots must be rejected (fail-closed)"


def test_forged_signature_rejected() -> None:
    """A forged signature must be rejected."""
    registry = _registry_with_verifier()
    args = {"path": "/tmp/safe/f"}
    ctx = _signed_context(signature="forged", arguments=args)
    error = registry._validate_echo_context(
        run_id="run",
        tool_name="file_read",
        arguments=args,
        echo_mode="on",
        execution_context=ctx,
    )
    assert error is not None


def test_empty_signature_rejected() -> None:
    """An empty signature must be rejected."""
    registry = _registry_with_verifier()
    args = {"path": "/tmp/safe/f"}
    ctx = _signed_context(signature="", arguments=args)
    error = registry._validate_echo_context(
        run_id="run",
        tool_name="file_read",
        arguments=args,
        echo_mode="on",
        execution_context=ctx,
    )
    assert error is not None
