"""RED: ToolRegistry.echo_context_verifier must not be forgeable.

The verifier is the last line of defence against a forged
``ToolExecutionContext`` carrying a fake lease.  If external code can
simply assign ``registry.echo_context_verifier = lambda _: None`` then
every tool gate becomes bypassable.  The verifier must be installed by
``install_echo_context_verifier`` and afterwards be read-only: any
attempt to overwrite it must raise.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.security.guard import BehaviorGuard
from js.tools.registry import ToolRegistry


def _registry(tmp_path: Path | None = None) -> ToolRegistry:
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
        tmp_path or Path("/tmp/verifier-test"),
    )
    return ToolRegistry(limits, guard)


def _real_verifier(_ctx: Any) -> str | None:
    return None


def _forged_verifier(_ctx: Any) -> str | None:
    return None


def test_echo_context_verifier_cannot_be_assigned_directly(tmp_path: Path) -> None:
    """Direct attribute assignment must raise, not silently replace."""
    reg = _registry(tmp_path)
    with pytest.raises((AttributeError, RuntimeError)):
        reg.echo_context_verifier = _forged_verifier  # type: ignore[misc]


def test_echo_context_verifier_install_then_lock(tmp_path: Path) -> None:
    """``install_echo_context_verifier`` sets it once; second install raises."""
    reg = _registry(tmp_path)
    reg.install_echo_context_verifier(_real_verifier)
    assert reg.echo_context_verifier is _real_verifier
    with pytest.raises((AttributeError, RuntimeError)):
        reg.install_echo_context_verifier(_forged_verifier)
    # Still the original
    assert reg.echo_context_verifier is _real_verifier


def test_echo_context_verifier_starts_unbound(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    assert reg.echo_context_verifier is None
