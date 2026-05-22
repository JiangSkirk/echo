"""Security-as-Strategy: pluggable defense strategies for tool calls.

Inspired by OpenClaw ClawAegis: defenses are not hardcoded if-else chains
but ordered, injectable strategy objects.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from js.config import DefenseMode, SecurityConfig
from js.utils.log import get_logger

logger = get_logger("js.security.strategies")


@dataclass
class DefenseContext:
    tool_name: str
    arguments: dict[str, Any]
    session_id: str
    run_id: str
    user_input: str
    config: SecurityConfig


@dataclass
class DefenseResult:
    blocked: bool
    reason: str = ""
    observe_only: bool = False


DefenseStrategy = Callable[[DefenseContext], DefenseResult]


def _get_defense_mode(ctx: DefenseContext) -> DefenseMode:
    """Return the normalized defense mode enum."""
    return ctx.config.defense_mode


class StrategyRegistry:
    """Registry of defense strategies applied in order."""

    def __init__(self) -> None:
        self._strategies: list[tuple[str, DefenseStrategy, int]] = []

    def register(self, name: str, strategy: DefenseStrategy, order: int = 0) -> None:
        """Register a defense strategy. Lower order = evaluated first."""
        self._strategies.append((name, strategy, order))
        self._strategies.sort(key=lambda x: x[2])
        logger.info(f"Registered defense strategy: {name}")

    def evaluate(self, ctx: DefenseContext) -> DefenseResult:
        """Evaluate all strategies in order. First block wins."""
        for name, strategy, _order in self._strategies:
            try:
                result = strategy(ctx)
                if result.blocked:
                    logger.warning(
                        f"Strategy '{name}' blocked {ctx.tool_name}: {result.reason}"
                    )
                    return result
                if result.observe_only:
                    logger.info(
                        f"Strategy '{name}' warned on {ctx.tool_name}: {result.reason}"
                    )
            except Exception as e:
                # Fail-open: strategy crash doesn't block the system
                logger.error(f"Strategy '{name}' crashed: {e}")
                continue

        return DefenseResult(blocked=False)

    def list_strategies(self) -> list[str]:
        return [name for name, _strategy, _order in self._strategies]


# Built-in strategies

def command_block_strategy(ctx: DefenseContext) -> DefenseResult:
    """Block high-risk shell commands."""
    if ctx.tool_name != "shell":
        return DefenseResult(blocked=False)

    raw = ctx.arguments.get("command", "")
    command = " ".join(raw) if isinstance(raw, list) else str(raw)
    high_risk = [
        "rm -rf /",
        "dd if=/dev/zero",
        "mkfs.",
        ":(){ :|:& };:",
    ]
    mode = _get_defense_mode(ctx)
    for pattern in high_risk:
        if pattern in command:
            return DefenseResult(
                blocked=mode == DefenseMode.ENFORCE,
                reason=f"High-risk command pattern: {pattern}",
                observe_only=mode == DefenseMode.OBSERVE,
            )
    return DefenseResult(blocked=False)


def path_protection_strategy(ctx: DefenseContext) -> DefenseResult:
    """Protect sensitive paths from file operations."""
    if ctx.tool_name not in ("file_read", "file_write", "file_delete"):
        return DefenseResult(blocked=False)

    raw = ctx.arguments.get("path", "")
    if raw is None:
        return DefenseResult(blocked=False)
    path = str(raw)
    protected = ctx.config.protected_paths or ["/etc", "/usr", "/bin", "/sys", "/dev", "/proc"]
    mode = _get_defense_mode(ctx)
    for p in protected:
        if path.startswith(p):
            return DefenseResult(
                blocked=mode == DefenseMode.ENFORCE,
                reason=f"Protected path: {p}",
                observe_only=mode == DefenseMode.OBSERVE,
            )
    return DefenseResult(blocked=False)


def loop_guard_strategy(_ctx: DefenseContext) -> DefenseResult:
    """Warn on potentially looping tool calls."""
    # Simplified: actual implementation would track per-run counters
    return DefenseResult(blocked=False)


def build_default_strategies() -> StrategyRegistry:
    """Build the default strategy registry."""
    registry = StrategyRegistry()
    registry.register("command_block", command_block_strategy, order=10)
    registry.register("path_protection", path_protection_strategy, order=20)
    registry.register("loop_guard", loop_guard_strategy, order=30)
    return registry
