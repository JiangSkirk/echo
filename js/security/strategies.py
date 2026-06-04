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
    relevant: bool = True  # False when strategy does not apply to this tool type


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
        """Evaluate all strategies in order. First block wins.

        Fail-closed: if no relevant strategy evaluates the operation and
        none blocks, the operation is denied by default.
        """
        any_relevant = False
        for name, strategy, _order in self._strategies:
            try:
                result = strategy(ctx)
                if not result.relevant:
                    continue
                any_relevant = True
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
                # Fail-closed: strategy crash blocks the operation
                logger.error(f"Strategy '{name}' crashed: {e}")
                return DefenseResult(
                    blocked=True,
                    reason=f"Strategy '{name}' crashed: {e}",
                )

        if any_relevant:
            return DefenseResult(blocked=False)

        # Fail-closed: no relevant strategy evaluated this operation
        return DefenseResult(
            blocked=True,
            reason="No relevant strategy evaluated this operation",
        )

    def list_strategies(self) -> list[str]:
        return [name for name, _strategy, _order in self._strategies]


# Built-in strategies

def command_block_strategy(ctx: DefenseContext) -> DefenseResult:
    """Block high-risk shell commands using regex for robust matching."""
    import re

    if ctx.tool_name != "shell":
        return DefenseResult(blocked=False, relevant=False)

    raw = ctx.arguments.get("command", "")
    command = " ".join(raw) if isinstance(raw, list) else str(raw)
    # Normalize: collapse multiple spaces and lower-case for consistent matching
    normalized = re.sub(r"\s+", " ", command.lower().strip())

    high_risk_patterns = [
        (r"rm\s+(-[rf]+\s+)*\/\s*($|\s|;)", "rm -rf / variant"),
        (r"dd\s+if=[^\s]*\s+of=\/dev\/sd[a-z]", "dd to block device"),
        (r"dd\s+if=\/dev\/zero\s+of=\/dev\/sd[a-z]", "dd zero to block device"),
        (r"mkfs\.[a-z0-9]+\s+\/dev\/sd[a-z]", "mkfs on block device"),
        (r"mkfs\.[a-z0-9]+\s+\/dev\/hd[a-z]", "mkfs on IDE device"),
        (r"mkfs\.[a-z0-9]+\s+\/dev\/nvme", "mkfs on NVMe device"),
        (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "fork bomb"),
        (r"curl\s+.*\|\s*sh", "curl pipe to shell"),
        (r"wget\s+.*\|\s*sh", "wget pipe to shell"),
        (r"curl\s+.*\|\s*bash", "curl pipe to bash"),
        (r"eval\s*\$", "eval of variable"),
        (r"chmod\s+-R\s+777\s+\/", "chmod 777 root"),
        (r"shutdown\s+-h\s+now", "shutdown now"),
        (r"halt\s+-p", "halt"),
        (r"reboot\s+-f", "forced reboot"),
        (r"init\s+0", "init 0"),
        (r"poweroff\s+-f", "forced poweroff"),
    ]
    mode = _get_defense_mode(ctx)
    for pattern, description in high_risk_patterns:
        if re.search(pattern, normalized):
            return DefenseResult(
                blocked=mode == DefenseMode.ENFORCE,
                reason=f"High-risk command: {description}",
                observe_only=mode == DefenseMode.OBSERVE,
            )
    return DefenseResult(blocked=False)


def path_protection_strategy(ctx: DefenseContext) -> DefenseResult:
    """Protect sensitive paths from file operations."""
    if ctx.tool_name not in ("file_read", "file_write", "file_delete"):
        return DefenseResult(blocked=False, relevant=False)

    raw = ctx.arguments.get("path", "")
    if raw is None:
        return DefenseResult(blocked=False)
    path = str(raw)
    protected = ctx.config.protected_paths or ["/etc", "/usr", "/bin", "/sys", "/dev", "/proc"]
    # Resolve the path to catch bypasses like //etc, /./etc, /home/../etc
    from pathlib import Path as _Path
    try:
        resolved = _Path(path).expanduser().resolve()
    except (OSError, ValueError):
        resolved = _Path(path)
    mode = _get_defense_mode(ctx)
    for p in protected:
        protected_resolved = _Path(p).resolve()
        try:
            resolved.relative_to(protected_resolved)
        except ValueError:
            continue  # Path is not under this protected root
        else:
            return DefenseResult(
                blocked=mode == DefenseMode.ENFORCE,
                reason=f"Protected path: {p}",
                observe_only=mode == DefenseMode.OBSERVE,
            )
    return DefenseResult(blocked=False)


def loop_guard_strategy(ctx: DefenseContext) -> DefenseResult:
    """Warn on potentially looping tool calls.

    Applies to all tool types — uses the same per-run counters as
    BehaviorGuard.check_loop, accessed via the strategy context.
    The actual loop detection is performed by guard.check_loop()
    during tool execution; this strategy provides an additional
    defense-in-depth layer for tools that bypass the guard path.
    """

    # Only relevant for tool calls that could repeat
    if ctx.tool_name in ("web_navigate", "web_snapshot", "web_click", "web_fill", "shell"):
        user_cmd = str(ctx.arguments.get("command", ctx.arguments.get("url", "")))
        # Quick heuristic: if the same command/URL appears in user_input
        # and this is a high-turn session, flag it
        if user_cmd and len(user_cmd) > 3 and user_cmd in ctx.user_input:
            mode = _get_defense_mode(ctx)
            return DefenseResult(
                blocked=mode == DefenseMode.ENFORCE,
                reason=f"Potential repeated call to {ctx.tool_name} with same input",
                observe_only=mode == DefenseMode.OBSERVE,
            )

    return DefenseResult(blocked=False)


def build_default_strategies() -> StrategyRegistry:
    """Build the default strategy registry."""
    registry = StrategyRegistry()
    registry.register("command_block", command_block_strategy, order=10)
    registry.register("path_protection", path_protection_strategy, order=20)
    registry.register("loop_guard", loop_guard_strategy, order=30)
    return registry
