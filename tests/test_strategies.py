"""Tests for security strategy system."""

import pytest

from js.config import SecurityConfig
from js.security.strategies import (
    DefenseContext,
    DefenseResult,
    StrategyRegistry,
    build_default_strategies,
)


class TestStrategyRegistry:
    @pytest.fixture
    def registry(self) -> StrategyRegistry:
        return build_default_strategies()

    def test_list_strategies(self, registry: StrategyRegistry) -> None:
        names = registry.list_strategies()
        assert "command_block" in names
        assert "path_protection" in names

    def test_command_block_allows_safe(self, registry: StrategyRegistry) -> None:
        config = SecurityConfig()
        config.defense_mode = "enforce"  # type: ignore[assignment]
        ctx = DefenseContext(
            tool_name="shell",
            arguments={"command": "ls -la"},
            session_id="s1",
            run_id="r1",
            user_input="list files",
            config=config,
        )
        result = registry.evaluate(ctx)
        assert not result.blocked

    def test_command_block_blocks_risky(self, registry: StrategyRegistry) -> None:
        config = SecurityConfig()
        config.defense_mode = "enforce"  # type: ignore[assignment]
        ctx = DefenseContext(
            tool_name="shell",
            arguments={"command": "rm -rf /"},
            session_id="s1",
            run_id="r1",
            user_input="delete everything",
            config=config,
        )
        result = registry.evaluate(ctx)
        assert result.blocked
        assert "High-risk" in result.reason

    def test_crashing_strategy_is_fail_open(self, registry: StrategyRegistry) -> None:
        def bad_strategy(ctx: DefenseContext) -> DefenseResult:
            raise RuntimeError("crash")

        registry.register("bad", bad_strategy, order=0)
        ctx = DefenseContext(
            tool_name="shell",
            arguments={"command": "ls"},
            session_id="s1",
            run_id="r1",
            user_input="test",
            config=SecurityConfig(),
        )
        result = registry.evaluate(ctx)
        assert not result.blocked  # Fail-open
