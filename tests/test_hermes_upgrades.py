"""Tests for JS Agent upgrades inspired by Hermes agent patterns."""

from __future__ import annotations

import asyncio
from pathlib import Path

from js.config import DefenseMode
from js.security.guard import BehaviorGuard, SecurityDecisionType
from js.tools.registry import ToolRegistry, ToolResult, ToolSpec


class MockSecurityConfig:
    """Mock security config for testing."""

    def __init__(self, mode: str = "enforce") -> None:
        self.defense_mode = DefenseMode(mode)
        self.protected_commands: list[str] = []
        self.protected_paths: list[str] = []
        self.allow_workspace_delete = False
        self.encoding_guard = True
        self.tool_result_scan = True
        self.script_provenance = False
        self.max_loop_iterations = 5
        self.tool_name_loop_threshold = 4


class TestHardlineBlocklist:
    """Hardline patterns block irreversible ops even in defense_mode=off."""

    def test_rm_rf_root_blocked_even_in_off_mode(self):
        guard = BehaviorGuard(MockSecurityConfig("off"), Path("/tmp/workspace"))
        decision = guard.check_command("rm -rf /", "/tmp")
        assert decision.decision == SecurityDecisionType.BLOCK
        assert "Hardline" in decision.reason

    def test_rm_rf_root_with_whitespace_blocked(self):
        guard = BehaviorGuard(MockSecurityConfig("off"), Path("/tmp/workspace"))
        decision = guard.check_command("rm -rf / ", "/tmp")
        assert decision.decision == SecurityDecisionType.BLOCK

    def test_dd_to_block_device_blocked(self):
        guard = BehaviorGuard(MockSecurityConfig("off"), Path("/tmp/workspace"))
        decision = guard.check_command("dd if=/dev/zero of=/dev/sda", "/tmp")
        assert decision.decision == SecurityDecisionType.BLOCK

    def test_mkfs_blocked(self):
        guard = BehaviorGuard(MockSecurityConfig("off"), Path("/tmp/workspace"))
        decision = guard.check_command("mkfs.ext4 /dev/sdb", "/tmp")
        assert decision.decision == SecurityDecisionType.BLOCK

    def test_fork_bomb_blocked(self):
        guard = BehaviorGuard(MockSecurityConfig("off"), Path("/tmp/workspace"))
        decision = guard.check_command(":(){ :|:& };:")
        assert decision.decision == SecurityDecisionType.BLOCK

    def test_shutdown_blocked(self):
        guard = BehaviorGuard(MockSecurityConfig("off"), Path("/tmp/workspace"))
        decision = guard.check_command("shutdown -h now")
        assert decision.decision == SecurityDecisionType.BLOCK

    def test_safe_command_allowed_in_off_mode(self):
        guard = BehaviorGuard(MockSecurityConfig("off"), Path("/tmp/workspace"))
        decision = guard.check_command("ls -la", "/tmp")
        assert decision.decision == SecurityDecisionType.ALLOW

    def test_safe_command_allowed_in_enforce_mode(self):
        guard = BehaviorGuard(MockSecurityConfig("enforce"), Path("/tmp/workspace"))
        decision = guard.check_command("ls -la", "/tmp")
        assert decision.decision == SecurityDecisionType.ALLOW

    def test_encoded_hardline_detected(self):
        """Hardline patterns are also checked in decoded payloads."""
        guard = BehaviorGuard(MockSecurityConfig("enforce"), Path("/tmp/workspace"))
        import base64
        # Use a payload whose base64 is >40 chars so the pattern detector picks it up
        encoded = base64.b64encode(b"rm -rf /very/important/system/directory").decode()
        decision = guard.check_command(f"echo {encoded} | base64 -d | bash")
        # The decoded content contains "rm -rf /" which should trigger hardline
        assert decision.decision == SecurityDecisionType.BLOCK


class TestRepeatedFailureGuard:
    """Hermes-style repeated failure guardrail."""

    def test_no_warning_on_first_failure(self):
        guard = BehaviorGuard(MockSecurityConfig("enforce"), Path("/tmp/workspace"))
        decision = guard.check_repeated_failure("run_1", "file_read", success=False)
        assert decision.decision == SecurityDecisionType.ALLOW

    def test_warning_on_second_failure(self):
        guard = BehaviorGuard(MockSecurityConfig("enforce"), Path("/tmp/workspace"))
        guard.check_repeated_failure("run_1", "file_read", success=False)
        decision = guard.check_repeated_failure("run_1", "file_read", success=False)
        assert decision.decision == SecurityDecisionType.WARN

    def test_block_on_third_failure(self):
        guard = BehaviorGuard(MockSecurityConfig("enforce"), Path("/tmp/workspace"))
        guard.check_repeated_failure("run_1", "file_read", success=False)
        guard.check_repeated_failure("run_1", "file_read", success=False)
        decision = guard.check_repeated_failure("run_1", "file_read", success=False)
        assert decision.decision == SecurityDecisionType.BLOCK
        assert "failed 3 consecutive times" in decision.reason

    def test_reset_on_success(self):
        guard = BehaviorGuard(MockSecurityConfig("enforce"), Path("/tmp/workspace"))
        guard.check_repeated_failure("run_1", "file_read", success=False)
        guard.check_repeated_failure("run_1", "file_read", success=False)
        guard.check_repeated_failure("run_1", "file_read", success=True)
        decision = guard.check_repeated_failure("run_1", "file_read", success=False)
        # Counter was reset by success, so this is the first failure again
        assert decision.decision == SecurityDecisionType.ALLOW

    def test_different_tools_tracked_separately(self):
        guard = BehaviorGuard(MockSecurityConfig("enforce"), Path("/tmp/workspace"))
        for _ in range(5):
            guard.check_repeated_failure("run_1", "file_read", success=False)
        # file_list should not be affected by file_read failures
        decision = guard.check_repeated_failure("run_1", "file_list", success=False)
        assert decision.decision == SecurityDecisionType.ALLOW

    def test_different_runs_tracked_separately(self):
        guard = BehaviorGuard(MockSecurityConfig("enforce"), Path("/tmp/workspace"))
        for _ in range(5):
            guard.check_repeated_failure("run_a", "file_read", success=False)
        decision = guard.check_repeated_failure("run_b", "file_read", success=False)
        assert decision.decision == SecurityDecisionType.ALLOW

    def test_reset_loop_counters_clears_failures(self):
        guard = BehaviorGuard(MockSecurityConfig("enforce"), Path("/tmp/workspace"))
        for _ in range(5):
            guard.check_repeated_failure("run_1", "file_read", success=False)
        guard.reset_loop_counters("run_1")
        decision = guard.check_repeated_failure("run_1", "file_read", success=False)
        assert decision.decision == SecurityDecisionType.ALLOW

    def test_off_mode_allows_failures(self):
        guard = BehaviorGuard(MockSecurityConfig("off"), Path("/tmp/workspace"))
        for _ in range(10):
            decision = guard.check_repeated_failure("run_1", "file_read", success=False)
        assert decision.decision == SecurityDecisionType.ALLOW


class TestToolResultCaching:
    """ToolRegistry result caching for idempotent tools."""

    def test_cache_hit_returns_same_result(self):
        guard = BehaviorGuard(MockSecurityConfig("enforce"), Path("/tmp/workspace"))
        registry = ToolRegistry(type("Limits", (), {"max_concurrent_tools": 10})(), guard)

        async def handler(name: str = "") -> ToolResult:
            return ToolResult(success=True, output=f"hello {name}")

        spec = ToolSpec(name="file_read", description="Read file", parameters=[], read_only=True)
        registry.register(spec, handler)

        # First call should execute
        result1 = asyncio.run(registry.execute("run_1", "file_read", {"name": "world"}))
        # Second call with same args should hit cache
        result2 = asyncio.run(registry.execute("run_1", "file_read", {"name": "world"}))
        assert result1.output == result2.output
        assert result1.success == result2.success

    def test_cache_miss_for_different_args(self):
        guard = BehaviorGuard(MockSecurityConfig("enforce"), Path("/tmp/workspace"))
        registry = ToolRegistry(type("Limits", (), {"max_concurrent_tools": 10})(), guard)

        call_count = 0

        async def handler(name: str = "") -> ToolResult:
            nonlocal call_count
            call_count += 1
            return ToolResult(success=True, output=f"hello {name}")

        spec = ToolSpec(name="file_read", description="Read file", parameters=[], read_only=True)
        registry.register(spec, handler)

        asyncio.run(registry.execute("run_1", "file_read", {"name": "a"}))
        asyncio.run(registry.execute("run_1", "file_read", {"name": "b"}))
        assert call_count == 2

    def test_cache_ttl_expires(self):
        guard = BehaviorGuard(MockSecurityConfig("enforce"), Path("/tmp/workspace"))
        registry = ToolRegistry(type("Limits", (), {"max_concurrent_tools": 10})(), guard)
        registry._cache_ttl_seconds = 0.01  # 10ms for testing

        call_count = 0

        async def handler(name: str = "") -> ToolResult:
            nonlocal call_count
            call_count += 1
            return ToolResult(success=True, output=f"hello {name}")

        spec = ToolSpec(name="file_read", description="Read file", parameters=[], read_only=True)
        registry.register(spec, handler)

        asyncio.run(registry.execute("run_1", "file_read", {"name": "world"}))
        import time
        time.sleep(0.02)
        asyncio.run(registry.execute("run_1", "file_read", {"name": "world"}))
        assert call_count == 2  # Cache expired, handler called again

    def test_no_cache_for_mutable_tools(self):
        guard = BehaviorGuard(MockSecurityConfig("enforce"), Path("/tmp/workspace"))
        registry = ToolRegistry(type("Limits", (), {"max_concurrent_tools": 10})(), guard)

        call_count = 0

        async def handler(name: str = "") -> ToolResult:
            nonlocal call_count
            call_count += 1
            return ToolResult(success=True, output=f"hello {name}")

        spec = ToolSpec(name="file_write", description="Write file", parameters=[], read_only=False)
        registry.register(spec, handler)

        asyncio.run(registry.execute("run_1", "file_write", {"name": "world"}))
        asyncio.run(registry.execute("run_1", "file_write", {"name": "world"}))
        assert call_count == 2  # No caching for write tools

    def test_failed_results_not_cached(self):
        guard = BehaviorGuard(MockSecurityConfig("enforce"), Path("/tmp/workspace"))
        registry = ToolRegistry(type("Limits", (), {"max_concurrent_tools": 10})(), guard)

        call_count = 0

        async def handler(name: str = "") -> ToolResult:
            nonlocal call_count
            call_count += 1
            return ToolResult(success=False, error="not found")

        spec = ToolSpec(name="file_read", description="Read file", parameters=[], read_only=True)
        registry.register(spec, handler)

        asyncio.run(registry.execute("run_1", "file_read", {"name": "world"}))
        asyncio.run(registry.execute("run_1", "file_read", {"name": "world"}))
        assert call_count == 2  # Failed results are not cached
