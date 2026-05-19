"""Tests for security subsystem."""

from pathlib import Path

import pytest

from js.config import SecurityConfig
from js.security.guard import BehaviorGuard, SecurityDecisionType
from js.security.sandbox import SandboxExecutor
from js.security.secrets import SecretManager


class TestBehaviorGuard:
    def test_high_risk_command_blocked(self, tmp_path: Path) -> None:
        config = SecurityConfig()
        guard = BehaviorGuard(config, tmp_path)

        result = guard.check_command("rm -rf /")
        assert result.decision == SecurityDecisionType.BLOCK

    def test_safe_command_allowed(self, tmp_path: Path) -> None:
        config = SecurityConfig()
        guard = BehaviorGuard(config, tmp_path)

        result = guard.check_command("ls -la")
        assert result.decision == SecurityDecisionType.ALLOW

    def test_protected_path_blocked(self, tmp_path: Path) -> None:
        config = SecurityConfig()
        guard = BehaviorGuard(config, tmp_path)

        result = guard.check_path_operation("/etc/passwd", "write")
        assert result.decision == SecurityDecisionType.BLOCK

    def test_workspace_delete_allowed(self, tmp_path: Path) -> None:
        config = SecurityConfig(allow_workspace_delete=False)
        guard = BehaviorGuard(config, tmp_path)

        result = guard.check_path_operation("/tmp/test.txt", "delete")
        assert result.decision == SecurityDecisionType.BLOCK

    def test_loop_detection(self, tmp_path: Path) -> None:
        config = SecurityConfig(max_loop_iterations=5)
        guard = BehaviorGuard(config, tmp_path)

        # First 2 calls should be allowed
        result = guard.check_loop("run1", "shell", "ls")
        assert result.decision == SecurityDecisionType.ALLOW
        result = guard.check_loop("run1", "shell", "ls")
        assert result.decision == SecurityDecisionType.ALLOW

        # 3rd call triggers warning (count=3 > 5//2=2)
        result = guard.check_loop("run1", "shell", "ls")
        assert result.decision == SecurityDecisionType.WARN

        # 6th call triggers block
        guard.check_loop("run1", "shell", "ls")
        guard.check_loop("run1", "shell", "ls")
        result = guard.check_loop("run1", "shell", "ls")
        assert result.decision == SecurityDecisionType.BLOCK


class TestSecretManager:
    def test_detect_openai_key(self, tmp_path: Path) -> None:
        sm = SecretManager(tmp_path)
        text = "My key is sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
        result = sm.detect_and_redact(text)
        assert "[REDACTED" in result
        assert "sk-" not in result

    def test_store_and_retrieve(self, tmp_path: Path) -> None:
        sm = SecretManager(tmp_path)
        sm.store("test_key", "secret_value")
        retrieved = sm.retrieve("test_key")
        assert retrieved == "secret_value"


class TestSandbox:
    @pytest.mark.asyncio
    async def test_basic_execution(self, tmp_path: Path) -> None:
        executor = SandboxExecutor(tmp_path)
        result = await executor.execute("echo hello")
        assert result.returncode == 0
        assert "hello" in result.stdout

    @pytest.mark.asyncio
    async def test_timeout(self, tmp_path: Path) -> None:
        executor = SandboxExecutor(tmp_path, timeout=0.5)
        result = await executor.execute("sleep 10")
        assert result.killed
        assert result.returncode != 0
