"""Fuzz tests for BehaviorGuard — randomized/mutated inputs.

Goal: discover crashes or unexpected ALLOW decisions on malformed input.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from js.config import SecurityConfig
from js.security.guard import BehaviorGuard, SecurityDecisionType


class TestFuzzCommandGuard:
    """Fuzz BehaviorGuard.check_command with random/mutated strings."""

    @pytest.fixture
    def guard(self, tmp_path: Path) -> BehaviorGuard:
        return BehaviorGuard(SecurityConfig(defense_mode="enforce"), tmp_path)

    @pytest.mark.parametrize(
        "command",
        [
            "",  # empty
            "   ",  # whitespace only
            "\x00\x01\x02",  # binary garbage
            "rm" * 1000,  # pathological repetition
            "a" * 10000,  # very long string
            ";" * 500,  # shell metachar flood
            "$(" * 100,  # unbalanced subshell
            "`" * 100,  # backtick flood
            "|" * 100,  # pipe flood
            "&" * 100,  # ampersand flood
            "." * 1000,  # dot flood (path traversal attempt)
            "../" * 100,  # deep relative path
            "\n" * 50 + "rm -rf /" + "\n" * 50,  # multiline with payload
            "\t" * 50 + "dd if=/dev/zero of=/dev/sda" + "\t" * 50,
            # Unicode variants
            "ｒｍ　－ｒｆ　／",  # fullwidth
            "𝓇𝓂 -𝓇𝒻 /",  # math script
            "𝔯𝔪 -𝔯𝔣 /",  # fraktur
        ],
    )
    def test_fuzz_does_not_crash(self, guard: BehaviorGuard, command: str) -> None:
        """All fuzz inputs must be handled without exception."""
        try:
            result = guard.check_command(command)
            # Result must be a valid decision enum member
            assert result.decision in (
                SecurityDecisionType.ALLOW,
                SecurityDecisionType.WARN,
                SecurityDecisionType.BLOCK,
            )
        except Exception as e:
            pytest.fail(f"Fuzz input crashed guard: {repr(command[:50])}... error: {e}")

    def test_fuzz_random_bytes_survive(self, guard: BehaviorGuard) -> None:
        """Random byte strings must not crash the guard."""
        import random
        random.seed(42)
        for _ in range(100):
            length = random.randint(0, 500)
            payload = bytes(random.randint(0, 255) for _ in range(length))
            try:
                result = guard.check_command(payload.decode("utf-8", errors="replace"))
                assert result.decision in (
                    SecurityDecisionType.ALLOW,
                    SecurityDecisionType.WARN,
                    SecurityDecisionType.BLOCK,
                )
            except Exception as e:
                pytest.fail(f"Random bytes crashed guard: error: {e}")


class TestFuzzPathGuard:
    """Fuzz BehaviorGuard.check_path_operation with malformed paths."""

    @pytest.fixture
    def guard(self, tmp_path: Path) -> BehaviorGuard:
        return BehaviorGuard(SecurityConfig(defense_mode="enforce"), tmp_path)

    @pytest.mark.parametrize(
        "path",
        [
            "",
            "   ",
            "/",
            "//",
            "/../" * 50,
            "." * 1000,
            "\x00",
            "\n",
            "file\x00.txt",
            "C:\\" * 50,  # Windows-style
            "\\\\server\\share",  # UNC path
            "file://etc/passwd",
            "data:text/plain,evil",
            "http://evil.com/../../etc/passwd",
        ],
    )
    def test_fuzz_path_does_not_crash(self, guard: BehaviorGuard, path: str) -> None:
        """All fuzz paths must be handled without exception."""
        for operation in ("read", "write", "delete", "list"):
            try:
                result = guard.check_path_operation(path, operation)
                assert result.decision in (
                    SecurityDecisionType.ALLOW,
                    SecurityDecisionType.WARN,
                    SecurityDecisionType.BLOCK,
                )
            except Exception as e:
                pytest.fail(
                    f"Fuzz path crashed guard: path={repr(path[:50])} op={operation} error: {e}"
                )


class TestFuzzLoopGuard:
    """Fuzz loop guard with edge-case identifiers."""

    @pytest.fixture
    def guard(self, tmp_path: Path) -> BehaviorGuard:
        return BehaviorGuard(SecurityConfig(defense_mode="enforce"), tmp_path)

    @pytest.mark.parametrize(
        "run_id,tool_name,args_key",
        [
            ("", "", ""),
            ("a" * 10000, "b" * 10000, "c" * 10000),
            ("\x00", "\x00", "\x00"),
            ("run:id:_with:colons", "tool/name", "args\nkey"),
        ],
    )
    def test_fuzz_loop_guard_does_not_crash(
        self,
        guard: BehaviorGuard,
        run_id: str,
        tool_name: str,
        args_key: str,
    ) -> None:
        """Loop guard must handle extreme identifiers."""
        try:
            result = guard.check_loop(run_id, tool_name, args_key)
            assert result.decision in (
                SecurityDecisionType.ALLOW,
                SecurityDecisionType.WARN,
                SecurityDecisionType.BLOCK,
            )
        except Exception as e:
            pytest.fail(f"Loop guard crash: run_id={repr(run_id[:20])} error: {e}")

    def test_loop_counter_unbounded_growth(self, guard: BehaviorGuard) -> None:
        """Loop counters must not grow unbounded — they auto-prune at 10k."""
        for i in range(11_000):
            guard.check_loop(f"run-{i}", "tool", "args")
        # After 11k unique keys, counter should have been cleared at least once
        assert len(guard._loop_counters) <= 10_000
