"""Code-fix environment: agent must fix a bug given a failing test."""

from __future__ import annotations

import asyncio
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

from js.echo.os_sandbox import SandboxExecutor, SandboxResult
from js.rl.env import BaseAgentEnv, EnvironmentStep
from js.utils.log import get_logger

logger = get_logger("js.rl.code_fix")

_MAX_CODE_BYTES = 1_000_000


class CodeFixEnv(BaseAgentEnv):
    """Minimal SWE-like environment.

    The agent is given:
      - A Python file with a bug
      - A test file that fails
      - A task description

    The agent must edit the code so all tests pass.
    """

    def __init__(self, task_dir: Path | None = None) -> None:
        self.task_dir = task_dir
        self._workspace: Path | None = None
        self._source_file: Path | None = None
        self._test_file: Path | None = None
        self._step_count = 0
        self._max_steps = 20
        self._last_test_output = ""
        self._tests_passed = False
        self._sandbox: SandboxExecutor | None = None

    @property
    def name(self) -> str:
        return "code_fix"

    def reset(
        self, *, seed: int | None = None, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Create a fresh workspace with the buggy code."""
        self._step_count = 0
        self._tests_passed = False
        self._last_test_output = ""

        # Use provided task_dir or create a synthetic task
        if self.task_dir and self.task_dir.exists():
            self._workspace = Path(tempfile.mkdtemp(prefix="js_rl_"))
            # Copy files to temp workspace
            for f in self.task_dir.iterdir():
                if f.is_file():
                    import shutil
                    shutil.copy2(f, self._workspace / f.name)
        else:
            self._workspace = self._create_synthetic_task()

        self._sandbox = SandboxExecutor(
            self._workspace,
            timeout=30.0,
            max_output_bytes=50_000,
            max_memory_mb=512,
            strict_isolation=True,
            trusted_executables=[Path(sys.executable)],
        )

        self._test_file = next(self._workspace.glob("test_*.py"))
        self._source_file = next(
            path
            for path in self._workspace.glob("*.py")
            if not path.name.startswith("test_")
        )

        source_code = self._read_source_safely()
        test_code = self._test_file.read_text(encoding="utf-8")

        return {
            "task": "Fix the bug so all tests pass.",
            "source_file": str(self._source_file.name),
            "source_code": source_code,
            "test_file": str(self._test_file.name),
            "test_code": test_code,
            "tests_passed": False,
            "step": 0,
            "max_steps": self._max_steps,
        }

    def step(self, action: dict[str, Any]) -> EnvironmentStep:
        """Execute an action: {type: "edit", file: "...", content: "..."} or {type: "test"}."""
        self._step_count += 1
        action_type = action.get("type", "noop")
        reward = -0.1  # Small time penalty per step
        terminated = False
        info: dict[str, Any] = {"step": self._step_count}

        if action_type == "edit":
            file_name = action.get("file", self._source_file.name if self._source_file else "main.py")
            content = action.get("content", "")
            if self._apply_edit(file_name, content):
                info["action"] = "Edited copied source file"
            else:
                info["action"] = "Edit rejected by code-fix boundary"

        elif action_type == "test":
            passed, output = self._run_tests()
            self._tests_passed = passed
            self._last_test_output = output
            info["test_output"] = output
            info["tests_passed"] = passed
            if passed:
                reward = 1.0  # Success!
                terminated = True
            else:
                reward = -0.2  # Failed tests penalty

        elif action_type == "noop":
            info["action"] = "No operation"

        # Check max steps
        truncated = self._step_count >= self._max_steps
        if truncated and not terminated:
            reward = -1.0  # Timeout penalty

        obs = self._build_observation()
        return EnvironmentStep(
            observation=obs,
            reward=reward,
            terminated=terminated,
            truncated=truncated,
            info=info,
        )

    def close(self) -> None:
        if self._workspace and self._workspace.exists():
            import shutil
            shutil.rmtree(self._workspace, ignore_errors=True)

    def _run_tests(self) -> tuple[bool, str]:
        """Run tests and return (all_passed, output).

        Untrusted task code runs only behind strict filesystem and network
        isolation.  Missing isolation is a hard failure, never a host fallback.
        """
        if not self._test_file or not self._workspace:
            return False, "No test file or workspace"
        sandbox = self._sandbox
        if (
            sandbox is None
            or not sandbox.network_isolation_available()
            or not sandbox.filesystem_isolation_available()
        ):
            return False, "Code-fix tests require a strict OS sandbox"

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            return False, "Code-fix tests must run in the isolated worker thread"

        result = self._run_sandboxed(
            [
                sys.executable,
                "-m",
                "pytest",
                str(self._test_file),
                "-v",
                "--tb=short",
            ]
        )
        if result is None:
            return False, "Code-fix sandbox execution failed safely"
        output = self._safe_test_output(result.stdout + result.stderr)
        return result.returncode == 0, output

    def _run_sandboxed(self, command: list[str]) -> SandboxResult | None:
        sandbox = self._sandbox
        if sandbox is None or self._workspace is None:
            return None
        try:
            return asyncio.run(
                sandbox.execute(
                    command,
                    cwd=str(self._workspace),
                    timeout=30.0,
                    network_allowed=False,
                    fs_restricted=True,
                )
            )
        except Exception as exc:
            logger.warning("Code-fix sandbox failed: %s", type(exc).__name__)
            return None

    def _safe_test_output(self, output: str) -> str:
        if self._workspace is not None:
            output = output.replace(str(self._workspace), "<workspace>")
        return output[:50_000]

    def _build_observation(self) -> dict[str, Any]:
        source = self._read_source_safely()
        return {
            "source_code": source,
            "tests_passed": self._tests_passed,
            "step": self._step_count,
            "max_steps": self._max_steps,
            "last_test_output": self._last_test_output,
        }

    def _apply_edit(self, file_name: object, content: object) -> bool:
        """Edit only the copied source file through a no-follow descriptor."""
        if (
            self._workspace is None
            or self._source_file is None
            or not isinstance(file_name, str)
            or not isinstance(content, str)
        ):
            return False
        relative = Path(file_name)
        if relative.is_absolute() or relative.parts != (self._source_file.name,):
            return False
        payload = content.encode("utf-8")
        if len(payload) > _MAX_CODE_BYTES:
            return False
        required = (os.open, os.stat)
        if (
            not hasattr(os, "O_DIRECTORY")
            or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_CLOEXEC")
            or any(function not in os.supports_dir_fd for function in required)
        ):
            return False
        directory_fd = os.open(
            self._workspace,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            metadata = os.stat(
                self._source_file.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                return False
            fd = os.open(
                self._source_file.name,
                os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            try:
                opened = os.fstat(fd)
                if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                    return False
                view = memoryview(payload)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        return False
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            return True
        except OSError as exc:
            logger.warning("Code-fix edit rejected: %s", type(exc).__name__)
            return False
        finally:
            os.close(directory_fd)

    def _read_source_safely(self) -> str:
        if self._workspace is None or self._source_file is None:
            return ""
        try:
            fd = os.open(
                self._source_file,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            try:
                metadata = os.fstat(fd)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_size > _MAX_CODE_BYTES
                ):
                    return ""
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = os.read(fd, min(65_536, _MAX_CODE_BYTES + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > _MAX_CODE_BYTES:
                        return ""
                return b"".join(chunks).decode("utf-8", errors="replace")
            finally:
                os.close(fd)
        except OSError as exc:
            logger.warning("Code-fix source read rejected: %s", type(exc).__name__)
            return ""

    def _create_synthetic_task(self) -> Path:
        """Create a simple synthetic bug-fixing task for demonstration."""
        ws = Path(tempfile.mkdtemp(prefix="js_rl_synthetic_"))
        # Buggy code: factorial uses wrong base case (returns 0 instead of 1 for n=0)
        (ws / "math_utils.py").write_text(
            "def factorial(n):\n"
            "    if n == 0:\n"
            "        return 0  # BUG: should return 1\n"
            "    return n * factorial(n - 1)\n",
            encoding="utf-8",
        )
        (ws / "test_math_utils.py").write_text(
            "from math_utils import factorial\n\n"
            "def test_factorial():\n"
            "    assert factorial(0) == 1\n"
            "    assert factorial(1) == 1\n"
            "    assert factorial(5) == 120\n"
            "    assert factorial(7) == 5040\n",
            encoding="utf-8",
        )
        return ws
