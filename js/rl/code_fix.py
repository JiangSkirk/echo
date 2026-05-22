"""Code-fix environment: agent must fix a bug given a failing test."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any

from js.rl.env import BaseAgentEnv, EnvironmentStep
from js.utils.log import get_logger

logger = get_logger("js.rl.code_fix")


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

        self._source_file = next(self._workspace.glob("*.py"))
        self._test_file = next(self._workspace.glob("test_*.py"))

        source_code = self._source_file.read_text(encoding="utf-8")
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
            target = self._workspace / file_name
            target.write_text(content, encoding="utf-8")
            info["action"] = f"Edited {file_name}"

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

        Uses multiple strategies: pytest → unittest → direct exec.
        """
        if not self._test_file or not self._workspace:
            return False, "No test file or workspace"

        # Strategy 1: pytest
        try:
            result = subprocess.run(
                ["python", "-m", "pytest", str(self._test_file), "-v", "--tb=short"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(self._workspace),
            )
            # Check if pytest is actually installed
            if "no module named pytest" in result.stderr.lower():
                pass  # pytest not available, fall through
            else:
                passed = result.returncode == 0
                return passed, result.stdout + result.stderr
        except FileNotFoundError:
            pass
        except Exception:
            pass

        # Strategy 2: direct exec — import and run test functions
        test_script = f"""
import sys, traceback
sys.path.insert(0, "{self._workspace}")
try:
    import {self._test_file.stem} as test_module
    failures = []
    for name in dir(test_module):
        obj = getattr(test_module, name)
        if callable(obj) and name.startswith("test_"):
            try:
                obj()
            except Exception as e:
                failures.append(f"{{name}}: {{e}}")
    if failures:
        print("FAILURES:")
        for f in failures:
            print(f)
        sys.exit(1)
    else:
        print(f"OK: {{len([n for n in dir(test_module) if n.startswith('test_')])}} tests passed")
        sys.exit(0)
except Exception as e:
    traceback.print_exc()
    sys.exit(1)
"""
        try:
            result = subprocess.run(
                ["python", "-c", test_script],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(self._workspace),
            )
            passed = result.returncode == 0
            return passed, result.stdout + result.stderr
        except Exception as e:
            return False, str(e)

    def _build_observation(self) -> dict[str, Any]:
        source = ""
        if self._source_file and self._source_file.exists():
            source = self._source_file.read_text(encoding="utf-8")
        return {
            "source_code": source,
            "tests_passed": self._tests_passed,
            "step": self._step_count,
            "max_steps": self._max_steps,
            "last_test_output": self._last_test_output,
        }

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
