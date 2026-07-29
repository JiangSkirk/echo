from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from js.rl.code_fix import CodeFixEnv


def _task(tmp_path: Path) -> Path:
    task = tmp_path / "task"
    task.mkdir()
    (task / "main.py").write_text("def answer(): return 42\n", encoding="utf-8")
    (task / "test_main.py").write_text(
        "from main import answer\n\ndef test_answer(): assert answer() == 42\n",
        encoding="utf-8",
    )
    return task


def test_code_fix_fails_closed_without_strict_os_sandbox(
    tmp_path: Path,
    monkeypatch,
) -> None:
    env = CodeFixEnv(_task(tmp_path))
    env.reset()
    env._sandbox = SimpleNamespace(  # type: ignore[attr-defined]
        network_isolation_available=lambda: False,
        filesystem_isolation_available=lambda: False,
    )
    host_run = MagicMock(side_effect=AssertionError("host subprocess must not run"))
    monkeypatch.setattr(subprocess, "run", host_run)

    passed, output = env._run_tests()

    assert passed is False
    assert "strict OS sandbox" in output
    host_run.assert_not_called()
    env.close()


def test_code_fix_executes_tests_only_through_strict_sandbox(tmp_path: Path) -> None:
    env = CodeFixEnv(_task(tmp_path))
    env.reset()
    sandbox = SimpleNamespace(
        network_isolation_available=lambda: True,
        filesystem_isolation_available=lambda: True,
        execute=AsyncMock(
            return_value=SimpleNamespace(
                returncode=0,
                stdout="1 passed",
                stderr="",
            )
        ),
    )
    env._sandbox = sandbox  # type: ignore[attr-defined]

    passed, output = env._run_tests()

    assert passed is True
    assert output == "1 passed"
    command = sandbox.execute.await_args.args[0]
    assert command[:3] == [sys.executable, "-m", "pytest"]
    assert sandbox.execute.await_args.kwargs["network_allowed"] is False
    assert sandbox.execute.await_args.kwargs["fs_restricted"] is True
    env.close()


def test_code_fix_edit_cannot_escape_or_follow_symlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("private = True\n", encoding="utf-8")
    env = CodeFixEnv(_task(tmp_path))
    env.reset()

    absolute_result = env.step(
        {"type": "edit", "file": str(outside), "content": "private = False\n"}
    )
    assert "rejected" in absolute_result.info["action"].lower()
    assert outside.read_text(encoding="utf-8") == "private = True\n"

    assert env._source_file is not None
    source = env._source_file
    source.unlink()
    source.symlink_to(outside)
    symlink_result = env.step(
        {"type": "edit", "file": source.name, "content": "private = False\n"}
    )

    assert "rejected" in symlink_result.info["action"].lower()
    assert outside.read_text(encoding="utf-8") == "private = True\n"
    env.close()
