from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path

import pytest


def _verifier_module():
    return importlib.import_module("scripts.verify_installed_artifact")


def test_verify_wheel_uses_clean_venv_and_normal_dependency_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    verifier = _verifier_module()
    wheel = tmp_path / "js_agent-0.1.5-py3-none-any.whl"
    wheel.touch()
    venv_dir = tmp_path / "installed"
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(verifier.subprocess, "run", fake_run)
    monkeypatch.setenv("PYTHONPATH", "/source/tree")
    monkeypatch.setenv("PIP_NO_INDEX", "1")

    verifier.verify_wheel(wheel, venv_dir)

    commands = [command for command, _ in calls]
    assert commands[0] == [sys.executable, "-m", "venv", str(venv_dir)]

    bootstrap_pip = commands[1]
    assert bootstrap_pip == [
        str(venv_dir / "bin" / "python"),
        "-m",
        "pip",
        "--isolated",
        "install",
        "--upgrade",
        "pip",
    ]

    install = commands[2]
    assert install == [
        str(venv_dir / "bin" / "python"),
        "-m",
        "pip",
        "--isolated",
        "install",
        str(wheel),
    ]
    assert "--no-deps" not in install
    assert "--no-index" not in install

    assert commands[3] == [str(venv_dir / "bin" / "js"), "--help"]
    assert commands[4] == [str(venv_dir / "bin" / "js"), "work", "--help"]
    assert commands[5] == [str(venv_dir / "bin" / "js-work"), "--help"]
    assert commands[6] == [str(venv_dir / "bin" / "python"), "-m", "js_work", "--help"]
    assert commands[7][:2] == [str(venv_dir / "bin" / "python"), "-c"]
    import_check = commands[7][2]
    assert "import js.echo" in import_check
    assert "import js_work.web" in import_check
    assert "js.rivetline" in import_check
    assert "js.agent_core" in import_check

    for index, (_, kwargs) in enumerate(calls[:8]):
        env = kwargs["env"]
        assert isinstance(env, dict)
        assert "PYTHONPATH" not in env
        assert "PIP_NO_INDEX" not in env
        assert "PIP_CONFIG_FILE" not in env
        assert env["HOME"] == str(venv_dir)
        assert env["XDG_CONFIG_HOME"] == str(venv_dir / ".config")
        assert env["XDG_STATE_HOME"] == str(venv_dir / ".local" / "state")
        assert kwargs["cwd"] == (venv_dir.parent if index == 0 else venv_dir)


def test_find_wheel_requires_exactly_one_wheel(tmp_path: Path) -> None:
    verifier = _verifier_module()
    (tmp_path / "first.whl").touch()
    (tmp_path / "second.whl").touch()

    with pytest.raises(RuntimeError, match="exactly one wheel"):
        verifier.find_wheel(tmp_path)


def test_verify_wheel_audits_only_the_clean_installed_artifact_site_packages(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    verifier = _verifier_module()
    wheel = tmp_path / "js_agent-0.1.5-py3-none-any.whl"
    wheel.touch()
    venv_dir = tmp_path / "installed"
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(verifier.subprocess, "run", fake_run)

    verifier.verify_wheel(wheel, venv_dir, audit=True)

    audit_command = next(command for command, _ in calls if "pip_audit" in command)
    assert audit_command[:3] == [str(venv_dir.parent / "audit" / "bin" / "python"), "-m", "pip_audit"]
    assert "--path" in audit_command
    assert str(venv_dir) in audit_command[audit_command.index("--path") + 1]
    assert "--local" not in audit_command
