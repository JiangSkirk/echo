from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

IMPORT_CHECK = """
import importlib.util
import js.echo
import js_work.web

assert importlib.util.find_spec("js.rivetline") is None
assert importlib.util.find_spec("js.agent_core") is None
"""


def clean_environment() -> dict[str, str]:
    env = os.environ.copy()
    for name in (
        "PYTHONHOME",
        "PYTHONPATH",
        "PIP_NO_INDEX",
        "PIP_FIND_LINKS",
        "PIP_CONFIG_FILE",
        "PIP_REQUIRE_VIRTUALENV",
    ):
        env.pop(name, None)
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


def find_wheel(artifact_dir: Path) -> Path:
    wheels = sorted(artifact_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(
            f"Expected exactly one wheel in {artifact_dir}, found {len(wheels)}."
        )
    return wheels[0]


def verify_wheel(wheel: Path, venv_dir: Path, *, audit: bool = False) -> None:
    env = clean_environment()
    env["HOME"] = str(venv_dir)
    env["XDG_CONFIG_HOME"] = str(venv_dir / ".config")
    env["XDG_STATE_HOME"] = str(venv_dir / ".local" / "state")
    python = venv_dir / "bin" / "python"
    commands = (
        ([sys.executable, "-m", "venv", str(venv_dir)], venv_dir.parent),
        ([str(python), "-m", "pip", "--isolated", "install", "--upgrade", "pip"], venv_dir),
        ([str(python), "-m", "pip", "--isolated", "install", str(wheel)], venv_dir),
        ([str(venv_dir / "bin" / "js"), "--help"], venv_dir),
        ([str(venv_dir / "bin" / "js"), "work", "--help"], venv_dir),
        ([str(venv_dir / "bin" / "js-work"), "--help"], venv_dir),
        ([str(python), "-m", "js_work", "--help"], venv_dir),
        ([str(python), "-c", IMPORT_CHECK], venv_dir),
    )
    for command, cwd in commands:
        subprocess.run(command, cwd=cwd, env=env, check=True)
    if audit:
        audit_installed_dependencies(venv_dir, env)


def audit_installed_dependencies(venv_dir: Path, env: dict[str, str]) -> None:
    """Audit the wheel's clean installation, not the repository development environment."""
    audit_venv = venv_dir.parent / "audit"
    audit_python = audit_venv / "bin" / "python"
    site_packages = (
        venv_dir
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    commands = (
        ([sys.executable, "-m", "venv", str(audit_venv)], audit_venv.parent),
        ([str(audit_python), "-m", "pip", "--isolated", "install", "pip-audit"], audit_venv),
        (
            [
                str(audit_python),
                "-m",
                "pip_audit",
                "--path",
                str(site_packages),
                "--desc",
                "--format=json",
            ],
            audit_venv,
        ),
    )
    for command, cwd in commands:
        subprocess.run(command, cwd=cwd, env=env, check=True)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify that a built wheel works when installed into a clean virtual environment."
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        required=True,
        help="Directory containing exactly one built wheel.",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Audit the installed wheel dependency set from a separate disposable auditor venv.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    wheel = find_wheel(args.artifact_dir)
    with tempfile.TemporaryDirectory(prefix="js-agent-installed-") as temporary_dir:
        verify_wheel(wheel.resolve(), Path(temporary_dir) / "venv", audit=args.audit)


if __name__ == "__main__":
    main()
