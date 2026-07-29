"""F-10: install.sh must fail closed and not swallow install failures."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path


def _write_install_repo(tmp_path: Path, *, with_uv_lock: bool = True) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    if with_uv_lock:
        (repo / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    scripts = repo / "scripts"
    scripts.mkdir()
    src = Path("scripts/install.sh").read_text(encoding="utf-8")
    install = scripts / "install.sh"
    install.write_text(src, encoding="utf-8")
    install.chmod(install.stat().st_mode | stat.S_IXUSR)
    return repo


def test_install_sh_fails_when_uv_sync_fails(tmp_path: Path) -> None:
    repo = _write_install_repo(tmp_path)
    install = repo / "scripts" / "install.sh"
    # Skip python -m venv (host site-packages can InterruptedError); this test
    # asserts fail-closed behavior of `uv sync --frozen` only.
    (repo / ".venv").mkdir()

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    argv_log = tmp_path / "uv-argv.txt"
    fake_uv = bin_dir / "uv"
    fake_uv.write_text(
        f'#!/bin/sh\nprintf "%s\\n" "$@" > "{argv_log}"\necho fake-uv-fail >&2\nexit 42\n',
        encoding="utf-8",
    )
    fake_uv.chmod(fake_uv.stat().st_mode | stat.S_IXUSR)

    # Provide a supported python on PATH for the script's detection.
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
    env["DRY_RUN"] = "0"
    env["OSTYPE"] = "darwin"  # may be ignored; script checks $OSTYPE from bash

    proc = subprocess.run(
        ["bash", str(install)],
        cwd=str(repo),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        input="n\n",
    )
    assert proc.returncode != 0
    combined = proc.stdout + proc.stderr
    assert "安装完成" not in combined
    assert "失败" in combined or "fail" in combined.lower() or proc.returncode == 42
    assert argv_log.is_file(), "fake uv was never invoked"
    recorded = argv_log.read_text(encoding="utf-8").strip().splitlines()
    # argv after the uv binary must be exactly sync --frozen
    assert recorded == ["sync", "--frozen"], f"expected `uv sync --frozen`, got {recorded!r}"


def test_install_sh_dry_run_fails_without_uv_lock(tmp_path: Path) -> None:
    repo = _write_install_repo(tmp_path, with_uv_lock=False)
    install = repo / "scripts" / "install.sh"

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_uv = bin_dir / "uv"
    fake_uv.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_uv.chmod(fake_uv.stat().st_mode | stat.S_IXUSR)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
    env["DRY_RUN"] = "1"

    proc = subprocess.run(
        ["bash", str(install)],
        cwd=str(repo),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        input="n\n",
    )
    assert proc.returncode != 0
    combined = proc.stdout + proc.stderr
    assert "uv.lock" in combined
    assert "所有前置检查通过" not in combined


def test_install_sh_remote_mode_fail_closed(tmp_path: Path) -> None:
    # Script without adjacent pyproject.toml enters remote mode and must exit non-zero.
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    src = Path("scripts/install.sh").read_text(encoding="utf-8")
    install = scripts / "install.sh"
    install.write_text(src, encoding="utf-8")
    install.chmod(install.stat().st_mode | stat.S_IXUSR)
    proc = subprocess.run(
        ["bash", str(install)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=10,
        input="n\n",
    )
    assert proc.returncode != 0
    assert "远程" in (proc.stdout + proc.stderr) or "remote" in (proc.stdout + proc.stderr).lower()


def test_install_sh_dry_run_empty_home_and_offline_path(tmp_path: Path) -> None:
    """Empty HOME + no network tooling: DRY_RUN must still validate uv/uv.lock.

    Does not invent checksums/signatures; remote/clean-install without a local
    repo remains fail-closed (covered by ``test_install_sh_remote_mode_fail_closed``).
    """
    repo = _write_install_repo(tmp_path)
    install = repo / "scripts" / "install.sh"

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_uv = bin_dir / "uv"
    fake_uv.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_uv.chmod(fake_uv.stat().st_mode | stat.S_IXUSR)

    # Point PATH at fake uv + the real Python that can satisfy the version check.
    import shutil

    python_bin = shutil.which("python3.12") or shutil.which("python3")
    assert python_bin is not None
    python_dir = str(Path(python_bin).resolve().parent)

    empty_home = tmp_path / "empty-home"
    empty_home.mkdir()
    # Intentionally omit curl/wget from PATH so DRY_RUN cannot fetch anything.
    env = {
        "PATH": f"{bin_dir}:{python_dir}:/usr/bin:/bin",
        "HOME": str(empty_home),
        "DRY_RUN": "1",
        "OSTYPE": "darwin23",
    }

    proc = subprocess.run(
        ["bash", str(install)],
        cwd=str(repo),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        input="n\n",
    )
    combined = proc.stdout + proc.stderr
    assert proc.returncode == 0, combined
    assert "所有前置检查通过" in combined
    # Must not claim success before the uv/lock gate (ordering check).
    uv_idx = combined.find("uv.lock")
    if uv_idx < 0:
        uv_idx = combined.find("uv 已安装")
    pass_idx = combined.find("所有前置检查通过")
    assert uv_idx >= 0
    assert pass_idx > uv_idx
    # Offline: no attempt to fetch an installer via curl|sh.
    assert "curl|sh" not in combined and "curl |" not in combined.lower()
