"""Canonical Echo OS sandbox smoke tests (async SandboxExecutor)."""

from __future__ import annotations

import platform
import shutil
import sys
from pathlib import Path

import pytest

import js.echo.os_sandbox as os_sandbox
import js.security.sandbox as security_sandbox
from js.echo.os_sandbox import SandboxExecutor, SandboxResult


def test_security_reexports_canonical_sandbox_types() -> None:
    assert security_sandbox.SandboxExecutor is os_sandbox.SandboxExecutor
    assert security_sandbox.SandboxResult is os_sandbox.SandboxResult


@pytest.mark.asyncio
async def test_workspace_echo_succeeds(tmp_path: Path) -> None:
    executor = SandboxExecutor(workspace=tmp_path, timeout=5.0)

    result = await executor.execute(["/bin/echo", "hello"])

    assert isinstance(result, SandboxResult)
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"
    assert not result.killed


@pytest.mark.asyncio
async def test_cwd_parent_escape_fails_closed(tmp_path: Path) -> None:
    executor = SandboxExecutor(workspace=tmp_path, timeout=5.0)

    result = await executor.execute(["/bin/echo", "blocked"], cwd="..")

    assert result.returncode == -1
    assert result.killed
    assert "cwd denied" in result.stderr.lower()


@pytest.mark.asyncio
async def test_fs_restricted_denies_etc_hosts_and_kills(tmp_path: Path) -> None:
    executor = SandboxExecutor(workspace=tmp_path, timeout=5.0)

    result = await executor.execute(["/bin/cat", "/etc/hosts"], fs_restricted=True)

    assert result.returncode == -1
    assert result.killed
    assert "outside workspace" in result.stderr.lower()


@pytest.mark.asyncio
async def test_fs_restricted_denies_relative_parent_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_text("secret", encoding="utf-8")
    executor = SandboxExecutor(workspace=tmp_path, timeout=5.0)

    result = await executor.execute(f"cat ../{outside.name}", fs_restricted=True)

    assert result.returncode == -1
    assert result.killed
    assert "outside workspace" in result.stderr.lower()
    assert "secret" not in result.stdout


@pytest.mark.asyncio
async def test_fs_restricted_denies_workspace_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "symlink-secret.txt"
    outside.write_text("secret-through-link", encoding="utf-8")
    (tmp_path / "link.txt").symlink_to(outside)
    executor = SandboxExecutor(workspace=tmp_path, timeout=5.0)

    result = await executor.execute(["/bin/cat", "link.txt"], fs_restricted=True)

    assert result.returncode == -1
    assert result.killed
    assert "outside workspace" in result.stderr.lower()
    assert "secret-through-link" not in result.stdout


@pytest.mark.asyncio
async def test_fs_restricted_denies_shell_c_path_escape(tmp_path: Path) -> None:
    executor = SandboxExecutor(workspace=tmp_path, timeout=5.0)

    result = await executor.execute(
        ["/bin/sh", "-c", "cat /etc/hosts"],
        fs_restricted=True,
    )

    assert result.returncode == -1
    assert result.killed
    assert "outside workspace" in result.stderr.lower()


@pytest.mark.asyncio
async def test_macos_profiles_are_fail_closed_not_allow_default() -> None:
    """F-08: both macOS sandbox-exec profiles must start from (deny default)."""
    assert "(deny default)" in os_sandbox._MACOS_NETWORK_DENY_PROFILE
    assert "(deny default)" in os_sandbox._MACOS_FS_RESTRICT_PROFILE
    assert "(allow default)" not in os_sandbox._MACOS_NETWORK_DENY_PROFILE
    assert "(allow default)" not in os_sandbox._MACOS_FS_RESTRICT_PROFILE


@pytest.mark.skipif(
    platform.system() != "Darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS sandbox-exec unavailable",
)
@pytest.mark.asyncio
async def test_macos_deny_default_profile_blocks_passwd_read_and_outside_write(
    tmp_path: Path,
) -> None:
    """F-08: sandboxed code cannot read /private/etc/master.passwd or write
    outside the workspace/HOME even though the interpreter itself runs."""
    executor = SandboxExecutor(
        workspace=tmp_path,
        timeout=15.0,
        trusted_executables=[Path(sys.executable)],
    )

    script = tmp_path / "ok.py"
    script.write_text("print('python-ok')", encoding="utf-8")
    result = await executor.execute(
        [sys.executable, str(script)],
        network_allowed=False,
        fs_restricted=True,
    )
    assert result.returncode == 0, result.stderr
    assert "python-ok" in result.stdout

    attack = tmp_path / "attack.py"
    attack.write_text(
        "print(open('/private/etc/master.passwd').read())", encoding="utf-8"
    )
    result = await executor.execute(
        [sys.executable, str(attack)],
        network_allowed=False,
        fs_restricted=True,
    )
    assert result.returncode != 0
    assert "nobody" not in result.stdout

    outside = tmp_path.parent / "sandbox-escape-write"
    if outside.exists():
        outside.unlink()
    attack.write_text(
        f"open({str(outside)!r}, 'w').write('x')", encoding="utf-8"
    )
    result = await executor.execute(
        [sys.executable, str(attack)],
        network_allowed=False,
        fs_restricted=True,
    )
    assert result.returncode != 0
    assert not outside.exists()


@pytest.mark.skipif(
    platform.system() != "Darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS sandbox-exec unavailable",
)
@pytest.mark.asyncio
async def test_macos_network_profile_also_denies_sensitive_reads(
    tmp_path: Path,
) -> None:
    """F-08: the network-isolation profile is deny-default as well."""
    executor = SandboxExecutor(workspace=tmp_path, timeout=5.0)

    result = await executor.execute(
        ["/bin/cat", "/private/etc/master.passwd"],
        network_allowed=False,
    )

    assert result.returncode != 0
    assert "nobody" not in result.stdout


@pytest.mark.asyncio
async def test_sandbox_home_is_private_directory_not_workspace(
    tmp_path: Path,
) -> None:
    """F-13: HOME is a sandbox-private dir under the workspace temp area."""
    executor = SandboxExecutor(workspace=tmp_path, timeout=5.0)

    env = executor._build_env()

    home = Path(env["HOME"])
    assert home != tmp_path.resolve()
    assert home == tmp_path.resolve() / ".echo-tmp" / "home"
    assert home.is_dir()


def test_linux_unshare_mount_namespace_is_not_claimed_as_fs_isolation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = SandboxExecutor(workspace=tmp_path, strict_isolation=True)
    executor._has_unshare = True
    executor._has_bwrap = False
    monkeypatch.setattr("js.echo.os_sandbox.platform.system", lambda: "Linux")

    with pytest.raises(RuntimeError, match="Filesystem isolation requested"):
        executor._wrap_filesystem_isolation(["/bin/echo", "ok"], fs_restricted=True)


@pytest.mark.asyncio
async def test_timeout_kills_process(tmp_path: Path) -> None:
    executor = SandboxExecutor(workspace=tmp_path, timeout=0.2)

    result = await executor.execute(["/bin/sleep", "10"])

    assert result.killed
    assert result.returncode == -9


@pytest.mark.asyncio
async def test_output_limit_is_enforced_in_bytes(tmp_path: Path) -> None:
    executor = SandboxExecutor(workspace=tmp_path, timeout=5.0, max_output_bytes=4)

    result = await executor.execute(
        [sys.executable, "-c", "import sys; sys.stdout.write('你' * 3)"]
    )

    assert "[output truncated]" in result.stdout
