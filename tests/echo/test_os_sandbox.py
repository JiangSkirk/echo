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
    attack.write_text("print(open('/private/etc/master.passwd').read())", encoding="utf-8")
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
    attack.write_text(f"open({str(outside)!r}, 'w').write('x')", encoding="utf-8")
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


@pytest.mark.skipif(
    platform.system() != "Darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS sandbox-exec unavailable",
)
@pytest.mark.asyncio
async def test_macos_sandbox_denies_workspace_git_writes(tmp_path: Path) -> None:
    """R3-2: the sandbox profile must deny writes to <workspace>/.git even
    though the rest of the workspace is writable — a planted hook would
    execute on the host's next git invocation, outside the sandbox."""
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    executor = SandboxExecutor(workspace=tmp_path, timeout=15.0)

    result = await executor.execute(
        ["sh", "-c", "echo pwn > .git/hooks/post-checkout"],
        network_allowed=False,
        fs_restricted=True,
    )
    assert result.returncode != 0
    assert not (tmp_path / ".git" / "hooks" / "post-checkout").exists()

    ok = await executor.execute(
        ["sh", "-c", "echo fine > normal.txt"],
        network_allowed=False,
        fs_restricted=True,
    )
    assert ok.returncode == 0
    assert (tmp_path / "normal.txt").read_text() == "fine\n"


def _make_nested_git_layout(workspace: Path) -> tuple[Path, Path]:
    """Create a nested repo ``.git`` directory and a submodule-style gitfile."""
    nested_git = workspace / "sub" / ".git"
    (nested_git / "hooks").mkdir(parents=True)
    gitfile_repo = workspace / "linked"
    gitfile_repo.mkdir()
    gitfile = gitfile_repo / ".git"
    gitfile.write_text("gitdir: ../elsewhere\n", encoding="utf-8")
    return nested_git, gitfile


def test_workspace_git_components_finds_nested_dirs_and_gitfiles(tmp_path: Path) -> None:
    nested_git, gitfile = _make_nested_git_layout(tmp_path)
    (tmp_path / "node_modules" / "dep" / ".git").mkdir(parents=True)

    git_dirs, git_files = os_sandbox._workspace_git_components(tmp_path)

    assert nested_git in git_dirs
    assert gitfile in git_files
    assert not any("node_modules" in path.parts for path in (*git_dirs, *git_files))


def test_macos_profile_denies_nested_git_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nested .git components must get trailing deny rules (subpath for
    directories, literal for gitfiles) after the root .git deny."""
    workspace = tmp_path.resolve()
    nested_git, gitfile = _make_nested_git_layout(workspace)
    executor = SandboxExecutor(workspace=workspace)
    executor._has_sandbox_exec = True
    monkeypatch.setattr("js.echo.os_sandbox.platform.system", lambda: "Darwin")

    wrapped = executor._wrap_filesystem_isolation(["/bin/echo", "ok"], fs_restricted=True)

    assert wrapped[:2] == ["sandbox-exec", "-p"]
    profile = wrapped[2]
    escape = os_sandbox._sandbox_profile_path
    root_deny = f'(deny file-write* (subpath "{escape(workspace / ".git")}"))'
    nested_deny = f'(deny file-write* (subpath "{escape(nested_git)}"))'
    gitfile_deny = f'(deny file-write* (literal "{escape(gitfile)}"))'
    assert root_deny in profile
    assert nested_deny in profile
    assert gitfile_deny in profile
    # SBPL evaluates later rules first: all denies must trail the broad
    # workspace write allow, and nested denies trail the root .git deny.
    assert profile.index(root_deny) > profile.index("(allow file-write*")
    assert profile.index(nested_deny) > profile.index(root_deny)
    assert profile.index(gitfile_deny) > profile.index(root_deny)
    regex_deny = os_sandbox._macos_deny_any_git_write_rule(workspace)
    assert regex_deny in profile
    assert profile.index(regex_deny) > profile.index("(allow file-write*")


def test_linux_bwrap_ro_binds_nested_git_components(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every existing nested .git component gets a --ro-bind after the rw
    workspace bind (later binds take precedence on Linux)."""
    workspace = tmp_path.resolve()
    nested_git, gitfile = _make_nested_git_layout(workspace)
    executor = SandboxExecutor(workspace=workspace)
    executor._has_bwrap = True
    monkeypatch.setattr("js.echo.os_sandbox.platform.system", lambda: "Linux")

    wrapped = executor._wrap_filesystem_isolation(["/bin/echo", "ok"], fs_restricted=True)

    assert wrapped[0] == "bwrap"
    workspace_bind = wrapped.index("--bind")

    def _ro_bind_index(path: Path) -> int:
        target = ["--ro-bind", str(path), str(path)]
        for idx in range(len(wrapped) - 2):
            if wrapped[idx : idx + 3] == target:
                return idx
        return -1

    assert _ro_bind_index(nested_git) > workspace_bind
    assert _ro_bind_index(gitfile) > workspace_bind


def test_macos_profile_regex_denies_uncreated_git_dirs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same-invocation ``mkdir nested/.git`` is not in the snapshot walk, so
    the profile must carry a regex deny that matches any future ``.git``."""
    workspace = tmp_path.resolve()
    executor = SandboxExecutor(workspace=workspace)
    executor._has_sandbox_exec = True
    monkeypatch.setattr("js.echo.os_sandbox.platform.system", lambda: "Darwin")

    wrapped = executor._wrap_filesystem_isolation(["/bin/echo", "ok"], fs_restricted=True)

    assert wrapped[:2] == ["sandbox-exec", "-p"]
    profile = wrapped[2]
    regex_deny = os_sandbox._macos_deny_any_git_write_rule(workspace)
    assert regex_deny in profile
    assert "(?i)" not in regex_deny
    assert profile.index(regex_deny) > profile.index("(allow file-write*")


@pytest.mark.skipif(
    platform.system() != "Darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS sandbox-exec unavailable",
)
def test_macos_sandbox_exec_denies_creating_nested_git(tmp_path: Path) -> None:
    """OS-layer: creating a brand-new nested ``.git`` must fail even when the
    app-layer argv check is skipped (direct sandbox-exec wrap)."""
    import subprocess

    workspace = tmp_path.resolve()
    executor = SandboxExecutor(workspace=workspace, timeout=15.0, strict_isolation=True)
    planted = workspace / "nested" / ".git"
    denied = subprocess.run(
        executor._wrap_filesystem_isolation(
            ["/bin/mkdir", "-p", str(planted)],
            fs_restricted=True,
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert denied.returncode != 0
    assert not planted.exists()

    ok_dir = workspace / "nested" / "ok"
    allowed = subprocess.run(
        executor._wrap_filesystem_isolation(
            ["/bin/mkdir", "-p", str(ok_dir)],
            fs_restricted=True,
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert allowed.returncode == 0
    assert ok_dir.is_dir()

    github = workspace / ".github"
    github_ok = subprocess.run(
        executor._wrap_filesystem_isolation(
            ["/bin/mkdir", "-p", str(github)],
            fs_restricted=True,
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert github_ok.returncode == 0
    assert github.is_dir()


@pytest.mark.skipif(
    platform.system() != "Darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS sandbox-exec unavailable",
)
@pytest.mark.asyncio
async def test_macos_sandbox_denies_nested_git_writes(tmp_path: Path) -> None:
    """R3-2: nested repositories must be as unwritable as the root .git tree —
    a planted nested hook/config would execute on the host's next git run."""
    (tmp_path / "sub" / ".git").mkdir(parents=True)
    executor = SandboxExecutor(workspace=tmp_path, timeout=15.0)

    result = await executor.execute(
        ["sh", "-c", "echo pwn > sub/.git/config"],
        network_allowed=False,
        fs_restricted=True,
    )
    assert result.returncode != 0
    assert not (tmp_path / "sub" / ".git" / "config").exists()

    ok = await executor.execute(
        ["sh", "-c", "echo fine > sub/normal.txt"],
        network_allowed=False,
        fs_restricted=True,
    )
    assert ok.returncode == 0
    assert (tmp_path / "sub" / "normal.txt").read_text() == "fine\n"


@pytest.mark.asyncio
async def test_fs_restricted_denies_parameter_expansion_path_string_form(
    tmp_path: Path,
) -> None:
    executor = SandboxExecutor(workspace=tmp_path, timeout=5.0)

    result = await executor.execute("cat ${X:-/etc/passwd}", fs_restricted=True)

    assert result.returncode == -1
    assert result.killed
    assert "expandable path" in result.stderr.lower()


@pytest.mark.asyncio
async def test_fs_restricted_denies_parameter_expansion_path_list_form(
    tmp_path: Path,
) -> None:
    executor = SandboxExecutor(workspace=tmp_path, timeout=5.0)

    result = await executor.execute(["cat", "${X:-/etc/passwd}"], fs_restricted=True)

    assert result.returncode == -1
    assert result.killed
    assert "expandable path" in result.stderr.lower()


@pytest.mark.asyncio
async def test_fs_restricted_denies_metadata_probe_outside_workspace(
    tmp_path: Path,
) -> None:
    """ls/stat/du/file/readlink must fail closed on paths outside the workspace."""
    executor = SandboxExecutor(workspace=tmp_path, timeout=5.0)

    probes = (
        ["ls", "/etc"],
        ["stat", "/etc/passwd"],
        ["du", "/etc"],
        ["file", "/etc/passwd"],
        ["readlink", "/etc"],
    )
    for probe in probes:
        result = await executor.execute(probe, fs_restricted=True)
        assert result.returncode == -1, probe
        assert result.killed
        assert "outside workspace" in result.stderr.lower()


@pytest.mark.asyncio
async def test_fs_restricted_allows_workspace_listing(tmp_path: Path) -> None:
    """ls with no path argument and ls . stay allowed inside the workspace."""
    (tmp_path / "normal.txt").write_text("fine", encoding="utf-8")
    executor = SandboxExecutor(workspace=tmp_path, timeout=5.0)

    for probe in (["ls"], ["ls", "."]):
        result = await executor.execute(probe, fs_restricted=True)
        assert result.returncode == 0, (probe, result.stderr)
        assert "normal.txt" in result.stdout


def test_git_env_overrides_cover_sequence_editor_and_merge_tool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """forced_pairs gains sequence.editor/merge.tool and GIT_CONFIG_COUNT stays
    in sync with the actual number of KEY/VALUE pairs."""

    class _FakeCompleted:
        stdout = "git version 2.39.3 (Apple Git-145)"
        stderr = ""
        returncode = 0

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: _FakeCompleted())
    executor = SandboxExecutor(workspace=tmp_path)

    overrides = executor._probe_git_env_overrides()

    count = int(overrides["GIT_CONFIG_COUNT"])
    pairs = [
        (overrides[f"GIT_CONFIG_KEY_{index}"], overrides[f"GIT_CONFIG_VALUE_{index}"])
        for index in range(count)
    ]
    assert ("sequence.editor", "") in pairs
    assert ("merge.tool", "") in pairs
    assert f"GIT_CONFIG_KEY_{count}" not in overrides


def test_macos_profile_denies_runtime_tcb_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from js.echo.os_sandbox import _macos_deny_runtime_tcb_write_rules
    from js.security.runtime_tcb import override_runtime_package_root

    workspace = tmp_path.resolve()
    package = workspace / "js"
    (package / "security").mkdir(parents=True)
    (package / "tools").mkdir()
    (package / "tools" / "code.py").write_text("#\n", encoding="utf-8")
    (package / "web" / "static").mkdir(parents=True)
    executor = SandboxExecutor(workspace=workspace)
    executor._has_sandbox_exec = True
    monkeypatch.setattr("js.echo.os_sandbox.platform.system", lambda: "Darwin")

    with override_runtime_package_root(package):
        wrapped = executor._wrap_filesystem_isolation(["/bin/echo", "ok"], fs_restricted=True)
        rules = _macos_deny_runtime_tcb_write_rules(workspace)

    assert wrapped[:2] == ["sandbox-exec", "-p"]
    profile = wrapped[2]
    assert rules
    assert rules in profile
    assert profile.index(rules) > profile.index("(allow file-write*")
    package_deny = f'(deny file-write* (subpath "{package}"))'
    static_allow = f'(allow file-write* (subpath "{package / "web" / "static"}"))'
    assert package_deny in profile
    assert static_allow in profile
    assert profile.index(static_allow) > profile.index(package_deny)


def test_linux_bwrap_ro_binds_package_then_rw_static(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from js.security.runtime_tcb import override_runtime_package_root

    workspace = tmp_path.resolve()
    package = workspace / "js"
    (package / "security").mkdir(parents=True)
    (package / "tools").mkdir()
    code_py = package / "tools" / "code.py"
    code_py.write_text("#\n", encoding="utf-8")
    static_dir = package / "web" / "static"
    static_dir.mkdir(parents=True)
    executor = SandboxExecutor(workspace=workspace)
    executor._has_bwrap = True
    monkeypatch.setattr("js.echo.os_sandbox.platform.system", lambda: "Linux")

    with override_runtime_package_root(package):
        wrapped = executor._wrap_filesystem_isolation(["/bin/echo", "ok"], fs_restricted=True)

    assert wrapped[0] == "bwrap"
    workspace_bind = wrapped.index("--bind")

    def _bind_index(flag: str, path: Path) -> int:
        target = [flag, str(path), str(path)]
        for idx in range(len(wrapped) - 2):
            if wrapped[idx : idx + 3] == target:
                return idx
        return -1

    package_ro = _bind_index("--ro-bind", package)
    static_rw = _bind_index("--bind", static_dir)
    assert package_ro > workspace_bind
    assert static_rw > package_ro


def test_purge_removes_new_git_and_keeps_existing(tmp_path: Path) -> None:
    from js.echo.os_sandbox import _purge_new_git_components, _workspace_git_components

    existing = tmp_path / ".git"
    existing.mkdir()
    (existing / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    before = _workspace_git_components(tmp_path)
    planted_dir = tmp_path / "nested" / ".git"
    planted_dir.mkdir(parents=True)
    (planted_dir / "config").write_text("plant\n", encoding="utf-8")

    planted = _purge_new_git_components(tmp_path, before)

    assert any("nested" in item for item in planted)
    assert not planted_dir.exists()
    assert (existing / "HEAD").read_text(encoding="utf-8") == "ref: refs/heads/main\n"


def test_git_denied_without_env_overrides(tmp_path: Path) -> None:
    executor = SandboxExecutor(workspace=tmp_path, timeout=2.0)
    executor._git_env_overrides = {}
    rejection = executor._fs_restricted_rejection(["git", "status"], fs_restricted=True)
    assert rejection is not None
    assert "2.31" in rejection


def test_reject_if_new_git_metadata_fails_closed(tmp_path: Path) -> None:
    from js.echo.os_sandbox import _workspace_git_components

    executor = SandboxExecutor(workspace=tmp_path, timeout=2.0)
    snapshot = _workspace_git_components(tmp_path)
    planted_dir = tmp_path / "nested" / ".git"
    planted_dir.mkdir(parents=True)
    result = executor._reject_if_new_git_metadata(
        SandboxResult(returncode=0, stdout="ok", stderr="", duration_ms=1.0),
        snapshot,
    )
    assert result.returncode == -1
    assert "newly created .git" in result.stderr
    assert not planted_dir.exists()


def test_process_tree_rss_sums_descendants(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeMemory:
        def __init__(self, rss: int) -> None:
            self.rss = rss

    class FakeChild:
        def memory_info(self) -> FakeMemory:
            return FakeMemory(50 * 1024 * 1024)

    class FakeRoot:
        def memory_info(self) -> FakeMemory:
            return FakeMemory(40 * 1024 * 1024)

        def children(self, *, recursive: bool) -> list[FakeChild]:
            assert recursive is True
            return [FakeChild(), FakeChild()]

    monkeypatch.setattr(os_sandbox.psutil, "Process", lambda _pid: FakeRoot())
    executor = SandboxExecutor(workspace=tmp_path, timeout=2.0)
    assert executor._process_tree_rss(123) == 140 * 1024 * 1024
