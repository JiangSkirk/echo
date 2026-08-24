"""Sandboxed execution environment for untrusted commands."""

from __future__ import annotations

import asyncio
import os
import platform
import re
import shlex
import shutil
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

from js.utils.log import get_logger

logger = get_logger("js.echo.os_sandbox")

_STDOUT_TRUNCATE_MARKER = "\n... [output truncated]"
_STDERR_TRUNCATE_MARKER = "\n... [stderr truncated]"
_STREAM_READ_CHUNK = 65_536
_SAFE_ENV_KEYS = frozenset(
    {
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "NO_COLOR",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONIOENCODING",
        "TERM",
        "TZ",
    }
)

# Bounded scan for nested repositories: noisy dependency directories are
# skipped and both depth and result count are capped so building the sandbox
# profile stays cheap even on huge workspaces.
_GIT_SCAN_SKIP_DIRS = frozenset({"node_modules", ".venv", ".echo-tmp"})
_GIT_SCAN_MAX_DEPTH = 6
_GIT_SCAN_MAX_ENTRIES = 128
# Path-shaped writers whose positional args must not name a ``.git``
# component.  Interpreters (python/node/...) are excluded: their argv
# can mention ``.git`` in a script without planting metadata.
_GIT_METADATA_FS_WRITE_COMMANDS = frozenset(
    {
        "cp",
        "install",
        "mkdir",
        "mv",
        "rm",
        "tee",
        "touch",
    }
)


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    duration_ms: float
    killed: bool = False
    oom_killed: bool = False
    # Parent-observed PID captured immediately after create_subprocess_exec().
    # This is evidence metadata only; callers must not treat child output as
    # authoritative for process identity.
    spawned_pid: int | None = None


# Shared macOS sandbox whitelist fragment: both profiles start fail-closed
# with ``(deny default)`` and only grant what a sandboxed interpreter needs:
# process execution, read-only runtime dependencies (dyld shared cache,
# system frameworks, /usr toolchain), workspace + private temp dir writes,
# and the standard devices.  Sensitive paths such as /private/etc are
# deliberately NOT readable.
# Residual risk: ``mach-lookup`` / ``file-ioctl`` / ``sysctl-read`` are granted
# broadly because macOS dyld refuses to launch any binary without them; the
# seatbelt profile language cannot scope them further.
_MACOS_BASE_ALLOW_RULES = """
(allow process-exec process-fork)
(allow file-read-metadata)
(allow file-read-xattr)
(allow file-ioctl)
(allow mach-lookup)
(allow sysctl-read)
(allow file-read-data
    (literal "/")
    (literal "/private")
    (literal "/private/var")
    (subpath "{workspace}")
    (subpath "/System")
    (subpath "/usr")
    (subpath "/opt")
    (subpath "/Library")
    (subpath "/private/var/db")
    (subpath "/dev")
{extra_read_paths})
(allow file-write*
    (subpath "{workspace}")
    (subpath "{sandbox_tmp}")
    (literal "/dev/null")
    (literal "/dev/stdout")
    (literal "/dev/stderr")
    (literal "/dev/urandom")
    (literal "/dev/zero"))
"""

# macOS sandbox profile that blocks all network access.  Filesystem access is
# also fail-closed: reads are limited to runtime dependencies and the
# workspace, writes to the workspace and its private temp directory.
_MACOS_NETWORK_DENY_PROFILE = (
    "(version 1)\n(deny default)\n(deny network*)\n" + _MACOS_BASE_ALLOW_RULES
)

# macOS sandbox profile that permits workspace reads plus runtime dependencies.
_MACOS_FS_RESTRICT_PROFILE = (
    "(version 1)\n(deny default)\n(deny network*)\n" + _MACOS_BASE_ALLOW_RULES
)


class SandboxExecutor:
    """Execute commands with resource limits and isolation."""

    def __init__(
        self,
        workspace: Path,
        timeout: float = 300.0,
        max_output_bytes: int = 50_000,
        max_memory_mb: int = 1024,
        env_passthrough: list[str] | None = None,
        strict_isolation: bool = False,
        trusted_executables: list[Path] | None = None,
    ) -> None:
        self.workspace = workspace.resolve()
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes
        self.max_memory_mb = max_memory_mb
        self.env_passthrough = env_passthrough or ["LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ"]
        self.strict_isolation = strict_isolation
        self._trusted_executables: set[Path] = set()
        # Read-only roots the sandbox profiles must grant so a trusted
        # interpreter can start: the resolved binary's directory plus the
        # virtualenv root (pyvenv.cfg marker) when the launcher lives in
        # <venv>/bin.  Without these a deny-default profile cannot even
        # import the ``site`` module.
        self._trusted_read_roots: set[Path] = set()
        for executable in trusted_executables or []:
            raw = executable.expanduser()
            try:
                resolved = raw.resolve()
            except (OSError, RuntimeError):
                continue
            self._trusted_executables.add(resolved)
            for candidate in (raw, resolved):
                bindir = candidate.parent
                venv_root = bindir.parent
                try:
                    if (venv_root / "pyvenv.cfg").is_file():
                        self._trusted_read_roots.add(venv_root.resolve())
                    else:
                        self._trusted_read_roots.add(bindir)
                except (OSError, RuntimeError):
                    continue
        self._has_sandbox_exec = shutil.which("sandbox-exec") is not None
        self._has_unshare = shutil.which("unshare") is not None
        self._has_bwrap = shutil.which("bwrap") is not None
        # Lazily probed once per executor: git env overrides that neutralize
        # repo-level config execution hooks (core.hooksPath / core.fsmonitor /
        # diff.external / core.pager / core.editor / core.sshCommand /
        # core.gitProxy / credential.helper). ``None`` means "not probed yet".
        self._git_env_overrides: dict[str, str] | None = None

    def network_isolation_available(self) -> bool:
        """Return whether the current platform has an enforced network backend."""
        system = platform.system()
        return (system == "Darwin" and self._has_sandbox_exec) or (
            system == "Linux" and self._has_unshare
        )

    def filesystem_isolation_available(self) -> bool:
        """Return whether the current platform has an enforced filesystem backend."""
        system = platform.system()
        return (system == "Darwin" and self._has_sandbox_exec) or (
            system == "Linux" and self._has_bwrap
        )

    def _reject_if_new_git_metadata(
        self,
        result: SandboxResult,
        snapshot: tuple[tuple[Path, ...], tuple[Path, ...]] | None,
    ) -> SandboxResult:
        """Fail closed if the command planted a ``.git`` tree mid-invocation.

        Linux bwrap can only ro-bind ``.git`` paths that existed at wrap
        time.  Interpreters are excluded from argv ``.git`` token scans, so
        a CODE skill could otherwise leave host-executing git metadata.
        """
        if snapshot is None:
            return result
        planted = _purge_new_git_components(self.workspace, snapshot)
        if not planted:
            return result
        return SandboxResult(
            returncode=-1,
            stdout="",
            stderr="Sandbox rejected newly created .git metadata: " + ", ".join(planted[:8]),
            duration_ms=result.duration_ms,
            killed=True,
            spawned_pid=result.spawned_pid,
        )

    def _build_env(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Build a restricted environment."""
        env: dict[str, str] = {}
        for key in self.env_passthrough:
            if key in _SAFE_ENV_KEYS and key in os.environ:
                env[key] = os.environ[key]
        if extra:
            for key, value in extra.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    continue
                if key in _SAFE_ENV_KEYS or key == "JS_SKILL_ARGS" or key.startswith("JS_ARG_"):
                    env[key] = value[:65_536]
        trusted_path_dirs = [Path("/usr/bin"), Path("/bin"), Path("/usr/sbin"), Path("/sbin")]
        homebrew_bin = Path("/opt/homebrew/bin")
        if homebrew_bin.is_dir():
            trusted_path_dirs.append(homebrew_bin)
        trusted_path_dirs.extend(executable.parent for executable in self._trusted_executables)
        env["PATH"] = os.pathsep.join(dict.fromkeys(str(path) for path in trusted_path_dirs))
        # HOME is a sandbox-private directory, never the real user home and
        # never the workspace root itself, so dotfiles/ssh/agent config under
        # the host HOME cannot leak into (or be written by) sandboxed runs.
        home_dir = self._sandbox_home_dir()
        home_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(home_dir, 0o700)
        env["HOME"] = str(home_dir)
        env["USER"] = "echo-sandbox"
        env["PWD"] = str(self.workspace)
        env["JS_SKILL_WORKSPACE"] = str(self.workspace)
        temp_dir = self._sandbox_temp_dir()
        temp_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(temp_dir, 0o700)
        env["TMPDIR"] = str(temp_dir)
        env.update(self._git_sandbox_env_overrides())
        return env

    def _git_sandbox_env_overrides(self) -> dict[str, str]:
        """Env overrides that neutralize repo-level git config execution hooks.

        The sandbox-private HOME already hides ``~/.gitconfig``, but a repo
        inside the workspace can still carry a hostile ``.git/config``
        (``core.hooksPath``, ``core.fsmonitor``, ``diff.external``,
        ``core.pager``, ``core.editor``, ``core.sshCommand``, ``core.gitProxy``,
        ``credential.helper``) that an innocent-looking ``git status`` would
        execute.  Injecting fixed ``GIT_CONFIG_*`` environment pairs overrides
        the on-disk values.
        """
        if self._git_env_overrides is None:
            self._git_env_overrides = self._probe_git_env_overrides()
        return dict(self._git_env_overrides)

    def _probe_git_env_overrides(self) -> dict[str, str]:
        """Build the git override set, gated on git >= 2.31.

        ``GIT_CONFIG_NOSYSTEM`` / ``GIT_CONFIG_GLOBAL`` / the
        ``GIT_CONFIG_COUNT``+``GIT_CONFIG_KEY_n``/``GIT_CONFIG_VALUE_n``
        mechanism all require git 2.31+.  Older or missing git keeps the
        previous behavior (no injection) — fail-open here means status quo,
        with the OS sandbox still containing any hook that does fire.
        GIT_CONFIG_COUNT must exactly match the number of KEY/VALUE pairs or
        every git invocation errors out, so the pairs are built from one list.
        """
        import subprocess

        try:
            result = subprocess.run(
                ["git", "--version"],
                capture_output=True,
                text=True,
                timeout=2,
            )
        except (OSError, subprocess.SubprocessError):
            return {}
        version = self._parse_git_version(result.stdout)
        if version is None or version < (2, 31):
            logger.info(
                "git >= 2.31 not found (detected: %s); sandbox git config overrides disabled",
                result.stdout.strip() or "unavailable",
            )
            return {}

        forced_pairs = [
            # Repo hooks (pre-commit et al.) never execute inside the sandbox.
            ("core.hooksPath", os.devnull),
            # A repo-configured fsmonitor hook command must not run on status.
            ("core.fsmonitor", ""),
            # A repo-configured external diff driver must not run on diff.
            ("diff.external", ""),
            # A repo-configured pager/editor must never spawn inside the sandbox.
            ("core.pager", ""),
            ("core.editor", ""),
            # Repo-configured rebase -i editor / mergetool must not run either.
            ("sequence.editor", ""),
            ("merge.tool", ""),
            # Repo-configured SSH/proxy wrappers must not run on fetch/clone.
            ("core.sshCommand", ""),
            ("core.gitProxy", ""),
            # Repo-configured credential helpers must not run (credential theft).
            ("credential.helper", ""),
        ]
        overrides: dict[str, str] = {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": str(len(forced_pairs)),
        }
        for index, (key, value) in enumerate(forced_pairs):
            overrides[f"GIT_CONFIG_KEY_{index}"] = key
            overrides[f"GIT_CONFIG_VALUE_{index}"] = value
        return overrides

    @staticmethod
    def _parse_git_version(text: str) -> tuple[int, int] | None:
        """Parse ``git version 2.39.3 (Apple Git-145)`` into ``(2, 39)``."""
        match = re.search(r"(\d+)\.(\d+)", text)
        if match is None:
            return None
        return int(match.group(1)), int(match.group(2))

    def _sandbox_temp_dir(self) -> Path:
        """Private temp directory shared by every sandboxed run."""
        return self.workspace / ".echo-tmp"

    def _sandbox_home_dir(self) -> Path:
        """Sandbox-private HOME; lives under the private temp directory."""
        return self._sandbox_temp_dir() / "home"

    def _wrap_network_isolation(
        self,
        cmd: list[str],
        network_allowed: bool = True,
    ) -> list[str]:
        """Wrap command with network isolation if requested and tools available."""
        if network_allowed:
            return cmd
        system = platform.system()
        if system == "Darwin" and self._has_sandbox_exec:
            # macOS: use sandbox-exec with a fail-closed profile denying network
            trusted_rules = "\n".join(
                f'            (subpath "{_sandbox_profile_path(path)}")'
                for path in sorted(self._trusted_read_roots)
                if not _path_is_within(path, self.workspace)
            )
            profile = _MACOS_NETWORK_DENY_PROFILE.format(
                workspace=_sandbox_profile_path(self.workspace),
                sandbox_tmp=_sandbox_profile_path(self._sandbox_temp_dir()),
                extra_read_paths=trusted_rules,
            )
            return [
                "sandbox-exec",
                "-p",
                profile,
                *cmd,
            ]
        if system == "Linux" and self._has_unshare:
            # Linux: unshare network namespace (no interfaces = no outbound)
            return ["unshare", "-n", *cmd]
        # Fail-closed: when strict isolation is required, block execution
        if self.strict_isolation:
            raise RuntimeError(
                f"Network isolation requested but no sandbox tool available "
                f"(platform={system}, sandbox-exec={self._has_sandbox_exec}, "
                f"unshare={self._has_unshare})"
            )
        logger.warning(
            "Network isolation requested but no sandbox tool available "
            "(platform=%s, sandbox-exec=%s, unshare=%s)",
            system,
            self._has_sandbox_exec,
            self._has_unshare,
        )
        return cmd

    def _wrap_filesystem_isolation(
        self,
        cmd: list[str],
        fs_restricted: bool = False,
        read_only_paths: tuple[Path, ...] = (),
        network_allowed: bool = True,
    ) -> list[str]:
        """Wrap command with filesystem isolation if requested and tools available."""
        if not fs_restricted:
            return cmd
        system = platform.system()
        if system == "Darwin" and self._has_sandbox_exec:
            read_rules = "\n".join(
                f'            (subpath "{_sandbox_profile_path(path)}")' for path in read_only_paths
            )
            traversal_rules = "\n".join(
                f'            (literal "{_sandbox_profile_path(path)}")'
                for path in _sandbox_traversal_paths((self.workspace, *read_only_paths))
            )
            trusted_rules = "\n".join(
                f'            (subpath "{_sandbox_profile_path(path)}")'
                for path in sorted(self._trusted_read_roots)
                if not _path_is_within(path, self.workspace)
            )
            extra_read_paths = "\n".join(
                rule for rule in (traversal_rules, read_rules, trusted_rules) if rule
            )
            profile = _MACOS_FS_RESTRICT_PROFILE.format(
                workspace=_sandbox_profile_path(self.workspace),
                sandbox_tmp=_sandbox_profile_path(self._sandbox_temp_dir()),
                extra_read_paths=extra_read_paths,
            )
            # R3-2: never let the sandboxed process write the workspace's
            # .git tree — a planted hook or core.fsmonitor config would
            # execute OUTSIDE the sandbox on the host's next git invocation.
            # SBPL evaluates later rules first, so this trailing deny wins
            # over the broad workspace write allow above.
            profile += (
                '\n(deny file-write* (subpath "'
                + _sandbox_profile_path(self.workspace / ".git")
                + '"))\n'
            )
            # R3-2 extended: the root-only deny left nested repositories
            # (e.g. sub/.git/config) writable for the same host-executing
            # plant attack, so deny every .git component found under the
            # workspace (bounded walk).  These trailing denies keep the
            # later-rule-wins ordering over the workspace write allow.
            git_dirs, git_files = _workspace_git_components(self.workspace)
            for nested_git_dir in git_dirs:
                profile += (
                    '\n(deny file-write* (subpath "'
                    + _sandbox_profile_path(nested_git_dir)
                    + '"))\n'
                )
            for nested_git_file in git_files:
                profile += (
                    '\n(deny file-write* (literal "'
                    + _sandbox_profile_path(nested_git_file)
                    + '"))\n'
                )
            # Snapshot subpath/literal denies only cover `.git` trees that
            # already exist when the profile is built.  A same-invocation
            # ``mkdir nested/.git && mv cfg nested/.git/config`` (or tar
            # extract) would otherwise plant host-executing git metadata.
            # This trailing regex matches any `.git` component under the
            # workspace, including directories created mid-command.
            profile += _macos_deny_any_git_write_rule(self.workspace)
            profile += _macos_deny_runtime_tcb_write_rules(self.workspace)
            return [
                "sandbox-exec",
                "-p",
                profile,
                *cmd,
            ]
        if system == "Linux" and self._has_bwrap:
            wrapped = [
                "bwrap",
                "--die-with-parent",
                "--new-session",
                "--unshare-user-try",
                "--unshare-pid",
                "--unshare-ipc",
                "--unshare-uts",
                "--unshare-cgroup-try",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
            ]
            if not network_allowed:
                wrapped.append("--unshare-net")
            for system_root in ("/usr", "/bin", "/lib", "/lib64", "/sbin"):
                if Path(system_root).exists():
                    wrapped.extend(("--ro-bind", system_root, system_root))
            for read_only_path in read_only_paths:
                wrapped.extend(("--ro-bind", str(read_only_path), str(read_only_path)))
            wrapped.extend(
                (
                    "--bind",
                    str(self.workspace),
                    str(self.workspace),
                    "--chdir",
                    str(self.workspace),
                    "--setenv",
                    "HOME",
                    str(self._sandbox_home_dir()),
                )
            )
            # R3-2: remount every .git component under the workspace read-only
            # (root and nested repositories, directories and gitfiles alike)
            # so a sandboxed process cannot plant hooks/config that would
            # execute on the host's next git invocation.  The ro-binds must
            # come after the rw workspace bind to take precedence on Linux.
            git_dirs, git_files = _workspace_git_components(self.workspace)
            for git_component in (*git_dirs, *git_files):
                if git_component.exists():
                    wrapped.extend(("--ro-bind", str(git_component), str(git_component)))
            from js.security.runtime_tcb import (
                workspace_tcb_allow_targets,
                workspace_tcb_deny_targets,
            )

            for tcb_path, _is_dir in workspace_tcb_deny_targets(self.workspace):
                if tcb_path.exists():
                    wrapped.extend(("--ro-bind", str(tcb_path), str(tcb_path)))
            # Later binds win: re-open dogfood static as writable after the
            # package-wide read-only remount.
            for allow_path, _is_dir in workspace_tcb_allow_targets(self.workspace):
                if allow_path.exists():
                    wrapped.extend(("--bind", str(allow_path), str(allow_path)))
            wrapped.extend(("--", *cmd))
            return wrapped
        # Fail-closed: when strict isolation is required, block execution
        if self.strict_isolation:
            raise RuntimeError(
                f"Filesystem isolation requested but no sandbox tool available "
                f"(platform={system}, sandbox-exec={self._has_sandbox_exec}, "
                f"unshare={self._has_unshare})"
            )
        logger.warning(
            "Filesystem isolation requested but no sandbox tool available "
            "(platform=%s, sandbox-exec=%s, unshare=%s)",
            system,
            self._has_sandbox_exec,
            self._has_unshare,
        )
        return cmd

    async def execute(
        self,
        command: str | list[str],
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        stdin: str | None = None,
        timeout: float | None = None,
        network_allowed: bool = True,
        fs_restricted: bool = False,
        read_only_paths: list[Path] | tuple[Path, ...] | None = None,
    ) -> SandboxResult:
        """Execute a command in sandboxed environment."""
        import time

        start_time = time.monotonic()
        effective_timeout = timeout if timeout is not None else self.timeout

        normalized_read_paths, read_path_error = self._normalize_read_only_paths(read_only_paths)
        if read_path_error is not None:
            return SandboxResult(
                returncode=-1,
                stdout="",
                stderr=read_path_error,
                duration_ms=(time.monotonic() - start_time) * 1000,
                killed=True,
            )
        if normalized_read_paths and (not fs_restricted or not self.strict_isolation):
            return SandboxResult(
                returncode=-1,
                stdout="",
                stderr="Read-only sandbox roots require strict filesystem isolation",
                duration_ms=(time.monotonic() - start_time) * 1000,
                killed=True,
            )

        work_dir, cwd_error = self.resolve_cwd(cwd, read_only_paths=normalized_read_paths)
        if cwd_error is not None or work_dir is None:
            return SandboxResult(
                returncode=-1,
                stdout="",
                stderr=cwd_error or "Sandbox cwd denied",
                duration_ms=(time.monotonic() - start_time) * 1000,
                killed=True,
            )

        rejection = self._fs_restricted_rejection(
            command,
            fs_restricted=fs_restricted,
            read_only_paths=normalized_read_paths,
        )
        if rejection is not None:
            return SandboxResult(
                returncode=-1,
                stdout="",
                stderr=rejection,
                duration_ms=(time.monotonic() - start_time) * 1000,
                killed=True,
            )

        git_snapshot = _workspace_git_components(self.workspace) if fs_restricted else None

        if isinstance(command, str):
            # Use shell for complex commands, but carefully
            # Cross-platform: use sh on Unix, cmd /c on Windows
            if platform.system() == "Windows":
                cmd = ["cmd", "/c", command]
            else:
                cmd = ["sh", "-c", command]
        else:
            cmd = list(command)

        # Avoid nested sandbox launchers: filesystem backends can enforce the
        # network restriction in the same process boundary.
        combined_isolation = fs_restricted and (
            (platform.system() == "Darwin" and self._has_sandbox_exec)
            or (platform.system() == "Linux" and self._has_bwrap)
        )
        if not combined_isolation:
            cmd = self._wrap_network_isolation(cmd, network_allowed=network_allowed)
        cmd = self._wrap_filesystem_isolation(
            cmd,
            fs_restricted=fs_restricted,
            read_only_paths=normalized_read_paths,
            network_allowed=network_allowed,
        )

        work_dir.mkdir(parents=True, exist_ok=True)

        built_env = self._build_env(env)

        proc: asyncio.subprocess.Process | None = None
        memory_task: asyncio.Task[bool] | None = None
        stdout_task: asyncio.Task[tuple[bytes, bool]] | None = None
        stderr_task: asyncio.Task[tuple[bytes, bool]] | None = None
        killed = False
        oom_killed = False
        returncode = 0

        try:
            popen_kwargs: dict[str, Any] = {
                "stdout": asyncio.subprocess.PIPE,
                "stderr": asyncio.subprocess.PIPE,
                "stdin": asyncio.subprocess.PIPE if stdin else None,
                "cwd": str(work_dir),
                "env": built_env,
            }
            # POSIX: isolate into a new session/process group so kill path can
            # terminate the whole tree. Windows keeps default spawn semantics.
            if os.name == "posix":
                popen_kwargs["start_new_session"] = True

            # Hard memory cap in the child where the platform supports it.
            rlimit_preexec = self._memory_rlimit_preexec()
            if rlimit_preexec is not None:
                popen_kwargs["preexec_fn"] = rlimit_preexec

            proc = await asyncio.create_subprocess_exec(*cmd, **popen_kwargs)

            if self.max_memory_mb > 0:
                memory_task = asyncio.create_task(self._monitor_memory(proc, self.max_memory_mb))

            # Concurrent bounded readers: cap retained bytes, keep draining pipes
            # so a chatty child cannot block on a full pipe buffer.
            if proc.stdout is not None:
                stdout_task = asyncio.create_task(
                    self._bounded_stream_read(proc.stdout, self.max_output_bytes)
                )
            if proc.stderr is not None:
                stderr_task = asyncio.create_task(
                    self._bounded_stream_read(proc.stderr, self.max_output_bytes)
                )

            if stdin is not None and proc.stdin is not None:
                try:
                    proc.stdin.write(stdin.encode())
                    await proc.stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    proc.stdin.close()

            try:
                await asyncio.wait_for(proc.wait(), timeout=effective_timeout)
                returncode = proc.returncode if proc.returncode is not None else 0
            except TimeoutError:
                killed = True
                self._kill_process_tree(proc)
                await self._reap_process(proc)
                # Cross-platform: SIGKILL (-9) is recognized on Unix and Windows
                returncode = -9

            stdout_bytes, stdout_truncated = await self._await_stream_task(stdout_task)
            stderr_bytes, stderr_truncated = await self._await_stream_task(stderr_task)
            stdout_task = None
            stderr_task = None

            oom_killed = await self._finalize_memory_task(memory_task)
            memory_task = None

            if killed:
                stdout = ""
                stderr = "Command timed out"
            else:
                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")
                if stdout_truncated:
                    stdout = stdout + _STDOUT_TRUNCATE_MARKER
                if stderr_truncated:
                    stderr = stderr + _STDERR_TRUNCATE_MARKER

            duration_ms = (time.monotonic() - start_time) * 1000

            return self._reject_if_new_git_metadata(
                SandboxResult(
                    returncode=returncode,
                    stdout=stdout,
                    stderr=stderr,
                    duration_ms=duration_ms,
                    killed=killed,
                    oom_killed=oom_killed,
                    spawned_pid=proc.pid,
                ),
                git_snapshot,
            )

        except Exception as e:
            duration_ms = (time.monotonic() - start_time) * 1000
            if proc is not None:
                self._kill_process_tree(proc)
                await self._reap_process(proc)
            return self._reject_if_new_git_metadata(
                SandboxResult(
                    returncode=-1,
                    stdout="",
                    stderr=f"Execution error: {e}",
                    duration_ms=duration_ms,
                    killed=True,
                    spawned_pid=proc.pid if proc is not None else None,
                ),
                git_snapshot,
            )
        finally:
            # No task/process leaks on normal, timeout, or exception paths.
            await self._cancel_tasks(stdout_task, stderr_task, memory_task)
            if proc is not None and proc.returncode is None:
                self._kill_process_tree(proc)
                await self._reap_process(proc)

    async def _bounded_stream_read(
        self,
        stream: asyncio.StreamReader,
        max_bytes: int,
    ) -> tuple[bytes, bool]:
        """Read a stream, retaining at most ``max_bytes`` while always draining.

        Byte-counted (not character-counted). Once the cap is hit, further data
        is discarded but still consumed so the child cannot block on a full pipe.
        """
        if max_bytes <= 0:
            while await stream.read(_STREAM_READ_CHUNK):
                pass
            return b"", True

        kept: list[bytes] = []
        kept_len = 0
        truncated = False
        while True:
            chunk = await stream.read(_STREAM_READ_CHUNK)
            if not chunk:
                break
            if truncated:
                continue
            room = max_bytes - kept_len
            if len(chunk) <= room:
                kept.append(chunk)
                kept_len += len(chunk)
            else:
                if room > 0:
                    kept.append(chunk[:room])
                    kept_len = max_bytes
                truncated = True
        return b"".join(kept), truncated

    async def _await_stream_task(
        self,
        task: asyncio.Task[tuple[bytes, bool]] | None,
    ) -> tuple[bytes, bool]:
        if task is None:
            return b"", False
        try:
            return await task
        except asyncio.CancelledError:
            return b"", False
        except Exception:
            logger.debug("Sandbox stream reader failed", exc_info=True)
            return b"", False

    async def _finalize_memory_task(
        self,
        memory_task: asyncio.Task[bool] | None,
    ) -> bool:
        if memory_task is None:
            return False
        if not memory_task.done():
            memory_task.cancel()
        try:
            return bool(await memory_task)
        except asyncio.CancelledError:
            return False
        except Exception:
            logger.debug("Sandbox memory monitor failed", exc_info=True)
            return False

    async def _cancel_tasks(self, *tasks: asyncio.Task[Any] | None) -> None:
        pending = [task for task in tasks if task is not None and not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    async def _reap_process(
        self,
        proc: asyncio.subprocess.Process,
        timeout: float = 5.0,
    ) -> None:
        """Await the subprocess so it cannot remain a zombie."""
        if proc.returncode is not None:
            return
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except TimeoutError:
            try:
                proc.kill()
            except (ProcessLookupError, OSError, PermissionError):
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=1.0)
            except TimeoutError:
                logger.warning("Failed to reap sandbox process pid=%s", proc.pid)

    def _memory_rlimit_preexec(self) -> Any:
        """Return a preexec hook applying an RLIMIT_AS hard memory cap.

        The psutil polling monitor (:meth:`_monitor_memory`) has an inherent
        ~0.5s race window; a setrlimit hard cap closes it where the platform
        enforces RLIMIT_AS (Linux).  macOS accepts but does not enforce
        RLIMIT_AS, so there we record the degradation once and keep the
        polling monitor as the only enforcement layer (fail-visible, not
        fail-silent).
        """
        if self.max_memory_mb <= 0 or os.name != "posix":
            return None
        try:
            import resource
        except ImportError:
            return None
        if not hasattr(resource, "RLIMIT_AS"):
            return None
        if platform.system() == "Darwin":
            if not getattr(self, "_rlimit_degradation_logged", False):
                self._rlimit_degradation_logged = True
                logger.info(
                    "RLIMIT_AS is not enforced on macOS; sandbox memory cap "
                    "relies on the psutil polling monitor"
                )
            return None
        limit_bytes = self.max_memory_mb * 1024 * 1024

        def _apply_rlimit() -> None:
            try:
                resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))
            except (OSError, ValueError):
                # Kernel refused the cap; the polling monitor remains as the
                # fallback enforcement layer.
                pass

        return _apply_rlimit

    async def _monitor_memory(self, proc: asyncio.subprocess.Process, max_mb: int) -> bool:
        """Monitor process memory and kill if it exceeds limit."""
        max_bytes = max_mb * 1024 * 1024
        try:
            while proc.returncode is None:
                await asyncio.sleep(0.5)
                try:
                    p = psutil.Process(proc.pid)
                    mem_info = p.memory_info()
                    if mem_info.rss > max_bytes:
                        self._kill_process_tree(proc)
                        return True
                except psutil.NoSuchProcess:
                    break
        except asyncio.CancelledError:
            # Task was cancelled (normal when the monitored process exits);
            # swallow silently so the caller's await does not re-raise.
            return False
        return False

    def _kill_process_tree(self, proc: asyncio.subprocess.Process) -> None:
        """Kill a process and all its children.

        On POSIX the child is started in its own process group; prefer
        killing the whole group. Then fall back to a psutil tree walk and
        ``proc.kill()`` so Windows and partial failures remain covered.
        """
        if proc.pid and os.name == "posix":
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass

        try:
            parent = psutil.Process(proc.pid)
            try:
                children = parent.children(recursive=True)
            except (psutil.AccessDenied, PermissionError, OSError, psutil.Error):
                children = []
            for child in children:
                try:
                    child.terminate()
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    PermissionError,
                    OSError,
                    psutil.Error,
                ):
                    pass
            try:
                parent.terminate()
            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                PermissionError,
                OSError,
                psutil.Error,
            ):
                pass
            # Wait briefly, then force kill
            try:
                _gone, alive = psutil.wait_procs(children + [parent], timeout=2)
                for p in alive:
                    try:
                        p.kill()
                    except (
                        psutil.NoSuchProcess,
                        psutil.AccessDenied,
                        PermissionError,
                        OSError,
                        psutil.Error,
                    ):
                        pass
            except (psutil.Error, OSError):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, OSError, psutil.Error):
            pass

        # Ultimate fallback: kill via asyncio subprocess API
        try:
            proc.kill()
        except (ProcessLookupError, OSError, PermissionError):
            pass

    def _fs_restricted_rejection(
        self,
        command: str | list[str],
        *,
        fs_restricted: bool,
        read_only_paths: tuple[Path, ...] = (),
        _shell_depth: int = 0,
    ) -> str | None:
        if not fs_restricted:
            return None
        from js.security.runtime_tcb import token_is_runtime_tcb_write

        if isinstance(command, str):
            try:
                tokens = shlex.split(command)
            except ValueError as exc:
                return f"Filesystem restricted command rejected: {exc}"
        else:
            tokens = [str(part) for part in command]
        if not tokens:
            return None

        read_command_names = {
            "cat",
            "head",
            "tail",
            "less",
            "more",
            "grep",
            "rg",
            "sed",
            "awk",
            "ls",
            "stat",
            "du",
            "file",
            "readlink",
            # Remaining allowlisted readers: every positional path they take is
            # checked against the workspace too (metadata/content probes).
            "cut",
            "diff",
            "jq",
            "sort",
            "test",
            "tr",
            "uniq",
            "wc",
        }
        write_command_names = {
            "cp",
            "install",
            "mkdir",
            "mv",
            "python",
            "python3",
            "rm",
            "ruby",
            "node",
            "perl",
            "tee",
            "touch",
        }
        # Interpreters stay in write_command_names (their argv may embed
        # paths) but are not scanned for a `.git` path component: a
        # ``python -c`` snippet that merely mentions ``.git`` is not a
        # filesystem plant.  Path-shaped write commands are.
        shell_command_names = {"bash", "sh", "zsh"}
        redirects = {">", ">>", "1>", "1>>", "2>", "2>>", "&>"}
        command_name = Path(tokens[0]).name
        if command_name in shell_command_names and "-c" in tokens:
            if _shell_depth >= 3:
                return "Filesystem restricted command rejected: nested shell depth exceeded"
            shell_index = tokens.index("-c")
            if shell_index + 1 >= len(tokens):
                return "Filesystem restricted command rejected: shell -c requires a script"
            nested_rejection = self._fs_restricted_rejection(
                tokens[shell_index + 1],
                fs_restricted=True,
                read_only_paths=read_only_paths,
                _shell_depth=_shell_depth + 1,
            )
            if nested_rejection is not None:
                return nested_rejection
        if command_name == "git" and not self._git_sandbox_env_overrides():
            return "git denied: sandbox git config overrides unavailable (git >= 2.31 required)"
        should_check_positional_paths = command_name in read_command_names | write_command_names
        for idx, token in enumerate(tokens):
            if token in {"<", "--"} | redirects:
                continue
            # sh expands $'...' / $"..." and $-prefixed shapes after shlex has
            # already stripped the quotes, so an absolute path can hide behind
            # `$/...` or `$\x..` (ANSI-C hex); ${VAR:-/abs/path} parameter
            # expansion smuggles one inside an ordinary-looking token.  Reject
            # every expandable shape that can resolve outside the workspace;
            # plain $VAR references (starting with a letter/underscore) stay
            # allowed.
            if token.startswith(("$/", "$\\", "$'", '$"')) or "${" in token:
                return f"Filesystem restricted command denied expandable path: {token}"
            if command_name in _GIT_METADATA_FS_WRITE_COMMANDS and "$" in token:
                return f"Filesystem restricted command denied expandable path: {token}"
            if idx == 0 and not should_check_positional_paths:
                continue
            if idx == 0 and self._is_trusted_executable(token):
                continue
            if token.startswith("-"):
                continue
            previous = tokens[idx - 1] if idx > 0 else ""
            if not should_check_positional_paths and idx > 0 and previous not in {"<"} | redirects:
                continue
            if _token_has_git_metadata_component(token) and (
                command_name in _GIT_METADATA_FS_WRITE_COMMANDS or previous in redirects
            ):
                return f"Filesystem restricted command denied write into .git metadata: {token}"

            if token_is_runtime_tcb_write(token, workspace=self.workspace) and (
                command_name in _GIT_METADATA_FS_WRITE_COMMANDS or previous in redirects
            ):
                return f"Filesystem restricted command denied write into runtime TCB: {token}"
            if self._looks_outside_workspace(token, read_only_paths=read_only_paths):
                return f"Filesystem restricted command denied path outside workspace: {token}"
        if command_name in write_command_names | shell_command_names:
            for token in tokens[1:]:
                for embedded_path in _embedded_absolute_paths(token):
                    if self._looks_outside_workspace(
                        embedded_path,
                        read_only_paths=read_only_paths,
                    ):
                        return (
                            "Filesystem restricted command denied path outside workspace: "
                            f"{embedded_path}"
                        )
        return None

    def resolve_cwd(
        self,
        cwd: str | None,
        *,
        read_only_paths: tuple[Path, ...] = (),
    ) -> tuple[Path | None, str | None]:
        """Resolve cwd under a writable workspace or an explicit read-only root."""
        requested_cwd = "." if cwd is None else cwd
        try:
            requested_path = Path(requested_cwd).expanduser()
            candidate = (
                requested_path if requested_path.is_absolute() else self.workspace / requested_path
            )
            resolved = candidate.resolve()
            if not _path_is_within(resolved, self.workspace) and not any(
                _path_is_within(resolved, root) for root in read_only_paths
            ):
                raise ValueError("cwd outside sandbox roots")
        except (OSError, RuntimeError, ValueError):
            return None, (f"Sandbox cwd denied: workspace={self.workspace} cwd={requested_cwd}")
        return resolved, None

    def _is_trusted_executable(self, token: str) -> bool:
        """Allow only the configured interpreter or a real workspace venv entrypoint."""
        try:
            requested = Path(token).expanduser()
            if not requested.is_absolute():
                requested = self.workspace / requested
            workspace_venv = self.workspace / ".venv"
            if requested == workspace_venv / "bin" / "python" and not workspace_venv.is_symlink():
                return True
            return requested.resolve() in self._trusted_executables
        except (OSError, RuntimeError):
            return False

    def _looks_outside_workspace(
        self,
        token: str,
        *,
        read_only_paths: tuple[Path, ...] = (),
    ) -> bool:
        if not token or token in {".", "-"}:
            return False
        if token.startswith("~"):
            return True
        try:
            path = Path(token).expanduser()
        except (OSError, RuntimeError):
            return True
        try:
            candidate = path if path.is_absolute() else self.workspace / path
            resolved = candidate.resolve()
            if not _path_is_within(resolved, self.workspace) and not any(
                _path_is_within(resolved, root) for root in read_only_paths
            ):
                return True
        except (OSError, RuntimeError, ValueError):
            return True
        return False

    def _normalize_read_only_paths(
        self,
        paths: list[Path] | tuple[Path, ...] | None,
    ) -> tuple[tuple[Path, ...], str | None]:
        """Validate the narrow host roots made readable to a strict sandbox."""
        if not paths:
            return (), None
        if len(paths) > 16:
            return (), "Too many read-only sandbox roots"
        home = Path.home().resolve()
        normalized: list[Path] = []
        for raw_path in paths:
            try:
                path = Path(raw_path).expanduser().resolve(strict=True)
            except (OSError, RuntimeError):
                return (), f"Read-only sandbox root does not exist: {raw_path}"
            if not path.is_dir():
                return (), f"Read-only sandbox root is not a directory: {raw_path}"
            if path == Path(path.anchor) or path == home or _path_is_within(self.workspace, path):
                return (), f"Read-only sandbox root is too broad: {raw_path}"
            if _path_is_within(path, self.workspace):
                continue
            normalized.append(path)
        return tuple(dict.fromkeys(normalized)), None


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _sandbox_profile_path(path: Path) -> str:
    """Escape an already-resolved path for a sandbox-exec string literal."""
    return str(path).replace("\\", "\\\\").replace('"', '\\"')


def _token_has_git_metadata_component(token: str) -> bool:
    """True when any path component is ``.git`` (case-insensitive)."""
    if not token or token in {".", "-"}:
        return False
    normalized = os.path.normpath(token.replace("\\", "/"))
    return any(part.casefold() == ".git" for part in normalized.split("/"))


def _macos_deny_runtime_tcb_write_rules(workspace: Path) -> str:
    """Trailing seatbelt: deny the whole package, then allow dogfood static.

    SBPL evaluates later rules first, so the static allow must trail the
    package deny, which itself trails the workspace write allow.
    """
    from js.security.runtime_tcb import workspace_tcb_allow_targets, workspace_tcb_deny_targets

    rules: list[str] = []
    for path, is_directory in workspace_tcb_deny_targets(workspace):
        escaped = _sandbox_profile_path(path)
        kind = "subpath" if is_directory else "literal"
        rules.append(f'(deny file-write* ({kind} "{escaped}"))')
    for path, is_directory in workspace_tcb_allow_targets(workspace):
        escaped = _sandbox_profile_path(path)
        kind = "subpath" if is_directory else "literal"
        rules.append(f'(allow file-write* ({kind} "{escaped}"))')
    if not rules:
        return ""
    return "\n" + "\n".join(rules) + "\n"


def _macos_deny_any_git_write_rule(workspace: Path) -> str:
    """SBPL regex denying writes to any ``.git`` component under workspace.

    Snapshot subpath denies miss directories created in the same sandboxed
    invocation.  The regex requires a path *component* named ``.git`` so
    ``.github`` / ``foo.git`` stay writable.  Seatbelt regex is POSIX ERE
    (no ``(?i)``); case-folding is enforced at the allowlist / fs-restriction
    layer instead.
    """
    escaped = re.escape(str(workspace.resolve())).replace('"', '\\"')
    return '(deny file-write* (regex #"^' + escaped + r'(/.*)?/\.git(/|$)"))' + "\n"


def _sandbox_traversal_paths(roots: tuple[Path, ...]) -> tuple[Path, ...]:
    """Allow directory metadata needed to traverse to narrow readable roots."""
    paths: list[Path] = []
    for root in roots:
        for parent in reversed(root.parents):
            if parent == Path(parent.anchor) or parent in paths:
                continue
            paths.append(parent)
    return tuple(paths)


def _workspace_git_components(workspace: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    """Locate every ``.git`` directory and gitfile under the workspace.

    The broad workspace write allow leaves nested repositories writable, so a
    sandboxed process could plant hooks or a ``diff.external`` config that
    later executes on the HOST when the user runs git in that directory.
    Returns ``(git directories, gitfiles)``; the walk is bounded (noisy
    dependency directories skipped, depth and result count capped) so a huge
    workspace cannot stall sandbox profile construction.
    """
    git_dirs: list[Path] = []
    git_files: list[Path] = []
    root_depth = len(workspace.parts)
    for dirpath, dirnames, filenames in os.walk(workspace):
        current = Path(dirpath)
        git_named_dirs = [name for name in dirnames if name.casefold() == ".git"]
        for name in git_named_dirs:
            git_dirs.append(current / name)
            dirnames.remove(name)
        git_named_files = [name for name in filenames if name.casefold() == ".git"]
        for name in git_named_files:
            git_files.append(current / name)
        dirnames[:] = [name for name in dirnames if name not in _GIT_SCAN_SKIP_DIRS]
        if len(current.parts) - root_depth >= _GIT_SCAN_MAX_DEPTH:
            dirnames[:] = []
        if len(git_dirs) + len(git_files) >= _GIT_SCAN_MAX_ENTRIES:
            break
    return tuple(git_dirs), tuple(git_files)


def _purge_new_git_components(
    workspace: Path,
    before: tuple[tuple[Path, ...], tuple[Path, ...]],
) -> tuple[str, ...]:
    """Remove ``.git`` dirs/files that appeared after a sandboxed command."""
    before_ids = {str(path.resolve()) for path in (*before[0], *before[1])}
    after_dirs, after_files = _workspace_git_components(workspace)
    planted: list[str] = []
    for path in (*after_dirs, *after_files):
        try:
            resolved = str(path.resolve())
        except OSError:
            continue
        if resolved in before_ids:
            continue
        planted.append(str(path))
        try:
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)
        except OSError:
            planted[-1] = f"{path}:purge-failed"
    return tuple(planted)


def _embedded_absolute_paths(token: str) -> tuple[str, ...]:
    if "/" not in token and "~" not in token:
        return ()
    paths: list[str] = []
    for match in re.finditer(r"""(?P<quote>['"])(?P<path>(?:/|~)[^'"]+)(?P=quote)""", token):
        paths.append(match.group("path"))
    return tuple(paths)
