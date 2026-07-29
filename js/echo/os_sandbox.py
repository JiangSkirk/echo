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


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    duration_ms: float
    killed: bool = False
    oom_killed: bool = False


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
        env["PATH"] = os.pathsep.join(
            dict.fromkeys(str(path) for path in trusted_path_dirs)
        )
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
        return env

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
                f'            (subpath "{_sandbox_profile_path(path)}")'
                for path in read_only_paths
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
                    "--",
                    *cmd,
                )
            )
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

        normalized_read_paths, read_path_error = self._normalize_read_only_paths(
            read_only_paths
        )
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
                memory_task = asyncio.create_task(
                    self._monitor_memory(proc, self.max_memory_mb)
                )

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

            return SandboxResult(
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                killed=killed,
                oom_killed=oom_killed,
            )

        except Exception as e:
            duration_ms = (time.monotonic() - start_time) * 1000
            if proc is not None:
                self._kill_process_tree(proc)
                await self._reap_process(proc)
            return SandboxResult(
                returncode=-1,
                stdout="",
                stderr=f"Execution error: {e}",
                duration_ms=duration_ms,
                killed=True,
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
                except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, OSError, psutil.Error):
                    pass
            try:
                parent.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, OSError, psutil.Error):
                pass
            # Wait briefly, then force kill
            try:
                _gone, alive = psutil.wait_procs(children + [parent], timeout=2)
                for p in alive:
                    try:
                        p.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, OSError, psutil.Error):
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
        if isinstance(command, str):
            try:
                tokens = shlex.split(command)
            except ValueError as exc:
                return f"Filesystem restricted command rejected: {exc}"
        else:
            tokens = [str(part) for part in command]
        if not tokens:
            return None

        read_command_names = {"cat", "head", "tail", "less", "more", "grep", "sed", "awk"}
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
        should_check_positional_paths = command_name in read_command_names | write_command_names
        for idx, token in enumerate(tokens):
            if token in {"<", "--"} | redirects:
                continue
            if idx == 0 and not should_check_positional_paths:
                continue
            if idx == 0 and self._is_trusted_executable(token):
                continue
            if token.startswith("-"):
                continue
            previous = tokens[idx - 1] if idx > 0 else ""
            if (
                not should_check_positional_paths
                and idx > 0
                and previous not in {"<"} | redirects
            ):
                continue
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
                requested_path
                if requested_path.is_absolute()
                else self.workspace / requested_path
            )
            resolved = candidate.resolve()
            if not _path_is_within(resolved, self.workspace) and not any(
                _path_is_within(resolved, root) for root in read_only_paths
            ):
                raise ValueError("cwd outside sandbox roots")
        except (OSError, RuntimeError, ValueError):
            return None, (
                f"Sandbox cwd denied: workspace={self.workspace} cwd={requested_cwd}"
            )
        return resolved, None

    def _is_trusted_executable(self, token: str) -> bool:
        """Allow only the configured interpreter or a real workspace venv entrypoint."""
        try:
            requested = Path(token).expanduser()
            if not requested.is_absolute():
                requested = self.workspace / requested
            workspace_venv = self.workspace / ".venv"
            if (
                requested == workspace_venv / "bin" / "python"
                and not workspace_venv.is_symlink()
            ):
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


def _sandbox_traversal_paths(roots: tuple[Path, ...]) -> tuple[Path, ...]:
    """Allow directory metadata needed to traverse to narrow readable roots."""
    paths: list[Path] = []
    for root in roots:
        for parent in reversed(root.parents):
            if parent == Path(parent.anchor) or parent in paths:
                continue
            paths.append(parent)
    return tuple(paths)


def _embedded_absolute_paths(token: str) -> tuple[str, ...]:
    if "/" not in token and "~" not in token:
        return ()
    paths: list[str] = []
    for match in re.finditer(r"""(?P<quote>['"])(?P<path>(?:/|~)[^'"]+)(?P=quote)""", token):
        paths.append(match.group("path"))
    return tuple(paths)
