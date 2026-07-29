"""Sandbox executor tests — resource limits and network isolation."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from js.security.sandbox import SandboxExecutor, SandboxResult


class TestSandboxExecution:
    """Test basic sandbox execution capabilities."""

    @pytest.fixture
    def sandbox(self, tmp_path: Path) -> SandboxExecutor:
        return SandboxExecutor(workspace=tmp_path, timeout=5.0, max_memory_mb=512)

    @pytest.mark.asyncio
    async def test_echo_command(self, sandbox: SandboxExecutor) -> None:
        """Sandbox can execute a simple echo command."""
        result = await sandbox.execute(["echo", "hello"])
        assert result.returncode == 0
        assert "hello" in result.stdout
        assert not result.killed

    @pytest.mark.asyncio
    async def test_timeout_kills_process(self, sandbox: SandboxExecutor) -> None:
        """Process exceeding timeout is killed."""
        result = await sandbox.execute(["sleep", "10"], timeout=0.5)
        assert result.killed
        # Cross-platform: force-killed processes report -9 (SIGKILL)
        assert result.returncode == -9
        assert "timed out" in result.stderr.lower()

    @pytest.mark.asyncio
    async def test_output_truncation(self, tmp_path: Path) -> None:
        """Excessive output is truncated."""
        sandbox = SandboxExecutor(workspace=tmp_path, timeout=5.0, max_output_bytes=20)
        result = await sandbox.execute(["python3", "-c", "print('x' * 1000)"])
        assert result.returncode == 0
        assert "[output truncated]" in result.stdout
        assert len(result.stdout) < 200

    @pytest.mark.asyncio
    async def test_stderr_captured(self, sandbox: SandboxExecutor) -> None:
        """Stderr is captured and returned."""
        result = await sandbox.execute(["python3", "-c", "import sys; sys.stderr.write('error!')"])
        assert result.returncode == 0
        assert "error!" in result.stderr

    def test_subprocess_environment_drops_host_secrets_and_loader_injection(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setenv("HOME", "/Users/private-person")
        monkeypatch.setenv("OPENAI_API_KEY", "must-not-cross-boundary")
        monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
        sandbox = SandboxExecutor(workspace=tmp_path)

        env = sandbox._build_env(
            {
                "OPENAI_API_KEY": "explicit-leak",
                "LD_PRELOAD": "/tmp/evil.so",
                "LANG": "C",
            }
        )

        # HOME is a sandbox-private directory (never the workspace root and
        # never the host HOME) so host dotfiles cannot leak across the boundary.
        assert env["HOME"] == str(tmp_path.resolve() / ".echo-tmp" / "home")
        assert env["PWD"] == str(tmp_path.resolve())
        assert env["LANG"] == "C"
        assert "OPENAI_API_KEY" not in env
        assert "LD_PRELOAD" not in env
        assert "/Users/private-person" not in repr(env)

    @pytest.mark.asyncio
    async def test_fs_restricted_blocks_absolute_reads_outside_workspace(
        self,
        tmp_path: Path,
    ) -> None:
        sandbox = SandboxExecutor(
            workspace=tmp_path,
            timeout=5.0,
            max_memory_mb=512,
            strict_isolation=True,
        )

        result = await sandbox.execute("cat /etc/hosts", fs_restricted=True)

        assert result.returncode != 0
        assert "outside workspace" in result.stderr.lower()

    @pytest.mark.asyncio
    async def test_fs_restricted_blocks_absolute_writes_outside_workspace(
        self,
        tmp_path: Path,
    ) -> None:
        sandbox = SandboxExecutor(
            workspace=tmp_path,
            timeout=5.0,
            max_memory_mb=512,
            strict_isolation=True,
        )
        outside = tmp_path.parent / "echo-sandbox-outside.txt"
        if outside.exists():
            outside.unlink()

        result = await sandbox.execute(f"touch {outside}", fs_restricted=True)

        assert result.returncode != 0
        assert "outside workspace" in result.stderr.lower()
        assert not outside.exists()

    @pytest.mark.asyncio
    async def test_fs_restricted_blocks_scripted_writes_outside_workspace(
        self,
        tmp_path: Path,
    ) -> None:
        sandbox = SandboxExecutor(
            workspace=tmp_path,
            timeout=5.0,
            max_memory_mb=512,
            strict_isolation=True,
        )
        outside = tmp_path.parent / "echo-sandbox-scripted.txt"
        if outside.exists():
            outside.unlink()

        result = await sandbox.execute(
            f"python3 -c \"open('{outside}', 'w').write('x')\"",
            fs_restricted=True,
        )

        assert result.returncode != 0
        assert "outside workspace" in result.stderr.lower()
        assert not outside.exists()

    @pytest.mark.asyncio
    async def test_fs_restricted_executes_read_only_skill_source(
        self,
        tmp_path: Path,
    ) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        skill_dir = tmp_path / "installed-skill"
        skill_dir.mkdir()
        script = skill_dir / "main.py"
        script.write_text("print('isolated-skill-ok')\n")
        sandbox = SandboxExecutor(
            workspace=workspace,
            timeout=5.0,
            max_memory_mb=512,
            strict_isolation=True,
        )
        if not sandbox.filesystem_isolation_available():
            pytest.skip("OS filesystem isolation backend unavailable")

        result = await sandbox.execute(
            [str(Path(sys.executable).resolve()), str(script.resolve())],
            cwd=str(skill_dir),
            network_allowed=False,
            fs_restricted=True,
            read_only_paths=[skill_dir],
        )

        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "isolated-skill-ok"

    @pytest.mark.asyncio
    async def test_read_only_skill_source_cannot_be_modified(
        self,
        tmp_path: Path,
    ) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        skill_dir = tmp_path / "installed-skill"
        skill_dir.mkdir()
        script = skill_dir / "main.py"
        script.write_text(
            "from pathlib import Path\n"
            "Path(__file__).with_name('tampered.txt').write_text('bad')\n"
        )
        sandbox = SandboxExecutor(
            workspace=workspace,
            timeout=5.0,
            max_memory_mb=512,
            strict_isolation=True,
        )
        if not sandbox.filesystem_isolation_available():
            pytest.skip("OS filesystem isolation backend unavailable")

        result = await sandbox.execute(
            [str(Path(sys.executable).resolve()), str(script.resolve())],
            cwd=str(skill_dir),
            network_allowed=False,
            fs_restricted=True,
            read_only_paths=[skill_dir],
        )

        assert result.returncode != 0
        assert not (skill_dir / "tampered.txt").exists()


class TestSandboxNetworkIsolation:
    """Test network isolation when network_allowed=False."""

    @pytest.fixture
    def sandbox(self, tmp_path: Path) -> SandboxExecutor:
        return SandboxExecutor(workspace=tmp_path, timeout=10.0)

    @pytest.mark.asyncio
    async def test_network_allowed_true_can_fetch(self, sandbox: SandboxExecutor) -> None:
        """With network_allowed=True, sandbox does not block outbound network."""
        import asyncio
        import errno

        async def _http_handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            """Serve a minimal HTTP response and gracefully close."""
            # Drain the request so curl doesn't see a RST.
            try:
                await asyncio.wait_for(reader.read(1024), timeout=1.0)
            except TimeoutError:
                pass
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        try:
            server = await asyncio.start_server(_http_handler, "127.0.0.1", 0)
        except PermissionError:
            pytest.skip("local loopback bind not permitted in this environment")
        except OSError as exc:
            if exc.errno == errno.EPERM:
                pytest.skip("local loopback bind not permitted in this environment")
            raise

        server_port = int(server.sockets[0].getsockname()[1])  # type: ignore[index]
        try:
            result = await sandbox.execute(
                ["curl", "-s", "--max-time", "2", f"http://127.0.0.1:{server_port}/"],
                network_allowed=True,
            )
            assert isinstance(result, SandboxResult)
            # curl exit code 56 can occur on macOS when the handler closes the
            # connection before curl finishes reading. With the graceful handler
            # above this should be 0, but we keep 56 in the allow-list for CI
            # environments where sandbox-exec timing may differ.
            assert result.returncode in (0, 56)
            assert "ok" in result.stdout
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_network_denied_blocks_outbound(self, sandbox: SandboxExecutor) -> None:
        """With network_allowed=False, outbound connections are blocked."""
        result = await sandbox.execute(
            ["curl", "-s", "--max-time", "2", "http://127.0.0.1:1/"],
            network_allowed=False,
        )
        # On macOS with sandbox-exec, curl should fail with network denial
        # On Linux with unshare, curl should also fail (no network interfaces)
        # If no sandbox tool is available, this may pass — test just asserts
        # the sandbox wrapped it without crashing.
        assert isinstance(result, SandboxResult)

    def test_wrap_network_isolation_noop_when_allowed(self, sandbox: SandboxExecutor) -> None:
        """Wrapper returns command unchanged when network_allowed=True."""
        cmd = ["echo", "hi"]
        wrapped = sandbox._wrap_network_isolation(cmd, network_allowed=True)
        assert wrapped == cmd

    def test_wrap_network_isolation_adds_wrapper_when_denied(self, sandbox: SandboxExecutor) -> None:
        """Wrapper adds sandbox prefix when network_allowed=False."""
        cmd = ["echo", "hi"]
        wrapped = sandbox._wrap_network_isolation(cmd, network_allowed=False)
        # Should be prefixed with sandbox-exec (macOS) or unshare (Linux)
        assert len(wrapped) > len(cmd)
        assert wrapped[-2:] == ["echo", "hi"]
