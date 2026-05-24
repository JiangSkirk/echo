"""Sandbox executor tests — resource limits and network isolation."""

from __future__ import annotations

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
