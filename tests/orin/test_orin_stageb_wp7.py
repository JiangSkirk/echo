"""WP7: Build Cell — shell/code execution outside the Echo process.

Acceptance items (ORIN_STAGE_B_SPEC.md §4 WP7):

- end-to-end: adapter.run_in_build_cell reaches a real sandboxed cell
  subprocess through orind's scheduler and returns untrusted output;
- no network / no credentials inside the cell (tested, not claimed);
- killing the Build Cell pauses exactly that effect class; other tools
  (heartbeat) keep working;
- policy still applies on the cell path (conservative default row);
- with ``cell_backend`` unset, shell/code take the legacy in-process path.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from js.echo.capability import LeaseDenied
from js.orin import taint
from js.orin.client import OrinLeaseClientAdapter
from js.orin.testing import TestOrind


def _pub_of(key: ed25519.Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(
        "ascii"
    )


import base64  # noqa: E402


def _wait_for_cell(daemon: Any, cap: str = "cell.build", timeout_s: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if daemon._cell_by_cap(cap) is not None:  # noqa: SLF001 - test probe
            return True
        time.sleep(0.2)
    return False


def _adapter(orind: TestOrind) -> OrinLeaseClientAdapter:
    return OrinLeaseClientAdapter(
        socket_path=orind.socket_path,
        state_dir=Path(orind.daemon._state_dir),  # noqa: SLF001 - test probe
        stage_b=True,
    )


@pytest.fixture()
def build_orind(tmp_path: Path):
    witness = ed25519.Ed25519PrivateKey.generate()
    with TestOrind(
        state_dir=tmp_path,
        stage_b=True,
        cell_build=True,
        witness_public_keys=(_pub_of(witness),),
    ) as orind:
        assert _wait_for_cell(orind.daemon), "build cell subprocess did not connect"
        yield orind


class TestBuildCellEndToEnd:
    def test_shell_round_trip_through_scheduler(self, build_orind: TestOrind) -> None:
        adapter = _adapter(build_orind)
        try:
            result = adapter.run_in_build_cell(
                {"kind": "shell", "command": "echo hello-cell", "cwd": ".", "tool": "shell"},
                context_taint=taint.USER_TURN,
            )
            assert result.get("status") == "COMMITTED"
            output = str(result.get("output") or "")
            assert "hello-cell" in output
            # untrusted tool result marker rides back for taint folding
            assert "returncode" in result
        finally:
            adapter.close()

    def test_no_credentials_inside_cell(self, build_orind: TestOrind) -> None:
        import os

        adapter = _adapter(build_orind)
        try:
            secret_name = "ORIN_TEST_SECRET_TOKEN"
            os.environ[secret_name] = "super-secret-value"
            try:
                result = adapter.run_in_build_cell(
                    {"kind": "shell", "command": f"env | grep {secret_name} || true",
                     "cwd": ".", "tool": "shell"},
                    context_taint=taint.USER_TURN,
                )
            finally:
                os.environ.pop(secret_name, None)
            output = str(result.get("output") or "")
            assert "super-secret-value" not in output
            assert result.get("status") == "COMMITTED"
        finally:
            adapter.close()

    def test_network_denied_inside_cell(self, build_orind: TestOrind) -> None:
        adapter = _adapter(build_orind)
        try:
            result = adapter.run_in_build_cell(
                {
                    "kind": "shell",
                    "command": (
                        "python3 -c \"import socket;\n"
                        "socket.setdefaulttimeout(3);\n"
                        "socket.create_connection(('93.184.216.34', 80))\""
                    ),
                    "cwd": ".",
                    "tool": "shell",
                    "timeout_ms": 15000,
                },
                context_taint=taint.USER_TURN,
            )
            # Either the sandbox blocked it (nonzero exit / killed) or the
            # environment has no egress at all — never a clean success.
            assert result.get("status") != "COMMITTED" or "Traceback" in str(
                result.get("output") or ""
            ) or result.get("returncode") not in (0,)
        finally:
            adapter.close()

    def test_kill_cell_pauses_only_build_class(self, build_orind: TestOrind) -> None:
        daemon = build_orind.daemon
        adapter = _adapter(build_orind)
        try:
            assert adapter.healthy(), "echo surface must be alive before kill"
            for proc in list(daemon._cell_procs):  # noqa: SLF001
                proc.terminate()
                proc.wait(timeout=5)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and daemon._cell_by_cap("cell.build"):
                time.sleep(0.2)
            with pytest.raises(LeaseDenied):
                adapter.run_in_build_cell(
                    {"kind": "shell", "command": "echo nope", "cwd": ".", "tool": "shell"},
                    context_taint=taint.USER_TURN,
                )
            # other tools unaffected: heartbeat + lease issuance still work
            assert adapter.healthy()
        finally:
            adapter.close()

    def test_policy_still_applies_on_cell_path(self, build_orind: TestOrind) -> None:
        from js.orin.client import OrinApprovalRequired

        adapter = _adapter(build_orind)
        try:
            # unknown tool name → conservative default row ⇒ approval_required
            with pytest.raises(OrinApprovalRequired):
                adapter.run_in_build_cell(
                    {"kind": "shell", "command": "echo x", "cwd": ".", "tool": "unknown_tool"}
                )
        finally:
            adapter.close()


class TestBuildCellUnit:
    def test_code_kind_runs_and_reports(self, tmp_path: Path) -> None:
        from js.orind.cells.build import BuildCell

        cell = BuildCell(socket_path=tmp_path / "unused.sock", state_dir=tmp_path,
                         workspace=tmp_path / "ws")
        result = asyncio.run(cell.execute({"kind": "code", "code": "print(1 + 1)"}))
        assert result["status"] == "COMMITTED"
        assert "2" in result["output"]

    def test_unsupported_kind_rejected(self, tmp_path: Path) -> None:
        from js.orind.cells.build import BuildCell

        cell = BuildCell(socket_path=tmp_path / "unused.sock", state_dir=tmp_path,
                         workspace=tmp_path / "ws")
        result = asyncio.run(cell.execute({"kind": "desktop"}))
        assert result["status"] == "FAILED"


class TestToolRouting:
    def _shell_tool(self, tmp_path: Path, backend: Any = None) -> Any:
        from js.tools.shell import ShellTool

        class _Limits:
            shell_timeout = 10
            shell_max_output_bytes = 65536
            shell_command_allowlist: tuple[str, ...] = ("echo", "python3")

        class _Decision:
            decision = "ALLOW"
            reason = ""

        class _Guard:
            def check_command(self, command: str, cwd: str) -> _Decision:
                return _Decision()

            def check_path_operation(self, path: str, op: str) -> _Decision:
                return _Decision()

        tool = ShellTool(tmp_path / "ws", _Limits(), _Guard())
        if backend is not None:
            tool.cell_backend = backend  # type: ignore[attr-defined]
        return tool

    def test_backend_absent_keeps_legacy_path(self, tmp_path: Path) -> None:
        tool = self._shell_tool(tmp_path)
        result = asyncio.run(tool.execute(command="echo local-path"))
        assert result.success
        assert (result.metadata or {}).get("cell") is None

    def test_backend_present_routes_and_marks_metadata(self, tmp_path: Path) -> None:
        calls: list[dict[str, Any]] = []

        async def fake_backend(payload: dict[str, Any]) -> dict[str, Any]:
            calls.append(payload)
            return {
                "status": "COMMITTED",
                "output": "via-cell",
                "returncode": 0,
                "duration_ms": 3,
                "killed": False,
            }

        tool = self._shell_tool(tmp_path, backend=fake_backend)
        result = asyncio.run(tool.execute(command="echo anything"))
        assert result.success
        assert "via-cell" in result.output
        assert (result.metadata or {}).get("cell") == "build"
        assert calls and calls[0]["kind"] == "shell"

    def test_backend_lease_denied_degrades_fixed_copy(self, tmp_path: Path) -> None:
        async def denying_backend(payload: dict[str, Any]) -> dict[str, Any]:
            raise LeaseDenied("cell unavailable")

        tool = self._shell_tool(tmp_path, backend=denying_backend)
        result = asyncio.run(tool.execute(command="echo x"))
        assert not result.success
        assert "Safety degradation" in (result.error or "")
