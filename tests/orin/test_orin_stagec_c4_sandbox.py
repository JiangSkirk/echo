"""WP-C4 explicit macOS sandbox carrier.  Official TCC stays external-pending."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from js.echo.os_sandbox import SandboxExecutor


def test_default_launchers_do_not_wire_a_c4_production_carrier() -> None:
    root = Path(__file__).resolve().parents[2]
    for path in (
        root / "js" / "appshell" / "launcher.py",
        root / "js" / "web" / "server.py",
        root / "desktop" / "sidecar" / "host.py",
    ):
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        assert "c4_harness" not in text
        assert "C4TestOrind" not in text


@pytest.mark.asyncio
async def test_deny_default_carrier_blocks_network_host_writes_and_secrets(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "c4-workspace"
    workspace.mkdir()
    interpreter = Path(sys.executable)
    executor = SandboxExecutor(
        workspace,
        strict_isolation=True,
        trusted_executables=[interpreter],
    )
    if not executor.network_isolation_available() or not executor.filesystem_isolation_available():
        pytest.skip("C4 evidence requires a deny-default OS sandbox backend")

    host_secret = tmp_path / "provider-token"
    host_secret.write_text("real-token", encoding="utf-8")
    cell_socket = tmp_path / "cells.sock"
    cell_socket.write_bytes(b"")
    probe = workspace / "probe.py"
    probe.write_text(
        "\n".join(
            (
                "import os, socket, sys",
                f"secret = {str(host_secret)!r}",
                f"cell = {str(cell_socket)!r}",
                "leaks = []",
                "for key in ('OPENAI_API_KEY', 'HTTPS_PROXY', 'SSH_AUTH_SOCK'):",
                "    if os.environ.get(key):",
                "        leaks.append('env:' + key)",
                "try:",
                "    socket.create_connection(('1.1.1.1', 443), timeout=1.0)",
                "    leaks.append('network')",
                "except OSError:",
                "    pass",
                "try:",
                "    open(secret, 'r').read()",
                "    leaks.append('host-secret')",
                "except OSError:",
                "    pass",
                "try:",
                "    open(cell, 'w').write('x')",
                "    leaks.append('cell-socket')",
                "except OSError:",
                "    pass",
                "sys.stdout.write('ok' if not leaks else 'leaked:' + ','.join(leaks))",
            )
        ),
        encoding="utf-8",
    )
    result = await executor.execute(
        [str(interpreter), str(probe)],
        cwd=str(workspace),
        env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"},
        network_allowed=False,
        fs_restricted=True,
        timeout=15.0,
    )
    output = (result.stdout or "") + (result.stderr or "")
    assert result.returncode == 0
    assert (result.stdout or "").strip() == "ok"
    assert "leaked:" not in output


def test_official_tcc_packaging_remains_external_pending() -> None:
    spec = (
        Path(__file__).resolve().parents[2] / "docs" / "security" / "orin" / "ORIN_STAGE_C_SPEC.md"
    )
    text = spec.read_text(encoding="utf-8")
    assert "TCC" in text
    assert "external-pending" in text
