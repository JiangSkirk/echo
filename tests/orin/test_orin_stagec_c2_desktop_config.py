"""WP-C2 configuration and launch-boundary contracts.

The Desktop Cell is evidence for the explicit C2 harness only.  Production
launchers keep their Stage-A/Stage-B in-process desktop path while
``orin.enforce`` remains unavailable.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import stat
import tempfile
from pathlib import Path

import pytest

from js.config import OrinConfig
from js.orin.protocol import encode_frame, make_envelope
from js.orin.testing import C2TestOrind
from js.orind.daemon import OrinDaemon

_COMMON_CELL_ENV = {
    "HOME",
    "LC_ALL",
    "ORIN_CELLS_SOCKET",
    "ORIN_CELL_IDENTITY_ENFORCE",
    "ORIN_CELL_LAUNCH_TICKETS",
    "ORIN_ORIND_PID",
    "ORIN_STATE_DIR",
    "PATH",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONIOENCODING",
    "PYTHONUTF8",
    "TMPDIR",
}
_DESKTOP_CELL_ENV = _COMMON_CELL_ENV | {
    "ORIN_DESKTOP_SCRIPT_PATH",
    "ORIN_KEYBOX_TIER",
}
_SENSITIVE_ENV = {
    "ALL_PROXY",
    "AWS_SECRET_ACCESS_KEY",
    "AZURE_OPENAI_API_KEY",
    "DYLD_INSERT_LIBRARIES",
    "GITHUB_TOKEN",
    "GIT_ASKPASS",
    "GOOGLE_API_KEY",
    "GPG_AGENT_INFO",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "LD_PRELOAD",
    "OPENAI_API_KEY",
    "PYTHONHOME",
    "PYTHONPATH",
    "SHELL",
    "SSH_AUTH_SOCK",
}


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def test_cell_desktop_switch_defaults_off_and_is_lazy() -> None:
    default = OrinConfig()
    opted_in = OrinConfig(cell_desktop=True)

    assert default.cell_desktop is False
    assert opted_in.cell_desktop is True
    assert opted_in.enforce is False


def test_desktop_cell_cannot_activate_outside_explicit_c2_harness(tmp_path: Path) -> None:
    daemon = OrinDaemon(
        state_dir=tmp_path,
        stage_b=True,
        cell_desktop=True,
        cell_identity_enforce=True,
        c1_test_harness=False,
    )
    try:
        assert daemon._cell_desktop_enabled is False  # noqa: SLF001
    finally:
        daemon._store.close()  # noqa: SLF001 - daemon loop was never started


def test_c2_harness_forces_strict_identity_and_desktop_only(tmp_path: Path) -> None:
    harness = C2TestOrind(state_dir=tmp_path)

    assert harness._stage_b is True  # noqa: SLF001 - explicit harness contract
    assert harness._cell_identity_enforce is True  # noqa: SLF001
    assert harness._c1_test_harness is True  # noqa: SLF001
    assert harness._cell_desktop is True  # noqa: SLF001
    assert harness._cell_build is False  # noqa: SLF001
    assert harness._cell_file is False  # noqa: SLF001
    assert harness._cell_net is False  # noqa: SLF001
    assert harness._cell_secret is False  # noqa: SLF001
    assert getattr(harness, "_cell_memory", False) is False


def test_desktop_cell_environment_is_an_exact_allowlist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in _SENSITIVE_ENV:
        monkeypatch.setenv(key, "must-not-enter-desktop-cell")
    script_path = tmp_path / "desktop-script.json"
    script_path.write_text("{}", encoding="utf-8")
    daemon = OrinDaemon(
        state_dir=tmp_path / "state",
        stage_b=True,
        cell_desktop=True,
        cell_identity_enforce=True,
        c1_test_harness=True,
        desktop_script_path=script_path,
    )
    ticket = secrets.token_hex(16)
    runtime_root = tmp_path / "desktop-private"
    runtime_root.mkdir(mode=0o700)
    try:
        environment = daemon._cell_environment(  # noqa: SLF001 - C2 harness contract
            kind="desktop",
            caps=frozenset({"cell.desktop"}),
            tickets={"cell.desktop": ticket},
            runtime_root=runtime_root,
        )

        assert set(environment) == _DESKTOP_CELL_ENV
        assert _SENSITIVE_ENV.isdisjoint(environment)
        assert json.loads(environment["ORIN_CELL_LAUNCH_TICKETS"]) == {"cell.desktop": ticket}
        assert environment["ORIN_CELL_IDENTITY_ENFORCE"] == "1"
        assert environment["ORIN_ORIND_PID"] == str(os.getpid())
        assert environment["ORIN_DESKTOP_SCRIPT_PATH"] == os.fspath(script_path)
        assert environment["ORIN_KEYBOX_TIER"] == daemon.keybox_tier
        assert _mode(Path(environment["HOME"])) == 0o700
        assert _mode(Path(environment["TMPDIR"])) == 0o700
    finally:
        daemon._store.close()  # noqa: SLF001 - daemon loop was never started


def test_default_daemon_does_not_spawn_desktop_cell(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spawned: list[object] = []
    monkeypatch.setattr(
        OrinDaemon,
        "_spawn_desktop_cell",
        lambda self: spawned.append(self),
        raising=False,
    )
    daemon = OrinDaemon(state_dir=tmp_path, stage_b=True)
    try:
        assert daemon._cell_desktop_enabled is False  # noqa: SLF001
        assert spawned == []
    finally:
        daemon._store.close()  # noqa: SLF001 - daemon loop was never started


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["wrong-ticket", "wrong-cap"])
async def test_desktop_cap_rejects_wire_identity_before_publishing_session_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="orin-c2-identity-") as short:
        short_root = Path(short)
        daemon = OrinDaemon(
            state_dir=tmp_path / attack,
            socket_path=short_root / "orind.sock",
            orin_dir=short_root,
            stage_b=True,
            cell_desktop=True,
            cell_identity_enforce=True,
            c1_test_harness=True,
        )
        monkeypatch.setattr(daemon, "_spawn_desktop_cell", lambda: None)
        await daemon.start()
        try:
            ticket = secrets.token_hex(16)
            daemon._expected_cell_caps_by_pid[os.getpid()] = frozenset(  # noqa: SLF001
                {"cell.desktop"}
            )
            daemon._expected_cell_launch_by_pid[os.getpid()] = {  # noqa: SLF001
                "cell.desktop": ticket
            }
            supplied_ticket = secrets.token_hex(16) if attack == "wrong-ticket" else ticket
            supplied_caps = ["cell.desktop"] if attack == "wrong-ticket" else ["cell.file"]
            reader, writer = await asyncio.open_unix_connection(path=str(daemon.cell_socket_path))
            hello = make_envelope(
                "hello",
                seq=1,
                nonce=supplied_ticket,
                session_key=None,
                caps=supplied_caps,
                pid=os.getpid(),
            )
            writer.write(encode_frame(hello))
            await writer.drain()
            try:
                with pytest.raises((asyncio.IncompleteReadError, ConnectionError, TimeoutError)):
                    await asyncio.wait_for(reader.readexactly(1), timeout=1.0)
            finally:
                writer.close()
                await writer.wait_closed()

            assert not (short_root / f"session-{os.getpid()}.key").exists()
            assert daemon._cell_by_cap("cell.desktop") is None  # noqa: SLF001
        finally:
            await daemon.stop()
