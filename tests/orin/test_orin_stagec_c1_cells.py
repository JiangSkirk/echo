"""WP-C1 Cell launch identity and environment contracts.

These tests exercise only the explicit C1 harness.  The Stage-A/Stage-B
product path remains default-off and is covered by the existing regression
suite.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import stat
import tempfile
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

from js.orin.protocol import ProtocolError, encode_frame, make_envelope, parse_frame, verify_mac
from js.orin.testing import C1TestOrind
from js.orind.cell_identity import read_session_key_once
from js.orind.cells.base import CellBase
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


def _strict_daemon(tmp_path: Path) -> OrinDaemon:
    return OrinDaemon(
        state_dir=tmp_path,
        stage_b=True,
        cell_identity_enforce=True,
        c1_test_harness=True,
    )


@pytest.mark.parametrize(
    ("kind", "caps", "extra_keys"),
    [
        ("build", frozenset({"cell.build"}), {"ORIN_BUILD_WORKSPACE"}),
        ("file", frozenset({"cell.file"}), {"ORIN_KEYBOX_TIER"}),
        (
            "services",
            frozenset({"cell.connector", "cell.net", "cell.secret"}),
            {"ORIN_CELLS_CAPS", "ORIN_KEYBOX_TIER"},
        ),
    ],
)
def test_strict_cell_environment_is_an_exact_allowlist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    caps: frozenset[str],
    extra_keys: set[str],
) -> None:
    for key in _SENSITIVE_ENV:
        monkeypatch.setenv(key, f"must-not-enter-{kind}")
    daemon = _strict_daemon(tmp_path / kind)
    tickets = {cap: secrets.token_hex(16) for cap in caps}
    private_root = tmp_path / f"{kind}-private"
    private_root.mkdir(mode=0o700)

    environment = daemon._cell_environment(  # noqa: SLF001 - C1 harness contract
        kind=kind,
        caps=caps,
        tickets=tickets,
        runtime_root=private_root,
    )

    assert set(environment) == _COMMON_CELL_ENV | extra_keys
    assert _SENSITIVE_ENV.isdisjoint(environment)
    assert json.loads(environment["ORIN_CELL_LAUNCH_TICKETS"]) == tickets
    assert environment["ORIN_CELL_IDENTITY_ENFORCE"] == "1"
    assert environment["ORIN_ORIND_PID"] == str(os.getpid())
    assert environment["ORIN_STATE_DIR"] == os.fspath(daemon._state_dir)  # noqa: SLF001
    assert environment["ORIN_CELLS_SOCKET"] == os.fspath(daemon.cell_socket_path)
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
    assert environment["PYTHONIOENCODING"] == "utf-8"
    assert environment["PYTHONUTF8"] == "1"
    assert environment["LC_ALL"] == "C"
    assert Path(environment["HOME"]).is_dir()
    assert Path(environment["TMPDIR"]).is_dir()
    assert _mode(Path(environment["HOME"])) == 0o700
    assert _mode(Path(environment["TMPDIR"])) == 0o700
    if kind == "build":
        assert Path(environment["ORIN_BUILD_WORKSPACE"]).is_dir()
        assert _mode(Path(environment["ORIN_BUILD_WORKSPACE"])) == 0o700
    if kind == "services":
        assert environment["ORIN_CELLS_CAPS"] == ",".join(sorted(caps))
    if kind in {"file", "services"}:
        assert environment["ORIN_KEYBOX_TIER"] == daemon.keybox_tier
    daemon._store.close()  # noqa: SLF001 - no daemon loop was started


def test_cell_identity_switch_is_lazy_outside_explicit_c1_harness(tmp_path: Path) -> None:
    daemon = OrinDaemon(
        state_dir=tmp_path,
        stage_b=True,
        cell_identity_enforce=True,
        c1_test_harness=False,
    )

    try:
        assert daemon._cell_identity_enforce is True  # noqa: SLF001
        assert daemon._cell_desktop_enabled is False  # noqa: SLF001
        assert daemon._cell_memory_enabled is False  # noqa: SLF001
    finally:
        daemon._store.close()  # noqa: SLF001 - no daemon loop was started


def test_default_cell_spawns_strip_c1_private_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_keys = {
        "ORIN_CELL_IDENTITY_ENFORCE",
        "ORIN_CELL_LAUNCH_TICKETS",
        "ORIN_ORIND_PID",
    }
    for key in private_keys:
        monkeypatch.setenv(key, "must-not-activate-c1")
    captured: list[dict[str, str]] = []

    class FakeProcess:
        next_pid = 90_000

        def __init__(self) -> None:
            type(self).next_pid += 1
            self.pid = type(self).next_pid

        def poll(self) -> None:
            return None

    def fake_popen(*_args: object, **kwargs: object) -> FakeProcess:
        environment = kwargs.get("env")
        assert isinstance(environment, dict)
        captured.append(environment)
        return FakeProcess()

    monkeypatch.setattr("js.orind.daemon.subprocess.Popen", fake_popen)
    daemon = OrinDaemon(
        state_dir=tmp_path,
        stage_b=True,
        cell_build=True,
        cell_net=True,
        cell_secret=True,
        cell_file=True,
    )
    try:
        daemon._spawn_build_cell()  # noqa: SLF001 - default spawn contract
        daemon._spawn_services_cell()  # noqa: SLF001 - default spawn contract
        daemon._spawn_file_cell()  # noqa: SLF001 - default spawn contract
    finally:
        daemon._store.close()  # noqa: SLF001 - no daemon loop was started

    assert len(captured) == 3
    assert all(private_keys.isdisjoint(environment) for environment in captured)


def test_strict_cell_start_surfaces_handshake_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ORIN_CELL_IDENTITY_ENFORCE", "1")
    cell = CellBase(
        cap="cell.build",
        socket_path=tmp_path / "unused.sock",
        state_dir=tmp_path,
        handler=lambda payload: payload,
    )

    async def reject_handshake() -> None:
        raise ProtocolError("synthetic strict handshake failure")

    monkeypatch.setattr(cell, "_connect_and_serve", reject_handshake)

    with pytest.raises(RuntimeError, match="strict identity handshake"):
        cell.start()


def test_explicit_c1_harness_launches_only_authenticated_existing_cells(
    tmp_path: Path,
) -> None:
    with C1TestOrind(
        state_dir=tmp_path,
        cell_build=True,
        cell_file=True,
        cell_net=True,
        cell_secret=True,
    ) as orind:
        expected = {
            "cell.build",
            "cell.connector",
            "cell.file",
            "cell.net",
            "cell.secret",
        }
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            ready = {
                cap
                for cap in expected
                if orind.daemon._cell_by_cap(cap) is not None  # noqa: SLF001
            }
            if ready == expected:
                break
            time.sleep(0.05)
        else:
            pytest.fail(f"strict C1 Cells did not authenticate: {sorted(ready)!r}")

        assert orind.daemon._cell_ready_caps == expected  # noqa: SLF001
        assert all(
            pid in orind.daemon._expected_cell_caps_by_pid  # noqa: SLF001
            for pid in (proc.pid for proc in orind.daemon._cell_procs)  # noqa: SLF001
        )


async def _read_frame(reader: asyncio.StreamReader) -> dict[str, Any]:
    header = await reader.readexactly(4)
    size = int.from_bytes(header, "big")
    return parse_frame(await reader.readexactly(size))


async def _expect_disconnect(reader: asyncio.StreamReader) -> None:
    with pytest.raises((asyncio.IncompleteReadError, ConnectionError, TimeoutError)):
        await asyncio.wait_for(_read_frame(reader), timeout=1.0)


async def _wait_for_cell_state(
    daemon: OrinDaemon,
    cap: str,
    *,
    connected: bool,
) -> None:
    for _ in range(100):
        if (daemon._cell_by_cap(cap) is not None) is connected:  # noqa: SLF001
            return
        await asyncio.sleep(0.01)
    pytest.fail(f"Cell {cap} did not become connected={connected}")


@asynccontextmanager
async def _running_identity_daemon(tmp_path: Path) -> AsyncIterator[OrinDaemon]:
    with tempfile.TemporaryDirectory(prefix="orin-c1-cells-") as short:
        short_root = Path(short)
        daemon = OrinDaemon(
            state_dir=tmp_path,
            socket_path=short_root / "orind.sock",
            orin_dir=short_root,
            stage_b=True,
            cell_identity_enforce=True,
            c1_test_harness=True,
        )
        await daemon.start()
        try:
            yield daemon
        finally:
            await daemon.stop()


async def _send_hello(
    daemon: OrinDaemon,
    *,
    declared_pid: int,
    caps: list[str],
    launch_nonce: str,
    client_nonce: str | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
    reader, writer = await asyncio.open_unix_connection(path=str(daemon.cell_socket_path))
    nonce = client_nonce or launch_nonce
    hello = make_envelope(
        "hello",
        seq=1,
        nonce=nonce,
        session_key=None,
        caps=caps,
        pid=declared_pid,
    )
    writer.write(encode_frame(hello))
    await writer.drain()
    return reader, writer, nonce


def _authorize_current_process(daemon: OrinDaemon, cap: str, ticket: str) -> None:
    daemon._expected_cell_caps_by_pid[os.getpid()] = frozenset({cap})  # noqa: SLF001
    daemon._expected_cell_launch_by_pid[os.getpid()] = {cap: ticket}  # noqa: SLF001


def _session_key_path(daemon: OrinDaemon) -> Path:
    return daemon._orin_dir / f"session-{os.getpid()}.key"  # noqa: SLF001


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("declared_pid_delta", "caps", "ticket_kind"),
    [
        (1, ["cell.file"], "valid"),
        (0, [], "valid"),
        (0, ["cell.build"], "valid"),
        (0, ["cell.file", "cell.build"], "valid"),
        (0, ["cell.file"], "wrong"),
    ],
)
async def test_strict_hello_rejects_before_publishing_a_session_key(
    tmp_path: Path,
    declared_pid_delta: int,
    caps: list[str],
    ticket_kind: str,
) -> None:
    async with _running_identity_daemon(tmp_path) as daemon:
        ticket = secrets.token_hex(16)
        _authorize_current_process(daemon, "cell.file", ticket)
        reader, writer, _nonce = await _send_hello(
            daemon,
            declared_pid=os.getpid() + declared_pid_delta,
            caps=caps,
            launch_nonce=ticket if ticket_kind == "valid" else secrets.token_hex(16),
        )
        try:
            await _expect_disconnect(reader)
        finally:
            writer.close()
            await writer.wait_closed()

        assert not _session_key_path(daemon).exists()
        assert daemon._cell_by_cap("cell.file") is None  # noqa: SLF001


@pytest.mark.asyncio
async def test_launch_ticket_is_one_shot_and_authenticated_heartbeat_is_proof(
    tmp_path: Path,
) -> None:
    async with _running_identity_daemon(tmp_path) as daemon:
        cap = "cell.file"
        ticket = secrets.token_hex(16)
        _authorize_current_process(daemon, cap, ticket)
        reader, writer, client_nonce = await _send_hello(
            daemon,
            declared_pid=os.getpid(),
            caps=[cap],
            launch_nonce=ticket,
        )
        ack = await asyncio.wait_for(_read_frame(reader), timeout=1.0)
        session_nonce = client_nonce + str(ack["server_nonce"])
        key_path = _session_key_path(daemon)
        session_key = read_session_key_once(key_path)

        assert daemon._cell_by_cap(cap) is None  # noqa: SLF001
        proof = make_envelope(
            "heartbeat",
            seq=2,
            nonce=session_nonce,
            session_key=session_key,
        )
        writer.write(encode_frame(proof))
        await writer.drain()
        proof_ack = await asyncio.wait_for(_read_frame(reader), timeout=1.0)

        assert proof_ack["type"] == "heartbeat_ack"
        assert proof_ack.get("healthy") is True
        assert proof_ack["nonce"] == session_nonce
        assert verify_mac(session_key, proof_ack)
        await _wait_for_cell_state(daemon, cap, connected=True)

        writer.close()
        await writer.wait_closed()
        await _wait_for_cell_state(daemon, cap, connected=False)
        replay_reader, replay_writer, _ = await _send_hello(
            daemon,
            declared_pid=os.getpid(),
            caps=[cap],
            launch_nonce=ticket,
            client_nonce=client_nonce,
        )
        try:
            await _expect_disconnect(replay_reader)
        finally:
            replay_writer.close()
            await replay_writer.wait_closed()
        assert not key_path.exists()


@pytest.mark.asyncio
async def test_correct_mac_with_wrong_session_nonce_is_rejected(tmp_path: Path) -> None:
    async with _running_identity_daemon(tmp_path) as daemon:
        cap = "cell.file"
        ticket = secrets.token_hex(16)
        _authorize_current_process(daemon, cap, ticket)
        reader, writer, _client_nonce = await _send_hello(
            daemon,
            declared_pid=os.getpid(),
            caps=[cap],
            launch_nonce=ticket,
        )
        await asyncio.wait_for(_read_frame(reader), timeout=1.0)
        key_path = _session_key_path(daemon)
        session_key = read_session_key_once(key_path)
        forged = make_envelope(
            "heartbeat",
            seq=2,
            nonce="f" * 64,
            session_key=session_key,
        )
        writer.write(encode_frame(forged))
        await writer.drain()
        try:
            await _expect_disconnect(reader)
        finally:
            writer.close()
            await writer.wait_closed()

        assert daemon._cell_by_cap(cap) is None  # noqa: SLF001


@pytest.mark.asyncio
async def test_authenticated_cell_sequence_replay_is_rejected(tmp_path: Path) -> None:
    async with _running_identity_daemon(tmp_path) as daemon:
        cap = "cell.file"
        ticket = secrets.token_hex(16)
        _authorize_current_process(daemon, cap, ticket)
        reader, writer, client_nonce = await _send_hello(
            daemon,
            declared_pid=os.getpid(),
            caps=[cap],
            launch_nonce=ticket,
        )
        ack = await asyncio.wait_for(_read_frame(reader), timeout=1.0)
        session_nonce = client_nonce + str(ack["server_nonce"])
        session_key = read_session_key_once(_session_key_path(daemon))
        heartbeat = make_envelope(
            "heartbeat",
            seq=2,
            nonce=session_nonce,
            session_key=session_key,
        )
        writer.write(encode_frame(heartbeat))
        await writer.drain()
        assert (await _read_frame(reader))["type"] == "heartbeat_ack"

        writer.write(encode_frame(heartbeat))
        await writer.drain()
        try:
            await _expect_disconnect(reader)
        finally:
            writer.close()
            await writer.wait_closed()


async def _fake_orind_server() -> tuple[
    asyncio.AbstractServer,
    asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
    Path,
    tempfile.TemporaryDirectory[str],
]:
    short_root = tempfile.TemporaryDirectory(prefix="orin-c1-fake-cell-")
    socket_path = Path(short_root.name) / "cells.sock"
    connected: asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = (
        asyncio.get_running_loop().create_future()
    )

    async def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not connected.done():
            connected.set_result((reader, writer))

    server = await asyncio.start_unix_server(accept, path=str(socket_path))
    socket_path.chmod(0o600)
    return server, connected, socket_path, short_root


def _set_strict_cell_launch_env(
    monkeypatch: pytest.MonkeyPatch,
    *,
    daemon_pid: int,
    cap: str,
    ticket: str,
) -> None:
    monkeypatch.setenv("ORIN_CELL_IDENTITY_ENFORCE", "1")
    monkeypatch.setenv("ORIN_ORIND_PID", str(daemon_pid))
    monkeypatch.setenv(
        "ORIN_CELL_LAUNCH_TICKETS",
        json.dumps({cap: ticket}, sort_keys=True, separators=(",", ":")),
    )


@pytest.mark.asyncio
async def test_cell_rejects_socket_server_with_wrong_orind_pid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, connected, socket_path, short_root = await _fake_orind_server()
    ticket = secrets.token_hex(16)
    _set_strict_cell_launch_env(
        monkeypatch,
        daemon_pid=os.getpid() + 10_000,
        cap="cell.build",
        ticket=ticket,
    )
    monkeypatch.setattr(
        "js.orind.cells.base.peer_credentials",
        lambda _socket: (os.geteuid(), os.getpid()),
    )
    cell = CellBase(
        cap="cell.build",
        socket_path=socket_path,
        state_dir=tmp_path,
        handler=lambda payload: payload,
    )
    task = asyncio.create_task(cell._connect_and_serve())  # noqa: SLF001
    _reader, server_writer = await asyncio.wait_for(connected, timeout=1.0)

    with pytest.raises(ProtocolError, match="launching orind"):
        await asyncio.wait_for(task, timeout=2.0)

    assert cell._writer is not None  # noqa: SLF001
    cell._writer.close()  # noqa: SLF001
    server_writer.close()
    await asyncio.wait_for(server_writer.wait_closed(), timeout=1.0)
    server.close()
    await server.wait_closed()
    short_root.cleanup()


@pytest.mark.asyncio
async def test_cell_accepts_one_commit_then_rejects_server_sequence_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_orin = tmp_path / "orin"
    state_orin.mkdir(mode=0o700)
    server, connected, socket_path, short_root = await _fake_orind_server()
    cap = "cell.build"
    ticket = secrets.token_hex(16)
    _set_strict_cell_launch_env(
        monkeypatch,
        daemon_pid=os.getpid(),
        cap=cap,
        ticket=ticket,
    )
    monkeypatch.setattr(
        "js.orind.cells.base.peer_credentials",
        lambda _socket: (os.geteuid(), os.getpid()),
    )
    calls: list[dict[str, Any]] = []

    def execute(payload: dict[str, Any]) -> dict[str, Any]:
        calls.append(payload)
        return {"status": "COMMITTED"}

    cell = CellBase(
        cap=cap,
        socket_path=socket_path,
        state_dir=tmp_path,
        handler=execute,
    )
    cell_task = asyncio.create_task(cell._connect_and_serve())  # noqa: SLF001
    reader, writer = await asyncio.wait_for(connected, timeout=1.0)
    hello = await asyncio.wait_for(_read_frame(reader), timeout=1.0)
    assert hello.get("pid") == os.getpid()
    assert hello.get("caps") == [cap]
    assert hello.get("nonce") == ticket

    session_key = b"c" * 32
    key_path = state_orin / f"session-{os.getpid()}.key"
    key_path.write_bytes(session_key)
    key_path.chmod(0o600)
    server_nonce = secrets.token_hex(16)
    session_nonce = str(hello["nonce"]) + server_nonce
    hello_ack = make_envelope(
        "hello_ack",
        seq=1,
        nonce=session_nonce,
        session_key=None,
        ok=True,
        caps=[cap],
        server_nonce=server_nonce,
    )
    writer.write(encode_frame(hello_ack))
    await writer.drain()
    proof = await asyncio.wait_for(_read_frame(reader), timeout=1.0)
    assert proof["type"] == "heartbeat"
    assert proof["nonce"] == session_nonce
    assert verify_mac(session_key, proof)
    proof_ack = make_envelope(
        "heartbeat_ack",
        seq=2,
        nonce=session_nonce,
        session_key=session_key,
        ok=True,
        healthy=True,
    )
    writer.write(encode_frame(proof_ack))
    await writer.drain()

    permit = {"kind": "shell", "command": "echo frozen-wp7-frame"}
    commit = make_envelope(
        "commit",
        seq=3,
        nonce=session_nonce,
        session_key=session_key,
        permit=permit,
    )
    writer.write(encode_frame(commit))
    await writer.drain()
    commit_ack = await asyncio.wait_for(_read_frame(reader), timeout=1.0)
    assert commit_ack["type"] == "commit_ack"
    assert commit_ack.get("ok") is True
    assert calls == [permit]

    writer.write(encode_frame(commit))
    await writer.drain()
    with pytest.raises(ProtocolError, match="seq regression"):
        await asyncio.wait_for(cell_task, timeout=1.0)
    assert calls == [permit]

    writer.close()
    await writer.wait_closed()
    assert cell._writer is not None  # noqa: SLF001
    cell._writer.close()  # noqa: SLF001
    await cell._writer.wait_closed()  # noqa: SLF001
    server.close()
    await server.wait_closed()
    short_root.cleanup()
