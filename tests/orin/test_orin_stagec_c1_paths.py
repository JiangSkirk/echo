"""WP-C1 private authority-path and lifecycle rejection tests."""

from __future__ import annotations

import os
import sqlite3
import stat
import tempfile
from pathlib import Path

import pytest

from js.orin.protocol import ProtocolError
from js.orind.cell_identity import read_session_key_once
from js.orind.cells.services import SecretStore
from js.orind.daemon import OrinDaemon, OrinDaemonError
from js.orind.keybox import KeyBox, KeyBoxError
from js.orind.membrane import CommitMembrane
from js.orind.private_paths import PrivatePathError, ensure_private_dir, verify_private_file
from js.orind.store import OrinStore


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o600)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def test_session_key_strict_read_is_one_shot(tmp_path: Path) -> None:
    key_path = tmp_path / "session-123.key"
    key = b"k" * 32
    _write_private(key_path, key)

    assert read_session_key_once(key_path) == key
    assert not key_path.exists()
    with pytest.raises(ProtocolError, match="unavailable"):
        read_session_key_once(key_path)


def test_session_key_read_rejects_intermediate_symlink_without_consuming_target(
    tmp_path: Path,
) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o700)
    outside_inner = tmp_path / "outside" / "inner"
    outside_inner.mkdir(parents=True, mode=0o700)
    target = outside_inner / "session-123.key"
    _write_private(target, b"k" * 32)
    (trusted / "alias").symlink_to(outside_inner.parent, target_is_directory=True)

    with pytest.raises(ProtocolError):
        read_session_key_once(trusted / "alias" / "inner" / target.name)

    assert target.read_bytes() == b"k" * 32


def test_session_key_publish_rejects_intermediate_symlink_without_writing_target(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    daemon = OrinDaemon(
        state_dir=state_dir,
        stage_b=True,
        cell_identity_enforce=True,
        c1_test_harness=True,
    )
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o700)
    outside_inner = tmp_path / "outside" / "inner"
    outside_inner.mkdir(parents=True, mode=0o700)
    (trusted / "alias").symlink_to(outside_inner.parent, target_is_directory=True)
    target = outside_inner / "session-123.key"

    try:
        identity = daemon._publish_strict_session_key(  # noqa: SLF001
            trusted / "alias" / "inner" / target.name,
            b"k" * 32,
        )
    finally:
        daemon._store.close()  # noqa: SLF001 - no daemon loop was started

    assert identity is None
    assert not target.exists()


def test_private_directory_contract_rejects_intermediate_symlink(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o700)
    outside_parent = tmp_path / "outside" / "parent"
    outside_child = outside_parent / "child"
    outside_child.mkdir(parents=True, mode=0o700)
    (trusted / "alias").symlink_to(outside_parent, target_is_directory=True)

    with pytest.raises(PrivatePathError):
        ensure_private_dir(trusted / "alias" / "child" / "must-not-exist")

    assert not (outside_child / "must-not-exist").exists()


def test_private_file_contract_rejects_replaced_ancestor_with_safe_leaf(
    tmp_path: Path,
) -> None:
    trusted = tmp_path / "trusted"
    inner = trusted / "inner"
    inner.mkdir(parents=True, mode=0o700)
    original = inner / "authority.key"
    _write_private(original, b"original")
    saved = tmp_path / "trusted-original"
    trusted.rename(saved)

    outside_inner = tmp_path / "outside" / "inner"
    outside_inner.mkdir(parents=True, mode=0o700)
    replacement = outside_inner / "authority.key"
    _write_private(replacement, b"replacement")
    trusted.symlink_to(outside_inner.parent, target_is_directory=True)

    with pytest.raises(PrivatePathError):
        verify_private_file(original)

    assert replacement.read_bytes() == b"replacement"


@pytest.mark.parametrize("attack", ["symlink", "hardlink", "wrong-mode"])
def test_session_key_rejects_links_and_wrong_mode_without_touching_target(
    tmp_path: Path,
    attack: str,
) -> None:
    key_path = tmp_path / "session-123.key"
    target = tmp_path / "outside-key"
    original = b"x" * 32
    _write_private(target, original)
    if attack == "symlink":
        key_path.symlink_to(target)
    elif attack == "hardlink":
        os.link(target, key_path)
    else:
        _write_private(key_path, original)
        key_path.chmod(0o640)

    with pytest.raises(ProtocolError, match="contract"):
        read_session_key_once(key_path)

    assert target.read_bytes() == original
    assert key_path.exists() or key_path.is_symlink()


@pytest.mark.parametrize("attack", ["symlink", "hardlink", "wrong-mode"])
def test_secret_store_rejects_unsafe_existing_file_without_repair(
    tmp_path: Path,
    attack: str,
) -> None:
    state_dir = tmp_path / "state"
    orin_dir = state_dir / "orin"
    orin_dir.mkdir(parents=True, mode=0o700)
    path = orin_dir / "secrets.jsonl"
    target = tmp_path / "outside-secrets"
    marker = b'{"handle_id":"outside","token":"keep"}\n'
    _write_private(target, marker)
    if attack == "symlink":
        path.symlink_to(target)
    elif attack == "hardlink":
        os.link(target, path)
    else:
        _write_private(path, marker)
        path.chmod(0o644)

    with pytest.raises(PrivatePathError):
        SecretStore(state_dir, strict_paths=True)

    assert target.read_bytes() == marker
    if attack == "wrong-mode":
        assert _mode(path) == 0o644


def test_secret_store_rejects_inode_replacement_before_writing_token(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    store = SecretStore(state_dir, strict_paths=True)
    store.put("sech:old", "old-token")
    path = state_dir / "orin" / "secrets.jsonl"
    original = path.with_suffix(".original")
    path.rename(original)
    replacement = b'{"handle_id":"replacement","token":"keep"}\n'
    _write_private(path, replacement)

    with pytest.raises(PrivatePathError, match="identity"):
        store.put("sech:new", "must-not-be-written")

    assert path.read_bytes() == replacement
    assert b"must-not-be-written" not in path.read_bytes()


def test_strict_keybox_rejects_non_private_state_parent(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o755)

    with pytest.raises(KeyBoxError, match="private"):
        KeyBox(state_dir, tier="dev", strict_paths=True)

    assert _mode(state_dir) == 0o755


@pytest.mark.parametrize("attack", ["symlink", "hardlink", "wrong-mode"])
def test_strict_keybox_rejects_unsafe_key_without_repair(
    tmp_path: Path,
    attack: str,
) -> None:
    state_dir = tmp_path / "state"
    orin_dir = state_dir / "orin"
    orin_dir.mkdir(parents=True, mode=0o700)
    path = orin_dir / "keybox.key"
    target = tmp_path / "outside-keybox"
    encoded = (b"ab" * 32)
    _write_private(target, encoded)
    if attack == "symlink":
        path.symlink_to(target)
    elif attack == "hardlink":
        os.link(target, path)
    else:
        _write_private(path, encoded)
        path.chmod(0o644)

    with pytest.raises(KeyBoxError):
        KeyBox(state_dir, tier="dev", strict_paths=True)

    assert target.read_bytes() == encoded
    if attack == "wrong-mode":
        assert _mode(path) == 0o644


def test_strict_keybox_rejects_fingerprint_replacement(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    KeyBox(state_dir, tier="dev", strict_paths=True)
    fingerprint = state_dir / "orin" / "keybox.fp"
    saved = fingerprint.with_suffix(".saved")
    fingerprint.rename(saved)
    outside = tmp_path / "outside-fingerprint"
    _write_private(outside, b"0" * 64 + b"\n")
    fingerprint.symlink_to(outside)

    with pytest.raises(KeyBoxError, match="fingerprint"):
        KeyBox(state_dir, tier="dev", strict_paths=True)

    assert outside.read_bytes() == b"0" * 64 + b"\n"


@pytest.mark.parametrize("attack", ["symlink", "wrong-mode"])
def test_strict_cell_runtime_parent_rejects_unsafe_existing_directory(
    tmp_path: Path,
    attack: str,
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    daemon = OrinDaemon(
        state_dir=state_dir,
        stage_b=True,
        cell_identity_enforce=True,
        c1_test_harness=True,
    )
    runtime_parent = state_dir / "orin" / "cell-runtime"
    outside = tmp_path / "outside-runtime"
    outside.mkdir(mode=0o755)
    if attack == "symlink":
        runtime_parent.symlink_to(outside, target_is_directory=True)
    else:
        runtime_parent.mkdir(mode=0o755)

    try:
        with pytest.raises((OrinDaemonError, PrivatePathError)):
            daemon._new_cell_launch(  # noqa: SLF001 - C1 strict-path contract
                "build",
                frozenset({"cell.build"}),
            )
    finally:
        daemon._store.close()  # noqa: SLF001 - no daemon loop was started

    assert _mode(outside) == 0o755
    if attack == "wrong-mode":
        assert _mode(runtime_parent) == 0o755


@pytest.mark.parametrize("attack", ["symlink", "hardlink", "wrong-mode"])
def test_strict_wal_store_rejects_unsafe_database_without_repair(
    tmp_path: Path,
    attack: str,
) -> None:
    orin_dir = tmp_path / "orin"
    orin_dir.mkdir(mode=0o700)
    database = orin_dir / "orind_state.db"
    target = tmp_path / "outside-db"
    _write_private(target, b"")
    if attack == "symlink":
        database.symlink_to(target)
    elif attack == "hardlink":
        os.link(target, database)
    else:
        _write_private(database, b"")
        database.chmod(0o644)

    with pytest.raises(PrivatePathError):
        OrinStore(database, strict_paths=True)

    assert target.read_bytes() == b""
    if attack == "wrong-mode":
        assert _mode(database) == 0o644


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_strict_wal_store_rejects_unsafe_sqlite_sidecar(
    tmp_path: Path,
    suffix: str,
) -> None:
    orin_dir = tmp_path / "orin"
    orin_dir.mkdir(mode=0o700)
    database = orin_dir / "orind_state.db"
    _write_private(database, b"")
    sidecar = Path(f"{database}{suffix}")
    _write_private(sidecar, b"")
    sidecar.chmod(0o644)

    with pytest.raises(PrivatePathError):
        OrinStore(database, strict_paths=True)

    assert _mode(sidecar) == 0o644


def test_strict_wal_store_detects_database_replacement_after_open(tmp_path: Path) -> None:
    database = tmp_path / "orin" / "orind_state.db"
    store = OrinStore(database, strict_paths=True)
    original = database.with_suffix(".original")
    database.rename(original)
    _write_private(database, b"")

    with pytest.raises(sqlite3.DatabaseError):
        store._conn.execute("SELECT 1").fetchone()  # noqa: SLF001 - replacement probe

    store.close()


def test_strict_commit_membrane_uses_same_database_contract(tmp_path: Path) -> None:
    orin_dir = tmp_path / "orin"
    orin_dir.mkdir(mode=0o700)
    database = orin_dir / "orind_state.db"
    outside = tmp_path / "outside-membrane"
    _write_private(outside, b"")
    database.symlink_to(outside)

    with pytest.raises(PrivatePathError):
        CommitMembrane(database, strict_paths=True)

    assert outside.read_bytes() == b""


def _long_orin_dir(tmp_path: Path) -> Path:
    path = tmp_path / ("long-orin-state-" + "x" * 80) / "orin"
    path.mkdir(parents=True, mode=0o700)
    return path


def test_short_socket_pointer_rejects_symlink_without_overwriting_target(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    orin_dir = _long_orin_dir(tmp_path)
    pointer = orin_dir / "cells.sock.path"
    outside = tmp_path / "outside-pointer"
    marker = b"do-not-overwrite"
    _write_private(outside, marker)
    pointer.symlink_to(outside)
    with (
        tempfile.TemporaryDirectory(prefix="orin-c1-main-") as short,
        pytest.raises((OrinDaemonError, PrivatePathError)),
    ):
        OrinDaemon(
            state_dir=state_dir,
            socket_path=Path(short) / "orind.sock",
            orin_dir=orin_dir,
            stage_b=True,
            cell_identity_enforce=True,
            c1_test_harness=True,
        )

    assert outside.read_bytes() == marker


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["symlink", "regular-file"])
async def test_strict_cell_socket_rejects_non_socket_leaf_without_repair(
    tmp_path: Path,
    attack: str,
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="orin-c1-socket-") as short:
        orin_dir = Path(short) / "orin"
        orin_dir.mkdir(mode=0o700)
        socket_path = orin_dir / "cells.sock"
        outside = tmp_path / "outside-socket"
        marker = b"do-not-touch"
        _write_private(outside, marker)
        if attack == "symlink":
            socket_path.symlink_to(outside)
        else:
            _write_private(socket_path, marker)
        daemon = OrinDaemon(
            state_dir=state_dir,
            socket_path=Path(short) / "orind.sock",
            orin_dir=orin_dir,
            stage_b=True,
            cell_identity_enforce=True,
            c1_test_harness=True,
        )

        try:
            with pytest.raises(OrinDaemonError, match="socket"):
                await daemon.start()
        finally:
            await daemon.stop()

        assert outside.read_bytes() == marker
        if attack == "regular-file":
            assert socket_path.read_bytes() == marker


@pytest.mark.asyncio
async def test_cell_socket_parent_alias_cannot_pass_identity_or_cleanup(
    tmp_path: Path,
) -> None:
    """An absolute leaf lstat is insufficient when an intermediate path moved."""

    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="orin-c1-parent-alias-") as short:
        short_root = Path(short)
        orin_dir = short_root / "orin"
        orin_dir.mkdir(mode=0o700)
        daemon = OrinDaemon(
            state_dir=state_dir,
            socket_path=short_root / "orind.sock",
            orin_dir=orin_dir,
            stage_b=True,
            cell_identity_enforce=True,
            c1_test_harness=True,
        )
        await daemon.start()
        socket_path = daemon.cell_socket_path
        assert socket_path.is_absolute()
        original_socket = socket_path.lstat()

        moved_orin_dir = short_root / "orin-moved"
        orin_dir.rename(moved_orin_dir)
        orin_dir.symlink_to(moved_orin_dir.name, target_is_directory=True)
        moved_socket = moved_orin_dir / socket_path.name

        # pathlib.Path.lstat() still reaches the same leaf inode because only
        # the final component is no-follow.  The pinned parent chain must make
        # this absolute path fail identity validation anyway.
        aliased_leaf = socket_path.lstat()
        assert (aliased_leaf.st_dev, aliased_leaf.st_ino) == (
            original_socket.st_dev,
            original_socket.st_ino,
        )
        identity_accepted = daemon._strict_socket_is_current(  # noqa: SLF001
            socket_path
        )

        await daemon.stop()

        outcome = {
            "identity_accepted": identity_accepted,
            "moved_socket_survived": moved_socket.exists(),
            "parent_alias_survived": orin_dir.is_symlink(),
        }
        assert outcome == {
            "identity_accepted": False,
            "moved_socket_survived": True,
            "parent_alias_survived": True,
        }


def test_strict_session_key_cleanup_preserves_replacement_inode(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="orin-c1-key-") as short:
        daemon = OrinDaemon(
            state_dir=state_dir,
            socket_path=Path(short) / "orind.sock",
            orin_dir=Path(short),
            stage_b=True,
            cell_identity_enforce=True,
            c1_test_harness=True,
        )
        key_path = Path(short) / "session-123.key"
        identity = daemon._publish_strict_session_key(  # noqa: SLF001
            key_path,
            b"k" * 32,
        )
        assert identity is not None
        original = key_path.with_suffix(".original")
        key_path.rename(original)
        replacement = b"replacement-key"
        _write_private(key_path, replacement)

        daemon._cleanup_strict_session_key(key_path, identity)  # noqa: SLF001

        assert key_path.read_bytes() == replacement
        assert original.read_bytes() == b"k" * 32
        daemon._store.close()  # noqa: SLF001 - no daemon loop was started


@pytest.mark.asyncio
async def test_short_cell_socket_and_pointer_are_private_and_cleaned(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    orin_dir = _long_orin_dir(tmp_path)
    pointer = orin_dir / "cells.sock.path"
    with tempfile.TemporaryDirectory(prefix="orin-c1-main-") as short:
        daemon = OrinDaemon(
            state_dir=state_dir,
            socket_path=Path(short) / "orind.sock",
            orin_dir=orin_dir,
            stage_b=True,
            cell_identity_enforce=True,
            c1_test_harness=True,
        )
        short_root = daemon.cell_socket_path.parent
        await daemon.start()
        assert stat.S_ISSOCK(daemon.cell_socket_path.lstat().st_mode)
        assert daemon.cell_socket_path.lstat().st_uid == os.geteuid()
        assert _mode(daemon.cell_socket_path) == 0o600
        assert short_root.lstat().st_uid == os.geteuid()
        assert _mode(short_root) == 0o700
        assert stat.S_ISREG(pointer.lstat().st_mode)
        assert pointer.lstat().st_uid == os.geteuid()
        assert _mode(pointer) == 0o600
        assert pointer.read_text(encoding="utf-8") == os.fspath(daemon.cell_socket_path)

        await daemon.stop()

    assert not pointer.exists()
    assert not short_root.exists()


@pytest.mark.asyncio
async def test_stop_preserves_replaced_cell_socket_and_pointer(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    orin_dir = _long_orin_dir(tmp_path)
    pointer = orin_dir / "cells.sock.path"
    with tempfile.TemporaryDirectory(prefix="orin-c1-main-") as short:
        daemon = OrinDaemon(
            state_dir=state_dir,
            socket_path=Path(short) / "orind.sock",
            orin_dir=orin_dir,
            stage_b=True,
            cell_identity_enforce=True,
            c1_test_harness=True,
        )
        await daemon.start()
        socket_path = daemon.cell_socket_path
        socket_path.unlink()
        socket_marker = b"replacement-socket"
        _write_private(socket_path, socket_marker)
        pointer.unlink()
        pointer_marker = b"replacement-pointer"
        _write_private(pointer, pointer_marker)

        await daemon.stop()

        assert socket_path.read_bytes() == socket_marker
        assert pointer.read_bytes() == pointer_marker
