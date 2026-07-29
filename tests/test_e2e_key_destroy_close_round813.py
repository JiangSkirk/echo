from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from js.echo.ledger.e2e_signing import (
    destroy_private_key,
    prepare_ephemeral_keypair,
)


def _prepare(tmp_path: Path):
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    keys_parent = tmp_path / "external-keys"
    (repo / "docs" / "security").mkdir(parents=True)
    evidence.mkdir()
    keys_parent.mkdir()
    os.chmod(keys_parent, 0o700)
    handle, pub, prov = prepare_ephemeral_keypair(
        repo, evidence_root=evidence, keys_parent=keys_parent
    )
    return handle, pub, prov


def _assert_fail_closed(handle, *, key_bytes_before: bytes | None = None) -> None:
    assert handle._closed
    if key_bytes_before is not None and handle.path.is_file():
        assert handle.path.read_bytes() == key_bytes_before


@pytest.mark.parametrize("field", ["mode", "uid", "dev", "ino"])
def test_destroy_parent_identity_drift_closes_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    handle, _pub, prov = _prepare(tmp_path)
    assert prov.get("destroyed") is False
    key_bytes = handle.path.read_bytes()
    parent = handle.path.parent
    real_fstat = os.fstat

    if field == "mode":
        os.chmod(parent, 0o755)
    else:

        def drifting_fstat(fd: int) -> Any:
            st = real_fstat(fd)
            if fd == handle._dir_fd:
                # Build a simple namespace-like override via os.stat_result if needed.
                vals = list(st)
                # st_mode, st_ino, st_dev, st_nlink, st_uid, st_gid, st_size, ...
                if field == "uid":
                    # index 4 is st_uid on macOS/Linux stat_result
                    vals[4] = int(st.st_uid) + 1
                elif field == "ino":
                    vals[1] = int(st.st_ino) + 999
                elif field == "dev":
                    vals[2] = int(st.st_dev) ^ 0xFFFF
                return os.stat_result(vals)
            return st

        monkeypatch.setattr(os, "fstat", drifting_fstat)

    with pytest.raises(RuntimeError, match="parent identity drifted"):
        destroy_private_key(handle)

    _assert_fail_closed(handle, key_bytes_before=key_bytes)
    assert handle.path.is_file()
    assert prov.get("destroyed") is False
    # Cleanup leftover key material (handle already closed).
    handle.path.unlink(missing_ok=True)
    try:
        parent.rmdir()
    except OSError:
        pass


def test_destroy_open_failure_closes_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle, _pub, prov = _prepare(tmp_path)
    key_bytes = handle.path.read_bytes()
    real_open = os.open

    def boom_open(path, flags, *args, **kwargs):
        if path == handle._basename or str(path).endswith("ledger.ed25519.private"):
            raise OSError("OPEN_FAILED")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", boom_open)
    with pytest.raises(OSError, match="OPEN_FAILED"):
        destroy_private_key(handle)
    assert handle._closed
    assert handle.path.is_file()
    assert handle.path.read_bytes() == key_bytes
    assert prov.get("destroyed") is False
    handle.path.unlink()
    try:
        handle.path.parent.rmdir()
    except OSError:
        pass


def test_destroy_unlink_failure_closes_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle, _pub, prov = _prepare(tmp_path)
    key_bytes = handle.path.read_bytes()
    real_unlink = os.unlink

    def boom_unlink(path, *args, **kwargs):
        if path == handle._basename or str(path).endswith("ledger.ed25519.private"):
            raise OSError("UNLINK_FAILED")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", boom_unlink)
    with pytest.raises(OSError, match="UNLINK_FAILED"):
        destroy_private_key(handle)
    assert handle._closed
    assert handle.path.is_file()
    assert handle.path.read_bytes() == key_bytes
    assert prov.get("destroyed") is False
    monkeypatch.undo()
    handle.path.unlink()
    try:
        handle.path.parent.rmdir()
    except OSError:
        pass


def test_destroy_fstat_failure_closes_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle, _pub, prov = _prepare(tmp_path)
    key_bytes = handle.path.read_bytes()
    real_fstat = os.fstat
    calls = {"n": 0}

    def boom_fstat(fd: int) -> Any:
        calls["n"] += 1
        # First fstat is parent; second is key after open — fail the key fstat.
        if calls["n"] >= 2:
            raise OSError("FSTAT_FAILED")
        return real_fstat(fd)

    monkeypatch.setattr(os, "fstat", boom_fstat)
    with pytest.raises(OSError, match="FSTAT_FAILED"):
        destroy_private_key(handle)
    assert handle._closed
    assert handle.path.is_file()
    assert handle.path.read_bytes() == key_bytes
    assert prov.get("destroyed") is False
    handle.path.unlink()
    try:
        handle.path.parent.rmdir()
    except OSError:
        pass


def test_destroy_overwrite_failure_closes_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle, _pub, prov = _prepare(tmp_path)
    real_write = os.write

    def boom_write(fd: int, data: bytes) -> int:
        raise OSError("OVERWRITE_FAILED")

    monkeypatch.setattr(os, "write", boom_write)
    with pytest.raises(OSError, match="OVERWRITE_FAILED"):
        destroy_private_key(handle)
    assert handle._closed
    assert prov.get("destroyed") is False
    # Trusted entry was unlinked before overwrite; parent may remain.
    assert not handle.path.exists()
    try:
        handle.path.parent.rmdir()
    except OSError:
        pass
    del real_write


def test_destroy_fsync_failure_closes_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle, _pub, prov = _prepare(tmp_path)

    def boom_fsync(fd: int) -> None:
        raise OSError("FSYNC_FAILED")

    monkeypatch.setattr(os, "fsync", boom_fsync)
    with pytest.raises(OSError, match="FSYNC_FAILED"):
        destroy_private_key(handle)
    assert handle._closed
    assert prov.get("destroyed") is False
    assert not handle.path.exists()
    try:
        handle.path.parent.rmdir()
    except OSError:
        pass


def test_destroy_close_failure_is_observable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle, _pub, prov = _prepare(tmp_path)
    real_close = os.close

    def boom_close(fd: int) -> None:
        if fd == handle._dir_fd:
            raise OSError("CLOSE_FAILED")
        return real_close(fd)

    monkeypatch.setattr(os, "close", boom_close)
    with pytest.raises(ExceptionGroup, match="residual|uncertain") as caught:
        destroy_private_key(handle)
    assert sum("CLOSE_FAILED" in str(exc) for exc in caught.value.exceptions) == 1
    # A failed close has unknowable state and must never retry the numeric FD.
    assert not handle._closed
    assert not handle._owns_dir_fd
    assert handle._close_state == "unknown"
    os.fstat(handle._dir_fd)
    monkeypatch.undo()
    os.close(handle._dir_fd)
    assert prov.get("destroyed") is False
