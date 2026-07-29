from __future__ import annotations

import os
from pathlib import Path

import pytest

from js.echo.ledger import e2e_signing
from js.echo.ledger.e2e_signing import prepare_ephemeral_keypair


def _setup(tmp_path: Path):
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    keys_parent = tmp_path / "external-keys"
    (repo / "docs" / "security").mkdir(parents=True)
    evidence.mkdir()
    keys_parent.mkdir()
    os.chmod(keys_parent, 0o700)
    return repo, evidence, keys_parent


def _find_private_keys(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file() and p.name == "ledger.ed25519.private"]


def _exception_text(exc: BaseException) -> str:
    parts = [str(exc), repr(exc)]
    if isinstance(exc, BaseExceptionGroup):
        for sub in exc.exceptions:
            parts.append(_exception_text(sub))
    if exc.__cause__ is not None:
        parts.append(_exception_text(exc.__cause__))
    if exc.__context__ is not None and exc.__context__ is not exc.__cause__:
        parts.append(_exception_text(exc.__context__))
    return "\n".join(parts)


def test_prepare_rollback_unlink_failure_is_observable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)

    def boom_pubkey(root: Path, public_raw: bytes) -> dict[str, object]:
        raise OSError("PUBLIC_WRITE_FAILED")

    real_unlink = os.unlink

    def boom_unlink(path, *args, **kwargs):
        name = path if isinstance(path, str) else str(path)
        if name == "ledger.ed25519.private" or name.endswith("ledger.ed25519.private"):
            raise OSError("ROLLBACK_UNLINK_FAILED")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(e2e_signing, "write_frozen_pubkey", boom_pubkey)
    monkeypatch.setattr(os, "unlink", boom_unlink)

    with pytest.raises(ExceptionGroup) as caught:
        prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)

    text = _exception_text(caught.value)
    assert "PUBLIC_WRITE_FAILED" in text
    assert "ROLLBACK_UNLINK_FAILED" in text
    assert "residual private key may remain" in text
    assert "PUBLIC_WRITE_FAILED" not in str(caught.value).encode("utf-8").hex()  # sanity
    # Absolute path / key bytes must not appear in the group message.
    assert str(keys_parent) not in str(caught.value)
    residual = _find_private_keys(keys_parent)
    assert len(residual) == 1
    assert len(residual[0].read_bytes()) == 32
    # No destroyed=true provenance.
    for path in evidence.rglob("*.json"):
        assert '"destroyed": true' not in path.read_text(encoding="utf-8")


def test_prepare_rollback_close_failure_is_observable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)
    dir_fds: list[int] = []
    real_open = os.open

    def tracking_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        # Track directory FDs opened for the temp key dir.
        if kwargs.get("dir_fd") is None and (flags & getattr(os, "O_DIRECTORY", 0)):
            dir_fds.append(fd)
        return fd

    def boom_pubkey(root: Path, public_raw: bytes) -> dict[str, object]:
        raise OSError("PUBLIC_WRITE_FAILED")

    real_close = os.close

    def boom_close(fd: int) -> None:
        if dir_fds and fd == dir_fds[-1]:
            raise OSError("ROLLBACK_CLOSE_FAILED")
        return real_close(fd)

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(e2e_signing, "write_frozen_pubkey", boom_pubkey)
    monkeypatch.setattr(os, "close", boom_close)

    with pytest.raises(ExceptionGroup) as caught:
        prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)

    text = _exception_text(caught.value)
    assert "PUBLIC_WRITE_FAILED" in text
    assert "ROLLBACK_CLOSE_FAILED" in text
    assert "residual private key may remain" in text or "cleanup errors" in text


def test_prepare_rollback_fsync_failure_during_create_is_observable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)

    def boom_fsync(fd: int) -> None:
        raise OSError("CREATE_FSYNC_FAILED")

    monkeypatch.setattr(os, "fsync", boom_fsync)
    with pytest.raises((OSError, ExceptionGroup)) as caught:
        prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)
    text = _exception_text(caught.value)
    assert "CREATE_FSYNC_FAILED" in text
    # Successful rollback leaves no residual key.
    # If cleanup also fails we still must not claim destroyed=true.
    for path in evidence.rglob("*.json"):
        assert '"destroyed": true' not in path.read_text(encoding="utf-8")


def test_prepare_primary_plus_multiple_cleanup_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)

    def boom_pubkey(root: Path, public_raw: bytes) -> dict[str, object]:
        raise OSError("PUBLIC_WRITE_FAILED")

    real_unlink = os.unlink
    real_close = os.close
    dir_fds: list[int] = []
    real_open = os.open

    def tracking_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if kwargs.get("dir_fd") is None and (flags & getattr(os, "O_DIRECTORY", 0)):
            dir_fds.append(fd)
        return fd

    def boom_unlink(path, *args, **kwargs):
        name = path if isinstance(path, str) else str(path)
        if name == "ledger.ed25519.private" or name.endswith("ledger.ed25519.private"):
            raise OSError("ROLLBACK_UNLINK_FAILED")
        return real_unlink(path, *args, **kwargs)

    def boom_close(fd: int) -> None:
        if dir_fds and fd == dir_fds[-1]:
            raise OSError("ROLLBACK_CLOSE_FAILED")
        return real_close(fd)

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(e2e_signing, "write_frozen_pubkey", boom_pubkey)
    monkeypatch.setattr(os, "unlink", boom_unlink)
    monkeypatch.setattr(os, "close", boom_close)

    with pytest.raises(ExceptionGroup) as caught:
        prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)

    text = _exception_text(caught.value)
    assert "PUBLIC_WRITE_FAILED" in text
    assert "ROLLBACK_UNLINK_FAILED" in text
    assert "ROLLBACK_CLOSE_FAILED" in text
    assert "residual private key may remain" in text
    assert len(caught.value.exceptions) >= 3
    assert _find_private_keys(keys_parent), "must report residual key honestly"


def test_prepare_rollback_failure_is_not_marked_destroyed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Truly simulate rollback failure (unlink fails), not just primary failure."""
    repo, evidence, keys_parent = _setup(tmp_path)

    def boom_pubkey(root: Path, public_raw: bytes) -> dict[str, object]:
        raise OSError("PUBLIC_WRITE_FAILED")

    real_unlink = os.unlink

    def boom_unlink(path, *args, **kwargs):
        name = path if isinstance(path, str) else str(path)
        if name == "ledger.ed25519.private" or name.endswith("ledger.ed25519.private"):
            raise OSError("ROLLBACK_UNLINK_FAILED")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(e2e_signing, "write_frozen_pubkey", boom_pubkey)
    monkeypatch.setattr(os, "unlink", boom_unlink)

    with pytest.raises(ExceptionGroup) as caught:
        prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)

    assert "ROLLBACK_UNLINK_FAILED" in _exception_text(caught.value)
    assert _find_private_keys(keys_parent)
    for path in evidence.rglob("*.json"):
        assert '"destroyed": true' not in path.read_text(encoding="utf-8")
    assert not (repo / "docs" / "security" / "ECHO_E2E_LEDGER_PUBKEY.json").exists()
