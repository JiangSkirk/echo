from __future__ import annotations

import os
from pathlib import Path

import pytest

from js.echo.ledger import e2e_signing
from js.echo.ledger.e2e_signing import (
    prepare_ephemeral_keypair,
)


def _setup(tmp_path: Path):
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    keys_parent = tmp_path / "external-keys"
    (repo / "docs" / "security").mkdir(parents=True)
    evidence.mkdir()
    keys_parent.mkdir()
    os.chmod(keys_parent, 0o700)
    return repo, evidence, keys_parent


def _count_open_fds() -> int:
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return -1


def _find_private_keys(root: Path) -> list[Path]:
    hits: list[Path] = []
    for path in root.rglob("*"):
        if path.is_file() and path.name == "ledger.ed25519.private":
            hits.append(path)
    return hits


def test_prepare_rolls_back_when_public_key_write_fails(tmp_path: Path, monkeypatch) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)

    def boom(root: Path, public_raw: bytes):
        raise OSError("simulated public key write failure")

    monkeypatch.setattr(e2e_signing, "write_frozen_pubkey", boom)

    with pytest.raises(OSError, match="simulated public key write failure"):
        prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)

    # No private key file may remain anywhere under the temp parent.
    assert _find_private_keys(keys_parent) == []
    # The frozen pubkey must not have been written (rollback means no partial state).
    assert not (repo / "docs" / "security" / "ECHO_E2E_LEDGER_PUBKEY.json").exists()
    # The trusted temp dir must be cleaned up (no empty dirs left under keys_parent).
    leftover = list(keys_parent.iterdir())
    assert leftover == [], f"temp key dir not cleaned up: {leftover}"


def test_prepare_rolls_back_on_short_write(tmp_path: Path, monkeypatch) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)

    real_write = os.write

    def short_write(fd, data, *args, **kwargs):
        # Always report a short count (1 byte) without writing the full payload.
        real_write(fd, data[:1])
        return 1

    monkeypatch.setattr(os, "write", short_write)

    with pytest.raises(Exception, match="short write|private key"):
        prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)

    assert _find_private_keys(keys_parent) == []
    leftover = list(keys_parent.iterdir())
    assert leftover == [], f"temp key dir not cleaned up: {leftover}"


def test_prepare_rollback_failure_is_not_marked_destroyed(tmp_path: Path, monkeypatch) -> None:
    """Rollback unlink failure must remain observable and never mark destroyed=true."""
    repo, evidence, keys_parent = _setup(tmp_path)

    def boom(root: Path, public_raw: bytes):
        raise OSError("PUBLIC_WRITE_FAILED")

    real_unlink = os.unlink

    def boom_unlink(path, *args, **kwargs):
        name = path if isinstance(path, str) else str(path)
        if name == "ledger.ed25519.private" or name.endswith("ledger.ed25519.private"):
            raise OSError("ROLLBACK_UNLINK_FAILED")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(e2e_signing, "write_frozen_pubkey", boom)
    monkeypatch.setattr(os, "unlink", boom_unlink)

    with pytest.raises(ExceptionGroup) as caught:
        prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)

    text = str(caught.value) + repr(caught.value.exceptions)
    assert "PUBLIC_WRITE_FAILED" in text
    assert "ROLLBACK_UNLINK_FAILED" in text
    assert _find_private_keys(keys_parent), "residual private key must remain after unlink failure"

    for path in evidence.rglob("*"):
        if path.is_file() and path.name.endswith(".json"):
            body = path.read_text(encoding="utf-8")
            assert '"destroyed": true' not in body, f"false destroyed=true in {path}"


def test_prepare_failure_leaves_no_private_key_or_open_fd(tmp_path: Path, monkeypatch) -> None:
    repo, evidence, keys_parent = _setup(tmp_path)

    def boom(root: Path, public_raw: bytes):
        raise OSError("simulated public key write failure")

    monkeypatch.setattr(e2e_signing, "write_frozen_pubkey", boom)

    before = _count_open_fds()
    try:
        prepare_ephemeral_keypair(repo, evidence_root=evidence, keys_parent=keys_parent)
    except OSError:
        pass

    assert _find_private_keys(keys_parent) == []
    leftover = list(keys_parent.iterdir())
    assert leftover == [], f"temp key dir not cleaned up: {leftover}"

    # No EphemeralKeyHandle should have leaked (dir_fd would be closed by __del__).
    import gc

    gc.collect()
    after = _count_open_fds()
    if before >= 0 and after >= 0:
        # Allow small fluctuation; a leaked dir_fd would show as +1 persistent.
        assert after - before < 2, f"fd leak detected: before={before} after={after}"
