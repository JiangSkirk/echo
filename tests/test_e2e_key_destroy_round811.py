from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from js.echo.ledger.e2e_signing import (
    assert_no_private_key_under,
    assert_provenance_destroyed,
    destroy_private_key,
    mark_destroyed,
    prepare_ephemeral_keypair,
    write_provenance_receipt,
)


def _prepare(tmp_path: Path):
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    keys_parent = tmp_path / "external-keys"
    (repo / "docs" / "security").mkdir(parents=True)
    evidence.mkdir()
    keys_parent.mkdir()
    os.chmod(keys_parent, 0o700)
    return (
        repo,
        evidence,
        prepare_ephemeral_keypair(
            repo,
            evidence_root=evidence,
            keys_parent=keys_parent,
        ),
    )


def _assert_destroy_failure_closed(handle) -> None:
    assert handle._closed
    assert not handle._owns_dir_fd
    assert handle._close_state == "closed"
    with pytest.raises(RuntimeError, match="already closed"):
        destroy_private_key(handle)


def test_handle_destroy_and_provenance_closure(tmp_path: Path) -> None:
    repo, evidence, (handle, pubkey, provenance) = _prepare(tmp_path)
    private_path = handle.path

    assert private_path.is_file()
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
    assert not private_path.resolve().is_relative_to(repo.resolve())
    assert not private_path.resolve().is_relative_to(evidence.resolve())
    assert pubkey["fingerprint_sha256"] == provenance["public_fingerprint"]
    assert not any(tmp_path.rglob(".private_key_env_path"))

    with pytest.raises(TypeError, match="EphemeralKeyHandle"):
        destroy_private_key(private_path)  # type: ignore[arg-type]

    destroy_private_key(handle)
    assert not private_path.exists()
    destroyed = mark_destroyed(provenance)
    receipt = evidence / "e2e" / "E2E_KEY_PROVENANCE.json"
    write_provenance_receipt(receipt, destroyed)
    assert receipt.is_file()
    assert_provenance_destroyed(destroyed)
    assert_no_private_key_under(evidence)


def test_destroy_refuses_hardlinked_private_key(tmp_path: Path) -> None:
    _repo, _evidence, (handle, _pubkey, _provenance) = _prepare(tmp_path)
    private_path = handle.path
    private_parent = private_path.parent
    alias = tmp_path / "private-key-hardlink"
    os.link(private_path, alias)

    with pytest.raises(PermissionError, match="nlink"):
        destroy_private_key(handle)
    _assert_destroy_failure_closed(handle)
    assert private_path.is_file()
    assert alias.is_file()

    alias.unlink()
    private_path.unlink()
    private_parent.rmdir()


@pytest.mark.parametrize("drift", ["mode", "size"])
def test_destroy_refuses_mode_or_size_drift(tmp_path: Path, drift: str) -> None:
    _repo, _evidence, (handle, _pubkey, _provenance) = _prepare(tmp_path)
    private_path = handle.path
    private_parent = private_path.parent
    if drift == "mode":
        os.chmod(private_path, 0o640)
    else:
        private_path.write_bytes(b"x")

    with pytest.raises(RuntimeError, match="identity drifted"):
        destroy_private_key(handle)

    _assert_destroy_failure_closed(handle)
    private_path.unlink()
    private_parent.rmdir()


def test_destroy_refuses_replaced_inode(tmp_path: Path) -> None:
    _repo, _evidence, (handle, _pubkey, _provenance) = _prepare(tmp_path)
    private_path = handle.path
    private_parent = private_path.parent
    private_path.unlink()
    private_path.write_bytes(os.urandom(32))
    os.chmod(private_path, 0o600)

    with pytest.raises(RuntimeError, match="identity drifted"):
        destroy_private_key(handle)

    _assert_destroy_failure_closed(handle)
    private_path.unlink()
    private_parent.rmdir()


def test_parent_rename_and_symlink_cannot_redirect_destroy(tmp_path: Path) -> None:
    _repo, _evidence, (handle, _pubkey, _provenance) = _prepare(tmp_path)
    original_parent = handle.path.parent
    moved_parent = original_parent.with_name(f"{original_parent.name}-moved")
    original_parent.rename(moved_parent)

    decoy_parent = tmp_path / "decoy"
    decoy_parent.mkdir()
    os.chmod(decoy_parent, 0o700)
    decoy_key = decoy_parent / handle.path.name
    decoy_bytes = os.urandom(32)
    decoy_key.write_bytes(decoy_bytes)
    os.chmod(decoy_key, 0o600)
    original_parent.symlink_to(decoy_parent, target_is_directory=True)

    destroy_private_key(handle)

    assert not (moved_parent / handle.path.name).exists()
    assert decoy_key.read_bytes() == decoy_bytes
