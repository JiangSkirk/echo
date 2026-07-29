from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from js.echo.ledger.e2e_signing import (
    E2E_PRIVATE_ENV,
    assert_no_private_key_under,
    assert_provenance_destroyed,
    destroy_private_key,
    load_private_key,
    mark_destroyed,
    open_private_key_bytes,
    prepare_ephemeral_keypair,
    write_provenance_receipt,
)


def test_prepare_uses_external_temp_not_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "docs" / "security").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    handle, payload, provenance = prepare_ephemeral_keypair(repo, evidence_root=evidence)
    private_path = handle.path
    assert not private_path.resolve().is_relative_to(repo.resolve())
    assert not private_path.resolve().is_relative_to(evidence.resolve())
    assert private_path.name == "ledger.ed25519.private"
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
    assert provenance["generation_method"] == "random"
    assert provenance["location_class"] == "external_temp"
    assert provenance["destroyed"] is False
    assert "private_path" not in provenance
    assert payload["fingerprint_sha256"] == provenance["public_fingerprint"]
    assert not (evidence / "e2e" / ".private_key_env_path").exists()
    with pytest.raises(RuntimeError, match="outside repo"):
        prepare_ephemeral_keypair(repo, keys_parent=repo / ".task-tmp" / "keys")
    destroy_private_key(handle)
    assert not private_path.exists()


def test_symlink_private_path_refuses_open_and_bare_path_destroy(tmp_path: Path) -> None:
    sentinel = tmp_path / "sentinel-secret"
    sentinel.write_bytes(os.urandom(32))
    os.chmod(sentinel, 0o600)
    key_dir = tmp_path / "keydir"
    key_dir.mkdir()
    os.chmod(key_dir, 0o700)
    link = key_dir / "ledger.ed25519.private"
    link.symlink_to(sentinel)
    with pytest.raises((PermissionError, OSError)):
        open_private_key_bytes(link)
    with pytest.raises(TypeError, match="EphemeralKeyHandle"):
        destroy_private_key(link)  # type: ignore[arg-type]
    assert sentinel.is_file()
    assert sentinel.read_bytes()


def test_destroy_and_provenance_receipt(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "docs" / "security").mkdir(parents=True)
    handle, _payload, provenance = prepare_ephemeral_keypair(repo)
    private_path = handle.path
    os.environ[E2E_PRIVATE_ENV] = str(private_path)
    try:
        key = load_private_key(private_path)
        assert key.public_key().public_bytes_raw()
        destroy_private_key(handle)
        provenance = mark_destroyed(provenance)
        receipt = tmp_path / "E2E_KEY_PROVENANCE.json"
        write_provenance_receipt(receipt, provenance)
        assert_provenance_destroyed(provenance)
        assert_no_private_key_under(tmp_path)
    finally:
        os.environ.pop(E2E_PRIVATE_ENV, None)


def test_failure_path_cleanup_leaves_no_key(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "docs" / "security").mkdir(parents=True)
    handle, _payload, provenance = prepare_ephemeral_keypair(repo)
    private_path = handle.path
    try:
        raise RuntimeError("simulated gate failure")
    except RuntimeError:
        destroy_private_key(handle)
        provenance = mark_destroyed(provenance)
    assert not private_path.exists()
    assert_provenance_destroyed(provenance)


def test_missing_or_false_destroyed_provenance_fails() -> None:
    with pytest.raises(RuntimeError, match="destroyed"):
        assert_provenance_destroyed(
            {
                "schema_version": "echo-e2e-ledger-key-provenance-v1",
                "generation_method": "random",
                "location_class": "external_temp",
                "destroyed": False,
            }
        )


def test_inode_replace_before_destroy_fails(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "docs" / "security").mkdir(parents=True)
    handle, _payload, _provenance = prepare_ephemeral_keypair(repo)
    private_path = handle.path
    parent = private_path.parent
    os.unlink(private_path)
    replacement = parent / "ledger.ed25519.private"
    replacement.write_bytes(os.urandom(32))
    os.chmod(replacement, 0o600)
    with pytest.raises(RuntimeError, match="identity drifted|missing"):
        destroy_private_key(handle)
    assert replacement.is_file()


def test_no_active_pointer_mechanism() -> None:
    import js.echo.ledger.e2e_signing as mod

    assert not hasattr(mod, "write_active_pointer")
    assert not hasattr(mod, "read_active_pointer")
    assert not hasattr(mod, "ACTIVE_POINTER_NAME")
