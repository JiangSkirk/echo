from __future__ import annotations

import os
from pathlib import Path

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
    return (
        repo,
        evidence,
        prepare_ephemeral_keypair(
            repo,
            evidence_root=evidence,
            keys_parent=keys_parent,
        ),
    )


def test_destroy_unlinks_before_overwrite_and_preserves_external_hardlink(
    tmp_path: Path, monkeypatch
) -> None:
    """An external hardlink created in the validate->unlink window must NOT be
    overwritten. Destroy must fail closed (raise) instead of corrupting the
    external file."""
    _repo, _evidence, (handle, _pub, _prov) = _prepare(tmp_path)
    alias = tmp_path / "external-hardlink"
    real_unlink = os.unlink

    def racing_unlink(name, *, dir_fd=None, **kwargs):
        if dir_fd is not None and Path(name).name == handle.path.name:
            os.link(handle.path, alias)
        return real_unlink(name, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(os, "unlink", racing_unlink)

    with pytest.raises(PermissionError):
        destroy_private_key(handle)

    assert alias.is_file()
    assert len(alias.read_bytes()) == 32
    assert not handle.path.exists()
    assert handle._closed


def test_destroy_overwrites_only_when_nlink_zero(tmp_path: Path) -> None:
    """Normal destroy: unlink -> nlink==0 -> best-effort overwrite -> file gone."""
    _repo, _evidence, (handle, _pub, _prov) = _prepare(tmp_path)
    private_path = handle.path
    assert private_path.is_file()
    destroy_private_key(handle)
    assert not private_path.exists()
    assert handle._closed
    assert not private_path.parent.exists()


def test_destroy_cleanup_refuses_swapped_parent_path(tmp_path: Path, monkeypatch) -> None:
    """If the temp dir path is swapped (rename/decoy) after unlink, cleanup must
    NOT delete the wrong directory; handle still closes."""
    _repo, _evidence, (handle, _pub, _prov) = _prepare(tmp_path)
    original_parent = handle.path.parent
    moved = original_parent.with_name(original_parent.name + "-moved")
    decoy = tmp_path / "decoy-cleanup-target"
    decoy.mkdir()
    os.chmod(decoy, 0o700)
    real_write = os.write

    def swapping_write(fd, data, *a, **kw):
        result = real_write(fd, data, *a, **kw)
        if original_parent.is_dir():
            original_parent.rename(moved)
        # Place a decoy empty dir at the original path.
        decoy2 = tmp_path / "decoy-at-original-path"
        decoy2.mkdir()
        os.chmod(decoy2, 0o700)
        original_parent.symlink_to(decoy2, target_is_directory=True)
        return result

    monkeypatch.setattr(os, "write", swapping_write)
    destroy_private_key(handle)

    assert handle._closed
    # Decoy at the original path must NOT be deleted by cleanup.
    assert (tmp_path / "decoy-at-original-path").is_dir()


def test_destroy_provenance_not_false_green_on_external_link(tmp_path: Path, monkeypatch) -> None:
    """When an external link survives unlink, destroy raises so the caller
    cannot mark provenance destroyed=true."""
    _repo, _evidence, (handle, _pub, provenance) = _prepare(tmp_path)
    alias = tmp_path / "external-hardlink"
    real_unlink = os.unlink

    def racing_unlink(name, *, dir_fd=None, **kwargs):
        if dir_fd is not None and Path(name).name == handle.path.name:
            os.link(handle.path, alias)
        return real_unlink(name, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(os, "unlink", racing_unlink)

    destroyed = False
    try:
        destroy_private_key(handle)
        destroyed = True
    except PermissionError:
        pass
    assert not destroyed, "destroy must fail closed when external link survives"

    # Caller must NOT call mark_destroyed on this path; if they did, it would be
    # a false green. Assert provenance still says destroyed=False.
    assert provenance["destroyed"] is False
    alias.unlink()


def test_destroy_external_hardlink_content_unchanged(tmp_path: Path, monkeypatch) -> None:
    """The external hardlink's bytes must be byte-identical to the original key
    (overwrite must be skipped when nlink!=0 after unlink)."""
    _repo, _evidence, (handle, _pub, _prov) = _prepare(tmp_path)
    alias = tmp_path / "external-hardlink"
    real_unlink = os.unlink

    # Snapshot the original private key bytes via the trusted path before destroy.
    original_bytes = handle.path.read_bytes()

    def racing_unlink(name, *, dir_fd=None, **kwargs):
        if dir_fd is not None and Path(name).name == handle.path.name:
            os.link(handle.path, alias)
        return real_unlink(name, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(os, "unlink", racing_unlink)

    with pytest.raises(PermissionError):
        destroy_private_key(handle)

    assert alias.read_bytes() == original_bytes
