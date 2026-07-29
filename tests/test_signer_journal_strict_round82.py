"""Round 8.2 B: strict signer journal validation, cleanup, and clear_journal."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from js.security import signer


def _write_journal(state_dir: Path, payload: dict[str, object]) -> Path:
    path = state_dir / ".signing_keypair.journal"
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _base_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "version": 1,
        "phase": "after_private_write",
        "pub_sha256": "0" * 64,
        "priv_tmp": ".signing_key.tmp-1-0123456789abcdef",
        "pub_tmp": None,
    }
    payload.update(overrides)
    return payload


@pytest.mark.parametrize(
    "version",
    ["1", True, 1.9],
)
def test_journal_version_rejects_non_int_types(tmp_path: Path, version: object) -> None:
    state = tmp_path / "state"
    state.mkdir()
    _write_journal(state, _base_payload(version=version))
    with pytest.raises(ValueError, match="unsupported signing keypair journal"):
        signer._recover_keypair(state)


def test_cross_prefix_temp_name_rejected_for_private_slot(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    pub_name = ".signing_key.pub.tmp-1-0123456789abcdef"
    (state / pub_name).write_bytes(b"x")
    os.chmod(state / pub_name, 0o644)
    _write_journal(state, _base_payload(priv_tmp=pub_name))
    with pytest.raises(ValueError):
        signer._recover_keypair(state)


def test_cross_prefix_temp_name_rejected_for_public_slot(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    priv_name = ".signing_key.tmp-1-0123456789abcdef"
    (state / priv_name).write_bytes(b"\x00" * 32)
    os.chmod(state / priv_name, 0o600)
    _write_journal(
        state,
        _base_payload(
            phase="after_public_write",
            priv_tmp=priv_name,
            pub_tmp=".signing_key.tmp-1-abcdef0123456789",
        ),
    )
    with pytest.raises(ValueError):
        signer._recover_keypair(state)


@pytest.mark.parametrize(
    ("phase", "priv_tmp", "pub_tmp"),
    [
        ("after_journal", ".signing_key.tmp-1-0123456789abcdef", None),
        ("after_private_write", None, ".signing_key.pub.tmp-1-0123456789abcdef"),
        ("after_public_publish", ".signing_key.tmp-1-0123456789abcdef", None),
    ],
)
def test_journal_phase_temp_field_combos_are_enforced(
    tmp_path: Path,
    phase: str,
    priv_tmp: str | None,
    pub_tmp: str | None,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    _write_journal(state, _base_payload(phase=phase, priv_tmp=priv_tmp, pub_tmp=pub_tmp))
    with pytest.raises(ValueError):
        signer._recover_keypair(state)


def test_clear_journal_unlink_failure_is_not_swallowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    _write_journal(state, _base_payload(phase="after_journal", priv_tmp=None, pub_tmp=None))

    real_unlink = os.unlink

    def _fail_journal_unlink(path: str | bytes, *args: object, **kwargs: object) -> None:
        name = os.path.basename(path if isinstance(path, str) else path.decode())
        if name == ".signing_keypair.journal":
            raise OSError("journal unlink blocked")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", _fail_journal_unlink)
    with pytest.raises(OSError, match="journal unlink blocked"):
        signer._clear_journal(state)


def test_cleanup_rejects_world_writable_public_temp(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    pub_name = ".signing_key.pub.tmp-1-0123456789abcdef"
    (state / pub_name).write_bytes(b"x" * 32)
    os.chmod(state / pub_name, 0o666)
    _write_journal(
        state,
        _base_payload(
            phase="after_public_write",
            priv_tmp=".signing_key.tmp-1-0123456789abcdef",
            pub_tmp=pub_name,
        ),
    )
    with pytest.raises((ValueError, PermissionError)):
        signer._recover_keypair(state)


def test_cleanup_rejects_wrong_owner_temp(tmp_path: Path) -> None:
    if os.getuid() == 0:
        pytest.skip("root owns all files")
    if not hasattr(os, "chown"):
        pytest.skip("chown unavailable")
    state = tmp_path / "state"
    state.mkdir()
    priv_name = ".signing_key.tmp-1-0123456789abcdef"
    temp = state / priv_name
    temp.write_bytes(b"\x00" * 32)
    os.chmod(temp, 0o600)
    try:
        os.chown(temp, os.getuid() + 1 if os.getuid() > 0 else 65534, -1)
    except PermissionError:
        pytest.skip("cannot change temp owner in this environment")
    _write_journal(state, _base_payload(priv_tmp=priv_name))
    with pytest.raises((ValueError, PermissionError)):
        signer._recover_keypair(state)


def test_validate_temp_basename_kind_private_public_journal() -> None:
    priv = ".signing_key.tmp-1-0123456789abcdef"
    pub = ".signing_key.pub.tmp-1-0123456789abcdef"
    journal = ".signing_keypair.journal.tmp-1-0123456789abcdef"
    signer._validate_temp_basename(priv, kind="private")
    signer._validate_temp_basename(pub, kind="public")
    signer._validate_temp_basename(journal, kind="journal")
    with pytest.raises(ValueError):
        signer._validate_temp_basename(pub, kind="private")
    with pytest.raises(ValueError):
        signer._validate_temp_basename(priv, kind="public")
    with pytest.raises(ValueError):
        signer._validate_temp_basename(priv, kind="journal")
