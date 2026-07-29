"""Round 8.1 B: signer journal recovery must not touch paths outside state_dir."""

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
    "priv_tmp",
    [
        "/tmp/round81-signer-sentinel",
        "../sentinel",
        "nested/path.tmp",
        ".signing_key.tmp-1-0123456789abcdef/../escape",
        ".signing_key.tmp-1-0123456789abcdef\x00evil",
        "unknown-prefix.tmp-1-0123456789abcdef",
    ],
)
def test_malicious_journal_temp_names_never_touch_outside_sentinel(
    tmp_path: Path, priv_tmp: str
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("KEEP", encoding="utf-8")
    state = tmp_path / "state"
    state.mkdir()
    abs_outside = outside / "abs-sentinel"
    abs_outside.write_text("ABS", encoding="utf-8")
    if priv_tmp.startswith("/"):
        # Point absolute path at a real outside file to prove deletion is blocked.
        target = abs_outside
        payload = _base_payload(priv_tmp=str(target))
    elif priv_tmp.startswith("../"):
        rel_sentinel = state.parent / "sentinel-rel"
        rel_sentinel.write_text("REL", encoding="utf-8")
        payload = _base_payload(priv_tmp=f"../{rel_sentinel.name}")
        target = rel_sentinel
    else:
        payload = _base_payload(priv_tmp=priv_tmp)
        target = sentinel

    _write_journal(state, payload)
    before = target.read_text(encoding="utf-8") if target.exists() else None
    with pytest.raises(ValueError):
        signer._recover_keypair(state)
    assert target.exists()
    assert target.read_text(encoding="utf-8") == before


@pytest.mark.parametrize(
    "payload",
    [
        _base_payload(version=2),
        _base_payload(phase="after_evil"),
        {k: v for k, v in _base_payload().items() if k != "pub_sha256"},
        {**_base_payload(), "extra": "nope"},
        _base_payload(priv_tmp=123),
    ],
)
def test_journal_schema_and_phase_are_strict(tmp_path: Path, payload: dict[str, object]) -> None:
    state = tmp_path / "state"
    state.mkdir()
    _write_journal(state, payload)
    with pytest.raises(ValueError):
        signer._recover_keypair(state)


def test_journal_symlink_is_rejected(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    real = tmp_path / "real-journal.json"
    real.write_text(json.dumps(_base_payload()), encoding="utf-8")
    os.chmod(real, 0o600)
    journal = state / ".signing_keypair.journal"
    journal.symlink_to(real)
    with pytest.raises(ValueError):
        signer._recover_keypair(state)


def test_cleanup_failure_is_not_silent_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    temp = state / ".signing_key.tmp-1-0123456789abcdef"
    temp.write_bytes(b"\x00" * 32)
    os.chmod(temp, 0o600)
    _write_journal(state, _base_payload(priv_tmp=temp.name))

    def _boom(*_a: object, **_k: object) -> None:
        raise OSError("cannot unlink")

    monkeypatch.setattr(os, "unlink", _boom)
    with pytest.raises(OSError, match="cannot unlink"):
        signer._recover_keypair(state)


def test_legitimate_basename_temp_is_cleaned(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    temp = state / ".signing_key.tmp-1-0123456789abcdef"
    temp.write_bytes(b"\x00" * 32)
    os.chmod(temp, 0o600)
    _write_journal(state, _base_payload(priv_tmp=temp.name, phase="after_private_write"))
    assert signer._recover_keypair(state) is None
    assert not temp.exists()
    assert not (state / ".signing_keypair.journal").exists()
