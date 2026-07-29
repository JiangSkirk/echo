"""Round 8.3 B: signer non-regular files, validation order, state_dir hygiene."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from js.security import signer


def _write_journal(state_dir: Path, payload: dict[str, object], *, mode: int = 0o600) -> Path:
    path = state_dir / ".signing_keypair.journal"
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(path, mode)
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


def _run_recover_subprocess(
    state_dir: Path, timeout: float = 2.0
) -> subprocess.CompletedProcess[str]:
    code = (
        "from pathlib import Path\n"
        "from js.security import signer\n"
        f"signer._recover_keypair(Path({str(state_dir)!r}))\n"
    )
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
    )


def test_journal_fifo_fail_closed_quickly(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    fifo = state / ".signing_keypair.journal"
    os.mkfifo(fifo, 0o600)
    started = time.monotonic()
    with pytest.raises((ValueError, OSError, PermissionError)):
        signer._recover_keypair(state)
    assert time.monotonic() - started < 1.5


def test_journal_fifo_subprocess_does_not_hang(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    os.mkfifo(state / ".signing_keypair.journal", 0o600)
    proc = _run_recover_subprocess(state, timeout=2.0)
    assert proc.returncode != 0


def test_private_temp_fifo_rejected_quickly(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    temp_name = ".signing_key.tmp-1-0123456789abcdef"
    os.mkfifo(state / temp_name, 0o600)
    _write_journal(state, _base_payload(priv_tmp=temp_name))
    started = time.monotonic()
    with pytest.raises((ValueError, OSError, PermissionError)):
        signer._recover_keypair(state)
    assert time.monotonic() - started < 1.5
    # Temp FIFO must still exist (not deleted before rejection completes incorrectly)
    assert (state / temp_name).exists()


@pytest.mark.parametrize("mode", [0o400, 0o640, 0o666])
def test_bad_mode_journal_does_not_delete_temps(tmp_path: Path, mode: int) -> None:
    state = tmp_path / "state"
    state.mkdir()
    temp_name = ".signing_key.tmp-1-0123456789abcdef"
    temp = state / temp_name
    temp.write_bytes(b"\x00" * 32)
    os.chmod(temp, 0o600)
    _write_journal(state, _base_payload(priv_tmp=temp_name), mode=mode)
    with pytest.raises(PermissionError):
        signer._recover_keypair(state)
    assert temp.is_file()
    assert temp.read_bytes() == b"\x00" * 32


def test_write_journal_replace_failure_cleans_journal_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    state.mkdir()

    def boom(src: str, dst: str) -> None:
        raise OSError("inject replace failure")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="inject replace failure"):
        signer._write_journal(
            state,
            {
                "version": 1,
                "phase": "after_journal",
                "pub_sha256": "0" * 64,
                "priv_tmp": None,
                "pub_tmp": None,
            },
        )
    leftovers = list(state.glob(".signing_keypair.journal.tmp-*"))
    assert leftovers == []


def test_state_dir_symlink_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real_state"
    real.mkdir()
    link = tmp_path / "linked_state"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="state"):
        signer.generate_signing_key(link)
    assert list(real.glob(".signing_key*")) == []


def test_state_dir_inode_change_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    trusted = signer._open_trusted_state_dir(state)
    os.close(trusted.dir_fd)
    # Replace directory with a new inode of the same path.
    state.rmdir()
    state.mkdir()
    with pytest.raises(ValueError, match="state"):
        signer._open_trusted_state_dir(state, expected=trusted)


def test_journal_directory_rejected(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    (state / ".signing_keypair.journal").mkdir()
    with pytest.raises(ValueError, match="regular file"):
        signer._recover_keypair(state)


def test_orphan_journal_temp_swept_on_successful_init(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    orphan = state / ".signing_keypair.journal.tmp-9-0123456789abcdef"
    orphan.write_bytes(b"{}")
    os.chmod(orphan, 0o600)
    key = signer.generate_signing_key(state)
    assert key is not None
    assert not orphan.exists()
