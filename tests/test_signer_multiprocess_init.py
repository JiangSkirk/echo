"""Multiprocess first-init race tests for signing keypair generation."""

from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from js.security import signer

_REPO_ROOT = str(Path(__file__).resolve().parents[1])
_PROCESS_COUNT = 8
_ROUND_COUNT = 20


_WORKER_SCRIPT = """
import base64
import os
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, {repo_root!r})
from js.security import signer

round_dir = Path({round_dir!r})
ready_dir = round_dir / ".barrier-ready"
go_file = round_dir / ".barrier-go"
ready_dir.mkdir(parents=True, exist_ok=True)
(ready_dir / str(os.getpid())).touch()
deadline = time.monotonic() + 30.0
while len(list(ready_dir.iterdir())) < {process_count}:
    if time.monotonic() > deadline:
        raise SystemExit(92)
    time.sleep(0.001)
if os.getpid() == min(int(p.name) for p in ready_dir.iterdir()):
    go_file.touch()
while not go_file.exists():
    if time.monotonic() > deadline:
        raise SystemExit(93)
    time.sleep(0.001)

private_key = signer.generate_signing_key(round_dir)
pub_bytes = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
print(base64.b64encode(pub_bytes).decode("ascii"), flush=True)
"""


def _run_barrier_round(round_dir: Path) -> list[str]:
    ready_dir = round_dir / ".barrier-ready"
    go_file = round_dir / ".barrier-go"
    if ready_dir.exists():
        for child in ready_dir.iterdir():
            child.unlink(missing_ok=True)
    go_file.unlink(missing_ok=True)

    env = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": _REPO_ROOT,
    }
    code = _WORKER_SCRIPT.format(
        repo_root=_REPO_ROOT,
        round_dir=str(round_dir),
        process_count=_PROCESS_COUNT,
    )
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", code],
            env=env,
            cwd=_REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(_PROCESS_COUNT)
    ]
    outputs: list[str] = []
    for proc in procs:
        stdout, stderr = proc.communicate(timeout=120)
        assert proc.returncode == 0, (
            f"child exited {proc.returncode}; stdout={stdout!r} stderr={stderr!r}"
        )
        line = stdout.strip().splitlines()[-1]
        assert line, f"empty stdout from child: stderr={stderr!r}"
        outputs.append(line)
    return outputs


def _assert_no_keypair_leftovers(state_dir: Path) -> None:
    assert not (state_dir / ".signing_keypair.journal").exists()
    assert not list(state_dir.glob(".signing_key.tmp-*"))
    assert not list(state_dir.glob(".signing_key.pub.tmp-*"))


def test_signing_keypair_multiprocess_first_init_barrier(tmp_path: Path) -> None:
    """Eight processes × 20 rounds must agree on one keypair with no leftovers."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()

    for round_idx in range(_ROUND_COUNT):
        round_dir = state_dir / f"round-{round_idx}"
        round_dir.mkdir()
        results = _run_barrier_round(round_dir)
        assert len(results) == _PROCESS_COUNT
        assert len(set(results)) == 1, (
            f"round {round_idx}: expected one public key, got {len(set(results))}: {results}"
        )

        private_key = signer.load_signing_key(round_dir)
        assert private_key is not None
        expected = base64.b64encode(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii")
        assert results[0] == expected

        priv_path = round_dir / ".signing_key"
        pub_path = round_dir / ".signing_key.pub"
        assert priv_path.is_file() and pub_path.is_file()
        assert not priv_path.is_symlink() and not pub_path.is_symlink()
        loaded_pub = pub_path.read_bytes()
        derived_pub = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        assert loaded_pub == derived_pub
        _assert_no_keypair_leftovers(round_dir)


@pytest.mark.parametrize(
    "fault_point",
    [
        "after_journal",
        "after_private_write",
        "after_public_write",
        "after_private_publish",
        "after_public_publish",
        "before_cleanup",
    ],
)
def test_signing_keypair_subprocess_crash_windows_under_lock(
    tmp_path: Path, fault_point: str
) -> None:
    """Real os._exit crash windows must recover cleanly with cross-process lock."""
    state = tmp_path / "state"
    state.mkdir()
    env = os.environ.copy()
    env["JS_SIGNING_KEYPAIR_FAULT"] = fault_point
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = _REPO_ROOT
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; from js.security import signer; "
            f"signer.generate_signing_key(Path({str(state)!r}))",
        ],
        env=env,
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0, (
        f"expected injected crash at {fault_point}, got success stdout={proc.stdout!r}"
    )

    recovered = signer.generate_signing_key(state)
    pub = signer.get_public_key(state)
    expected = base64.b64encode(
        recovered.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    assert pub == expected
    assert (state / ".signing_key").is_file()
    assert (state / ".signing_key.pub").is_file()
    _assert_no_keypair_leftovers(state)
