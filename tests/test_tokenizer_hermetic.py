"""P1-7: tokenizer resources must be hermetic (offline, version-pinned).

Codex observed pytest collection pulling ``cl100k_base.tiktoken`` from the
network with an empty HOME, meaning release smoke depended on the user
machine's tokenizer cache.  These tests require:

- importing the benchmark modules never touches the network;
- the real tokenizer loads offline from the version-pinned vendored cache;
- a missing resource fails closed (never a silent imprecise counter).
"""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _blocked(*_args, **_kwargs):  # noqa: ANN001, ANN202
        raise OSError("network disabled by test")

    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _blocked)


def test_benchmark_modules_import_without_network(_no_network: None) -> None:
    """Importing the benchmark/baseline modules must not fetch anything."""
    import importlib

    for module_name in (
        "scripts.echo_architecture_benchmark",
        "benchmarks.old_architecture_baseline",
    ):
        module = importlib.import_module(module_name)
        assert module is not None


def test_tokenizer_loads_offline_from_vendored_cache(_no_network: None) -> None:
    pytest.importorskip("tiktoken")
    from js.echo.context_tokenizer import tiktoken_counter_factory

    counter = tiktoken_counter_factory("cl100k_base")
    assert counter(b"hello world") > 0
    assert counter.token_unit_id == "tiktoken:cl100k_base"


def test_tokenizer_missing_resource_fails_closed(tmp_path: Path) -> None:
    """No vendored cache + no network + empty TIKTOKEN_CACHE_DIR => hard error.

    Runs in a subprocess because tiktoken caches loaded encodings in-process.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    script = r'''
import os, socket, sys
socket.create_connection = lambda *a, **k: (_ for _ in ()).throw(OSError("network disabled"))
socket.socket.connect = lambda *a, **k: (_ for _ in ()).throw(OSError("network disabled"))
from js.echo.context_tokenizer import tiktoken_counter_factory
try:
    tiktoken_counter_factory("cl100k_base")
except Exception as exc:
    print(f"fail-closed ok: {type(exc).__name__}")
    sys.exit(0)
print("ERROR: tokenizer loaded without resource and without network")
sys.exit(1)
'''
    result = subprocess.run(
        [str(REPO_ROOT / ".venv" / "bin" / "python"), "-c", script],
        cwd=REPO_ROOT,
        env={
            "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "HOME": str(empty),
            "TMPDIR": str(empty),
            "TIKTOKEN_CACHE_DIR": str(empty),
        },
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"expected fail-closed, got rc={result.returncode}: "
        f"{result.stdout[-1000:]} {result.stderr[-1000:]}"
    )
    assert "fail-closed ok" in result.stdout


def test_full_pytest_collection_is_hermetic() -> None:
    """Collection with empty HOME/TMPDIR and no network must not download."""
    env = {
        "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    empty_home = REPO_ROOT / ".pytest-hermetic-home"
    try:
        empty_home.mkdir(exist_ok=True)
        env["HOME"] = str(empty_home)
        env["TMPDIR"] = str(empty_home)
        result = subprocess.run(
            [
                str(REPO_ROOT / ".venv" / "bin" / "python"),
                "-m",
                "pytest",
                "--collect-only",
                "-q",
                "-p",
                "no:cacheprovider",
            ],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert "openaipublic" not in result.stdout + result.stderr
        assert result.returncode == 0, (
            f"collection failed hermetically:\n{result.stdout[-2000:]}\n{result.stderr[-2000:]}"
        )
    finally:
        import shutil

        shutil.rmtree(empty_home, ignore_errors=True)
