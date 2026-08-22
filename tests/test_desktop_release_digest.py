from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from desktop.source_digest import desktop_source_digest
from js.echo.ledger import release_gates


@pytest.fixture
def desktop_release_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(
        release_gates,
        "_RELEASE_SOURCE_DIGEST_SURFACES",
        (Path("desktop"),),
    )
    files = {
        "desktop/build_driver.py": "DRIVER_VERSION = 1\n",
        "desktop/package.json": '{"private":true}\n',
        "desktop/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
        "desktop/requirements-build.txt": "pyinstaller==6.21.0\n",
        "desktop/sidecar/host.py": "HOST_VERSION = 1\n",
        "desktop/source_digest.py": "SOURCE_VERSION = 1\n",
        "desktop/src-tauri/Cargo.lock": "version = 4\n",
        "desktop/src-tauri/src/main.rs": "fn main() {}\n",
    }
    for relative, content in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return tmp_path


def test_release_digest_changes_when_desktop_source_changes(
    desktop_release_tree: Path,
) -> None:
    before = release_gates.release_source_digest(desktop_release_tree)
    (desktop_release_tree / "desktop/sidecar/host.py").write_text(
        "HOST_VERSION = 2\n",
        encoding="utf-8",
    )

    assert release_gates.release_source_digest(desktop_release_tree) != before


def test_desktop_digest_is_exact_release_digest(desktop_release_tree: Path) -> None:
    assert desktop_source_digest(desktop_release_tree) == release_gates.release_source_digest(
        desktop_release_tree
    )


@pytest.mark.parametrize(
    "relative",
    [
        "desktop/src-tauri/Cargo.lock",
        "desktop/pnpm-lock.yaml",
        "desktop/requirements-build.txt",
        "desktop/build_driver.py",
    ],
)
def test_desktop_locks_and_driver_are_release_sources(
    desktop_release_tree: Path,
    relative: str,
) -> None:
    before = release_gates.release_source_digest(desktop_release_tree)
    path = desktop_release_tree / relative
    path.write_bytes(path.read_bytes() + b"# changed\n")

    assert release_gates.release_source_digest(desktop_release_tree) != before


@pytest.mark.parametrize(
    "relative",
    [
        "desktop/node_modules/package/index.js",
        "desktop/src-tauri/target/release/js-agent-desktop",
        "desktop/src-tauri/binaries/js-agent-host-aarch64-apple-darwin",
        "desktop/src-tauri/gen/schemas/desktop-schema.json",
        "desktop/.pytest_cache/v/cache/nodeids",
        "desktop/cache/tool/state.bin",
        "desktop/sidecar/__pycache__/host.cpython-312.pyc",
        "desktop/.embedded_source_digest",
    ],
)
def test_generated_desktop_outputs_do_not_change_release_digest(
    desktop_release_tree: Path,
    relative: str,
) -> None:
    before = release_gates.release_source_digest(desktop_release_tree)
    generated = desktop_release_tree / relative
    generated.parent.mkdir(parents=True, exist_ok=True)
    generated.write_bytes(b"generated-build-output")

    assert release_gates.release_source_digest(desktop_release_tree) == before


@pytest.mark.parametrize("suffix", [".png", ".icns"])
def test_release_source_integrity_accepts_desktop_binary_icons_but_rejects_symlinks(
    desktop_release_tree: Path,
    suffix: str,
) -> None:
    icon = desktop_release_tree / f"desktop/src-tauri/icons/icon{suffix}"
    icon.parent.mkdir(parents=True, exist_ok=True)
    icon.write_bytes(b"\x00\xff\x89binary-icon-source")

    release_gates.validate_release_source_integrity(desktop_release_tree)

    link = desktop_release_tree / "desktop/sidecar/linked_host.py"
    link.symlink_to(desktop_release_tree / "desktop/sidecar/host.py")
    with pytest.raises(ValueError, match=r"desktop/sidecar/linked_host\.py: symlink"):
        release_gates.validate_release_source_integrity(desktop_release_tree)


def test_live_and_immutable_archive_digest_share_desktop_generated_filter(
    desktop_release_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = desktop_release_tree / "desktop/src-tauri/target/release/generated"
    generated.parent.mkdir(parents=True)
    generated.write_bytes(b"must-not-be-hashed")
    live_digest = release_gates.release_source_digest(desktop_release_tree)

    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w") as archive:
        for path in sorted((desktop_release_tree / "desktop").rglob("*")):
            if path.is_file():
                archive.add(path, arcname=path.relative_to(desktop_release_tree).as_posix())
    monkeypatch.setattr(
        release_gates,
        "_git_bytes",
        lambda *_args, **_kwargs: archive_bytes.getvalue(),
    )

    assert release_gates._git_release_source_digest(desktop_release_tree, "f" * 40) == live_digest


@pytest.mark.parametrize(
    "member_name",
    [
        "/desktop/sidecar/host.py",
        "desktop/./sidecar/host.py",
        "desktop/../evil.txt",
        "desktop//sidecar/host.py",
        "C:/desktop/sidecar/host.py",
        "C:\\desktop\\sidecar\\host.py",
        "desktop\\sidecar\\host.py",
    ],
)
def test_immutable_archive_digest_rejects_noncanonical_member_names_before_hashing(
    desktop_release_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    member_name: str,
) -> None:
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w") as archive:
        legitimate = tarfile.TarInfo("desktop/sidecar/host.py")
        legitimate.size = len(b"HOST_VERSION = 1\n")
        archive.addfile(legitimate, io.BytesIO(b"HOST_VERSION = 1\n"))
        malicious = tarfile.TarInfo(member_name)
        malicious.size = len(b"malicious")
        archive.addfile(malicious, io.BytesIO(b"malicious"))
    monkeypatch.setattr(
        release_gates,
        "_git_bytes",
        lambda *_args, **_kwargs: archive_bytes.getvalue(),
    )

    assert release_gates._git_release_source_digest(desktop_release_tree, "f" * 40) is None


def test_immutable_archive_digest_rejects_duplicate_member_names(
    desktop_release_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w") as archive:
        for payload in (b"first", b"second"):
            member = tarfile.TarInfo("desktop/sidecar/host.py")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    monkeypatch.setattr(
        release_gates,
        "_git_bytes",
        lambda *_args, **_kwargs: archive_bytes.getvalue(),
    )

    assert release_gates._git_release_source_digest(desktop_release_tree, "f" * 40) is None
