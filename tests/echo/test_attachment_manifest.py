from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from js.echo.attachment_gate import (
    AttachmentGateError,
    SecureUploadWriter,
    build_attachment_manifest,
    delete_owned_upload_by_name,
    list_owned_uploads,
    safe_upload_filename,
    upload_dir,
)
from js.echo.ledger.service import EchoBlockedError
from js.echo.turn_loop import EchoTurnLoop


def _owned_attachment(
    workspace: Path,
    *,
    owner: str,
    session: str,
    name: str = "note.txt",
    content: bytes = b"hello",
) -> str:
    directory = upload_dir(workspace, owner, session)
    directory.mkdir(parents=True)
    path = directory / name
    path.write_bytes(content)
    return path.relative_to(workspace).as_posix()


def test_attachment_manifest_binds_exact_owned_bytes_without_disclosing_path(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    relative_path = _owned_attachment(
        workspace,
        owner="owner-a",
        session="session-a",
    )

    manifest = build_attachment_manifest(
        workspace=workspace,
        attachments=[relative_path],
        owner_key_hash="owner-a",
        session_id="session-a",
    )

    assert manifest == (
        {
            "name": "note.txt",
            "size": 5,
            "sha256": "sha256:" + hashlib.sha256(b"hello").hexdigest(),
            "media_type": "text/plain",
        },
    )
    assert str(workspace) not in repr(manifest)
    assert "hello" not in repr(manifest)


def test_attachment_manifest_reads_from_open_descriptor_when_parent_is_swapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from js.echo import attachment_gate

    workspace = tmp_path / "workspace"
    relative_path = _owned_attachment(
        workspace,
        owner="owner-a",
        session="session-a",
        content=b"owned-bytes",
    )
    owned_path = workspace / relative_path
    scoped_dir = owned_path.parent
    parked_dir = scoped_dir.with_name(scoped_dir.name + "-parked")
    outside_dir = tmp_path / "outside-read"
    outside_dir.mkdir()
    (outside_dir / owned_path.name).write_bytes(b"outside-secret")
    original_open = attachment_gate._open_attachment_file

    def open_then_swap(root: Path, relative: Path) -> int:
        file_fd = original_open(root, relative)
        scoped_dir.rename(parked_dir)
        scoped_dir.symlink_to(outside_dir, target_is_directory=True)
        return file_fd

    monkeypatch.setattr(attachment_gate, "_open_attachment_file", open_then_swap)

    manifest = build_attachment_manifest(
        workspace=workspace,
        attachments=[relative_path],
        owner_key_hash="owner-a",
        session_id="session-a",
    )

    assert manifest[0]["sha256"] == (
        "sha256:" + hashlib.sha256(b"owned-bytes").hexdigest()
    )
    assert manifest[0]["sha256"] != (
        "sha256:" + hashlib.sha256(b"outside-secret").hexdigest()
    )


def test_upload_filename_removes_cross_platform_paths_controls_and_excess_length() -> None:
    sanitized = safe_upload_filename("..\\folder\\line\nname.txt")

    assert sanitized == "line_name.txt"
    assert "/" not in sanitized and "\\" not in sanitized
    assert len(safe_upload_filename("a" * 400 + ".txt").encode("utf-8")) <= 240


def test_attachment_manifest_rejects_another_owner_upload(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    relative_path = _owned_attachment(
        workspace,
        owner="owner-b",
        session="session-a",
    )

    with pytest.raises(AttachmentGateError, match="Upload access denied"):
        build_attachment_manifest(
            workspace=workspace,
            attachments=[relative_path],
            owner_key_hash="owner-a",
            session_id="session-a",
        )


def test_owned_upload_listing_does_not_follow_file_or_directory_symlinks(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    directory = upload_dir(workspace, "owner-a", "session-a")
    directory.mkdir(parents=True)
    (directory / "owned.txt").write_text("owned", encoding="utf-8")
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("outside", encoding="utf-8")
    outside_directory = tmp_path / "outside-directory"
    outside_directory.mkdir()
    (outside_directory / "nested-secret.txt").write_text("secret", encoding="utf-8")
    (directory / "file-link.txt").symlink_to(outside_file)
    (directory / "directory-link").symlink_to(outside_directory, target_is_directory=True)

    listed = list_owned_uploads(workspace, "owner-a", "session-a")

    assert [path.name for path in listed] == ["owned.txt"]


def test_owned_upload_delete_is_bound_to_open_session_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from js.echo import attachment_gate

    workspace = tmp_path / "workspace"
    relative_path = _owned_attachment(
        workspace,
        owner="owner-a",
        session="session-a",
    )
    owned_path = workspace / relative_path
    scoped_dir = owned_path.parent
    parked_dir = scoped_dir.with_name(scoped_dir.name + "-parked")
    outside_dir = tmp_path / "outside-delete"
    outside_dir.mkdir()
    outside_victim = outside_dir / owned_path.name
    outside_victim.write_text("preserve-me", encoding="utf-8")
    original_open = attachment_gate._open_existing_upload_dir

    def open_then_swap(*args: object, **kwargs: object) -> int | None:
        directory_fd = original_open(*args, **kwargs)  # type: ignore[arg-type]
        assert directory_fd is not None
        scoped_dir.rename(parked_dir)
        scoped_dir.symlink_to(outside_dir, target_is_directory=True)
        return directory_fd

    monkeypatch.setattr(
        attachment_gate,
        "_open_existing_upload_dir",
        open_then_swap,
    )

    assert delete_owned_upload_by_name(
        workspace,
        "owner-a",
        owned_path.name,
        "session-a",
    )
    assert outside_victim.read_text(encoding="utf-8") == "preserve-me"
    assert not (parked_dir / owned_path.name).exists()


def test_attachment_gate_rejects_raw_absolute_path_inside_owned_root(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    relative_path = _owned_attachment(
        workspace,
        owner="owner-a",
        session="session-a",
    )

    with pytest.raises(AttachmentGateError, match="relative"):
        build_attachment_manifest(
            workspace=workspace,
            attachments=[str((workspace / relative_path).resolve())],
            owner_key_hash="owner-a",
            session_id="session-a",
        )


def test_secure_upload_writer_publishes_atomically_with_collision_suffix(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"

    with SecureUploadWriter(
        workspace, "owner-a", "session-a", "note.txt"
    ) as first:
        first.write(b"first")
        first_path = first.commit()
    with SecureUploadWriter(
        workspace, "owner-a", "session-a", "note.txt"
    ) as second:
        second.write(b"second")
        second_path = second.commit()

    assert first_path.name == "note.txt"
    assert second_path.name == "note_1.txt"
    assert first_path.read_bytes() == b"first"
    assert second_path.read_bytes() == b"second"
    assert not list(first_path.parent.glob(".upload-*.tmp"))


def test_secure_upload_writer_rejects_symlinked_session_directory(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    scoped_dir = upload_dir(workspace, "owner-a", "session-a")
    scoped_dir.parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    scoped_dir.symlink_to(outside, target_is_directory=True)

    with pytest.raises(AttachmentGateError, match="Unsafe upload directory"):
        SecureUploadWriter(workspace, "owner-a", "session-a", "escape.txt")

    assert list(outside.iterdir()) == []


def test_secure_upload_writer_aborts_oversized_staging_file(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    with (
        pytest.raises(AttachmentGateError, match="too large"),
        SecureUploadWriter(
            workspace,
            "owner-a",
            "session-a",
            "large.bin",
            max_bytes=3,
        ) as writer,
    ):
        writer.write(b"four")

    scoped_dir = upload_dir(workspace, "owner-a", "session-a")
    assert list(scoped_dir.iterdir()) == []


@pytest.mark.asyncio
async def test_turn_loop_rejects_attachment_changed_after_admission(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    relative_path = _owned_attachment(
        workspace,
        owner="owner-a",
        session="session-a",
    )
    admitted = build_attachment_manifest(
        workspace=workspace,
        attachments=[relative_path],
        owner_key_hash="owner-a",
        session_id="session-a",
    )
    (workspace / relative_path).write_bytes(b"changed")
    loop = object.__new__(EchoTurnLoop)
    loop.agent = SimpleNamespace(settings=SimpleNamespace(workspace=workspace))
    loop.attachments = [relative_path]
    loop.attachment_manifest = admitted
    loop.owner_key_hash = "owner-a"
    loop.session_id = "session-a"

    with pytest.raises(EchoBlockedError, match="changed after the Echo turn was admitted"):
        await loop._assert_attachment_manifest_current()
