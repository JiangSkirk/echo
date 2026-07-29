from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from fastapi import HTTPException

from js.echo.attachment_gate import (
    AttachmentGateError,
    AttachmentSnapshot,
    SecureUploadWriter,
    find_owned_upload_by_name,
    list_owned_upload_entries,
    list_owned_uploads,
    owner_slug,
    safe_upload_filename,
    session_slug,
    upload_dir,
)
from js.echo.attachment_gate import (
    delete_owned_upload_by_name as _delete_owned_upload_by_name,
)
from js.echo.attachment_gate import (
    read_agent_attachment as _read_agent_attachment,
)
from js.echo.attachment_gate import (
    resolve_owned_upload_path as _resolve_owned_upload_path,
)
from js.echo.attachment_gate import (
    validate_agent_attachment_path as _validate_agent_attachment_path,
)
from js.echo.attachment_gate import (
    validate_chat_attachments as _validate_chat_attachments,
)

__all__ = [
    "delete_owned_upload_by_name",
    "find_owned_upload_by_name",
    "list_owned_uploads",
    "list_owned_upload_entries",
    "owner_slug",
    "read_agent_attachment",
    "resolve_owned_upload_path",
    "safe_upload_filename",
    "secure_upload_writer",
    "session_slug",
    "upload_dir",
    "validate_agent_attachment_path",
    "validate_chat_attachments",
]


def read_agent_attachment(
    *,
    workspace: Path,
    path: str,
    owner_key_hash: str | None,
    session_id: str | None,
    max_bytes: int = 100 * 1024 * 1024,
) -> AttachmentSnapshot:
    try:
        return _read_agent_attachment(
            workspace=workspace,
            path=path,
            owner_key_hash=owner_key_hash,
            session_id=session_id,
            max_bytes=max_bytes,
        )
    except AttachmentGateError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc


def delete_owned_upload_by_name(
    workspace: Path,
    owner_key_hash: str | None,
    filename: str,
    session_id: str | None = None,
) -> bool:
    try:
        return _delete_owned_upload_by_name(
            workspace,
            owner_key_hash,
            filename,
            session_id,
        )
    except AttachmentGateError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc


@contextmanager
def secure_upload_writer(
    *,
    workspace: Path,
    owner_key_hash: str | None,
    session_id: str | None,
    filename: str | None,
    max_bytes: int = 100 * 1024 * 1024,
    quota_limits: object | None = None,
) -> Iterator[SecureUploadWriter]:
    """Translate the generic attachment gate error into an HTTP response."""
    try:
        with SecureUploadWriter(
            workspace,
            owner_key_hash,
            session_id,
            filename,
            max_bytes=max_bytes,
            quota_limits=quota_limits,
        ) as writer:
            yield writer
    except AttachmentGateError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc


def resolve_owned_upload_path(
    *,
    workspace: Path,
    path: str,
    owner_key_hash: str | None,
    session_id: str | None = None,
    allow_pending: bool = False,
) -> Path:
    try:
        return _resolve_owned_upload_path(
            workspace=workspace,
            path=path,
            owner_key_hash=owner_key_hash,
            session_id=session_id,
            allow_pending=allow_pending,
        )
    except AttachmentGateError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc


def validate_agent_attachment_path(
    *,
    workspace: Path,
    path: str,
    owner_key_hash: str | None = None,
    session_id: str | None = None,
) -> Path:
    try:
        return _validate_agent_attachment_path(
            workspace=workspace,
            path=path,
            owner_key_hash=owner_key_hash,
            session_id=session_id,
        )
    except AttachmentGateError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc


def validate_chat_attachments(
    *,
    workspace: Path,
    attachments: list[str],
    owner_key_hash: str | None,
    session_id: str | None,
) -> None:
    try:
        _validate_chat_attachments(
            workspace=workspace,
            attachments=attachments,
            owner_key_hash=owner_key_hash,
            session_id=session_id,
        )
    except AttachmentGateError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc
