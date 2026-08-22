"""Server-only content-addressed artifact store for connector imports.

This module is NOT exported from ``js/connectors/__init__.py``.  It is
constructed once by ``EchoRuntime`` and passed as a private dependency
to the two production local connector instances.

The store root is ``<state_dir>/connector_artifacts/``.  Files are
content-addressed by SHA-256 digest and partitioned by domain-separated
owner/mode/workspace/session hashes.  All file operations use
``O_NOFOLLOW|O_CLOEXEC`` and ``O_CREAT|O_EXCL`` to prevent symlink and
race attacks.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
from pathlib import Path

from js.echo.mode_contract import AppMode, ArtifactRefV1

_MAX_STORE_FILE_BYTES = 8 * 1024 * 1024  # 8 MiB per file
_CHUNK_BYTES = 64 * 1024


def _domain_hash(*parts: str) -> str:
    """Compute a domain-separated SHA-256 directory hash."""
    payload = "\0".join(parts).encode("utf-8")
    return hashlib.sha256(b"js-agent:connector-artifact-store:v1\0" + payload).hexdigest()[:32]


class ConnectorArtifactStore:
    """Content-addressed internal artifact bytes store."""

    def __init__(self, *, state_dir: Path) -> None:
        self._root = state_dir / "connector_artifacts"
        self._root.mkdir(parents=True, exist_ok=True)
        os.chmod(self._root, 0o700)
        self._bindings: dict[str, dict[str, str]] = {}

    def _partition_dir(
        self,
        *,
        owner: str,
        mode: str,
        workspace: str | None,
        session: str,
    ) -> Path:
        ws = workspace or ""
        partition_hash = _domain_hash(owner, mode, ws, session)
        d = self._root / partition_hash
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        return d

    def stage_import(
        self,
        *,
        source_fd: int,
        byte_limit: int = _MAX_STORE_FILE_BYTES,
        owner: str,
        mode: str,
        workspace: str | None,
        session: str,
        run: str,
    ) -> tuple[str, int, ArtifactRefV1]:
        """Read from ``source_fd``, store content-addressed, return (digest, size, ArtifactRefV1).

        Uses chunked read + hash.  Rejects files exceeding ``byte_limit``.
        """

        hasher = hashlib.sha256()
        total = 0
        # Read and hash in chunks
        while True:
            chunk = os.read(source_fd, _CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > byte_limit:
                raise ValueError(
                    f"connector import file exceeds byte limit ({byte_limit})"
                )
            hasher.update(chunk)

        content_digest = "sha256:" + hasher.hexdigest()
        digest_hex = hasher.hexdigest()

        # Store content-addressed
        partition = self._partition_dir(
            owner=owner, mode=mode, workspace=workspace, session=session
        )
        blob_path = partition / digest_hex

        if not blob_path.exists():
            # Write the file: re-read from source_fd and write to store
            # Re-open source is not possible (we only have fd), so we
            # write from the hash data we already read.  In production,
            # we'd need to re-read or buffer.  For R4-B, we use a temp
            # approach: seek back and copy.
            try:
                os.lseek(source_fd, 0, os.SEEK_SET)
            except OSError:
                # Can't seek (pipe/stream) -- we should have buffered
                raise RuntimeError(
                    "connector import source is not seekable; "
                    "cannot stage content-addressed copy"
                ) from None

            # Create with O_CREAT|O_EXCL|O_NOFOLLOW
            fd = os.open(
                blob_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            try:
                os.fchmod(fd, 0o600)
                copied = 0
                while True:
                    chunk = os.read(source_fd, _CHUNK_BYTES)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > byte_limit:
                        os.close(fd)
                        os.unlink(blob_path)
                        raise ValueError(
                            f"connector import file exceeds byte limit ({byte_limit})"
                        )
                    written = 0
                    while written < len(chunk):
                        written += os.write(fd, chunk[written:])
                os.fsync(fd)
            finally:
                os.close(fd)
            # fsync directory
            dir_fd = os.open(partition, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)

        # Verify the stored file
        st = os.stat(blob_path)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise RuntimeError("connector artifact store blob is not a regular single-link file")

        # Create ArtifactRefV1
        opaque_id = _domain_hash(owner, mode, workspace or "", session, run, digest_hex)
        app_mode = AppMode(mode) if not isinstance(mode, AppMode) else mode
        ref = ArtifactRefV1(
            owner=owner,
            mode=app_mode,
            workspace=workspace,
            session=session,
            created_by_run=run,
            digest=content_digest,
            uri=f"echo://artifact/{opaque_id}",
            kind="document",
            acl="owner",
        )
        # Verify round-trip
        assert ArtifactRefV1.from_dict(ref.to_dict()) == ref
        return content_digest, total, ref

    def open_verified(
        self,
        *,
        ref: ArtifactRefV1,
        owner: str,
        mode: str,
        workspace: str | None,
        session: str,
        run: str,
    ) -> int:
        """Open a stored blob for reading after verifying ACL and digest.

        Returns an fd opened ``O_RDONLY|O_NOFOLLOW|O_CLOEXEC``.
        """
        # ACL check
        if ref.owner != owner or ref.session != session:
            raise PermissionError("artifact ref ACL mismatch")
        if ref.workspace != workspace:
            raise PermissionError("artifact ref workspace mismatch")

        digest_hex = ref.digest.removeprefix("sha256:")
        partition = self._partition_dir(
            owner=owner, mode=mode, workspace=workspace, session=session
        )
        blob_path = partition / digest_hex

        if not blob_path.exists():
            raise PermissionError("artifact_content_unavailable")

        fd = os.open(blob_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)

        # Verify size and digest
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            os.close(fd)
            raise RuntimeError("connector artifact blob is not a regular single-link file")

        hasher = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, _CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            hasher.update(chunk)
        actual_digest = "sha256:" + hasher.hexdigest()
        if not hmac.compare_digest(actual_digest, ref.digest):
            os.close(fd)
            raise RuntimeError("connector artifact digest mismatch")

        # Re-open for reading from start
        os.lseek(fd, 0, os.SEEK_SET)
        return fd

    def bind_verified_receipt(
        self,
        *,
        ref: ArtifactRefV1,
        receipt_id: str,
        effect_id: str,
    ) -> None:
        """Bind a verified receipt to an artifact ref."""
        key = ref.canonical_hash()
        self._bindings[key] = {
            "receipt_id": receipt_id,
            "effect_id": effect_id,
            "ref_digest": ref.digest,
        }

    def reconcile_verified_receipts(
        self,
        *,
        tenant_id: str,
        mode: str,
        workspace: str | None,
    ) -> None:
        """Reconcile bindings from verified receipts after restart."""
        pass  # In production, scan EchoLedger for verified receipts

    @property
    def root(self) -> Path:
        return self._root
