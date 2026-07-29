"""Owner/session upload quota ledger with durable reserve → publish → commit.

State machine (upload):
  reserved → published → committed

State machine (delete):
  deleting → deleted → finalized

All owner/session roots and ledger files are opened with directory fds,
``O_NOFOLLOW``, and ``fstat`` regularity checks. Scans fail closed on
capacity or I/O errors so usage is never underestimated.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from js.echo.attachment_gate import (
    _MAX_UPLOAD_SCAN_ENTRIES,
    AttachmentGateError,
    owner_slug,
    session_slug,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None  # type: ignore[assignment]


_DEFAULT_OWNER_MAX_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB
_DEFAULT_OWNER_MAX_FILES = 5_000
_DEFAULT_SESSION_MAX_BYTES = 512 * 1024 * 1024  # 512 MiB
_DEFAULT_SESSION_MAX_FILES = 1_000
_DEFAULT_MIN_FREE_BYTES = 256 * 1024 * 1024  # 256 MiB
_LEDGER_VERSION = 1
_STATE_RESERVED = "reserved"
_STATE_PUBLISHED = "published"
_STATE_COMMITTED = "committed"
_STATE_DELETING = "deleting"
_STATE_DELETED = "deleted"
_STATE_FINALIZED = "finalized"
_UPLOAD_STATES = frozenset({_STATE_RESERVED, _STATE_PUBLISHED, _STATE_COMMITTED})
_DELETE_STATES = frozenset({_STATE_DELETING, _STATE_DELETED, _STATE_FINALIZED})


@dataclass(frozen=True)
class UploadQuotaLimits:
    owner_max_bytes: int = _DEFAULT_OWNER_MAX_BYTES
    owner_max_files: int = _DEFAULT_OWNER_MAX_FILES
    session_max_bytes: int = _DEFAULT_SESSION_MAX_BYTES
    session_max_files: int = _DEFAULT_SESSION_MAX_FILES
    min_free_disk_bytes: int = _DEFAULT_MIN_FREE_BYTES


def _is_regular_file(mode: int) -> bool:
    return stat.S_ISREG(mode)


def _is_directory(mode: int) -> bool:
    return stat.S_ISDIR(mode)


class UploadQuotaLedger:
    """Persistent per-owner quota accounting with cross-process locking."""

    def __init__(
        self,
        workspace: Path,
        owner_key_hash: str | None,
        *,
        limits: UploadQuotaLimits | None = None,
        recover_on_init: bool = False,
    ) -> None:
        self._workspace = workspace.resolve()
        self._owner_key = owner_key_hash
        self._owner = owner_slug(owner_key_hash)
        self._limits = limits or UploadQuotaLimits()
        self._uploads_root = self._workspace / "uploads"
        self._owner_root = self._uploads_root / self._owner
        self._ledger_name = ".quota.json"
        self._lock_name = ".quota.lock"
        self._ledger_path = self._owner_root / self._ledger_name
        self._lock_path = self._owner_root / self._lock_name
        self._thread_lock = threading.Lock()
        if recover_on_init:
            try:
                self.recover()
            except AttachmentGateError:
                # Recover is best-effort at construct; callers still fail closed
                # on subsequent reserve/commit when the tree is unsafe.
                pass

    def _open_uploads_root_fd(self) -> int:
        self._uploads_root.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(self._uploads_root), flags)
        except OSError as exc:
            raise AttachmentGateError(500, "uploads root must be a real directory") from exc
        try:
            meta = os.fstat(fd)
            if not _is_directory(meta.st_mode):
                raise AttachmentGateError(500, "uploads root must be a directory")
            return fd
        except Exception:
            os.close(fd)
            raise

    def _open_owner_root_fd(self, uploads_fd: int) -> int:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            try:
                return os.open(self._owner, flags, dir_fd=uploads_fd)
            except FileNotFoundError:
                os.mkdir(self._owner, 0o700, dir_fd=uploads_fd)
                return os.open(self._owner, flags, dir_fd=uploads_fd)
        except OSError as exc:
            raise AttachmentGateError(500, "owner upload root must not be a symlink") from exc

    def _disk_free(self) -> int:
        usage = os.statvfs(self._workspace)
        return int(usage.f_bavail * usage.f_frsize)

    def _empty_ledger(self) -> dict[str, Any]:
        return {
            "version": _LEDGER_VERSION,
            "owner": self._owner,
            "owner_bytes": 0,
            "owner_files": 0,
            "sessions": {},
            "reservations": {},
            "commits": {},
            "deletes": {},
            "created_at": time.time(),
            "rebuilt_at": time.time(),
        }

    def _scan_usage_fd(self, owner_fd: int) -> dict[str, Any]:
        sessions: dict[str, dict[str, int]] = {}
        owner_bytes = 0
        owner_files = 0
        scanned = 0
        try:
            with os.scandir(owner_fd) as entries:
                for entry in entries:
                    # Every directory entry counts toward the scan budget
                    # (including empty session dirs and dotfiles).
                    scanned += 1
                    if scanned > _MAX_UPLOAD_SCAN_ENTRIES:
                        raise AttachmentGateError(
                            429,
                            "Upload tree exceeds scan capacity; refusing new reservations",
                        )
                    name = entry.name
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        raise AttachmentGateError(500, f"upload scan I/O error on {name}") from exc
                    if stat.S_ISLNK(st.st_mode):
                        continue
                    if name.startswith("."):
                        continue
                    if not _is_directory(st.st_mode):
                        continue
                    sess_bytes = 0
                    sess_files = 0
                    try:
                        sess_fd = os.open(
                            name,
                            os.O_RDONLY
                            | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_NOFOLLOW", 0),
                            dir_fd=owner_fd,
                        )
                    except OSError as exc:
                        raise AttachmentGateError(
                            500, f"upload session dir unsafe: {name}"
                        ) from exc
                    try:
                        with os.scandir(sess_fd) as files:
                            for file_entry in files:
                                scanned += 1
                                if scanned > _MAX_UPLOAD_SCAN_ENTRIES:
                                    raise AttachmentGateError(
                                        429,
                                        "Upload tree exceeds scan capacity; "
                                        "refusing new reservations",
                                    )
                                try:
                                    fst = file_entry.stat(follow_symlinks=False)
                                except OSError as exc:
                                    raise AttachmentGateError(
                                        500,
                                        f"upload scan I/O error on {name}/{file_entry.name}",
                                    ) from exc
                                if file_entry.name.startswith("."):
                                    continue
                                if stat.S_ISLNK(fst.st_mode):
                                    continue
                                if not _is_regular_file(fst.st_mode):
                                    continue
                                sess_bytes += int(fst.st_size)
                                sess_files += 1
                    finally:
                        os.close(sess_fd)
                    sessions[name] = {"bytes": sess_bytes, "files": sess_files}
                    owner_bytes += sess_bytes
                    owner_files += sess_files
        except AttachmentGateError:
            raise
        except OSError as exc:
            raise AttachmentGateError(500, "upload scan I/O error") from exc
        data = self._empty_ledger()
        data["sessions"] = sessions
        data["owner_bytes"] = owner_bytes
        data["owner_files"] = owner_files
        data["rebuilt_at"] = time.time()
        return data

    def _validate_ledger(self, raw: object) -> dict[str, Any] | None:
        if not isinstance(raw, dict):
            return None
        try:
            version = raw.get("version")
            if type(version) is not int or version != _LEDGER_VERSION:
                return None
            owner = raw.get("owner")
            if not isinstance(owner, str) or owner != self._owner:
                return None
            created_at = raw.get("created_at")
            if type(created_at) is int or type(created_at) is float:
                if created_at < 0:
                    return None
            else:
                return None
            owner_bytes = raw.get("owner_bytes")
            owner_files = raw.get("owner_files")
            if type(owner_bytes) is not int or type(owner_files) is not int:
                return None
            if owner_bytes < 0 or owner_files < 0:
                return None
            sessions = raw.get("sessions")
            reservations = raw.get("reservations")
            commits = raw.get("commits", {})
            deletes = raw.get("deletes", {})
            if not isinstance(sessions, dict) or not isinstance(reservations, dict):
                return None
            if not isinstance(commits, dict) or not isinstance(deletes, dict):
                return None
            for cid, meta in commits.items():
                if not isinstance(cid, str) or not cid or not isinstance(meta, dict):
                    return None
                if type(meta.get("actual_bytes")) is not int or meta["actual_bytes"] < 0:
                    return None
                if not isinstance(meta.get("session"), str) or not meta["session"]:
                    return None
                if not isinstance(meta.get("filename"), str) or not meta["filename"]:
                    return None
                committed_at = meta.get("committed_at")
                if type(committed_at) is not int and type(committed_at) is not float:
                    return None
                if float(committed_at) < 0:
                    return None
            for sess_key, meta in sessions.items():
                if not isinstance(sess_key, str) or not sess_key or not isinstance(meta, dict):
                    return None
                if type(meta.get("bytes")) is not int or type(meta.get("files")) is not int:
                    return None
                if meta["bytes"] < 0 or meta["files"] < 0:
                    return None
            for rid, meta in reservations.items():
                if not isinstance(rid, str) or not rid or not isinstance(meta, dict):
                    return None
                if "state" not in meta:
                    return None
                state = meta.get("state")
                if state not in _UPLOAD_STATES:
                    return None
                if meta.get("owner") != self._owner:
                    return None
                if not isinstance(meta.get("session"), str) or not meta["session"]:
                    return None
                if type(meta.get("bytes")) is not int or type(meta.get("files")) is not int:
                    return None
                if meta["bytes"] < 0 or meta["files"] < 0:
                    return None
                if type(meta.get("created_at")) not in (int, float):
                    return None
                if float(meta["created_at"]) < 0:
                    return None
                if state in {_STATE_PUBLISHED, _STATE_COMMITTED}:
                    if type(meta.get("actual_bytes")) is not int or meta["actual_bytes"] < 0:
                        return None
                    if not isinstance(meta.get("filename"), str) or not meta["filename"]:
                        return None
            for did, meta in deletes.items():
                if not isinstance(did, str) or not did or not isinstance(meta, dict):
                    return None
                if "state" not in meta:
                    return None
                state = meta.get("state")
                if state not in _DELETE_STATES:
                    return None
                if type(meta.get("bytes")) is not int or meta["bytes"] < 0:
                    return None
                if not isinstance(meta.get("session"), str) or not meta["session"]:
                    return None
                if type(meta.get("created_at")) not in (int, float):
                    return None
                if float(meta["created_at"]) < 0:
                    return None
                filename = meta.get("filename")
                if "filename" in meta and (not isinstance(filename, str) or not filename):
                    return None
        except Exception:
            return None
        out = dict(raw)
        out.setdefault("deletes", {})
        out.setdefault("commits", {})
        return out

    def _load_unlocked(self, owner_fd: int, *, rebuild_if_invalid: bool = False) -> dict[str, Any]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self._ledger_name, flags, dir_fd=owner_fd)
        except FileNotFoundError:
            return self._scan_usage_fd(owner_fd)
        except OSError as exc:
            raise AttachmentGateError(500, "quota ledger open failed") from exc
        try:
            meta = os.fstat(fd)
            if not _is_regular_file(meta.st_mode):
                raise AttachmentGateError(500, "Upload quota ledger must be a regular file")
            mode = meta.st_mode & 0o777
            if mode & 0o077:
                raise AttachmentGateError(500, "Upload quota ledger permissions too open")
            raw_text = os.read(fd, 8 * 1024 * 1024).decode("utf-8")
        finally:
            os.close(fd)
        try:
            parsed = self._validate_ledger(json.loads(raw_text))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            if rebuild_if_invalid:
                return self._scan_usage_fd(owner_fd)
            raise AttachmentGateError(500, "quota ledger JSON invalid") from exc
        if parsed is None:
            if rebuild_if_invalid:
                return self._scan_usage_fd(owner_fd)
            raise AttachmentGateError(500, "quota ledger schema invalid")
        return parsed

    def _save_unlocked(self, owner_fd: int, data: dict[str, Any]) -> None:
        payload = json.dumps(data, sort_keys=True).encode("utf-8")
        tmp_name = f".quota.json.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        fd = os.open(tmp_name, flags, 0o600, dir_fd=owner_fd)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_name, self._ledger_name, src_dir_fd=owner_fd, dst_dir_fd=owner_fd)
        os.fsync(owner_fd)

    def _open_lock_fd(self, owner_fd: int) -> int:
        """Open/create the flock file without Darwin O_NOFOLLOW+O_CREAT ENOENT."""
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        cloexec = getattr(os, "O_CLOEXEC", 0)
        existing_flags = os.O_RDWR | nofollow | cloexec
        try:
            fd = os.open(self._lock_name, existing_flags, dir_fd=owner_fd)
        except FileNotFoundError:
            # New inode cannot be a symlink; avoid O_NOFOLLOW+O_CREAT (ENOENT on macOS).
            create_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | cloexec
            try:
                fd = os.open(self._lock_name, create_flags, 0o600, dir_fd=owner_fd)
            except FileExistsError:
                fd = os.open(self._lock_name, existing_flags, dir_fd=owner_fd)
        meta = os.fstat(fd)
        if not _is_regular_file(meta.st_mode):
            os.close(fd)
            raise AttachmentGateError(500, "quota lock must be a regular file")
        os.fchmod(fd, 0o600)
        return fd

    def _with_owner_lock(self, fn: Any) -> Any:
        with self._thread_lock:
            uploads_fd = self._open_uploads_root_fd()
            try:
                owner_fd = self._open_owner_root_fd(uploads_fd)
                try:
                    lock_fd = self._open_lock_fd(owner_fd)
                    try:
                        if fcntl is not None:
                            fcntl.flock(lock_fd, fcntl.LOCK_EX)
                        try:
                            return fn(owner_fd)
                        finally:
                            if fcntl is not None:
                                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    finally:
                        os.close(lock_fd)
                finally:
                    os.close(owner_fd)
            finally:
                os.close(uploads_fd)

    def rebuild(self) -> dict[str, Any]:
        def _rebuild(owner_fd: int) -> dict[str, Any]:
            prior_commits: dict[str, Any] = {}
            try:
                prior = self._load_unlocked(owner_fd, rebuild_if_invalid=True)
                prior_commits = dict(prior.get("commits") or {})
            except AttachmentGateError:
                prior_commits = {}
            data = self._scan_usage_fd(owner_fd)
            data["commits"] = prior_commits
            self._save_unlocked(owner_fd, data)
            return data

        return cast("dict[str, Any]", self._with_owner_lock(_rebuild))

    def recover(self) -> dict[str, Any]:
        """Bounded crash recovery: commit published leftovers, finish deletes.

        Replay is idempotent: never re-apply a stale local snapshot over
        mutations performed by ``_apply_commit`` / ``_finalize_delete``.
        """
        return cast("dict[str, Any]", self._with_owner_lock(self._recover_unlocked))

    def _file_exists_unlocked(self, owner_fd: int, session: str, filename: str) -> bool:
        try:
            sess_fd = os.open(
                session,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=owner_fd,
            )
        except OSError:
            return False
        try:
            try:
                fd = os.open(
                    filename,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=sess_fd,
                )
            except OSError:
                return False
            try:
                meta = os.fstat(fd)
                return _is_regular_file(meta.st_mode)
            finally:
                os.close(fd)
        finally:
            os.close(sess_fd)

    def _recover_unlocked(self, owner_fd: int) -> dict[str, Any]:
        data = self._load_unlocked(owner_fd)
        now = time.time()
        changed = False
        for rid, meta in list(dict(data.get("reservations") or {}).items()):
            if not isinstance(meta, dict):
                continue
            state = meta.get("state", _STATE_RESERVED)
            if state == _STATE_PUBLISHED:
                filename = str(meta.get("filename") or "")
                session = str(meta.get("session") or "")
                if filename and session and self._file_exists_unlocked(owner_fd, session, filename):
                    if rid not in dict(data.get("commits") or {}):
                        self._apply_commit(data, meta=meta, reservation_id=rid)
                        changed = True
                    else:
                        reservations = dict(data.get("reservations") or {})
                        reservations.pop(rid, None)
                        data["reservations"] = reservations
                        changed = True
                else:
                    reservations = dict(data.get("reservations") or {})
                    reservations.pop(rid, None)
                    data["reservations"] = reservations
                    changed = True
            elif state == _STATE_COMMITTED:
                reservations = dict(data.get("reservations") or {})
                reservations.pop(rid, None)
                data["reservations"] = reservations
                changed = True
            elif state == _STATE_RESERVED:
                filename = str(meta.get("filename") or "")
                session = str(meta.get("session") or "")
                if filename and session and self._file_exists_unlocked(owner_fd, session, filename):
                    continue
                age = now - float(meta.get("created_at", 0))
                if age > 3600:
                    reservations = dict(data.get("reservations") or {})
                    reservations.pop(rid, None)
                    data["reservations"] = reservations
                    changed = True

        for did, meta in list(dict(data.get("deletes") or {}).items()):
            if not isinstance(meta, dict):
                continue
            state = meta.get("state")
            if state == _STATE_DELETED:
                self._finalize_delete(data, delete_id=did, meta=meta)
                deletes = dict(data.get("deletes") or {})
                deletes.pop(did, None)
                data["deletes"] = deletes
                changed = True
            elif state == _STATE_DELETING:
                # Only finalize when the target file is gone; never drop billing
                # for a still-visible file after a crash between begin_delete and unlink.
                filename = str(meta.get("filename") or "")
                session = str(meta.get("session") or "")
                if filename and session and self._file_exists_unlocked(owner_fd, session, filename):
                    continue
                self._finalize_delete(data, delete_id=did, meta=meta)
                deletes = dict(data.get("deletes") or {})
                deletes.pop(did, None)
                data["deletes"] = deletes
                changed = True
            elif state == _STATE_FINALIZED:
                deletes = dict(data.get("deletes") or {})
                deletes.pop(did, None)
                data["deletes"] = deletes
                changed = True

        data = self._compact_terminal_records(data)
        if changed or not self._ledger_path.exists():
            self._save_unlocked(owner_fd, data)
        return data

    @staticmethod
    def _compact_terminal_records(
        data: dict[str, Any], *, max_commits: int = 256
    ) -> dict[str, Any]:
        """Bound commit receipts while keeping recent ids for idempotent retries."""
        commits = dict(data.get("commits") or {})
        if len(commits) <= max_commits:
            return data
        ranked = sorted(
            commits.items(),
            key=lambda item: float((item[1] or {}).get("committed_at", 0)),
            reverse=True,
        )
        data["commits"] = dict(ranked[:max_commits])
        return data

    def reserve(
        self,
        *,
        session_id: str,
        bytes_needed: int,
        files_needed: int = 1,
        reservation_id: str,
    ) -> None:
        if type(bytes_needed) is not int or type(files_needed) is not int:
            raise AttachmentGateError(500, "Invalid quota reservation")
        if bytes_needed < 0 or files_needed < 0:
            raise AttachmentGateError(500, "Invalid quota reservation")
        session = session_slug(session_id)

        def _reserve(owner_fd: int) -> None:
            self._recover_unlocked(owner_fd)
            free = self._disk_free()
            if free < self._limits.min_free_disk_bytes + bytes_needed:
                raise AttachmentGateError(507, "Insufficient disk space for upload")
            data = self._load_unlocked(owner_fd)
            now = time.time()
            reservations = {
                rid: meta
                for rid, meta in dict(data.get("reservations") or {}).items()
                if isinstance(meta, dict)
                and meta.get("state") in {_STATE_RESERVED, _STATE_PUBLISHED}
                and now - float(meta.get("created_at", 0)) < 3600
            }
            reserved_owner_bytes = sum(int(m.get("bytes", 0)) for m in reservations.values())
            reserved_owner_files = sum(int(m.get("files", 0)) for m in reservations.values())
            reserved_session_bytes = sum(
                int(m.get("bytes", 0)) for m in reservations.values() if m.get("session") == session
            )
            reserved_session_files = sum(
                int(m.get("files", 0)) for m in reservations.values() if m.get("session") == session
            )
            sessions = dict(data.get("sessions") or {})
            sess = dict(sessions.get(session) or {"bytes": 0, "files": 0})
            owner_bytes = int(data.get("owner_bytes", 0)) + reserved_owner_bytes
            owner_files = int(data.get("owner_files", 0)) + reserved_owner_files
            session_bytes = int(sess.get("bytes", 0)) + reserved_session_bytes
            session_files = int(sess.get("files", 0)) + reserved_session_files

            if owner_files + files_needed > self._limits.owner_max_files:
                raise AttachmentGateError(429, "Owner upload file quota exceeded")
            if session_files + files_needed > self._limits.session_max_files:
                raise AttachmentGateError(429, "Session upload file quota exceeded")
            if owner_bytes + bytes_needed > self._limits.owner_max_bytes:
                raise AttachmentGateError(413, "Owner upload byte quota exceeded")
            if session_bytes + bytes_needed > self._limits.session_max_bytes:
                raise AttachmentGateError(413, "Session upload byte quota exceeded")

            reservations[reservation_id] = {
                "owner": self._owner,
                "session": session,
                "bytes": bytes_needed,
                "files": files_needed,
                "created_at": now,
                "state": _STATE_RESERVED,
            }
            data["reservations"] = reservations
            data["owner"] = self._owner
            data["version"] = _LEDGER_VERSION
            data.setdefault("created_at", now)
            self._save_unlocked(owner_fd, data)

        self._with_owner_lock(_reserve)

    def mark_published(
        self,
        *,
        session_id: str,
        reservation_id: str,
        filename: str,
        actual_bytes: int,
    ) -> None:
        if type(actual_bytes) is not int or actual_bytes < 0:
            raise AttachmentGateError(500, "Invalid publish accounting")
        if not isinstance(filename, str) or not filename or "/" in filename or "\\" in filename:
            raise AttachmentGateError(500, "Invalid publish filename")
        session = session_slug(session_id)

        def _publish(owner_fd: int) -> None:
            data = self._load_unlocked(owner_fd)
            reservations = dict(data.get("reservations") or {})
            meta = reservations.get(reservation_id)
            if meta is None:
                raise AttachmentGateError(409, "Upload reservation missing for publish")
            if meta.get("session") != session or meta.get("owner") != self._owner:
                raise AttachmentGateError(409, "Upload reservation owner/session mismatch")
            state = meta.get("state", _STATE_RESERVED)
            if state == _STATE_PUBLISHED:
                if meta.get("filename") == filename and meta.get("actual_bytes") == actual_bytes:
                    return  # idempotent
                # Intent-before-link may retry a new candidate name after FileExistsError.
                # Allow updating the published intent when bytes match and we have not
                # yet committed (file may not exist for the previous candidate).
                if int(meta.get("actual_bytes", -1)) == actual_bytes:
                    meta = dict(meta)
                    meta["filename"] = filename
                    reservations[reservation_id] = meta
                    data["reservations"] = reservations
                    self._save_unlocked(owner_fd, data)
                    return
                raise AttachmentGateError(409, "Upload reservation already published differently")
            if state != _STATE_RESERVED:
                raise AttachmentGateError(409, f"Upload reservation not reservable: {state}")
            meta = dict(meta)
            meta["state"] = _STATE_PUBLISHED
            meta["filename"] = filename
            meta["actual_bytes"] = actual_bytes
            reservations[reservation_id] = meta
            data["reservations"] = reservations
            self._save_unlocked(owner_fd, data)

        self._with_owner_lock(_publish)

    @staticmethod
    def _apply_commit(data: dict[str, Any], *, meta: dict[str, Any], reservation_id: str) -> None:
        session = str(meta["session"])
        actual_bytes = int(meta.get("actual_bytes", meta.get("bytes", 0)))
        filename = str(meta.get("filename") or "")
        sessions = dict(data.get("sessions") or {})
        sess = dict(sessions.get(session) or {"bytes": 0, "files": 0})
        sess["bytes"] = int(sess.get("bytes", 0)) + actual_bytes
        sess["files"] = int(sess.get("files", 0)) + 1
        sessions[session] = sess
        data["sessions"] = sessions
        data["owner_bytes"] = int(data.get("owner_bytes", 0)) + actual_bytes
        data["owner_files"] = int(data.get("owner_files", 0)) + 1
        reservations = dict(data.get("reservations") or {})
        reservations.pop(reservation_id, None)
        data["reservations"] = reservations
        commits = dict(data.get("commits") or {})
        commits[reservation_id] = {
            "session": session,
            "actual_bytes": actual_bytes,
            "filename": filename,
            "committed_at": time.time(),
        }
        data["commits"] = commits

    def commit(
        self,
        *,
        session_id: str,
        reservation_id: str,
        actual_bytes: int,
        filename: str | None = None,
    ) -> None:
        if type(actual_bytes) is not int or actual_bytes < 0:
            raise AttachmentGateError(500, "Invalid quota commit")
        session = session_slug(session_id)

        def _commit(owner_fd: int) -> None:
            data = self._load_unlocked(owner_fd)
            commits = dict(data.get("commits") or {})
            prior = commits.get(reservation_id)
            if prior is not None:
                if (
                    int(prior.get("actual_bytes", -1)) == actual_bytes
                    and prior.get("session") == session
                    and (filename is None or prior.get("filename") == filename)
                ):
                    return
                raise AttachmentGateError(409, "Upload reservation committed with different bytes")
            reservations = dict(data.get("reservations") or {})
            meta = reservations.get(reservation_id)
            if meta is None:
                raise AttachmentGateError(409, "Upload reservation missing for commit")
            if meta.get("session") != session or meta.get("owner") != self._owner:
                raise AttachmentGateError(409, "Upload reservation owner/session mismatch")
            state = meta.get("state", _STATE_RESERVED)
            if state == _STATE_RESERVED:
                # Allow commit without explicit publish when caller supplies filename.
                if filename is None:
                    raise AttachmentGateError(409, "Upload must be published before commit")
                meta = dict(meta)
                meta["filename"] = filename
                meta["actual_bytes"] = actual_bytes
                meta["state"] = _STATE_PUBLISHED
            elif state == _STATE_PUBLISHED:
                meta = dict(meta)
                if filename is not None and meta.get("filename") != filename:
                    raise AttachmentGateError(409, "Upload publish/commit filename mismatch")
                if int(meta.get("actual_bytes", -1)) != actual_bytes:
                    # Prefer the committed measured size when republishing.
                    meta["actual_bytes"] = actual_bytes
            else:
                raise AttachmentGateError(409, f"Upload reservation bad state: {state}")
            self._apply_commit(data, meta=meta, reservation_id=reservation_id)
            # Drop committed reservation after successful apply to keep ledger small;
            # retain a commit receipt for idempotency under deletes map? Keep in
            # reservations with committed state until recover prunes.
            self._save_unlocked(owner_fd, data)

        self._with_owner_lock(_commit)

    def release(self, *, reservation_id: str, abandon_published: bool = False) -> None:
        def _release(owner_fd: int) -> None:
            data = self._load_unlocked(owner_fd)
            reservations = dict(data.get("reservations") or {})
            meta = reservations.get(reservation_id)
            if meta is None:
                return
            if meta.get("state") == _STATE_COMMITTED:
                return
            if meta.get("state") == _STATE_PUBLISHED and not abandon_published:
                # Must not silently drop a published unaccounted file.
                raise AttachmentGateError(
                    409,
                    "Cannot release published upload; unlink file then abandon",
                )
            reservations.pop(reservation_id, None)
            data["reservations"] = reservations
            self._save_unlocked(owner_fd, data)

        self._with_owner_lock(_release)

    def begin_delete(
        self,
        *,
        session_id: str,
        bytes_freed: int,
        delete_id: str,
        filename: str | None = None,
    ) -> None:
        session = session_slug(session_id)
        if type(bytes_freed) is not int or bytes_freed < 0:
            raise AttachmentGateError(500, "Invalid delete accounting")
        if filename is not None and (
            not isinstance(filename, str) or not filename or "/" in filename or "\\" in filename
        ):
            raise AttachmentGateError(500, "Invalid delete filename")

        def _begin(owner_fd: int) -> None:
            data = self._load_unlocked(owner_fd)
            deletes = dict(data.get("deletes") or {})
            existing = deletes.get(delete_id)
            if existing is not None:
                if (
                    existing.get("session") == session
                    and int(existing.get("bytes", -1)) == bytes_freed
                    and (filename is None or existing.get("filename") == filename)
                ):
                    return
                raise AttachmentGateError(409, "Delete id conflict")
            record: dict[str, Any] = {
                "session": session,
                "bytes": bytes_freed,
                "state": _STATE_DELETING,
                "created_at": time.time(),
            }
            if filename is not None:
                record["filename"] = filename
            deletes[delete_id] = record
            data["deletes"] = deletes
            self._save_unlocked(owner_fd, data)

        self._with_owner_lock(_begin)

    def mark_deleted(self, *, delete_id: str) -> None:
        def _mark(owner_fd: int) -> None:
            data = self._load_unlocked(owner_fd)
            deletes = dict(data.get("deletes") or {})
            meta = deletes.get(delete_id)
            if meta is None:
                raise AttachmentGateError(409, "Delete record missing")
            if meta.get("state") in {_STATE_DELETED, _STATE_FINALIZED}:
                return
            meta = dict(meta)
            meta["state"] = _STATE_DELETED
            deletes[delete_id] = meta
            data["deletes"] = deletes
            self._save_unlocked(owner_fd, data)

        self._with_owner_lock(_mark)

    @staticmethod
    def _finalize_delete(data: dict[str, Any], *, delete_id: str, meta: dict[str, Any]) -> None:
        session = str(meta["session"])
        bytes_freed = int(meta["bytes"])
        sessions = dict(data.get("sessions") or {})
        sess = dict(sessions.get(session) or {"bytes": 0, "files": 0})
        sess["bytes"] = max(0, int(sess.get("bytes", 0)) - bytes_freed)
        sess["files"] = max(0, int(sess.get("files", 0)) - 1)
        sessions[session] = sess
        data["sessions"] = sessions
        data["owner_bytes"] = max(0, int(data.get("owner_bytes", 0)) - bytes_freed)
        data["owner_files"] = max(0, int(data.get("owner_files", 0)) - 1)
        deletes = dict(data.get("deletes") or {})
        done = dict(meta)
        done["state"] = _STATE_FINALIZED
        deletes[delete_id] = done
        data["deletes"] = deletes

    def finalize_delete(self, *, delete_id: str) -> None:
        def _finalize(owner_fd: int) -> None:
            data = self._load_unlocked(owner_fd)
            deletes = dict(data.get("deletes") or {})
            meta = deletes.get(delete_id)
            if meta is None:
                raise AttachmentGateError(409, "Delete record missing")
            if meta.get("state") == _STATE_FINALIZED:
                return
            if meta.get("state") not in {_STATE_DELETED, _STATE_DELETING}:
                raise AttachmentGateError(409, "Delete not ready to finalize")
            self._finalize_delete(data, delete_id=delete_id, meta=meta)
            # Prune finalized record.
            deletes = dict(data.get("deletes") or {})
            deletes.pop(delete_id, None)
            data["deletes"] = deletes
            self._save_unlocked(owner_fd, data)

        self._with_owner_lock(_finalize)

    def release_file(self, *, session_id: str, bytes_freed: int) -> None:
        """Backward-compatible delete accounting (single-shot)."""
        delete_id = secrets.token_hex(16)
        self.begin_delete(session_id=session_id, bytes_freed=bytes_freed, delete_id=delete_id)
        self.mark_deleted(delete_id=delete_id)
        self.finalize_delete(delete_id=delete_id)
