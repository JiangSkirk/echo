"""Safe file operations with path validation and size limits."""

from __future__ import annotations

import asyncio
import errno
import os
import secrets
import stat
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from js.config import ToolLimits
from js.echo.turn_context import current_runtime_context
from js.security.guard import BehaviorGuard, SecurityDecisionType
from js.security.runtime_tcb import runtime_tcb_write_error
from js.tools.registry import ToolParam, ToolResult, ToolSpec

_CODE_SEARCH_INCOMPLETE_METADATA = {"matches": 0, "truncated": False, "complete": False}

_GIT_METADATA_COMPONENT = ".git"


def _cancel_requested(token: Any) -> bool:
    if token is None:
        return False
    for attribute in ("is_set", "cancelled", "is_cancelled"):
        value = getattr(token, attribute, None)
        if callable(value):
            try:
                value = value()
            except Exception:
                continue
        if value is True:
            return True
    return False


def _regex_match_lines(
    pattern: str,
    lines: list[str],
    *,
    max_line_chars: int,
    max_matches: int,
) -> list[tuple[int, str]]:
    """Module-level helper for spawn-safe regex matching in a worker process."""
    import re

    regex = re.compile(pattern)
    hits: list[tuple[int, str]] = []
    for index, line in enumerate(lines, start=1):
        sample = line if len(line) <= max_line_chars else line[:max_line_chars]
        if regex.search(sample):
            snippet = sample.strip()
            if len(snippet) > 120:
                snippet = snippet[:120] + "..."
            hits.append((index, snippet))
            if len(hits) >= max_matches:
                break
    return hits


def _regex_search_job(
    pattern: str,
    files: list[tuple[str, list[str]]],
    *,
    max_line_chars: int,
    max_matches: int,
    result_conn: Any,
) -> None:
    """Worker entry: search many files and push a single result payload via Pipe."""
    try:
        payload: list[tuple[str, int, str]] = []
        for rel_path, lines in files:
            remaining = max_matches - len(payload)
            if remaining <= 0:
                break
            for line_no, snippet in _regex_match_lines(
                pattern,
                lines,
                max_line_chars=max_line_chars,
                max_matches=remaining,
            ):
                payload.append((rel_path, line_no, snippet))
                if len(payload) >= max_matches:
                    break
        result_conn.send(("ok", payload))
    except Exception as exc:  # noqa: BLE001 - forwarded to parent
        try:
            result_conn.send(("err", f"{type(exc).__name__}: {exc}"))
        except Exception:
            pass
    finally:
        try:
            result_conn.close()
        except Exception:
            pass


class FileTools:
    """Collection of safe file system tools."""

    def __init__(
        self,
        workspace: Path,
        limits: ToolLimits,
        guard: BehaviorGuard,
        *,
        cell_backend: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        self.workspace = workspace.resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.limits = limits
        self.guard = guard
        self.cell_backend = cell_backend

    def _relative_path(self, path: str) -> Path:
        if not isinstance(path, str) or not path or "\x00" in path:
            raise ValueError("Invalid workspace path")
        if path.startswith("~"):
            raise ValueError("Home-relative paths are not allowed")
        candidate = Path(path)
        if candidate.is_absolute():
            try:
                relative = candidate.relative_to(self.workspace)
            except ValueError as exc:
                raise ValueError(f"Path escapes workspace: {path}") from exc
        else:
            relative = candidate
        parts = tuple(part for part in relative.parts if part not in ("", "."))
        if any(part == ".." for part in parts):
            raise ValueError(f"Path escapes workspace: {path}")
        return Path(*parts) if parts else Path(".")

    def _logical_path(self, path: str) -> Path:
        return self.workspace / self._relative_path(path)

    def _reject_git_metadata_write(self, path: str) -> None:
        """Fail closed when a write/delete targets the workspace ``.git`` tree.

        Repository metadata (hooks, config, refs) must never be mutated through
        the file tools: a hostile ``.git/config`` or hook would execute on the
        host's next git invocation.  Reads stay allowed.  The lexical check is
        safe because the dir_fd walk below opens every component with
        ``O_NOFOLLOW``, so a ``.git`` component cannot be a symlink decoy.
        The comparison is case-insensitive (``casefold``) because the default
        macOS/Windows filesystems resolve ``.GIT`` onto ``.git``; on
        case-sensitive filesystems this merely over-blocks a lookalike name,
        which is the fail-closed direction.
        """
        relative = self._relative_path(path)
        if _GIT_METADATA_COMPONENT in (part.casefold() for part in relative.parts):
            raise ValueError(f"Workspace .git metadata cannot be modified: {path}")

    def _reject_runtime_tcb_write(self, path: str) -> None:
        """Fail closed when a write/delete targets the installed ``js/`` package.

        Only applies when the workspace contains the live package (dogfood).
        ``js/web/static/`` is the sole write exception; everything else under
        the package is TCB.
        """
        logical = self.workspace / self._relative_path(path)
        error = runtime_tcb_write_error(logical, workspace=self.workspace)
        if error is not None:
            raise ValueError(error)

    @contextmanager
    def _open_secure_parent(
        self,
        path: str,
        *,
        create_parents: bool,
    ) -> Iterator[tuple[int, str, Path]]:
        relative = self._relative_path(path)
        if relative == Path(".") or not relative.name:
            raise ValueError("A file or directory name is required")
        required_dir_fd = (os.open, os.mkdir, os.stat, os.unlink)
        if (
            not hasattr(os, "O_DIRECTORY")
            or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_CLOEXEC")
            or any(function not in os.supports_dir_fd for function in required_dir_fd)
        ):
            raise RuntimeError("Secure workspace filesystem primitives are unavailable")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        current_fd = os.open(self.workspace, flags)
        try:
            for component in relative.parts[:-1]:
                if create_parents:
                    try:
                        os.mkdir(component, 0o700, dir_fd=current_fd)
                    except FileExistsError:
                        pass
                next_fd = os.open(component, flags, dir_fd=current_fd)
                metadata = os.fstat(next_fd)
                if not stat.S_ISDIR(metadata.st_mode):
                    os.close(next_fd)
                    raise ValueError("Workspace path parent is not a directory")
                os.close(current_fd)
                current_fd = next_fd
            yield current_fd, relative.name, self.workspace / relative
        finally:
            os.close(current_fd)

    @staticmethod
    def _write_all(fd: int, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("Workspace file write stalled")
            view = view[written:]

    @staticmethod
    def _reject_unsafe_final(parent_fd: int, name: str) -> os.stat_result | None:
        try:
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("Symlinks are not allowed for workspace file operations")
        return metadata

    def _secure_write(self, path: str, payload: bytes, *, append: bool) -> Path:
        self._reject_git_metadata_write(path)
        self._reject_runtime_tcb_write(path)
        with self._open_secure_parent(path, create_parents=True) as (
            parent_fd,
            name,
            logical,
        ):
            metadata = self._reject_unsafe_final(parent_fd, name)
            if metadata is not None and not stat.S_ISREG(metadata.st_mode):
                raise ValueError("Workspace write target must be a regular file")
            if append:
                flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
                fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
                try:
                    opened = os.fstat(fd)
                    if not stat.S_ISREG(opened.st_mode):
                        raise ValueError("Workspace write target must be a regular file")
                    self._write_all(fd, payload)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(parent_fd)
                return logical

            temp_name = f".echo-write-{secrets.token_hex(16)}.tmp"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
                try:
                    self._write_all(fd, payload)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.replace(
                    temp_name,
                    name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                os.fsync(parent_fd)
            finally:
                try:
                    os.unlink(temp_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
            return logical

    def _secure_read_text(self, path: str, *, max_bytes: int) -> tuple[str, Path]:
        text, logical, _bytes_read, _stable = self._secure_read_text_detailed(
            path,
            max_bytes=max_bytes,
        )
        return text, logical

    def _secure_read_bytes(
        self,
        path: str,
        *,
        max_bytes: int,
    ) -> tuple[bytes, Path, int, bool]:
        """Read bytes via dir_fd and report size stability."""
        with self._open_secure_parent(path, create_parents=False) as (
            parent_fd,
            name,
            logical,
        ):
            self._reject_unsafe_final(parent_fd, name)
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open(name, flags, dir_fd=parent_fd)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError("Workspace read target must be a regular file")
                if before.st_size > max_bytes:
                    raise ValueError("Workspace file exceeds the read size limit")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = os.read(fd, min(65_536, max_bytes + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("Workspace file exceeds the read size limit")
                    chunks.append(chunk)
                after = os.fstat(fd)
            finally:
                os.close(fd)
        stable = (
            before.st_size == total
            and after.st_size == before.st_size
            and after.st_mtime_ns == before.st_mtime_ns
            and after.st_ino == before.st_ino
            and after.st_dev == before.st_dev
        )
        return b"".join(chunks), logical, total, stable

    def _secure_read_text_detailed(
        self,
        path: str,
        *,
        max_bytes: int,
    ) -> tuple[str, Path, int, bool]:
        """Read text and report actual bytes plus whether the size stayed stable."""
        payload, logical, total, stable = self._secure_read_bytes(path, max_bytes=max_bytes)
        return payload.decode("utf-8", errors="replace"), logical, total, stable

    async def _commit_file_cell_change(self, path: str, content: str) -> ToolResult:
        """Send one complete file replacement through the File Cell boundary."""
        try:
            relative = self._relative_path(path)
            if relative == Path(".") or not relative.name:
                raise ValueError("A file name is required")
            self._reject_git_metadata_write(path)
            self._reject_runtime_tcb_write(path)
            backend = self.cell_backend
            if backend is None:
                raise RuntimeError("File Cell backend is unavailable")
            result = await asyncio.to_thread(
                backend,
                {
                    "path": relative.as_posix(),
                    "content": content,
                },
            )
        except Exception:  # noqa: BLE001 - Cell failures must never fall back locally
            return ToolResult(success=False, error="File Cell safety boundary unavailable")

        if not isinstance(result, dict) or result.get("status") != "COMMITTED":
            return ToolResult(success=False, error="File Cell denied request")

        logical = self.workspace / relative
        if logical.suffix in (".sh", ".py", ".js", ".ts", ".bash", ".zsh"):
            self.guard.register_script_artifact(str(logical))

        output = result.get("output")
        if not isinstance(output, str):
            output = f"Committed {len(content)} chars through File Cell"
        return ToolResult(
            success=True,
            output=output,
            metadata={
                "path": relative.as_posix(),
                "bytes": len(content.encode("utf-8")),
                "cell": "file",
            },
        )

    @contextmanager
    def _open_secure_directory(self, path: str) -> Iterator[tuple[int, Path]]:
        relative = self._relative_path(path)
        if (
            not hasattr(os, "O_DIRECTORY")
            or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_CLOEXEC")
        ):
            raise RuntimeError("Secure workspace filesystem primitives are unavailable")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        current_fd = os.open(self.workspace, flags)
        try:
            for component in () if relative == Path(".") else relative.parts:
                next_fd = os.open(component, flags, dir_fd=current_fd)
                metadata = os.fstat(next_fd)
                if not stat.S_ISDIR(metadata.st_mode):
                    os.close(next_fd)
                    raise ValueError("Workspace path is not a directory")
                os.close(current_fd)
                current_fd = next_fd
            yield current_fd, self.workspace / relative
        finally:
            os.close(current_fd)

    def _secure_lstat(self, path: str) -> tuple[os.stat_result, Path]:
        relative = self._relative_path(path)
        if relative == Path("."):
            return self.workspace.stat(), self.workspace
        with self._open_secure_parent(path, create_parents=False) as (
            parent_fd,
            name,
            logical,
        ):
            metadata = self._reject_unsafe_final(parent_fd, name)
            if metadata is None:
                raise FileNotFoundError(path)
            return metadata, logical

    def _walk_secure_directory(
        self,
        directory_fd: int,
        *,
        recursive: bool,
        max_entries: int = 4_096,
        max_depth: int = 64,
    ) -> list[tuple[Path, int, int]]:
        entries: list[tuple[Path, int, int]] = []
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

        def visit(fd: int, prefix: Path, depth: int) -> None:
            if depth > max_depth:
                raise ValueError("Workspace directory depth limit exceeded")
            for name in sorted(os.listdir(fd)):
                if name in {".", ".."}:
                    continue
                try:
                    metadata = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(metadata.st_mode):
                    continue
                relative = prefix / name
                entries.append((relative, metadata.st_mode, metadata.st_size))
                if len(entries) >= max_entries:
                    raise ValueError("Workspace directory entry limit exceeded")
                if recursive and stat.S_ISDIR(metadata.st_mode):
                    try:
                        child_fd = os.open(name, flags, dir_fd=fd)
                    except (FileNotFoundError, NotADirectoryError):
                        continue
                    try:
                        child_metadata = os.fstat(child_fd)
                        if stat.S_ISDIR(child_metadata.st_mode):
                            visit(child_fd, relative, depth + 1)
                    finally:
                        os.close(child_fd)

        visit(directory_fd, Path(), 0)
        return entries

    def _resolve(self, path: str, *, follow_symlinks: bool = True) -> Path:
        """Resolve path relative to workspace.

        When follow_symlinks=False (for write/delete operations), rejects
        symlinks to prevent TOCTOU attacks where a symlink is swapped after
        the workspace check.
        """
        p = Path(path)
        raw = self.workspace / p if not p.is_absolute() else p
        resolved = raw.resolve()
        # Ensure resolved path is inside workspace
        try:
            resolved.relative_to(self.workspace)
        except ValueError as e:
            raise ValueError(f"Path escapes workspace: {path}") from e
        # Reject symlinks for write/delete: check the unresolved path
        if not follow_symlinks and raw.is_symlink():
            raise ValueError(f"Symlinks are not allowed for write operations: {path}")
        return resolved

    def get_specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name="file_read",
                description="Read contents of a file. Returns up to max_chars characters.",
                parameters=[
                    ToolParam("path", "string", "Relative or absolute path to file"),
                    ToolParam("offset", "integer", "Line offset to start from", required=False),
                    ToolParam("limit", "integer", "Max lines to read", required=False),
                ],
                read_only=True,
            ),
            ToolSpec(
                name="file_write",
                description="Write content to a file. Creates directories if needed.",
                parameters=[
                    ToolParam("path", "string", "Relative or absolute path"),
                    ToolParam("content", "string", "Content to write"),
                    ToolParam("append", "boolean", "Append instead of overwrite", required=False),
                ],
                dangerous=True,
            ),
            ToolSpec(
                name="file_list",
                description="List files in a directory.",
                parameters=[
                    ToolParam("path", "string", "Directory path", required=False),
                    ToolParam("recursive", "boolean", "List recursively", required=False),
                ],
                read_only=True,
            ),
            ToolSpec(
                name="file_search",
                description="Search for files by pattern.",
                parameters=[
                    ToolParam("pattern", "string", "Glob pattern like *.py"),
                    ToolParam("path", "string", "Directory to search in", required=False),
                ],
                read_only=True,
            ),
            ToolSpec(
                name="file_delete",
                description="Delete a file or empty directory.",
                parameters=[
                    ToolParam("path", "string", "Path to delete"),
                ],
                dangerous=True,
            ),
            ToolSpec(
                name="file_edit",
                description=(
                    "Precisely edit a file by replacing a unique search block with new content. "
                    "The search block must match exactly (including whitespace). "
                    "If the search block appears multiple times, only the first occurrence is replaced."
                ),
                parameters=[
                    ToolParam("path", "string", "Relative or absolute path to file"),
                    ToolParam("search", "string", "Exact text block to search for"),
                    ToolParam("replace", "string", "Replacement text block"),
                ],
                dangerous=True,
            ),
            ToolSpec(
                name="file_view",
                description=(
                    "View a file with line numbers, or list a directory as a tree. "
                    "Use this instead of file_read when you need line numbers or directory structure."
                ),
                parameters=[
                    ToolParam("path", "string", "File or directory path"),
                    ToolParam(
                        "offset",
                        "integer",
                        "Line offset to start from (files only)",
                        required=False,
                    ),
                    ToolParam("limit", "integer", "Max lines to read (files only)", required=False),
                ],
                read_only=True,
            ),
            ToolSpec(
                name="code_search",
                description=(
                    "Search for text inside file contents (not filenames). "
                    "Defaults to literal substring search. Set use_regex=true only when needed; "
                    "regex runs in an isolated worker with a hard timeout."
                ),
                parameters=[
                    ToolParam("pattern", "string", "Literal text or regex pattern to search for"),
                    ToolParam("path", "string", "Directory to search in", required=False),
                    ToolParam(
                        "file_pattern", "string", "File glob filter e.g. *.py", required=False
                    ),
                    ToolParam("max_results", "integer", "Max matches to return", required=False),
                    ToolParam(
                        "use_regex",
                        "boolean",
                        "Use regular expressions (default false = literal search)",
                        required=False,
                    ),
                ],
                read_only=True,
            ),
        ]

    async def read(self, path: str, offset: int = 0, limit: int = 0) -> ToolResult:
        try:
            logical = self._logical_path(path)
            decision = self.guard.check_path_operation(str(logical), "read")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)
            content, _target = self._secure_read_text(
                path,
                max_bytes=max(
                    self.limits.file_read_max_chars * 4,
                    self.limits.tool_output_budget_chars * 4,
                ),
            )
            lines = content.splitlines()
            total_lines = len(lines)

            if offset > 0:
                lines = lines[offset:]
            if limit > 0:
                lines = lines[:limit]

            result = "\n".join(lines)
            budget = self.limits.tool_output_budget_chars

            # Orin WP2 site 11: credential-path reads mark the result so the
            # turn loop stamps SECRET on the tool-result message (D §6.1
            # deterministic credential table — never a semantic judgment).
            from js.orin.taint import METADATA_SECRET_FLAG, path_is_credential, secret_hint

            secret_hit = path_is_credential(str(logical)) or secret_hint(content)
            from js.orin.hooks import inspect_canary_text

            inspect_canary_text(content, surface="read")
            metadata: dict[str, Any] = {"lines": len(lines), "total_lines": total_lines}
            if secret_hit:
                metadata[METADATA_SECRET_FLAG] = True

            if len(result) > budget:
                overflow_meta: dict[str, Any] = {
                    "too_large": True,
                    "size": len(content),
                    "suggestion": "Use file_read with offset and limit to paginate",
                }
                if secret_hit:
                    overflow_meta[METADATA_SECRET_FLAG] = True
                return ToolResult(
                    success=True,
                    output="",
                    metadata=overflow_meta,
                )

            return ToolResult(success=True, output=result, metadata=metadata)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def write(self, path: str, content: str, append: bool = False) -> ToolResult:
        try:
            logical = self._logical_path(path)
            decision = self.guard.check_path_operation(str(logical), "write")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

        from js.orin.hooks import inspect_canary_text

        canary_block = inspect_canary_text(content, surface="write")
        if canary_block is not None:
            return ToolResult(success=False, error=canary_block)

        if len(content) > self.limits.file_write_max_chars:
            return ToolResult(
                success=False,
                error=f"Content too large: {len(content)} > {self.limits.file_write_max_chars}",
            )

        if self.cell_backend is not None:
            final_content = content
            if append:
                try:
                    existing, _target = self._secure_read_text(
                        path,
                        max_bytes=max(
                            self.limits.file_write_max_chars * 4,
                            self.limits.file_read_max_chars,
                        ),
                    )
                except FileNotFoundError:
                    existing = ""
                except Exception as exc:
                    return ToolResult(success=False, error=f"File Cell input rejected: {exc}")
                final_content = existing + content
                if len(final_content) > self.limits.file_write_max_chars:
                    return ToolResult(
                        success=False,
                        error=(
                            f"Content too large: {len(final_content)} > "
                            f"{self.limits.file_write_max_chars}"
                        ),
                    )
            return await self._commit_file_cell_change(path, final_content)

        try:
            payload = content.encode("utf-8")
            target = self._secure_write(path, payload, append=append)

            # Track script provenance
            if target.suffix in (".sh", ".py", ".js", ".ts", ".bash", ".zsh"):
                self.guard.register_script_artifact(str(target))

            return ToolResult(
                success=True,
                output=f"Written {len(content)} chars to {path}",
                metadata={"path": str(target), "bytes": len(content.encode())},
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def list_dir(self, path: str = ".", recursive: bool = False) -> ToolResult:
        try:
            logical = self._logical_path(path)
            decision = self.guard.check_path_operation(str(logical), "read")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)

            def _list() -> list[tuple[Any, int, int]]:
                with self._open_secure_directory(path) as (directory_fd, _target):
                    return self._walk_secure_directory(
                        directory_fd,
                        recursive=recursive,
                    )

            entries = await asyncio.to_thread(_list)
            items = []
            for relative, mode, size in entries:
                marker = "📁" if stat.S_ISDIR(mode) else "📄"
                if recursive:
                    items.append(f"{marker} {relative}")
                else:
                    items.append(
                        f"{marker} {relative.name} ({size if stat.S_ISREG(mode) else 0} bytes)"
                    )

            return ToolResult(success=True, output="\n".join(items))
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def search(self, pattern: str, path: str = ".") -> ToolResult:
        try:
            logical = self._logical_path(path)
            decision = self.guard.check_path_operation(str(logical), "read")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)

            import fnmatch

            def _search() -> list[str]:
                matches: list[str] = []
                with self._open_secure_directory(path) as (directory_fd, target):
                    entries = self._walk_secure_directory(directory_fd, recursive=True)
                    target_relative = target.relative_to(self.workspace)
                    for relative, _mode, _size in entries:
                        if fnmatch.fnmatch(relative.name, pattern):
                            matches.append(str(target_relative / relative))
                        if len(matches) >= 100:
                            matches.append("... (too many matches)")
                            break
                return matches

            matches = await asyncio.to_thread(_search)
            return ToolResult(success=True, output="\n".join(matches) or "No matches found")
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def delete(self, path: str) -> ToolResult:
        try:
            logical = self._logical_path(path)
            decision = self.guard.check_path_operation(str(logical), "delete")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)
            if self.cell_backend is not None:
                return ToolResult(
                    success=False,
                    error="File Cell delete is not supported; local delete is disabled",
                )
            self._reject_git_metadata_write(path)
            self._reject_runtime_tcb_write(path)
            with self._open_secure_parent(path, create_parents=False) as (
                parent_fd,
                name,
                _logical,
            ):
                metadata = self._reject_unsafe_final(parent_fd, name)
                if metadata is None:
                    return ToolResult(success=False, error=f"Path not found: {path}")
                if stat.S_ISREG(metadata.st_mode):
                    os.unlink(name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                    return ToolResult(success=True, output=f"Deleted file: {path}")
                if stat.S_ISDIR(metadata.st_mode):
                    try:
                        os.rmdir(name, dir_fd=parent_fd)
                    except OSError as exc:
                        if exc.errno in {errno.ENOTEMPTY, errno.EEXIST}:
                            return ToolResult(
                                success=False,
                                error="Directory not empty, use recursive delete",
                            )
                        raise
                    os.fsync(parent_fd)
                    return ToolResult(success=True, output=f"Deleted directory: {path}")
                return ToolResult(
                    success=False,
                    error="Workspace delete target has an unsupported file type",
                )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def edit(self, path: str, search: str, replace: str) -> ToolResult:
        """Precisely edit a file by replacing a unique search block."""
        try:
            logical = self._logical_path(path)
            decision = self.guard.check_path_operation(str(logical), "write")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)
            content, target = self._secure_read_text(
                path,
                max_bytes=max(
                    self.limits.file_write_max_chars * 4,
                    self.limits.file_read_max_chars,
                ),
            )
            occurrences = content.count(search)
            if occurrences == 0:
                return ToolResult(
                    success=False,
                    error=(
                        f"Search block not found in {path}. "
                        f"The text must match exactly (including whitespace and newlines)."
                    ),
                )
            if occurrences > 1:
                return ToolResult(
                    success=False,
                    error=(
                        f"Search block appears {occurrences} times in {path}. "
                        f"Please provide a more unique search block."
                    ),
                )

            new_content = content.replace(search, replace, 1)
            if len(new_content) > self.limits.file_write_max_chars:
                return ToolResult(
                    success=False,
                    error=(
                        f"Content too large: {len(new_content)} > "
                        f"{self.limits.file_write_max_chars}"
                    ),
                )
            if self.cell_backend is not None:
                return await self._commit_file_cell_change(path, new_content)
            target = self._secure_write(
                path,
                new_content.encode("utf-8"),
                append=False,
            )

            # Track script provenance
            if target.suffix in (".sh", ".py", ".js", ".ts", ".bash", ".zsh"):
                self.guard.register_script_artifact(str(target))

            return ToolResult(
                success=True,
                output=f"Edited {path}: replaced {len(search)} chars with {len(replace)} chars",
                metadata={
                    "path": str(target),
                    "search_chars": len(search),
                    "replace_chars": len(replace),
                },
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def view(self, path: str, offset: int = 0, limit: int = 0) -> ToolResult:
        """View a file with line numbers, or list a directory as a tree."""
        try:
            logical = self._logical_path(path)
            decision = self.guard.check_path_operation(str(logical), "read")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)

            def _view() -> ToolResult:
                metadata, target = self._secure_lstat(path)
                if stat.S_ISDIR(metadata.st_mode):
                    with self._open_secure_directory(path) as (directory_fd, _target):
                        entries = self._walk_secure_directory(directory_fd, recursive=True)
                    lines = ["./"]
                    lines.extend(
                        f"{'📁' if stat.S_ISDIR(mode) else '📄'} {relative}"
                        for relative, mode, _size in entries
                    )
                    return ToolResult(
                        success=True,
                        output="\n".join(lines),
                        metadata={"type": "directory", "entries": len(lines)},
                    )

                if not stat.S_ISREG(metadata.st_mode):
                    return ToolResult(success=False, error="Unsupported workspace file type")
                content, target = self._secure_read_text(
                    path,
                    max_bytes=max(
                        self.limits.file_read_max_chars * 4,
                        self.limits.tool_output_budget_chars * 4,
                    ),
                )
                all_lines = content.splitlines()

                if offset > 0:
                    display_lines = all_lines[offset:]
                else:
                    display_lines = all_lines
                if limit > 0:
                    display_lines = display_lines[:limit]

                max_digits = len(str(len(all_lines)))
                numbered: list[str] = []
                for i, line in enumerate(display_lines, start=offset + 1):
                    numbered.append(f"{i:>{max_digits}} | {line}")

                result = "\n".join(numbered)
                if len(result) > self.limits.file_read_max_chars:
                    result = result[: self.limits.file_read_max_chars] + "\n... [truncated]"

                return ToolResult(
                    success=True,
                    output=result,
                    metadata={
                        "lines": len(display_lines),
                        "total_lines": len(all_lines),
                        "offset": offset,
                        "type": "file",
                    },
                )

            return await asyncio.to_thread(_view)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def code_search(
        self,
        pattern: str,
        path: str = ".",
        file_pattern: str = "",
        max_results: int = 50,
        use_regex: bool = False,
    ) -> ToolResult:
        """Search for text patterns inside file contents.

        Literal search is the default (linear). Regex mode runs in a killable
        spawn process so catastrophic backtracking cannot block the event loop.
        Walk/read/splitlines/literal search and process start run in a worker
        thread so the event loop stays responsive.
        """
        try:
            import multiprocessing as mp

            if type(use_regex) is not bool:
                return ToolResult(
                    success=False,
                    error="use_regex must be a boolean",
                    metadata=dict(_CODE_SEARCH_INCOMPLETE_METADATA),
                )
            if type(max_results) is not int:
                return ToolResult(
                    success=False,
                    error="max_results must be an integer",
                    metadata=dict(_CODE_SEARCH_INCOMPLETE_METADATA),
                )
            if not isinstance(pattern, str) or not pattern:
                return ToolResult(
                    success=False,
                    error="pattern must be a non-empty string",
                    metadata=dict(_CODE_SEARCH_INCOMPLETE_METADATA),
                )
            if len(pattern) > self.limits.code_search_max_pattern_chars:
                return ToolResult(
                    success=False,
                    error=(
                        "pattern exceeds length limit "
                        f"({self.limits.code_search_max_pattern_chars} chars)"
                    ),
                    metadata=dict(_CODE_SEARCH_INCOMPLETE_METADATA),
                )

            logical = self._logical_path(path)
            decision = self.guard.check_path_operation(str(logical), "read")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)

            max_results = max(1, min(max_results, 100))
            task = asyncio.current_task()
            runtime = current_runtime_context()
            cancel_token = None if runtime is None else runtime.cancel_token

            def _cancelled() -> bool:
                if task is not None and (task.cancelled() or task.cancelling()):
                    return True
                return _cancel_requested(cancel_token)

            def _collect_payloads() -> tuple[
                list[tuple[str, list[str]]],
                bool,
                ToolResult | None,
            ]:
                """Return (payloads, complete, early_error)."""
                if _cancelled():
                    raise asyncio.CancelledError
                files_scanned = 0
                bytes_scanned = 0
                complete = True
                file_payloads: list[tuple[str, list[str]]] = []

                try:
                    with self._open_secure_directory(path) as (directory_fd, target):
                        entries = self._walk_secure_directory(directory_fd, recursive=True)
                except OSError as exc:
                    return (
                        [],
                        False,
                        ToolResult(
                            success=False,
                            error=f"code_search walk failed: {exc}",
                            metadata={
                                "matches": 0,
                                "truncated": False,
                                "complete": False,
                            },
                        ),
                    )
                target_relative = target.relative_to(self.workspace)
                per_file_cap = max(
                    self.limits.file_read_max_chars * 4,
                    self.limits.tool_output_budget_chars * 4,
                )

                for relative, mode, _size in entries:
                    if _cancelled():
                        raise asyncio.CancelledError
                    if not stat.S_ISREG(mode):
                        continue
                    if file_pattern and not relative.match(file_pattern):
                        continue
                    if files_scanned >= self.limits.code_search_max_files:
                        return (
                            file_payloads,
                            False,
                            ToolResult(
                                success=False,
                                error=(
                                    "code_search exceeded file scan limit "
                                    f"({self.limits.code_search_max_files})"
                                ),
                                metadata={
                                    "matches": 0,
                                    "truncated": False,
                                    "complete": False,
                                },
                            ),
                        )
                    remaining = self.limits.code_search_max_bytes - bytes_scanned
                    if remaining <= 0:
                        return (
                            file_payloads,
                            False,
                            ToolResult(
                                success=False,
                                error=(
                                    "code_search exceeded total byte scan limit "
                                    f"({self.limits.code_search_max_bytes})"
                                ),
                                metadata={
                                    "matches": 0,
                                    "truncated": False,
                                    "complete": False,
                                },
                            ),
                        )
                    relative_to_workspace = str(target_relative / relative)
                    try:
                        text, _logical_file, bytes_read, stable = self._secure_read_text_detailed(
                            relative_to_workspace,
                            max_bytes=min(remaining, per_file_cap),
                        )
                    except ValueError as exc:
                        message = str(exc)
                        if "exceeds the read size limit" in message:
                            return (
                                file_payloads,
                                False,
                                ToolResult(
                                    success=False,
                                    error=(
                                        "code_search exceeded total byte scan limit "
                                        f"({self.limits.code_search_max_bytes})"
                                    ),
                                    metadata={
                                        "matches": 0,
                                        "truncated": False,
                                        "complete": False,
                                    },
                                ),
                            )
                        complete = False
                        continue
                    except Exception:
                        complete = False
                        continue

                    if bytes_scanned + bytes_read > self.limits.code_search_max_bytes:
                        return (
                            file_payloads,
                            False,
                            ToolResult(
                                success=False,
                                error=(
                                    "code_search exceeded total byte scan limit "
                                    f"({self.limits.code_search_max_bytes})"
                                ),
                                metadata={
                                    "matches": 0,
                                    "truncated": False,
                                    "complete": False,
                                },
                            ),
                        )
                    bytes_scanned += bytes_read
                    files_scanned += 1
                    if not stable:
                        complete = False
                    file_payloads.append((relative_to_workspace, text.splitlines()))
                return file_payloads, complete, None

            def _literal_search(
                file_payloads: list[tuple[str, list[str]]],
                *,
                complete: bool,
            ) -> ToolResult:
                matches: list[str] = []
                for rel_path, lines in file_payloads:
                    if _cancelled():
                        raise asyncio.CancelledError
                    for i, line in enumerate(lines, start=1):
                        sample = (
                            line
                            if len(line) <= self.limits.code_search_max_line_chars
                            else line[: self.limits.code_search_max_line_chars]
                        )
                        if pattern not in sample:
                            continue
                        snippet = sample.strip()
                        if len(snippet) > 120:
                            snippet = snippet[:120] + "..."
                        matches.append(f"{rel_path}:{i} | {snippet}")
                        if len(matches) >= max_results:
                            return ToolResult(
                                success=True,
                                output="\n".join(matches),
                                metadata={
                                    "matches": len(matches),
                                    "truncated": True,
                                    "complete": False,
                                    "mode": "literal",
                                },
                            )
                return ToolResult(
                    success=True,
                    output="\n".join(matches) or "No matches found",
                    metadata={
                        "matches": len(matches),
                        "truncated": False,
                        "complete": complete,
                        "mode": "literal",
                    },
                )

            def _terminate_worker(worker: Any) -> None:
                if worker is None:
                    return
                try:
                    if worker.is_alive():
                        worker.terminate()
                        worker.join(timeout=1.0)
                        if worker.is_alive():
                            worker.kill()
                            worker.join(timeout=1.0)
                except Exception:
                    pass

            def _regex_search(
                file_payloads: list[tuple[str, list[str]]],
                *,
                complete: bool,
            ) -> ToolResult:
                if _cancelled():
                    raise asyncio.CancelledError
                ctx = mp.get_context("spawn")
                parent_conn, child_conn = ctx.Pipe(duplex=False)
                worker = ctx.Process(
                    target=_regex_search_job,
                    args=(pattern, file_payloads),
                    kwargs={
                        "max_line_chars": self.limits.code_search_max_line_chars,
                        "max_matches": max_results,
                        "result_conn": child_conn,
                    },
                    daemon=True,
                )
                status: str | None = None
                payload: Any = None
                try:
                    # start is inside the cleanup scope so failures never orphan workers.
                    worker.start()
                    try:
                        child_conn.close()
                    except Exception:
                        pass
                    timeout = float(self.limits.code_search_regex_timeout_seconds)
                    # Poll cancel on a short interval so caller cancellation can
                    # terminate the worker promptly (do not block for full timeout).
                    poll_interval = 0.05
                    deadline = time.monotonic() + max(0.0, timeout)
                    while True:
                        if _cancelled():
                            raise asyncio.CancelledError
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            if worker.is_alive():
                                raise TimeoutError("regex search timed out")
                            raise RuntimeError("regex worker exited without a result")
                        if parent_conn.poll(min(poll_interval, remaining)):
                            status, payload = parent_conn.recv()
                            worker.join(timeout=1.0)
                            break
                except TimeoutError:
                    return ToolResult(
                        success=False,
                        error=(
                            "regex search timed out; refine the pattern or use "
                            "literal search (use_regex=false)"
                        ),
                        metadata={"matches": 0, "truncated": False, "complete": False},
                    )
                finally:
                    _terminate_worker(worker)
                    try:
                        parent_conn.close()
                    except Exception:
                        pass
                    try:
                        child_conn.close()
                    except Exception:
                        pass

                if status != "ok":
                    return ToolResult(
                        success=False,
                        error=f"Invalid regex: {payload}",
                        metadata=dict(_CODE_SEARCH_INCOMPLETE_METADATA),
                    )
                matches = [f"{rel}:{line_no} | {snippet}" for rel, line_no, snippet in payload]
                truncated = len(matches) >= max_results
                return ToolResult(
                    success=True,
                    output="\n".join(matches) or "No matches found",
                    metadata={
                        "matches": len(matches),
                        "truncated": truncated,
                        "complete": complete and not truncated,
                        "mode": "regex",
                    },
                )

            def _run() -> ToolResult:
                file_payloads, complete, early = _collect_payloads()
                if early is not None:
                    return early
                if use_regex:
                    return _regex_search(file_payloads, complete=complete)
                return _literal_search(file_payloads, complete=complete)

            return await asyncio.to_thread(_run)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                metadata={"matches": 0, "truncated": False, "complete": False},
            )

    def register_all(self, registry: Any) -> None:
        """Register all file tools with a ToolRegistry."""
        for spec in self.get_specs():
            if spec.name == "file_read":
                registry.register(spec, self.read)
            elif spec.name == "file_write":
                registry.register(spec, self.write)
            elif spec.name == "file_list":
                registry.register(spec, self.list_dir)
            elif spec.name == "file_search":
                registry.register(spec, self.search)
            elif spec.name == "file_delete":
                registry.register(spec, self.delete)
            elif spec.name == "file_edit":
                registry.register(spec, self.edit)
            elif spec.name == "file_view":
                registry.register(spec, self.view)
            elif spec.name == "code_search":
                registry.register(spec, self.code_search)
