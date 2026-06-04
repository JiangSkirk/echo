"""Safe file operations with path validation and size limits."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from js.config import ToolLimits
from js.security.guard import BehaviorGuard, SecurityDecisionType
from js.tools.registry import ToolParam, ToolResult, ToolSpec


class FileTools:
    """Collection of safe file system tools."""

    def __init__(self, workspace: Path, limits: ToolLimits, guard: BehaviorGuard) -> None:
        self.workspace = workspace.resolve()
        self.limits = limits
        self.guard = guard

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
                    ToolParam("offset", "integer", "Line offset to start from (files only)", required=False),
                    ToolParam("limit", "integer", "Max lines to read (files only)", required=False),
                ],
                read_only=True,
            ),
            ToolSpec(
                name="code_search",
                description=(
                    "Search for text patterns inside file contents (not filenames). "
                    "Searches within the workspace recursively. Returns matching lines with file paths."
                ),
                parameters=[
                    ToolParam("pattern", "string", "Text or regex pattern to search for"),
                    ToolParam("path", "string", "Directory to search in", required=False),
                    ToolParam("file_pattern", "string", "File glob filter e.g. *.py", required=False),
                    ToolParam("max_results", "integer", "Max matches to return", required=False),
                ],
                read_only=True,
            ),
        ]

    async def read(self, path: str, offset: int = 0, limit: int = 0) -> ToolResult:
        try:
            target = self._resolve(path)
            decision = self.guard.check_path_operation(str(target), "read")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)

            if not target.exists():
                return ToolResult(success=False, error=f"File not found: {path}")

            content = target.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()

            if offset > 0:
                lines = lines[offset:]
            if limit > 0:
                lines = lines[:limit]

            result = "\n".join(lines)
            if len(result) > self.limits.file_read_max_chars:
                result = result[: self.limits.file_read_max_chars] + "\n... [truncated]"

            return ToolResult(
                success=True,
                output=result,
                metadata={"lines": len(lines), "total_lines": len(content.splitlines())},
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def write(self, path: str, content: str, append: bool = False) -> ToolResult:
        try:
            target = self._resolve(path, follow_symlinks=False)
            decision = self.guard.check_path_operation(str(target), "write")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

        if len(content) > self.limits.file_write_max_chars:
            return ToolResult(
                success=False,
                error=f"Content too large: {len(content)} > {self.limits.file_write_max_chars}",
            )

        try:
            import os as _os
            target.parent.mkdir(parents=True, exist_ok=True)
            mode = "a" if append else "w"
            # Atomic write: write to a temp file then atomically replace.
            # Prevents corruption if the process crashes mid-write.
            tmp_path = target.with_suffix(target.suffix + ".js_tmp")
            # Remove any existing symlink at tmp_path to prevent TOCTOU bypass
            if tmp_path.is_symlink():
                tmp_path.unlink()
            with open(tmp_path, mode, encoding="utf-8") as f:
                f.write(content)
            _os.replace(str(tmp_path), str(target))

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
            target = self._resolve(path)
            decision = self.guard.check_path_operation(str(target), "read")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)

            if not target.is_dir():
                return ToolResult(success=False, error=f"Not a directory: {path}")

            items: list[str] = []
            if recursive:
                for p in target.rglob("*"):
                    rel = p.relative_to(target)
                    marker = "📁" if p.is_dir() else "📄"
                    items.append(f"{marker} {rel}")
            else:
                for p in sorted(target.iterdir()):
                    marker = "📁" if p.is_dir() else "📄"
                    size = p.stat().st_size if p.is_file() else 0
                    items.append(f"{marker} {p.name} ({size} bytes)")

            return ToolResult(success=True, output="\n".join(items))
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def search(self, pattern: str, path: str = ".") -> ToolResult:
        try:
            target = self._resolve(path)
            decision = self.guard.check_path_operation(str(target), "read")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)

            import fnmatch

            matches: list[str] = []
            for p in target.rglob("*"):
                if fnmatch.fnmatch(p.name, pattern):
                    matches.append(str(p.relative_to(self.workspace)))
                if len(matches) >= 100:
                    matches.append("... (too many matches)")
                    break

            return ToolResult(success=True, output="\n".join(matches) or "No matches found")
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def delete(self, path: str) -> ToolResult:
        try:
            target = self._resolve(path, follow_symlinks=False)
            decision = self.guard.check_path_operation(str(target), "delete")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)

            if target.is_file():
                target.unlink()
                return ToolResult(success=True, output=f"Deleted file: {path}")
            elif target.is_dir():
                if any(target.iterdir()):
                    return ToolResult(
                        success=False, error="Directory not empty, use recursive delete"
                    )
                target.rmdir()
                return ToolResult(success=True, output=f"Deleted directory: {path}")
            else:
                return ToolResult(success=False, error=f"Path not found: {path}")
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def edit(self, path: str, search: str, replace: str) -> ToolResult:
        """Precisely edit a file by replacing a unique search block."""
        try:
            target = self._resolve(path, follow_symlinks=False)
            decision = self.guard.check_path_operation(str(target), "write")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)

            if not target.exists():
                return ToolResult(success=False, error=f"File not found: {path}")

            content = target.read_text(encoding="utf-8", errors="replace")
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
            # Atomic write: remove any symlink at temp path first
            import os as _os
            tmp_path = target.with_suffix(target.suffix + ".js_tmp")
            if tmp_path.is_symlink():
                tmp_path.unlink()
            tmp_path.write_text(new_content, encoding="utf-8")
            _os.replace(str(tmp_path), str(target))

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
            target = self._resolve(path)
            decision = self.guard.check_path_operation(str(target), "read")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)

            if not target.exists():
                return ToolResult(success=False, error=f"Path not found: {path}")

            if target.is_dir():
                lines = self._tree_lines(target, target, prefix="")
                return ToolResult(
                    success=True,
                    output="\n".join(lines),
                    metadata={"type": "directory", "entries": len(lines)},
                )

            content = target.read_text(encoding="utf-8", errors="replace")
            all_lines = content.splitlines()

            if offset > 0:
                display_lines = all_lines[offset:]
            else:
                display_lines = all_lines
            if limit > 0:
                display_lines = display_lines[:limit]

            # Build numbered output
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
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def _tree_lines(
        self, root: Path, current: Path, prefix: str = ""
    ) -> list[str]:
        """Recursively build directory tree lines."""
        lines: list[str] = []
        rel = current.relative_to(root)
        name = current.name if rel != Path(".") else "."
        if current.is_dir():
            lines.append(f"{prefix}{name}/")
            children = sorted(current.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
            for i, child in enumerate(children):
                is_last = i == len(children) - 1
                child_prefix = prefix + ("    " if is_last else "│   ")
                lines.extend(self._tree_lines(root, child, child_prefix))
        else:
            size = current.stat().st_size
            lines.append(f"{prefix}{name} ({size} bytes)")
        return lines

    async def code_search(
        self,
        pattern: str,
        path: str = ".",
        file_pattern: str = "",
        max_results: int = 50,
    ) -> ToolResult:
        """Search for text patterns inside file contents."""
        try:
            import re

            target = self._resolve(path)
            decision = self.guard.check_path_operation(str(target), "read")
            if decision.decision == SecurityDecisionType.BLOCK:
                return ToolResult(success=False, error=decision.reason)

            regex = re.compile(pattern)
            matches: list[str] = []
            max_results = min(max_results, 100)

            for p in target.rglob("*"):
                if p.is_symlink():
                    continue  # Block symlink traversal in code search
                if not p.is_file():
                    continue
                if file_pattern and not p.match(file_pattern):
                    continue
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                    for i, line in enumerate(text.splitlines(), start=1):
                        if regex.search(line):
                            rel = p.relative_to(self.workspace)
                            snippet = line.strip()
                            if len(snippet) > 120:
                                snippet = snippet[:120] + "..."
                            matches.append(f"{rel}:{i} | {snippet}")
                            if len(matches) >= max_results:
                                return ToolResult(
                                    success=True,
                                    output="\n".join(matches),
                                    metadata={
                                        "matches": len(matches),
                                        "truncated": True,
                                    },
                                )
                except Exception:
                    continue

            return ToolResult(
                success=True,
                output="\n".join(matches) or "No matches found",
                metadata={"matches": len(matches), "truncated": False},
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

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
