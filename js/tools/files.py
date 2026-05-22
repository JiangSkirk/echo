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

    def _resolve(self, path: str) -> Path:
        """Resolve path relative to workspace."""
        p = Path(path)
        if p.is_absolute():
            resolved = p.resolve()
        else:
            resolved = (self.workspace / p).resolve()
        # Ensure resolved path is inside workspace
        try:
            resolved.relative_to(self.workspace)
        except ValueError as e:
            raise ValueError(f"Path escapes workspace: {path}") from e
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
            target = self._resolve(path)
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
            target.parent.mkdir(parents=True, exist_ok=True)
            mode = "a" if append else "w"
            with open(target, mode, encoding="utf-8") as f:
                f.write(content)

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
            target = self._resolve(path)
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
