"""Tests for tool system."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard, SecurityDecisionType
from js.tools.files import FileTools
from js.tools.registry import ToolRegistry


class TestFileTools:
    @pytest.fixture
    def file_tools(self, tmp_path: Path) -> FileTools:
        limits = ToolLimits()
        guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
        return FileTools(tmp_path, limits, guard)

    @pytest.mark.asyncio
    async def test_read_write(self, file_tools: FileTools, tmp_path: Path) -> None:
        result = await file_tools.write("test.txt", "hello world")
        assert result.success

        result = await file_tools.read("test.txt")
        assert result.success
        assert "hello world" in result.output

    @pytest.mark.asyncio
    async def test_list_dir(self, file_tools: FileTools) -> None:
        await file_tools.write("a.txt", "a")
        await file_tools.write("b.txt", "b")

        result = await file_tools.list_dir(".")
        assert result.success
        assert "a.txt" in result.output
        assert "b.txt" in result.output

    @pytest.mark.asyncio
    async def test_delete(self, file_tools: FileTools) -> None:
        await file_tools.write("delete_me.txt", "content")
        result = await file_tools.delete("delete_me.txt")
        assert result.success

        result = await file_tools.read("delete_me.txt")
        assert not result.success

    @pytest.mark.asyncio
    async def test_write_fails_closed_if_parent_is_swapped_to_symlink(
        self,
        file_tools: FileTools,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        parent = tmp_path / "parent"
        parent.mkdir()
        outside = tmp_path.parent / f"{tmp_path.name}-outside-write"
        outside.mkdir()
        swapped = False

        def swap_parent(_path: str, _operation: str) -> SimpleNamespace:
            nonlocal swapped
            if not swapped:
                parent.rename(tmp_path / "original-parent")
                parent.symlink_to(outside, target_is_directory=True)
                swapped = True
            return SimpleNamespace(decision=SecurityDecisionType.ALLOW, reason="")

        monkeypatch.setattr(file_tools.guard, "check_path_operation", swap_parent)

        result = await file_tools.write("parent/escape.txt", "must stay inside")

        assert result.success is False
        assert not (outside / "escape.txt").exists()

    @pytest.mark.asyncio
    async def test_delete_fails_closed_if_parent_is_swapped_to_symlink(
        self,
        file_tools: FileTools,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        parent = tmp_path / "parent-delete"
        parent.mkdir()
        (parent / "victim.txt").write_text("inside", encoding="utf-8")
        outside = tmp_path.parent / f"{tmp_path.name}-outside-delete"
        outside.mkdir()
        outside_victim = outside / "victim.txt"
        outside_victim.write_text("private", encoding="utf-8")
        swapped = False

        def swap_parent(_path: str, _operation: str) -> SimpleNamespace:
            nonlocal swapped
            if not swapped:
                parent.rename(tmp_path / "original-parent-delete")
                parent.symlink_to(outside, target_is_directory=True)
                swapped = True
            return SimpleNamespace(decision=SecurityDecisionType.ALLOW, reason="")

        monkeypatch.setattr(file_tools.guard, "check_path_operation", swap_parent)

        result = await file_tools.delete("parent-delete/victim.txt")

        assert result.success is False
        assert outside_victim.read_text(encoding="utf-8") == "private"
    @pytest.mark.asyncio
    async def test_git_metadata_writes_are_rejected(
        self, file_tools: FileTools, tmp_path: Path
    ) -> None:
        """file_write/file_edit/file_delete must never touch workspace .git/.

        A tool-written hook or config would execute on the host's next git
        invocation; reads stay allowed for legitimate inspection.
        """
        git_dir = tmp_path / ".git"
        (git_dir / "hooks").mkdir(parents=True)
        config = git_dir / "config"
        config.write_text("[core]\n\trepositoryformatversion = 0\n", encoding="utf-8")

        for path in (".git/config", ".git/hooks/pre-commit", ".git"):
            result = await file_tools.write(path, "[core]\n\thooksPath = evil\n")
            assert result.success is False, path
            assert ".git" in result.error

        result = await file_tools.edit(
            ".git/config", "repositoryformatversion = 0", "hooksPath = evil"
        )
        assert result.success is False
        assert ".git" in result.error

        result = await file_tools.delete(".git/config")
        assert result.success is False
        assert ".git" in result.error

        # Nothing was mutated and reads are unaffected.
        assert "hooksPath" not in config.read_text(encoding="utf-8")
        assert not (git_dir / "hooks" / "pre-commit").exists()
        result = await file_tools.read(".git/config")
        assert result.success
        assert "repositoryformatversion" in result.output

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path", [".GIT/config", ".Git/hooks/pwn", ".gIt", "x/.GiT/y"])
    async def test_git_metadata_case_variants_are_rejected(
        self, file_tools: FileTools, tmp_path: Path, path: str
    ) -> None:
        """Round-3 finding: on case-insensitive filesystems (default APFS,
        Windows) a case variant like ``.GIT/config`` resolved onto ``.git/``
        and bypassed the lexical guard — it must be compared case-folded."""
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        result = await file_tools.write(path, "pwned")
        assert result.success is False, path
        assert ".git" in result.error.lower()
        assert not (tmp_path / ".git" / "config").exists()
        result = await file_tools.delete(path)
        assert result.success is False, path


class TestToolRegistry:
    def test_register_and_list(self, tmp_path: Path) -> None:
        limits = ToolLimits()
        guard = BehaviorGuard(SecurityConfig(), tmp_path)
        registry = ToolRegistry(limits, guard)

        from js.tools.registry import ToolParam, ToolSpec

        async def dummy_handler(x: int) -> None:
            pass

        spec = ToolSpec(
            name="test",
            description="A test tool",
            parameters=[ToolParam("x", "integer", "A number")],
        )
        registry.register(spec, dummy_handler)

        assert registry.get("test") is not None
        assert len(registry.list_tools()) == 1

    def test_replace_owned_removes_only_the_requested_owner(self, tmp_path: Path) -> None:
        """Owner revocation must not behave like a registry-wide close."""
        from js.tools.registry import ToolResult, ToolSpec

        registry = ToolRegistry(ToolLimits(), BehaviorGuard(SecurityConfig(), tmp_path))

        async def handler() -> ToolResult:
            return ToolResult(success=True)

        registry.register(ToolSpec("native", "native", []), handler)
        owner = object()
        accepted = registry.replace_owned(
            owner,
            1,
            [(ToolSpec("managed", "managed", []), handler)],
        )
        assert accepted == frozenset({"managed"})

        registry.replace_owned(owner, 2, [])

        assert registry.get("managed") is None
        assert registry.get("native") is not None
