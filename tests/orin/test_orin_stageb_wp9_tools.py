"""WP9 FileTools routing into the resident File Cell."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.agent.tool_executor import ToolExecutorMixin
from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.files import FileTools


def _executor(*, enabled: bool, stage_b: bool, cell_file: bool) -> ToolExecutorMixin:
    executor = object.__new__(ToolExecutorMixin)
    executor.settings = SimpleNamespace(  # type: ignore[attr-defined]
        orin=SimpleNamespace(
            enabled=enabled,
            stage_b=stage_b,
            cell_file=cell_file,
        )
    )
    return executor


def _file_tools(
    workspace: Path,
    backend: Any,
) -> FileTools:
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), workspace)
    return FileTools(
        workspace,
        ToolLimits(),
        guard,
        cell_backend=backend,
    )


def _forbid_local_write(
    tools: FileTools,
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[Any, ...]]:
    calls: list[tuple[Any, ...]] = []

    def forbidden(*args: Any, **kwargs: Any) -> Path:
        calls.append((*args, kwargs))
        raise AssertionError("FileTools must not write in-process while File Cell is enabled")

    monkeypatch.setattr(tools, "_secure_write", forbidden)
    return calls


class TestFileCellBackendConfig:
    @pytest.mark.parametrize(
        ("enabled", "stage_b", "cell_file"),
        (
            (False, True, True),
            (True, False, True),
            (True, True, False),
            (False, False, False),
        ),
    )
    def test_backend_absent_unless_all_three_switches_are_enabled(
        self,
        enabled: bool,
        stage_b: bool,
        cell_file: bool,
    ) -> None:
        executor = _executor(enabled=enabled, stage_b=stage_b, cell_file=cell_file)
        assert executor._file_cell_backend() is None  # type: ignore[attr-defined]

    def test_backend_present_when_all_three_switches_are_enabled(self) -> None:
        executor = _executor(enabled=True, stage_b=True, cell_file=True)
        assert callable(executor._file_cell_backend())  # type: ignore[attr-defined]


class TestFileToolsCellBoundary:
    @pytest.mark.asyncio
    async def test_write_dispatches_only_relative_path_and_content(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        dispatched: list[dict[str, Any]] = []

        def backend(change: dict[str, Any]) -> dict[str, Any]:
            dispatched.append(change)
            return {"status": "COMMITTED", "output": "committed by File Cell"}

        tools = _file_tools(tmp_path, backend)
        local_calls = _forbid_local_write(tools, monkeypatch)

        result = await tools.write(str(tmp_path / "nested" / "report.txt"), "hello")

        assert result.success is True
        assert result.output == "committed by File Cell"
        assert dispatched == [{"path": "nested/report.txt", "content": "hello"}]
        assert set(dispatched[0]) == {"path", "content"}
        assert not Path(dispatched[0]["path"]).is_absolute()
        assert local_calls == []
        assert not (tmp_path / "nested" / "report.txt").exists()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("operation", "expected"),
        (
            ("append", "before-after"),
            ("edit", "after"),
        ),
    )
    async def test_append_and_edit_dispatch_exact_result_without_local_write(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        operation: str,
        expected: str,
    ) -> None:
        target = tmp_path / f"{operation}.txt"
        target.write_text("before", encoding="utf-8")
        dispatched: list[dict[str, Any]] = []

        def backend(change: dict[str, Any]) -> dict[str, Any]:
            dispatched.append(change)
            return {"status": "COMMITTED", "output": "committed by File Cell"}

        tools = _file_tools(tmp_path, backend)
        local_calls = _forbid_local_write(tools, monkeypatch)

        if operation == "append":
            result = await tools.write(target.name, "-after", append=True)
        else:
            result = await tools.edit(target.name, "before", "after")

        assert result.success is True
        assert dispatched == [{"path": target.name, "content": expected}]
        assert local_calls == []
        assert target.read_text(encoding="utf-8") == "before"

    @pytest.mark.asyncio
    async def test_delete_fails_closed_without_calling_local_unlink(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = tmp_path / "keep.txt"
        target.write_text("keep", encoding="utf-8")
        dispatched: list[dict[str, Any]] = []
        unlink_calls: list[tuple[Any, ...]] = []

        def backend(change: dict[str, Any]) -> dict[str, Any]:
            dispatched.append(change)
            return {"status": "COMMITTED"}

        def forbidden_unlink(*args: Any, **kwargs: Any) -> None:
            unlink_calls.append((*args, kwargs))
            raise AssertionError("File Cell mode must not unlink in-process")

        tools = _file_tools(tmp_path, backend)
        monkeypatch.setattr(os, "unlink", forbidden_unlink)

        result = await tools.delete(target.name)

        assert result.success is False
        assert "File Cell" in result.error
        assert dispatched == []
        assert unlink_calls == []
        assert target.read_text(encoding="utf-8") == "keep"

    @pytest.mark.asyncio
    async def test_backend_exception_fails_closed_without_local_fallback(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def unavailable(_change: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("cells.sock unavailable")

        tools = _file_tools(tmp_path, unavailable)
        local_calls = _forbid_local_write(tools, monkeypatch)

        result = await tools.write("must-not-exist.txt", "secret")

        assert result.success is False
        assert "File Cell" in result.error
        assert local_calls == []
        assert not (tmp_path / "must-not-exist.txt").exists()

    @pytest.mark.asyncio
    async def test_path_outside_workspace_never_reaches_backend(
        self,
        tmp_path: Path,
    ) -> None:
        dispatched: list[dict[str, Any]] = []

        def backend(change: dict[str, Any]) -> dict[str, Any]:
            dispatched.append(change)
            return {"status": "COMMITTED"}

        tools = _file_tools(tmp_path, backend)
        result = await tools.write(str(tmp_path.parent / "outside.txt"), "blocked")

        assert result.success is False
        assert dispatched == []

    @pytest.mark.asyncio
    async def test_without_backend_preserves_legacy_local_write(self, tmp_path: Path) -> None:
        guard = BehaviorGuard(SecurityConfig(), tmp_path)
        tools = FileTools(tmp_path, ToolLimits(), guard)

        result = await tools.write("legacy.txt", "legacy")

        assert result.success is True
        assert (tmp_path / "legacy.txt").read_text(encoding="utf-8") == "legacy"
