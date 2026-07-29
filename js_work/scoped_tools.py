"""Explicit owner-path policies for Work's shared file and office tools."""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import Any, Literal

from js.config import ToolLimits
from js.tools.registry import ToolRegistry, ToolResult
from js_work.file_scope import (
    WorkFileScopeError,
    WorkFileSnapshot,
    WorkOwnerFileScope,
    current_work_identity,
)

PathMode = Literal["private", "input", "output"]
_PATH_POLICIES: dict[str, dict[str, PathMode]] = {
    "file_read": {"path": "input"},
    "file_view": {"path": "input"},
    "file_list": {"path": "private"},
    "file_search": {"path": "private"},
    "code_search": {"path": "private"},
    "file_write": {"path": "output"},
    "file_edit": {"path": "output"},
    "file_delete": {"path": "output"},
    "csv_read": {"path": "input"},
    "csv_write": {"path": "output"},
    "excel_read": {"path": "input"},
    "excel_write": {"path": "output"},
    "excel_merge": {
        "source_path": "input",
        "target_path": "input",
        "output_path": "output",
    },
    "excel_create": {"path": "output"},
    "pdf_generate": {"path": "output"},
}
_DEFAULT_PATHS: dict[tuple[str, str], str] = {
    ("file_list", "path"): ".",
    ("file_search", "path"): ".",
    ("code_search", "path"): ".",
}
_SNAPSHOT_OFFICE_INPUTS = {
    "csv_read": frozenset({"path"}),
    "excel_read": frozenset({"path"}),
    "excel_merge": frozenset({"source_path", "target_path"}),
}


class WorkOfficeInput(str):
    """Lease-compatible path string carrying immutable Work-approved bytes."""

    _snapshot: WorkFileSnapshot

    def __new__(cls, value: str, snapshot: WorkFileSnapshot) -> WorkOfficeInput:
        if not isinstance(snapshot, WorkFileSnapshot):
            raise TypeError("Work Office input requires a file snapshot")
        instance = super().__new__(cls, value)
        object.__setattr__(instance, "_snapshot", snapshot)
        return instance

    def __setattr__(self, name: str, value: Any) -> None:
        del name, value
        raise AttributeError("Work Office input snapshots are immutable")

    def _work_office_snapshot(self) -> WorkFileSnapshot:
        return self._snapshot

    def _registry_argument_policy_binding(self) -> str:
        snapshot = self._snapshot
        snapshot.verified_data()
        return ":".join(
            (
                "work-office-input-v1",
                snapshot.relative_path,
                str(snapshot.size),
                snapshot.sha256,
            )
        )

    def __reduce_ex__(self, protocol: Any) -> tuple[type[WorkOfficeInput], tuple[str, Any]]:
        del protocol
        return type(self), (str(self), self._snapshot)


def install_work_file_scope(
    registry: ToolRegistry,
    *,
    workspace: Path,
    limits: ToolLimits,
) -> None:
    """Wrap every shared path-taking Work tool with an explicit owner policy."""
    for tool_name, parameter_modes in _PATH_POLICIES.items():
        registry.register_argument_policy(
            tool_name,
            partial(
                _scoped_arguments,
                tool_name=tool_name,
                parameter_modes=parameter_modes,
                workspace=workspace,
                limits=limits,
            ),
            path_defaults={
                parameter: default
                for (default_tool, parameter), default in _DEFAULT_PATHS.items()
                if default_tool == tool_name
            },
        )
        registry.register_result_policy(
            tool_name,
            partial(_scoped_result, workspace=workspace),
        )


def _scoped_arguments(
    arguments: dict[str, Any],
    *,
    tool_name: str,
    parameter_modes: dict[str, PathMode],
    workspace: Path,
    limits: ToolLimits,
) -> dict[str, Any] | ToolResult:
    transformed = dict(arguments)
    try:
        owner, session_id = current_work_identity()
        scope = WorkOwnerFileScope(
            workspace,
            owner=owner,
            session_id=session_id,
        )
        for parameter, mode in parameter_modes.items():
            value = transformed.get(
                parameter,
                _DEFAULT_PATHS.get((tool_name, parameter)),
            )
            if value is None:
                continue
            if not isinstance(value, str):
                raise WorkFileScopeError(400, f"Invalid {parameter}")
            snapshot = None
            if mode == "private":
                resolved = scope.resolve_private_read(value)
            elif mode == "input":
                if parameter in _SNAPSHOT_OFFICE_INPUTS.get(tool_name, ()):
                    snapshot = scope.read_routine_input(
                        value,
                        max_bytes=_office_input_max_bytes(tool_name, limits),
                    )
                    resolved = scope.workspace / snapshot.relative_path
                else:
                    snapshot = None
                    resolved = scope.resolve_routine_input(value)
            else:
                resolved = scope.resolve_output(value)
            registry_path = resolved.relative_to(scope.workspace).as_posix()
            transformed[parameter] = (
                WorkOfficeInput(registry_path, snapshot)
                if snapshot is not None
                else registry_path
            )
    except WorkFileScopeError as exc:
        return ToolResult(success=False, error=exc.detail)
    return transformed


def _office_input_max_bytes(tool_name: str, limits: ToolLimits) -> int:
    if tool_name == "csv_read":
        return limits.csv_read_max_bytes
    from js_work.routines.precise_edit import MAX_COMPRESSED_BYTES

    return MAX_COMPRESSED_BYTES


_RESULT_PATH_KEYS = {
    "destination",
    "output_path",
    "path",
    "report_path",
    "source_path",
    "target_path",
    "validation_path",
}


def _scoped_result(result: ToolResult, *, workspace: Path) -> ToolResult:
    """Return only owner-root handles and reject unexpected workspace disclosures."""
    owner, session_id = current_work_identity()
    scope = WorkOwnerFileScope(workspace, owner=owner, session_id=session_id)
    return ToolResult(
        success=result.success,
        output=_sanitize_result_text(result.output, scope),
        error=_sanitize_result_text(result.error, scope),
        metadata=_sanitize_result_value(result.metadata, scope),
    )


def _sanitize_result_value(value: Any, scope: WorkOwnerFileScope, *, key: str = "") -> Any:
    if isinstance(value, dict):
        return {
            item_key: _sanitize_result_value(item, scope, key=str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_result_value(item, scope) for item in value]
    if key in _RESULT_PATH_KEYS and isinstance(value, str):
        return scope.to_public_handle(value)
    if isinstance(value, str):
        return _sanitize_result_text(value, scope)
    return value


def _sanitize_result_text(value: str, scope: WorkOwnerFileScope) -> str:
    if not value:
        return value
    private_absolute = scope.private_root.as_posix()
    private_relative = scope.private_root.relative_to(scope.workspace).as_posix()
    upload_absolute = scope.owned_upload_root.as_posix()
    upload_relative = scope.owned_upload_root.relative_to(scope.workspace).as_posix()
    sanitized = value.replace(f"{private_absolute}/", "")
    sanitized = sanitized.replace(private_absolute, ".")
    sanitized = sanitized.replace(f"{private_relative}/", "")
    sanitized = sanitized.replace(private_relative, ".")
    sanitized = sanitized.replace(f"{upload_absolute}/", f"{upload_relative}/")
    sanitized = sanitized.replace(upload_absolute, upload_relative)
    if scope.workspace.as_posix() in sanitized:
        raise WorkFileScopeError(500, "Work tool result exposed an unauthorized path")
    return sanitized
