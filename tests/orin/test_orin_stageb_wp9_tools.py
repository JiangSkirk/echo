"""WP9 FileTools routing into the resident File Cell."""

from __future__ import annotations

import hashlib
import os
import time
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.agent.tool_executor import ToolExecutorMixin
from js.appshell.principal import AppShellEpochBindingV1
from js.config import SecurityConfig, ToolLimits
from js.echo.capability import LeaseDenied
from js.echo.turn_context import (
    RuntimeContext,
    reset_runtime_context,
    set_runtime_context,
)
from js.orin import taint as orin_taint
from js.orin.client import OrinApprovalRequired, OrinLeaseClientAdapter
from js.orin.handles import make_handle_id
from js.orin.intent import Budgets, IntentEnvelope
from js.orin.protocol import canonical_json
from js.security.guard import BehaviorGuard
from js.tools import registry as tool_registry
from js.tools.files import FileTools
from js.tools.registry import ToolExecutionContext

_INSTALLATION_OWNER = "sha256:" + "a" * 64
_PRINCIPAL_OWNER = "principal-owner:test"
_PRODUCT_ID = "js-agent-work"
_PARENT_SESSION = "appshell-session:wp9-tools"
_APPSHELL_EPOCH = 7


def _directory_handle_id(
    *,
    task_id: str,
    profile: str,
    principal_owner: str,
    principal_session: str,
    principal_epoch: int,
    root: Path,
    product_id: str = _PRODUCT_ID,
    installation_owner: str = _INSTALLATION_OWNER,
) -> str:
    root_nfc = unicodedata.normalize("NFC", os.fspath(root.expanduser().resolve()))
    commitment = [
        "orin:appshell-dirh:v1",
        installation_owner,
        product_id,
        task_id,
        profile,
        principal_owner,
        principal_session,
        principal_epoch,
        root_nfc,
    ]
    digest = hashlib.sha256(canonical_json(commitment).encode("utf-8")).hexdigest()
    return make_handle_id("DirectoryHandle", f"appshell-{digest}")


def _file_intent(
    *,
    root: Path,
    task_id: str,
    profile: str = "work",
    principal_owner: str = _PRINCIPAL_OWNER,
    principal_session: str = _PARENT_SESSION,
    principal_epoch: int = _APPSHELL_EPOCH,
    product_id: str = _PRODUCT_ID,
    installation_owner: str = _INSTALLATION_OWNER,
    expires_at_ms: int | None = None,
) -> tuple[dict[str, Any], str]:
    now = int(time.time() * 1000)
    handle_id = _directory_handle_id(
        task_id=task_id,
        profile=profile,
        principal_owner=principal_owner,
        principal_session=principal_session,
        principal_epoch=principal_epoch,
        root=root,
        product_id=product_id,
        installation_owner=installation_owner,
    )
    intent = IntentEnvelope(
        intent_id=f"intent:{task_id.removeprefix('task:')}",
        owner_key_hash=installation_owner,
        product_id=product_id,
        profile=profile,
        task_id=task_id,
        raw_request_hash="sha256:" + "b" * 64,
        allowed_effect_classes=("file.commit",),
        allowed_resource_handles=(handle_id,),
        allowed_sink_handles=(),
        budgets=Budgets(max_invocations=20, max_bytes_out=1 << 20),
        approval_policy=(
            "preauthorized_exact_template" if profile == "work" else "exact_commit_required"
        ),
        issued_by="appshell:test",
        issued_at_ms=now - 1_000,
        expires_at_ms=expires_at_ms or now + 60_000,
        signature="test-owner-witness",
    )
    return intent.to_dict(), handle_id


def _orin_adapter(tmp_path: Path) -> OrinLeaseClientAdapter:
    return OrinLeaseClientAdapter(
        socket_path=tmp_path / "orin.sock",
        state_dir=tmp_path / "state",
        stage_b=True,
    )


def _register_file_binding(
    adapter: OrinLeaseClientAdapter,
    monkeypatch: pytest.MonkeyPatch,
    *,
    root: Path,
    task_id: str = "task:wp9-tools",
    profile: str = "work",
    principal_owner: str = _PRINCIPAL_OWNER,
    principal_session: str = _PARENT_SESSION,
    principal_epoch: int = _APPSHELL_EPOCH,
    product_id: str = _PRODUCT_ID,
    installation_owner: str = _INSTALLATION_OWNER,
    expires_at_ms: int | None = None,
) -> tuple[dict[str, Any], str]:
    intent, handle_id = _file_intent(
        root=root,
        task_id=task_id,
        profile=profile,
        principal_owner=principal_owner,
        principal_session=principal_session,
        principal_epoch=principal_epoch,
        product_id=product_id,
        installation_owner=installation_owner,
        expires_at_ms=expires_at_ms,
    )
    monkeypatch.setattr(
        adapter,
        "_call",
        lambda _factory: {"ok": True, "directory_handle_id": handle_id},
    )
    ack = adapter.register_file_binding(
        intent,
        appshell_owner=principal_owner,
        appshell_session=principal_session,
        appshell_epoch=principal_epoch,
        workspace_root=root,
    )
    assert ack["directory_handle_id"] == handle_id
    return intent, handle_id


@contextmanager
def _active_file_context(
    workspace: Path,
    *,
    principal_owner: str = _PRINCIPAL_OWNER,
    parent_session: str = _PARENT_SESSION,
    active_mode: str = "work",
    epoch: int = _APPSHELL_EPOCH,
    product_id: str = _PRODUCT_ID,
    epoch_workspace: str | None = "opaque:work-directory-handle",
    runtime_profile: str = "work-profile-projection-not-orin-profile",
    runtime_fs_roots: tuple[Path, ...] | None = None,
    tool_owner: str | None = None,
    tool_fs_roots: tuple[str, ...] | None = None,
    include_tool_context: bool = True,
) -> Iterator[None]:
    resolved_workspace = workspace.resolve()
    resolved_runtime_roots = runtime_fs_roots or (resolved_workspace,)
    binding = AppShellEpochBindingV1(
        owner=principal_owner,
        session=parent_session,
        active_mode=active_mode,  # type: ignore[arg-type]
        workspace=epoch_workspace,
        epoch=epoch,
    )
    runtime = RuntimeContext(
        product_id=product_id,
        channel="api_chat",
        owner_key_hash=principal_owner,
        session_id="echo-child-session:must-not-key-file-binding",
        run_id="work-run:must-not-be-orin-task",
        role="operator",
        profile=runtime_profile,
        capabilities=("file_write",),
        workspace=resolved_workspace,
        state_dir=workspace.parent / "state",
        fs_roots=resolved_runtime_roots,
        appshell_epoch_binding=binding,
    )
    runtime_token = set_runtime_context(runtime)
    tool_token: object | None = None
    if include_tool_context:
        tool_context = ToolExecutionContext(
            owner_key_hash=tool_owner or principal_owner,
            run_id=runtime.run_id,
            tool_name="file_write",
            args_hash="sha256:" + "c" * 64,
            fs_roots=tool_fs_roots or tuple(str(item) for item in resolved_runtime_roots),
            network_policy="deny",
            max_bytes=1 << 20,
            max_duration_ms=30_000,
            resource_scope=str(resolved_workspace),
            lease_id="lease:wp9-tools",
            lease_mac="mac:test",
            signature="sig:test",
            product_id=product_id,
            session_id=runtime.session_id,
            profile=runtime_profile,
        )
        tool_token = tool_registry._CURRENT_TOOL_EXECUTION_CONTEXT.set(tool_context)  # noqa: SLF001
    try:
        yield
    finally:
        if tool_token is not None:
            tool_registry._CURRENT_TOOL_EXECUTION_CONTEXT.reset(tool_token)  # noqa: SLF001
        reset_runtime_context(runtime_token)


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


class TestOrinFileChangeAdapter:
    def test_run_file_change_uses_principal_binding_and_runtime_workspace(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        workspace = tmp_path / "owner-root"
        workspace.mkdir()
        adapter = _orin_adapter(tmp_path)
        task_id = "task:orin-authority-not-work-run"
        intent, directory_handle = _register_file_binding(
            adapter,
            monkeypatch,
            root=workspace,
            task_id=task_id,
        )
        assert intent["subject"]["owner_key_hash"] == _INSTALLATION_OWNER
        assert _INSTALLATION_OWNER != _PRINCIPAL_OWNER

        calls: list[tuple[str, Any]] = []
        submitted: dict[str, Any] = {}
        submit_taint: dict[str, int] = {}

        def submit(draft: dict[str, Any], **taint: int) -> dict[str, Any]:
            calls.append(("submit", draft["draft_id"]))
            submitted.update(draft)
            submit_taint.update(taint)
            return {
                "ok": True,
                "verdict": "deny_missing_witness",
                "missing": ["state_witness"],
            }

        def preflight(draft_id: str, executor_id: str | None = None) -> dict[str, Any]:
            calls.append(("preflight", (draft_id, executor_id)))
            return {"ok": True, "witness": {"witness_id": "state:test"}}

        def consume(draft_id: str) -> dict[str, Any]:
            calls.append(("consume", draft_id))
            return {
                "status": "COMMITTED",
                "remote_operation_id": "operation:file-test",
                "duplicate": False,
                "files": ["nested/report.txt"],
                "bytes_written": 1_700,
                "diff_hash": "sha256:" + "d" * 64,
                "overwrites": [],
                "commit_guarantee": "best_effort",
                "permit": {"secret": "must-not-return"},
                "package": {"draft": "must-not-return"},
                "token": "must-not-return",
                "content": "must-not-return",
                "root": str(workspace),
                "witness": {"witness_id": "must-not-return"},
                "license": "must-not-return",
            }

        monkeypatch.setattr(adapter, "submit_draft", submit)
        monkeypatch.setattr(adapter, "preflight_draft", preflight)
        monkeypatch.setattr(adapter, "consume_draft", consume)
        change = {
            "path": "nested/report.txt",
            "content": "untrusted exact file payload " * 64,
        }
        snapshot = orin_taint.ToolTaintSnapshot(
            context_taint=orin_taint.WEB_CONTENT,
            clearance=orin_taint.CLEARANCE_PUBLIC,
            dirty_samples=(canonical_json(change),),
        )
        taint_token = orin_taint.set_tool_taint_snapshot(snapshot)
        try:
            # The epoch workspace is deliberately opaque and the Work projection
            # profile is deliberately not the Orin profile.  The real root is the
            # RuntimeContext.workspace Path and the cache key is the parent principal.
            with _active_file_context(workspace):
                result = adapter.run_file_change(change)
        finally:
            orin_taint.reset_tool_taint_snapshot(taint_token)
            adapter.close()

        draft_id = submitted["draft_id"]
        assert isinstance(draft_id, str) and draft_id.startswith("draft:")
        assert calls == [
            ("submit", draft_id),
            ("preflight", (draft_id, "cell.file")),
            ("consume", draft_id),
        ]
        assert submitted["task_id"] == task_id
        assert submitted["effect_type"] == "file.commit"
        assert submitted["arguments"] == {
            "directory_handle": directory_handle,
            "changes": [change],
        }
        assert set(submitted["arguments"]) == {"directory_handle", "changes"}
        assert submitted["declared_expectation"] == {
            "external_visibility": "private",
            "reversibility": "reversible_until_stage",
        }
        assert submit_taint == {
            "context_taint": orin_taint.WEB_CONTENT,
            "arg_taint": orin_taint.TOOL_RESULT,
            "clearance": 0,
        }
        assert result == {
            "status": "COMMITTED",
            "remote_operation_id": "operation:file-test",
            "duplicate": False,
            "files": ["nested/report.txt"],
            "bytes_written": 1_700,
            "diff_hash": "sha256:" + "d" * 64,
            "overwrites": [],
            "commit_guarantee": "best_effort",
        }
        assert not {
            "permit",
            "package",
            "token",
            "content",
            "root",
            "witness",
            "license",
        } & set(result)

    def test_binding_cache_partitions_same_orin_owner_by_parent_principal(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        workspace = tmp_path / "shared-root"
        workspace.mkdir()
        adapter = _orin_adapter(tmp_path)
        bindings = (
            ("principal-owner:a", "appshell-session:a", 3, "task:principal-a"),
            ("principal-owner:b", "appshell-session:b", 4, "task:principal-b"),
        )
        expected_handles: dict[str, str] = {}
        for owner, session, epoch, task_id in bindings:
            _intent, handle_id = _register_file_binding(
                adapter,
                monkeypatch,
                root=workspace,
                task_id=task_id,
                principal_owner=owner,
                principal_session=session,
                principal_epoch=epoch,
            )
            expected_handles[task_id] = handle_id

        observed: list[tuple[str, str]] = []

        def submit(draft: dict[str, Any], **_taint: int) -> dict[str, Any]:
            observed.append(
                (draft["task_id"], draft["arguments"]["directory_handle"]),
            )
            return {
                "ok": True,
                "verdict": "deny_missing_witness",
                "missing": ["state_witness"],
            }

        monkeypatch.setattr(adapter, "submit_draft", submit)
        monkeypatch.setattr(adapter, "preflight_draft", lambda *_args, **_kwargs: {"ok": True})
        monkeypatch.setattr(
            adapter,
            "consume_draft",
            lambda _draft_id: {"status": "COMMITTED"},
        )
        try:
            for owner, session, epoch, _task_id in bindings:
                with _active_file_context(
                    workspace,
                    principal_owner=owner,
                    parent_session=session,
                    epoch=epoch,
                ):
                    adapter.run_file_change({"path": "report.txt", "content": owner})
        finally:
            adapter.close()

        assert observed == [
            (task_id, expected_handles[task_id])
            for _owner, _session, _epoch, task_id in bindings
        ]

    @pytest.mark.parametrize(
        "change",
        (
            {"path": "report.txt"},
            {"content": "text"},
            {"path": "report.txt", "content": "text", "task_id": "task:forged"},
            {"path": "report.txt", "content": "text", "directory_handle": "dirh:forged"},
            {"path": 7, "content": "text"},
            {"path": "report.txt", "content": b"bytes"},
            ["report.txt", "text"],
        ),
    )
    def test_run_file_change_rejects_non_exact_change_shape_before_submit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        change: Any,
    ) -> None:
        workspace = tmp_path / "shape-root"
        workspace.mkdir()
        adapter = _orin_adapter(tmp_path)
        _register_file_binding(adapter, monkeypatch, root=workspace)
        submit_calls: list[dict[str, Any]] = []
        monkeypatch.setattr(
            adapter,
            "submit_draft",
            lambda draft, **_taint: submit_calls.append(draft),
        )
        try:
            with _active_file_context(workspace), pytest.raises(ValueError):
                adapter.run_file_change(change)
        finally:
            adapter.close()
        assert submit_calls == []

    @pytest.mark.parametrize(
        "path",
        (
            "/absolute.txt",
            "../escape.txt",
            "nested\\windows.txt",
            "nested//empty.txt",
            "nested/./dot.txt",
            "Cafe\u0301/report.txt",
            "nested/\x00control.txt",
            ".git/config",
            f"{'a' * 256}/report.txt",
        ),
    )
    def test_run_file_change_rejects_non_portable_or_non_nfc_path_before_submit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        path: str,
    ) -> None:
        workspace = tmp_path / "path-root"
        workspace.mkdir()
        adapter = _orin_adapter(tmp_path)
        _register_file_binding(adapter, monkeypatch, root=workspace)
        submit_calls: list[dict[str, Any]] = []
        monkeypatch.setattr(
            adapter,
            "submit_draft",
            lambda draft, **_taint: submit_calls.append(draft),
        )
        try:
            with _active_file_context(workspace), pytest.raises(ValueError):
                adapter.run_file_change({"path": path, "content": "text"})
        finally:
            adapter.close()
        assert submit_calls == []

    def test_missing_binding_fails_before_submit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        workspace = tmp_path / "unbound-root"
        workspace.mkdir()
        adapter = _orin_adapter(tmp_path)
        submit_calls: list[dict[str, Any]] = []
        monkeypatch.setattr(
            adapter,
            "submit_draft",
            lambda draft, **_taint: submit_calls.append(draft),
        )
        try:
            with _active_file_context(workspace), pytest.raises(LeaseDenied, match="binding"):
                adapter.run_file_change({"path": "report.txt", "content": "text"})
        finally:
            adapter.close()
        assert submit_calls == []

    @pytest.mark.parametrize(
        ("context_overrides", "tool_overrides"),
        (
            ({"principal_owner": "principal-owner:other"}, {}),
            ({"parent_session": "appshell-session:other"}, {}),
            ({"active_mode": "personal"}, {}),
            ({"epoch": _APPSHELL_EPOCH + 1}, {}),
            ({"product_id": "js-agent-other"}, {}),
            ({}, {"tool_owner": "principal-owner:other"}),
        ),
    )
    def test_identity_binding_mismatch_fails_before_submit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        context_overrides: dict[str, Any],
        tool_overrides: dict[str, Any],
    ) -> None:
        workspace = tmp_path / "identity-root"
        workspace.mkdir()
        adapter = _orin_adapter(tmp_path)
        _register_file_binding(adapter, monkeypatch, root=workspace)
        submit_calls: list[dict[str, Any]] = []
        monkeypatch.setattr(
            adapter,
            "submit_draft",
            lambda draft, **_taint: submit_calls.append(draft),
        )
        try:
            with _active_file_context(
                workspace,
                **context_overrides,
                **tool_overrides,
            ), pytest.raises(LeaseDenied):
                adapter.run_file_change({"path": "report.txt", "content": "text"})
        finally:
            adapter.close()
        assert submit_calls == []

    def test_runtime_workspace_not_epoch_workspace_is_the_authoritative_root(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        bound_root = tmp_path / "bound-root"
        wrong_runtime_root = tmp_path / "wrong-runtime-root"
        bound_root.mkdir()
        wrong_runtime_root.mkdir()
        adapter = _orin_adapter(tmp_path)
        _register_file_binding(adapter, monkeypatch, root=bound_root)
        submit_calls: list[dict[str, Any]] = []
        monkeypatch.setattr(
            adapter,
            "submit_draft",
            lambda draft, **_taint: submit_calls.append(draft),
        )
        try:
            # The opaque epoch workspace remains identical to the successful
            # product binding, but the live RuntimeContext.workspace changed.
            with _active_file_context(wrong_runtime_root), pytest.raises(LeaseDenied):
                adapter.run_file_change({"path": "report.txt", "content": "text"})
        finally:
            adapter.close()
        assert submit_calls == []

    @pytest.mark.parametrize("missing_context", ["runtime", "tool"])
    def test_verified_runtime_and_tool_context_are_both_required(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        missing_context: str,
    ) -> None:
        workspace = tmp_path / "context-root"
        workspace.mkdir()
        adapter = _orin_adapter(tmp_path)
        _register_file_binding(adapter, monkeypatch, root=workspace)
        submit_calls: list[dict[str, Any]] = []
        monkeypatch.setattr(
            adapter,
            "submit_draft",
            lambda draft, **_taint: submit_calls.append(draft),
        )
        try:
            if missing_context == "runtime":
                with pytest.raises(LeaseDenied):
                    adapter.run_file_change({"path": "report.txt", "content": "text"})
            else:
                with _active_file_context(
                    workspace,
                    include_tool_context=False,
                ), pytest.raises(LeaseDenied):
                    adapter.run_file_change({"path": "report.txt", "content": "text"})
        finally:
            adapter.close()
        assert submit_calls == []

    def test_tool_filesystem_roots_must_cover_the_exact_target(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        workspace = tmp_path / "tool-root"
        other = workspace / "other"
        workspace.mkdir()
        other.mkdir()
        adapter = _orin_adapter(tmp_path)
        _register_file_binding(adapter, monkeypatch, root=workspace)
        submit_calls: list[dict[str, Any]] = []
        monkeypatch.setattr(
            adapter,
            "submit_draft",
            lambda draft, **_taint: submit_calls.append(draft),
        )
        try:
            with _active_file_context(
                workspace,
                tool_fs_roots=(str(other),),
            ), pytest.raises(LeaseDenied):
                adapter.run_file_change({"path": "report.txt", "content": "text"})
        finally:
            adapter.close()
        assert submit_calls == []

    def test_expired_binding_fails_before_submit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        workspace = tmp_path / "expired-root"
        workspace.mkdir()
        adapter = _orin_adapter(tmp_path)
        expires_at_ms = int(time.time() * 1000) + 60_000
        _register_file_binding(
            adapter,
            monkeypatch,
            root=workspace,
            expires_at_ms=expires_at_ms,
        )
        monkeypatch.setattr(adapter, "_now", lambda: expires_at_ms)
        submit_calls: list[dict[str, Any]] = []
        monkeypatch.setattr(
            adapter,
            "submit_draft",
            lambda draft, **_taint: submit_calls.append(draft),
        )
        try:
            with _active_file_context(workspace), pytest.raises(LeaseDenied):
                adapter.run_file_change({"path": "report.txt", "content": "text"})
        finally:
            adapter.close()
        assert submit_calls == []

    @pytest.mark.parametrize(
        "proposed",
        (
            {"ok": True, "verdict": "deny_policy", "missing": []},
            {
                "ok": True,
                "verdict": "deny_missing_witness",
                "missing": ["state_witness", "approval"],
            },
            {"ok": True, "verdict": "require_approval", "missing": ["approval"]},
        ),
    )
    def test_submit_must_be_soft_denied_only_for_the_missing_witness(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        proposed: dict[str, Any],
    ) -> None:
        workspace = tmp_path / "verdict-root"
        workspace.mkdir()
        adapter = _orin_adapter(tmp_path)
        _register_file_binding(adapter, monkeypatch, root=workspace)
        preflight_calls: list[str] = []
        monkeypatch.setattr(adapter, "submit_draft", lambda *_args, **_kwargs: proposed)
        monkeypatch.setattr(
            adapter,
            "preflight_draft",
            lambda draft_id, **_kwargs: preflight_calls.append(draft_id),
        )
        try:
            with _active_file_context(workspace), pytest.raises(LeaseDenied):
                adapter.run_file_change({"path": "report.txt", "content": "text"})
        finally:
            adapter.close()
        assert preflight_calls == []

    def test_personal_exact_approval_stops_after_real_preflight_without_consuming(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        workspace = tmp_path / "personal-root"
        workspace.mkdir()
        adapter = _orin_adapter(tmp_path)
        _register_file_binding(
            adapter,
            monkeypatch,
            root=workspace,
            task_id="task:personal-exact",
            profile="personal",
            product_id="js-agent-personal",
        )
        calls: list[str] = []
        submitted: dict[str, Any] = {}
        preflight_count = 0

        def submit(draft_data: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
            from js.orin.draft import draft_from_dict
            from js.orind.kernel import canonical_effect_hash_of

            calls.append("submit")
            draft = draft_from_dict(draft_data)
            effect_hash = canonical_effect_hash_of(draft)
            submitted.update({"draft": draft, "effect_hash": effect_hash})
            return {
                "ok": True,
                "verdict": "deny_missing_witness",
                "missing": ["state_witness"],
                "payload_hash": effect_hash,
            }

        def preflight(draft_id: str, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
            from js.orin.draft import FileCommitPreviewV1, Impact, StateWitness

            nonlocal preflight_count
            preflight_count += 1
            calls.append("preflight")
            now = int(time.time() * 1000)
            witness = StateWitness(
                witness_id=f"state:personal-{preflight_count}",
                draft_id=draft_id,
                executor_id="cell.file",
                target_version="file-stage:test",
                canonical_effect_hash=str(submitted["effect_hash"]),
                impact=Impact(writes=1),
                reversibility="reversible_until_stage",
                idempotency_support="client_key",
                created_at_ms=now - 1,
                expires_at_ms=now + 60_000,
                file_commit_preview=FileCommitPreviewV1(
                    file_count=1,
                    bytes=4,
                    overwrites=(),
                    diff_hash="sha256:" + str(preflight_count) * 64,
                ),
            )
            return {"ok": True, "witness": witness.to_dict()}

        def consume(_draft_id: str) -> dict[str, Any]:
            calls.append("consume")
            pytest.fail("Personal file.commit must stop before consume until owner approval")

        monkeypatch.setattr(adapter, "submit_draft", submit)
        monkeypatch.setattr(adapter, "preflight_draft", preflight)
        monkeypatch.setattr(adapter, "consume_draft", consume)
        try:
            with _active_file_context(
                workspace,
                active_mode="personal",
                product_id="js-agent-personal",
                epoch_workspace=None,
                runtime_profile="personal-projection-not-orin-profile",
            ), pytest.raises(OrinApprovalRequired) as caught:
                adapter.run_file_change({"path": "report.txt", "content": "text"})
            first_pending = adapter.pending_file_approvals(
                appshell_owner=_PRINCIPAL_OWNER,
                appshell_session=_PARENT_SESSION,
                appshell_epoch=_APPSHELL_EPOCH,
                active_mode="personal",
                product_id="js-agent-personal",
                workspace_root=workspace,
            )
            with _active_file_context(
                workspace,
                active_mode="personal",
                product_id="js-agent-personal",
                epoch_workspace=None,
                runtime_profile="personal-projection-not-orin-profile",
            ), pytest.raises(OrinApprovalRequired) as duplicate:
                adapter.run_file_change({"path": "second.txt", "content": "more"})
            still_pending = adapter.pending_file_approvals(
                appshell_owner=_PRINCIPAL_OWNER,
                appshell_session=_PARENT_SESSION,
                appshell_epoch=_APPSHELL_EPOCH,
                active_mode="personal",
                product_id="js-agent-personal",
                workspace_root=workspace,
            )
        finally:
            adapter.close()

        visible = str(caught.value)
        assert "draft:" not in visible
        assert "state:personal-1" not in visible
        assert "witness" not in visible.lower()
        duplicate_visible = str(duplicate.value)
        assert "draft:" not in duplicate_visible
        assert "state:" not in duplicate_visible
        assert first_pending == still_pending
        assert first_pending[0]["witness_id"] == "state:personal-1"
        assert calls == ["submit", "preflight"]


class TestFileToolsCellBoundary:
    @pytest.mark.asyncio
    async def test_personal_pending_approval_never_leaks_authority_or_falls_back(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        secret_draft = "draft:must-never-reach-echo"
        secret_witness = "state:must-never-reach-echo"
        secret_root = str(tmp_path.resolve())

        def pending(_change: dict[str, Any]) -> dict[str, Any]:
            raise OrinApprovalRequired(
                f"pending {secret_draft} {secret_witness} root={secret_root}"
            )

        tools = _file_tools(tmp_path, pending)
        local_calls = _forbid_local_write(tools, monkeypatch)

        result = await tools.write("pending.txt", "owner must confirm")

        assert result.success is False
        assert result.error == "File Cell safety boundary unavailable"
        visible = repr(result)
        for secret in (secret_draft, secret_witness, secret_root, "owner must confirm"):
            assert secret not in visible
        assert local_calls == []
        assert not (tmp_path / "pending.txt").exists()

    @pytest.mark.asyncio
    async def test_enabled_product_backend_without_binding_never_falls_back_locally(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        adapter = _orin_adapter(tmp_path)
        executor = _executor(enabled=True, stage_b=True, cell_file=True)
        monkeypatch.setattr(
            executor,
            "_get_echo_tool_lease_authority",
            lambda: adapter,
        )
        backend = executor._file_cell_backend()  # type: ignore[attr-defined]
        assert callable(backend)
        tools = _file_tools(tmp_path, backend)
        local_calls = _forbid_local_write(tools, monkeypatch)

        try:
            result = await tools.write("must-stay-absent.txt", "secret")
        finally:
            adapter.close()

        assert result.success is False
        assert result.error == "File Cell safety boundary unavailable"
        assert local_calls == []
        assert not (tmp_path / "must-stay-absent.txt").exists()

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
