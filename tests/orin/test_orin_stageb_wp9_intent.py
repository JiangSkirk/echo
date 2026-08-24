"""WP9 AppShell owner-intent resource-handle boundary tests."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import unicodedata
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import HTTPException
from pydantic import ValidationError

from js.appshell.principal import AppShellOperationLimitError, AppShellPrincipalV1
from js.appshell.routers import (
    FileCommitApproveRequest,
    IntentIssueRequest,
    approve_pending_file_commit,
    get_pending_file_commits,
    issue_owner_intent,
)
from js.appshell.routing import AppShellEpochClosedError
from js.echo.capability import LeaseDenied
from js.orin.intent import intent_from_dict
from js.orin.witness import build_intent_from_template


class _RecordingAdapter:
    _stage_b = True

    def __init__(self) -> None:
        self.registered: list[dict[str, Any]] = []
        self.file_bindings: list[tuple[dict[str, Any], dict[str, Any]]] = []
        self.pending_calls: list[dict[str, Any]] = []
        self.approval_calls: list[dict[str, Any]] = []

    def register_intent(self, intent: dict[str, Any]) -> dict[str, Any]:
        self.registered.append(intent)
        return {"ok": True}

    def register_file_binding(
        self,
        intent: dict[str, Any],
        **binding: Any,
    ) -> dict[str, Any]:
        self.file_bindings.append((intent, binding))
        return {"ok": True}

    def pending_file_approvals(self, **binding: Any) -> list[dict[str, Any]]:
        self.pending_calls.append(binding)
        return [
            {
                "file_count": 1,
                "bytes": 12,
                "overwrites": ["report.txt"],
                "diff_hash": "sha256:" + "a" * 64,
                "witness_id": "state:appshell-safe-preview",
                "draft_id": "draft:must-be-filtered",
                "workspace_root": "/must/not/escape",
            }
        ]

    def approve_pending_file_change(self, **approval: Any) -> dict[str, Any]:
        self.approval_calls.append(approval)
        return {
            "status": "COMMITTED",
            "files": 1,
            "draft_id": "draft:must-be-filtered",
            "permit": "permit:must-be-filtered",
        }


class _ImmediateModeGate:
    def __init__(self, admit_error: BaseException | None = None) -> None:
        self.admit_error = admit_error
        self.admits = 0
        self.releases = 0
        self.operation_kinds: list[str] = []

    async def admit(self, _principal: Any, *, operation_kind: str) -> object:
        assert operation_kind in {
            "appshell_orin_intent",
            "appshell_orin_file_commit_pending",
            "appshell_orin_file_commit_approve",
        }
        self.operation_kinds.append(operation_kind)
        self.admits += 1
        if self.admit_error is not None:
            raise self.admit_error
        return object()

    async def release(self, _admission: object) -> None:
        self.releases += 1


def _route_context(
    tmp_path: Path,
    adapter: _RecordingAdapter,
    *,
    mode: str = "personal",
) -> tuple[Any, AppShellPrincipalV1, Path]:
    workspace = tmp_path / f"{mode}-runtime-workspace"
    workspace.mkdir(exist_ok=True)
    agent = SimpleNamespace(_get_echo_tool_lease_authority=lambda: adapter)
    runtime = SimpleNamespace(
        agent=agent,
        settings=SimpleNamespace(
            state_dir=tmp_path,
            workspace=workspace,
            product_id="js-work" if mode == "work" else "js-agent",
        ),
    )
    child = SimpleNamespace(state=SimpleNamespace(web_runtime=runtime))
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                personal_app=child,
                work_app=child,
                work_workspace_handle="workspace:opaque-work-selection",
                appshell_mode_gate=_ImmediateModeGate(),
            ),
        ),
    )
    principal = AppShellPrincipalV1(
        owner="sha256:" + "1" * 64,
        session="session:wp9-intent",
        active_mode=mode,  # type: ignore[arg-type]
        mode_roles={mode: "admin"},
        workspace=("workspace:opaque-work-selection" if mode == "work" else None),
        expires_at=4_000_000_000.0,
        epoch=17,
    )
    return request, principal, workspace


def _install_witness(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[ed25519.Ed25519PrivateKey, str]:
    from js.orin import witness

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
    ).decode("ascii")
    monkeypatch.setattr(
        witness,
        "ensure_witness_keypair",
        lambda _state_dir: (private_key, public_key),
    )
    monkeypatch.setattr("js.appshell.routers.check_origin", lambda _request: None)
    return private_key, public_key


def _public_key(private_key: ed25519.Ed25519PrivateKey) -> str:
    return base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
    ).decode("ascii")


def _assert_no_authority_material(value: Any) -> None:
    forbidden = {
        "approval_id",
        "draft_id",
        "workspace_root",
        "object_digest",
        "handle",
        "package",
        "permit",
        "license",
        "token",
        "witness",
        "signature",
    }
    if isinstance(value, dict):
        assert forbidden.isdisjoint(value)
        for item in value.values():
            _assert_no_authority_material(item)
    elif isinstance(value, list):
        for item in value:
            _assert_no_authority_material(item)


@pytest.mark.asyncio
async def test_intent_route_balances_mode_gate_on_success_and_orind_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _RecordingAdapter()
    request, principal, _workspace = _route_context(tmp_path, adapter)
    _install_witness(monkeypatch)
    gate = request.app.state.appshell_mode_gate

    await issue_owner_intent(
        request,
        IntentIssueRequest(raw_request="bind one exact task", template="personal"),
        principal,
    )
    assert (gate.admits, gate.releases) == (1, 1)

    def reject_binding(_intent: dict[str, Any], **_binding: Any) -> dict[str, Any]:
        raise LeaseDenied("orind refused the binding")

    adapter.register_file_binding = reject_binding  # type: ignore[method-assign]
    with pytest.raises(HTTPException) as caught:
        await issue_owner_intent(
            request,
            IntentIssueRequest(raw_request="reject one exact task", template="personal"),
            principal,
        )
    assert caught.value.status_code == 502
    assert (gate.admits, gate.releases) == (2, 2)


@pytest.mark.asyncio
async def test_intent_route_requires_live_mode_gate_before_touching_orind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _RecordingAdapter()
    request, principal, _workspace = _route_context(tmp_path, adapter)
    _install_witness(monkeypatch)
    del request.app.state.appshell_mode_gate

    with pytest.raises(HTTPException) as caught:
        await issue_owner_intent(
            request,
            IntentIssueRequest(raw_request="missing parent gate", template="personal"),
            principal,
        )
    assert caught.value.status_code == 503
    assert adapter.registered == []
    assert adapter.file_bindings == []


def test_file_commit_approval_request_rejects_fake_booleans_and_authority_overrides() -> None:
    valid = {
        "approved": True,
        "witness_id": "state:appshell-safe-preview",
        "diff_hash": "sha256:" + "a" * 64,
    }
    assert FileCommitApproveRequest.model_validate(valid).approved is True
    for invalid in (
        {**valid, "approved": 1},
        {**valid, "approved": "true"},
        {**valid, "approved": False},
        {**valid, "task_id": "task:model-selected"},
        {**valid, "draft_id": "draft:model-selected"},
        {**valid, "directory_handle_id": "dirh:model-selected"},
        {**valid, "workspace_root": "/tmp/model-selected"},
        {**valid, "canonical_effect_hash": "sha256:" + "b" * 64},
    ):
        with pytest.raises(ValidationError):
            FileCommitApproveRequest.model_validate(invalid)


@pytest.mark.asyncio
async def test_personal_pending_and_approval_routes_project_only_safe_machine_facts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _RecordingAdapter()
    request, principal, workspace = _route_context(tmp_path, adapter, mode="personal")
    private_key, _public_key = _install_witness(monkeypatch)

    pending_response = await get_pending_file_commits(request, principal)
    assert pending_response.headers["cache-control"] == "no-store"
    pending = json.loads(pending_response.body)
    assert pending == {
        "schema": "AppShellFileCommitPendingV1",
        "pending": [
            {
                "file_count": 1,
                "bytes": 12,
                "overwrites": ["report.txt"],
                "diff_hash": "sha256:" + "a" * 64,
                "witness_id": "state:appshell-safe-preview",
            }
        ],
    }
    _assert_no_authority_material(pending)

    approved_response = await approve_pending_file_commit(
        request,
        FileCommitApproveRequest(
            approved=True,
            witness_id="state:appshell-safe-preview",
            diff_hash="sha256:" + "a" * 64,
        ),
        principal,
    )
    assert approved_response.headers["cache-control"] == "no-store"
    approved = json.loads(approved_response.body)
    assert approved == {
        "schema": "AppShellFileCommitApprovalAckV1",
        "ok": True,
        "status": "COMMITTED",
    }
    _assert_no_authority_material(approved)
    assert len(adapter.approval_calls) == 1
    call = adapter.approval_calls[0]
    assert call["private_key"] is private_key
    assert call["workspace_root"] == workspace
    assert call["appshell_owner"] == principal.owner
    assert call["appshell_session"] == principal.session
    assert call["appshell_epoch"] == principal.epoch
    assert call["active_mode"] == "personal"
    assert set(call) == {
        "witness_id",
        "diff_hash",
        "ttl_ms",
        "private_key",
        "appshell_owner",
        "appshell_session",
        "appshell_epoch",
        "active_mode",
        "product_id",
        "workspace_root",
    }
    gate = request.app.state.appshell_mode_gate
    assert gate.operation_kinds[-2:] == [
        "appshell_orin_file_commit_pending",
        "appshell_orin_file_commit_approve",
    ]
    assert (gate.admits, gate.releases) == (2, 2)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overwrites",
    (
        ["../escape.txt"],
        ["absolute\\path.txt"],
        [".git/config"],
        ["e\u0301.txt"],
        ["A.txt", "a.txt"],
    ),
)
async def test_pending_route_rejects_unsafe_file_preview_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overwrites: list[str],
) -> None:
    adapter = _RecordingAdapter()
    request, principal, _workspace = _route_context(tmp_path, adapter, mode="personal")
    _install_witness(monkeypatch)
    adapter.pending_file_approvals = lambda **_binding: [  # type: ignore[method-assign]
        {
            "file_count": len(overwrites),
            "bytes": 12,
            "overwrites": overwrites,
            "diff_hash": "sha256:" + "a" * 64,
            "witness_id": "state:unsafe-preview",
        }
    ]

    with pytest.raises(HTTPException) as caught:
        await get_pending_file_commits(request, principal)

    assert caught.value.status_code == 502
    gate = request.app.state.appshell_mode_gate
    assert (gate.admits, gate.releases) == (1, 1)


@pytest.mark.asyncio
async def test_work_cannot_enter_personal_exact_approval_routes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _RecordingAdapter()
    request, principal, _workspace = _route_context(tmp_path, adapter, mode="work")
    _install_witness(monkeypatch)

    with pytest.raises(HTTPException) as pending_error:
        await get_pending_file_commits(request, principal)
    with pytest.raises(HTTPException) as approval_error:
        await approve_pending_file_commit(
            request,
            FileCommitApproveRequest(
                approved=True,
                witness_id="state:appshell-safe-preview",
                diff_hash="sha256:" + "a" * 64,
            ),
            principal,
        )
    assert pending_error.value.status_code == 403
    assert approval_error.value.status_code == 403
    assert adapter.pending_calls == []
    assert adapter.approval_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("gate_error", "status_code"),
    [
        (AppShellEpochClosedError("closed"), 409),
        (AppShellOperationLimitError("full"), 429),
    ],
)
async def test_intent_route_rejects_closed_or_saturated_epoch_before_orind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    gate_error: BaseException,
    status_code: int,
) -> None:
    adapter = _RecordingAdapter()
    request, principal, _workspace = _route_context(tmp_path, adapter)
    _install_witness(monkeypatch)
    gate = _ImmediateModeGate(gate_error)
    request.app.state.appshell_mode_gate = gate

    with pytest.raises(HTTPException) as caught:
        await issue_owner_intent(
            request,
            IntentIssueRequest(raw_request="stale parent epoch", template="personal"),
            principal,
        )
    assert caught.value.status_code == status_code
    assert (gate.admits, gate.releases) == (1, 0)
    assert adapter.registered == []
    assert adapter.file_bindings == []


def test_directory_handle_commitment_has_frozen_order_nfc_root_and_golden_vector(
    tmp_path: Path,
) -> None:
    from js.orin.handles import (
        canonical_workspace_root,
        derive_appshell_directory_handle_id,
    )
    from js.orin.protocol import canonical_json

    decomposed = tmp_path / "Cafe\u0301"
    decomposed.mkdir()
    canonical_root = canonical_workspace_root(decomposed)
    assert canonical_root == unicodedata.normalize("NFC", os.fspath(decomposed.resolve()))
    assert unicodedata.is_normalized("NFC", canonical_root)

    fields: list[str | int] = [
        "orin:appshell-dirh:v1",
        "sha256:" + "a" * 64,
        "js-work",
        "task:golden-001",
        "work",
        "sha256:" + "b" * 64,
        "session:appshell-golden",
        7,
        "/tmp/Café",
    ]
    assert canonical_json(fields) == (
        '["orin:appshell-dirh:v1",'
        '"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        '"js-work","task:golden-001","work",'
        '"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
        '"session:appshell-golden",7,"/tmp/Café"]'
    )
    assert derive_appshell_directory_handle_id(
        installation_owner_hash="sha256:" + "a" * 64,
        product_id="js-work",
        task_id="task:golden-001",
        profile="work",
        principal_owner="sha256:" + "b" * 64,
        principal_session="session:appshell-golden",
        principal_epoch=7,
        workspace_root="/tmp/Café",
    ) == "dirh:appshell-de15ad9457e43fb85948854fac735fca1c7f55032b4cf5f83b8c2f59c16fd1f6"


def test_appshell_directory_binding_grant_round_trips_strictly(tmp_path: Path) -> None:
    from js.orin.handles import (
        AppShellDirectoryBindingV1,
        appshell_directory_binding_from_dict,
        canonical_workspace_root,
    )
    from js.orin.protocol import ProtocolError

    root = canonical_workspace_root(tmp_path)
    binding = AppShellDirectoryBindingV1(
        principal_owner="sha256:" + "1" * 64,
        principal_epoch=3,
        product_id="js-work",
        workspace_root=root,
    )
    raw = binding.to_dict()
    assert raw == {
        "schema": "AppShellDirectoryBindingV1",
        "principal_owner": "sha256:" + "1" * 64,
        "principal_epoch": 3,
        "product_id": "js-work",
        "workspace_root": root,
    }
    assert appshell_directory_binding_from_dict(raw) == binding

    for invalid in (
        {**raw, "principal_epoch": True},
        {**raw, "schema": "AppShellDirectoryBindingV2"},
        {**raw, "principal_session": "session:must-stay-top-level"},
        {key: value for key, value in raw.items() if key != "workspace_root"},
    ):
        with pytest.raises(ProtocolError):
            appshell_directory_binding_from_dict(invalid)


def test_intent_issue_request_keeps_factory_task_but_forbids_root_override() -> None:
    request = IntentIssueRequest.model_validate(
        {
            "raw_request": "run the fixed workflow",
            "template": "factory",
            "task_id": "task:factory-client-compatible",
            "resource_handles": ["fileh:report"],
        }
    )
    assert request.task_id == "task:factory-client-compatible"
    assert request.resource_handles == ["fileh:report"]

    with pytest.raises(ValidationError):
        IntentIssueRequest.model_validate(
            {
                "raw_request": "stage this exact file",
                "workspace_root": "/tmp/model-selected-root",
            }
        )


@pytest.mark.parametrize("template", ["personal", "work"])
def test_file_commit_remains_available_in_personal_and_work_templates(template: str) -> None:
    envelope = build_intent_from_template(
        template=template,
        task_id=f"task:wp9-{template}-file",
        raw_request="stage and commit this exact file",
        owner_key_hash="sha256:" + "2" * 64,
        resource_handles=("dirh:server-derived",),
    )

    assert "file.commit" in envelope.allowed_effect_classes
    parsed = intent_from_dict(envelope.to_dict())
    assert parsed.allowed_effect_classes == envelope.allowed_effect_classes


def test_factory_template_effect_classes_remain_exactly_unchanged() -> None:
    envelope = build_intent_from_template(
        template="factory",
        task_id="task:wp9-factory-unchanged",
        raw_request="run the fixed factory workflow",
        owner_key_hash="sha256:" + "3" * 64,
    )

    assert envelope.allowed_effect_classes == (
        "artifact.read",
        "artifact.stage",
        "net.fetch",
        "email.send_exact",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(("mode", "template"), [("personal", "personal"), ("work", "work")])
async def test_each_confirmation_mints_fresh_task_and_server_directory_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    template: str,
) -> None:
    from js.orin.handles import (
        canonical_workspace_root,
        derive_appshell_directory_handle_id,
    )

    adapter = _RecordingAdapter()
    request, principal, workspace = _route_context(tmp_path, adapter, mode=mode)
    _private_key, public_key = _install_witness(monkeypatch)
    body = IntentIssueRequest(
        raw_request="commit this exact workspace file",
        template=template,  # type: ignore[arg-type]
        resource_handles=["fileh:monthly-report"],
    )

    first = await issue_owner_intent(request, body, principal)
    second = await issue_owner_intent(request, body, principal)

    assert first["task_id"].startswith("task:")
    assert second["task_id"].startswith("task:")
    assert first["task_id"] != second["task_id"]
    assert first["directory_handle_id"] != second["directory_handle_id"]
    assert adapter.registered == []
    assert len(adapter.file_bindings) == 2

    expected_root = canonical_workspace_root(workspace)
    installation_owner = "sha256:" + hashlib.sha256(
        f"js-agent:{tmp_path}".encode()
    ).hexdigest()
    product_id = "js-work" if mode == "work" else "js-agent"
    for response, (raw_intent, binding) in zip(
        (first, second), adapter.file_bindings, strict=True
    ):
        signed = intent_from_dict(raw_intent, verify_signature=True)
        assert signed.verify(public_key)
        assert signed.owner_key_hash == installation_owner
        assert signed.owner_key_hash != principal.owner
        assert signed.product_id == product_id
        assert signed.profile == mode
        assert signed.task_id == response["task_id"]
        assert signed.allowed_resource_handles == (
            "fileh:monthly-report",
            response["directory_handle_id"],
        )
        assert binding == {
            "appshell_owner": principal.owner,
            "appshell_session": principal.session,
            "appshell_epoch": principal.epoch,
            "workspace_root": expected_root,
        }
        assert binding["workspace_root"] != principal.workspace
        assert response["directory_handle_id"] == derive_appshell_directory_handle_id(
            installation_owner_hash=installation_owner,
            product_id=product_id,
            task_id=response["task_id"],
            profile=mode,
            principal_owner=principal.owner,
            principal_session=principal.session,
            principal_epoch=principal.epoch,
            workspace_root=expected_root,
        )
        _assert_no_authority_material(response)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["personal", "work"])
async def test_personal_and_work_confirmation_reject_client_task_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    adapter = _RecordingAdapter()
    request, principal, _workspace = _route_context(tmp_path, adapter, mode=mode)
    _install_witness(monkeypatch)

    with pytest.raises(HTTPException) as caught:
        await issue_owner_intent(
            request,
            IntentIssueRequest(
                raw_request="try to select Orin authority",
                template=mode,  # type: ignore[arg-type]
                task_id="task:model-selected",
            ),
            principal,
        )

    assert caught.value.status_code == 400
    assert adapter.registered == []
    assert adapter.file_bindings == []


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["personal", "work"])
async def test_confirmation_rejects_client_directory_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    adapter = _RecordingAdapter()
    request, principal, _workspace = _route_context(tmp_path, adapter, mode=mode)
    _install_witness(monkeypatch)

    with pytest.raises(HTTPException) as caught:
        await issue_owner_intent(
            request,
            IntentIssueRequest(
                raw_request="try to select another directory",
                template=mode,  # type: ignore[arg-type]
                resource_handles=["dirh:forged-by-echo"],
            ),
            principal,
        )

    assert caught.value.status_code == 400
    assert adapter.registered == []
    assert adapter.file_bindings == []


@pytest.mark.asyncio
@pytest.mark.parametrize(("mode", "template"), [("personal", "work"), ("work", "personal")])
async def test_confirmation_rejects_profile_different_from_active_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    template: str,
) -> None:
    adapter = _RecordingAdapter()
    request, principal, _workspace = _route_context(tmp_path, adapter, mode=mode)
    _install_witness(monkeypatch)

    with pytest.raises(HTTPException) as caught:
        await issue_owner_intent(
            request,
            IntentIssueRequest(
                raw_request="try to select the other profile",
                template=template,  # type: ignore[arg-type]
            ),
            principal,
        )

    assert caught.value.status_code in {400, 403}
    assert adapter.registered == []
    assert adapter.file_bindings == []


@pytest.mark.asyncio
async def test_factory_keeps_client_task_and_does_not_mint_directory_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _RecordingAdapter()
    request, principal, _workspace = _route_context(tmp_path, adapter)
    _private_key, public_key = _install_witness(monkeypatch)

    response = await issue_owner_intent(
        request,
        IntentIssueRequest(
            raw_request="run fixed workflow",
            template="factory",
            task_id="task:factory-client-compatible",
            resource_handles=["artifact:input"],
        ),
        principal,
    )

    assert response["task_id"] == "task:factory-client-compatible"
    assert adapter.file_bindings == []
    assert len(adapter.registered) == 1
    registered = intent_from_dict(adapter.registered[0], verify_signature=True)
    assert registered.verify(public_key)
    assert registered.profile == "factory"
    assert registered.allowed_resource_handles == ("artifact:input",)


def _adapter_for(orind: Any) -> Any:
    from js.orin.client import OrinLeaseClientAdapter

    return OrinLeaseClientAdapter(
        socket_path=orind.socket_path,
        state_dir=Path(orind.daemon._state_dir),
        stage_b=True,
    )


def _send_binding_register(
    adapter: Any,
    *,
    intent: dict[str, Any],
    grant: dict[str, Any],
    session_id: str,
) -> dict[str, Any]:
    return adapter._call(
        lambda: adapter._request(
            "intent",
            op="register",
            intent=intent,
            grant=grant,
            session_id=session_id,
        )
    )


def test_plain_register_without_grant_remains_legal_and_mints_nothing(tmp_path: Path) -> None:
    from js.orin.testing import TestOrind

    witness = ed25519.Ed25519PrivateKey.generate()
    with TestOrind(
        state_dir=tmp_path,
        stage_b=True,
        witness_public_keys=(_public_key(witness),),
    ) as orind:
        adapter = _adapter_for(orind)
        try:
            signed = build_intent_from_template(
                template="work",
                task_id="task:plain-register-no-grant",
                raw_request="register only",
                owner_key_hash="sha256:" + "2" * 64,
                product_id="js-work",
                resource_handles=(),
            ).sign_with(witness)

            assert adapter.register_intent(signed.to_dict())["ok"] is True
            assert adapter.active_intent(signed.task_id) is not None
            assert orind.daemon._broker.seed_list("DirectoryHandle") == []
        finally:
            adapter.close()


def test_strict_appshell_grant_mints_handle_with_orin_owner_not_principal(
    tmp_path: Path,
) -> None:
    from js.orin.handles import (
        canonical_workspace_root,
        derive_appshell_directory_handle_id,
        handle_from_dict,
    )
    from js.orin.testing import TestOrind

    witness = ed25519.Ed25519PrivateKey.generate()
    workspace = tmp_path / "work-root"
    workspace.mkdir()
    root = canonical_workspace_root(workspace)
    installation_owner = "sha256:" + "2" * 64
    principal_owner = "sha256:" + "3" * 64
    session = "session:trusted-appshell-parent"
    task_id = "task:strict-binding"
    handle_id = derive_appshell_directory_handle_id(
        installation_owner_hash=installation_owner,
        product_id="js-work",
        task_id=task_id,
        profile="work",
        principal_owner=principal_owner,
        principal_session=session,
        principal_epoch=9,
        workspace_root=root,
    )
    signed = build_intent_from_template(
        template="work",
        task_id=task_id,
        raw_request="commit inside trusted root",
        owner_key_hash=installation_owner,
        product_id="js-work",
        resource_handles=(handle_id,),
    ).sign_with(witness)

    with TestOrind(
        state_dir=tmp_path,
        stage_b=True,
        witness_public_keys=(_public_key(witness),),
    ) as orind:
        adapter = _adapter_for(orind)
        try:
            ack = adapter.register_file_binding(
                signed.to_dict(),
                appshell_owner=principal_owner,
                appshell_session=session,
                appshell_epoch=9,
                workspace_root=root,
            )
            assert ack["ok"] is True
            _assert_no_authority_material(ack)
            resolved = orind.daemon._broker.resolve(handle_id)
            assert resolved["ok"] is True
            handle = handle_from_dict(resolved["handle"], require_signature=True)
            assert handle.owner_key_hash == installation_owner
            assert handle.owner_key_hash != principal_owner
            assert handle.tenant == "work"
            assert handle.object_digest == root
            assert handle.capabilities == ("read", "stage", "write")
            assert handle.issuer == "orind:broker"
        finally:
            adapter.close()


@pytest.mark.parametrize(
    "tamper",
    ["root", "commitment", "principal", "session", "epoch", "product", "task", "profile"],
)
def test_binding_grant_rejects_every_commitment_field_tamper(
    tmp_path: Path,
    tamper: str,
) -> None:
    from js.orin.handles import (
        canonical_workspace_root,
        derive_appshell_directory_handle_id,
    )
    from js.orin.testing import TestOrind

    witness = ed25519.Ed25519PrivateKey.generate()
    workspace = tmp_path / "owner-root"
    workspace.mkdir()
    other_workspace = tmp_path / "other-root"
    other_workspace.mkdir()
    root = canonical_workspace_root(workspace)
    installation_owner = "sha256:" + "4" * 64
    principal_owner = "sha256:" + "5" * 64
    session = "session:commitment-parent"
    epoch = 11
    product_id = "js-work"
    task_id = f"task:tamper-{tamper}"
    profile = "work"
    committed_handle = derive_appshell_directory_handle_id(
        installation_owner_hash=installation_owner,
        product_id=product_id,
        task_id=task_id,
        profile=profile,
        principal_owner=principal_owner,
        principal_session=session,
        principal_epoch=epoch,
        workspace_root=root,
    )
    intent_handle = committed_handle
    grant = {
        "schema": "AppShellDirectoryBindingV1",
        "principal_owner": principal_owner,
        "principal_epoch": epoch,
        "product_id": product_id,
        "workspace_root": root,
    }
    sent_session = session
    intent_task = task_id
    intent_profile = profile
    intent_product = product_id
    if tamper == "root":
        grant["workspace_root"] = canonical_workspace_root(other_workspace)
    elif tamper == "commitment":
        intent_handle = "dirh:appshell-" + "0" * 64
    elif tamper == "principal":
        grant["principal_owner"] = "sha256:" + "6" * 64
    elif tamper == "session":
        sent_session = "session:different-parent"
    elif tamper == "epoch":
        grant["principal_epoch"] = epoch + 1
    elif tamper == "product":
        grant["product_id"] = "js-agent"
    elif tamper == "task":
        intent_task = task_id + "-different"
    elif tamper == "profile":
        intent_profile = "personal"

    signed = build_intent_from_template(
        template=intent_profile,
        task_id=intent_task,
        raw_request="tamper probe",
        owner_key_hash=installation_owner,
        product_id=intent_product,
        resource_handles=(intent_handle,),
    ).sign_with(witness)

    with TestOrind(
        state_dir=tmp_path,
        stage_b=True,
        witness_public_keys=(_public_key(witness),),
    ) as orind:
        adapter = _adapter_for(orind)
        try:
            with pytest.raises(LeaseDenied):
                _send_binding_register(
                    adapter,
                    intent=signed.to_dict(),
                    grant=grant,
                    session_id=sent_session,
                )
            assert orind.daemon._intents.active_envelope(intent_task, now_ms=0) is None
            assert orind.daemon._broker.resolve(committed_handle)["ok"] is False
        finally:
            adapter.close()


def test_plain_handle_issue_cannot_self_approve_directory_handle(tmp_path: Path) -> None:
    from js.orin.testing import TestOrind

    with TestOrind(state_dir=tmp_path, stage_b=True) as orind:
        adapter = _adapter_for(orind)
        try:
            with pytest.raises(LeaseDenied):
                adapter._call(
                    lambda: adapter._request(
                        "handle",
                        op="issue",
                        spec={
                            "kind": "DirectoryHandle",
                            "token": "echo-forged-root",
                            "owner_key_hash": "sha256:" + "7" * 64,
                            "object_digest": "/tmp/echo-selected",
                            "capabilities": ["read", "stage", "write"],
                            "approved": True,
                        },
                    )
                )
            assert orind.daemon._broker.resolve("dirh:echo-forged-root")["ok"] is False
        finally:
            adapter.close()
