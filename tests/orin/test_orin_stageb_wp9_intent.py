"""WP9 AppShell owner-intent resource-handle boundary tests."""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import ValidationError

from js.appshell.principal import AppShellPrincipalV1
from js.appshell.routers import IntentIssueRequest, issue_owner_intent
from js.orin.intent import intent_from_dict
from js.orin.witness import build_intent_from_template


class _RecordingAdapter:
    _stage_b = True

    def __init__(self) -> None:
        self.registered: list[dict[str, Any]] = []

    def register_intent(self, intent: dict[str, Any]) -> dict[str, Any]:
        self.registered.append(intent)
        return {"ok": True}


def _route_context(tmp_path: Path, adapter: _RecordingAdapter) -> tuple[Any, Any]:
    agent = SimpleNamespace(_get_echo_tool_lease_authority=lambda: adapter)
    runtime = SimpleNamespace(
        agent=agent,
        settings=SimpleNamespace(state_dir=tmp_path),
    )
    child = SimpleNamespace(state=SimpleNamespace(web_runtime=runtime))
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(personal_app=child, work_app=child),
        ),
    )
    principal = AppShellPrincipalV1(
        owner="sha256:" + "1" * 64,
        session="session:wp9-intent",
        active_mode="personal",
        mode_roles={"personal": "admin"},
        workspace=None,
        expires_at=4_000_000_000.0,
    )
    return request, principal


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


def test_intent_issue_request_accepts_resource_handles_and_forbids_extra() -> None:
    request = IntentIssueRequest.model_validate(
        {
            "raw_request": "stage this exact file",
            "resource_handles": ["dirh:workspace", "fileh:report"],
        }
    )
    assert request.resource_handles == ["dirh:workspace", "fileh:report"]

    with pytest.raises(ValidationError):
        IntentIssueRequest.model_validate(
            {
                "raw_request": "stage this exact file",
                "resource_handles": ["fileh:report"],
                "untrusted_authority": "dirh:anywhere",
            }
        )


@pytest.mark.parametrize("template", ["personal", "work"])
def test_file_commit_is_available_without_changing_requested_resources(
    template: str,
) -> None:
    requested_handles = ("dirh:owner-root", "fileh:staging-target")
    envelope = build_intent_from_template(
        template=template,
        task_id=f"task:wp9-{template}-file",
        raw_request="stage and commit this exact file",
        owner_key_hash="sha256:" + "2" * 64,
        resource_handles=requested_handles,
    )

    assert "file.commit" in envelope.allowed_effect_classes
    assert envelope.allowed_resource_handles == requested_handles
    parsed = intent_from_dict(envelope.to_dict())
    assert parsed.allowed_effect_classes == envelope.allowed_effect_classes
    assert parsed.allowed_resource_handles == requested_handles


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
async def test_issue_owner_intent_preserves_resource_handles_in_signed_envelope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from js.orin import witness

    adapter = _RecordingAdapter()
    request, principal = _route_context(tmp_path, adapter)
    _private_key, public_key = _install_witness(monkeypatch)
    original_builder = witness.build_intent_from_template
    builder_arguments: dict[str, Any] = {}

    def recording_builder(**kwargs: Any) -> Any:
        builder_arguments.update(kwargs)
        return original_builder(**kwargs)

    monkeypatch.setattr(witness, "build_intent_from_template", recording_builder)
    requested_handles = ["dirh:workspace", "fileh:monthly-report"]

    response = await issue_owner_intent(
        request,
        IntentIssueRequest(
            raw_request="prepare the monthly report",
            task_id="task:wp9-resources",
            resource_handles=requested_handles,
        ),
        principal,
    )

    assert response["ok"] is True
    assert builder_arguments["resource_handles"] == tuple(requested_handles)
    assert len(adapter.registered) == 1
    signed = intent_from_dict(adapter.registered[0], verify_signature=True)
    assert signed.allowed_resource_handles == tuple(requested_handles)
    assert signed.verify(public_key)


@pytest.mark.asyncio
async def test_issue_owner_intent_omission_explicitly_grants_no_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from js.orin import witness

    adapter = _RecordingAdapter()
    request, principal = _route_context(tmp_path, adapter)
    _private_key, public_key = _install_witness(monkeypatch)
    original_builder = witness.build_intent_from_template
    builder_arguments: dict[str, Any] = {}

    def recording_builder(**kwargs: Any) -> Any:
        builder_arguments.update(kwargs)
        return original_builder(**kwargs)

    monkeypatch.setattr(witness, "build_intent_from_template", recording_builder)

    await issue_owner_intent(
        request,
        IntentIssueRequest(
            raw_request="read nothing unless I select it",
            task_id="task:wp9-no-resources",
        ),
        principal,
    )

    assert builder_arguments["resource_handles"] == ()
    assert len(adapter.registered) == 1
    signed = intent_from_dict(adapter.registered[0], verify_signature=True)
    assert signed.allowed_resource_handles == ()
    assert signed.verify(public_key)
