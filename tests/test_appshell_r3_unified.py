"""R3 unified Inbox and Artifact Center tests against real authorities."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from js.config import EchoLedgerConfig
from js.echo.ledger._hashing import stable_hash, stable_hmac
from js.echo.ledger.service import EchoSafetyService
from js.echo.mode_contract import AppMode, ArtifactRefV1
from js.security.approvals import ApprovalDecisionType

_ADMIN_KEY = "js_r3-shared-admin-key"
_USER_KEY = "js_r3-shared-user-key"
_SECOND_ADMIN_KEY = "js_r3-second-admin-key"


def _write_personal_config(root: Path) -> tuple[Path, Path, Path]:
    state = root / "personal-state"
    workspace = root / "personal-workspace"
    config = root / "personal.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "state_dir": str(state),
                "workspace": str(workspace),
                "echo_engine": "on",
                "first_run_completed": True,
                "security": {"api_key_required": True},
                "providers": [],
                "models": [],
            }
        ),
        encoding="utf-8",
    )
    return config, state, workspace


def _write_work_config(root: Path) -> tuple[Path, Path, Path, Path]:
    home = root / "work-home"
    state = home / ".js-work" / "state"
    workspace = home / ".js-work" / "workspace"
    config = root / "work.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "state_dir": str(state),
                "workspace": str(workspace),
                "echo_engine": "on",
                "first_run_completed": True,
                "security": {"api_key_required": True},
                "providers": [],
                "models": [],
            }
        ),
        encoding="utf-8",
    )
    return config, home, state, workspace


def _provision_shared_keys(personal_state: Path, work_state: Path) -> None:
    from js.web.auth import AuthManager

    personal = AuthManager(personal_state)
    work = AuthManager(work_state)
    for api_key, name, role in (
        (_ADMIN_KEY, "r3-admin", "admin"),
        (_USER_KEY, "r3-user", "user"),
        (_SECOND_ADMIN_KEY, "r3-second-admin", "admin"),
    ):
        personal.provision_existing_key(api_key, name=name, role=role)
        work.provision_existing_key(api_key, name=name, role=role)


@dataclass
class _Harness:
    client: TestClient
    app: Any
    admin_owner: str
    user_owner: str
    second_owner: str
    work_handle: str

    def login(self, api_key: str = _ADMIN_KEY) -> dict[str, Any]:
        response = self.client.post(
            "/api/appshell/session",
            headers={"X-API-Key": api_key},
        )
        assert response.status_code == 200, response.text
        return response.json()

    def switch_to_work(self) -> dict[str, Any]:
        response = self.client.post(
            "/api/appshell/switch",
            json={
                "expected_from_mode": "personal",
                "to_mode": "work",
                "session_id": None,
                "workspace_handle": self.work_handle,
            },
        )
        assert response.status_code == 200, response.text
        return response.json()


@pytest.fixture()
def appshell_harness(tmp_path: Path) -> Any:
    from js.appshell.server import create_appshell_app
    from js.echo.turn_runtime import _workspace_handle
    from js_work.tools import WorkToolProfile

    personal_config, personal_state, _personal_workspace = _write_personal_config(tmp_path)
    work_config, work_home, work_state, work_workspace = _write_work_config(tmp_path)
    _provision_shared_keys(personal_state, work_state)
    app = create_appshell_app(
        personal_config=str(personal_config),
        work_config=str(work_config),
        work_home=work_home,
        work_profile=WorkToolProfile.SAFE,
        host="127.0.0.1",
        port=8000,
    )
    with TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost"},
        client=("127.0.0.1", 50124),
    ) as client:
        yield _Harness(
            client=client,
            app=app,
            admin_owner=hashlib.sha256(_ADMIN_KEY.encode()).hexdigest(),
            user_owner=hashlib.sha256(_USER_KEY.encode()).hexdigest(),
            second_owner=hashlib.sha256(_SECOND_ADMIN_KEY.encode()).hexdigest(),
            work_handle=_workspace_handle(work_workspace),
        )


@pytest.fixture()
def guest_appshell_client(appshell_harness: _Harness) -> TestClient:
    assert "js_appshell_session" not in appshell_harness.client.cookies
    return appshell_harness.client


@pytest.fixture()
def authed_harness(appshell_harness: _Harness) -> _Harness:
    appshell_harness.login()
    assert appshell_harness.client.cookies.get("js_appshell_session")
    return appshell_harness


@dataclass
class _RealAuthorities:
    harness: _Harness
    personal_agent: Any
    work_agent: Any
    approval_session: str
    approval_run: str
    memory_session: str
    manual_session: str
    manual_run: str


@pytest.fixture()
def r3_real_authorities(authed_harness: _Harness) -> _RealAuthorities:
    personal_agent = authed_harness.app.state.personal_app.state.web_runtime.agent
    work_agent = authed_harness.app.state.work_app.state.web_runtime.agent

    approval_session = "session-personal-approval"
    approval_run = "run-personal-approval"
    decision = personal_agent.approvals.request_decision(
        tool_name="file_write",
        arguments={"path": "safe.txt", "content": "fixture"},
        context="web",
        session_id=approval_session,
        run_id=approval_run,
        owner_key_hash=authed_harness.admin_owner,
        queue_if_unhandled=True,
    )
    assert decision.action is ApprovalDecisionType.PENDING
    assert len(
        personal_agent.approvals.get_pending(
            owner_key_hash=authed_harness.admin_owner
        )
    ) == 1

    memory_session = "session-personal-memory"
    proposal = personal_agent.memory.propose_change(
        action="create",
        key="favorite-drink",
        value="tea",
        category="preference",
        source="manual",
        session_id=memory_session,
        owner_key_hash=authed_harness.admin_owner,
        auto_apply=False,
    )
    assert proposal["status"] == "pending"
    assert len(
        personal_agent.memory.list_proposals(
            "pending", authed_harness.admin_owner, 50
        )
    ) == 1

    manual_session = "session-work-manual"
    manual_run = "run-work-manual"
    work_settings = authed_harness.app.state.work_app.state.runtime_settings
    writer = EchoSafetyService.from_settings(work_settings)
    context = writer.begin_chat_turn(
        tenant_id=authed_harness.admin_owner,
        run_id=manual_run,
        user_text="manual-review-fixture",
        model_id="mock",
        call_metadata={
            "product_id": "js-work",
            "session_id": manual_session,
        },
    )
    writer.assert_model_execution_permitted(context)
    writer.close()
    assert work_agent.echo_safety_service.list_manual_reviews(
        tenant_id=authed_harness.admin_owner
    )

    return _RealAuthorities(
        harness=authed_harness,
        personal_agent=personal_agent,
        work_agent=work_agent,
        approval_session=approval_session,
        approval_run=approval_run,
        memory_session=memory_session,
        manual_session=manual_session,
        manual_run=manual_run,
    )


def _append_real_artifact(
    service: EchoSafetyService,
    *,
    owner: str,
    mode: AppMode,
    session: str,
    run: str,
    workspace: str | None,
    acl: str = "owner",
    marker: str = "a" * 32,
    digest_char: str = "2",
) -> ArtifactRefV1:
    product_id = "js-work" if mode is AppMode.WORK else "js-agent"
    context = service.begin_tool_effect(
        tenant_id=owner,
        product_id=product_id,
        session_id=session,
        run_id=run,
        tool_name="excel_write",
        tool_call_id=f"call-r3-artifact-{marker}",
        args_hash="sha256:" + "1" * 64,
        lease_id="lease-r3-artifact",
        replay_class="non_idempotent",
        workspace=workspace,
    )
    ref = ArtifactRefV1(
        mode=mode,
        owner=owner,
        session=session,
        workspace=workspace,
        kind="spreadsheet",
        uri="echo://artifact/" + marker,
        digest="sha256:" + digest_char * 64,
        acl=acl,
        created_by_run=run,
    )
    service.finish_tool_effect(
        context,
        status="ok",
        output_hash=ref.digest,
        artifact_refs=(ref,),
    )
    return ref


def _append_artifact_batch(
    service: EchoSafetyService,
    *,
    owner: str,
    session: str,
    run: str,
    acl: str,
    count: int,
    marker: str,
) -> tuple[ArtifactRefV1, ...]:
    context = service.begin_tool_effect(
        tenant_id=owner,
        product_id="js-agent",
        session_id=session,
        run_id=run,
        tool_name="excel_write",
        tool_call_id=f"call-{marker}",
        args_hash="sha256:" + "9" * 64,
        lease_id=f"lease-{marker}",
        replay_class="non_idempotent",
    )
    refs = tuple(
        ArtifactRefV1(
            mode=AppMode.PERSONAL,
            owner=owner,
            session=session,
            workspace=None,
            kind="spreadsheet",
            uri=f"echo://artifact/{marker}-{index}",
            digest="sha256:" + f"{(index % 15) + 1:x}" * 64,
            acl=acl,
            created_by_run=run,
        )
        for index in range(count)
    )
    service.finish_tool_effect(
        context,
        status="ok",
        output_hash="sha256:" + "f" * 64,
        artifact_refs=refs,
    )
    return refs


def _append_empty_effect(
    service: EchoSafetyService,
    *,
    owner: str,
    mode: AppMode,
    session: str,
    run: str,
    workspace: str | None,
) -> None:
    product_id = "js-work" if mode is AppMode.WORK else "js-agent"
    context = service.begin_tool_effect(
        tenant_id=owner,
        product_id=product_id,
        session_id=session,
        run_id=run,
        tool_name="file_write",
        tool_call_id=f"call-{run}",
        args_hash="sha256:" + "c" * 64,
        lease_id=f"lease-{run}",
        replay_class="non_idempotent",
        workspace=workspace,
    )
    service.finish_tool_effect(
        context,
        status="ok",
        output_hash="sha256:" + "d" * 64,
    )


def _write_v1_retired_checkpoint_with_gap(
    service: EchoSafetyService,
    *,
    owner: str,
    session: str,
    product_id: str,
) -> Path:
    journal = service.journal_path_for_scope(
        owner,
        product_id=product_id,
        session_id=session,
    )
    owner_root = journal.parent.parent
    checkpoint_path = owner_root / "retired-sessions.json"
    key_path = owner_root / "retention.key"
    key = b"v" * 32
    key_path.write_text(key.hex(), encoding="ascii")
    os.chmod(key_path, 0o600)
    genesis = "sha256:" + "0" * 64
    receipt_body = {
        "seq": 1,
        "session_partition": "session_" + "b" * 32,
        "source_files_hash": "sha256:" + "1" * 64,
        "source_file_count": 1,
        "source_total_bytes": 1,
        "journal_record_count": 1,
        "journal_tip_hash": "sha256:" + "2" * 64,
        "retired_at": "2026-08-02T00:00:00+00:00",
        "prev_hash": genesis,
    }
    tip = stable_hash(receipt_body)
    body = {
        "schema_version": "echo-session-retention-v1",
        "product_partition": owner_root.parent.name,
        "owner_partition": owner_root.name,
        "retired_count": 1,
        "compacted_count": 0,
        "compacted_tip": genesis,
        "tip": tip,
        "receipts": [{**receipt_body, "receipt_hash": tip}],
    }
    checkpoint_path.write_text(
        json.dumps(
            {**body, "mac": stable_hmac(key, body).hex()},
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    return checkpoint_path


def test_guest_without_parent_cookie_is_rejected_exactly(
    guest_appshell_client: TestClient,
) -> None:
    assert "js_appshell_session" not in guest_appshell_client.cookies
    response = guest_appshell_client.get("/api/appshell/inbox")
    assert response.status_code == 401
    assert response.json() == {"detail": "AppShell session is required"}
    assert response.headers["cache-control"] == "no-store"


def test_real_pending_approval_and_memory_proposal_project_as_legal_attention_items(
    r3_real_authorities: _RealAuthorities,
) -> None:
    response = r3_real_authorities.harness.client.get("/api/appshell/inbox")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ok"
    by_kind = {item["kind"]: item for item in body["items"]}
    assert set(by_kind) == {"approval", "memory_proposal"}
    assert by_kind["approval"]["mode"] == "personal"
    assert by_kind["approval"]["session"] == r3_real_authorities.approval_session
    assert by_kind["approval"]["run"] == r3_real_authorities.approval_run
    assert by_kind["memory_proposal"]["session"] == r3_real_authorities.memory_session
    assert by_kind["memory_proposal"]["run"].startswith("memory-proposal:")
    for item in body["items"]:
        assert item["effect_digest"].startswith("sha256:")
        assert item["args_digest"].startswith("sha256:")
        assert item["workspace"] is None
        assert "owner" not in item
        assert "eligible_approver" not in item
    assert r3_real_authorities.harness.admin_owner not in response.text
    assert r3_real_authorities.harness.admin_owner[:8] not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_real_manual_review_survives_restart_and_uses_trusted_work_runtime(
    r3_real_authorities: _RealAuthorities,
) -> None:
    r3_real_authorities.harness.switch_to_work()
    response = r3_real_authorities.harness.client.get(
        "/api/appshell/inbox", params={"mode": "work"}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ok"
    assert body["source_watermark"]["mode"] == "work"
    assert [item["kind"] for item in body["items"]] == ["manual_review"]
    item = body["items"][0]
    assert item["mode"] == "work"
    assert item["workspace"] == r3_real_authorities.harness.work_handle
    assert item["session"] == r3_real_authorities.manual_session
    assert item["run"] == r3_real_authorities.manual_run


def test_cross_owner_pending_rows_do_not_appear_or_leak_owner_prefix(
    authed_harness: _Harness,
) -> None:
    agent = authed_harness.app.state.personal_app.state.web_runtime.agent
    decision = agent.approvals.request_decision(
        tool_name="file_write",
        arguments={"path": "other.txt", "content": "other"},
        context="web",
        session_id="same-session-name",
        run_id="same-run-name",
        owner_key_hash=authed_harness.second_owner,
        queue_if_unhandled=True,
    )
    assert decision.action is ApprovalDecisionType.PENDING
    proposal = agent.memory.propose_change(
        action="create",
        key="other-owner-key",
        value="other-owner-value",
        category="preference",
        source="manual",
        session_id="same-session-name",
        owner_key_hash=authed_harness.second_owner,
        auto_apply=False,
    )
    assert proposal["status"] == "pending"

    response = authed_harness.client.get("/api/appshell/inbox")
    assert response.status_code == 200, response.text
    assert response.json()["items"] == []
    assert authed_harness.second_owner not in response.text
    assert authed_harness.second_owner[:8] not in response.text


def test_user_cannot_infer_admin_only_manual_or_memory_from_count_or_issue(
    appshell_harness: _Harness,
) -> None:
    appshell_harness.login(_USER_KEY)
    agent = appshell_harness.app.state.personal_app.state.web_runtime.agent
    proposal = agent.memory.propose_change(
        action="create",
        key="admin-only-memory",
        value="hidden",
        category="preference",
        source="manual",
        session_id="session-user-hidden",
        owner_key_hash=appshell_harness.user_owner,
        auto_apply=False,
    )
    assert proposal["status"] == "pending"
    writer = EchoSafetyService.from_settings(
        appshell_harness.app.state.personal_app.state.runtime_settings
    )
    context = writer.begin_chat_turn(
        tenant_id=appshell_harness.user_owner,
        run_id="run-user-hidden",
        user_text="hidden manual review",
        model_id="mock",
        call_metadata={
            "product_id": "js-agent",
            "session_id": "session-user-hidden",
        },
    )
    writer.assert_model_execution_permitted(context)
    writer.close()

    response = appshell_harness.client.get("/api/appshell/inbox")
    assert response.status_code == 200, response.text
    assert response.json()["items"] == []
    assert response.json()["count"] == 0
    assert response.json()["access_issues"] == []


def test_unbound_legacy_manual_review_is_not_forged_as_unknown(
    authed_harness: _Harness,
) -> None:
    writer = EchoSafetyService.from_settings(
        authed_harness.app.state.personal_app.state.runtime_settings
    )
    context = writer.begin_chat_turn(
        tenant_id=authed_harness.admin_owner,
        run_id="legacy-run-without-session-binding",
        user_text="legacy sealed input must remain private",
        model_id="mock",
    )
    writer.assert_model_execution_permitted(context)
    writer.close()

    response = authed_harness.client.get("/api/appshell/inbox")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "partial"
    assert response.json()["items"] == []
    assert response.json()["access_issues"] == [
        {
            "source": "manual_reviews",
            "code": "unbound_record",
            "safe_detail": "projection source unavailable",
        }
    ]
    assert "unknown" not in response.text
    assert "legacy sealed input" not in response.text


def test_verified_artifact_ref_round_trips_through_endpoint_and_orphans_never_appear(
    authed_harness: _Harness,
) -> None:
    settings = authed_harness.app.state.personal_app.state.runtime_settings
    workspace = Path(settings.workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "orphan.xlsx").write_bytes(b"orphan spreadsheet")
    (workspace / "orphan.pdf").write_bytes(b"orphan pdf")
    nested = workspace / "nested"
    nested.mkdir()
    (nested / "orphan.txt").write_text("orphan", encoding="utf-8")

    empty = authed_harness.client.get("/api/appshell/artifacts")
    assert empty.status_code == 200, empty.text
    assert empty.json()["status"] == "ok"
    assert empty.json()["items"] == []

    service = authed_harness.app.state.personal_app.state.web_runtime.agent.echo_safety_service
    expected = _append_real_artifact(
        service,
        owner=authed_harness.admin_owner,
        mode=AppMode.PERSONAL,
        session="session-personal-artifact",
        run="run-personal-artifact",
        workspace=None,
    )
    response = authed_harness.client.get("/api/appshell/artifacts")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ok"
    assert body["count"] == 1
    assert body["items"] == [
        {
            key: value
            for key, value in expected.to_dict().items()
            if key != "owner"
        }
    ]
    assert "orphan.xlsx" not in response.text
    assert str(workspace) not in response.text
    assert authed_harness.admin_owner not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_legacy_v1_retirement_gap_is_partial_with_sanitized_issue(
    authed_harness: _Harness,
) -> None:
    service = authed_harness.app.state.personal_app.state.web_runtime.agent.echo_safety_service
    expected = _append_real_artifact(
        service,
        owner=authed_harness.admin_owner,
        mode=AppMode.PERSONAL,
        session="session-active-with-v1-gap",
        run="run-active-with-v1-gap",
        workspace=None,
    )
    _write_v1_retired_checkpoint_with_gap(
        service,
        owner=authed_harness.admin_owner,
        session=expected.session,
        product_id="js-agent",
    )

    response = authed_harness.client.get("/api/appshell/artifacts")

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "partial"
    assert [item["digest"] for item in response.json()["items"]] == [expected.digest]
    assert response.json()["access_issues"] == [
        {
            "source": "echo_ledger",
            "code": "retired_artifacts_not_available",
            "safe_detail": "retired artifact history is unavailable",
        }
    ]
    assert authed_harness.admin_owner not in response.text


def test_session_and_private_artifact_acl_require_strict_filters(
    authed_harness: _Harness,
) -> None:
    service = authed_harness.app.state.personal_app.state.web_runtime.agent.echo_safety_service
    session_ref = _append_real_artifact(
        service,
        owner=authed_harness.admin_owner,
        mode=AppMode.PERSONAL,
        session="session-acl",
        run="run-session-acl",
        workspace=None,
        acl="session",
    )
    private_ref = _append_real_artifact(
        service,
        owner=authed_harness.admin_owner,
        mode=AppMode.PERSONAL,
        session="session-acl",
        run="run-private-acl",
        workspace=None,
        acl="private",
    )

    assert authed_harness.client.get("/api/appshell/artifacts").json()["items"] == []
    session_only = authed_harness.client.get(
        "/api/appshell/artifacts", params={"session": "session-acl"}
    ).json()["items"]
    assert [item["digest"] for item in session_only] == [session_ref.digest]
    exact_private = authed_harness.client.get(
        "/api/appshell/artifacts",
        params={"session": "session-acl", "run": "run-private-acl"},
    ).json()["items"]
    assert [item["digest"] for item in exact_private] == [private_ref.digest]


def test_artifact_acl_filtering_happens_before_public_limit(
    authed_harness: _Harness,
) -> None:
    service = authed_harness.app.state.personal_app.state.web_runtime.agent.echo_safety_service
    first_private = _append_artifact_batch(
        service,
        owner=authed_harness.admin_owner,
        session="session-limit-private",
        run="aa-private-run",
        acl="private",
        count=32,
        marker="limit-private-a",
    )
    _append_artifact_batch(
        service,
        owner=authed_harness.admin_owner,
        session="session-limit-private",
        run="ab-private-run",
        acl="private",
        count=18,
        marker="limit-private-b",
    )
    session_ref = _append_artifact_batch(
        service,
        owner=authed_harness.admin_owner,
        session="session-limit-visible",
        run="zc-session-run",
        acl="session",
        count=1,
        marker="limit-session",
    )[0]
    owner_ref = _append_artifact_batch(
        service,
        owner=authed_harness.admin_owner,
        session="session-limit-owner",
        run="zz-owner-run",
        acl="owner",
        count=1,
        marker="limit-owner",
    )[0]

    unfiltered = authed_harness.client.get("/api/appshell/artifacts")
    assert unfiltered.status_code == 200, unfiltered.text
    assert [item["uri"] for item in unfiltered.json()["items"]] == [owner_ref.uri]

    session_only = authed_harness.client.get(
        "/api/appshell/artifacts",
        params={"session": session_ref.session},
    )
    assert [item["uri"] for item in session_only.json()["items"]] == [session_ref.uri]

    exact_private = authed_harness.client.get(
        "/api/appshell/artifacts",
        params={
            "session": "session-limit-private",
            "run": "aa-private-run",
        },
    )
    assert exact_private.status_code == 200, exact_private.text
    assert {item["uri"] for item in exact_private.json()["items"]} == {
        ref.uri for ref in first_private
    }


def test_retired_owner_session_and_private_acl_remain_exact(
    authed_harness: _Harness,
) -> None:
    service = authed_harness.app.state.personal_app.state.web_runtime.agent.echo_safety_service
    service._ledger_config = EchoLedgerConfig(max_session_partitions_per_owner=2)
    session = "session-retired-acl"
    owner_ref = _append_real_artifact(
        service,
        owner=authed_harness.admin_owner,
        mode=AppMode.PERSONAL,
        session=session,
        run="run-retired-owner",
        workspace=None,
        marker="retired-owner",
        digest_char="3",
    )
    session_ref = _append_real_artifact(
        service,
        owner=authed_harness.admin_owner,
        mode=AppMode.PERSONAL,
        session=session,
        run="run-retired-session",
        workspace=None,
        acl="session",
        marker="retired-session",
        digest_char="4",
    )
    private_ref = _append_real_artifact(
        service,
        owner=authed_harness.admin_owner,
        mode=AppMode.PERSONAL,
        session=session,
        run="run-retired-private",
        workspace=None,
        acl="private",
        marker="retired-private",
        digest_char="5",
    )
    retired_journal = service.journal_path_for_scope(
        authed_harness.admin_owner,
        product_id="js-agent",
        session_id=session,
    )
    os.utime(retired_journal, ns=(1_000_000_000, 1_000_000_000))
    for index in range(2):
        _append_empty_effect(
            service,
            owner=authed_harness.admin_owner,
            mode=AppMode.PERSONAL,
            session=f"session-retired-acl-trigger-{index}",
            run=f"run-retired-acl-trigger-{index}",
            workspace=None,
        )
    assert not retired_journal.exists()

    global_items = authed_harness.client.get("/api/appshell/artifacts").json()["items"]
    assert [item["digest"] for item in global_items] == [owner_ref.digest]
    session_items = authed_harness.client.get(
        "/api/appshell/artifacts", params={"session": session}
    ).json()["items"]
    assert {item["digest"] for item in session_items} == {
        owner_ref.digest,
        session_ref.digest,
    }
    private_items = authed_harness.client.get(
        "/api/appshell/artifacts",
        params={"session": session, "run": private_ref.created_by_run},
    ).json()["items"]
    assert [item["digest"] for item in private_items] == [private_ref.digest]


def test_retired_work_workspace_ref_stays_in_exact_mode_and_workspace(
    authed_harness: _Harness,
) -> None:
    service = authed_harness.app.state.work_app.state.web_runtime.agent.echo_safety_service
    service._ledger_config = EchoLedgerConfig(max_session_partitions_per_owner=2)
    expected = _append_real_artifact(
        service,
        owner=authed_harness.admin_owner,
        mode=AppMode.WORK,
        session="session-retired-work",
        run="run-retired-work",
        workspace=authed_harness.work_handle,
        acl="workspace",
        marker="retired-workspace",
        digest_char="6",
    )
    retired_journal = service.journal_path_for_scope(
        authed_harness.admin_owner,
        product_id="js-work",
        session_id=expected.session,
    )
    os.utime(retired_journal, ns=(1_000_000_000, 1_000_000_000))
    for index in range(2):
        _append_empty_effect(
            service,
            owner=authed_harness.admin_owner,
            mode=AppMode.WORK,
            session=f"session-retired-work-trigger-{index}",
            run=f"run-retired-work-trigger-{index}",
            workspace=authed_harness.work_handle,
        )
    assert not retired_journal.exists()
    assert authed_harness.client.get("/api/appshell/artifacts").json()["items"] == []
    authed_harness.switch_to_work()
    response = authed_harness.client.get(
        "/api/appshell/artifacts", params={"mode": "work"}
    )
    assert response.status_code == 200, response.text
    assert [item["digest"] for item in response.json()["items"]] == [expected.digest]
    assert response.json()["items"][0]["workspace"] == authed_harness.work_handle


def test_work_workspace_artifact_comes_only_from_work_runtime(
    authed_harness: _Harness,
) -> None:
    personal_service = (
        authed_harness.app.state.personal_app.state.web_runtime.agent.echo_safety_service
    )
    work_service = authed_harness.app.state.work_app.state.web_runtime.agent.echo_safety_service
    _append_real_artifact(
        personal_service,
        owner=authed_harness.admin_owner,
        mode=AppMode.PERSONAL,
        session="session-personal-hidden",
        run="run-personal-hidden",
        workspace=None,
    )
    expected = _append_real_artifact(
        work_service,
        owner=authed_harness.admin_owner,
        mode=AppMode.WORK,
        session="session-work-artifact",
        run="run-work-artifact",
        workspace=authed_harness.work_handle,
        acl="workspace",
    )
    authed_harness.switch_to_work()

    response = authed_harness.client.get(
        "/api/appshell/artifacts",
        params={"mode": "work"},
    )
    assert response.status_code == 200, response.text
    assert [item["digest"] for item in response.json()["items"]] == [expected.digest]
    assert response.json()["items"][0]["workspace"] == authed_harness.work_handle
    assert response.json()["items"][0]["acl"] == "workspace"
    assert "run-personal-hidden" not in response.text


def test_artifact_cross_owner_receipt_is_not_visible(
    authed_harness: _Harness,
) -> None:
    service = authed_harness.app.state.personal_app.state.web_runtime.agent.echo_safety_service
    service._ledger_config = EchoLedgerConfig(max_session_partitions_per_owner=2)
    hidden = _append_real_artifact(
        service,
        owner=authed_harness.second_owner,
        mode=AppMode.PERSONAL,
        session="same-session-artifact",
        run="same-run-artifact",
        workspace=None,
    )
    hidden_journal = service.journal_path_for_scope(
        authed_harness.second_owner,
        product_id="js-agent",
        session_id=hidden.session,
    )
    os.utime(hidden_journal, ns=(1_000_000_000, 1_000_000_000))
    for index in range(2):
        _append_empty_effect(
            service,
            owner=authed_harness.second_owner,
            mode=AppMode.PERSONAL,
            session=f"same-owner-retire-trigger-{index}",
            run=f"same-owner-retire-run-{index}",
            workspace=None,
        )
    assert not hidden_journal.exists()

    response = authed_harness.client.get("/api/appshell/artifacts")
    assert response.status_code == 200, response.text
    assert response.json()["items"] == []
    assert authed_harness.second_owner not in response.text


def test_inbox_partial_and_blocked_statuses_are_exact_and_desensitized(
    authed_harness: _Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = authed_harness.app.state.personal_app.state.web_runtime.agent

    def unavailable(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("private path and owner details must not escape")

    monkeypatch.setattr(agent.approvals, "get_pending", unavailable)
    partial = authed_harness.client.get("/api/appshell/inbox")
    assert partial.status_code == 200, partial.text
    assert partial.json()["status"] == "partial"
    assert partial.json()["items"] == []
    assert partial.json()["access_issues"] == [
        {
            "source": "tool_approvals",
            "code": "source_unavailable",
            "safe_detail": "projection source unavailable",
        }
    ]
    assert "private path" not in partial.text

    monkeypatch.setattr(agent.echo_safety_service, "list_manual_reviews", unavailable)
    monkeypatch.setattr(agent.memory, "list_proposals", unavailable)
    monkeypatch.setattr(agent.memory, "list_compression_proposals", unavailable)
    blocked = authed_harness.client.get("/api/appshell/inbox")
    assert blocked.status_code == 503, blocked.text
    assert blocked.json()["status"] == "blocked"
    assert blocked.json()["items"] == []
    assert len(blocked.json()["access_issues"]) == 4
    assert blocked.headers["cache-control"] == "no-store"


def test_artifact_authority_failure_is_blocked_503(
    authed_harness: _Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = authed_harness.app.state.personal_app.state.web_runtime.agent.echo_safety_service

    def unavailable(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("ledger private location")

    monkeypatch.setattr(service, "project_verified_artifacts", unavailable)
    response = authed_harness.client.get("/api/appshell/artifacts")
    assert response.status_code == 503
    assert response.json()["status"] == "blocked"
    assert response.json()["items"] == []
    assert response.json()["access_issues"] == [
        {
            "source": "echo_ledger",
            "code": "source_unavailable",
            "safe_detail": "projection source unavailable",
        }
    ]
    assert "private location" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_corrupt_retired_catalog_blocks_active_artifacts_and_returns_503(
    authed_harness: _Harness,
) -> None:
    service = authed_harness.app.state.personal_app.state.web_runtime.agent.echo_safety_service
    service._ledger_config = EchoLedgerConfig(max_session_partitions_per_owner=2)
    _append_real_artifact(
        service,
        owner=authed_harness.admin_owner,
        mode=AppMode.PERSONAL,
        session="session-retired-corrupt",
        run="run-retired-corrupt",
        workspace=None,
        marker="retired-corrupt",
        digest_char="7",
    )
    retired_journal = service.journal_path_for_scope(
        authed_harness.admin_owner,
        product_id="js-agent",
        session_id="session-retired-corrupt",
    )
    os.utime(retired_journal, ns=(1_000_000_000, 1_000_000_000))
    _append_empty_effect(
        service,
        owner=authed_harness.admin_owner,
        mode=AppMode.PERSONAL,
        session="session-corrupt-existing",
        run="run-corrupt-existing",
        workspace=None,
    )
    active_ref = _append_real_artifact(
        service,
        owner=authed_harness.admin_owner,
        mode=AppMode.PERSONAL,
        session="session-corrupt-active",
        run="run-corrupt-active",
        workspace=None,
        marker="corrupt-active",
        digest_char="8",
    )
    assert not retired_journal.exists()
    checkpoint_path = service.journal_path_for_scope(
        authed_harness.admin_owner,
        product_id="js-agent",
        session_id=active_ref.session,
    ).parent.parent / "retired-sessions.json"
    row = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    row["mac"] = ("0" if row["mac"][0] != "0" else "1") + row["mac"][1:]
    checkpoint_path.write_text(
        json.dumps(row, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    response = authed_harness.client.get("/api/appshell/artifacts")

    assert response.status_code == 503
    assert response.json()["status"] == "blocked"
    assert response.json()["items"] == []
    assert response.json()["access_issues"][0]["safe_detail"] == (
        "projection source unavailable"
    )
    assert active_ref.digest not in response.text


def test_client_cannot_submit_owner_product_or_workspace_authority(
    authed_harness: _Harness,
) -> None:
    for field, value in (
        ("owner", authed_harness.second_owner),
        ("product", "js-work"),
        ("workspace", "/private/workspace"),
    ):
        response = authed_harness.client.get(
            "/api/appshell/inbox",
            params={field: value},
        )
        assert response.status_code == 400
        assert response.json() == {
            "detail": {"code": "unsupported_projection_parameter"}
        }
        assert response.headers["cache-control"] == "no-store"


def test_projection_operation_blocks_successful_switch_until_read_finishes(
    authed_harness: _Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = authed_harness.app.state.personal_app.state.web_runtime.agent
    original = agent.approvals.get_pending
    entered = threading.Event()
    release = threading.Event()
    call_lock = threading.Lock()
    call_count = 0

    def blocking_get_pending(*, owner_key_hash: str | None = None) -> Any:
        nonlocal call_count
        with call_lock:
            call_count += 1
            current = call_count
        if current == 1:
            entered.set()
            assert release.wait(timeout=5)
        return original(owner_key_hash=owner_key_hash)

    monkeypatch.setattr(agent.approvals, "get_pending", blocking_get_pending)
    inbox_result: dict[str, Any] = {}
    switch_result: dict[str, Any] = {}

    def read_inbox() -> None:
        inbox_result["response"] = authed_harness.client.get("/api/appshell/inbox")

    def switch_mode() -> None:
        switch_result["response"] = authed_harness.client.post(
            "/api/appshell/switch",
            json={
                "expected_from_mode": "personal",
                "to_mode": "work",
                "session_id": None,
                "workspace_handle": authed_harness.work_handle,
            },
        )

    inbox_thread = threading.Thread(target=read_inbox, daemon=True)
    inbox_thread.start()
    assert entered.wait(timeout=5)
    switch_thread = threading.Thread(target=switch_mode, daemon=True)
    switch_thread.start()
    time.sleep(0.1)
    assert switch_thread.is_alive(), "switch committed while projection read was still active"
    release.set()
    inbox_thread.join(timeout=5)
    switch_thread.join(timeout=5)
    assert not inbox_thread.is_alive()
    assert not switch_thread.is_alive()
    assert inbox_result["response"].status_code == 200
    assert switch_result["response"].status_code == 200


def test_settings_and_deferred_surfaces_keep_existing_parent_contracts(
    authed_harness: _Harness,
) -> None:
    settings = authed_harness.client.get("/api/appshell/settings")
    assert settings.status_code == 200
    assert settings.json()["sections"] == ["global", "personal", "work"]
    for path, feature in (
        ("/api/appshell/devices", "devices"),
        ("/api/appshell/friends", "friends"),
    ):
        response = authed_harness.client.get(path)
        assert response.status_code == 404
        assert response.json() == {
            "detail": {"code": "feature_not_enabled", "feature": feature}
        }
