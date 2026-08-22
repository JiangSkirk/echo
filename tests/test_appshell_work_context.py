"""B3: Work Context projection — closed DTOs, session/run binding, ACL.

Negative-first tests for the dedicated ``js/appshell/work_context.py``
projection. The Inbox projection stays separate; WorkContextEnvelopeV1 is a
closed schema with fail-closed unknown fields.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from js.appshell.inbox import ProjectionAuthorityV1
from js.appshell.work_context import (
    WorkContextEnvelopeV1,
    WorkContextError,
    WorkContextSummaryV1,
    WorkFileRefV1,
    WorkTaskStatusV1,
    list_work_context,
)
from js.echo.mode_contract import AppMode

# ── DTO closed-set contracts ────────────────────────────────


class TestWorkFileRef:
    def test_round_trip(self) -> None:
        ref = WorkFileRefV1(root="uploads", path="data/report.xlsx")
        assert WorkFileRefV1.from_dict(ref.to_dict()) == ref

    @pytest.mark.parametrize(
        "bad_path",
        [
            "/Users/alice/secret.xlsx",
            "/etc/passwd",
            "../escape.txt",
            "a/../../b.txt",
            "C:\\windows\\system32",
            "back\\slash\\path.txt",
            "",
            "a//b.txt",
        ],
    )
    def test_absolute_or_escaping_paths_rejected(self, bad_path: str) -> None:
        with pytest.raises(WorkContextError):
            WorkFileRefV1(root="uploads", path=bad_path)

    def test_from_dict_rejects_absolute_path(self) -> None:
        with pytest.raises(WorkContextError):
            WorkFileRefV1.from_dict(
                {"schema_version": 1, "root": "uploads", "path": "/Users/x/y.txt"}
            )

    def test_unknown_field_fail_closed(self) -> None:
        with pytest.raises(WorkContextError):
            WorkFileRefV1.from_dict(
                {
                    "schema_version": 1,
                    "root": "uploads",
                    "path": "a.txt",
                    "owner": "forged",
                }
            )

    def test_cannot_subclass(self) -> None:
        with pytest.raises(TypeError):

            class _Evil(WorkFileRefV1):  # type: ignore[misc]
                pass


class TestWorkTaskStatus:
    def test_round_trip(self) -> None:
        task = WorkTaskStatusV1(
            task_id="t-1",
            title="整理报表",
            status="running",
            session="s-1",
            run="r-1",
            progress=0.5,
        )
        assert WorkTaskStatusV1.from_dict(task.to_dict()) == task

    def test_invalid_status_rejected(self) -> None:
        with pytest.raises(WorkContextError):
            WorkTaskStatusV1(
                task_id="t-1", title="x", status="exploding", session=None, run=None,
                progress=0.0,
            )

    def test_progress_bounds(self) -> None:
        with pytest.raises(WorkContextError):
            WorkTaskStatusV1(
                task_id="t-1", title="x", status="running", session=None, run=None,
                progress=1.5,
            )


class TestWorkContextSummary:
    def test_grants_count_only_when_bound(self) -> None:
        with pytest.raises(WorkContextError):
            WorkContextSummaryV1(
                workspace="ws-x",
                grants_state="unavailable",
                grants_count=2,
                write_policy="unknown",
            )

    def test_round_trip(self) -> None:
        summary = WorkContextSummaryV1(
            workspace="ws-x",
            grants_state="unavailable",
            grants_count=None,
            write_policy="unknown",
        )
        assert WorkContextSummaryV1.from_dict(summary.to_dict()) == summary


class TestEnvelope:
    def test_full_round_trip(self) -> None:
        envelope = WorkContextEnvelopeV1(
            status="partial",
            workspace_summary=WorkContextSummaryV1(
                workspace="ws-x",
                grants_state="unavailable",
                grants_count=None,
                write_policy="unknown",
            ),
            files=(WorkFileRefV1(root="uploads", path="a.txt"),),
            artifacts=(),
            attention_items=(),
            current_task=None,
            access_issues=(),
            source_watermark={"mode": "work"},
        )
        payload = envelope.to_dict()
        assert payload["schema"] == "WorkContextEnvelopeV1"
        assert WorkContextEnvelopeV1.from_dict(payload) == envelope

    def test_unknown_top_level_field_fail_closed(self) -> None:
        envelope = WorkContextEnvelopeV1(
            status="ok",
            workspace_summary=None,
            files=(),
            artifacts=(),
            attention_items=(),
            current_task=None,
            access_issues=(),
            source_watermark={},
        )
        payload = envelope.to_dict()
        payload["product"] = "forged"
        with pytest.raises(WorkContextError):
            WorkContextEnvelopeV1.from_dict(payload)


# ── Projector unit tests with stub authority ────────────────


class _StubApprovals:
    def __init__(self, pending: list[Any]) -> None:
        self._pending = pending

    def get_pending(self, owner_key_hash: str) -> list[Any]:
        return list(self._pending)

    def pending_arguments_hash(self, request_id: str, owner_key_hash: str) -> str:
        return "sha256:" + "ab" * 32


@dataclass
class _StubApprovalRequest:
    id: str
    owner_key_hash: str
    session_id: str
    run_id: str
    timestamp: float
    timeout_seconds: float


class _StubAgent:
    def __init__(
        self,
        approvals: Any = None,
        task_rows: list[dict[str, Any]] | None = None,
        lifecycle_rows: dict[tuple[str, str], dict[str, Any]] | None = None,
    ) -> None:
        self.approvals = approvals or _StubApprovals([])
        self._task_rows = task_rows or []
        self._lifecycle_rows = lifecycle_rows or {}
        self.memory = None

    @property
    def task_manager(self) -> Any:
        rows = self._task_rows

        class _TM:
            def list(self, status: Any = None, type: Any = None, limit: int = 100, owner_key_hash: str = "") -> list[dict[str, Any]]:
                return list(rows)

        return _TM()

    @property
    def lifecycle_store(self) -> Any:
        rows = self._lifecycle_rows

        class _Lifecycle:
            def get(self, session_id: str, owner_key_hash: str) -> dict[str, Any] | None:
                return rows.get((owner_key_hash, session_id))

        return _Lifecycle()


class _BrokenEchoService:
    def project_verified_artifacts(self, **kwargs: Any) -> Any:
        raise OSError("ledger down")


class _EmptyEchoService:
    class _Projection:
        refs: tuple = ()
        retired_history_complete = True

    def project_verified_artifacts(self, **kwargs: Any) -> Any:
        return self._Projection()


def _authority(
    *,
    mode: AppMode = AppMode.WORK,
    workspace: str | None = "ws-handle",
    agent: Any = None,
    echo: Any = None,
) -> ProjectionAuthorityV1:
    return ProjectionAuthorityV1(
        mode=mode,
        owner="owner-hash",
        workspace=workspace,
        parent_session="parent-session",
        role="admin",
        agent=agent or _StubAgent(),
        echo_safety_service=echo or _EmptyEchoService(),
    )


class TestProjectorAcl:
    def test_personal_authority_rejected(self) -> None:
        with pytest.raises(ValueError):
            list_work_context(
                _authority(mode=AppMode.PERSONAL, workspace=None),
                session="s-1",
            )

    def test_session_required(self) -> None:
        with pytest.raises(ValueError):
            list_work_context(_authority(), session="")

    def test_unknown_run_fail_closed(self) -> None:
        with pytest.raises(ValueError):
            list_work_context(_authority(), session="s-1", run="forged-run")

    def test_attention_filtered_to_session(self) -> None:
        req_mine = _StubApprovalRequest(
            id="req-1",
            owner_key_hash="owner-hash",
            session_id="s-1",
            run_id="r-1",
            timestamp=1_700_000_000.0,
            timeout_seconds=86_400.0,
        )
        req_other = _StubApprovalRequest(
            id="req-2",
            owner_key_hash="owner-hash",
            session_id="s-other",
            run_id="r-9",
            timestamp=1_700_000_000.0,
            timeout_seconds=86_400.0,
        )
        agent = _StubAgent(approvals=_StubApprovals([req_mine, req_other]))
        envelope = list_work_context(_authority(agent=agent), session="s-1")
        sessions = {item.session for item in envelope.attention_items}
        assert sessions == {"s-1"}

    def test_all_sources_failed_is_blocked_not_empty_ok(self) -> None:
        class _AllBrokenAgent:
            @property
            def approvals(self) -> Any:
                raise OSError("approvals down")

            @property
            def task_manager(self) -> Any:
                raise OSError("tasks down")

            memory = None

        envelope = list_work_context(
            _authority(agent=_AllBrokenAgent(), echo=_BrokenEchoService()),
            session="s-1",
        )
        assert envelope.status == "blocked"
        assert envelope.files == ()
        assert envelope.access_issues

    def test_grants_honestly_unavailable(self) -> None:
        envelope = list_work_context(_authority(), session="s-1")
        assert envelope.workspace_summary is not None
        assert envelope.workspace_summary.grants_state == "unavailable"
        assert envelope.workspace_summary.grants_count is None
        grant_issues = [
            issue for issue in envelope.access_issues if issue.source == "directory_grants"
        ]
        assert grant_issues, "missing honest directory-grant access issue"

    def test_current_task_bound_to_session(self) -> None:
        agent = _StubAgent(
            lifecycle_rows={
                ("owner-hash", "s-1"): {
                    "session_id": "s-1",
                    "owner_key_hash": "owner-hash",
                    "run_id": "r-1",
                    "status": "running",
                },
                ("owner-hash", "s-other"): {
                    "session_id": "s-other",
                    "owner_key_hash": "owner-hash",
                    "run_id": "r-other",
                    "status": "running",
                },
            }
        )
        envelope = list_work_context(_authority(agent=agent), session="s-1")
        assert envelope.current_task is not None
        assert envelope.current_task.task_id == "r-1"
        assert envelope.current_task.session == "s-1"
        assert envelope.current_task.run == "r-1"


# ── HTTP surface via the real AppShell app ──────────────────

_SHARED_KEY = "js_wc-shared-appshell-test-key"


def _install_key(state_dir: Path, key: str, *, name: str, role: str) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    with sqlite3.connect(state_dir / "api_keys.db") as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS api_keys "
            "(key_hash TEXT PRIMARY KEY, name TEXT, role TEXT, created_at REAL, enabled INTEGER)"
        )
        connection.execute(
            "INSERT INTO api_keys (key_hash, name, role, created_at, enabled) "
            "VALUES (?, ?, ?, 1.0, 1)",
            (key_hash, name, role),
        )
        connection.commit()


@dataclass
class _Harness:
    client: TestClient
    work_handle: str

    def login(self) -> None:
        response = self.client.post(
            "/api/appshell/session",
            headers={"X-API-Key": _SHARED_KEY},
        )
        assert response.status_code == 200, response.text

    def switch_to_work(self) -> None:
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


@pytest.fixture()
def appshell(tmp_path: Path) -> Any:
    from js.appshell.server import create_appshell_app
    from js.echo.turn_runtime import _workspace_handle
    from js_work.tools import WorkToolProfile

    personal_state = tmp_path / "personal-state"
    work_home = tmp_path / "work-home"
    work_state = work_home / ".js-work" / "state"
    work_workspace = work_home / ".js-work" / "workspace"
    personal_config = tmp_path / "personal.yaml"
    personal_config.write_text(
        yaml.safe_dump(
            {
                "state_dir": str(personal_state),
                "workspace": str(tmp_path / "personal-workspace"),
                "echo_engine": "on",
                "first_run_completed": True,
                "security": {"api_key_required": True},
                "providers": [],
                "models": [],
            }
        ),
        encoding="utf-8",
    )
    work_config = tmp_path / "work.yaml"
    work_config.write_text(
        yaml.safe_dump(
            {
                "state_dir": str(work_state),
                "workspace": str(work_workspace),
                "echo_engine": "on",
                "first_run_completed": True,
                "security": {"api_key_required": True},
                "providers": [],
                "models": [],
            }
        ),
        encoding="utf-8",
    )
    _install_key(personal_state, _SHARED_KEY, name="wc-owner", role="admin")
    _install_key(work_state, _SHARED_KEY, name="wc-owner", role="admin")

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
        client=("127.0.0.1", 50123),
    ) as client:
        yield _Harness(client=client, work_handle=_workspace_handle(work_workspace))


class TestWorkContextEndpoint:
    def test_real_work_lifecycle_projects_current_run(self, appshell: _Harness) -> None:
        appshell.login()
        appshell.switch_to_work()
        owner = hashlib.sha256(_SHARED_KEY.encode("utf-8")).hexdigest()
        work_agent = appshell.client.app.state.work_app.state.web_runtime.agent
        work_agent.lifecycle_store.mark_started("s-live", owner, "r-live")

        response = appshell.client.get(
            "/api/appshell/work-context", params={"session_id": "s-live"}
        )

        assert response.status_code == 200, response.text
        task = response.json()["current_task"]
        assert task == {
            "schema_version": 1,
            "task_id": "r-live",
            "title": "当前工作任务",
            "status": "running",
            "session": "s-live",
            "run": "r-live",
            "progress": 0.0,
        }

    def test_unauthenticated_fails_closed(self, appshell: _Harness) -> None:
        response = appshell.client.get(
            "/api/appshell/work-context", params={"session_id": "s-1"}
        )
        assert response.status_code == 401

    def test_personal_mode_forbidden(self, appshell: _Harness) -> None:
        appshell.login()
        response = appshell.client.get(
            "/api/appshell/work-context", params={"session_id": "s-1"}
        )
        assert response.status_code == 403

    def test_session_id_required(self, appshell: _Harness) -> None:
        appshell.login()
        appshell.switch_to_work()
        response = appshell.client.get("/api/appshell/work-context")
        assert response.status_code == 400

    def test_unknown_query_param_rejected(self, appshell: _Harness) -> None:
        appshell.login()
        appshell.switch_to_work()
        response = appshell.client.get(
            "/api/appshell/work-context",
            params={"session_id": "s-1", "workspace": "forged"},
        )
        assert response.status_code == 400

    def test_owner_product_fields_cannot_be_forged(self, appshell: _Harness) -> None:
        appshell.login()
        appshell.switch_to_work()
        response = appshell.client.get(
            "/api/appshell/work-context",
            params={"session_id": "s-1", "owner": "evil", "product": "js-work"},
        )
        assert response.status_code == 400

    def test_work_mode_returns_closed_envelope(self, appshell: _Harness) -> None:
        appshell.login()
        appshell.switch_to_work()
        response = appshell.client.get(
            "/api/appshell/work-context", params={"session_id": "s-1"}
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["schema"] == "WorkContextEnvelopeV1"
        assert payload["status"] in {"ok", "partial"}
        summary = payload["workspace_summary"]
        assert summary["workspace"] == appshell.work_handle
        assert summary["grants_state"] in {"none", "unavailable"}
        assert summary["grants_count"] is None
        # No absolute paths may ever appear.
        for item in payload["files"]:
            assert not item["path"].startswith("/")
            assert ".." not in item["path"].split("/")
        assert set(payload) <= {
            "schema",
            "status",
            "workspace_summary",
            "files",
            "artifacts",
            "attention_items",
            "current_task",
            "access_issues",
            "source_watermark",
        }

    def test_unknown_run_fail_closed(self, appshell: _Harness) -> None:
        appshell.login()
        appshell.switch_to_work()
        response = appshell.client.get(
            "/api/appshell/work-context",
            params={"session_id": "s-1", "run_id": "forged-run"},
        )
        assert response.status_code == 409
