"""WP10 integration: one durable membrane for File and Connector Cells.

The tests in this module deliberately cross the real client socket and the
authenticated ``cells.sock`` boundary.  Fault injection happens only after
the target Cell has replied (response loss) or after COMMITTING is durable but
before dispatch.  That distinction pins the no-blind-retry recovery contract.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sqlite3
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from js.echo.capability import LeaseDenied
from js.orin.client import OrinLeaseClientAdapter, OrinUnavailable
from js.orin.draft import EffectDraft, ExactCommitApprovalV1, ExportPass
from js.orin.intent import Budgets, IntentEnvelope
from js.orin.testing import TestOrind
from js.orind.membrane import AdmissionBackpressure


class _InjectedCrashError(RuntimeError):
    """Deterministic crash raised from a persisted membrane fault boundary."""


class _CrashAt:
    def __init__(self, target: str) -> None:
        self.target = target
        self.seen: list[tuple[str, str]] = []
        self.fired = False

    def __call__(self, label: str, draft_id: str) -> None:
        self.seen.append((label, draft_id))
        if label == self.target and not self.fired:
            self.fired = True
            raise _InjectedCrashError(label)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _pub_of(key: ed25519.Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _adapter(orind: TestOrind) -> OrinLeaseClientAdapter:
    return OrinLeaseClientAdapter(
        socket_path=orind.socket_path,
        state_dir=Path(orind.daemon._state_dir),  # noqa: SLF001 - boundary probe
        stage_b=True,
    )


def _wait_for_cells(orind: TestOrind, caps: tuple[str, ...]) -> None:
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        if all(orind.daemon._cell_by_cap(cap) is not None for cap in caps):  # noqa: SLF001
            return
        time.sleep(0.1)
    pytest.fail(f"Cell subprocesses did not connect: {caps!r}")


def _start_orind(
    state_dir: Path,
    witness_key: ed25519.Ed25519PrivateKey,
    *,
    cell_file: bool = False,
    cell_connector: bool = False,
    cell_build: bool = False,
    commit_membrane: bool = True,
    membrane_fault_hook: Callable[[str, str], None] | None = None,
) -> TestOrind:
    orind = TestOrind(
        state_dir=state_dir,
        stage_b=True,
        cell_build=cell_build,
        cell_file=cell_file,
        cell_net=cell_connector,
        commit_membrane=commit_membrane,
        membrane_fault_hook=membrane_fault_hook,
        witness_public_keys=(_pub_of(witness_key),),
    )
    orind.start()
    caps: list[str] = []
    if cell_build:
        caps.append("cell.build")
    if cell_file:
        caps.append("cell.file")
    if cell_connector:
        caps.append("cell.connector")
    _wait_for_cells(orind, tuple(caps))
    return orind


def _issue_handle(
    orind: TestOrind,
    *,
    kind: str,
    token: str,
    owner: str,
    tenant: str,
    object_digest: str = "",
    capabilities: tuple[str, ...],
) -> str:
    issued = orind.daemon._broker.issue(  # noqa: SLF001 - approval-channel stand-in
        kind=kind,
        token=token,
        owner_key_hash=owner,
        tenant=tenant,
        object_digest=object_digest,
        capabilities=capabilities,
        approved=True,
    )
    assert issued["ok"] is True
    return str(issued["handle"]["handle_id"])


def _register_intent(
    adapter: OrinLeaseClientAdapter,
    witness_key: ed25519.Ed25519PrivateKey,
    *,
    task_id: str,
    owner: str,
    profile: str,
    effect_type: str,
    resource_handles: tuple[str, ...] = (),
    sink_handles: tuple[str, ...] = (),
    max_invocations: int = 8,
    max_bytes_out: int = 1 << 20,
) -> None:
    now = _now_ms()
    intent = IntentEnvelope(
        intent_id=f"intent:{uuid4().hex}",
        owner_key_hash=owner,
        product_id="js-agent",
        profile=profile,
        task_id=task_id,
        raw_request_hash="sha256:" + "8" * 64,
        allowed_effect_classes=(effect_type,),
        allowed_resource_handles=resource_handles,
        allowed_sink_handles=sink_handles,
        budgets=Budgets(
            max_invocations=max_invocations,
            max_bytes_out=max_bytes_out,
        ),
        approval_policy=(
            "preauthorized_exact_template"
            if profile == "work"
            else "exact_commit_required"
        ),
        issued_by="appshell:wp10-test",
        issued_at_ms=now - 1_000,
        expires_at_ms=now + 120_000,
    ).sign_with(witness_key)
    assert adapter.register_intent(intent.to_dict())["ok"] is True


def _prepare_file(
    orind: TestOrind,
    witness_key: ed25519.Ed25519PrivateKey,
    owner_root: Path,
    *,
    content: str = "membrane-file-content\n",
) -> tuple[OrinLeaseClientAdapter, EffectDraft, Path]:
    owner_root.mkdir(parents=True, exist_ok=True)
    owner = "sha256:" + "4" * 64
    handle_id = _issue_handle(
        orind,
        kind="DirectoryHandle",
        token=uuid4().hex,
        owner=owner,
        tenant="work",
        object_digest=str(owner_root.resolve()),
        capabilities=("read", "stage", "write"),
    )
    adapter = _adapter(orind)
    task_id = f"task:{uuid4().hex}"
    _register_intent(
        adapter,
        witness_key,
        task_id=task_id,
        owner=owner,
        profile="work",
        effect_type="file.commit",
        resource_handles=(handle_id,),
    )
    draft = EffectDraft(
        draft_id=f"draft:{uuid4().hex}",
        task_id=task_id,
        effect_type="file.commit",
        arguments={
            "directory_handle": handle_id,
            "changes": [{"path": "nested/result.txt", "content": content}],
        },
        declared_expectation={
            "external_visibility": "private",
            "reversibility": "reversible_until_stage",
        },
    )
    proposed = adapter.submit_draft(draft.to_dict())
    assert proposed["verdict"] == "deny_missing_witness"
    preflight = adapter.preflight_draft(draft.draft_id, executor_id="cell.file")
    assert preflight["ok"] is True
    target = owner_root / "nested" / "result.txt"
    assert not target.exists(), "preflight may stage but must not write the owner root"
    return adapter, draft, target


def _prepare_connector(
    orind: TestOrind,
    witness_key: ed25519.Ed25519PrivateKey,
    *,
    profile: str,
    body: str = "membrane-exact-body",
) -> tuple[OrinLeaseClientAdapter, EffectDraft, ExportPass]:
    owner = "sha256:" + "1" * 64
    recipient_id = _issue_handle(
        orind,
        kind="RecipientHandle",
        token=f"wp10-{uuid4().hex}",
        owner=owner,
        tenant=profile,
        capabilities=("send",),
    )
    adapter = _adapter(orind)
    task_id = f"task:{uuid4().hex}"
    _register_intent(
        adapter,
        witness_key,
        task_id=task_id,
        owner=owner,
        profile=profile,
        effect_type="email.send_exact",
        sink_handles=() if profile == "personal" else (recipient_id,),
    )
    draft = EffectDraft(
        draft_id=f"draft:{uuid4().hex}",
        task_id=task_id,
        effect_type="email.send_exact",
        arguments={
            "recipient_handle": recipient_id,
            "subject": "WP10 exact subject",
            "body_draft": body,
        },
        declared_expectation={"external_visibility": "named_recipients"},
    )
    proposed = adapter.submit_draft(draft.to_dict())
    assert proposed["verdict"] == "deny_missing_witness"
    preflight = adapter.preflight_draft(draft.draft_id, executor_id="cell.connector")
    assert preflight["ok"] is True
    witness = preflight["witness"]
    export_pass = ExportPass(
        pass_id=f"export:{uuid4().hex}",
        task_id=task_id,
        payload_hash=str(proposed["payload_hash"]),
        destination_handles=(recipient_id,),
        witness_id=str(witness["witness_id"]),
        created_at_ms=_now_ms(),
        expires_at_ms=_now_ms() + 120_000,
    ).sign_with(witness_key)
    assert adapter.grant_export(export_pass.to_dict(), task_id=task_id)["ok"] is True
    return adapter, draft, export_pass


def _consume_raw(adapter: OrinLeaseClientAdapter, draft_id: str) -> dict[str, Any]:
    return adapter._call(  # noqa: SLF001 - inspect the complete Echo-visible ack
        lambda: adapter._request(  # noqa: SLF001
            "consume",
            mode="cell",
            payload={"draft_id": draft_id},
        )
    )


def _consume_wire_response(adapter: OrinLeaseClientAdapter, draft_id: str) -> dict[str, Any]:
    """Return the authenticated ack without translating its error code."""

    async def request() -> dict[str, Any]:
        connection = await adapter._connection()  # noqa: SLF001 - wire mapping probe
        return await connection.request(
            "consume",
            mode="cell",
            payload={"draft_id": draft_id},
        )

    return dict(adapter._call(request))  # noqa: SLF001 - sync adapter loop


def _expect_interrupted_consume(adapter: OrinLeaseClientAdapter, draft_id: str) -> None:
    with pytest.raises((LeaseDenied, OrinUnavailable, TimeoutError, _InjectedCrashError)):
        _consume_raw(adapter, draft_id)


def _operation(orind: TestOrind, draft_id: str) -> Any:
    membrane = orind.daemon.membrane
    assert membrane is not None
    operation = membrane.operation_for_draft(draft_id)
    assert operation is not None
    return operation


def _outbox_records(state_dir: Path) -> tuple[dict[str, Any], ...]:
    path = state_dir / "orin" / "connector_outbox.jsonl"
    if not path.exists():
        return ()
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        assert isinstance(value, dict)
        records.append(value)
    return tuple(records)


def _file_marker(path: Path) -> tuple[bytes, int, int] | None:
    if not path.exists():
        return None
    stat = path.stat()
    return (path.read_bytes(), stat.st_ino, stat.st_mtime_ns)


def _effect_marker(kind: str, state_dir: Path, target: Path | None) -> object:
    if kind == "connector":
        return _outbox_records(state_dir)
    assert target is not None
    return _file_marker(target)


def _assert_one_effect(kind: str, state_dir: Path, target: Path | None) -> None:
    marker = _effect_marker(kind, state_dir, target)
    if kind == "connector":
        assert isinstance(marker, tuple)
        assert len(marker) == 1
        return
    assert isinstance(marker, tuple)
    assert marker[0] == b"membrane-file-content\n"


def _assert_safe_receipted_ack(response: dict[str, Any], *, secret_text: str) -> None:
    assert response["receipt_id"].startswith("receipt:")
    cell = response["cell"]
    assert cell["status"] in {"COMMITTED", "RECONCILED_COMMITTED"}
    assert "commit_guarantee" not in cell

    def all_keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | {key for item in value.values() for key in all_keys(item)}
        if isinstance(value, list):
            return {key for item in value for key in all_keys(item)}
        return set()

    keys = all_keys(response)
    assert {"package", "permit", "permit_id", "resolved_handles"}.isdisjoint(keys)
    assert secret_text not in json.dumps(response, sort_keys=True)


def _budget_usage(state_dir: Path, task_id: str) -> tuple[int, int, int]:
    with sqlite3.connect(state_dir / "orin" / "orind_state.db") as connection:
        row = connection.execute(
            "SELECT invocations, bytes_out, sequence FROM effect_budget_usage WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    assert row is not None
    return (int(row[0]), int(row[1]), int(row[2]))


def _pass_state(state_dir: Path, pass_id: str) -> tuple[int, int]:
    with sqlite3.connect(state_dir / "orin" / "orind_state.db") as connection:
        row = connection.execute(
            "SELECT revoked, claimed_at_ms FROM export_passes WHERE pass_id = ?",
            (pass_id,),
        ).fetchone()
    assert row is not None
    return (int(row[0]), int(row[1]))


class TestSharedMembrane:
    def test_file_and_connector_share_one_receipting_membrane(self, tmp_path: Path) -> None:
        state_dir = tmp_path / "state"
        witness_key = ed25519.Ed25519PrivateKey.generate()
        orind = _start_orind(
            state_dir,
            witness_key,
            cell_file=True,
            cell_connector=True,
        )
        file_adapter: OrinLeaseClientAdapter | None = None
        connector_adapter: OrinLeaseClientAdapter | None = None
        try:
            file_adapter, file_draft, target = _prepare_file(
                orind,
                witness_key,
                tmp_path / "owner",
            )
            connector_adapter, connector_draft, _export = _prepare_connector(
                orind,
                witness_key,
                profile="work",
            )
            file_response = _consume_raw(file_adapter, file_draft.draft_id)
            connector_response = _consume_raw(connector_adapter, connector_draft.draft_id)

            file_operation = _operation(orind, file_draft.draft_id)
            connector_operation = _operation(orind, connector_draft.draft_id)
            assert file_operation.state == "RECEIPTED"
            assert connector_operation.state == "RECEIPTED"
            assert file_operation.executor_id == "cell.file"
            assert connector_operation.executor_id == "cell.connector"
            assert file_operation.operation_id != connector_operation.operation_id
            assert target.read_text(encoding="utf-8") == "membrane-file-content\n"
            assert len(_outbox_records(state_dir)) == 1
            _assert_safe_receipted_ack(
                file_response,
                secret_text="membrane-file-content",
            )
            _assert_safe_receipted_ack(
                connector_response,
                secret_text="membrane-exact-body",
            )
        finally:
            if file_adapter is not None:
                file_adapter.close()
            if connector_adapter is not None:
                connector_adapter.close()
            orind.stop()


class TestCrashRecovery:
    def test_file_authority_paths_never_use_broad_active_envelope(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state_dir = tmp_path / "state"
        witness_key = ed25519.Ed25519PrivateKey.generate()
        crash = _CrashAt("after_prepared_tx")
        orind = _start_orind(
            state_dir,
            witness_key,
            cell_file=True,
            membrane_fault_hook=crash,
        )
        adapter: OrinLeaseClientAdapter | None = None
        try:
            intents = orind.daemon._intents  # noqa: SLF001
            assert intents is not None
            original_effective_grant = intents.effective_grant
            effective_calls: list[str] = []

            def effective_grant(task_id: str, *, now_ms: int) -> Any:
                effective_calls.append(task_id)
                return original_effective_grant(task_id, now_ms=now_ms)

            def forbidden_active(*_args: Any, **_kwargs: Any) -> Any:
                raise AssertionError("file authority must not use the broad active intent view")

            monkeypatch.setattr(intents, "effective_grant", effective_grant)
            monkeypatch.setattr(intents, "active_envelope", forbidden_active)
            adapter, draft, target = _prepare_file(
                orind,
                witness_key,
                tmp_path / "owner-effective",
            )
            raw_witness = orind.daemon._store.current_state_witness(  # noqa: SLF001
                draft.draft_id
            )
            assert isinstance(raw_witness, dict)
            now = _now_ms()
            bogus_work_approval = ExactCommitApprovalV1(
                approval_id=f"exact:{uuid4().hex}",
                task_id=draft.task_id,
                draft_id=draft.draft_id,
                witness_id=str(raw_witness["witness_id"]),
                canonical_effect_hash=str(raw_witness["canonical_effect_hash"]),
                directory_handle_id=str(draft.arguments["directory_handle"]),
                approved=True,
                created_at_ms=now - 1,
                expires_at_ms=now + 60_000,
            ).sign_with(witness_key)
            with pytest.raises(LeaseDenied):
                adapter.grant_exact(bogus_work_approval.to_dict(), task_id=draft.task_id)

            _expect_interrupted_consume(adapter, draft.draft_id)
            assert _operation(orind, draft.draft_id).state == "PREPARED"
            response = _consume_raw(adapter, draft.draft_id)
            assert response["receipt_id"].startswith("receipt:")
            assert target.read_text(encoding="utf-8") == "membrane-file-content\n"
            assert len(effective_calls) >= 7
            assert set(effective_calls) == {draft.task_id}
        finally:
            if adapter is not None:
                adapter.close()
            orind.stop()

    def test_live_duplicate_consume_cannot_reconcile_committing_operation(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state_dir = tmp_path / "state"
        witness_key = ed25519.Ed25519PrivateKey.generate()
        orind = _start_orind(state_dir, witness_key, cell_file=True)
        first_adapter: OrinLeaseClientAdapter | None = None
        second_adapter: OrinLeaseClientAdapter | None = None
        entered_commit = threading.Event()
        release_commit = threading.Event()
        request_types: list[str] = []
        executor = ThreadPoolExecutor(max_workers=1)
        first_future: Any = None
        try:
            first_adapter, draft, target = _prepare_file(
                orind,
                witness_key,
                tmp_path / "owner",
            )
            second_adapter = _adapter(orind)
            original_request = orind.daemon._request_cell  # noqa: SLF001

            async def hold_first_commit(
                cap: str,
                message_type: str,
                *,
                timeout_s: float = 90.0,
                _allow_unready: bool = False,
                **fields: Any,
            ) -> dict[str, Any] | None:
                request_types.append(message_type)
                if message_type == "commit" and not entered_commit.is_set():
                    entered_commit.set()
                    released = await asyncio.to_thread(release_commit.wait, 10.0)
                    if not released:
                        raise AssertionError("timed out holding the first Cell commit")
                return await original_request(
                    cap,
                    message_type,
                    timeout_s=timeout_s,
                    _allow_unready=_allow_unready,
                    **fields,
                )

            monkeypatch.setattr(orind.daemon, "_request_cell", hold_first_commit)
            first_future = executor.submit(_consume_raw, first_adapter, draft.draft_id)
            assert entered_commit.wait(10.0), "first consume never reached Cell commit dispatch"
            assert _operation(orind, draft.draft_id).state == "COMMITTING"

            with pytest.raises((LeaseDenied, OrinUnavailable)):
                _consume_raw(second_adapter, draft.draft_id)

            assert _operation(orind, draft.draft_id).state == "COMMITTING"
            assert "reconcile" not in request_types
            assert not target.exists()
            release_commit.set()
            response = first_future.result(timeout=20.0)
            assert response["receipt_id"].startswith("receipt:")
            assert _operation(orind, draft.draft_id).state == "RECEIPTED"
            _assert_one_effect("file", state_dir, target)
        finally:
            release_commit.set()
            executor.shutdown(wait=True, cancel_futures=True)
            if first_adapter is not None:
                first_adapter.close()
            if second_adapter is not None:
                second_adapter.close()
            orind.stop()

    @pytest.mark.parametrize("kind", ["file", "connector"])
    def test_crash_before_cell_call_reconciles_absent_without_blind_retry(
        self,
        tmp_path: Path,
        kind: str,
    ) -> None:
        state_dir = tmp_path / "state"
        witness_key = ed25519.Ed25519PrivateKey.generate()
        crash = _CrashAt("after_committing_persisted")
        orind = _start_orind(
            state_dir,
            witness_key,
            cell_file=kind == "file",
            cell_connector=kind == "connector",
            membrane_fault_hook=crash,
        )
        adapter: OrinLeaseClientAdapter | None = None
        target: Path | None = None
        try:
            if kind == "file":
                adapter, draft, target = _prepare_file(
                    orind,
                    witness_key,
                    tmp_path / "owner",
                )
            else:
                adapter, draft, _export = _prepare_connector(
                    orind,
                    witness_key,
                    profile="work",
                )
            _expect_interrupted_consume(adapter, draft.draft_id)
            interrupted = _operation(orind, draft.draft_id)
            assert interrupted.state == "COMMITTING"
            assert crash.fired is True
            marker = _effect_marker(kind, state_dir, target)
            assert marker is None or marker == ()
            operation_id = interrupted.operation_id
        finally:
            if adapter is not None:
                adapter.close()
            orind.stop()

        restarted = _start_orind(
            state_dir,
            witness_key,
            cell_file=kind == "file",
            cell_connector=kind == "connector",
        )
        resumed_adapter = _adapter(restarted)
        try:
            reconciled = _operation(restarted, draft.draft_id)
            assert reconciled.operation_id == operation_id
            assert reconciled.state == "PREPARED"
            marker = _effect_marker(kind, state_dir, target)
            assert marker is None or marker == ()
            response = _consume_raw(resumed_adapter, draft.draft_id)
            assert response["receipt_id"].startswith("receipt:")
            completed = _operation(restarted, draft.draft_id)
            assert completed.operation_id == operation_id
            assert completed.state == "RECEIPTED"
            _assert_one_effect(kind, state_dir, target)
        finally:
            resumed_adapter.close()
            restarted.stop()

    @pytest.mark.parametrize("kind", ["file", "connector"])
    def test_response_lost_after_effect_enters_unknown_and_restart_only_reconciles(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        kind: str,
    ) -> None:
        state_dir = tmp_path / "state"
        witness_key = ed25519.Ed25519PrivateKey.generate()
        orind = _start_orind(
            state_dir,
            witness_key,
            cell_file=kind == "file",
            cell_connector=kind == "connector",
        )
        adapter: OrinLeaseClientAdapter | None = None
        target: Path | None = None
        try:
            if kind == "file":
                adapter, draft, target = _prepare_file(
                    orind,
                    witness_key,
                    tmp_path / "owner",
                )
            else:
                adapter, draft, _export = _prepare_connector(
                    orind,
                    witness_key,
                    profile="work",
                )

            original_request = orind.daemon._request_cell  # noqa: SLF001
            dropped = False

            async def drop_commit_ack(
                cap: str,
                message_type: str,
                *,
                timeout_s: float = 90.0,
                **fields: Any,
            ) -> dict[str, Any] | None:
                nonlocal dropped
                response = await original_request(
                    cap,
                    message_type,
                    timeout_s=timeout_s,
                    **fields,
                )
                if message_type == "commit" and cap in {"cell.file", "cell.connector"}:
                    dropped = True
                    return None
                return response

            monkeypatch.setattr(orind.daemon, "_request_cell", drop_commit_ack)
            _expect_interrupted_consume(adapter, draft.draft_id)
            assert dropped is True, "the real Cell must execute before its ack is discarded"
            unknown = _operation(orind, draft.draft_id)
            assert unknown.state == "UNKNOWN_COMMIT"
            operation_id = unknown.operation_id
            before_restart = _effect_marker(kind, state_dir, target)
            _assert_one_effect(kind, state_dir, target)
        finally:
            if adapter is not None:
                adapter.close()
            orind.stop()

        unavailable = _start_orind(
            state_dir,
            witness_key,
        )
        try:
            still_unknown = _operation(unavailable, draft.draft_id)
            assert still_unknown.operation_id == operation_id
            assert still_unknown.state == "UNKNOWN_COMMIT"
            assert _effect_marker(kind, state_dir, target) == before_restart
        finally:
            unavailable.stop()

        restarted = _start_orind(
            state_dir,
            witness_key,
            cell_file=kind == "file",
            cell_connector=kind == "connector",
        )
        try:
            recovered = _operation(restarted, draft.draft_id)
            assert recovered.operation_id == operation_id
            assert recovered.state == "RECEIPTED"
            assert recovered.attempt_count == 1
            assert recovered.receipt_id.startswith("receipt:")
            assert _effect_marker(kind, state_dir, target) == before_restart
        finally:
            restarted.stop()


class TestAtomicPassBudgetAndAttempts:
    def test_personal_pass_budget_and_prepared_are_one_transaction(self, tmp_path: Path) -> None:
        state_dir = tmp_path / "state"
        witness_key = ed25519.Ed25519PrivateKey.generate()
        crash = _CrashAt("after_prepared_tx")
        orind = _start_orind(
            state_dir,
            witness_key,
            cell_connector=True,
            membrane_fault_hook=crash,
        )
        adapter: OrinLeaseClientAdapter | None = None
        try:
            adapter, draft, export_pass = _prepare_connector(
                orind,
                witness_key,
                profile="personal",
            )
            _expect_interrupted_consume(adapter, draft.draft_id)
            prepared = _operation(orind, draft.draft_id)
            assert prepared.state == "PREPARED"
            assert prepared.export_pass_id == export_pass.pass_id
            assert prepared.export_pass_claimed is True
            assert prepared.budget_sequence == 1
            assert prepared.permit_id
            assert _pass_state(state_dir, export_pass.pass_id)[0] == 1
            assert _budget_usage(state_dir, draft.task_id)[0::2] == (1, 1)
            assert _outbox_records(state_dir) == ()
            operation_id = prepared.operation_id
        finally:
            if adapter is not None:
                adapter.close()
            orind.stop()

        restarted = _start_orind(
            state_dir,
            witness_key,
            cell_connector=True,
        )
        resumed = _adapter(restarted)
        try:
            still_prepared = _operation(restarted, draft.draft_id)
            assert still_prepared.operation_id == operation_id
            assert still_prepared.state == "PREPARED"
            response = _consume_raw(resumed, draft.draft_id)
            assert response["receipt_id"].startswith("receipt:")
            with pytest.raises(LeaseDenied):
                _consume_raw(resumed, draft.draft_id)
            assert len(_outbox_records(state_dir)) == 1
            assert _budget_usage(state_dir, draft.task_id)[0::2] == (1, 1)
        finally:
            resumed.close()
            restarted.stop()

    def test_prepared_work_attempt_revalidates_revoked_standing_pass_before_commit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state_dir = tmp_path / "state"
        witness_key = ed25519.Ed25519PrivateKey.generate()
        crash = _CrashAt("after_prepared_tx")
        orind = _start_orind(
            state_dir,
            witness_key,
            cell_connector=True,
            membrane_fault_hook=crash,
        )
        adapter: OrinLeaseClientAdapter | None = None
        commit_frames: list[tuple[str, str]] = []
        try:
            adapter, draft, export_pass = _prepare_connector(
                orind,
                witness_key,
                profile="work",
            )
            _expect_interrupted_consume(adapter, draft.draft_id)
            prepared = _operation(orind, draft.draft_id)
            assert prepared.state == "PREPARED"
            assert prepared.attempt_count == 0
            assert _outbox_records(state_dir) == ()
            assert orind.daemon._store.revoke_export_pass(export_pass.pass_id) is True  # noqa: SLF001

            original_request = orind.daemon._request_cell  # noqa: SLF001

            async def record_commit(
                cap: str,
                message_type: str,
                *,
                timeout_s: float = 90.0,
                **fields: Any,
            ) -> dict[str, Any] | None:
                if message_type == "commit":
                    commit_frames.append((cap, message_type))
                return await original_request(
                    cap,
                    message_type,
                    timeout_s=timeout_s,
                    **fields,
                )

            monkeypatch.setattr(orind.daemon, "_request_cell", record_commit)
            response = _consume_wire_response(adapter, draft.draft_id)

            assert response["ok"] is False
            assert response["code"] == "stale_state"
            unchanged = _operation(orind, draft.draft_id)
            assert unchanged.operation_id == prepared.operation_id
            assert unchanged.state == "PREPARED"
            assert unchanged.attempt_count == 0
            assert unchanged.permit_id == prepared.permit_id
            assert unchanged.budget_sequence == prepared.budget_sequence
            assert commit_frames == []
            assert _outbox_records(state_dir) == ()
        finally:
            if adapter is not None:
                adapter.close()
            orind.stop()

    def test_prepared_file_attempt_revalidates_expired_witness_before_commit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state_dir = tmp_path / "state"
        witness_key = ed25519.Ed25519PrivateKey.generate()
        crash = _CrashAt("after_prepared_tx")
        orind = _start_orind(
            state_dir,
            witness_key,
            cell_file=True,
            membrane_fault_hook=crash,
        )
        adapter: OrinLeaseClientAdapter | None = None
        commit_frames: list[tuple[str, str]] = []
        try:
            adapter, draft, target = _prepare_file(
                orind,
                witness_key,
                tmp_path / "owner",
            )
            _expect_interrupted_consume(adapter, draft.draft_id)
            prepared = _operation(orind, draft.draft_id)
            assert prepared.state == "PREPARED"
            assert prepared.attempt_count == 0
            assert not target.exists()

            with sqlite3.connect(state_dir / "orin" / "orind_state.db") as connection:
                cursor = connection.execute(
                    "UPDATE state_witnesses SET expires_at_ms = 1 WHERE witness_id = ?",
                    (prepared.witness_id,),
                )
            assert cursor.rowcount == 1

            original_request = orind.daemon._request_cell  # noqa: SLF001

            async def record_commit(
                cap: str,
                message_type: str,
                *,
                timeout_s: float = 90.0,
                **fields: Any,
            ) -> dict[str, Any] | None:
                if message_type == "commit":
                    commit_frames.append((cap, message_type))
                return await original_request(
                    cap,
                    message_type,
                    timeout_s=timeout_s,
                    **fields,
                )

            monkeypatch.setattr(orind.daemon, "_request_cell", record_commit)
            response = _consume_wire_response(adapter, draft.draft_id)

            assert response["ok"] is False
            assert response["code"] == "stale_state"
            unchanged = _operation(orind, draft.draft_id)
            assert unchanged.operation_id == prepared.operation_id
            assert unchanged.state == "PREPARED"
            assert unchanged.attempt_count == 0
            assert unchanged.permit_id == prepared.permit_id
            assert unchanged.budget_sequence == prepared.budget_sequence
            assert commit_frames == []
            assert not target.exists()
        finally:
            if adapter is not None:
                adapter.close()
            orind.stop()

    def test_work_pass_is_standing_but_same_draft_wire_replay_is_idempotent(
        self,
        tmp_path: Path,
    ) -> None:
        state_dir = tmp_path / "state"
        witness_key = ed25519.Ed25519PrivateKey.generate()
        orind = _start_orind(
            state_dir,
            witness_key,
            cell_connector=True,
        )
        adapter: OrinLeaseClientAdapter | None = None
        try:
            adapter, draft, export_pass = _prepare_connector(
                orind,
                witness_key,
                profile="work",
            )
            first_response = _consume_raw(adapter, draft.draft_id)
            first = _operation(orind, draft.draft_id)
            first_fields = (
                first.operation_id,
                first.permit_id,
                first.permit_sequence,
                first.budget_sequence,
                first.idempotency_key,
            )
            second_response = _consume_raw(adapter, draft.draft_id)
            second = _operation(orind, draft.draft_id)

            # The wire carries only draft_id, not an attempt/request id.  A
            # repeated consume therefore has to mean retry of this operation;
            # treating it as a fresh send would make an ACK-loss retry
            # indistinguishable from an intentional second side effect.
            assert second.operation_id == first_fields[0]
            assert second.permit_id == first_fields[1]
            assert second.permit_sequence == first_fields[2]
            assert second.budget_sequence == first_fields[3]
            assert second.idempotency_key == first_fields[4]
            assert first_response["receipt_id"] == second_response["receipt_id"]
            assert _pass_state(state_dir, export_pass.pass_id) == (0, 0)
            assert _budget_usage(state_dir, draft.task_id)[0::2] == (1, 1)
            assert len(_outbox_records(state_dir)) == 1
            assert second.state == "RECEIPTED"
        finally:
            if adapter is not None:
                adapter.close()
            orind.stop()


class TestBackpressureMapping:
    @staticmethod
    def _reject_admission(_spec: object) -> None:
        raise AdmissionBackpressure("test membrane saturation")

    def test_first_operation_admission_maps_to_backpressure_not_connection_rate_limit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state_dir = tmp_path / "state"
        witness_key = ed25519.Ed25519PrivateKey.generate()
        orind = _start_orind(
            state_dir,
            witness_key,
            cell_file=True,
        )
        adapter: OrinLeaseClientAdapter | None = None
        try:
            adapter, draft, target = _prepare_file(
                orind,
                witness_key,
                tmp_path / "owner",
            )
            membrane = orind.daemon.membrane
            assert membrane is not None
            assert membrane.operation_for_draft(draft.draft_id) is None
            monkeypatch.setattr(membrane, "admit", self._reject_admission)

            response = _consume_wire_response(adapter, draft.draft_id)

            assert response["ok"] is False
            assert response["code"] == "backpressure"
            assert response["code"] != "rate_limited"
            assert membrane.operation_for_draft(draft.draft_id) is None
            assert not target.exists()
        finally:
            if adapter is not None:
                adapter.close()
            orind.stop()

    def test_existing_prepared_operation_resume_maps_to_backpressure(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state_dir = tmp_path / "state"
        witness_key = ed25519.Ed25519PrivateKey.generate()
        crash = _CrashAt("after_prepared_tx")
        orind = _start_orind(
            state_dir,
            witness_key,
            cell_file=True,
            membrane_fault_hook=crash,
        )
        adapter: OrinLeaseClientAdapter | None = None
        try:
            adapter, draft, target = _prepare_file(
                orind,
                witness_key,
                tmp_path / "owner",
            )
            _expect_interrupted_consume(adapter, draft.draft_id)
            prepared = _operation(orind, draft.draft_id)
            assert prepared.state == "PREPARED"
            membrane = orind.daemon.membrane
            assert membrane is not None
            monkeypatch.setattr(membrane, "admit", self._reject_admission)

            response = _consume_wire_response(adapter, draft.draft_id)

            assert response["ok"] is False
            assert response["code"] == "backpressure"
            assert response["code"] != "rate_limited"
            unchanged = _operation(orind, draft.draft_id)
            assert unchanged.operation_id == prepared.operation_id
            assert unchanged.state == "PREPARED"
            assert not target.exists()
        finally:
            if adapter is not None:
                adapter.close()
            orind.stop()


class TestRollbackCompatibility:
    def test_membrane_disabled_keeps_wp9_one_shot_package_path(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state_dir = tmp_path / "state"
        witness_key = ed25519.Ed25519PrivateKey.generate()
        orind = _start_orind(
            state_dir,
            witness_key,
            cell_file=True,
            commit_membrane=False,
        )
        adapter: OrinLeaseClientAdapter | None = None
        frames: list[tuple[str, str, dict[str, Any]]] = []
        try:
            assert orind.daemon.membrane is None
            original_request = orind.daemon._request_cell  # noqa: SLF001

            async def record_request(
                cap: str,
                message_type: str,
                *,
                timeout_s: float = 90.0,
                **fields: Any,
            ) -> dict[str, Any] | None:
                frames.append((cap, message_type, fields))
                return await original_request(
                    cap,
                    message_type,
                    timeout_s=timeout_s,
                    **fields,
                )

            monkeypatch.setattr(orind.daemon, "_request_cell", record_request)
            adapter, draft, target = _prepare_file(
                orind,
                witness_key,
                tmp_path / "owner",
            )
            result = adapter.consume_draft(draft.draft_id)
            assert result["status"] == "COMMITTED"
            assert result["commit_guarantee"] == "best_effort"
            assert target.read_text(encoding="utf-8") == "membrane-file-content\n"
            assert [message for _cap, message, _fields in frames] == ["preflight", "commit"]
            assert "package" in frames[0][2] and "permit" not in frames[0][2]
            assert set(frames[1][2]) == {"package", "permit"}
            best_effort_events = [
                event
                for event in orind.daemon.audit_events()
                if event.get("event") == "best_effort_commit"
            ]
            assert best_effort_events == [
                {
                    "event": "best_effort_commit",
                    "draft_id": draft.draft_id,
                    "effect_type": "file.commit",
                    "executor_id": "cell.file",
                }
            ]
            assert "membrane-file-content" not in json.dumps(best_effort_events)
        finally:
            if adapter is not None:
                adapter.close()
            orind.stop()

    def test_membrane_disabled_marks_connector_commit_best_effort(
        self,
        tmp_path: Path,
    ) -> None:
        state_dir = tmp_path / "state"
        witness_key = ed25519.Ed25519PrivateKey.generate()
        orind = _start_orind(
            state_dir,
            witness_key,
            cell_connector=True,
            commit_membrane=False,
        )
        adapter: OrinLeaseClientAdapter | None = None
        try:
            adapter, draft, _export_pass = _prepare_connector(
                orind,
                witness_key,
                profile="work",
            )
            result = adapter.consume_draft(draft.draft_id)

            assert result["status"] == "COMMITTED"
            assert result["commit_guarantee"] == "best_effort"
            assert len(_outbox_records(state_dir)) == 1
            best_effort_events = [
                event
                for event in orind.daemon.audit_events()
                if event.get("event") == "best_effort_commit"
            ]
            assert best_effort_events == [
                {
                    "event": "best_effort_commit",
                    "draft_id": draft.draft_id,
                    "effect_type": "email.send_exact",
                    "executor_id": "cell.connector",
                }
            ]
            assert "membrane-exact-body" not in json.dumps(best_effort_events)
        finally:
            if adapter is not None:
                adapter.close()
            orind.stop()

    def test_wp7_build_commit_frame_is_byte_for_byte_legacy_under_membrane(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state_dir = tmp_path / "state"
        witness_key = ed25519.Ed25519PrivateKey.generate()
        orind = _start_orind(
            state_dir,
            witness_key,
            cell_build=True,
        )
        adapter = _adapter(orind)
        seen: list[tuple[str, str, dict[str, Any]]] = []
        payload = {
            "kind": "shell",
            "command": "echo wp7-frame-unchanged",
            "cwd": ".",
            "tool": "shell",
        }
        original_request = orind.daemon._request_cell  # noqa: SLF001

        async def record_request(
            cap: str,
            message_type: str,
            *,
            timeout_s: float = 90.0,
            **fields: Any,
        ) -> dict[str, Any] | None:
            seen.append((cap, message_type, fields))
            return await original_request(
                cap,
                message_type,
                timeout_s=timeout_s,
                **fields,
            )

        monkeypatch.setattr(orind.daemon, "_request_cell", record_request)
        try:
            result = adapter.run_in_build_cell(payload, context_taint=1)
            assert result["status"] == "COMMITTED"
            assert "wp7-frame-unchanged" in str(result["output"])
            # WP7 has always inserted the selected Cell cap into the legacy
            # permit payload before Orind proxies it byte-for-byte.  WP10 must
            # preserve that exact established frame, not reinterpret it as a
            # strict CommitPermit/package pair.
            legacy_payload = {"cell": "cell.build", **payload}
            assert seen == [("cell.build", "commit", {"permit": legacy_payload})]
            with sqlite3.connect(state_dir / "orin" / "orind_state.db") as connection:
                count = connection.execute("SELECT COUNT(*) FROM commit_operations").fetchone()
            assert count == (0,)
        finally:
            adapter.close()
            orind.stop()
