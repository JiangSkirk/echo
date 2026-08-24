"""WP10 contract tests for the single durable Commit Membrane.

These tests fix the public seam of ``js.orind.membrane``.  The membrane owns
one SQLite/WAL transaction boundary for the
operation state, budget reservation, one-shot permit sequence, and (for
Personal) exact ExportPass claim.  Connector and File Cell integration is
covered separately; this file only fixes the state/storage semantics.
"""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from js.orin.draft import ExportPass
from js.orind.membrane import (
    AdmissionBackpressure,
    AdmissionTicket,
    BudgetExhausted,
    CommitMembrane,
    CommitState,
    ExportPassUnavailable,
    InvalidTransition,
    MembraneDisabled,
    OperationConflict,
    OperationSnapshot,
    OperationSpec,
)
from js.orind.store import OrinStore

NOW_MS = 2_000_000_000_000
OWNER_KEY_HASH = "sha256:" + "1" * 64
EFFECT_HASH = "sha256:" + "2" * 64


def _spec(
    *,
    operation_id: str | None = None,
    draft_id: str | None = None,
    task_id: str | None = None,
    profile: str = "work",
    effect_type: str = "file.commit",
    executor_id: str = "cell.file",
    side_effect_class: str = "R2",
    canonical_effect_hash: str = EFFECT_HASH,
    witness_id: str | None = None,
    destinations: tuple[str, ...] = (),
    bytes_out: int = 17,
) -> OperationSpec:
    token = uuid4().hex
    return OperationSpec(
        operation_id=operation_id or f"operation:{token}",
        draft_id=draft_id or f"draft:{token}",
        task_id=task_id or f"task:{token}",
        owner_key_hash=OWNER_KEY_HASH,
        session_id=f"session:{token}",
        effect_type=effect_type,
        executor_id=executor_id,
        side_effect_class=side_effect_class,
        canonical_effect_hash=canonical_effect_hash,
        witness_id=witness_id or f"state:{token}",
        intent_id=f"intent:{token}",
        profile=profile,
        destinations=destinations,
        bytes_out=bytes_out,
        idempotency_key=f"idem:{token}",
    )


def _email_spec(
    *,
    profile: str,
    task_id: str | None = None,
    witness_id: str | None = None,
    operation_id: str | None = None,
    draft_id: str | None = None,
) -> OperationSpec:
    return _spec(
        operation_id=operation_id,
        draft_id=draft_id,
        task_id=task_id,
        profile=profile,
        effect_type="email.send_exact",
        executor_id="cell.connector",
        canonical_effect_hash="sha256:" + "e" * 64,
        witness_id=witness_id,
        destinations=("rcpt:finance",),
        bytes_out=64,
    )


def _membrane(db_path: Path, *, enabled: bool = True) -> CommitMembrane:
    return CommitMembrane(db_path, enabled=enabled, now_fn=lambda: NOW_MS)


def _propose_and_preflight(
    membrane: CommitMembrane,
    spec: OperationSpec,
) -> None:
    proposed = membrane.propose(spec)
    assert proposed.state is CommitState.PROPOSED
    preflighted = membrane.transition(spec.operation_id, CommitState.PREFLIGHTED)
    assert preflighted.state is CommitState.PREFLIGHTED


def _prepare_local(membrane: CommitMembrane, spec: OperationSpec) -> OperationSnapshot:
    _propose_and_preflight(membrane, spec)
    return membrane.prepare(
        spec.operation_id,
        max_invocations=20,
        max_bytes_out=1 << 20,
        export_pass_id=None,
        require_personal_pass=False,
        now_ms=NOW_MS,
    )


def _finish_receipted(membrane: CommitMembrane, spec: OperationSpec) -> None:
    membrane.begin_commit(spec.operation_id)
    membrane.transition(spec.operation_id, CommitState.COMMITTED)
    membrane.transition(
        spec.operation_id,
        CommitState.RECEIPTED,
        receipt_id=f"receipt:{uuid4().hex}",
    )


def _record_export_pass(
    db_path: Path,
    spec: OperationSpec,
    *,
    pass_id: str,
    profile: str,
) -> None:
    export_pass = ExportPass(
        pass_id=pass_id,
        task_id=spec.task_id,
        payload_hash=spec.canonical_effect_hash,
        destination_handles=spec.destinations,
        witness_id=spec.witness_id,
        created_at_ms=NOW_MS - 1_000,
        expires_at_ms=NOW_MS + 60_000,
        signature="",
    )
    store = OrinStore(db_path)
    try:
        assert (
            store.record_export_pass(
                pass_id=pass_id,
                payload=export_pass.to_dict(),
                profile=profile,
                standing=profile == "work",
            )
            == "inserted"
        )
    finally:
        store.close()


def _pass_state(db_path: Path, pass_id: str) -> tuple[int, int]:
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT revoked, claimed_at_ms FROM export_passes WHERE pass_id = ?",
            (pass_id,),
        ).fetchone()
    assert row is not None
    return int(row[0]), int(row[1])


def _budget_state(db_path: Path, task_id: str) -> tuple[int, int, int]:
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT invocations, bytes_out, sequence FROM effect_budget_usage WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    if row is None:
        return (0, 0, 0)
    return int(row[0]), int(row[1]), int(row[2])


class TestCommitStateGraph:
    def test_proposed_has_only_denied_or_preflighted_edges(self, tmp_path: Path) -> None:
        membrane = _membrane(tmp_path / "state.db")
        denied = _spec()
        preflighted = _spec()
        try:
            membrane.propose(denied)
            assert membrane.transition(denied.operation_id, CommitState.DENIED).state is (
                CommitState.DENIED
            )

            membrane.propose(preflighted)
            assert (
                membrane.transition(preflighted.operation_id, CommitState.PREFLIGHTED).state
                is CommitState.PREFLIGHTED
            )
        finally:
            membrane.close()

    def test_preflighted_and_approval_pending_edges(self, tmp_path: Path) -> None:
        membrane = _membrane(tmp_path / "state.db")
        pending_then_denied = _spec()
        pending_then_prepared = _spec()
        directly_prepared = _spec()
        try:
            _propose_and_preflight(membrane, pending_then_denied)
            pending = membrane.transition(
                pending_then_denied.operation_id,
                CommitState.APPROVAL_PENDING,
            )
            assert pending.state is CommitState.APPROVAL_PENDING
            assert (
                membrane.transition(pending_then_denied.operation_id, CommitState.DENIED).state
                is CommitState.DENIED
            )

            _propose_and_preflight(membrane, pending_then_prepared)
            membrane.transition(
                pending_then_prepared.operation_id,
                CommitState.APPROVAL_PENDING,
            )
            assert (
                membrane.prepare(
                    pending_then_prepared.operation_id,
                    max_invocations=20,
                    max_bytes_out=1 << 20,
                    export_pass_id=None,
                    require_personal_pass=False,
                    now_ms=NOW_MS,
                ).state
                is CommitState.PREPARED
            )

            assert _prepare_local(membrane, directly_prepared).state is CommitState.PREPARED
        finally:
            membrane.close()

    def test_prepared_committing_committed_receipted_edges(self, tmp_path: Path) -> None:
        membrane = _membrane(tmp_path / "state.db")
        spec = _spec()
        try:
            prepared = _prepare_local(membrane, spec)
            assert prepared.permit_id.startswith("permit:")
            assert prepared.permit_sequence >= 1

            committing = membrane.begin_commit(spec.operation_id)
            assert committing.state is CommitState.COMMITTING
            assert committing.attempt_count == 1

            committed = membrane.transition(spec.operation_id, CommitState.COMMITTED)
            assert committed.state is CommitState.COMMITTED
            receipted = membrane.transition(
                spec.operation_id,
                CommitState.RECEIPTED,
                receipt_id=f"receipt:{uuid4().hex}",
            )
            assert receipted.state is CommitState.RECEIPTED
            assert receipted.receipt_id.startswith("receipt:")
        finally:
            membrane.close()

    def test_unknown_reconcile_has_only_committed_or_fresh_prepared_edges(
        self,
        tmp_path: Path,
    ) -> None:
        membrane = _membrane(tmp_path / "state.db")
        confirmed = _spec()
        absent = _spec()
        try:
            _prepare_local(membrane, confirmed)
            membrane.begin_commit(confirmed.operation_id)
            unknown = membrane.mark_ambiguous(confirmed.operation_id, "connection lost")
            assert unknown.state is CommitState.UNKNOWN_COMMIT
            assert (
                membrane.reconcile(
                    confirmed.operation_id,
                    "committed",
                    remote_operation_id="provider:confirmed",
                ).state
                is CommitState.COMMITTED
            )

            first_prepare = _prepare_local(membrane, absent)
            membrane.begin_commit(absent.operation_id)
            membrane.mark_ambiguous(absent.operation_id, "ack lost")
            inconclusive = membrane.reconcile(absent.operation_id, "unknown")
            assert inconclusive.state is CommitState.UNKNOWN_COMMIT
            with pytest.raises(InvalidTransition):
                membrane.begin_commit(absent.operation_id)

            retry = membrane.reconcile(absent.operation_id, "absent")
            assert retry.state is CommitState.PREPARED
            assert retry.permit_id != first_prepare.permit_id
            assert retry.permit_sequence > first_prepare.permit_sequence
            assert membrane.begin_commit(absent.operation_id).attempt_count == 2
        finally:
            membrane.close()

    @pytest.mark.parametrize(
        ("source", "illegal_target"),
        [
            (CommitState.PROPOSED, CommitState.PREPARED),
            (CommitState.PREFLIGHTED, CommitState.COMMITTING),
            (CommitState.APPROVAL_PENDING, CommitState.COMMITTED),
            (CommitState.PREPARED, CommitState.COMMITTED),
            (CommitState.COMMITTING, CommitState.RECEIPTED),
            (CommitState.UNKNOWN_COMMIT, CommitState.PREPARED),
            (CommitState.COMMITTED, CommitState.COMMITTING),
            (CommitState.DENIED, CommitState.PROPOSED),
            (CommitState.RECEIPTED, CommitState.PROPOSED),
        ],
    )
    def test_illegal_transition_is_rejected_without_mutation(
        self,
        tmp_path: Path,
        source: CommitState,
        illegal_target: CommitState,
    ) -> None:
        membrane = _membrane(tmp_path / f"{source.value}.db")
        spec = _spec()
        try:
            _reach_state(membrane, spec, source)
            before = membrane.get(spec.operation_id)
            with pytest.raises(InvalidTransition):
                membrane.transition(spec.operation_id, illegal_target)
            assert membrane.get(spec.operation_id) == before
        finally:
            membrane.close()

    def test_special_transition_methods_also_fail_closed(self, tmp_path: Path) -> None:
        membrane = _membrane(tmp_path / "state.db")
        proposed = _spec()
        committing = _spec()
        try:
            membrane.propose(proposed)
            with pytest.raises(InvalidTransition):
                membrane.begin_commit(proposed.operation_id)
            with pytest.raises(InvalidTransition):
                membrane.mark_ambiguous(proposed.operation_id, "not dispatched")

            _prepare_local(membrane, committing)
            membrane.begin_commit(committing.operation_id)
            with pytest.raises(InvalidTransition):
                membrane.reconcile(committing.operation_id, "absent")
        finally:
            membrane.close()


def _reach_state(
    membrane: CommitMembrane,
    spec: OperationSpec,
    target: CommitState,
) -> None:
    membrane.propose(spec)
    if target is CommitState.PROPOSED:
        return
    if target is CommitState.DENIED:
        membrane.transition(spec.operation_id, CommitState.DENIED)
        return
    membrane.transition(spec.operation_id, CommitState.PREFLIGHTED)
    if target is CommitState.PREFLIGHTED:
        return
    if target is CommitState.APPROVAL_PENDING:
        membrane.transition(spec.operation_id, CommitState.APPROVAL_PENDING)
        return
    membrane.prepare(
        spec.operation_id,
        max_invocations=20,
        max_bytes_out=1 << 20,
        export_pass_id=None,
        require_personal_pass=False,
        now_ms=NOW_MS,
    )
    if target is CommitState.PREPARED:
        return
    membrane.begin_commit(spec.operation_id)
    if target is CommitState.COMMITTING:
        return
    if target is CommitState.UNKNOWN_COMMIT:
        membrane.mark_ambiguous(spec.operation_id, "test ambiguity")
        return
    membrane.transition(spec.operation_id, CommitState.COMMITTED)
    if target is CommitState.COMMITTED:
        return
    membrane.transition(
        spec.operation_id,
        CommitState.RECEIPTED,
        receipt_id=f"receipt:{uuid4().hex}",
    )


class TestDurabilityAndIdentity:
    def test_sqlite_restart_preserves_unknown_and_requires_reconciliation(
        self,
        tmp_path: Path,
    ) -> None:
        db_path = tmp_path / "restart.db"
        spec = _spec()
        first = _membrane(db_path)
        prepared = _prepare_local(first, spec)
        first.begin_commit(spec.operation_id)
        first.mark_ambiguous(spec.operation_id, "socket closed after dispatch")
        first.close()

        restarted = _membrane(db_path)
        try:
            recovered = restarted.operation_for_draft(spec.draft_id)
            assert recovered is not None
            assert recovered.operation_id == spec.operation_id
            assert recovered.state is CommitState.UNKNOWN_COMMIT
            assert recovered.permit_id == prepared.permit_id
            assert recovered.permit_sequence == prepared.permit_sequence
            assert recovered.attempt_count == 1
            assert recovered.last_error == "socket closed after dispatch"
            with pytest.raises(InvalidTransition):
                restarted.begin_commit(spec.operation_id)

            reconciled = restarted.reconcile(spec.operation_id, "absent")
            assert reconciled.state is CommitState.PREPARED
        finally:
            restarted.close()

        restarted_again = _membrane(db_path)
        try:
            retried = restarted_again.begin_commit(spec.operation_id)
            assert retried.state is CommitState.COMMITTING
            assert retried.attempt_count == 2
        finally:
            restarted_again.close()

    def test_same_operation_is_idempotent_but_content_conflicts(self, tmp_path: Path) -> None:
        membrane = _membrane(tmp_path / "identity.db")
        spec = _spec()
        try:
            first = membrane.propose(spec)
            replay = membrane.propose(spec)
            assert replay == first
            assert membrane.operation_for_draft(spec.draft_id) == first

            with pytest.raises(OperationConflict):
                membrane.propose(replace(spec, canonical_effect_hash="sha256:" + "9" * 64))
            assert membrane.get(spec.operation_id) == first

            with pytest.raises(OperationConflict):
                membrane.propose(
                    replace(
                        spec,
                        operation_id=f"operation:{uuid4().hex}",
                    )
                )
            assert membrane.operation_for_draft(spec.draft_id) == first
        finally:
            membrane.close()

    def test_permit_sequence_is_unique_idempotent_and_restart_monotonic(
        self,
        tmp_path: Path,
    ) -> None:
        db_path = tmp_path / "permits.db"
        task_id = f"task:{uuid4().hex}"
        first_spec = _spec(task_id=task_id)
        second_spec = _spec(task_id=task_id)
        membrane = _membrane(db_path)
        first = _prepare_local(membrane, first_spec)
        replay = membrane.prepare(
            first_spec.operation_id,
            max_invocations=20,
            max_bytes_out=1 << 20,
            export_pass_id=None,
            require_personal_pass=False,
            now_ms=NOW_MS,
        )
        second = _prepare_local(membrane, second_spec)
        assert replay == first
        assert second.permit_sequence == first.permit_sequence + 1
        assert second.permit_id != first.permit_id
        assert _budget_state(db_path, task_id) == (2, 34, second.permit_sequence)
        membrane.close()

        restarted = _membrane(db_path)
        third_spec = _spec(task_id=task_id)
        try:
            third = _prepare_local(restarted, third_spec)
            assert third.permit_sequence == second.permit_sequence + 1
            assert len({first.permit_id, second.permit_id, third.permit_id}) == 3
        finally:
            restarted.close()


class TestCrashRestartMatrix:
    @pytest.mark.parametrize(
        ("crash_state", "recovered_state"),
        [
            (CommitState.PROPOSED, CommitState.PROPOSED),
            (CommitState.DENIED, CommitState.DENIED),
            (CommitState.PREFLIGHTED, CommitState.PREFLIGHTED),
            (CommitState.APPROVAL_PENDING, CommitState.APPROVAL_PENDING),
            (CommitState.PREPARED, CommitState.PREPARED),
            (CommitState.COMMITTING, CommitState.UNKNOWN_COMMIT),
            (CommitState.UNKNOWN_COMMIT, CommitState.UNKNOWN_COMMIT),
            (CommitState.COMMITTED, CommitState.COMMITTED),
            (CommitState.RECEIPTED, CommitState.RECEIPTED),
        ],
    )
    def test_each_durable_state_recovers_without_unsafe_regression(
        self,
        tmp_path: Path,
        crash_state: CommitState,
        recovered_state: CommitState,
    ) -> None:
        db_path = tmp_path / f"crash-{crash_state.value}.db"
        spec = _spec()
        first = _membrane(db_path)
        _reach_state(first, spec, crash_state)
        before = first.get(spec.operation_id)
        budget_before = _budget_state(db_path, spec.task_id)
        first.close()

        restarted = _membrane(db_path)
        try:
            recovered = restarted.get(spec.operation_id)
            assert recovered.state is recovered_state
            assert restarted.operation_for_draft(spec.draft_id) == recovered
            assert restarted.operations_for_draft(spec.draft_id) == [recovered]
            assert _authority_identity(recovered) == _authority_identity(before)
            assert recovered.permit_id == before.permit_id
            assert recovered.permit_sequence == before.permit_sequence
            assert recovered.budget_sequence == before.budget_sequence
            assert recovered.attempt_count == before.attempt_count
            assert recovered.export_pass_claimed is before.export_pass_claimed
            assert recovered.receipt_id == before.receipt_id
            assert _budget_state(db_path, spec.task_id) == budget_before

            if recovered_state is CommitState.UNKNOWN_COMMIT:
                with pytest.raises(InvalidTransition):
                    restarted.begin_commit(spec.operation_id)
                still_unknown = restarted.reconcile(spec.operation_id, "unknown")
                assert still_unknown.state is CommitState.UNKNOWN_COMMIT
            elif crash_state in {CommitState.COMMITTED, CommitState.RECEIPTED}:
                with pytest.raises(InvalidTransition):
                    restarted.begin_commit(spec.operation_id)
        finally:
            restarted.close()

        restarted_again = _membrane(db_path)
        try:
            stable = restarted_again.get(spec.operation_id)
            assert stable.state is recovered_state
            assert stable.permit_id == before.permit_id
            assert stable.permit_sequence == before.permit_sequence
            assert stable.budget_sequence == before.budget_sequence
            assert stable.attempt_count == before.attempt_count
            assert _budget_state(db_path, spec.task_id) == budget_before
        finally:
            restarted_again.close()

    def test_personal_prepare_and_inflight_recovery_never_double_claim_or_budget(
        self,
        tmp_path: Path,
    ) -> None:
        db_path = tmp_path / "personal-crash-matrix.db"
        spec = _email_spec(profile="personal")
        pass_id = f"export:{uuid4().hex}"
        _record_export_pass(db_path, spec, pass_id=pass_id, profile="personal")

        first = _membrane(db_path)
        _propose_and_preflight(first, spec)
        prepared = first.prepare(
            spec.operation_id,
            max_invocations=10,
            max_bytes_out=1 << 20,
            export_pass_id=pass_id,
            require_personal_pass=True,
            now_ms=NOW_MS,
        )
        assert prepared.state is CommitState.PREPARED
        assert _pass_state(db_path, pass_id) == (1, NOW_MS)
        assert _budget_state(db_path, spec.task_id) == (
            1,
            spec.bytes_out,
            prepared.permit_sequence,
        )
        first.close()

        prepared_restart = _membrane(db_path)
        try:
            stable = prepared_restart.get(spec.operation_id)
            assert stable.state is CommitState.PREPARED
            assert stable.permit_id == prepared.permit_id
            assert stable.permit_sequence == prepared.permit_sequence
            assert stable.budget_sequence == prepared.budget_sequence
            assert _pass_state(db_path, pass_id) == (1, NOW_MS)
            assert _budget_state(db_path, spec.task_id) == (
                1,
                spec.bytes_out,
                prepared.permit_sequence,
            )
            prepared_restart.begin_commit(spec.operation_id)
        finally:
            prepared_restart.close()

        inflight_restart = _membrane(db_path)
        try:
            unknown = inflight_restart.get(spec.operation_id)
            assert unknown.state is CommitState.UNKNOWN_COMMIT
            assert unknown.permit_id == prepared.permit_id
            assert unknown.permit_sequence == prepared.permit_sequence
            assert unknown.attempt_count == 1
            assert _pass_state(db_path, pass_id) == (1, NOW_MS)
            assert _budget_state(db_path, spec.task_id) == (
                1,
                spec.bytes_out,
                prepared.permit_sequence,
            )
            with pytest.raises(InvalidTransition):
                inflight_restart.begin_commit(spec.operation_id)

            retry = inflight_restart.reconcile(spec.operation_id, "absent")
            assert retry.state is CommitState.PREPARED
            assert retry.permit_id != prepared.permit_id
            assert retry.permit_sequence > prepared.permit_sequence
            assert retry.budget_sequence == prepared.budget_sequence
            assert _pass_state(db_path, pass_id) == (1, NOW_MS)
            retried_budget = _budget_state(db_path, spec.task_id)
            assert retried_budget[:2] == (1, spec.bytes_out)
            assert retried_budget[2] == retry.permit_sequence
        finally:
            inflight_restart.close()

        retry_restart = _membrane(db_path)
        try:
            stable_retry = retry_restart.get(spec.operation_id)
            assert stable_retry.state is CommitState.PREPARED
            assert stable_retry.permit_id == retry.permit_id
            assert stable_retry.permit_sequence == retry.permit_sequence
            assert stable_retry.budget_sequence == prepared.budget_sequence
            assert _pass_state(db_path, pass_id) == (1, NOW_MS)
            assert _budget_state(db_path, spec.task_id)[:2] == (1, spec.bytes_out)
        finally:
            retry_restart.close()


def _authority_identity(snapshot: OperationSnapshot) -> tuple[object, ...]:
    return (
        snapshot.operation_id,
        snapshot.draft_id,
        snapshot.task_id,
        snapshot.owner_key_hash,
        snapshot.session_id,
        snapshot.effect_type,
        snapshot.executor_id,
        snapshot.side_effect_class,
        snapshot.canonical_effect_hash,
        snapshot.witness_id,
        snapshot.intent_id,
        snapshot.profile,
        snapshot.destinations,
        snapshot.bytes_out,
        snapshot.idempotency_key,
    )


class TestAtomicPrepare:
    def test_personal_claim_budget_and_prepared_are_one_transaction(
        self,
        tmp_path: Path,
    ) -> None:
        db_path = tmp_path / "personal.db"
        spec = _email_spec(profile="personal")
        pass_id = f"export:{uuid4().hex}"
        _record_export_pass(db_path, spec, pass_id=pass_id, profile="personal")
        membrane = _membrane(db_path)
        try:
            _propose_and_preflight(membrane, spec)
            with pytest.raises(BudgetExhausted):
                membrane.prepare(
                    spec.operation_id,
                    max_invocations=0,
                    max_bytes_out=1 << 20,
                    export_pass_id=pass_id,
                    require_personal_pass=True,
                    now_ms=NOW_MS,
                )

            assert membrane.get(spec.operation_id).state is CommitState.PREFLIGHTED
            assert _pass_state(db_path, pass_id) == (0, 0)
            assert _budget_state(db_path, spec.task_id) == (0, 0, 0)

            prepared = membrane.prepare(
                spec.operation_id,
                max_invocations=1,
                max_bytes_out=spec.bytes_out,
                export_pass_id=pass_id,
                require_personal_pass=True,
                now_ms=NOW_MS,
            )
            assert prepared.state is CommitState.PREPARED
            assert _pass_state(db_path, pass_id) == (1, NOW_MS)
            assert _budget_state(db_path, spec.task_id) == (
                1,
                spec.bytes_out,
                prepared.permit_sequence,
            )

            replay = membrane.prepare(
                spec.operation_id,
                max_invocations=1,
                max_bytes_out=spec.bytes_out,
                export_pass_id=pass_id,
                require_personal_pass=True,
                now_ms=NOW_MS,
            )
            assert replay == prepared
            assert _budget_state(db_path, spec.task_id)[0] == 1
        finally:
            membrane.close()

    def test_personal_pass_is_single_use_across_operations(self, tmp_path: Path) -> None:
        db_path = tmp_path / "personal-single-use.db"
        task_id = f"task:{uuid4().hex}"
        witness_id = f"state:{uuid4().hex}"
        first_spec = _email_spec(profile="personal", task_id=task_id, witness_id=witness_id)
        second_spec = replace(first_spec, operation_id=f"operation:{uuid4().hex}")
        pass_id = f"export:{uuid4().hex}"
        _record_export_pass(db_path, first_spec, pass_id=pass_id, profile="personal")
        membrane = _membrane(db_path)
        try:
            _propose_and_preflight(membrane, first_spec)
            membrane.prepare(
                first_spec.operation_id,
                max_invocations=10,
                max_bytes_out=1 << 20,
                export_pass_id=pass_id,
                require_personal_pass=True,
                now_ms=NOW_MS,
            )
            _finish_receipted(membrane, first_spec)

            _propose_and_preflight(membrane, second_spec)
            with pytest.raises(ExportPassUnavailable):
                membrane.prepare(
                    second_spec.operation_id,
                    max_invocations=10,
                    max_bytes_out=1 << 20,
                    export_pass_id=pass_id,
                    require_personal_pass=True,
                    now_ms=NOW_MS,
                )
            assert membrane.get(second_spec.operation_id).state is CommitState.PREFLIGHTED
            assert membrane.operation_for_draft(first_spec.draft_id).operation_id == (
                second_spec.operation_id
            )
            assert [
                item.operation_id for item in membrane.operations_for_draft(first_spec.draft_id)
            ] == [
                first_spec.operation_id,
                second_spec.operation_id,
            ]
            assert _budget_state(db_path, task_id)[0] == 1
        finally:
            membrane.close()

    def test_work_standing_pass_is_rechecked_but_never_consumed(self, tmp_path: Path) -> None:
        db_path = tmp_path / "work.db"
        task_id = f"task:{uuid4().hex}"
        witness_id = f"state:{uuid4().hex}"
        first_spec = _email_spec(profile="work", task_id=task_id, witness_id=witness_id)
        second_spec = replace(first_spec, operation_id=f"operation:{uuid4().hex}")
        pass_id = f"export:{uuid4().hex}"
        _record_export_pass(db_path, first_spec, pass_id=pass_id, profile="work")
        membrane = _membrane(db_path)
        try:
            _propose_and_preflight(membrane, first_spec)
            first = membrane.prepare(
                first_spec.operation_id,
                max_invocations=10,
                max_bytes_out=1 << 20,
                export_pass_id=pass_id,
                require_personal_pass=False,
                now_ms=NOW_MS,
            )
            _finish_receipted(membrane, first_spec)

            _propose_and_preflight(membrane, second_spec)
            second = membrane.prepare(
                second_spec.operation_id,
                max_invocations=10,
                max_bytes_out=1 << 20,
                export_pass_id=pass_id,
                require_personal_pass=False,
                now_ms=NOW_MS,
            )

            assert _pass_state(db_path, pass_id) == (0, 0)
            assert _budget_state(db_path, task_id)[:2] == (2, 128)
            assert second_spec.draft_id == first_spec.draft_id
            assert second_spec.idempotency_key == first_spec.idempotency_key
            assert second.permit_sequence > first.permit_sequence
            assert second.permit_id != first.permit_id
            assert membrane.operation_for_draft(first_spec.draft_id) == second
            assert [
                item.operation_id for item in membrane.operations_for_draft(first_spec.draft_id)
            ] == [
                first_spec.operation_id,
                second_spec.operation_id,
            ]
        finally:
            membrane.close()


def test_disabled_membrane_exposes_no_unknown_guarantee_or_state_path(tmp_path: Path) -> None:
    db_path = tmp_path / "disabled.db"
    membrane = _membrane(db_path, enabled=False)
    try:
        assert membrane.enabled is False
        assert membrane.strong_commit_guarantees is False
        assert membrane.supports_unknown_commit is False
        with pytest.raises(MembraneDisabled):
            membrane.propose(_spec())
        with pytest.raises(MembraneDisabled):
            membrane.mark_ambiguous("operation:disabled", "not available")
        assert not db_path.exists()
    finally:
        membrane.close()


class TestRecoveryMetadataAndAdmission:
    def test_prepared_permit_rotation_is_cas_and_does_not_reserve_budget_twice(
        self,
        tmp_path: Path,
    ) -> None:
        db_path = tmp_path / "rotate.db"
        spec = _spec()
        membrane = _membrane(db_path)
        try:
            first = _prepare_local(membrane, spec)
            rotated = membrane.rotate_prepared_permit(
                spec.operation_id,
                expected_permit_id=first.permit_id,
                expected_intent_id=spec.intent_id,
                expected_witness_id=spec.witness_id,
                expected_export_pass_id=None,
                now_ms=NOW_MS + 120_000,
            )
            assert rotated.state is CommitState.PREPARED
            assert rotated.permit_id != first.permit_id
            assert rotated.permit_sequence > first.permit_sequence
            assert _budget_state(db_path, spec.task_id)[:2] == (1, spec.bytes_out)
            with pytest.raises(OperationConflict):
                membrane.rotate_prepared_permit(
                    spec.operation_id,
                    expected_permit_id=first.permit_id,
                    expected_intent_id=spec.intent_id,
                    expected_witness_id=spec.witness_id,
                    expected_export_pass_id=None,
                    now_ms=NOW_MS + 121_000,
                )
        finally:
            membrane.close()

    def test_safe_receipt_projection_survives_restart_and_unsafe_result_rolls_back(
        self,
        tmp_path: Path,
    ) -> None:
        db_path = tmp_path / "safe-result.db"
        spec = _spec()
        membrane = _membrane(db_path)
        _prepare_local(membrane, spec)
        membrane.begin_commit(spec.operation_id)
        committed = membrane.transition(
            spec.operation_id,
            CommitState.COMMITTED,
            safe_result={
                "status": "COMMITTED",
                "files": ["nested/result.txt"],
                "bytes_written": spec.bytes_out,
                "diff_hash": EFFECT_HASH,
            },
        )
        assert committed.safe_result["files"] == ["nested/result.txt"]
        membrane.transition(
            spec.operation_id,
            CommitState.RECEIPTED,
            receipt_id="receipt:" + uuid4().hex,
        )

        unsafe = _spec()
        _prepare_local(membrane, unsafe)
        membrane.begin_commit(unsafe.operation_id)
        with pytest.raises(ValueError):
            membrane.transition(
                unsafe.operation_id,
                CommitState.COMMITTED,
                safe_result={"status": "COMMITTED", "body": "must-not-persist"},
            )
        assert membrane.get(unsafe.operation_id).state is CommitState.COMMITTING
        membrane.close()

        restarted = _membrane(db_path)
        try:
            replay = restarted.get(spec.operation_id)
            assert replay.state is CommitState.RECEIPTED
            assert replay.safe_result["files"] == ["nested/result.txt"]
            assert replay.safe_result_digest.startswith("sha256:")
            # The failed transaction left no result content and restart turns
            # an in-flight COMMITTING row into UNKNOWN_COMMIT.
            failed = restarted.get(unsafe.operation_id)
            assert failed.state is CommitState.UNKNOWN_COMMIT
            assert failed.safe_result == {}
        finally:
            restarted.close()

    @pytest.mark.parametrize("limited_scope", ["owner", "session", "task", "effect_class"])
    def test_four_scope_buckets_all_have_to_pass_without_partial_deduction(
        self,
        tmp_path: Path,
        limited_scope: str,
    ) -> None:
        clock = [1.0]
        base = _spec()
        membrane = CommitMembrane(
            tmp_path / f"admission-{limited_scope}.db",
            now_fn=lambda: NOW_MS,
            monotonic_fn=lambda: clock[0],
        )
        tickets: list[AdmissionTicket] = []

        def scoped(index: int) -> OperationSpec:
            return replace(
                base,
                owner_key_hash=(
                    base.owner_key_hash
                    if limited_scope == "owner"
                    else "sha256:" + f"{index + 2:064x}"
                ),
                session_id=(
                    base.session_id if limited_scope == "session" else f"session:varied:{index}"
                ),
                task_id=(base.task_id if limited_scope == "task" else f"task:varied:{index}"),
                side_effect_class=(
                    base.side_effect_class
                    if limited_scope == "effect_class"
                    else ("R0", "R1", "R2", "R3")[index % 4]
                ),
            )

        try:
            for _ in range(200):
                tickets.append(membrane.admit(scoped(len(tickets))))
            probe = scoped(10_000)
            with pytest.raises(AdmissionBackpressure) as exhausted:
                membrane.admit(probe)
            assert exhausted.value.retry_after_ms > 0

            # Repeating a request rejected by one exhausted scope must not
            # partially drain any of its other three valid scopes.
            for _ in range(200):
                with pytest.raises(AdmissionBackpressure):
                    membrane.admit(probe)
            if limited_scope == "owner":
                independent = replace(probe, owner_key_hash="sha256:" + "f" * 64)
            elif limited_scope == "session":
                independent = replace(probe, session_id="session:independent")
            elif limited_scope == "task":
                independent = replace(probe, task_id="task:independent")
            else:
                independent = replace(probe, side_effect_class="R3")
            independent_ticket = membrane.admit(independent)
            assert membrane.release(independent_ticket) is True

            clock[0] += 0.02
            refilled = membrane.admit(probe)
            assert membrane.release(refilled) is True
            for ticket in tickets:
                assert membrane.release(ticket) is True
            assert membrane.release(tickets[0]) is False
        finally:
            membrane.close()

    def test_admission_queue_has_a_hard_1024_outstanding_limit(self, tmp_path: Path) -> None:
        clock = [1.0]

        def advancing_clock() -> float:
            clock[0] += 0.02
            return clock[0]

        membrane = CommitMembrane(
            tmp_path / "queue.db",
            now_fn=lambda: NOW_MS,
            monotonic_fn=advancing_clock,
        )
        first = _spec()
        second = replace(
            first,
            owner_key_hash="sha256:" + "a" * 64,
            session_id="session:second",
            task_id="task:second",
            side_effect_class="R3",
        )
        tickets = []
        try:
            for index in range(1024):
                tickets.append(membrane.admit(first if index % 2 == 0 else second))
            with pytest.raises(AdmissionBackpressure, match="queue"):
                membrane.admit(first)

            real_ticket = tickets.pop(0)
            forged_ticket = replace(real_ticket, session_id="session:forged")
            assert membrane.release(forged_ticket) is False
            with pytest.raises(AdmissionBackpressure, match="queue"):
                membrane.admit(first)
            assert membrane.release(real_ticket) is True
            tickets.append(membrane.admit(first))
        finally:
            for ticket in tickets:
                membrane.release(ticket)
            membrane.close()


def test_operation_spec_rejects_unknown_persistence_class() -> None:
    with pytest.raises(ValueError, match="R0"):
        replace(_spec(), side_effect_class="R4")
