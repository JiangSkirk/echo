from __future__ import annotations

import dataclasses

import pytest

from js.echo.ledger.effects import DurableEffectLog, EffectAdapter, EffectReceipt, ProbeResult
from js.echo.ledger.journal import EchoJournal, verify_records
from js.echo.ledger.policy import (
    IdentityContext,
    PermitSeal,
    PolicyBundle,
    PolicyRule,
    create_permit_seal,
    evaluate_policy,
)
from js.echo.ledger.types import EffectIntent


class FakeAdapter(EffectAdapter):
    def __init__(self) -> None:
        self.executions = 0
        self.probes = 0

    def execute(self, effect_id: str, sealed_input_ref: str) -> EffectReceipt:
        self.executions += 1
        return EffectReceipt(
            receipt_id=f"receipt:{effect_id}",
            effect_id=effect_id,
            tenant_id="tenant-a",
            status="ok",
            output_ref=f"blob:output:{sealed_input_ref}",
            replay_class="idempotent",
        )

    def probe(self, effect_id: str) -> ProbeResult:
        self.probes += 1
        return ProbeResult(effect_id=effect_id, status="unknown", receipt=None)

    def cancel(self, effect_id: str) -> str:
        return f"cancelled:{effect_id}"


def _seal(
    *,
    action_kind: str = "tool.echo",
    replay_class: str = "idempotent",
) -> tuple[EffectIntent, PermitSeal]:
    intent = EffectIntent.build(
        tenant_id="tenant-a",
        run_id="run-1",
        task_path=("root", action_kind, replay_class),
        action_kind=action_kind,
        resource=action_kind,
        scopes=(action_kind,),
        input_hash="sha256:payload",
        replay_class=replay_class,
        risk="low",
    )
    identity = IdentityContext(actor_id="user-1", tenant_id="tenant-a", roles=("developer",))
    decision = evaluate_policy(
        intent,
        identity,
        PolicyBundle(
            bundle_id="bundle-1",
            rules=(
                PolicyRule(
                    rule_id="allow-tool",
                    effect="allow",
                    scopes=(action_kind,),
                    action_prefix=action_kind,
                ),
            ),
        ),
        resource_snapshot_hash="sha256:res",
        mac_key=b"test-key",
    )
    return intent, create_permit_seal(
        intent=intent,
        decision=decision,
        key_epoch="permit-epoch-1",
        journal_seq=7,
        deadline_ms=5000,
        signing_key=b"test-key",
    )


def test_journal_hash_chain_detects_record_tampering() -> None:
    journal = EchoJournal(mac_key=b"journal-key")
    first = journal.append(
        record_type="decision",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"decision_id": "d1"},
    )
    second = journal.append(
        record_type="permit",
        tenant_id="tenant-a",
        run_id="run-1",
        payload={"effect_id": "e1"},
    )

    assert first.seq == 0
    assert second.seq == 1
    assert verify_records(journal.records, mac_key=b"journal-key").ok

    tampered = list(journal.records)
    tampered[0] = dataclasses.replace(tampered[0], payload={"decision_id": "evil"})

    report = verify_records(tuple(tampered), mac_key=b"journal-key")

    assert not report.ok
    assert report.errors == ("seq:0:record_hash_mismatch",)


def test_outbox_refuses_dispatch_without_permit_seal() -> None:
    log = DurableEffectLog()

    with pytest.raises(PermissionError, match="PermitSeal"):
        log.enqueue(seal=None, sealed_input_ref="blob:input")


def test_archived_effect_lookup_blocks_non_idempotent_replay() -> None:
    _intent, seal = _seal(action_kind="tool.file_write", replay_class="non_idempotent")
    log = DurableEffectLog(completed_effect_lookup=lambda effect_id: effect_id == seal.effect_id)

    with pytest.raises(PermissionError, match="durable|already"):
        log.enqueue(seal=seal, sealed_input_ref="blob:replay")


def test_retained_snapshot_row_can_supersede_archived_effect_tombstone() -> None:
    _intent, seal = _seal(action_kind="tool.file_write", replay_class="non_idempotent")
    source = DurableEffectLog()
    row = source.enqueue(seal=seal, sealed_input_ref="blob:retained")
    replay = DurableEffectLog(completed_effect_lookup=lambda effect_id: effect_id == seal.effect_id)

    with pytest.raises(PermissionError, match="durable|already"):
        replay.load_outbox(row)

    replay.load_outbox(row, supersedes_snapshot_tombstone=True)
    assert replay.row_for_effect(seal.effect_id) == row


def test_archived_effect_lookup_failure_is_fail_closed() -> None:
    _intent, seal = _seal(action_kind="tool.file_write", replay_class="non_idempotent")

    def unavailable(_effect_id: str) -> bool:
        raise RuntimeError("archive unavailable")

    log = DurableEffectLog(completed_effect_lookup=unavailable)
    with pytest.raises(RuntimeError, match="archive unavailable"):
        log.enqueue(seal=seal, sealed_input_ref="blob:replay")


def test_receipt_recovery_replays_merge_without_reexecuting_effect() -> None:
    _intent, seal = _seal()
    log = DurableEffectLog()
    adapter = FakeAdapter()
    row = log.enqueue(seal=seal, sealed_input_ref="blob:input")

    receipt = log.dispatch(row.outbox_id, adapter)
    recovery = log.recover({"tool.echo": adapter})

    assert receipt.effect_id == seal.effect_id
    assert log.status(row.outbox_id) == "receipted"
    assert adapter.executions == 1
    assert recovery.merge_effect_ids == (seal.effect_id,)
    assert recovery.dispatch_effect_ids == ()
    assert adapter.executions == 1


def test_effect_outbox_rejects_receipt_tenant_mismatch() -> None:
    _intent, seal = _seal()
    log = DurableEffectLog()
    row = log.enqueue(seal=seal, sealed_input_ref="blob:input")
    log.claim(row.outbox_id)

    with pytest.raises(ValueError, match="tenant_id"):
        log.record_receipt(
            row.outbox_id,
            EffectReceipt(
                receipt_id=f"receipt:{seal.effect_id}",
                effect_id=seal.effect_id,
                tenant_id="tenant-b",
                status="ok",
                output_ref="blob:output",
                replay_class="idempotent",
            ),
        )

    assert log.status(row.outbox_id) == "claimed"


def test_unreceipted_claim_uses_probe_instead_of_blind_retry() -> None:
    _intent, seal = _seal()
    log = DurableEffectLog()
    adapter = FakeAdapter()
    row = log.enqueue(seal=seal, sealed_input_ref="blob:input")
    log.claim(row.outbox_id)

    recovery = log.recover({"tool.echo": adapter})

    assert adapter.executions == 0
    assert adapter.probes == 1
    assert recovery.manual_review_effect_ids == (seal.effect_id,)


def test_remove_merged_retains_only_irreversible_tool_tombstones() -> None:
    log = DurableEffectLog()
    _model_intent, model_seal = _seal(
        action_kind="model.js_agent_chat",
        replay_class="probe_required",
    )
    _tool_intent, tool_seal = _seal(
        action_kind="tool.file_write",
        replay_class="non_idempotent",
    )

    for seal in (model_seal, tool_seal):
        log.enqueue(seal=seal, sealed_input_ref=f"blob:{seal.effect_id}")
        log.mark_merged(seal.effect_id)

    assert set(log.completed_effect_ids()) == {model_seal.effect_id, tool_seal.effect_id}
    assert log.remove_merged() == 2
    assert log.completed_effect_ids() == (tool_seal.effect_id,)

    # Compacted model calls may be authorized again, matching journal replay.
    log.enqueue(seal=model_seal, sealed_input_ref="blob:model-retry")
    with pytest.raises(PermissionError, match="durable|already"):
        log.enqueue(seal=tool_seal, sealed_input_ref="blob:tool-retry")


def test_archived_lookup_allows_local_tombstone_memory_to_be_released() -> None:
    _intent, seal = _seal(action_kind="tool.file_write", replay_class="non_idempotent")
    archived: set[str] = set()
    log = DurableEffectLog(completed_effect_lookup=archived.__contains__)
    log.enqueue(seal=seal, sealed_input_ref="blob:original")
    log.mark_merged(seal.effect_id)
    assert log.remove_merged() == 1
    assert log.completed_effect_ids() == (seal.effect_id,)

    archived.add(seal.effect_id)
    assert log.clear_completed_effects() == 1
    assert log.completed_effect_ids() == ()
    with pytest.raises(PermissionError, match="durable|already"):
        log.enqueue(seal=seal, sealed_input_ref="blob:replay")
