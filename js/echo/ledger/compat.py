from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from js.echo.ledger.effects import DurableEffectLog, EffectAdapter, EffectReceipt, ProbeResult
from js.echo.ledger.journal import FileEchoLedger
from js.echo.ledger.kernel import decide
from js.echo.ledger.policy import (
    IdentityContext,
    PolicyBundle,
    PolicyRule,
    create_permit_seal,
    evaluate_policy,
)
from js.echo.ledger.privacy import (
    ModelCallRequest,
    ProviderCapability,
    build_model_privacy_envelope,
)
from js.echo.ledger.types import IntakeEvent, KernelSnapshot


@dataclass(frozen=True)
class MockChatResult:
    response_text: str
    record_types: tuple[str, ...]


class MockChatAdapter(EffectAdapter):
    def __init__(self, *, tenant_id: str, response_text: str) -> None:
        self._tenant_id = tenant_id
        self._response_text = response_text

    def execute(self, effect_id: str, sealed_input_ref: str) -> EffectReceipt:
        return EffectReceipt(
            receipt_id=f"receipt:{effect_id}",
            effect_id=effect_id,
            tenant_id=self._tenant_id,
            status="ok",
            output_ref=sealed_input_ref,
            replay_class="idempotent",
        )

    def probe(self, effect_id: str) -> ProbeResult:
        return ProbeResult(effect_id=effect_id, status="unknown", receipt=None)

    def cancel(self, effect_id: str) -> str:
        return f"cancelled:{effect_id}"

    @property
    def response_text(self) -> str:
        return self._response_text


def run_mock_chat_turn(
    *,
    tenant_id: str,
    run_id: str,
    user_text: str,
    journal_path: Path,
    journal_key: bytes,
    permit_key: bytes,
) -> MockChatResult:
    journal = FileEchoLedger(journal_path, mac_key=journal_key)
    journal.append(
        record_type="intake",
        tenant_id=tenant_id,
        run_id=run_id,
        payload={"payload_ref": f"text:{user_text}"},
    )

    snapshot = KernelSnapshot(tenant_id=tenant_id, run_id=run_id, run_seq=0, facts=())
    event = IntakeEvent(
        event_id="evt-1",
        tenant_id=tenant_id,
        run_id=run_id,
        payload_ref=f"text:{user_text}",
        trust_level="user",
        monotonic_ms=1,
        wall_time="2026-06-28T00:00:00Z",
    )
    decision = decide(snapshot, (event,))
    journal.append(
        record_type="decision",
        tenant_id=tenant_id,
        run_id=run_id,
        payload={"decision_id": decision.decision_id},
    )

    intent = decision.intents[0]
    identity = IdentityContext(actor_id="local-user", tenant_id=tenant_id, roles=("developer",))
    policy_decision = evaluate_policy(
        intent,
        identity,
        PolicyBundle(
            bundle_id="mock-chat",
            rules=(
                PolicyRule(
                    rule_id="allow-model",
                    effect="allow",
                    scopes=("model:invoke",),
                    action_prefix="model.",
                ),
            ),
        ),
        resource_snapshot_hash="sha256:mock",
        mac_key=permit_key,
    )
    journal.append(
        record_type="policy_decision",
        tenant_id=tenant_id,
        run_id=run_id,
        payload={"policy_decision_id": policy_decision.decision_id},
    )
    seal = create_permit_seal(
        intent=intent,
        decision=policy_decision,
        key_epoch="permit-epoch-1",
        journal_seq=len(journal.records),
        deadline_ms=60_000,
        signing_key=permit_key,
    )
    journal.append(
        record_type="permit",
        tenant_id=tenant_id,
        run_id=run_id,
        payload={"seal_id": seal.seal_id, "effect_id": seal.effect_id},
    )

    envelope = build_model_privacy_envelope(
        ModelCallRequest(
            model_request_id="model-1",
            tenant_id=tenant_id,
            provider_id="mock",
            model_id="mock-chat",
            prompt=user_text,
            data_classes=("UserPrivate",),
            prompt_slots_used=("user",),
            max_tokens=128,
            cost_budget=1,
            policy_decision_id=policy_decision.decision_id,
        ),
        ProviderCapability(
            provider_id="mock",
            zero_data_retention=True,
            retention_class="local-mock",
            region_policy=None,
        ),
    )
    journal.append(
        record_type="model_privacy_envelope",
        tenant_id=tenant_id,
        run_id=run_id,
        payload={"model_request_id": envelope.model_request_id, "allow_training": False},
    )

    effects = DurableEffectLog()
    row = effects.enqueue(seal=seal, sealed_input_ref=f"mock:{user_text}")
    journal.append(
        record_type="outbox",
        tenant_id=tenant_id,
        run_id=run_id,
        payload={"outbox_id": row.outbox_id, "effect_id": seal.effect_id},
    )
    adapter = MockChatAdapter(tenant_id=tenant_id, response_text=f"mock:{user_text}")
    receipt = effects.dispatch(row.outbox_id, adapter)
    journal.append(
        record_type="receipt",
        tenant_id=tenant_id,
        run_id=run_id,
        payload={"receipt_id": receipt.receipt_id, "effect_id": receipt.effect_id},
    )
    effects.mark_merged(receipt.effect_id)
    journal.append(
        record_type="merge",
        tenant_id=tenant_id,
        run_id=run_id,
        payload={"effect_id": receipt.effect_id},
    )
    return MockChatResult(
        response_text=adapter.response_text,
        record_types=tuple(record.record_type for record in journal.records),
    )
