from __future__ import annotations

from js.echo.ledger._hashing import stable_hash
from js.echo.ledger.types import DecisionBundle, EffectIntent, IntakeEvent, KernelSnapshot


def decide(snapshot: KernelSnapshot, inbound: tuple[IntakeEvent, ...]) -> DecisionBundle:
    denials: list[str] = []
    accepted: list[IntakeEvent] = []
    for event in inbound:
        if event.tenant_id != snapshot.tenant_id or event.run_id != snapshot.run_id:
            denials.append(f"tenant_mismatch:{event.event_id}")
            continue
        if not event.payload_ref:
            raise ValueError("payload_ref must be non-empty")
        accepted.append(event)

    intents = tuple(
        EffectIntent.build(
            tenant_id=snapshot.tenant_id,
            run_id=snapshot.run_id,
            task_path=("chat", event.event_id),
            action_kind="model.mock_chat",
            resource="model:mock",
            scopes=("model:invoke",),
            input_hash=stable_hash(
                {
                    "event_id": event.event_id,
                    "payload_ref": event.payload_ref,
                    "trust_level": event.trust_level,
                }
            ),
            replay_class="idempotent",
            risk="low",
        )
        for event in accepted
    )
    input_hash = stable_hash(
        {
            "snapshot": {
                "tenant_id": snapshot.tenant_id,
                "run_id": snapshot.run_id,
                "run_seq": snapshot.run_seq,
                "facts": snapshot.facts,
            },
            "events": [
                {
                    "event_id": event.event_id,
                    "tenant_id": event.tenant_id,
                    "run_id": event.run_id,
                    "payload_ref": event.payload_ref,
                    "trust_level": event.trust_level,
                    "monotonic_ms": event.monotonic_ms,
                    "wall_time": event.wall_time,
                }
                for event in inbound
            ],
        }
    )
    decision_id = "dec_" + stable_hash(
        {
            "run_seq": snapshot.run_seq,
            "input_hash": input_hash,
            "intent_ids": [intent.effect_id for intent in intents],
            "denials": denials,
        }
    ).removeprefix("sha256:")[:32]
    return DecisionBundle(
        decision_id=decision_id,
        tenant_id=snapshot.tenant_id,
        run_id=snapshot.run_id,
        run_seq=snapshot.run_seq + 1,
        intents=intents,
        response_ref="pending" if intents else "denied",
        input_hash=input_hash,
        denials=tuple(denials),
    )
