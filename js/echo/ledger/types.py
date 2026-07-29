from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from js.echo.ledger._hashing import stable_hash

ReplayClass = Literal["idempotent", "probe_required", "non_idempotent"]
RiskLevel = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class IntakeEvent:
    event_id: str
    tenant_id: str
    run_id: str
    payload_ref: str
    trust_level: str
    monotonic_ms: int
    wall_time: str


@dataclass(frozen=True)
class KernelSnapshot:
    tenant_id: str
    run_id: str
    run_seq: int
    facts: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class EffectIntent:
    effect_id: str
    tenant_id: str
    run_id: str
    task_path: tuple[str, ...]
    action_kind: str
    resource: str
    scopes: tuple[str, ...]
    input_hash: str
    replay_class: ReplayClass
    risk: RiskLevel

    @classmethod
    def build(
        cls,
        *,
        tenant_id: str,
        run_id: str,
        task_path: tuple[str, ...],
        action_kind: str,
        resource: str,
        scopes: tuple[str, ...],
        input_hash: str,
        replay_class: ReplayClass,
        risk: RiskLevel,
    ) -> EffectIntent:
        stable_id = stable_hash(
            {
                "tenant_id": tenant_id,
                "run_id": run_id,
                "task_path": task_path,
                "action_kind": action_kind,
                "resource": resource,
                "scopes": scopes,
                "input_hash": input_hash,
                "replay_class": replay_class,
            }
        )
        return cls(
            effect_id="eff_" + stable_id.removeprefix("sha256:")[:32],
            tenant_id=tenant_id,
            run_id=run_id,
            task_path=task_path,
            action_kind=action_kind,
            resource=resource,
            scopes=scopes,
            input_hash=input_hash,
            replay_class=replay_class,
            risk=risk,
        )


@dataclass(frozen=True)
class DecisionBundle:
    decision_id: str
    tenant_id: str
    run_id: str
    run_seq: int
    intents: tuple[EffectIntent, ...]
    response_ref: str
    input_hash: str
    denials: tuple[str, ...] = ()
