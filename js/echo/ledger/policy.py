from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

from js.echo.ledger._hashing import hmac_matches, stable_hash, stable_hmac
from js.echo.ledger.types import EffectIntent

PolicyEffect = Literal["allow", "deny", "require_approval"]
PolicyResult = Literal["allow", "deny", "require_approval"]


@dataclass(frozen=True)
class IdentityContext:
    actor_id: str
    tenant_id: str
    roles: tuple[str, ...]


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    effect: PolicyEffect
    scopes: tuple[str, ...]
    action_prefix: str = ""
    reason: str = ""

    def matches(self, intent: EffectIntent) -> bool:
        action_matches = not self.action_prefix or intent.action_kind.startswith(self.action_prefix)
        scope_matches = bool(set(intent.scopes).intersection(self.scopes))
        return action_matches and scope_matches


@dataclass(frozen=True)
class PolicyBundle:
    bundle_id: str
    rules: tuple[PolicyRule, ...]

    @property
    def bundle_hash(self) -> str:
        return stable_hash(
            {
                "bundle_id": self.bundle_id,
                "rules": [
                    {
                        "rule_id": rule.rule_id,
                        "effect": rule.effect,
                        "scopes": rule.scopes,
                        "action_prefix": rule.action_prefix,
                        "reason": rule.reason,
                    }
                    for rule in self.rules
                ],
            }
        )


@dataclass(frozen=True)
class PolicyDecisionRecord:
    decision_id: str
    effect_id: str
    tenant_id: str
    policy_bundle_hash: str
    input_hash: str
    result: PolicyResult
    granted_scopes: tuple[str, ...]
    denied_reasons: tuple[str, ...]
    approval_challenge_ref: str | None
    evaluated_rules: tuple[str, ...]
    schema_version: str
    mac: bytes

    def _mac_payload(self) -> dict[str, object]:
        return {
            "decision_id": self.decision_id,
            "effect_id": self.effect_id,
            "tenant_id": self.tenant_id,
            "policy_bundle_hash": self.policy_bundle_hash,
            "input_hash": self.input_hash,
            "result": self.result,
            "granted_scopes": self.granted_scopes,
            "denied_reasons": self.denied_reasons,
            "approval_challenge_ref": self.approval_challenge_ref,
            "evaluated_rules": self.evaluated_rules,
            "schema_version": self.schema_version,
        }

    def verify(self, mac_key: bytes) -> bool:
        """Verify the record MAC against the service-derived key.

        Fails closed: records signed with any other key (including the
        legacy hardcoded ``b"policy-decision-record-v1"`` constant) are
        rejected.
        """
        return hmac_matches(mac_key, self._mac_payload(), self.mac)


@dataclass(frozen=True)
class PermitSeal:
    seal_id: str
    effect_id: str
    tenant_id: str
    action_kind: str
    policy_decision_id: str
    granted_scopes: tuple[str, ...]
    key_epoch: str
    journal_seq: int
    deadline_ms: int
    replay_class: str
    mac: bytes

    def _mac_payload(self) -> dict[str, object]:
        return {
            "seal_id": self.seal_id,
            "effect_id": self.effect_id,
            "tenant_id": self.tenant_id,
            "action_kind": self.action_kind,
            "policy_decision_id": self.policy_decision_id,
            "granted_scopes": self.granted_scopes,
            "key_epoch": self.key_epoch,
            "journal_seq": self.journal_seq,
            "deadline_ms": self.deadline_ms,
            "replay_class": self.replay_class,
        }

    def verify(self, signing_key: bytes) -> bool:
        return hmac_matches(signing_key, self._mac_payload(), self.mac)


def evaluate_policy(
    intent: EffectIntent,
    identity: IdentityContext,
    bundle: PolicyBundle,
    *,
    resource_snapshot_hash: str,
    mac_key: bytes,
) -> PolicyDecisionRecord:
    evaluated: list[str] = []
    denied_reasons: list[str] = []
    allow_scopes: set[str] = set()
    approval_required = False

    if identity.tenant_id != intent.tenant_id:
        denied_reasons.append("tenant_boundary:identity_tenant_mismatch")

    for rule in bundle.rules:
        if not rule.matches(intent):
            continue
        evaluated.append(rule.rule_id)
        if rule.effect == "deny":
            reason = rule.reason or "explicit deny"
            denied_reasons.append(f"{rule.rule_id}:{reason}")
        elif rule.effect == "allow":
            allow_scopes.update(set(intent.scopes).intersection(rule.scopes))
        elif rule.effect == "require_approval":
            approval_required = True

    if denied_reasons:
        result: PolicyResult = "deny"
        granted_scopes: tuple[str, ...] = ()
        approval_ref = None
    elif allow_scopes:
        result = "require_approval" if approval_required else "allow"
        granted_scopes = tuple(scope for scope in intent.scopes if scope in allow_scopes)
        approval_ref = (
            "approval:" + stable_hash({"effect_id": intent.effect_id, "rules": evaluated})[-16:]
            if approval_required
            else None
        )
    else:
        result = "deny"
        granted_scopes = ()
        denied_reasons.append("default_deny:no_allow_rule")
        approval_ref = None

    input_hash = stable_hash(
        {
            "intent": {
                "effect_id": intent.effect_id,
                "tenant_id": intent.tenant_id,
                "action_kind": intent.action_kind,
                "resource": intent.resource,
                "scopes": intent.scopes,
                "input_hash": intent.input_hash,
            },
            "identity": {
                "actor_id": identity.actor_id,
                "tenant_id": identity.tenant_id,
                "roles": identity.roles,
            },
            "policy_bundle_hash": bundle.bundle_hash,
            "resource_snapshot_hash": resource_snapshot_hash,
        }
    )
    decision_id = "pdr_" + stable_hash(
        {
            "effect_id": intent.effect_id,
            "input_hash": input_hash,
            "result": result,
            "granted_scopes": granted_scopes,
            "denied_reasons": denied_reasons,
            "evaluated": evaluated,
        }
    ).removeprefix("sha256:")[:32]
    record = PolicyDecisionRecord(
        decision_id=decision_id,
        effect_id=intent.effect_id,
        tenant_id=intent.tenant_id,
        policy_bundle_hash=bundle.bundle_hash,
        input_hash=input_hash,
        result=result,
        granted_scopes=granted_scopes,
        denied_reasons=tuple(denied_reasons),
        approval_challenge_ref=approval_ref,
        evaluated_rules=tuple(evaluated),
        schema_version="policy-decision-record/v1",
        mac=b"",
    )
    # The MAC key is derived per service instance (same domain as the permit
    # signing key); never sign with a public constant, which would let anyone
    # forge allow decisions.
    return replace(record, mac=stable_hmac(mac_key, record._mac_payload()))


def create_permit_seal(
    *,
    intent: EffectIntent,
    decision: PolicyDecisionRecord,
    key_epoch: str,
    journal_seq: int,
    deadline_ms: int,
    signing_key: bytes,
) -> PermitSeal:
    if decision.result != "allow":
        raise PermissionError("PermitSeal can only be created from an allow decision")
    if not decision.verify(signing_key):
        raise PermissionError("PolicyDecisionRecord MAC invalid")
    if decision.effect_id != intent.effect_id:
        raise PermissionError("PolicyDecisionRecord does not match intent")
    if decision.tenant_id != intent.tenant_id:
        raise PermissionError("PolicyDecisionRecord tenant does not match intent")

    seal_id = "seal_" + stable_hash(
        {
            "effect_id": intent.effect_id,
            "policy_decision_id": decision.decision_id,
            "journal_seq": journal_seq,
            "deadline_ms": deadline_ms,
            "key_epoch": key_epoch,
        }
    ).removeprefix("sha256:")[:32]
    payload = {
        "seal_id": seal_id,
        "effect_id": intent.effect_id,
        "tenant_id": intent.tenant_id,
        "action_kind": intent.action_kind,
        "policy_decision_id": decision.decision_id,
        "granted_scopes": decision.granted_scopes,
        "key_epoch": key_epoch,
        "journal_seq": journal_seq,
        "deadline_ms": deadline_ms,
        "replay_class": intent.replay_class,
    }
    return PermitSeal(
        seal_id=seal_id,
        effect_id=intent.effect_id,
        tenant_id=intent.tenant_id,
        action_kind=intent.action_kind,
        policy_decision_id=decision.decision_id,
        granted_scopes=decision.granted_scopes,
        key_epoch=key_epoch,
        journal_seq=journal_seq,
        deadline_ms=deadline_ms,
        replay_class=intent.replay_class,
        mac=stable_hmac(signing_key, payload),
    )
