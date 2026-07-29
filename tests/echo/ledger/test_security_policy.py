from __future__ import annotations

import dataclasses

import pytest

from js.echo.ledger._hashing import stable_hmac
from js.echo.ledger.policy import (
    IdentityContext,
    PolicyBundle,
    PolicyDecisionRecord,
    PolicyRule,
    create_permit_seal,
    evaluate_policy,
)
from js.echo.ledger.types import EffectIntent


def _intent(*, scopes: tuple[str, ...] = ("file:read",), action_kind: str = "file.read") -> EffectIntent:
    return EffectIntent.build(
        tenant_id="tenant-a",
        run_id="run-1",
        task_path=("root", "effect"),
        action_kind=action_kind,
        resource="file:/safe/readme.md",
        scopes=scopes,
        input_hash="sha256:payload",
        replay_class="idempotent",
        risk="low",
    )


def test_policy_deny_overrides_allow_and_is_replayable() -> None:
    intent = _intent(scopes=("file:read", "file:write"), action_kind="file.write")
    identity = IdentityContext(actor_id="user-1", tenant_id="tenant-a", roles=("developer",))
    bundle = PolicyBundle(
        bundle_id="bundle-1",
        rules=(
            PolicyRule(
                rule_id="allow-file",
                effect="allow",
                scopes=("file:read", "file:write"),
                action_prefix="file.",
            ),
            PolicyRule(
                rule_id="deny-write",
                effect="deny",
                scopes=("file:write",),
                action_prefix="file.write",
                reason="writes disabled",
            ),
        ),
    )

    first = evaluate_policy(intent, identity, bundle, resource_snapshot_hash="sha256:res", mac_key=b"test-mac-key")
    second = evaluate_policy(intent, identity, bundle, resource_snapshot_hash="sha256:res", mac_key=b"test-mac-key")

    assert first == second
    assert first.result == "deny"
    assert first.denied_reasons == ("deny-write:writes disabled",)
    assert first.evaluated_rules == ("allow-file", "deny-write")


def test_policy_allow_grants_only_requested_scope_intersection() -> None:
    intent = _intent(scopes=("file:read", "network:egress"), action_kind="file.read")
    identity = IdentityContext(actor_id="user-1", tenant_id="tenant-a", roles=("developer",))
    bundle = PolicyBundle(
        bundle_id="bundle-1",
        rules=(
            PolicyRule(
                rule_id="allow-limited",
                effect="allow",
                scopes=("file:read", "file:write"),
                action_prefix="file.",
            ),
        ),
    )

    record = evaluate_policy(intent, identity, bundle, resource_snapshot_hash="sha256:res", mac_key=b"test-key")

    assert record.result == "allow"
    assert record.granted_scopes == ("file:read",)


def test_human_approval_cannot_expand_policy_denial() -> None:
    intent = _intent(scopes=("file:write",), action_kind="file.write")
    identity = IdentityContext(actor_id="user-1", tenant_id="tenant-a", roles=("developer",))
    bundle = PolicyBundle(
        bundle_id="bundle-1",
        rules=(
            PolicyRule(
                rule_id="deny-write",
                effect="deny",
                scopes=("file:write",),
                action_prefix="file.write",
            ),
            PolicyRule(
                rule_id="approval-write",
                effect="require_approval",
                scopes=("file:write",),
                action_prefix="file.write",
            ),
        ),
    )

    record = evaluate_policy(intent, identity, bundle, resource_snapshot_hash="sha256:res", mac_key=b"test-key")

    assert record.result == "deny"
    assert record.approval_challenge_ref is None


def test_permit_seal_requires_allow_decision_and_binds_decision_id() -> None:
    intent = _intent()
    identity = IdentityContext(actor_id="user-1", tenant_id="tenant-a", roles=("developer",))
    bundle = PolicyBundle(
        bundle_id="bundle-1",
        rules=(
            PolicyRule(
                rule_id="allow-read",
                effect="allow",
                scopes=("file:read",),
                action_prefix="file.",
            ),
        ),
    )
    decision = evaluate_policy(intent, identity, bundle, resource_snapshot_hash="sha256:res", mac_key=b"test-key")

    seal = create_permit_seal(
        intent=intent,
        decision=decision,
        key_epoch="permit-epoch-1",
        journal_seq=42,
        deadline_ms=5000,
        signing_key=b"test-key",
    )

    assert seal.policy_decision_id == decision.decision_id
    assert seal.effect_id == intent.effect_id
    assert seal.journal_seq == 42
    assert seal.verify(b"test-key")
    assert not dataclasses.replace(seal, journal_seq=43).verify(b"test-key")


def test_permit_seal_refuses_denied_decision() -> None:
    intent = _intent(action_kind="file.write")
    identity = IdentityContext(actor_id="user-1", tenant_id="tenant-a", roles=("developer",))
    bundle = PolicyBundle(
        bundle_id="bundle-1",
        rules=(
            PolicyRule(
                rule_id="deny-write",
                effect="deny",
                scopes=("file:write",),
                action_prefix="file.write",
            ),
        ),
    )
    decision = evaluate_policy(intent, identity, bundle, resource_snapshot_hash="sha256:res", mac_key=b"test-key")

    with pytest.raises(PermissionError, match="allow"):
        create_permit_seal(
            intent=intent,
            decision=decision,
            key_epoch="permit-epoch-1",
            journal_seq=42,
            deadline_ms=5000,
            signing_key=b"test-key",
        )


def _allow_decision(mac_key: bytes) -> tuple[EffectIntent, PolicyDecisionRecord]:
    intent = _intent()
    identity = IdentityContext(actor_id="user-1", tenant_id="tenant-a", roles=("developer",))
    bundle = PolicyBundle(
        bundle_id="bundle-1",
        rules=(
            PolicyRule(
                rule_id="allow-read",
                effect="allow",
                scopes=("file:read",),
                action_prefix="file.",
            ),
        ),
    )
    decision = evaluate_policy(
        intent, identity, bundle, resource_snapshot_hash="sha256:res", mac_key=mac_key
    )
    assert decision.result == "allow"
    return intent, decision


def test_permit_seal_rejects_decision_signed_with_legacy_public_key() -> None:
    """F-23: a PolicyDecisionRecord forged with the old hardcoded public
    constant key must fail closed at permit creation."""
    intent, decision = _allow_decision(b"service-secret-key")
    forged = dataclasses.replace(
        decision,
        mac=stable_hmac(b"policy-decision-record-v1", decision._mac_payload()),
    )

    assert not forged.verify(b"service-secret-key")
    with pytest.raises(PermissionError, match="MAC"):
        create_permit_seal(
            intent=intent,
            decision=forged,
            key_epoch="permit-epoch-1",
            journal_seq=42,
            deadline_ms=5000,
            signing_key=b"service-secret-key",
        )


def test_permit_seal_rejects_decision_signed_with_wrong_key() -> None:
    """A decision minted under another instance's key is not trusted."""
    intent, foreign_decision = _allow_decision(b"other-instance-key")

    with pytest.raises(PermissionError, match="MAC"):
        create_permit_seal(
            intent=intent,
            decision=foreign_decision,
            key_epoch="permit-epoch-1",
            journal_seq=42,
            deadline_ms=5000,
            signing_key=b"service-secret-key",
        )


def test_decision_verify_accepts_own_key() -> None:
    _intent_obj, decision = _allow_decision(b"service-secret-key")
    assert decision.verify(b"service-secret-key")
    assert not decision.verify(b"policy-decision-record-v1")
