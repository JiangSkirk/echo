"""P1-3: Orin policy lattice — widen needs explicit config or approval."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from js.config import JSSettings, OrinConfig, OrinPolicyProfile
from js.evolution.cycle import STATUS_PROPOSED, EvolutionCycle
from js.orin import taint as t
from js.orin.draft import EffectDraft, Impact, StateWitness
from js.orin.intent import Budgets, IntentEnvelope, request_hash_of
from js.orin.policy_lattice import (
    PolicyChangeError,
    compare_orin_config,
    compare_profiles,
    evaluate_orin_config_change,
    evaluate_policy_change_intent,
    evaluate_profile_change,
    payload_mutates_orin_policy,
    policy_profile_explicitly_set,
    reject_evolution_policy_mutation,
)
from js.orin.supervisor import prepare_product_orin
from js.orind.gatekeeper import GateKeeper
from js.orind.kernel import GateInputs, GateKernel, canonical_effect_hash_of
from js.orind.store import OrinStore
from js.utils.db import db_connection


def _settings(tmp_path: Path, **orin_kwargs: object) -> JSSettings:
    orin = OrinConfig(**orin_kwargs) if orin_kwargs else OrinConfig()
    return JSSettings(
        workspace=tmp_path / "ws",
        state_dir=tmp_path / "st",
        providers=[],
        orin=orin,
    )


def _gate(tmp_path: Path, *, profile: str) -> GateKeeper:
    return GateKeeper(
        mac_key=b"k" * 32,
        ledger_path=tmp_path / "lease.jsonl",
        store=OrinStore(tmp_path / "orin.db"),
        key_dir=tmp_path / "keys",
        policy_profile=profile,
        now_fn=lambda: 1_000_000,
    )


def _lease_params(tool: str) -> dict[str, object]:
    return {
        "owner_key_hash": "owner-a",
        "run_id": "run-1",
        "tool_name": tool,
        "args_schema": "args",
        "resource_scope": "scope",
        "max_bytes": 1024,
        "max_duration_ms": 1000,
        "ttl_ms": 60_000,
        "max_invocations": 1,
        "network_policy": "deny",
    }


def test_compat_is_wider_than_conservative() -> None:
    assert compare_profiles("compat", "conservative") == "narrow"
    assert compare_profiles("conservative", "compat") == "widen"
    assert compare_profiles("conservative", "conservative") == "equal"
    assert compare_profiles("mystery", "compat") == "unknown"


def test_widen_without_explicit_or_approval_is_denied() -> None:
    decision = evaluate_profile_change(
        before="conservative",
        after="compat",
    )
    assert decision.allowed is False
    assert decision.kind == "widen"
    assert decision.requires_approval is True


def test_widen_with_explicit_operator_setting_is_allowed() -> None:
    decision = evaluate_profile_change(
        before="conservative",
        after="compat",
        explicit=True,
    )
    assert decision.allowed is True
    assert decision.kind == "widen"


def test_widen_with_human_approval_is_allowed() -> None:
    decision = evaluate_profile_change(
        before="conservative",
        after="compat",
        approved=True,
    )
    assert decision.allowed is True
    assert decision.kind == "widen"


def test_narrow_auto_passes() -> None:
    decision = evaluate_profile_change(before="compat", after="conservative")
    assert decision.allowed is True
    assert decision.kind == "narrow"
    assert decision.requires_approval is False


def test_unknown_profile_fails_closed_toward_approval() -> None:
    decision = evaluate_profile_change(before="conservative", after="permissive")
    assert decision.allowed is False
    assert decision.kind == "unknown"
    assert decision.requires_approval is True


def test_shadow_mode_true_is_widen() -> None:
    assert compare_orin_config({"shadow_mode": False}, {"shadow_mode": True}) == "widen"
    decision = evaluate_orin_config_change(
        before={"shadow_mode": False},
        after={"shadow_mode": True},
    )
    assert decision.allowed is False
    assert decision.requires_approval is True


def test_opening_enforce_fails_closed() -> None:
    kind = compare_orin_config({"enforce": False}, {"enforce": True})
    assert kind == "unknown"
    decision = evaluate_orin_config_change(
        before={"enforce": False},
        after={"enforce": True},
        explicit=True,
    )
    assert decision.allowed is False
    assert decision.requires_approval is True


def test_prepare_does_not_silently_widen_to_compat(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    assert not policy_profile_explicitly_set(settings.orin)
    prepare_product_orin(settings)
    assert settings.orin.enabled is True
    assert settings.orin.policy_profile.value == "conservative"
    assert evaluate_profile_change(
        before="conservative",
        after=settings.orin.policy_profile.value,
    ).allowed


def test_prepare_keeps_explicit_compat(tmp_path: Path) -> None:
    settings = _settings(tmp_path, policy_profile=OrinPolicyProfile.COMPAT)
    assert policy_profile_explicitly_set(settings.orin)
    prepare_product_orin(settings)
    assert settings.orin.policy_profile.value == "compat"


def test_env_compat_is_treated_as_explicit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JS_ORIN__POLICY_PROFILE", "compat")
    settings = JSSettings(
        workspace=tmp_path / "ws",
        state_dir=tmp_path / "st",
        providers=[],
    )
    assert settings.orin.policy_profile.value == "compat"
    assert policy_profile_explicitly_set(settings.orin)
    prepare_product_orin(settings)
    assert settings.orin.policy_profile.value == "compat"


def test_prepare_does_not_compat_degrade_gateway(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    prepare_product_orin(settings)
    gate = _gate(tmp_path, profile=settings.orin.policy_profile.value)
    result = gate.handle_issue(
        _lease_params("file_write"),
        None,
        context_taint=t.WEB_CONTENT,
        arg_taint=t.WEB_CONTENT,
        channel="gateway:telegram",
    )
    assert result["ok"] is False
    assert result["code"] == "approval_required"
    assert "compat:" not in result["reason"]


def test_explicit_compat_still_keeps_gateway_conservative(tmp_path: Path) -> None:
    settings = _settings(tmp_path, policy_profile=OrinPolicyProfile.COMPAT)
    prepare_product_orin(settings)
    gate = _gate(tmp_path, profile=settings.orin.policy_profile.value)
    result = gate.handle_issue(
        _lease_params("file_write"),
        None,
        context_taint=t.WEB_CONTENT,
        arg_taint=t.WEB_CONTENT,
        channel="gateway:telegram",
    )
    assert result["ok"] is False
    assert result["code"] == "approval_required"
    assert "compat:" not in result["reason"]


def test_payload_mutates_orin_policy_detects_nested_keys() -> None:
    assert payload_mutates_orin_policy({"suggestion": "tighten prompt"}) is False
    assert payload_mutates_orin_policy({"policy_profile": "compat"}) is True
    assert payload_mutates_orin_policy({"orin": {"policy_profile": "compat"}}) is True
    assert payload_mutates_orin_policy({"patch": {"orin.policy_profile": "compat"}}) is True


def test_reject_evolution_policy_mutation_raises() -> None:
    with pytest.raises(PolicyChangeError):
        reject_evolution_policy_mutation({"orin": {"policy_profile": "compat"}})
    reject_evolution_policy_mutation({"suggestion": "review low scores", "auto_apply": False})


def test_forged_evolution_proposal_cannot_apply_policy_table(tmp_path: Path) -> None:
    cycle = EvolutionCycle(tmp_path)
    proposal = cycle.generate("owner-a", max_proposals=1)[0]
    with db_connection(cycle.db_path, row_factory=sqlite3.Row) as conn:
        conn.execute(
            """
            UPDATE evolution_proposals
            SET payload_json = ?
            WHERE proposal_id = ? AND owner = ?
            """,
            (
                json.dumps({"orin": {"policy_profile": "compat"}, "auto_apply": True}),
                proposal.proposal_id,
                "owner-a",
            ),
        )
        conn.commit()
    with pytest.raises(PolicyChangeError, match="must not mutate"):
        cycle.approve_and_apply(
            proposal.proposal_id,
            "owner-a",
            decided_by="admin",
            benchmark=lambda: 1.0,
            baseline_score=1.0,
        )
    leftover = cycle.get(proposal.proposal_id, "owner-a")
    assert leftover is not None
    assert leftover.status == STATUS_PROPOSED
    assert not list((tmp_path / "evolution" / "applied").glob("*.json"))


def _assess_policy_change(
    *,
    current_profile: str,
    after: str,
    approved: bool,
) -> object:
    now = 1_000_000
    task = "task:" + "a" * 32
    draft = EffectDraft(
        draft_id="draft:" + "b" * 32,
        task_id=task,
        effect_type="policy.change",
        arguments={"policy_profile": after},
        declared_expectation={},
    )
    effect_hash = canonical_effect_hash_of(draft)
    intent = IntentEnvelope(
        intent_id="intent:" + "d" * 32,
        owner_key_hash="sha256:" + "1" * 64,
        product_id="js-agent",
        profile="personal",
        task_id=task,
        raw_request_hash=request_hash_of("change policy"),
        allowed_effect_classes=("policy.change",),
        allowed_resource_handles=(),
        allowed_sink_handles=(),
        budgets=Budgets(max_invocations=1),
        approval_policy="dual_control",
        issued_by="appshell:test",
        issued_at_ms=now - 1,
        expires_at_ms=now + 60_000,
    )
    witness = StateWitness(
        witness_id="state:" + "c" * 32,
        draft_id=draft.draft_id,
        executor_id="cell:test",
        target_version="v1",
        canonical_effect_hash=effect_hash,
        impact=Impact(),
        reversibility="irreversible_after_provider_accept",
        idempotency_support="none",
        created_at_ms=now - 1,
        expires_at_ms=now + 60_000,
    )
    return GateKernel(secret_taint_bit=1 << 12).assess(
        draft,
        GateInputs(
            now_ms=now,
            intent=intent,
            witness=witness,
            canonical_effect_hash=effect_hash,
            policy_profile=current_profile,
            approval_satisfied=approved,
        ),
    )


def test_policy_change_intent_widen_requires_approval() -> None:
    lattice = evaluate_policy_change_intent(
        {"policy_profile": "compat"},
        current_profile="conservative",
    )
    assert lattice.allowed is False
    decision = _assess_policy_change(
        current_profile="conservative",
        after="compat",
        approved=False,
    )
    assert decision.verdict == "require_dual_control"
    assert decision.reason_code == "policy_widen_requires_approval"


def test_policy_change_intent_narrow_still_dual_control() -> None:
    lattice = evaluate_policy_change_intent(
        {"policy_profile": "conservative"},
        current_profile="compat",
    )
    assert lattice.allowed is True
    decision = _assess_policy_change(
        current_profile="compat",
        after="conservative",
        approved=False,
    )
    assert decision.verdict == "require_dual_control"
    assert decision.reason_code == "dual_control_required"


def test_policy_change_approved_widen_still_dual_control() -> None:
    decision = _assess_policy_change(
        current_profile="conservative",
        after="compat",
        approved=True,
    )
    assert decision.verdict == "require_dual_control"
    assert decision.reason_code == "dual_control_required"


def test_daemon_gate_inputs_carry_configured_policy_profile(tmp_path: Path) -> None:
    from js.orind.daemon import OrinDaemon

    daemon = OrinDaemon(
        state_dir=tmp_path,
        stage_b=True,
        policy_profile="compat",
    )
    draft = EffectDraft(
        draft_id="draft:" + "b" * 32,
        task_id="task:" + "a" * 32,
        effect_type="policy.change",
        arguments={"policy_profile": "compat"},
        declared_expectation={},
    )
    inputs, _error = daemon._gate_inputs_for_record(draft, {})
    assert inputs.policy_profile == "compat"
