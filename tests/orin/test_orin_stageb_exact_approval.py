"""Personal ``file.commit`` exact-approval product boundary.

These tests deliberately keep ``ExactCommitApprovalV1`` separate from
``ExportPass``.  The former authorizes one already-preflighted local file
draft; the latter remains exclusive to named egress effects.
"""

from __future__ import annotations

import base64
import concurrent.futures
import json
import sqlite3
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from js.echo.capability import LeaseDenied
from js.orin.client import OrinLeaseClientAdapter
from js.orin.draft import EffectDraft, ExactCommitApprovalV1, Impact, StateWitness
from js.orin.intent import Budgets, IntentEnvelope
from js.orin.protocol import ProtocolError, canonical_json, make_envelope, parse_frame
from js.orin.testing import TestOrind as OrindHarness
from js.orind import membrane as membrane_module
from js.orind.intent_store import IntentStore
from js.orind.kernel import canonical_effect_hash_of
from js.orind.membrane import (
    CommitMembrane,
    CommitState,
    ExactApprovalUnavailable,
    ExportPassUnavailable,
    OperationConflict,
    OperationSpec,
)
from js.orind.store import OrinStore

_STORE_NOW_MS = 2_000_000_000_000
_STORE_OWNER_HASH = "sha256:" + "1" * 64

_ExactFixture = tuple[
    OrindHarness,
    ed25519.Ed25519PrivateKey,
    ed25519.Ed25519PrivateKey,
    Path,
]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _pub_of(key: ed25519.Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _adapter(orind: OrindHarness) -> OrinLeaseClientAdapter:
    return OrinLeaseClientAdapter(
        socket_path=orind.socket_path,
        state_dir=Path(orind.daemon._state_dir),  # noqa: SLF001 - boundary probe
        stage_b=True,
    )


def _approval_type() -> tuple[type[Any], Any]:
    from js.orin.draft import ExactCommitApprovalV1, exact_commit_approval_from_dict

    return ExactCommitApprovalV1, exact_commit_approval_from_dict


def _approval(
    prepared: _PreparedFile,
    key: ed25519.Ed25519PrivateKey,
    **overrides: Any,
) -> Any:
    approval_type, _parser = _approval_type()
    now = _now_ms()
    fields: dict[str, Any] = {
        "approval_id": f"exact:{uuid4().hex}",
        "task_id": prepared.draft.task_id,
        "draft_id": prepared.draft.draft_id,
        "witness_id": prepared.witness_id,
        "canonical_effect_hash": prepared.effect_hash,
        "directory_handle_id": prepared.directory_handle_id,
        "approved": True,
        "created_at_ms": now - 1_000,
        "expires_at_ms": now + 60_000,
    }
    fields.update(overrides)
    return approval_type(**fields).sign_with(key)


def _unit_intent(
    key: ed25519.Ed25519PrivateKey,
    *,
    task_id: str,
    intent_id: str,
    issued_at_ms: int = _STORE_NOW_MS - 1_000,
    expires_at_ms: int = _STORE_NOW_MS + 60_000,
    effects: tuple[str, ...] = ("file.commit",),
    resources: tuple[str, ...] = ("dirh:unit-root",),
) -> IntentEnvelope:
    return IntentEnvelope(
        intent_id=intent_id,
        owner_key_hash=_STORE_OWNER_HASH,
        product_id="js-agent",
        profile="personal",
        task_id=task_id,
        raw_request_hash="sha256:" + "2" * 64,
        allowed_effect_classes=effects,
        allowed_resource_handles=resources,
        allowed_sink_handles=(),
        budgets=Budgets(max_invocations=4, max_bytes_out=1 << 20),
        approval_policy="exact_commit_required",
        issued_by="appshell:exact-unit",
        issued_at_ms=issued_at_ms,
        expires_at_ms=expires_at_ms,
    ).sign_with(key)


def _unit_exact_approval(
    key: ed25519.Ed25519PrivateKey,
    *,
    approval_id: str,
    task_id: str,
    draft_id: str = "draft:unit",
    witness_id: str = "state:unit",
    effect_hash: str = "sha256:" + "3" * 64,
    directory_handle_id: str = "dirh:unit-root",
) -> ExactCommitApprovalV1:
    return ExactCommitApprovalV1(
        approval_id=approval_id,
        task_id=task_id,
        draft_id=draft_id,
        witness_id=witness_id,
        canonical_effect_hash=effect_hash,
        directory_handle_id=directory_handle_id,
        approved=True,
        created_at_ms=_STORE_NOW_MS - 1_000,
        expires_at_ms=_STORE_NOW_MS + 60_000,
    ).sign_with(key)


def _exact_binding(approval: ExactCommitApprovalV1) -> dict[str, str]:
    return {
        "task_id": approval.task_id,
        "draft_id": approval.draft_id,
        "witness_id": approval.witness_id,
        "canonical_effect_hash": approval.canonical_effect_hash,
        "directory_handle_id": approval.directory_handle_id,
    }


class TestExactCommitApprovalSchema:
    def test_signature_round_trip_is_strict_and_owner_verifiable(self) -> None:
        approval_type, parser = _approval_type()
        owner = ed25519.Ed25519PrivateKey.generate()
        now = _now_ms()
        signed = approval_type(
            approval_id="exact:round-trip",
            task_id="task:round-trip",
            draft_id="draft:round-trip",
            witness_id="state:round-trip",
            canonical_effect_hash="sha256:" + "a" * 64,
            directory_handle_id="dirh:round-trip",
            approved=True,
            created_at_ms=now - 1_000,
            expires_at_ms=now + 60_000,
        ).sign_with(owner)

        raw = signed.to_dict()
        assert set(raw) == {
            "schema",
            "approval_id",
            "task_id",
            "draft_id",
            "witness_id",
            "canonical_effect_hash",
            "directory_handle_id",
            "approved",
            "created_at_ms",
            "expires_at_ms",
            "signature",
        }
        assert raw["schema"] == "ExactCommitApprovalV1"
        parsed = parser(raw)
        assert parsed == signed
        assert parsed.verify(_pub_of(owner)) is True
        assert parsed.verify(_pub_of(ed25519.Ed25519PrivateKey.generate())) is False
        assert replace(parsed, witness_id="state:tampered").verify(_pub_of(owner)) is False

    @pytest.mark.parametrize(
        ("mutation", "value"),
        (
            ("unknown", "field"),
            ("approved", 1),
            ("approved", "true"),
            ("approved", False),
            ("created_at_ms", True),
            ("canonical_effect_hash", "sha256:" + "G" * 64),
            ("directory_handle_id", "rcpt:not-a-directory"),
            ("expires_at_ms", 1),
        ),
    )
    def test_unknown_fields_fake_booleans_and_invalid_bindings_are_rejected(
        self,
        mutation: str,
        value: Any,
    ) -> None:
        approval_type, parser = _approval_type()
        now = _now_ms()
        raw = approval_type(
            approval_id="exact:strict",
            task_id="task:strict",
            draft_id="draft:strict",
            witness_id="state:strict",
            canonical_effect_hash="sha256:" + "b" * 64,
            directory_handle_id="dirh:strict",
            approved=True,
            created_at_ms=now - 1_000,
            expires_at_ms=now + 60_000,
        ).to_dict()
        if mutation == "unknown":
            raw[str(value)] = True
        else:
            raw[mutation] = value
        with pytest.raises(ProtocolError):
            parser(raw)

    @pytest.mark.parametrize(
        "missing",
        (
            "schema",
            "approval_id",
            "task_id",
            "draft_id",
            "witness_id",
            "canonical_effect_hash",
            "directory_handle_id",
            "approved",
            "created_at_ms",
            "expires_at_ms",
            "signature",
        ),
    )
    def test_every_wire_field_is_required(self, missing: str) -> None:
        approval_type, parser = _approval_type()
        now = _now_ms()
        raw = approval_type(
            approval_id="exact:required",
            task_id="task:required",
            draft_id="draft:required",
            witness_id="state:required",
            canonical_effect_hash="sha256:" + "c" * 64,
            directory_handle_id="dirh:required",
            approved=True,
            created_at_ms=now - 1_000,
            expires_at_ms=now + 60_000,
        ).to_dict()
        raw.pop(missing)
        with pytest.raises(ProtocolError):
            parser(raw)

    def test_grant_exact_reuses_intent_message_with_one_exact_shape(self) -> None:
        approval_type, _parser = _approval_type()
        now = _now_ms()
        grant = approval_type(
            approval_id="exact:wire",
            task_id="task:wire",
            draft_id="draft:wire",
            witness_id="state:wire",
            canonical_effect_hash="sha256:" + "d" * 64,
            directory_handle_id="dirh:wire",
            approved=True,
            created_at_ms=now - 1_000,
            expires_at_ms=now + 60_000,
        ).to_dict()
        envelope = make_envelope(
            "intent",
            seq=1,
            nonce="0" * 32,
            session_key=b"k" * 32,
            op="grant_exact",
            task_id="task:wire",
            grant=grant,
        )
        parsed = parse_frame(canonical_json(envelope).encode("utf-8"))
        assert parsed["op"] == "grant_exact"
        assert parsed["task_id"] == "task:wire"
        assert parsed["grant"] == grant
        assert "intent" not in parsed and "session_id" not in parsed

    @pytest.mark.parametrize(
        "fields",
        (
            {"task_id": "task:wire"},
            {"grant": {}},
            {"task_id": "task:wire", "grant": [],},
            {"task_id": "task:wire", "grant": {}, "intent": {}},
            {"task_id": "task:wire", "grant": {}, "session_id": "session:echo"},
        ),
    )
    def test_grant_exact_rejects_missing_or_mixed_authority_fields(
        self,
        fields: dict[str, Any],
    ) -> None:
        with pytest.raises(ProtocolError):
            make_envelope(
                "intent",
                seq=1,
                nonce="1" * 32,
                session_key=b"k" * 32,
                op="grant_exact",
                **fields,
            )

    def test_existing_intent_op_discriminants_remain_closed(self) -> None:
        plain = make_envelope(
            "intent",
            seq=1,
            nonce="2" * 32,
            session_key=b"k" * 32,
            op="register",
            intent={},
        )
        assert parse_frame(canonical_json(plain).encode("utf-8"))["op"] == "register"
        with pytest.raises(ProtocolError):
            make_envelope(
                "intent",
                seq=2,
                nonce="3" * 32,
                session_key=b"k" * 32,
                op="admin_unfreeze",
                intent={},
                session_id="session:frozen",
                grant={},
            )


class TestExactApprovalStoreAuthority:
    def test_exact_permission_uses_effective_intersection_not_active_signer(
        self,
        tmp_path: Path,
    ) -> None:
        owner = ed25519.Ed25519PrivateKey.generate()
        task_id = "task:effective-intersection"
        broad = _unit_intent(
            owner,
            task_id=task_id,
            intent_id="intent:z-broad-active-tie",
        )
        tight = _unit_intent(
            owner,
            task_id=task_id,
            intent_id="intent:a-tight-intersection",
            effects=(),
            resources=(),
        )
        store = OrinStore(tmp_path / "effective.db")
        intents = IntentStore(store=store, trusted_public_keys=(_pub_of(owner),))
        try:
            assert intents.register(broad.to_dict(), now_ms=_STORE_NOW_MS)["ok"] is True
            assert intents.register(tight.to_dict(), now_ms=_STORE_NOW_MS)["ok"] is True
            active = intents.active_envelope(task_id, now_ms=_STORE_NOW_MS)
            effective = intents.effective_grant(task_id, now_ms=_STORE_NOW_MS)
            assert active is not None and active.intent_id == broad.intent_id
            assert effective is not None
            assert effective.allowed_effect_classes == ()
            assert effective.allowed_resource_handles == ()

            approval = _unit_exact_approval(
                owner,
                approval_id="exact:intersection",
                task_id=task_id,
            )
            result = intents.grant_exact(
                approval.to_dict(),
                now_ms=_STORE_NOW_MS,
                expected_binding=_exact_binding(approval),
            )
            assert result["ok"] is False
            assert result["code"] == "denied"
        finally:
            store.close()

    @pytest.mark.parametrize("historical_state", ("live", "expired", "revoked"))
    def test_task_signer_is_frozen_across_full_intent_history(
        self,
        tmp_path: Path,
        historical_state: str,
    ) -> None:
        first_key = ed25519.Ed25519PrivateKey.generate()
        takeover_key = ed25519.Ed25519PrivateKey.generate()
        task_id = f"task:signer-history-{historical_state}"
        first_expiry = (
            _STORE_NOW_MS + 10
            if historical_state == "expired"
            else _STORE_NOW_MS + 60_000
        )
        first = _unit_intent(
            first_key,
            task_id=task_id,
            intent_id=f"intent:first-{historical_state}",
            expires_at_ms=first_expiry,
        )
        store = OrinStore(tmp_path / f"signer-{historical_state}.db")
        intents = IntentStore(
            store=store,
            trusted_public_keys=(_pub_of(first_key), _pub_of(takeover_key)),
        )
        try:
            assert intents.register(first.to_dict(), now_ms=_STORE_NOW_MS)["ok"] is True
            if historical_state == "revoked":
                assert intents.revoke(first.intent_id) is True
            takeover_now = (
                _STORE_NOW_MS + 20 if historical_state == "expired" else _STORE_NOW_MS
            )
            takeover = _unit_intent(
                takeover_key,
                task_id=task_id,
                intent_id=f"intent:takeover-{historical_state}",
                issued_at_ms=takeover_now - 1,
                expires_at_ms=takeover_now + 60_000,
            )
            result = intents.register(takeover.to_dict(), now_ms=takeover_now)
            assert result["ok"] is False
            assert result["code"] == "denied"
            assert "witness key is immutable" in result["reason"]
            assert store.intent_public_keys_for_task(task_id) == (_pub_of(first_key),)
        finally:
            store.close()

    def test_concurrent_first_intents_atomically_select_one_task_signer(
        self,
        tmp_path: Path,
    ) -> None:
        db_path = tmp_path / "concurrent-signer.db"
        stores = (OrinStore(db_path), OrinStore(db_path))
        keys = (
            ed25519.Ed25519PrivateKey.generate(),
            ed25519.Ed25519PrivateKey.generate(),
        )
        task_id = "task:concurrent-first-signer"
        intents = tuple(
            _unit_intent(
                key,
                task_id=task_id,
                intent_id=f"intent:concurrent-{index}",
            )
            for index, key in enumerate(keys)
        )

        def record(index: int) -> str:
            return stores[index].record_intent(
                intent_id=intents[index].intent_id,
                payload=intents[index].to_dict(),
                public_key=_pub_of(keys[index]),
            )

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                results = tuple(executor.map(record, (0, 1)))
            assert sorted(results) == ["inserted", "task_key_conflict"]
            winner = results.index("inserted")
            assert stores[0].intent_public_keys_for_task(task_id) == (
                _pub_of(keys[winner]),
            )
        finally:
            for store in stores:
                store.close()

    def test_replaying_claimed_id_cannot_borrow_another_live_matching_approval(
        self,
        tmp_path: Path,
    ) -> None:
        owner = ed25519.Ed25519PrivateKey.generate()
        task_id = "task:approval-id-replay"
        store = OrinStore(tmp_path / "approval-replay.db")
        intents = IntentStore(store=store, trusted_public_keys=(_pub_of(owner),))
        try:
            intent = _unit_intent(
                owner,
                task_id=task_id,
                intent_id="intent:approval-id-replay",
            )
            assert intents.register(intent.to_dict(), now_ms=_STORE_NOW_MS)["ok"] is True
            first = _unit_exact_approval(
                owner,
                approval_id="exact:first-same-binding",
                task_id=task_id,
            )
            second = replace(first, approval_id="exact:second-same-binding", signature="").sign_with(
                owner
            )
            for approval in (first, second):
                result = intents.grant_exact(
                    approval.to_dict(),
                    now_ms=_STORE_NOW_MS,
                    expected_binding=_exact_binding(approval),
                )
                assert result["ok"] is True
            assert intents.claim_personal_exact_commit_approval(
                approval_id=first.approval_id,
                task_id=first.task_id,
                draft_id=first.draft_id,
                witness_id=first.witness_id,
                canonical_effect_hash=first.canonical_effect_hash,
                directory_handle_id=first.directory_handle_id,
                now_ms=_STORE_NOW_MS,
            ) is True

            replay = intents.grant_exact(
                first.to_dict(),
                now_ms=_STORE_NOW_MS,
                expected_binding=_exact_binding(first),
            )
            assert replay["ok"] is False
            assert replay["code"] == "denied"
            live = intents.active_exact_commit_approvals(
                **_exact_binding(second),
                now_ms=_STORE_NOW_MS,
            )
            assert [row["approval_id"] for row in live] == [second.approval_id]
        finally:
            store.close()


@dataclass(slots=True)
class _SeededExactMembrane:
    db_path: Path
    membrane: CommitMembrane
    spec: OperationSpec
    approval: ExactCommitApprovalV1
    witness: StateWitness


def _seed_exact_membrane(tmp_path: Path) -> _SeededExactMembrane:
    token = uuid4().hex
    db_path = tmp_path / f"membrane-{token}.db"
    task_id = f"task:{token}"
    draft = EffectDraft(
        draft_id=f"draft:{token}",
        task_id=task_id,
        effect_type="file.commit",
        arguments={
            "directory_handle": f"dirh:{token}",
            "changes": [{"path": "result.txt", "content": "approved\n"}],
        },
        declared_expectation={
            "external_visibility": "private",
            "reversibility": "reversible_until_stage",
        },
    )
    effect_hash = canonical_effect_hash_of(draft)
    witness = StateWitness(
        witness_id=f"state:{token}-first",
        draft_id=draft.draft_id,
        executor_id="cell.file",
        target_version="file-report:first",
        canonical_effect_hash=effect_hash,
        impact=Impact(writes=1),
        reversibility="reversible_until_stage",
        idempotency_support="client_key",
        created_at_ms=_STORE_NOW_MS - 1_000,
        expires_at_ms=_STORE_NOW_MS + 120_000,
    )
    owner = ed25519.Ed25519PrivateKey.generate()
    approval = _unit_exact_approval(
        owner,
        approval_id=f"exact:{token}",
        task_id=task_id,
        draft_id=draft.draft_id,
        witness_id=witness.witness_id,
        effect_hash=effect_hash,
        directory_handle_id=str(draft.arguments["directory_handle"]),
    )
    store = OrinStore(db_path)
    try:
        assert store.record_effect_draft(
            {
                "draft": draft.to_dict(),
                "draft_id": draft.draft_id,
                "task_id": draft.task_id,
                "effect_type": draft.effect_type,
                "executor_id": "cell.file",
                "canonical_effect_hash": effect_hash,
                "context_taint": 0,
                "arg_taint": 0,
                "clearance": 1,
                "created_at_ms": _STORE_NOW_MS - 2_000,
                "expires_at_ms": _STORE_NOW_MS + 120_000,
            }
        ) == "inserted"
        assert store.record_state_witness(witness) == "inserted"
        assert store.record_exact_commit_approval(
            approval_id=approval.approval_id,
            payload=approval.to_dict(),
            public_key=_pub_of(owner),
        ) == "inserted"
    finally:
        store.close()

    membrane = CommitMembrane(db_path, now_fn=lambda: _STORE_NOW_MS)
    spec = OperationSpec(
        operation_id=f"operation:{token}",
        draft_id=draft.draft_id,
        task_id=draft.task_id,
        owner_key_hash=_STORE_OWNER_HASH,
        session_id=f"session:{token}",
        effect_type="file.commit",
        executor_id="cell.file",
        side_effect_class="R2",
        canonical_effect_hash=effect_hash,
        witness_id=witness.witness_id,
        intent_id=f"intent:{token}",
        profile="personal",
        destinations=(),
        bytes_out=0,
        idempotency_key=f"idem:{token}",
        directory_handle_id=str(draft.arguments["directory_handle"]),
    )
    assert membrane.propose(spec).state is CommitState.PROPOSED
    assert membrane.transition(spec.operation_id, CommitState.PREFLIGHTED).state is (
        CommitState.PREFLIGHTED
    )
    return _SeededExactMembrane(db_path, membrane, spec, approval, witness)


def _replace_current_witness(seeded: _SeededExactMembrane) -> StateWitness:
    replacement = replace(
        seeded.witness,
        witness_id=f"state:{uuid4().hex}-replacement",
        target_version="file-report:replacement",
        created_at_ms=seeded.witness.created_at_ms + 1,
    )
    store = OrinStore(seeded.db_path)
    try:
        assert store.record_state_witness(replacement) == "inserted"
    finally:
        store.close()
    return replacement


def _prepare_seeded_exact(seeded: _SeededExactMembrane) -> None:
    prepared = seeded.membrane.prepare(
        seeded.spec.operation_id,
        max_invocations=4,
        max_bytes_out=1 << 20,
        export_pass_id=None,
        require_personal_pass=False,
        exact_approval_id=seeded.approval.approval_id,
        require_personal_exact=True,
        now_ms=_STORE_NOW_MS,
    )
    assert prepared.state is CommitState.PREPARED
    assert prepared.exact_approval_id == seeded.approval.approval_id
    assert prepared.exact_approval_claimed is True


class TestExactApprovalMembraneAuthority:
    def test_replaced_witness_cannot_be_claimed_into_prepared(
        self,
        tmp_path: Path,
    ) -> None:
        seeded = _seed_exact_membrane(tmp_path)
        try:
            _replace_current_witness(seeded)
            with pytest.raises(ExactApprovalUnavailable):
                _prepare_seeded_exact(seeded)
            assert seeded.membrane.get(seeded.spec.operation_id).state is (
                CommitState.PREFLIGHTED
            )
            with sqlite3.connect(seeded.db_path) as connection:
                claimed = connection.execute(
                    "SELECT claimed_at_ms FROM exact_commit_approvals WHERE approval_id = ?",
                    (seeded.approval.approval_id,),
                ).fetchone()
            assert claimed == (0,)
        finally:
            seeded.membrane.close()

    def test_begin_commit_rechecks_current_witness_in_same_transaction(
        self,
        tmp_path: Path,
    ) -> None:
        seeded = _seed_exact_membrane(tmp_path)
        try:
            _prepare_seeded_exact(seeded)
            _replace_current_witness(seeded)
            with pytest.raises(OperationConflict, match="witness is no longer current"):
                seeded.membrane.begin_commit(seeded.spec.operation_id)
            assert seeded.membrane.get(seeded.spec.operation_id).state is CommitState.PREPARED
        finally:
            seeded.membrane.close()

    def test_membrane_rejects_exact_or_export_authority_outside_personal_file_cell(
        self,
        tmp_path: Path,
    ) -> None:
        db_path = tmp_path / "membrane-type-guards.db"
        membrane = CommitMembrane(db_path, now_fn=lambda: _STORE_NOW_MS)
        token = uuid4().hex

        def spec(
            suffix: str,
            *,
            profile: str = "personal",
            executor_id: str = "cell.file",
            destinations: tuple[str, ...] = (),
        ) -> OperationSpec:
            return OperationSpec(
                operation_id=f"operation:{token}-{suffix}",
                draft_id=f"draft:{token}-{suffix}",
                task_id=f"task:{token}-{suffix}",
                owner_key_hash=_STORE_OWNER_HASH,
                session_id=f"session:{token}-{suffix}",
                effect_type="file.commit",
                executor_id=executor_id,
                side_effect_class="R2",
                canonical_effect_hash="sha256:" + "4" * 64,
                witness_id=f"state:{token}-{suffix}",
                intent_id=f"intent:{token}-{suffix}",
                profile=profile,
                destinations=destinations,
                bytes_out=0,
                idempotency_key=f"idem:{token}-{suffix}",
                directory_handle_id=f"dirh:{token}-{suffix}",
            )

        try:
            no_exact = spec("no-exact")
            membrane.propose(no_exact)
            membrane.transition(no_exact.operation_id, CommitState.PREFLIGHTED)
            with pytest.raises(ExactApprovalUnavailable):
                membrane.prepare(
                    no_exact.operation_id,
                    max_invocations=4,
                    max_bytes_out=1 << 20,
                    export_pass_id=None,
                    require_personal_pass=False,
                    now_ms=_STORE_NOW_MS,
                )

            wrong_executor = spec("wrong-executor", executor_id="cell.connector")
            membrane.propose(wrong_executor)
            membrane.transition(wrong_executor.operation_id, CommitState.PREFLIGHTED)
            with pytest.raises(ExactApprovalUnavailable):
                membrane.prepare(
                    wrong_executor.operation_id,
                    max_invocations=4,
                    max_bytes_out=1 << 20,
                    export_pass_id=None,
                    require_personal_pass=False,
                    exact_approval_id="exact:wrong-executor",
                    require_personal_exact=True,
                    now_ms=_STORE_NOW_MS,
                )

            egress_file = spec("egress", destinations=("rcpt:forbidden",))
            membrane.propose(egress_file)
            membrane.transition(egress_file.operation_id, CommitState.PREFLIGHTED)
            with pytest.raises(ExportPassUnavailable):
                membrane.prepare(
                    egress_file.operation_id,
                    max_invocations=4,
                    max_bytes_out=1 << 20,
                    export_pass_id="export:forbidden",
                    require_personal_pass=True,
                    now_ms=_STORE_NOW_MS,
                )

            work = spec("work", profile="work")
            membrane.propose(work)
            membrane.transition(work.operation_id, CommitState.PREFLIGHTED)
            assert membrane.prepare(
                work.operation_id,
                max_invocations=4,
                max_bytes_out=1 << 20,
                export_pass_id=None,
                require_personal_pass=False,
                now_ms=_STORE_NOW_MS,
            ).state is CommitState.PREPARED
        finally:
            membrane.close()

    @pytest.mark.parametrize(
        "legacy_state",
        (CommitState.PREPARED, CommitState.UNKNOWN_COMMIT),
    )
    def test_schema_upgrade_recovers_legacy_file_directory_binding_and_fingerprint(
        self,
        tmp_path: Path,
        legacy_state: CommitState,
    ) -> None:
        seeded = _seed_exact_membrane(tmp_path)
        _prepare_seeded_exact(seeded)
        if legacy_state is CommitState.UNKNOWN_COMMIT:
            seeded.membrane.begin_commit(seeded.spec.operation_id)
            seeded.membrane.mark_ambiguous(seeded.spec.operation_id, "legacy crash")
        seeded.membrane.close()
        legacy_fingerprint = membrane_module._spec_fingerprint(  # noqa: SLF001
            replace(seeded.spec, directory_handle_id="")
        )
        with sqlite3.connect(seeded.db_path) as connection:
            connection.execute(
                "UPDATE commit_operations SET directory_handle_id = '',"
                " spec_fingerprint = ? WHERE operation_id = ?",
                (legacy_fingerprint, seeded.spec.operation_id),
            )
            connection.execute("ALTER TABLE commit_operations DROP COLUMN directory_handle_id")

        restarted = CommitMembrane(seeded.db_path, now_fn=lambda: _STORE_NOW_MS)
        try:
            migrated = restarted.get(seeded.spec.operation_id)
            assert migrated.state is legacy_state
            assert migrated.directory_handle_id == seeded.spec.directory_handle_id
            assert restarted.propose(seeded.spec).state is legacy_state
        finally:
            restarted.close()

    def test_schema_upgrade_leaves_unprovable_legacy_file_binding_fail_closed(
        self,
        tmp_path: Path,
    ) -> None:
        seeded = _seed_exact_membrane(tmp_path)
        seeded.membrane.close()
        legacy_fingerprint = membrane_module._spec_fingerprint(  # noqa: SLF001
            replace(seeded.spec, directory_handle_id="")
        )
        with sqlite3.connect(seeded.db_path) as connection:
            connection.execute(
                "UPDATE commit_operations SET directory_handle_id = '',"
                " spec_fingerprint = ? WHERE operation_id = ?",
                (legacy_fingerprint, seeded.spec.operation_id),
            )
            connection.execute(
                "UPDATE effect_drafts SET payload_json = '{}' WHERE draft_id = ?",
                (seeded.spec.draft_id,),
            )
            connection.execute("ALTER TABLE commit_operations DROP COLUMN directory_handle_id")

        restarted = CommitMembrane(seeded.db_path, now_fn=lambda: _STORE_NOW_MS)
        try:
            assert restarted.get(seeded.spec.operation_id).directory_handle_id == ""
            with pytest.raises(OperationConflict):
                restarted.propose(seeded.spec)
        finally:
            restarted.close()


@dataclass(slots=True)
class _PreparedFile:
    adapter: OrinLeaseClientAdapter
    draft: EffectDraft
    target: Path
    directory_handle_id: str
    witness_id: str
    effect_hash: str
    profile: str


@pytest.fixture(scope="module")
def exact_file_orind(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("exact-file-orind")
    witness = ed25519.Ed25519PrivateKey.generate()
    other_trusted_witness = ed25519.Ed25519PrivateKey.generate()
    with OrindHarness(
        state_dir=root / "state",
        stage_b=True,
        cell_file=True,
        commit_membrane=True,
        witness_public_keys=(_pub_of(witness), _pub_of(other_trusted_witness)),
    ) as orind:
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            if orind.daemon._cell_by_cap("cell.file") is not None:  # noqa: SLF001
                break
            time.sleep(0.1)
        else:
            pytest.fail("File Cell subprocess did not connect")
        yield orind, witness, other_trusted_witness, root


def _prepare_file(
    exact_file_orind: _ExactFixture,
    *,
    profile: str,
    content: str = "owner-approved exact content\n",
) -> _PreparedFile:
    orind, witness, _other_trusted_witness, root = exact_file_orind
    token = uuid4().hex
    owner_root = root / f"owner-{token}"
    owner_root.mkdir()
    owner = "sha256:" + token.ljust(64, "0")[:64]
    issued = orind.daemon._broker.issue(  # noqa: SLF001 - approval-channel stand-in
        kind="DirectoryHandle",
        token=token,
        owner_key_hash=owner,
        tenant=profile,
        object_digest=str(owner_root.resolve()),
        capabilities=("read", "stage", "write"),
        approved=True,
    )
    assert issued["ok"] is True
    directory_handle_id = str(issued["handle"]["handle_id"])
    task_id = f"task:{uuid4().hex}"
    now = _now_ms()
    intent = IntentEnvelope(
        intent_id=f"intent:{uuid4().hex}",
        owner_key_hash=owner,
        product_id="js-agent",
        profile=profile,
        task_id=task_id,
        raw_request_hash="sha256:" + "7" * 64,
        allowed_effect_classes=("file.commit",),
        allowed_resource_handles=(directory_handle_id,),
        allowed_sink_handles=(),
        budgets=Budgets(max_invocations=20, max_bytes_out=1 << 20),
        approval_policy=(
            "exact_commit_required"
            if profile == "personal"
            else "preauthorized_exact_template"
        ),
        issued_by="appshell:exact-test",
        issued_at_ms=now - 1_000,
        expires_at_ms=now + 120_000,
    ).sign_with(witness)
    adapter = _adapter(orind)
    assert adapter.register_intent(intent.to_dict())["ok"] is True
    target = owner_root / "nested" / "approved.txt"
    draft = EffectDraft(
        draft_id=f"draft:{uuid4().hex}",
        task_id=task_id,
        effect_type="file.commit",
        arguments={
            "directory_handle": directory_handle_id,
            "changes": [{"path": "nested/approved.txt", "content": content}],
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
    witness_data = preflight["witness"]
    assert not target.exists(), "preflight must never mutate the owner root"
    return _PreparedFile(
        adapter=adapter,
        draft=draft,
        target=target,
        directory_handle_id=directory_handle_id,
        witness_id=str(witness_data["witness_id"]),
        effect_hash=str(witness_data["canonical_effect_hash"]),
        profile=profile,
    )


def _forbid_export_pass_calls(orind: OrindHarness, monkeypatch: pytest.MonkeyPatch) -> None:
    intents = orind.daemon._intents  # noqa: SLF001
    assert intents is not None

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("file.commit must not query or consume ExportPass")

    for name in (
        "export_passes_for_task",
        "active_exact_export_passes",
        "claim_personal_export_pass",
    ):
        monkeypatch.setattr(intents, name, forbidden)


class TestPersonalExactFileCommit:
    def test_without_approval_consume_is_denied_and_owner_root_is_unchanged(
        self,
        exact_file_orind: _ExactFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        orind, _witness, _other_trusted_witness, _root = exact_file_orind
        _forbid_export_pass_calls(orind, monkeypatch)
        prepared = _prepare_file(exact_file_orind, profile="personal")
        try:
            with pytest.raises(LeaseDenied):
                prepared.adapter.consume_draft(prepared.draft.draft_id)
            assert not prepared.target.exists()
        finally:
            prepared.adapter.close()

    @pytest.mark.parametrize(
        "mismatch",
        ("task", "draft", "witness", "hash", "dirh"),
    )
    def test_mismatched_exact_binding_is_rejected_before_commit(
        self,
        exact_file_orind: _ExactFixture,
        mismatch: str,
    ) -> None:
        _orind, witness, _other_trusted_witness, _root = exact_file_orind
        prepared = _prepare_file(exact_file_orind, profile="personal")
        overrides = {
            "task": {"task_id": f"task:{uuid4().hex}"},
            "draft": {"draft_id": f"draft:{uuid4().hex}"},
            "witness": {"witness_id": f"state:{uuid4().hex}"},
            "hash": {"canonical_effect_hash": "sha256:" + "0" * 64},
            "dirh": {"directory_handle_id": f"dirh:{uuid4().hex}"},
        }[mismatch]
        wrong = _approval(prepared, witness, **overrides)
        try:
            with pytest.raises(LeaseDenied):
                prepared.adapter.grant_exact(
                    wrong.to_dict(),
                    task_id=prepared.draft.task_id,
                )
            with pytest.raises(LeaseDenied):
                prepared.adapter.consume_draft(prepared.draft.draft_id)
            assert not prepared.target.exists()
        finally:
            prepared.adapter.close()

    @pytest.mark.parametrize("fault", ("expired", "different-trusted-owner-witness"))
    def test_expired_or_wrong_owner_approval_is_rejected(
        self,
        exact_file_orind: _ExactFixture,
        fault: str,
    ) -> None:
        _orind, witness, other_trusted_witness, _root = exact_file_orind
        prepared = _prepare_file(exact_file_orind, profile="personal")
        if fault == "expired":
            now = _now_ms()
            approval = _approval(
                prepared,
                witness,
                created_at_ms=now - 2_000,
                expires_at_ms=now - 1,
            )
        else:
            approval = _approval(prepared, other_trusted_witness)
        try:
            with pytest.raises(LeaseDenied):
                prepared.adapter.grant_exact(
                    approval.to_dict(),
                    task_id=prepared.draft.task_id,
                )
            assert not prepared.target.exists()
        finally:
            prepared.adapter.close()

    def test_owner_approval_commits_once_without_export_pass_or_authority_leak(
        self,
        exact_file_orind: _ExactFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        orind, witness, _other_trusted_witness, _root = exact_file_orind
        _forbid_export_pass_calls(orind, monkeypatch)
        prepared = _prepare_file(exact_file_orind, profile="personal")
        approval = _approval(prepared, witness)
        try:
            granted = prepared.adapter.grant_exact(
                approval.to_dict(),
                task_id=prepared.draft.task_id,
            )
            assert granted["ok"] is True
            committed = prepared.adapter.consume_draft(prepared.draft.draft_id)
            assert committed["status"] == "COMMITTED"
            assert prepared.target.read_text(encoding="utf-8") == (
                "owner-approved exact content\n"
            )
            visible = json.dumps(committed, sort_keys=True)
            for secret in (
                prepared.draft.draft_id,
                prepared.witness_id,
                prepared.directory_handle_id,
                str(prepared.target.parent.parent.resolve()),
                "permit",
                "package",
                "token",
                "license",
                "approval_id",
            ):
                assert secret not in visible
            with pytest.raises(LeaseDenied):
                prepared.adapter.consume_draft(prepared.draft.draft_id)
        finally:
            prepared.adapter.close()

        db_path = Path(orind.daemon._state_dir) / "orin" / "orind_state.db"  # noqa: SLF001
        with sqlite3.connect(db_path) as connection:
            export_rows = connection.execute("SELECT COUNT(*) FROM export_passes").fetchone()
        assert export_rows == (0,), "ExactCommitApproval must never enter ExportPass storage"

    def test_work_never_queries_or_claims_exact_approval_and_keeps_one_shot_path(
        self,
        exact_file_orind: _ExactFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        orind, witness, _other_trusted_witness, _root = exact_file_orind
        intents = orind.daemon._intents  # noqa: SLF001
        assert intents is not None

        def forbidden_exact(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("Work file.commit must not query or claim ExactCommitApproval")

        for name in (
            "exact_commit_approvals_for_task",
            "active_exact_commit_approvals",
            "claim_personal_exact_commit_approval",
        ):
            monkeypatch.setattr(intents, name, forbidden_exact, raising=False)
        _forbid_export_pass_calls(orind, monkeypatch)
        prepared = _prepare_file(exact_file_orind, profile="work", content="work unchanged\n")
        bogus = _approval(prepared, witness)
        try:
            with pytest.raises(LeaseDenied):
                prepared.adapter.grant_exact(
                    bogus.to_dict(),
                    task_id=prepared.draft.task_id,
                )
            committed = prepared.adapter.consume_draft(prepared.draft.draft_id)
            assert committed["status"] == "COMMITTED"
            assert prepared.target.read_text(encoding="utf-8") == "work unchanged\n"
        finally:
            prepared.adapter.close()
