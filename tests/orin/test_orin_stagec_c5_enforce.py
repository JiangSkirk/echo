"""WP-C5 enforce conjunction and signed Cell receipts.

``orin.enforce`` stays fail-fast: K§15.6 #8/#9 and official TCC are still
blocked, so the §6.1 conjunction is not observed.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import ValidationError

from js.config import OrinConfig
from js.echo.capability import LeaseDenied
from js.orin.client import OrinLeaseClientAdapter
from js.orin.draft import (
    EffectDraft,
    EffectReceipt,
    SignedEffectReceiptV1,
    signed_receipt_from_dict,
)
from js.orin.intent import Budgets, IntentEnvelope, request_hash_of
from js.orin.protocol import ProtocolError
from js.orin.receipts import DecisionReceipt
from js.orin.testing import C3TestOrind
from js.orind.daemon import OrinDaemon, OrinDaemonError
from js.orind.kernel import GateInputs, GateKernel
from js.orind.manifest import builtin_manifest


def test_enforce_still_fails_fast_because_conjunction_is_incomplete() -> None:
    with pytest.raises(ValidationError, match="conjunction incomplete"):
        OrinConfig(enforce=True)


def test_daemon_enforce_still_fails_before_state(tmp_path: Path) -> None:
    state_dir = tmp_path / "must-not-exist"
    with pytest.raises(OrinDaemonError, match="conjunction incomplete"):
        OrinDaemon(state_dir=state_dir, orin_enforce=True)
    assert not state_dir.exists()


def test_signed_effect_receipt_is_not_a_decision_receipt() -> None:
    receipt = EffectReceipt(
        receipt_id="receipt:" + "a" * 32,
        permit_id="permit:" + "b" * 32,
        executor_id="cell.desktop",
        status="COMMITTED",
        remote_operation_id="",
        committed_effect_hash="sha256:" + "c" * 64,
        result_digest="sha256:" + "d" * 64,
        started_at_ms=1,
        finished_at_ms=2,
        previous_receipt_hash="",
    )
    signed = SignedEffectReceiptV1(
        schema="receipt.signed.v1", receipt=receipt, signature=""
    ).sealed_by(b"k" * 32)
    assert signed.verify_seal(b"k" * 32) is True
    assert signed.verify_seal(b"x" * 32) is False
    parsed = signed_receipt_from_dict(signed.to_dict(), mac_key=b"k" * 32)
    assert parsed.receipt.receipt_id == receipt.receipt_id

    decision = DecisionReceipt(
        receipt_id="receipt:decision",
        kind="consume",
        verdict="allow",
        lease_id="lease:1",
        policy_version=1,
        created_at=1,
        signature="sig",
        public_key="pub",
    )
    with pytest.raises(ProtocolError, match="DecisionReceipt"):
        signed_receipt_from_dict(decision.to_dict())


def test_hmac_handle_issue_cannot_create_production_side_effects(tmp_path: Path) -> None:
    daemon = OrinDaemon(state_dir=tmp_path, stage_b=True)
    try:
        denied = daemon._on_handle(  # noqa: SLF001
            {"op": "issue", "kind": "ApplicationHandle", "spec": {"approved": True}}
        )
        assert denied["ok"] is False
        assert denied["code"] == "unsupported"
    finally:
        daemon._store.close()  # noqa: SLF001


def test_unregistered_handler_and_missing_witness_deny() -> None:
    kernel = GateKernel(
        secret_taint_bit=1 << 12,
        manifest=builtin_manifest(b"k" * 32),
    )
    draft = EffectDraft(
        draft_id="draft:" + "a" * 32,
        task_id="task:" + "b" * 32,
        effect_type="unknown.explode",
        arguments={},
        declared_expectation={
            "external_visibility": "private",
            "reversibility": "irreversible_after_provider_accept",
        },
    )
    decision = kernel.assess(draft, GateInputs())
    assert decision.verdict == "deny_policy"

    memory_write = EffectDraft(
        draft_id="draft:" + "c" * 32,
        task_id="task:" + "d" * 32,
        effect_type="memory.write",
        arguments={"key": "x", "value": "y", "source": "user"},
        declared_expectation={
            "external_visibility": "private",
            "reversibility": "irreversible_after_provider_accept",
        },
    )
    # Production manifest has no memory.write unless the C3 harness enabled it.
    assert builtin_manifest(b"k" * 32).get("memory.write") is None
    missing = kernel.assess(memory_write, GateInputs())
    assert missing.verdict == "deny_policy"


def test_enforce_false_default_daemon_spawns_no_stage_c_cells(tmp_path: Path) -> None:
    daemon = OrinDaemon(state_dir=tmp_path, stage_b=True)
    try:
        assert daemon._cell_desktop_enabled is False  # noqa: SLF001
        assert daemon._cell_memory_enabled is False  # noqa: SLF001
        assert OrinConfig().enforce is False
    finally:
        daemon._store.close()  # noqa: SLF001


def _c3_memory_adapter(
    tmp_path: Path, now_fn: Any | None = None
) -> tuple[C3TestOrind, OrinLeaseClientAdapter, str, str]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_key = base64.b64encode(raw).decode("ascii")
    task_id = f"task:{uuid4().hex}"
    owner = "sha256:" + "1" * 64
    now = time.time_ns() // 1_000_000
    intent = IntentEnvelope(
        intent_id=f"intent:{uuid4().hex}",
        owner_key_hash=owner,
        product_id="js-work",
        profile="work",
        task_id=task_id,
        raw_request_hash=request_hash_of("remember this note"),
        allowed_effect_classes=("memory.read", "memory.write", "memory.mutate"),
        allowed_resource_handles=(),
        allowed_sink_handles=(),
        budgets=Budgets(
            max_invocations=20,
            max_bytes_read=1 << 20,
            max_bytes_out=0,
            max_cost_minor_units=0,
        ),
        approval_policy="preauthorized_exact_template",
        issued_by="appshell:owner-witness",
        issued_at_ms=now - 1_000,
        expires_at_ms=now + 600_000,
    ).sign_with(private_key)
    kwargs: dict[str, Any] = {
        "state_dir": tmp_path / "state",
        "witness_public_keys": (public_key,),
    }
    if now_fn is not None:
        kwargs["now_fn"] = now_fn
    orind = C3TestOrind(**kwargs)
    orind.start()
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        if orind.daemon._cell_by_cap("cell.memory") is not None:  # noqa: SLF001
            break
        time.sleep(0.05)
    else:
        orind.stop()
        raise AssertionError("authenticated Memory Cell did not become ready")
    adapter = OrinLeaseClientAdapter(
        socket_path=orind.socket_path,
        state_dir=Path(orind.daemon._state_dir),  # noqa: SLF001
        stage_b=True,
    )
    assert adapter.register_intent(intent.to_dict(), session_id="session:c5")["ok"] is True
    return orind, adapter, task_id, owner


def _memory_write_draft(task_id: str, owner: str, *, key: str = "note") -> EffectDraft:
    return EffectDraft(
        draft_id=f"draft:{uuid4().hex}",
        task_id=task_id,
        effect_type="memory.write",
        arguments={
            "owner_key_hash": owner,
            "profile": "work",
            "session_id": "session:c5",
            "key": key,
            "value": "hello",
            "source": "user",
            "taint": 0,
            "clearance": 1,
        },
        declared_expectation={
            "external_visibility": "private",
            "reversibility": "irreversible_after_provider_accept",
        },
    )


def test_c3_missing_wrong_and_expired_witness_are_denied(tmp_path: Path) -> None:
    orind, adapter, task_id, owner = _c3_memory_adapter(tmp_path)
    try:
        missing = _memory_write_draft(task_id, owner, key="missing")
        proposed = adapter.submit_draft(missing.to_dict())
        assert proposed.get("ok") is True
        with pytest.raises(LeaseDenied):
            adapter.consume_draft(missing.draft_id, session_id="session:c5")

        wrong = _memory_write_draft(task_id, owner, key="wrong")
        proposed = adapter.submit_draft(wrong.to_dict())
        assert proposed.get("ok") is True
        preflight = adapter.preflight_draft(wrong.draft_id, "cell.memory", session_id="session:c5")
        assert preflight.get("ok") is True
        row = orind.daemon._store._conn.execute(  # noqa: SLF001
            "SELECT payload_json FROM state_witnesses WHERE draft_id = ? AND is_current = 1",
            (wrong.draft_id,),
        ).fetchone()
        assert row is not None
        payload = json.loads(str(row[0]))
        payload["canonical_effect_hash"] = "sha256:" + "e" * 64
        orind.daemon._store._conn.execute(  # noqa: SLF001
            "UPDATE state_witnesses SET payload_json = ?, canonical_effect_hash = ? "
            "WHERE draft_id = ?",
            (json.dumps(payload), payload["canonical_effect_hash"], wrong.draft_id),
        )
        orind.daemon._store._conn.commit()  # noqa: SLF001
        with pytest.raises(LeaseDenied):
            adapter.consume_draft(wrong.draft_id, session_id="session:c5")
    finally:
        orind.stop()

    clock = {"ms": time.time_ns() // 1_000_000}

    def now() -> int:
        return clock["ms"]

    expired_home = tmp_path / "expired"
    expired_home.mkdir()
    orind, adapter, task_id, owner = _c3_memory_adapter(expired_home, now_fn=now)
    try:
        expired = _memory_write_draft(task_id, owner, key="expired")
        proposed = adapter.submit_draft(expired.to_dict())
        assert proposed.get("ok") is True
        preflight = adapter.preflight_draft(
            expired.draft_id, "cell.memory", session_id="session:c5"
        )
        assert preflight.get("ok") is True
        clock["ms"] += 120_000
        with pytest.raises(LeaseDenied):
            adapter.consume_draft(expired.draft_id, session_id="session:c5")
    finally:
        orind.stop()


def test_c3_signed_receipt_is_verified_then_dropped_from_echo(tmp_path: Path) -> None:
    orind, adapter, task_id, owner = _c3_memory_adapter(tmp_path)
    try:
        written = adapter.write_memory(
            task_id,
            owner_key_hash=owner,
            profile="work",
            session_id="session:c5",
            key="sealed",
            value="hello",
            source="user",
        )
        assert written["status"] == "COMMITTED"
        assert "signed_receipt" not in written
        dumped = json.dumps(written)
        assert "permit:" not in dumped
        assert "receipt.signed.v1" not in dumped
    finally:
        orind.stop()
