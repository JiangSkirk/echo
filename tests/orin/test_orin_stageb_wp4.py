"""WP4: three-witness types, Gate Kernel skeleton, and caps-gated protocol.

Covers the ORIN_STAGE_B_SPEC.md §4 WP4 acceptance items:

- schema round-trips and unknown-field rejection for every new type;
- Echo cannot forge an owner intent (signature trust is registry-based);
- expired state witnesses are rejected (deny_stale_state);
- CommitPermit never appears in an Echo-visible structure;
- stage-B message types without a negotiated cap drop the connection;
- ``stage_b=False`` leaves the Stage A surface untouched.
"""

from __future__ import annotations

import asyncio
import base64
import os
import secrets
import time
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from js.orin.draft import (
    CommitPermit,
    EffectDraft,
    ExportPass,
    Impact,
    StateWitness,
)
from js.orin.handles import OriginHandle, handle_from_dict
from js.orin.intent import (
    Budgets,
    IntentEnvelope,
    request_hash_of,
    session_tightening_ok,
)
from js.orin.protocol import (
    GATE_VERDICTS,
    STAGE_B_CLIENT_CAPS,
    ProtocolError,
    canonical_json,
    compute_mac,
    encode_frame,
    make_envelope,
    parse_frame,
)
from js.orin.testing import TestOrind
from js.orind.kernel import GateInputs, GateKernel

# -- fixtures ------------------------------------------------------------------


def _now_ms() -> int:
    return int(time.time() * 1000)


@pytest.fixture()
def witness_keypair() -> tuple[ed25519.Ed25519PrivateKey, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    return key, pub_b64


def _make_intent(
    *,
    task_id: str | None = None,
    classes: tuple[str, ...] = ("email.send_exact",),
    policy: str = "dual_control",
    now: int | None = None,
) -> IntentEnvelope:
    ts = now if now is not None else _now_ms()
    return IntentEnvelope(
        intent_id=f"intent:{uuid4().hex}",
        owner_key_hash="sha256:" + "1" * 64,
        product_id="js-agent",
        profile="personal",
        task_id=task_id or f"task:{uuid4().hex}",
        raw_request_hash=request_hash_of("send the monthly report"),
        allowed_effect_classes=classes,
        allowed_resource_handles=("dirh:workspace",),
        allowed_sink_handles=("rcpt:finance",),
        budgets=Budgets(
            max_invocations=10, max_bytes_read=1000, max_bytes_out=500, max_cost_minor_units=0
        ),
        approval_policy=policy,
        issued_by="appshell:test-witness",
        issued_at_ms=ts - 1000,
        expires_at_ms=ts + 60_000,
    )


def _make_draft(task_id: str, *, effect_type: str = "email.send_exact") -> EffectDraft:
    return EffectDraft(
        draft_id=f"draft:{uuid4().hex}",
        task_id=task_id,
        effect_type=effect_type,
        arguments={"recipient_handle": "rcpt:finance", "subject": "monthly"},
        declared_expectation={"external_visibility": "named_recipients"},
    )


def _make_witness(draft: EffectDraft, *, expires_delta_ms: int = 60_000) -> StateWitness:
    ts = _now_ms()
    return StateWitness(
        witness_id=f"state:{uuid4().hex}",
        draft_id=draft.draft_id,
        executor_id="cell:test",
        target_version="provider-etag-1",
        canonical_effect_hash="sha256:" + "a" * 64,
        impact=Impact(writes=1, recipients=1, bytes_out=38421, cost_upper_bound=0),
        reversibility="irreversible_after_provider_accept",
        idempotency_support="provider_native",
        created_at_ms=ts - 100,
        expires_at_ms=ts + expires_delta_ms,
    )


# -- schema round-trips ----------------------------------------------------------


class TestSchemaRoundTrip:
    def test_every_stageb_type_round_trips(self) -> None:
        nonce = secrets.token_hex(16)
        key = b"k" * 32
        intent_data = _make_intent().to_dict()
        permit = CommitPermit(
            permit_id=f"permit:{uuid4().hex}",
            intent_id="intent:x",
            draft_id="draft:y",
            state_witness_id="state:z",
            executor_id="cell:test",
            canonical_effect_hash="sha256:" + "a" * 64,
            idempotency_key=str(uuid4()),
            sequence=7,
            not_before_ms=_now_ms(),
            expires_at_ms=_now_ms() + 1000,
        )
        cases: list[dict[str, object]] = [
            {"type": "intent", "op": "register", "intent": intent_data},
            {"type": "intent_ack", "ok": True, "intent": intent_data},
            {"type": "handle", "op": "seed_list", "kind": "RecipientHandle"},
            {"type": "handle_ack", "ok": True, "candidates": []},
            {
                "type": "draft_ack",
                "ok": True,
                "verdict": "require_approval",
                "missing": ["owner_intent"],
            },
            {"type": "preflight", "draft_id": "draft:1", "executor_id": "cell:test"},
            {"type": "preflight_ack", "ok": True},
            {"type": "commit", "permit": permit.to_dict()},
            {"type": "commit_ack", "ok": True, "receipt_id": "receipt:r1"},
            {"type": "receipt_ack", "ok": True},
            {"type": "reconcile", "effect_id": "effect:1"},
            {"type": "reconcile_ack", "ok": True, "state": "committed"},
        ]
        for case in cases:
            message_type = str(case.pop("type"))
            envelope = make_envelope(message_type, seq=1, nonce=nonce, session_key=key, **case)
            parsed = parse_frame(canonical_json(envelope).encode("utf-8"))
            assert parsed["type"] == message_type
            assert compute_mac(key, parsed) == envelope["mac"]

    def test_draft_envelope_carries_taint_fields(self) -> None:
        draft = _make_draft("task:t")
        envelope = make_envelope(
            "draft",
            seq=3,
            nonce=secrets.token_hex(16),
            session_key=b"k" * 32,
            draft=draft.to_dict(),
            context_taint=4096,
            arg_taint=8,
            clearance=1,
        )
        parsed = parse_frame(canonical_json(envelope).encode("utf-8"))
        assert parsed["context_taint"] == 4096

    def test_unknown_field_rejected(self) -> None:
        with pytest.raises(ProtocolError):
            make_envelope(
                "intent",
                seq=1,
                nonce=secrets.token_hex(16),
                session_key=b"k" * 32,
                op="active",
                task_id="task:x",
                sneaky="field",
            )

    def test_intent_register_requires_intent_object(self) -> None:
        with pytest.raises(ProtocolError):
            make_envelope(
                "intent", seq=1, nonce=secrets.token_hex(16), session_key=b"k" * 32, op="register"
            )

    def test_bad_gate_verdict_rejected(self) -> None:
        with pytest.raises(ProtocolError):
            make_envelope(
                "draft_ack",
                seq=1,
                nonce=secrets.token_hex(16),
                session_key=b"k" * 32,
                ok=True,
                verdict="sure_why_not",
            )

    def test_bad_reconcile_state_rejected(self) -> None:
        with pytest.raises(ProtocolError):
            make_envelope(
                "reconcile_ack",
                seq=1,
                nonce=secrets.token_hex(16),
                session_key=b"k" * 32,
                ok=True,
                state="maybe",
            )


# -- intent forgery / tightening -----------------------------------------------


class TestIntentTrust:
    def test_signed_intent_verifies_against_registered_key(
        self, witness_keypair: tuple[ed25519.Ed25519PrivateKey, str]
    ) -> None:
        key, pub_b64 = witness_keypair
        envelope = _make_intent().sign_with(key)
        assert envelope.signature
        assert envelope.verify(pub_b64)

    def test_wrong_key_fails(self, witness_keypair: tuple[ed25519.Ed25519PrivateKey, str]) -> None:
        _, pub_b64 = witness_keypair
        other = ed25519.Ed25519PrivateKey.generate()
        envelope = _make_intent().sign_with(other)
        assert not envelope.verify(pub_b64)

    def test_tampered_payload_fails(
        self, witness_keypair: tuple[ed25519.Ed25519PrivateKey, str]
    ) -> None:
        key, pub_b64 = witness_keypair
        envelope = _make_intent().sign_with(key)
        forged = IntentEnvelope(
            **{
                **{f: getattr(envelope, f) for f in envelope.__dataclass_fields__},  # type: ignore[attr-defined]
                "allowed_effect_classes": ("admin.unfreeze",),
            }
        )
        assert not forged.verify(pub_b64)

    def test_missing_signature_is_invalid(self) -> None:
        from js.orin.intent import intent_from_dict

        with pytest.raises(ProtocolError):
            intent_from_dict(_make_intent().to_dict(), verify_signature=True)

    def test_session_permissions_only_tighten(self) -> None:
        active = _make_intent(classes=("artifact.read", "email.send_exact"), policy="dual_control")
        tighter = _make_intent(classes=("artifact.read",), policy="dual_control")
        looser = _make_intent(classes=("admin.unfreeze",), policy="dual_control")
        assert session_tightening_ok(tighter, active)
        assert not session_tightening_ok(looser, active)


# -- gate kernel -----------------------------------------------------------------


class TestGateKernel:
    def _kernel(self) -> GateKernel:
        return GateKernel(secret_taint_bit=1 << 12)

    def _inputs_with_intent(self, draft_task: str, **overrides: object) -> GateInputs:
        inputs = GateInputs(now_ms=_now_ms())
        inputs.intent = _make_intent(task_id=draft_task)
        inputs.canonical_effect_hash = "sha256:" + "a" * 64
        for name, value in overrides.items():
            setattr(inputs, name, value)
        return inputs

    def test_no_intent_denies(self) -> None:
        decision = self._kernel().assess(_make_draft("task:none"), GateInputs(now_ms=_now_ms()))
        assert decision.verdict == "deny_missing_witness"
        assert "owner_intent" in decision.missing

    def test_expired_intent_denies(self) -> None:
        task = f"task:{uuid4().hex}"
        inputs = self._inputs_with_intent(task, now_ms=_now_ms() + 120_000)
        decision = self._kernel().assess(_make_draft(task), inputs)
        assert decision.verdict == "deny_policy"
        assert decision.reason_code == "intent_expired"
        assert decision.missing == ()

    def test_ungranted_class_denies_policy(self) -> None:
        task = f"task:{uuid4().hex}"
        inputs = self._inputs_with_intent(task)
        inputs.intent = _make_intent(task_id=task, classes=("artifact.read",))
        decision = self._kernel().assess(_make_draft(task), inputs)
        assert decision.verdict == "deny_policy"

    def test_unknown_effect_type_requires_approval(self) -> None:
        task = f"task:{uuid4().hex}"
        inputs = self._inputs_with_intent(task)
        decision = self._kernel().assess(_make_draft(task, effect_type="warp.speed"), inputs)
        assert decision.verdict == "require_approval"
        assert decision.missing == ("unknown_effect_manifest",)

    def test_unresolved_handle_denies_witness(self) -> None:
        task = f"task:{uuid4().hex}"
        inputs = self._inputs_with_intent(task)
        decision = self._kernel().assess(_make_draft(task), inputs)
        assert decision.verdict == "deny_missing_witness"
        assert any(m.startswith("handle:") for m in decision.missing)

    def test_expired_witness_denies_stale_state(self) -> None:
        task = f"task:{uuid4().hex}"
        kernel = self._kernel()
        draft = _make_draft(task)
        inputs = self._inputs_with_intent(task)
        inputs.handles_by_id["rcpt:finance"] = _sealed_handle()
        inputs.witness = _make_witness(draft, expires_delta_ms=-1)
        decision = kernel.assess(draft, inputs)
        assert decision.verdict == "deny_stale_state"
        assert decision.reason_code == "witness_expired"

    def test_changed_effect_denies_stale_state(self) -> None:
        task = f"task:{uuid4().hex}"
        kernel = self._kernel()
        draft = _make_draft(task)
        inputs = self._inputs_with_intent(task)
        inputs.handles_by_id["rcpt:finance"] = _sealed_handle()
        inputs.witness = _make_witness(draft)
        inputs.canonical_effect_hash = "sha256:" + "b" * 64
        assert kernel.assess(draft, inputs).verdict == "deny_stale_state"

    def test_secret_context_egress_requires_export_pass(self) -> None:
        task = f"task:{uuid4().hex}"
        kernel = self._kernel()
        draft = _make_draft(task)
        inputs = self._inputs_with_intent(
            task, context_has_secret=True, export_pass_satisfied=False
        )
        inputs.handles_by_id["rcpt:finance"] = _sealed_handle()
        inputs.witness = _make_witness(draft)
        decision = kernel.assess(draft, inputs)
        assert decision.verdict == "require_approval"
        assert "export_pass" in decision.missing

    def test_explicit_dual_control_intent_still_requires_dual_control(self) -> None:
        task = f"task:{uuid4().hex}"
        kernel = self._kernel()
        draft = _make_draft(task)
        inputs = self._inputs_with_intent(task)
        inputs.handles_by_id["rcpt:finance"] = _sealed_handle()
        inputs.witness = _make_witness(draft)
        inputs.export_passes = (
            ExportPass(
                pass_id=f"export:{uuid4().hex}",
                task_id=task,
                payload_hash=str(inputs.canonical_effect_hash),
                destination_handles=("rcpt:finance",),
                witness_id=inputs.witness.witness_id,
                created_at_ms=_now_ms() - 100,
                expires_at_ms=_now_ms() + 60_000,
            ),
        )
        decision = kernel.assess(draft, inputs)
        assert decision.verdict == "require_dual_control"

    def test_freeze_blocks_but_reads_survive(self) -> None:
        task = f"task:{uuid4().hex}"
        kernel = self._kernel()
        read_draft = EffectDraft(
            draft_id=f"draft:{uuid4().hex}",
            task_id=task,
            effect_type="artifact.read",
            arguments={},
            declared_expectation={},
        )
        frozen = GateInputs(now_ms=_now_ms(), freeze_active=True)
        frozen.intent = _make_intent(task_id=task, classes=("artifact.read",))
        assert kernel.assess(read_draft, frozen).verdict == "allow_read"
        side_effect = _make_draft(task)
        frozen2 = GateInputs(now_ms=_now_ms(), freeze_active=True)
        frozen2.intent = _make_intent(task_id=task)
        assert kernel.assess(side_effect, frozen2).verdict == "deny_policy"

    def test_reconciliation_defers(self) -> None:
        task = f"task:{uuid4().hex}"
        inputs = self._inputs_with_intent(task, reconciliation_pending=True)
        assert self._kernel().assess(_make_draft(task), inputs).verdict == "defer_reconciliation"

    def test_verdicts_always_in_protocol_vocabulary(self) -> None:
        task = f"task:{uuid4().hex}"
        inputs = self._inputs_with_intent(task)
        for verdict in {self._kernel().assess(_make_draft(task), inputs).verdict}:
            assert verdict in GATE_VERDICTS


def _sealed_handle() -> OriginHandle:
    ts = _now_ms()
    base = OriginHandle(
        handle_id="rcpt:finance",
        kind="RecipientHandle",
        owner_key_hash="sha256:" + "1" * 64,
        tenant="personal",
        source_class="USER_AUTHENTICATED",
        integrity="trusted_local_object",
        confidentiality="CONFIDENTIAL",
        object_digest="",
        capabilities=("send",),
        issuer="orind:broker",
        created_at_ms=ts,
        expires_at_ms=ts + 60_000,
    )
    return base.sealed_by(b"k" * 32, "orind:broker", ts)


# -- permit visibility ------------------------------------------------------------


class TestPermitVisibility:
    def test_echo_visible_projection_is_id_only(self) -> None:
        permit = CommitPermit(
            permit_id=f"permit:{uuid4().hex}",
            intent_id="intent:x",
            draft_id="draft:y",
            state_witness_id="state:z",
            executor_id="cell:test",
            canonical_effect_hash="sha256:" + "a" * 64,
            idempotency_key=str(uuid4()),
            sequence=1,
            not_before_ms=0,
            expires_at_ms=_now_ms() + 1000,
        )
        visible = permit.echo_visible()
        assert set(visible) == {"permit_id"}
        full = permit.to_dict()
        assert "canonical_effect_hash" in full and "idempotency_key" in full

    def test_permit_dict_strict_parsing(self) -> None:
        from js.orin.draft import permit_from_dict

        data = {
            "protocol": "orin/v1",
            "permit_id": f"permit:{uuid4().hex}",
            "intent_id": "intent:x",
            "draft_id": "draft:y",
            "state_witness_id": "state:z",
            "executor_id": "cell:test",
            "canonical_effect_hash": "sha256:" + "a" * 64,
            "idempotency_key": "k",
            "sequence": 1,
            "not_before_ms": 0,
            "expires_at_ms": _now_ms() + 1000,
        }
        assert permit_from_dict(data).permit_id == data["permit_id"]
        with pytest.raises(ProtocolError):
            permit_from_dict({**data, "surprise": True})


# -- broker sealing -----------------------------------------------------------------


class TestBrokerSeals:
    def test_issue_requires_approval_flag(self, tmp_path: Path) -> None:
        from js.orind.broker import HandleBroker
        from js.orind.store import OrinStore

        store = OrinStore(tmp_path / "state.db")
        broker = HandleBroker(store=store, mac_key=b"k" * 32)
        refused = broker.issue(
            kind="RecipientHandle", token="newperson", owner_key_hash="sha256:" + "1" * 64
        )
        assert refused["ok"] is False and refused["code"] == "approval_required"
        minted = broker.issue(
            kind="RecipientHandle",
            token="newperson",
            owner_key_hash="sha256:" + "1" * 64,
            capabilities=("send",),
            approved=True,
        )
        assert minted["ok"] is True
        handle = handle_from_dict(minted["handle"], require_signature=True)
        resolved = broker.resolve(handle.handle_id)
        assert resolved["ok"] is True
        # tamper breaks the seal
        tampered = dict(handle.to_dict())
        tampered["capabilities"] = ["read", "write", "send"]
        broken = handle_from_dict(tampered, require_signature=True)
        assert not broken.verify_seal(b"k" * 32)
        # desktop handles are never issued in Stage B
        desktop = broker.issue(
            kind="DesktopTargetHandle", token="win1", owner_key_hash="sha256:" + "1" * 64,
            approved=True,
        )
        assert desktop["ok"] is False


# -- daemon integration (caps gating) ----------------------------------------------


class DaemonHarness:
    async def fresh_session(
        self, orind: TestOrind, caps: list[str]
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str, bytes]:
        reader, writer = await asyncio.open_unix_connection(path=str(orind.socket_path))
        hello = make_envelope(
            "hello", seq=1, nonce=secrets.token_hex(16), session_key=None,
            caps=caps, pid=os.getpid(),
        )
        writer.write(encode_frame(hello))
        await writer.drain()
        header = await reader.readexactly(4)
        payload = await reader.readexactly(int.from_bytes(header, "big"))
        ack = parse_frame(payload)
        assert ack["type"] == "hello_ack"
        key_file = Path(orind.daemon._orin_dir) / f"session-{os.getpid()}.key"
        session_key = key_file.read_bytes()
        key_file.unlink()
        return reader, writer, hello["nonce"] + ack["server_nonce"], session_key

    @staticmethod
    async def hangup(writer: asyncio.StreamWriter) -> None:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, RuntimeError):
            pass

    async def read_frame(self, reader: asyncio.StreamReader) -> dict[str, object]:
        header = await reader.readexactly(4)
        payload = await reader.readexactly(int.from_bytes(header, "big"))
        return parse_frame(payload)


class TestCapsGating(DaemonHarness):
    async def test_new_type_without_cap_disconnects(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with TestOrind(state_dir=tmp_path, stage_b=False) as orind:
            reader, writer, nonce, key = await self.fresh_session(
                orind, ["lease.v2", "draft.v1"]
            )
            draft = _make_draft(f"task:{uuid4().hex}")
            env = make_envelope(
                "draft", seq=2, nonce=nonce, session_key=key, draft=draft.to_dict()
            )
            writer.write(encode_frame(env))
            await writer.drain()
            with pytest.raises((asyncio.IncompleteReadError, asyncio.TimeoutError)):
                await asyncio.wait_for(self.read_frame(reader), timeout=2.0)
            await self.hangup(writer)

    async def test_negotiated_draft_gets_kernel_verdict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with TestOrind(state_dir=tmp_path, stage_b=True) as orind:
            reader, writer, nonce, key = await self.fresh_session(
                orind, list(STAGE_B_CLIENT_CAPS)
            )
            task = f"task:{uuid4().hex}"
            draft = _make_draft(task)
            env = make_envelope(
                "draft",
                seq=2,
                nonce=nonce,
                session_key=key,
                draft=draft.to_dict(),
                context_taint=0,
            )
            writer.write(encode_frame(env))
            await writer.drain()
            reply = await self.read_frame(reader)
            assert reply.get("ok") is True
            assert reply.get("verdict") == "deny_missing_witness"
            assert "owner_intent" in reply.get("missing", [])  # type: ignore[operator]
            await self.hangup(writer)

    async def test_intent_register_then_active_query(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        witness_keypair: tuple[ed25519.Ed25519PrivateKey, str],
    ) -> None:
        key, pub_b64 = witness_keypair
        with TestOrind(
            state_dir=tmp_path, stage_b=True, witness_public_keys=(pub_b64,)
        ) as orind:
            reader, writer, nonce, session_key = await self.fresh_session(
                orind, ["lease.v2", "intent.v1"]
            )
            intent = _make_intent(policy="exact_commit_required").sign_with(key)
            reg = make_envelope(
                "intent",
                seq=2,
                nonce=nonce,
                session_key=session_key,
                op="register",
                intent=intent.to_dict(),
            )
            writer.write(encode_frame(reg))
            await writer.drain()
            ack = await self.read_frame(reader)
            assert ack.get("ok") is True

            query = make_envelope(
                "intent",
                seq=3,
                nonce=nonce,
                session_key=session_key,
                op="active",
                task_id=intent.task_id,
            )
            writer.write(encode_frame(query))
            await writer.drain()
            got = await self.read_frame(reader)
            assert got.get("ok") is True
            active = got.get("intent")
            assert isinstance(active, dict) and active["intent_id"] == intent.intent_id
            await self.hangup(writer)

    async def test_untrusted_intent_signature_refused(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        witness_keypair: tuple[ed25519.Ed25519PrivateKey, str],
    ) -> None:
        other = ed25519.Ed25519PrivateKey.generate()
        trusted = ed25519.Ed25519PrivateKey.generate()
        trusted_pub = base64.b64encode(
            trusted.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode("ascii")
        with TestOrind(
            state_dir=tmp_path, stage_b=True, witness_public_keys=(trusted_pub,)
        ) as orind:
            reader, writer, nonce, session_key = await self.fresh_session(
                orind, ["lease.v2", "intent.v1"]
            )
            forged = _make_intent().sign_with(other)
            reg = make_envelope(
                "intent",
                seq=2,
                nonce=nonce,
                session_key=session_key,
                op="register",
                intent=forged.to_dict(),
            )
            writer.write(encode_frame(reg))
            await writer.drain()
            ack = await self.read_frame(reader)
            assert ack.get("ok") is False
            assert ack.get("code") == "unknown_intent"
            await self.hangup(writer)

    async def test_handle_issue_over_protocol_needs_approval_channel(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with TestOrind(state_dir=tmp_path, stage_b=True) as orind:
            reader, writer, nonce, session_key = await self.fresh_session(
                orind, ["lease.v2", "handle.v1"]
            )
            req = make_envelope(
                "handle",
                seq=2,
                nonce=nonce,
                session_key=session_key,
                op="issue",
                kind="RecipientHandle",
                spec={"token": "x", "approved": True},
            )
            writer.write(encode_frame(req))
            await writer.drain()
            ack = await self.read_frame(reader)
            assert ack.get("ok") is False
            assert ack.get("code") == "unsupported"
