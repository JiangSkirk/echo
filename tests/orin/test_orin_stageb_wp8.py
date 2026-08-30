"""WP8: Secret/Network/Connector cells and the two-phase export pass.

Acceptance items (ORIN_STAGE_B_SPEC.md §4 WP8):

- SECRET-tainted context + egress effect ⇒ ``require_approval`` with the
  ``export_pass`` marker — never an automatic send;
- without a matching pass (hash + destinations) nothing goes out; a pass
  whose payload hash differs is refused;
- redirect to another host is denied by the Network Cell;
- connector dedupe: same idempotency key ⇒ one outbox record, zero
  duplicate effects;
- tokens never appear in any Echo-visible result.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from js.echo.capability import LeaseDenied
from js.orin.client import OrinLeaseClientAdapter
from js.orin.draft import (
    CommitPermit,
    EffectDraft,
    ExportPass,
    Impact,
    StateWitness,
    cell_package_from_dict,
    export_pass_from_dict,
    permit_from_dict,
)
from js.orin.handles import OriginHandle
from js.orin.intent import Budgets, IntentEnvelope
from js.orin.protocol import ProtocolError, canonical_json, make_envelope, parse_frame
from js.orin.testing import TestOrind
from js.orind.cells.services import ConnectorCell, SecretStore, provision_secret
from js.orind.kernel import GateInputs, GateKernel, canonical_effect_hash_of


def _now_ms() -> int:
    return int(time.time() * 1000)


def _pub_of(key: ed25519.Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(
        "ascii"
    )


def _intent(
    task: str,
    *,
    profile: str = "work",
    sink_handles: tuple[str, ...] = (),
) -> IntentEnvelope:
    return IntentEnvelope(
        intent_id=f"intent:{uuid4().hex}",
        owner_key_hash="sha256:" + "1" * 64,
        product_id="js-agent",
        profile=profile,
        task_id=task,
        raw_request_hash="sha256:" + "3" * 64,
        allowed_effect_classes=("net.send", "email.send_exact", "net.fetch"),
        allowed_resource_handles=("dirh:workspace",),
        allowed_sink_handles=sink_handles,
        budgets=Budgets(max_invocations=100, max_bytes_out=1 << 20),
        approval_policy=(
            "preauthorized_exact_template" if profile == "work" else "exact_commit_required"
        ),
        issued_by="appshell:test",
        issued_at_ms=_now_ms() - 1000,
        expires_at_ms=_now_ms() + 60_000,
    )


def _adapter(orind: TestOrind) -> OrinLeaseClientAdapter:
    return OrinLeaseClientAdapter(
        socket_path=orind.socket_path,
        state_dir=Path(orind.daemon._state_dir),  # noqa: SLF001 - test probe
        stage_b=True,
    )


def _sealed_rcpt(mac_key: bytes, token: str) -> OriginHandle:
    ts = _now_ms()
    base = OriginHandle(
        handle_id=f"rcpt:{token}",
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
    return base.sealed_by(mac_key, "orind:broker", ts)


def _sealed_endpoint(mac_key: bytes, host: str) -> OriginHandle:
    ts = _now_ms()
    token = host.replace(":", "-").replace(".", "-")
    base = OriginHandle(
        handle_id=f"ep:{token}",
        kind="EndpointHandle",
        owner_key_hash="sha256:" + "1" * 64,
        tenant="personal",
        source_class="USER_AUTHENTICATED",
        integrity="trusted_local_object",
        confidentiality="PUBLIC",
        object_digest=host,
        capabilities=("read",),
        issuer="orind:broker",
        created_at_ms=ts,
        expires_at_ms=ts + 60_000,
    )
    return base.sealed_by(mac_key, "orind:broker", ts)


def _state_witness(draft: EffectDraft, effect_hash: str) -> StateWitness:
    ts = _now_ms()
    return StateWitness(
        witness_id=f"state:{uuid4().hex}",
        draft_id=draft.draft_id,
        executor_id="cell.connector",
        target_version="outbox:v1",
        canonical_effect_hash=effect_hash,
        impact=Impact(writes=1, recipients=1, bytes_out=128, cost_upper_bound=0),
        reversibility="irreversible_after_provider_accept",
        idempotency_support="client_key",
        created_at_ms=ts - 100,
        expires_at_ms=ts + 60_000,
    )


def _export_pass(
    *,
    key: ed25519.Ed25519PrivateKey,
    task_id: str,
    payload_hash: str,
    destinations: tuple[str, ...],
    witness_id: str,
) -> ExportPass:
    return ExportPass(
        pass_id=f"export:{uuid4().hex}",
        task_id=task_id,
        payload_hash=payload_hash,
        destination_handles=destinations,
        witness_id=witness_id,
        created_at_ms=_now_ms(),
        expires_at_ms=_now_ms() + 60_000,
    ).sign_with(key)


def _cell_package(
    draft: EffectDraft,
    *,
    effect_hash: str,
    handles: tuple[OriginHandle, ...],
    witness: StateWitness | None = None,
) -> dict[str, object]:
    package: dict[str, object] = {
        "protocol": "orin/v1",
        "draft": draft.to_dict(),
        "executor_id": "cell.connector",
        "canonical_effect_hash": effect_hash,
        "resolved_handles": [handle.to_dict() for handle in handles],
        "clearance": 1,
    }
    if witness is not None:
        package["state_witness"] = witness.to_dict()
    return package


class TestCellPackageProtocol:
    def test_preflight_and_commit_carry_package_as_peer_field(self) -> None:
        draft = EffectDraft(
            draft_id=f"draft:{uuid4().hex}",
            task_id=f"task:{uuid4().hex}",
            effect_type="email.send_exact",
            arguments={"recipient_handle": "rcpt:finance", "subject": "s", "body_draft": "b"},
            declared_expectation={},
        )
        effect_hash = canonical_effect_hash_of(draft)
        witness = _state_witness(draft, effect_hash)
        package = _cell_package(
            draft,
            effect_hash=effect_hash,
            handles=(_sealed_rcpt(b"k" * 32, "finance"),),
            witness=witness,
        )
        permit = CommitPermit(
            permit_id=f"permit:{uuid4().hex}",
            intent_id=f"intent:{uuid4().hex}",
            draft_id=draft.draft_id,
            state_witness_id=witness.witness_id,
            executor_id="cell.connector",
            canonical_effect_hash=effect_hash,
            idempotency_key=f"idem:{uuid4().hex}",
            sequence=1,
            not_before_ms=_now_ms() - 100,
            expires_at_ms=_now_ms() + 60_000,
        )
        nonce = secrets.token_hex(16)
        key = b"p" * 32

        preflight = make_envelope(
            "preflight",
            seq=1,
            nonce=nonce,
            session_key=key,
            draft_id=draft.draft_id,
            executor_id="cell.connector",
            package={key: value for key, value in package.items() if key != "state_witness"},
        )
        parsed_preflight = parse_frame(canonical_json(preflight).encode())
        assert parsed_preflight["package"]["draft"]["draft_id"] == draft.draft_id

        commit = make_envelope(
            "commit",
            seq=2,
            nonce=nonce,
            session_key=key,
            permit=permit.to_dict(),
            package=package,
        )
        parsed_commit = parse_frame(canonical_json(commit).encode())
        assert parsed_commit["permit"] == permit.to_dict()
        assert parsed_commit["package"] == package
        assert "package" not in parsed_commit["permit"]
        assert permit_from_dict(parsed_commit["permit"]).draft_id == draft.draft_id
        with pytest.raises(ProtocolError):
            permit_from_dict({**parsed_commit["permit"], "package": package})

    def test_export_pass_signature_round_trip(self) -> None:
        key = ed25519.Ed25519PrivateKey.generate()
        signed = _export_pass(
            key=key,
            task_id="task:round-trip",
            payload_hash="sha256:" + "a" * 64,
            destinations=("rcpt:finance",),
            witness_id="state:round-trip",
        )
        payload = signed.to_dict()
        assert payload["signature"] == signed.signature
        parsed = export_pass_from_dict(payload)
        assert parsed == signed
        assert parsed.verify(_pub_of(key))
        duplicate = replace(signed, destination_handles=("rcpt:finance", "rcpt:finance"))
        with pytest.raises(ProtocolError):
            export_pass_from_dict(duplicate.to_dict())


class TestClearanceTransport:
    async def test_explicit_public_clearance_is_not_replaced_by_internal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[int] = []
        with TestOrind(state_dir=tmp_path, stage_b=True) as orind:

            def authorize(
                _payload: dict[str, object],
                *,
                context_taint: int,
                arg_taint: int,
                clearance: int,
                channel: str = "",
            ) -> dict[str, object]:
                _ = context_taint, arg_taint, channel
                seen.append(clearance)
                return {"ok": True, "verdict": "allow"}

            async def proxy(
                _cap: str, _payload: dict[str, object], *, timeout_s: float
            ) -> dict[str, object]:
                _ = timeout_s
                return {"ok": True, "result": {"status": "COMMITTED"}}

            monkeypatch.setattr(orind.daemon.gatekeeper, "authorize_cell", authorize)
            monkeypatch.setattr(orind.daemon, "_proxy_cell", proxy)
            await orind.daemon._dispatch_cell(  # noqa: SLF001 - taint transport probe
                {
                    "payload": {"cell": "cell.build", "tool": "file_read"},
                    "context_taint": 0,
                    "arg_taint": 0,
                    "clearance": 0,
                }
            )
            await orind.daemon._dispatch_cell(  # noqa: SLF001 - default probe
                {
                    "payload": {"cell": "cell.build", "tool": "file_read"},
                    "context_taint": 0,
                    "arg_taint": 0,
                }
            )
        assert seen == [0, 1]


class TestExportPassFlow:
    @pytest.fixture()
    def services_orind(self, tmp_path: Path):
        witness = ed25519.Ed25519PrivateKey.generate()
        with TestOrind(
            state_dir=tmp_path,
            stage_b=True,
            cell_net=True,
            cell_secret=True,
            witness_public_keys=(_pub_of(witness),),
        ) as orind:
            deadline = time.time() + 20
            while time.time() < deadline:
                if orind.daemon._cell_by_cap("cell.connector"):  # noqa: SLF001
                    break
                time.sleep(0.2)
            else:
                pytest.fail("services cells did not connect")
            yield orind, witness

    @staticmethod
    def _issued_recipient(orind: TestOrind, token: str) -> str:
        issued = orind.daemon._broker.issue(  # noqa: SLF001 - test probe
            kind="RecipientHandle",
            token=token,
            owner_key_hash="sha256:" + "1" * 64,
            capabilities=("send",),
            approved=True,
        )
        assert issued["ok"] is True
        return str(issued["handle"]["handle_id"])

    def _prepare_export(
        self,
        *,
        adapter: OrinLeaseClientAdapter,
        orind: TestOrind,
        witness_key: ed25519.Ed25519PrivateKey,
        profile: str,
        token: str,
    ) -> tuple[EffectDraft, str, dict[str, object]]:
        rcpt_id = self._issued_recipient(orind, token)
        task = f"task:{uuid4().hex}"
        standing_sinks = () if profile == "personal" else (rcpt_id,)
        intent = _intent(task, profile=profile, sink_handles=standing_sinks).sign_with(witness_key)
        assert adapter.register_intent(intent.to_dict()).get("ok") is True
        draft = EffectDraft(
            draft_id=f"draft:{uuid4().hex}",
            task_id=task,
            effect_type="email.send_exact",
            arguments={
                "recipient_handle": rcpt_id,
                "subject": "monthly numbers",
                "body_draft": "approved exact body",
            },
            declared_expectation={"external_visibility": "named_recipients"},
        )
        proposed = adapter.submit_draft(draft.to_dict(), context_taint=1 << 12)
        assert proposed["verdict"] == "deny_missing_witness"
        assert proposed["missing"] == ["state_witness", "export_pass"]

        preflight = adapter.preflight_draft(draft.draft_id, executor_id="cell.connector")
        assert preflight.get("ok") is True
        witness_data = preflight.get("witness")
        assert isinstance(witness_data, dict)
        assert witness_data["draft_id"] == draft.draft_id
        assert witness_data["executor_id"] == "cell.connector"
        assert witness_data["canonical_effect_hash"] == proposed["payload_hash"]
        return (
            draft,
            rcpt_id,
            {
                "payload_hash": str(proposed["payload_hash"]),
                "witness_id": str(witness_data["witness_id"]),
            },
        )

    def test_client_cannot_inject_cell_package(self, services_orind) -> None:
        orind, _witness = services_orind
        adapter = _adapter(orind)
        try:
            with pytest.raises(LeaseDenied):
                adapter._call(  # noqa: SLF001 - role-boundary protocol probe
                    lambda: adapter._request(  # noqa: SLF001
                        "preflight",
                        draft_id="draft:client-injection",
                        executor_id="cell.connector",
                        package={"draft": {"arguments": {"body_draft": "attacker bytes"}}},
                    )
                )
        finally:
            adapter.close()

    def test_personal_export_pass_is_single_use(self, services_orind) -> None:
        orind, witness = services_orind
        adapter = _adapter(orind)
        try:
            draft, rcpt_id, binding = self._prepare_export(
                adapter=adapter,
                orind=orind,
                witness_key=witness,
                profile="personal",
                token=f"personal-{uuid4().hex}",
            )
            exact = _export_pass(
                key=witness,
                task_id=draft.task_id,
                payload_hash=str(binding["payload_hash"]),
                destinations=(rcpt_id,),
                witness_id=str(binding["witness_id"]),
            )
            assert adapter.grant_export(exact.to_dict(), task_id=draft.task_id)["ok"] is True
            committed = adapter.consume_draft(draft.draft_id)
            assert committed["status"] == "COMMITTED"
            with pytest.raises(LeaseDenied):
                adapter.consume_draft(draft.draft_id)
        finally:
            adapter.close()

    def test_work_export_pass_remains_valid_for_exact_binding(self, services_orind) -> None:
        orind, witness = services_orind
        adapter = _adapter(orind)
        try:
            draft, rcpt_id, binding = self._prepare_export(
                adapter=adapter,
                orind=orind,
                witness_key=witness,
                profile="work",
                token=f"work-{uuid4().hex}",
            )
            exact = _export_pass(
                key=witness,
                task_id=draft.task_id,
                payload_hash=str(binding["payload_hash"]),
                destinations=(rcpt_id,),
                witness_id=str(binding["witness_id"]),
            )
            assert adapter.grant_export(exact.to_dict(), task_id=draft.task_id)["ok"] is True
            first = adapter.consume_draft(draft.draft_id)
            second = adapter.consume_draft(draft.draft_id)
            assert first["status"] == "COMMITTED"
            assert second["status"] in {"COMMITTED", "RECONCILED_COMMITTED"}
            assert second.get("remote_operation_id") == first.get("remote_operation_id")
        finally:
            adapter.close()

    def test_mismatched_export_pass_is_rejected_at_grant(self, services_orind) -> None:
        orind, witness = services_orind
        adapter = _adapter(orind)
        try:
            draft, rcpt_id, binding = self._prepare_export(
                adapter=adapter,
                orind=orind,
                witness_key=witness,
                profile="work",
                token=f"binding-{uuid4().hex}",
            )
            mismatches = (
                {"task_id": f"task:{uuid4().hex}"},
                {"payload_hash": "sha256:" + "0" * 64},
                {"destinations": (rcpt_id, "rcpt:extra")},
                {"destinations": (rcpt_id, rcpt_id)},
                {"witness_id": f"state:{uuid4().hex}"},
            )
            baseline: dict[str, object] = {
                "task_id": draft.task_id,
                "payload_hash": str(binding["payload_hash"]),
                "destinations": (rcpt_id,),
                "witness_id": str(binding["witness_id"]),
            }
            for changed in mismatches:
                fields = {**baseline, **changed}
                wrong = _export_pass(key=witness, **fields)  # type: ignore[arg-type]
                with pytest.raises(LeaseDenied):
                    adapter.grant_export(wrong.to_dict(), task_id=draft.task_id)
        finally:
            adapter.close()

    def test_direct_connector_raw_payload_is_rejected(self, services_orind) -> None:
        orind, _witness = services_orind
        adapter = _adapter(orind)
        try:
            rcpt = _sealed_rcpt(
                orind.daemon._keybox.key,  # noqa: SLF001 - test probe
                f"raw-bypass-{uuid4().hex}",
            )
            with pytest.raises(LeaseDenied):
                adapter.run_in_cell(
                    "cell.connector",
                    {
                        "op": "send_exact",
                        # A raw caller can lie about the policy classifier;
                        # the connector cap itself must be rejected before
                        # any legacy payload field is trusted.
                        "tool": "file_read",
                        "recipient_handles": [rcpt.to_dict()],
                        "payload_hash": "sha256:" + "a" * 64,
                        "idempotency_key": f"key-{uuid4().hex}",
                    },
                    context_taint=0,
                )
        finally:
            adapter.close()

    def test_connector_dedupe_and_token_isolation_inside_cell(self, services_orind) -> None:
        orind, _witness = services_orind
        mac_key = orind.daemon._keybox.key  # noqa: SLF001
        state_dir = Path(orind.daemon._state_dir)  # noqa: SLF001

        sealed = provision_secret(
            state_dir,
            mac_key,
            name=f"smtp-{uuid4().hex}",
            token="SUPER-TOKEN",
            audience="personal",
        )
        rcpt = _sealed_rcpt(mac_key, f"finance-{uuid4().hex}")
        cell = ConnectorCell(
            socket_path=state_dir / "unused.sock",
            state_dir=state_dir,
            mac_key=mac_key,
            secrets=SecretStore(state_dir),
        )
        payload = {
            "op": "send_exact",
            "idempotency_key": f"key-{uuid4().hex}",
            "payload_hash": "sha256:" + "a" * 64,
            "recipient_handles": [rcpt.to_dict()],
            "secret_handle": sealed.to_dict(),
        }
        first = cell._send_exact(dict(payload))  # noqa: SLF001
        second = cell._send_exact(dict(payload))  # noqa: SLF001
        assert first.get("status") == "COMMITTED"
        assert second.get("duplicate") is True
        assert second.get("remote_operation_id") == first.get("remote_operation_id")

        outbox = state_dir / "orin" / "connector_outbox.jsonl"
        lines = [json.loads(line) for line in outbox.read_text().splitlines()]
        matching = [row for row in lines if row["idempotency_key"] == payload["idempotency_key"]]
        assert len(matching) == 1  # duplicate side effects: ZERO
        assert "SUPER-TOKEN" not in json.dumps([first, second])


class TestGateConjunctionAndExactBinding:
    @staticmethod
    def _draft(task: str, recipients: tuple[str, ...] = ("rcpt:finance",)) -> EffectDraft:
        return EffectDraft(
            draft_id=f"draft:{uuid4().hex}",
            task_id=task,
            effect_type="email.send_exact",
            arguments={
                "recipient_handles": list(recipients),
                "subject": "monthly numbers",
                "body_draft": "approved exact body",
            },
            declared_expectation={"external_visibility": "named_recipients"},
        )

    @staticmethod
    def _inputs(
        draft: EffectDraft,
        *,
        intent: IntentEnvelope,
        witness: StateWitness | None,
        export_passes: tuple[ExportPass, ...] = (),
    ) -> GateInputs:
        effect_hash = canonical_effect_hash_of(draft)
        inputs = GateInputs(
            now_ms=_now_ms(),
            intent=intent,
            witness=witness,
            canonical_effect_hash=effect_hash,
            export_passes=export_passes,
            context_has_secret=True,
        )
        inputs.handles_by_id = {
            ref: _sealed_rcpt(b"k" * 32, ref.removeprefix("rcpt:"))
            for ref in draft.arguments["recipient_handles"]
        }
        return inputs

    def test_soft_missing_conjuncts_accumulate_without_replacing_state_witness(self) -> None:
        task = f"task:{uuid4().hex}"
        draft = self._draft(task)
        decision = GateKernel(secret_taint_bit=1 << 12).assess(
            draft,
            self._inputs(draft, intent=_intent(task), witness=None),
        )
        assert decision.verdict == "deny_missing_witness"
        assert decision.missing == ("state_witness", "export_pass")

    def test_hard_policy_deny_short_circuits_soft_missing(self) -> None:
        task = f"task:{uuid4().hex}"
        draft = self._draft(task)
        denied_intent = replace(_intent(task), allowed_effect_classes=("artifact.read",))
        decision = GateKernel(secret_taint_bit=1 << 12).assess(
            draft,
            self._inputs(draft, intent=denied_intent, witness=None),
        )
        assert decision.verdict == "deny_policy"
        assert decision.reason_code == "effect_class_not_granted"
        assert decision.missing == ()

    def test_stale_witness_hard_deny_short_circuits_missing_export(self) -> None:
        task = f"task:{uuid4().hex}"
        draft = self._draft(task)
        effect_hash = canonical_effect_hash_of(draft)
        stale = replace(_state_witness(draft, effect_hash), expires_at_ms=_now_ms() - 1)
        decision = GateKernel(secret_taint_bit=1 << 12).assess(
            draft,
            self._inputs(draft, intent=_intent(task), witness=stale),
        )
        assert decision.verdict == "deny_stale_state"
        assert decision.reason_code == "witness_expired"
        assert decision.missing == ()

    def test_export_pass_matches_task_hash_destinations_and_witness_exactly(self) -> None:
        key = ed25519.Ed25519PrivateKey.generate()
        task = f"task:{uuid4().hex}"
        destinations = ("rcpt:finance", "rcpt:legal")
        draft = self._draft(task, destinations)
        effect_hash = canonical_effect_hash_of(draft)
        witness = _state_witness(draft, effect_hash)
        exact = _export_pass(
            key=key,
            task_id=task,
            payload_hash=effect_hash,
            destinations=destinations,
            witness_id=witness.witness_id,
        )
        baseline: dict[str, object] = {
            "task_id": task,
            "payload_hash": effect_hash,
            "destinations": destinations,
            "witness_id": witness.witness_id,
        }
        mismatches = (
            {"task_id": f"task:{uuid4().hex}"},
            {"payload_hash": "sha256:" + "0" * 64},
            {"destinations": ("rcpt:finance",)},
            {"destinations": (*destinations, "rcpt:extra")},
            {"destinations": ("rcpt:legal", "rcpt:finance", "rcpt:finance")},
            {"witness_id": f"state:{uuid4().hex}"},
        )
        kernel = GateKernel(secret_taint_bit=1 << 12)
        exact_inputs = self._inputs(
            draft,
            intent=_intent(task),
            witness=witness,
            export_passes=(exact,),
        )
        assert kernel._export_pass_matches(draft, exact_inputs) is True  # noqa: SLF001
        reordered = _export_pass(
            key=key,
            task_id=task,
            payload_hash=effect_hash,
            destinations=tuple(reversed(destinations)),
            witness_id=witness.witness_id,
        )
        reordered_inputs = self._inputs(
            draft,
            intent=_intent(task),
            witness=witness,
            export_passes=(reordered,),
        )
        assert kernel._export_pass_matches(draft, reordered_inputs) is True  # noqa: SLF001
        for changed in mismatches:
            fields = {**baseline, **changed}
            wrong = _export_pass(key=key, **fields)  # type: ignore[arg-type]
            wrong_inputs = self._inputs(
                draft,
                intent=_intent(task),
                witness=witness,
                export_passes=(wrong,),
            )
            assert kernel._export_pass_matches(draft, wrong_inputs) is False  # noqa: SLF001

    def test_email_send_exact_is_not_unconditionally_dual_control(self) -> None:
        key = ed25519.Ed25519PrivateKey.generate()
        task = f"task:{uuid4().hex}"
        draft = self._draft(task)
        effect_hash = canonical_effect_hash_of(draft)
        witness = _state_witness(draft, effect_hash)
        export_pass = _export_pass(
            key=key,
            task_id=task,
            payload_hash=effect_hash,
            destinations=("rcpt:finance",),
            witness_id=witness.witness_id,
        )
        decision = GateKernel(secret_taint_bit=1 << 12).assess(
            draft,
            self._inputs(
                draft,
                intent=_intent(task, profile="personal"),
                witness=witness,
                export_passes=(export_pass,),
            ),
        )
        assert decision.verdict == "require_approval"
        assert decision.missing == ("exact_approval",)


class TestNetFetchDispatch:
    async def test_fetch_uses_strict_preflight_commit_without_export_pass(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import js.security.net_guard as net_guard

        phases: list[str] = []

        def export_pass_forbidden(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("net.fetch must never query or claim an ExportPass")

        with TestOrind(state_dir=tmp_path, stage_b=True) as orind:
            intents = orind.daemon._intents  # noqa: SLF001 - boundary sentinel
            assert intents is not None
            for method_name in (
                "export_passes_for_task",
                "active_exact_export_passes",
                "claim_personal_export_pass",
            ):
                monkeypatch.setattr(intents, method_name, export_pass_forbidden)
            monkeypatch.setattr(
                net_guard,
                "resolve_and_validate",
                lambda _url: ["127.0.0.1"],
            )

            async def request_cell(
                cap: str,
                message_type: str,
                **fields: object,
            ) -> dict[str, object]:
                assert cap == "cell.net"
                phases.append(message_type)
                package = cell_package_from_dict(dict(fields["package"]))  # type: ignore[arg-type]
                assert package.executor_id == "cell.net"
                assert package.draft.effect_type == "net.fetch"
                assert len(package.resolved_handles) == 1
                assert package.resolved_handles[0].kind == "EndpointHandle"
                if message_type == "preflight":
                    assert "permit" not in fields
                    assert package.state_witness is None
                    now = _now_ms()
                    witness = StateWitness(
                        witness_id=f"state:{uuid4().hex}",
                        draft_id=package.draft.draft_id,
                        executor_id="cell.net",
                        target_version="net:test-pinned-origin",
                        canonical_effect_hash=package.canonical_effect_hash,
                        impact=Impact(),
                        reversibility="reversible_until_stage",
                        idempotency_support="none",
                        created_at_ms=now,
                        expires_at_ms=now + 60_000,
                    )
                    return {"ok": True, "witness": witness.to_dict()}
                assert message_type == "commit"
                assert set(fields) == {"permit", "package"}
                permit = permit_from_dict(dict(fields["permit"]))  # type: ignore[arg-type]
                assert "package" not in fields["permit"]  # type: ignore[operator]
                assert package.state_witness is not None
                assert permit.draft_id == package.draft.draft_id
                assert permit.executor_id == package.executor_id == "cell.net"
                assert permit.canonical_effect_hash == package.canonical_effect_hash
                assert permit.state_witness_id == package.state_witness.witness_id
                return {
                    "ok": True,
                    "result": {
                        "status": "COMMITTED",
                        "output": "network-cell-body",
                        "content_hash": "sha256:" + "a" * 64,
                        "final_url": "https://example.test/final",
                        "token": "MUST-NOT-PROJECT",
                    },
                }

            monkeypatch.setattr(orind.daemon, "_request_cell", request_cell)
            result = await orind.daemon._dispatch_net_fetch(  # noqa: SLF001
                {
                    "cell": "cell.net",
                    "tool": "net.fetch",
                    "url": "https://example.test/start",
                    "max_chars": 321,
                },
                {"ok": True, "verdict": "allow"},
            )

        assert phases == ["preflight", "commit"]
        assert result["ok"] is True
        assert result["cell"]["status"] == "COMMITTED"  # type: ignore[index]
        assert result["cell"]["output"] == "network-cell-body"  # type: ignore[index]
        assert "MUST-NOT-PROJECT" not in repr(result)


class TestNetCell:
    def test_cross_host_redirect_denied(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from js.orind.cells import services

        mac_key = b"k" * 32
        endpoint = _sealed_endpoint(mac_key, "allowed.example")
        cell = services.NetCell(
            socket_path=tmp_path / "unused.sock",
            state_dir=tmp_path,
            mac_key=mac_key,
            allowed_hosts=frozenset({"allowed.example"}),
        )

        # Isolate redirect behavior from DNS/network availability: the
        # initial origin passed validation, then the injected transport
        # presents a real 302 target on another origin.
        monkeypatch.setattr(services, "resolve_and_validate", lambda _url: None)

        class InitialRequest:
            host = "allowed.example"

        class RedirectingOpener:
            def __init__(self, handler: object) -> None:
                self._handler = handler

            def open(self, _request: object, *, timeout: float) -> object:
                _ = timeout
                return self._handler.redirect_request(  # type: ignore[attr-defined,no-any-return]
                    InitialRequest(),
                    None,
                    302,
                    "Found",
                    {},
                    "https://evil.example/steal",
                )

        monkeypatch.setattr(
            services.urllib.request,
            "build_opener",
            lambda handler: RedirectingOpener(handler),
        )
        result = cell._fetch(  # noqa: SLF001 - direct unit call
            {
                "url": "https://allowed.example/start",
                "endpoint_handle": endpoint.to_dict(),
            }
        )
        assert result.get("status") == "FAILED"
        assert "cross-host redirect denied" in str(result.get("error"))

    def test_pinned_transport_rejects_cross_origin_before_second_server(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import http.server
        import threading

        from js.orind.cells import services

        requests = {"allowed": 0, "evil": 0}

        class EvilHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                requests["evil"] += 1
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"evil reached")

            def log_message(self, *_args: object) -> None:
                pass

        evil = http.server.HTTPServer(("127.0.0.1", 0), EvilHandler)
        evil_port = int(evil.server_address[1])

        class AllowedHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                requests["allowed"] += 1
                self.send_response(302)
                self.send_header(
                    "Location",
                    f"http://127.0.0.1:{evil_port}/steal",
                )
                self.end_headers()

            def log_message(self, *_args: object) -> None:
                pass

        allowed = http.server.HTTPServer(("127.0.0.1", 0), AllowedHandler)
        allowed_port = int(allowed.server_address[1])
        evil_thread = threading.Thread(target=evil.serve_forever, daemon=True)
        allowed_thread = threading.Thread(target=allowed.serve_forever, daemon=True)
        evil_thread.start()
        allowed_thread.start()
        try:
            monkeypatch.setattr(
                services,
                "resolve_and_validate",
                lambda _url: ["127.0.0.1"],
            )
            mac_key = b"k" * 32
            cell = services.NetCell(
                socket_path=tmp_path / "unused.sock",
                state_dir=tmp_path,
                mac_key=mac_key,
                allowed_hosts=frozenset({"127.0.0.1"}),
            )
            result = cell._fetch(  # noqa: SLF001 - real pinned transport probe
                {
                    "url": f"http://127.0.0.1:{allowed_port}/start",
                    "endpoint_handle": _sealed_endpoint(mac_key, "127.0.0.1").to_dict(),
                    "timeout_s": 3,
                }
            )
        finally:
            allowed.shutdown()
            evil.shutdown()
            allowed.server_close()
            evil.server_close()
            allowed_thread.join(timeout=5)
            evil_thread.join(timeout=5)

        assert result.get("status") == "FAILED"
        assert requests["allowed"] == 1, result
        assert requests["evil"] == 0
        assert "cross-host redirect denied" in str(result.get("error"))

    def test_private_target_blocked_by_net_guard(self, tmp_path: Path) -> None:
        from js.orind.cells.services import NetCell

        mac_key = b"k" * 32
        cell = NetCell(socket_path=tmp_path / "unused.sock", state_dir=tmp_path, mac_key=mac_key)
        for url in ("http://10.0.0.1/x", "http://169.254.169.254/latest/meta-data"):
            host = url.split("/", 3)[2]
            result = cell._fetch(  # noqa: SLF001
                {"url": url, "endpoint_handle": _sealed_endpoint(mac_key, host).to_dict()}
            )
            assert result.get("status") == "FAILED"
            assert "egress blocked" in str(result.get("error"))

    def test_unsealed_endpoint_handle_refused(self, tmp_path: Path) -> None:
        from js.orind.cells.services import NetCell

        cell = NetCell(socket_path=tmp_path / "unused.sock", state_dir=tmp_path, mac_key=b"k" * 32)
        result = cell._fetch(  # noqa: SLF001
            {"url": "https://example.com/", "endpoint_handle": {"handle_id": "ep:x"}}
        )
        assert result.get("status") == "FAILED"
        assert "unsealed" in str(result.get("error"))


class TestSecretCellUnit:
    def test_clearance_below_secret_is_denied_and_token_never_returns(self, tmp_path: Path) -> None:
        from js.orind.cells.services import SecretCell

        secrets = SecretStore(tmp_path)
        sealed = provision_secret(tmp_path, b"k" * 32, name="mail", token="t0k", audience="work")
        cell = SecretCell(
            socket_path=tmp_path / "s.sock", state_dir=tmp_path, mac_key=b"k" * 32, secrets=secrets
        )

        for clearance in (0, 1):
            denied = cell._resolve(  # noqa: SLF001
                {
                    "secret_handle": sealed.to_dict(),
                    "audience": "work",
                    "clearance": clearance,
                }
            )
            assert denied["status"] == "FAILED"
            assert "clearance" in str(denied.get("error", "")).lower()

        ok_call = cell._resolve(  # noqa: SLF001
            {"secret_handle": sealed.to_dict(), "audience": "work", "clearance": 2}
        )
        assert ok_call["status"] == "COMMITTED"
        assert "token" not in ok_call
        assert "t0k" not in json.dumps(ok_call)

        wrong_audience = cell._resolve(  # noqa: SLF001
            {"secret_handle": sealed.to_dict(), "audience": "other", "clearance": 2}
        )
        assert wrong_audience["status"] == "FAILED"

        tampered = replace(sealed, signature="")
        bad = cell._resolve(  # noqa: SLF001
            {"secret_handle": tampered.to_dict(), "audience": "work", "clearance": 2}
        )
        assert bad["status"] == "FAILED"
