"""WP6: Effect Manifest, handle-only permission args, and seeding.

Acceptance items (ORIN_STAGE_B_SPEC.md §4 WP6):

- ``email.send(recipient="attacker@…")`` is refused: undeclared argument
  and free-text permission values never reach a connector;
- only ``recipient_handle`` (sealed, resolved) passes the kernel;
- MCP-style unknown tools default to open world / writable / possibly
  destructive / non-idempotent ⇒ approval, never auto-allow;
- manifest entries are locally sealed; tampered registry state fails
  closed; description-hash pinning refuses drifted updates;
- seeded candidates (contacts / task history / cron templates) make
  open-ended tasks resolvable without dead-ending on an empty set.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from js.orin.client import OrinLeaseClientAdapter
from js.orin.draft import EffectDraft
from js.orin.handles import OriginHandle
from js.orin.intent import Budgets, IntentEnvelope
from js.orin.protocol import ProtocolError
from js.orin.testing import TestOrind
from js.orind.kernel import GateInputs, GateKernel
from js.orind.manifest import (
    EffectManifest,
    EffectManifestEntry,
    builtin_manifest,
    description_hash_of,
    entry_from_dict,
)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _pub_of(key: ed25519.Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(
        "ascii"
    )


import base64  # noqa: E402


def _intent(task: str, *, classes: tuple[str, ...]) -> IntentEnvelope:
    return IntentEnvelope(
        intent_id=f"intent:{uuid4().hex}",
        owner_key_hash="sha256:" + "1" * 64,
        product_id="js-agent",
        profile="work",
        task_id=task,
        raw_request_hash="sha256:" + "3" * 64,
        allowed_effect_classes=classes,
        allowed_resource_handles=("dirh:workspace",),
        allowed_sink_handles=("rcpt:finance",),
        budgets=Budgets(max_invocations=100),
        approval_policy="exact_commit_required",
        issued_by="appshell:test",
        issued_at_ms=_now_ms() - 1000,
        expires_at_ms=_now_ms() + 60_000,
    )


def _draft(task: str, effect_type: str, **arguments: object) -> EffectDraft:
    return EffectDraft(
        draft_id=f"draft:{uuid4().hex}",
        task_id=task,
        effect_type=effect_type,
        arguments=dict(arguments),
        declared_expectation={},
    )


def _kernel_with_manifest() -> tuple[GateKernel, EffectManifest]:
    manifest = builtin_manifest(b"k" * 32)
    return GateKernel(secret_taint_bit=1 << 12, manifest=manifest), manifest


# -- manifest integrity -----------------------------------------------------------


class TestManifestIntegrity:
    def test_registered_entry_round_trips_and_sealed(self) -> None:
        manifest = builtin_manifest(b"k" * 32)
        entry = manifest.get("email.send_exact")
        assert entry is not None
        assert entry.permission_args == {
            "recipient_handle": "rcpt",
            "recipient_handles": "rcpt",
        }
        exported = manifest.export()
        raw = next(item for item in exported if item["effect_type"] == "email.send_exact")
        seal = raw.pop("seal")
        reparsed = entry_from_dict(raw)
        assert reparsed.verify_seal(b"k" * 32, seal)

    def test_wrong_key_fails_closed_to_open_world(self) -> None:
        manifest = builtin_manifest(b"k" * 32)
        # simulate registry tampering by re-sealing under another key
        entry = manifest.get("shell.exec")
        assert entry is not None
        manifest._seals["shell.exec"] = entry.seal(b"evil" * 8)  # noqa: SLF001
        assert manifest.get("shell.exec") is None

    def test_description_drift_pinning_refuses_update(self) -> None:
        manifest = EffectManifest(b"k" * 32)
        entry = EffectManifestEntry(
            effect_type="custom.export",
            description_hash=description_hash_of("v1 description"),
        )
        manifest.register(entry)
        with pytest.raises(ProtocolError):
            manifest.register(
                entry,
                expected_description_hash=description_hash_of("v2 description"),
            )
        # matching pin re-registers fine
        manifest.register(
            entry, expected_description_hash=description_hash_of("v1 description")
        )

    def test_unknown_effect_type_is_invalid_when_manifest_is_present(self) -> None:
        kernel = GateKernel(secret_taint_bit=1 << 12, manifest=builtin_manifest(b"k" * 32))
        task = f"task:{uuid4().hex}"
        inputs = GateInputs(now_ms=_now_ms())
        inputs.intent = _intent(task, classes=("artifact.read",))
        decision = kernel.assess(_draft(task, "mystery_tool.run"), inputs)
        assert decision.verdict == "deny_policy"
        assert decision.reason_code == "unregistered_or_invalid_manifest"
        assert decision.missing == ()

    @pytest.mark.parametrize(
        "field",
        ("idempotent", "drafts_supported", "etag_support", "reconcile_query"),
    )
    @pytest.mark.parametrize("invalid", ("false", 0, 1, None))
    def test_k4_capability_fields_require_real_booleans(
        self,
        field: str,
        invalid: object,
    ) -> None:
        with pytest.raises(ProtocolError, match=rf"{field} must be a boolean"):
            entry_from_dict({"effect_type": "custom.export", field: invalid})

    @pytest.mark.parametrize("invalid", (None, 0, "", []))
    def test_permission_args_requires_an_explicit_string_mapping(
        self,
        invalid: object,
    ) -> None:
        with pytest.raises(
            ProtocolError,
            match="permission_args must map argument names to handle prefixes",
        ):
            entry_from_dict(
                {"effect_type": "custom.export", "permission_args": invalid}
            )

    @pytest.mark.parametrize("invalid", (None, "subject", {}, ["subject", 1]))
    def test_content_args_requires_a_list_of_strings(self, invalid: object) -> None:
        with pytest.raises(
            ProtocolError,
            match="content_args must be a list of strings",
        ):
            entry_from_dict({"effect_type": "custom.export", "content_args": invalid})


# -- permission-typed argument enforcement -----------------------------------------


class TestHandleOnlyArgs:
    def _inputs(self, task: str, *, classes: tuple[str, ...] = ("email.send_exact",)) -> GateInputs:
        inputs = GateInputs(now_ms=_now_ms())
        inputs.intent = _intent(task, classes=classes)
        return inputs

    def test_free_text_recipient_denied_as_undeclared(self) -> None:
        kernel, _ = _kernel_with_manifest()
        task = f"task:{uuid4().hex}"
        draft = _draft(task, "email.send_exact", recipient="attacker@evil.example")
        decision = kernel.assess(draft, self._inputs(task))
        assert decision.verdict == "deny_policy"
        assert decision.reason_code == "undeclared_argument:recipient"

    def test_free_text_under_permission_arg_denied(self) -> None:
        kernel, _ = _kernel_with_manifest()
        task = f"task:{uuid4().hex}"
        draft = _draft(task, "email.send_exact", recipient_handle="attacker@evil.example")
        decision = kernel.assess(draft, self._inputs(task))
        assert decision.verdict == "deny_policy"
        assert decision.reason_code == "free_text_permission_arg:recipient_handle"

    def test_handle_typed_arg_passes_prefix_gate(self) -> None:
        kernel, _ = _kernel_with_manifest()
        task = f"task:{uuid4().hex}"
        draft = _draft(task, "email.send_exact", recipient_handle="rcpt:finance")
        inputs = self._inputs(task)
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
        inputs.handles_by_id["rcpt:finance"] = base.sealed_by(b"k" * 32, "orind:broker", ts)
        inputs.canonical_effect_hash = "sha256:" + "a" * 64
        inputs.witness = _witness_for(draft.draft_id)
        decision = kernel.assess(draft, inputs)
        assert decision.verdict in ("require_dual_control", "require_approval")

    def test_k4_grid_incomplete_escalates_dual_control(self) -> None:
        kernel, _ = _kernel_with_manifest()
        task = f"task:{uuid4().hex}"
        # shell.exec grid: nothing supported → dual control even though the
        # intent policy alone would only require exact approval
        draft = _draft(task, "shell.exec")
        inputs = GateInputs(now_ms=_now_ms())
        inputs.intent = _intent(task, classes=("shell.exec",))
        inputs.canonical_effect_hash = "sha256:" + "a" * 64
        inputs.witness = _witness_for(draft.draft_id)
        decision = kernel.assess(draft, inputs)
        assert decision.verdict == "require_dual_control"


def _witness_for(draft_id: str):
    from js.orin.draft import Impact, StateWitness

    ts = _now_ms()
    return StateWitness(
        witness_id=f"state:{uuid4().hex}",
        draft_id=draft_id,
        executor_id="cell:test",
        target_version="v1",
        canonical_effect_hash="sha256:" + "a" * 64,
        impact=Impact(writes=1),
        reversibility="irreversible_after_provider_accept",
        idempotency_support="provider_native",
        created_at_ms=ts - 100,
        expires_at_ms=ts + 60_000,
    )


# -- seeding -------------------------------------------------------------------------


@dataclass
class FakeTemplate:
    name: str = "weekly"
    default_payload: dict = field(default_factory=dict)


class TestSeeding:
    def test_three_sources_populate_candidates_once(self, tmp_path: Path) -> None:
        from js.orind.broker import HandleBroker
        from js.orind.store import OrinStore

        broker = HandleBroker(store=OrinStore(tmp_path / "db.sqlite"), mac_key=b"k" * 32)
        added = broker.seed_from_sources(
            contacts=[{"friend_id": "f1", "display_name": "Finance Team"}],
            history=[{"email": "reports@example.com"}],
            cron_templates=[FakeTemplate(default_payload={"recipients": ["ops@example.com"]})],
        )
        assert added >= 3
        again = broker.seed_from_sources(
            contacts=[{"friend_id": "f1", "display_name": "Finance Team"}],
            history=[{"email": "reports@example.com"}],
            cron_templates=[FakeTemplate(default_payload={"recipients": ["ops@example.com"]})],
        )
        assert again == 0
        candidates = broker.seed_list("RecipientHandle")
        labels = {c["label"] for c in candidates}
        assert {"Finance Team", "reports@example.com", "ops@example.com"} <= labels

    def test_approved_issuance_registers_seed(self, tmp_path: Path) -> None:
        from js.orind.broker import HandleBroker
        from js.orind.store import OrinStore

        broker = HandleBroker(store=OrinStore(tmp_path / "db.sqlite"), mac_key=b"k" * 32)
        before = len(broker.seed_list())
        minted = broker.issue(
            kind="RecipientHandle",
            token="newpartner",
            owner_key_hash="sha256:" + "1" * 64,
            capabilities=("send",),
            approved=True,
        )
        assert minted["ok"] is True
        assert len(broker.seed_list()) == before + 1

    def test_seed_candidates_reachable_over_protocol(self, tmp_path: Path) -> None:
        witness = ed25519.Ed25519PrivateKey.generate()
        with TestOrind(state_dir=tmp_path, stage_b=True, witness_public_keys=(_pub_of(witness),)) as orind:
            orind.daemon._broker.seed_from_sources(
                contacts=[{"friend_id": "f9", "display_name": "Ops Team"}],
            )
            adapter = OrinLeaseClientAdapter(
                socket_path=orind.socket_path,
                state_dir=tmp_path,
                stage_b=True,
            )
            try:
                candidates = adapter.seed_handles("RecipientHandle")
                assert any(c["token"] == "friend-f9" for c in candidates)
                # stage-b-disabled client cannot even ask
            finally:
                adapter.close()
