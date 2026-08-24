"""WP5: AppShell owner-witness intents and admin-master unfreeze.

Acceptance items (ORIN_STAGE_B_SPEC.md §4 WP5):

- witness keypair provisioning is idempotent; orind trusts the published key;
- default templates: personal refuses standing sinks; work grants them;
- an intent signed by a trusted witness registers over the real protocol;
- forged / untrusted intents are refused (Echo cannot mint owner authority);
- frozen sessions can only be unwound by a dual-control admin.unfreeze
  intent — Echo has no path;
- session permissions only tighten.
"""

from __future__ import annotations

import base64
import time
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from js.echo.capability import LeaseDenied
from js.orin.client import OrinLeaseClientAdapter, OrinUnknownIntent
from js.orin.intent import (
    Budgets,
    IntentEnvelope,
    request_hash_of,
    session_tightening_ok,
)
from js.orin.testing import TestOrind
from js.orin.witness import (
    DEFAULT_TEMPLATES,
    build_intent_from_template,
    ensure_witness_keypair,
    load_published_public_key,
)


def _pub_of(key: ed25519.Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(
        "ascii"
    )


def _adapter(orind: TestOrind) -> OrinLeaseClientAdapter:
    """Adapter bound to the daemon's (possibly relocated) socket."""
    state_dir = orind.daemon._state_dir
    return OrinLeaseClientAdapter(
        socket_path=orind.socket_path,
        state_dir=Path(state_dir),
        stage_b=True,
    )


# -- witness identity -------------------------------------------------------------


class TestWitnessIdentity:
    def test_ensure_is_idempotent_and_publishes_pub(self, tmp_path: Path) -> None:
        key1, pub1 = ensure_witness_keypair(tmp_path)
        key2, pub2 = ensure_witness_keypair(tmp_path)
        assert pub1 == pub2
        env = build_intent_from_template(
            template="personal",
            task_id="task:t1",
            raw_request="read reports",
            owner_key_hash="sha256:" + "2" * 64,
        )
        assert env.sign_with(key1).verify(pub1)
        assert load_published_public_key(tmp_path) == pub1

    def test_personal_template_refuses_standing_sinks(self) -> None:
        envelope = build_intent_from_template(
            template="personal",
            task_id="task:t2-classes",
            raw_request="send one exact message",
            owner_key_hash="sha256:" + "2" * 64,
        )
        assert "email.send_exact" in envelope.allowed_effect_classes
        assert envelope.budgets.max_bytes_out > 0
        with pytest.raises(ValueError):
            build_intent_from_template(
                template="personal",
                task_id="task:t2",
                raw_request="send stuff",
                owner_key_hash="sha256:" + "2" * 64,
                sink_handles=("rcpt:finance",),
            )

    def test_work_template_grants_standing_authorization(self) -> None:
        envelope = build_intent_from_template(
            template="work",
            task_id="task:t3",
            raw_request="weekly automation",
            owner_key_hash="sha256:" + "2" * 64,
            sink_handles=("rcpt:finance",),
        )
        assert envelope.approval_policy == DEFAULT_TEMPLATES["work"]["policy"]
        assert "shell.exec" in envelope.allowed_effect_classes
        assert "email.send_exact" in envelope.allowed_effect_classes

    def test_unknown_template_rejected(self) -> None:
        with pytest.raises(ValueError):
            build_intent_from_template(
                template="chaos",
                task_id="task:x",
                raw_request="r",
                owner_key_hash="sha256:" + "2" * 64,
            )


class TestSessionTightening:
    def test_budget_expansion_refused(self) -> None:
        base = build_intent_from_template(
            template="personal",
            task_id="task:b",
            raw_request="a",
            owner_key_hash="sha256:" + "3" * 64,
        )
        expanded = replace(base, budgets=Budgets(max_invocations=10_000))
        assert not session_tightening_ok(expanded, base)


# -- daemon-side admin unfreeze -----------------------------------------------------


def _admin_intent(owner: str, *, classes: tuple[str, ...] = ("admin.unfreeze",)) -> IntentEnvelope:
    ts = int(time.time() * 1000)
    return IntentEnvelope(
        intent_id=f"intent:{ts:x}-{uuid4().hex[:8]}",
        owner_key_hash=owner,
        product_id="js-agent",
        profile="admin",
        task_id=f"task:admin-{uuid4().hex[:8]}",
        raw_request_hash=request_hash_of("unfreeze"),
        allowed_effect_classes=classes,
        allowed_resource_handles=(),
        allowed_sink_handles=(),
        budgets=Budgets(),
        approval_policy="dual_control",
        issued_by="appshell:admin-witness",
        issued_at_ms=ts - 1000,
        expires_at_ms=ts + 60_000,
    )


class TestAdminUnfreeze:
    def _freeze_session(self, orind: TestOrind, session_id: str) -> None:
        orind.daemon.gatekeeper.responder.escalate(
            session_id=session_id,
            level=3,
            now_ms=int(time.time() * 1000),
            evidence="canary double hit",
        )

    def test_frozen_session_requires_admin_intent(self, tmp_path: Path) -> None:
        witness = ed25519.Ed25519PrivateKey.generate()
        with TestOrind(
            state_dir=tmp_path,
            stage_b=True,
            witness_public_keys=(_pub_of(witness),),
        ) as orind:
            session_id = "sess-frozen"
            self._freeze_session(orind, session_id)
            adapter = _adapter(orind)
            try:
                # properly signed but non-admin classes → denied
                weak = build_intent_from_template(
                    template="personal",
                    task_id=f"task:weak-{uuid4().hex[:8]}",
                    raw_request="let me out",
                    owner_key_hash="sha256:" + "9" * 64,
                ).sign_with(witness)
                with pytest.raises(LeaseDenied):
                    adapter.admin_unfreeze(weak.to_dict(), session_id=session_id)

                # proper dual-control admin signature unwinds the ladder
                admin = _admin_intent("sha256:" + "9" * 64).sign_with(witness)
                ok = adapter.admin_unfreeze(admin.to_dict(), session_id=session_id)
                assert ok.get("ok") is True
                assert session_id in (ok.get("unfrozen") or [])
                assert orind.daemon.gatekeeper.responder.level_of(session_id) == 0
            finally:
                adapter.close()

    def test_forged_admin_signature_refused(self, tmp_path: Path) -> None:
        trusted = ed25519.Ed25519PrivateKey.generate()
        forger = ed25519.Ed25519PrivateKey.generate()
        with TestOrind(
            state_dir=tmp_path,
            stage_b=True,
            witness_public_keys=(_pub_of(trusted),),
        ) as orind:
            session_id = "sess-frozen-2"
            self._freeze_session(orind, session_id)
            adapter = _adapter(orind)
            try:
                forged = _admin_intent("sha256:" + "8" * 64).sign_with(forger)
                with pytest.raises(OrinUnknownIntent):
                    adapter.admin_unfreeze(forged.to_dict(), session_id=session_id)
                assert orind.daemon.gatekeeper.responder.level_of(session_id) == 3
            finally:
                adapter.close()


class TestIntentClientSurface:
    def test_register_and_query_active(self, tmp_path: Path) -> None:
        witness = ed25519.Ed25519PrivateKey.generate()
        with TestOrind(
            state_dir=tmp_path,
            stage_b=True,
            witness_public_keys=(_pub_of(witness),),
        ) as orind:
            adapter = _adapter(orind)
            try:
                envelope = build_intent_from_template(
                    template="work",
                    task_id="task:active-1",
                    raw_request="weekly report automation",
                    owner_key_hash="sha256:" + "7" * 64,
                    sink_handles=("rcpt:finance",),
                ).sign_with(witness)
                ack = adapter.register_intent(envelope.to_dict())
                assert ack.get("ok") is True
                active = adapter.active_intent("task:active-1")
                assert active is not None
                assert active["intent"]["intent_id"] == envelope.intent_id
                missing = adapter.active_intent("task:never-registered")
                assert missing is None
            finally:
                adapter.close()

    def test_unknown_intent_maps_to_none_not_crash(self, tmp_path: Path) -> None:
        with TestOrind(state_dir=tmp_path, stage_b=True) as orind:
            adapter = _adapter(orind)
            try:
                assert adapter.active_intent("task:nothing") is None
            finally:
                adapter.close()

    def test_tightening_replacement_accepted_expansion_refused(
        self, tmp_path: Path
    ) -> None:
        witness = ed25519.Ed25519PrivateKey.generate()
        with TestOrind(
            state_dir=tmp_path,
            stage_b=True,
            witness_public_keys=(_pub_of(witness),),
        ) as orind:
            adapter = _adapter(orind)
            task = f"task:tighten-{uuid4().hex[:6]}"
            base = build_intent_from_template(
                template="work",
                task_id=task,
                raw_request="automation",
                owner_key_hash="sha256:" + "5" * 64,
            ).sign_with(witness)
            tighter = replace(
                base, allowed_effect_classes=("artifact.read",), intent_id=f"intent:{uuid4().hex}"
            ).sign_with(witness)
            looser = replace(
                base,
                allowed_effect_classes=("artifact.read", "net.send", "shell.exec"),
                intent_id=f"intent:{uuid4().hex}",
            ).sign_with(witness)
            try:
                assert adapter.register_intent(base.to_dict()).get("ok") is True
                assert adapter.register_intent(tighter.to_dict()).get("ok") is True
                with pytest.raises(LeaseDenied):
                    adapter.register_intent(looser.to_dict())
            finally:
                adapter.close()

    def test_stage_b_disabled_client_refuses_surface(self, tmp_path: Path) -> None:
        from js.orin.client import OrinUnavailable

        with TestOrind(state_dir=tmp_path, stage_b=False) as orind:
            plain = OrinLeaseClientAdapter(
                socket_path=orind.socket_path,
                state_dir=Path(orind.daemon._state_dir),
                stage_b=False,
            )
            try:
                with pytest.raises(OrinUnavailable):
                    plain.register_intent({})
                with pytest.raises(OrinUnavailable):
                    _ = plain.active_intent("task:x")
            finally:
                plain.close()
