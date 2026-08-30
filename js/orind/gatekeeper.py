"""orind GateKeeper: authoritative lease stamping over the JSONL ledger.

The GateKeeper owns the only :class:`LeaseAuthority` instance in the Orin
world. Its ledger path is deliberately the *same* ``echo_tool_lease.jsonl``
the in-process authority used to write — one ledger, one truth — and the
KeyBox supplies the same HMAC key (adopted, never rotated), so pre-Orin
leases verify unchanged and ``orin_enabled=false`` rollback keeps every
WP1-issued lease registered.

Decision path rules (Stage A iron law): no LLM, no classifier, no content
semantics — only MAC checks, registry lookups, and bit operations. The
daemon always uses its own clock; request-carried time does not exist in
the protocol.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from js.echo.capability import (
    LeaseAuthority,
    LeaseBindingMismatch,
    LeaseContextMismatch,
    LeaseDenied,
    LeaseExhausted,
    LeaseExpired,
    LeaseMacInvalid,
    LeaseNonceReplay,
    LeaseOwnerMismatch,
    LeaseParentMissing,
    LeaseRevoked,
    LeaseScopeMismatch,
    LeaseToolMismatch,
    _lease_from_payload,
    _lease_to_payload,
    sign_tool_execution_context,
)
from js.echo.types import CapabilityLease
from js.orin.protocol import EchoContextPayload
from js.orin.receipts import DecisionReceipt, ReceiptSigner
from js.orind import policy as policy_mod
from js.orind.canary import FREEZE_TEXT, REFUSAL_TEXT, CanaryVault
from js.orind.patrol import PatrolBoard
from js.orind.responder import LEVEL_FREEZE, LEVEL_NARROW, Responder
from js.orind.store import OrinStore

POLICY_VERSION = 2
"""Stage A WP2 policy table version (taint rows active)."""

EXC_TO_CODE: dict[type[Exception], str] = {
    LeaseMacInvalid: "mac_invalid",
    LeaseExpired: "expired",
    LeaseNonceReplay: "replay",
    LeaseRevoked: "revoked",
    LeaseExhausted: "exhausted",
    LeaseOwnerMismatch: "binding_mismatch",
    LeaseToolMismatch: "binding_mismatch",
    LeaseScopeMismatch: "binding_mismatch",
    LeaseBindingMismatch: "binding_mismatch",
    LeaseContextMismatch: "context_mismatch",
    LeaseParentMissing: "parent_missing",
    LeaseDenied: "denied",
}


class GateKeeper:
    """Handles one protocol request at a time; no internal concurrency."""

    def __init__(
        self,
        *,
        mac_key: bytes,
        ledger_path: Path,
        store: OrinStore,
        key_dir: Path,
        now_fn: Callable[[], int] | None = None,
        policy_profile: str = policy_mod.PROFILE_CONSERVATIVE,
        shadow_mode: bool = False,
        canary_enabled: bool = True,
        responder_lock_l0: bool = False,
        patrol_record_only: bool = False,
    ) -> None:
        self._authority = LeaseAuthority(
            mac_key=mac_key,
            now_fn=now_fn or (lambda: int(time.time() * 1000)),
            ledger_path=ledger_path,
        )
        self._store = store
        self._receipts = ReceiptSigner(key_dir)
        self._policy_profile = policy_profile
        self._shadow_mode = shadow_mode
        self._gateway_lease_ids: set[str] = set()
        self.policy_version = POLICY_VERSION
        self.canaries = CanaryVault(store, enabled=canary_enabled)
        self.responder = Responder(
            store,
            lock_l0=responder_lock_l0,
            freeze_fn=self.freeze_all_for_session,
        )
        self.patrol = PatrolBoard(record_only=patrol_record_only)

    # -- helpers -------------------------------------------------------------
    def _now(self) -> int:
        return int(self._authority._now())

    def _evaluate_policy(
        self,
        *,
        tool_name: str,
        context_taint: int,
        arg_taint_bits: int,
        args_overlap_dirty: bool,
        clearance: int,
        channel: str = "",
        lease_id: str = "",
    ) -> policy_mod.PolicyDecision:
        """Evaluate the policy table; shadow mode records but never blocks."""

        profile = self._policy_profile
        if channel.startswith("gateway:") or lease_id in self._gateway_lease_ids:
            profile = policy_mod.PROFILE_CONSERVATIVE
        decision = policy_mod.evaluate(
            tool_name=tool_name,
            context_taint=context_taint,
            arg_taint_bits=arg_taint_bits,
            args_overlap_dirty=args_overlap_dirty,
            clearance=clearance,
            profile=profile,
        )
        if self._shadow_mode and decision.verdict != policy_mod.VERDICT_ALLOW:
            return policy_mod.PolicyDecision(
                verdict=policy_mod.VERDICT_ALLOW,
                reason=f"shadow: {decision.verdict} ({decision.reason})",
                matched_row=decision.matched_row,
            )
        return decision

    @staticmethod
    def _policy_error(decision: policy_mod.PolicyDecision) -> dict[str, Any] | None:
        """Map a non-allow policy decision to an error-ack payload."""

        if decision.verdict == policy_mod.VERDICT_ALLOW:
            return None
        if decision.verdict == policy_mod.VERDICT_DENY:
            code = "policy_deny"
        elif decision.verdict == policy_mod.VERDICT_EXPORT_GATE:
            code = "export_gate"
        else:
            code = "approval_required"
        return {"ok": False, "code": code, "reason": decision.reason}

    def _sign_receipt(
        self,
        *,
        kind: str,
        verdict: str,
        lease_id: str,
    ) -> DecisionReceipt:
        receipt = self._receipts.sign(
            kind=kind,
            verdict=verdict,
            lease_id=lease_id,
            policy_version=self.policy_version,
            created_at=self._now(),
            receipt_id=secrets.token_hex(16),
        )
        self._store.record_receipt(receipt.to_dict())
        return receipt

    @staticmethod
    def _error_payload(exc: Exception) -> dict[str, Any]:
        if isinstance(exc, LeaseDenied):
            code = EXC_TO_CODE.get(type(exc), "denied")
        elif isinstance(exc, (ValueError, TypeError)):
            code = "bad_message"
        else:
            code = "internal"
        return {"ok": False, "code": code, "reason": f"{type(exc).__name__}"}

    # -- issue ---------------------------------------------------------------
    def handle_issue(
        self,
        lease_params: dict[str, Any],
        context_fields: dict[str, Any] | None,
        *,
        context_taint: int = 0,
        arg_taint: int = 0,
        clearance: int = 1,
        channel: str = "",
    ) -> dict[str, Any]:
        tool_name = str(lease_params.get("tool_name", ""))
        args_overlap = bool(arg_taint)
        decision = self._evaluate_policy(
            tool_name=tool_name,
            context_taint=context_taint,
            arg_taint_bits=arg_taint,
            args_overlap_dirty=args_overlap,
            clearance=clearance,
            channel=channel,
        )
        policy_error = self._policy_error(decision)
        if policy_error is not None:
            self._sign_receipt(kind="issue", verdict=decision.verdict, lease_id="")
            return policy_error
        try:
            lease = self._issue_from_params(
                lease_params,
                taint_sink=policy_mod.sinks_for_tool(tool_name),
                clearance=clearance,
            )
            if channel.startswith("gateway:"):
                self._gateway_lease_ids.add(lease.lease_id)
            signature = ""
            if context_fields is not None:
                signature = self._sign_context(lease, context_fields)
            receipt = self._sign_receipt(kind="issue", verdict="allow", lease_id=lease.lease_id)
            return {
                "ok": True,
                "lease": _lease_to_payload(lease),
                "context_signature": signature,
                "receipt_id": receipt.receipt_id,
            }
        except Exception as exc:  # noqa: BLE001 - mapped to error acks
            return self._error_payload(exc)

    def _issue_from_params(
        self,
        params: dict[str, Any],
        *,
        taint_sink: int = 0,
        clearance: int = 1,
    ) -> CapabilityLease:
        return self._authority.issue(
            owner_key_hash=str(params["owner_key_hash"]),
            run_id=str(params["run_id"]),
            tool_name=str(params["tool_name"]),
            args_schema=str(params["args_schema"]),
            resource_scope=str(params["resource_scope"]),
            max_bytes=int(params["max_bytes"]),
            max_duration_ms=int(params["max_duration_ms"]),
            ttl_ms=int(params["ttl_ms"]),
            fs_roots=tuple(str(item) for item in params.get("fs_roots", ())),
            network_policy=str(params.get("network_policy", "deny")),
            max_invocations=int(params.get("max_invocations", 1)),
            parent_lease_id=(
                str(params["parent_lease_id"])
                if params.get("parent_lease_id") is not None
                else None
            ),
            product_id=str(params.get("product_id", "")),
            session_id=str(params.get("session_id", "")),
            network_hosts=tuple(str(item) for item in params.get("network_hosts", ())),
            taint_sink=int(taint_sink),
            clearance=int(clearance),
        )

    def _sign_context(
        self,
        lease: CapabilityLease,
        context_fields: dict[str, Any],
    ) -> str:
        context = EchoContextPayload(
            product_id=lease.product_id,
            owner_key_hash=lease.owner_key_hash,
            session_id=lease.session_id,
            run_id=lease.run_id,
            profile=str(context_fields.get("profile", "")),
            tool_name=lease.tool_name,
            args_hash=lease.args_schema,
            resource_scope=lease.resource_scope,
            fs_roots=tuple(lease.fs_roots),
            network_policy=lease.network_policy,
            network_hosts=tuple(lease.network_hosts),
            max_bytes=lease.max_bytes,
            max_duration_ms=lease.max_duration_ms,
        )
        signed = sign_tool_execution_context(
            context,
            lease=lease,
            authority=self._authority,
            now=self._now(),
        )
        return str(getattr(signed, "signature", ""))

    # -- consume ---------------------------------------------------------------
    def authorize_cell(
        self,
        payload: dict[str, Any],
        *,
        context_taint: int = 0,
        arg_taint: int = 0,
        clearance: int = 1,
        channel: str = "",
    ) -> dict[str, Any]:
        """Deterministic policy gate for a cell-dispatched effect (WP7).

        No lease consumption happens here: the execution-context verifier
        already spent the lease before the tool handler ran. This is the
        policy table plus a signed decision receipt — nothing else.
        """

        tool_name = str(payload.get("tool", "") or payload.get("effect_type") or "")
        decision = self._evaluate_policy(
            tool_name=tool_name,
            context_taint=context_taint,
            arg_taint_bits=arg_taint,
            args_overlap_dirty=bool(arg_taint),
            clearance=clearance,
            channel=channel,
        )
        policy_error = self._policy_error(decision)
        if policy_error is not None:
            self._sign_receipt(kind="cell", verdict=decision.verdict, lease_id="")
            return policy_error
        receipt = self._sign_receipt(kind="cell", verdict="allow", lease_id="")
        return {
            "ok": True,
            "verdict": "allow",
            "receipt_id": receipt.receipt_id,
            "policy_version": self.policy_version,
        }

    def handle_consume(
        self,
        mode: str,
        lease_payload: dict[str, Any] | None,
        context_payload: dict[str, Any] | None,
        expected: dict[str, Any] | None,
        *,
        context_taint: int = 0,
        arg_taint: int = 0,
        clearance: int = 1,
        scan_text: str = "",
        scan_surface: str = "",
        session_id: str = "",
        channel: str = "",
    ) -> dict[str, Any]:
        if mode == "scan":
            return self._handle_scan(
                scan_text=scan_text,
                scan_surface=scan_surface or "net",
                session_id=session_id,
            )
        tool_name = ""
        lease_id = ""
        if lease_payload is not None:
            tool_name = str(lease_payload.get("tool_name", ""))
            lease_id = str(lease_payload.get("lease_id", ""))
        elif context_payload is not None:
            tool_name = str(context_payload.get("tool_name", ""))
            lease_id = str(context_payload.get("lease_id", ""))
        decision = self._evaluate_policy(
            tool_name=tool_name,
            context_taint=context_taint,
            arg_taint_bits=arg_taint,
            args_overlap_dirty=bool(arg_taint),
            clearance=clearance,
            channel=channel,
            lease_id=lease_id,
        )
        policy_error = self._policy_error(decision)
        if policy_error is not None:
            self._sign_receipt(kind="consume", verdict=decision.verdict, lease_id=lease_id)
            return policy_error
        try:
            if mode == "verify":
                result = self._consume_verify(lease_payload, expected)
            elif mode == "preflight":
                result = self._consume_bound(lease_payload, expected, consume=False)
            elif mode == "consume":
                if expected is None:
                    result = self._consume_plain(lease_payload)
                else:
                    result = self._consume_bound(lease_payload, expected, consume=True)
            elif mode == "context":
                result = self._consume_context(context_payload)
            else:
                result = {"ok": False, "code": "bad_message", "reason": "unknown mode"}
            if result.get("ok") and lease_id and mode in {"consume", "context"}:
                self._gateway_lease_ids.discard(lease_id)
            return result
        except Exception as exc:  # noqa: BLE001 - mapped to error acks
            return self._error_payload(exc)

    def _consume_plain(
        self,
        lease_payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        assert lease_payload is not None
        lease = _lease_from_payload(lease_payload)
        self._authority.consume(lease, now=self._now())
        receipt = self._sign_receipt(kind="consume", verdict="allow", lease_id=lease.lease_id)
        return {
            "ok": True,
            "verdict": "allow",
            "receipt_id": receipt.receipt_id,
            "policy_version": self.policy_version,
        }

    def _consume_verify(
        self,
        lease_payload: dict[str, Any] | None,
        expected: dict[str, Any] | None,
    ) -> dict[str, Any]:
        assert lease_payload is not None and expected is not None
        lease = _lease_from_payload(lease_payload)
        self._authority.verify(
            lease,
            expected_owner=str(expected["owner"]),
            expected_tool=str(expected["tool"]),
            expected_scope=str(expected["scope"]),
            now=self._now(),
        )
        receipt = self._sign_receipt(kind="consume", verdict="allow", lease_id=lease.lease_id)
        return {
            "ok": True,
            "verdict": "allow",
            "receipt_id": receipt.receipt_id,
            "policy_version": self.policy_version,
        }

    def _consume_bound(
        self,
        lease_payload: dict[str, Any] | None,
        expected: dict[str, Any] | None,
        *,
        consume: bool,
    ) -> dict[str, Any]:
        assert lease_payload is not None and expected is not None
        lease = _lease_from_payload(lease_payload)
        kwargs: dict[str, Any] = {
            "expected_product_id": str(expected["product_id"]),
            "expected_owner": str(expected["owner_key_hash"]),
            "expected_session": str(expected["session_id"]),
            "expected_run": str(expected["run_id"]),
            "expected_tool": str(expected["tool_name"]),
            "expected_args_schema": str(expected["args_schema"]),
            "expected_resource_scope": str(expected["resource_scope"]),
            "expected_fs_roots": tuple(str(i) for i in expected.get("fs_roots", ())),
            "expected_network_policy": str(expected["network_policy"]),
            "expected_network_hosts": tuple(str(i) for i in expected.get("network_hosts", ())),
            "expected_max_bytes": int(expected["max_bytes"]),
            "expected_max_duration_ms": int(expected["max_duration_ms"]),
            "now": self._now(),
            "require_single_use": bool(expected.get("require_single_use", True)),
        }
        if not consume:
            self._authority.verify_bound(lease, **kwargs)
            receipt = self._sign_receipt(kind="consume", verdict="allow", lease_id=lease.lease_id)
            return {
                "ok": True,
                "verdict": "allow",
                "receipt_id": receipt.receipt_id,
                "policy_version": self.policy_version,
            }
        ledger_receipt = self._authority.consume_bound(lease, **kwargs)
        receipt = self._sign_receipt(kind="consume", verdict="allow", lease_id=lease.lease_id)
        return {
            "ok": True,
            "verdict": "allow",
            "receipt": {
                "lease_id": ledger_receipt.lease_id,
                "nonce": ledger_receipt.nonce,
                "consumed_at": ledger_receipt.consumed_at,
                "ledger_seq": ledger_receipt.ledger_seq,
                "ledger_record_hash": ledger_receipt.ledger_record_hash,
            },
            "receipt_id": receipt.receipt_id,
            "policy_version": self.policy_version,
        }

    def _consume_context(self, context_payload: dict[str, Any] | None) -> dict[str, Any]:
        assert context_payload is not None
        context = EchoContextPayload(
            product_id=str(context_payload.get("product_id", "")),
            owner_key_hash=str(context_payload.get("owner_key_hash", "")),
            session_id=str(context_payload.get("session_id", "")),
            run_id=str(context_payload.get("run_id", "")),
            profile=str(context_payload.get("profile", "")),
            tool_name=str(context_payload.get("tool_name", "")),
            args_hash=str(context_payload.get("args_hash", "")),
            resource_scope=str(context_payload.get("resource_scope", "")),
            fs_roots=tuple(str(i) for i in context_payload.get("fs_roots", ())),
            network_policy=str(context_payload.get("network_policy", "deny")),
            network_hosts=tuple(str(i) for i in context_payload.get("network_hosts", ())),
            max_bytes=int(context_payload.get("max_bytes", 0)),
            max_duration_ms=int(context_payload.get("max_duration_ms", 0)),
            lease_id=str(context_payload.get("lease_id", "")),
            lease_mac=str(context_payload.get("lease_mac", "")),
            signature=str(context_payload.get("signature", "")),
        )
        self._authority.consume_execution_context(context, now=self._now())
        receipt = self._sign_receipt(kind="consume", verdict="allow", lease_id=context.lease_id)
        return {
            "ok": True,
            "verdict": "allow",
            "receipt_id": receipt.receipt_id,
            "policy_version": self.policy_version,
        }

    # -- revoke / queries ------------------------------------------------------
    def handle_revoke(
        self,
        op: str,
        lease_id: str | None,
        owner_key_hash: str | None,
        session_id: str | None,
    ) -> dict[str, Any]:
        try:
            if op == "lease":
                assert lease_id is not None
                self._authority.revoke(lease_id)
                receipt = self._sign_receipt(kind="revoke", verdict="allow", lease_id=lease_id)
                return {"ok": True, "revoked": [lease_id], "receipt_id": receipt.receipt_id}
            if op == "session":
                assert owner_key_hash is not None and session_id is not None
                revoked = self._authority.revoke_for_session(
                    owner_key_hash=owner_key_hash,
                    session_id=session_id,
                )
                receipt = self._sign_receipt(
                    kind="revoke", verdict="allow", lease_id="session:" + session_id
                )
                return {"ok": True, "revoked": list(revoked), "receipt_id": receipt.receipt_id}
            if op == "active_sessions":
                assert owner_key_hash is not None
                sessions = self._authority.active_session_ids_for_owner(
                    owner_key_hash=owner_key_hash,
                )
                return {"ok": True, "sessions": list(sessions)}
            if op == "is_revoked":
                assert lease_id is not None
                return {"ok": True, "is_revoked": self._authority.is_revoked(lease_id)}
            return {"ok": False, "code": "bad_message", "reason": "unknown op"}
        except Exception as exc:  # noqa: BLE001 - mapped to error acks
            return self._error_payload(exc)

    def _handle_scan(
        self,
        *,
        scan_text: str,
        scan_surface: str,
        session_id: str,
    ) -> dict[str, Any]:
        if not self.canaries.enabled:
            return {"ok": True, "verdict": "allow"}
        self.canaries.ensure_session(session_id, now_ms=self._now())
        now = self._now()
        if scan_surface == "read":
            hit = self.canaries.record_read(session_id=session_id, text=scan_text, now_ms=now)
            if hit is None:
                return {"ok": True, "verdict": "allow"}
            self.responder.escalate(
                session_id=session_id,
                level=LEVEL_NARROW,
                now_ms=now,
                evidence="read",
            )
            return {"ok": True, "verdict": "allow"}
        hit = self.canaries.record_egress(
            session_id=session_id,
            text=scan_text,
            surface=scan_surface,
            now_ms=now,
        )
        if hit is None:
            return {"ok": True, "verdict": "allow"}
        if hit.dual_evidence:
            self.responder.escalate(
                session_id=session_id,
                level=LEVEL_FREEZE,
                now_ms=now,
                evidence="dual",
            )
            if self.responder.lock_l0:
                return {"ok": True, "verdict": "allow"}
            return {
                "ok": False,
                "code": "frozen",
                "reason": FREEZE_TEXT,
                "verdict": "freeze",
            }
        self.responder.escalate(
            session_id=session_id,
            level=LEVEL_NARROW,
            now_ms=now,
            evidence="single",
        )
        if self.responder.lock_l0:
            return {"ok": True, "verdict": "allow"}
        return {
            "ok": False,
            "code": "policy_deny",
            "reason": REFUSAL_TEXT,
            "verdict": "deny",
        }

    def authorize_egress_text(self, text: str, *, surface: str = "connector") -> dict[str, Any]:
        """Final authoritative honeytoken check before an external side effect.

        EffectDraft intentionally carries no caller-controlled session id.
        The vault therefore matches across its protected registry and uses the
        owning session from the matched row for responder escalation.
        """

        hit = self.canaries.record_egress_any(text=text, surface=surface)
        if hit is None:
            return {"ok": True, "verdict": "allow"}
        now = self._now()
        level = LEVEL_FREEZE if hit.dual_evidence else LEVEL_NARROW
        self.responder.escalate(
            session_id=hit.session_id,
            level=level,
            now_ms=now,
            evidence="dual" if hit.dual_evidence else "single",
        )
        if self.responder.lock_l0:
            return {"ok": True, "verdict": "allow"}
        return {
            "ok": False,
            "code": "frozen" if hit.dual_evidence else "policy_deny",
            "reason": FREEZE_TEXT if hit.dual_evidence else REFUSAL_TEXT,
            "verdict": "freeze" if hit.dual_evidence else "deny",
        }

    def freeze_all_for_session(self, session_id: str) -> tuple[str, ...]:
        """Revoke every lease bound to a session (Responder L3 hook)."""

        revoked: list[str] = []
        for lease_id in self._authority.known_lease_ids():
            stored = self._authority._issued.get(lease_id)
            if stored is not None and stored.session_id == session_id:
                revoked.append(lease_id)
        for lease_id in revoked:
            self._authority.revoke(lease_id)
        return tuple(revoked)

    def authority(self) -> LeaseAuthority:
        """Direct access for in-process testing (never used over IPC)."""

        return self._authority


def context_payload_to_dict(context: EchoContextPayload) -> dict[str, Any]:
    """Serialize a context payload for the wire."""

    return {
        "product_id": context.product_id,
        "owner_key_hash": context.owner_key_hash,
        "session_id": context.session_id,
        "run_id": context.run_id,
        "profile": context.profile,
        "tool_name": context.tool_name,
        "args_hash": context.args_hash,
        "resource_scope": context.resource_scope,
        "fs_roots": list(context.fs_roots),
        "network_policy": context.network_policy,
        "network_hosts": list(context.network_hosts),
        "max_bytes": context.max_bytes,
        "max_duration_ms": context.max_duration_ms,
        "lease_id": context.lease_id,
        "lease_mac": context.lease_mac,
        "signature": context.signature,
    }


def replace_signature(context: EchoContextPayload, signature: str) -> EchoContextPayload:
    return replace(context, signature=signature)


__all__ = [
    "EXC_TO_CODE",
    "EchoContextPayload",
    "GateKeeper",
    "POLICY_VERSION",
    "context_payload_to_dict",
    "replace_signature",
]
