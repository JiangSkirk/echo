"""Intent registry (WP4 types / WP5 wiring): verify-then-store owner intents.

An IntentEnvelope is accepted only when

1. its Ed25519 signature verifies against a *registered witness public key*
   (keys Echo does not hold — they arrive via AppShell provisioning, WP5),
2. it is currently within its validity window, and
3. replacing permissions for the same task only ever tightens: the effective
   grant of a task is the INTERSECTION of all live intents (M decision I-08;
   expansions require a fresh task).

The store deliberately keeps no lease state: JSONL stays the only ledger.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from js.orin.draft import exact_commit_approval_from_dict, export_pass_from_dict
from js.orin.intent import (
    Budgets,
    IntentEnvelope,
    intent_from_dict,
    session_tightening_ok,
)
from js.orind.store import OrinStore


class IntentStore:
    """Verify-and-register facade over the WAL ``intents`` table."""

    def __init__(self, *, store: OrinStore, trusted_public_keys: tuple[str, ...] = ()) -> None:
        self._store = store
        self._trusted_keys: set[str] = set(trusted_public_keys)

    # -- witness key management (AppShell provisioning lands in WP5) ---------
    def register_witness_key(self, public_key_b64: str) -> None:
        if not public_key_b64 or len(public_key_b64) > 176:
            raise ValueError("witness public key must be a bounded base64 string")
        self._trusted_keys.add(public_key_b64)

    def trusted_public_keys(self) -> frozenset[str]:
        return frozenset(self._trusted_keys) | frozenset(self._store.witness_public_keys())

    # -- registration ----------------------------------------------------------
    def register(self, data: dict[str, Any], *, now_ms: int) -> dict[str, Any]:
        """Validate + verify + persist. Returns an ack payload fragment.

        Never raises on policy failures — returns ``{"ok": False, ...}``
        shaped fragments so the daemon can answer uniformly.
        """

        try:
            envelope = intent_from_dict(data)
        except Exception as exc:  # ProtocolError from strict parsing
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        if not envelope.signature:
            return {"ok": False, "code": "unknown_intent", "reason": "intent is unsigned"}
        candidates = self.trusted_public_keys()
        verified = any(envelope.verify(key) for key in candidates if key)
        if not verified:
            # Echo cannot forge this: no Echo-held key is ever registered.
            return {"ok": False, "code": "unknown_intent", "reason": "signature not trusted"}
        if now_ms >= envelope.expires_at_ms:
            return {"ok": False, "code": "expired", "reason": "intent already expired"}
        effective = self._effective_grant(envelope.task_id, now_ms=now_ms)
        if effective is not None:
            same_subject = (
                envelope.owner_key_hash == effective.owner_key_hash
                and envelope.product_id == effective.product_id
                and envelope.profile == effective.profile
            )
            if not same_subject:
                return {
                    "ok": False,
                    "code": "denied",
                    "reason": "task owner/product/profile binding is immutable",
                }
            if not session_tightening_ok(envelope, effective):
                return {
                    "ok": False,
                    "code": "denied",
                    "reason": "session permissions may only tighten",
                }
        pub = _matching_key(envelope, candidates) or ""
        status = self._store.record_intent(
            intent_id=envelope.intent_id,
            payload=envelope.to_dict(),
            public_key=pub,
        )
        if status in {"conflict", "revoked"}:
            return {
                "ok": False,
                "code": "denied",
                "reason": "intent id is immutable and cannot be replayed",
            }
        if status == "task_key_conflict":
            return {
                "ok": False,
                "code": "denied",
                "reason": "task owner witness key is immutable",
            }
        return {"ok": True, "intent": envelope.to_dict()}

    def _effective_grant(self, task_id: str, *, now_ms: int) -> IntentEnvelope | None:
        """Intersection of all live intents for the task (monotonic shrink)."""

        rows = self._store.active_intents_for_task(task_id)
        envelopes: list[IntentEnvelope] = []
        for raw in rows:
            try:
                candidate = intent_from_dict(raw)
            except Exception:  # corrupted row → fail closed by ignoring it
                continue
            if now_ms < candidate.expires_at_ms:
                envelopes.append(candidate)
        if not envelopes:
            return None
        effective = envelopes[0]
        for other in envelopes[1:]:
            classes = tuple(
                set(effective.allowed_effect_classes) & set(other.allowed_effect_classes)
            )
            resources = tuple(
                sorted(
                    set(effective.allowed_resource_handles) & set(other.allowed_resource_handles)
                )
            )
            sinks = tuple(
                sorted(set(effective.allowed_sink_handles) & set(other.allowed_sink_handles))
            )
            budgets = Budgets(
                max_invocations=min(
                    effective.budgets.max_invocations, other.budgets.max_invocations
                ),
                max_bytes_read=min(effective.budgets.max_bytes_read, other.budgets.max_bytes_read),
                max_bytes_out=min(effective.budgets.max_bytes_out, other.budgets.max_bytes_out),
                max_cost_minor_units=min(
                    effective.budgets.max_cost_minor_units,
                    other.budgets.max_cost_minor_units,
                ),
            )
            stricter = (
                "dual_control"
                if "dual_control" in (effective.approval_policy, other.approval_policy)
                else (
                    "exact_commit_required"
                    if "exact_commit_required" in (effective.approval_policy, other.approval_policy)
                    else other.approval_policy
                )
            )
            effective = replace(
                effective,
                allowed_effect_classes=classes,
                allowed_resource_handles=resources,
                allowed_sink_handles=sinks,
                budgets=budgets,
                approval_policy=stricter,
            )
        return effective

    def active_envelope(self, task_id: str, *, now_ms: int) -> IntentEnvelope | None:
        """Most recent live intent — informational view; enforcement uses
        :meth:`_effective_grant` semantics via register-time checks."""

        raw_rows = self._store.active_intents_for_task(task_id)
        if not raw_rows:
            return None
        try:
            envelope = intent_from_dict(raw_rows[0])
        except Exception:  # corrupted row → fail closed
            return None
        if now_ms >= envelope.expires_at_ms:
            return None
        return envelope

    def effective_grant(self, task_id: str, *, now_ms: int) -> IntentEnvelope | None:
        """Return the monotonic intersection used for authority decisions."""

        return self._effective_grant(task_id, now_ms=now_ms)

    def revoke(self, intent_id: str) -> bool:
        return self._store.revoke_intent(intent_id)

    # -- two-phase egress (K§7.9 / WP8) ---------------------------------------
    def grant_export(
        self,
        data: dict[str, Any],
        *,
        now_ms: int,
        expected_binding: dict[str, Any] | None = None,
        profile: str = "",
        standing: bool = False,
    ) -> dict[str, Any]:
        """Verify and register an ExportPass for one current exact binding.

        ``expected_binding`` is loaded by orind from its immutable draft and
        current-witness rows.  Omitting it fails closed: a correctly signed
        but stale pass is not enough to select an operation by itself.
        """

        try:
            export_pass = export_pass_from_dict(data)
        except Exception as exc:
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        if not export_pass.signature:
            return {"ok": False, "code": "unknown_intent", "reason": "export pass is unsigned"}
        candidates = self.trusted_public_keys()
        if not any(export_pass.verify(key) for key in candidates if key):
            return {"ok": False, "code": "unknown_intent", "reason": "signature not trusted"}
        if not export_pass.created_at_ms <= now_ms < export_pass.expires_at_ms:
            return {"ok": False, "code": "expired", "reason": "export pass expired"}
        if expected_binding is None:
            return {
                "ok": False,
                "code": "denied",
                "reason": "current draft/witness binding required",
            }
        try:
            expected = _normalize_export_binding(expected_binding)
            destinations = _canonical_destinations(export_pass.destination_handles)
        except ValueError as exc:
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        actual = {
            "task_id": export_pass.task_id,
            "payload_hash": export_pass.payload_hash,
            "destination_handles": destinations,
            "witness_id": export_pass.witness_id,
        }
        if actual != expected:
            return {
                "ok": False,
                "code": "denied",
                "reason": "export pass does not exactly match current binding",
            }
        active = self._effective_grant(export_pass.task_id, now_ms=now_ms)
        if active is None:
            return {"ok": False, "code": "unknown_intent", "reason": "no active owner intent"}
        effective_profile = profile or active.profile
        if effective_profile != active.profile or effective_profile not in {"personal", "work"}:
            return {"ok": False, "code": "denied", "reason": "profile binding mismatch"}
        if standing and effective_profile != "work":
            return {"ok": False, "code": "denied", "reason": "Personal pass cannot stand"}
        effective_standing = effective_profile == "work"
        standing_sinks = set(active.allowed_sink_handles)
        if effective_standing and (
            "*" in standing_sinks or not set(destinations) <= standing_sinks
        ):
            return {
                "ok": False,
                "code": "denied",
                "reason": "Work export pass requires exact pre-registered sinks",
            }
        payload = export_pass.to_dict()
        status = self._store.record_export_pass(
            pass_id=export_pass.pass_id,
            payload=payload,
            profile=effective_profile,
            standing=effective_standing,
            public_key=_matching_key(export_pass, candidates) or "",
        )
        if status == "conflict":
            return {
                "ok": False,
                "code": "denied",
                "reason": "export pass id already binds different bytes",
            }
        if not self._store.active_exact_export_passes(
            export_pass.task_id,
            export_pass.payload_hash,
            destinations,
            export_pass.witness_id,
            now_ms=now_ms,
        ):
            return {
                "ok": False,
                "code": "denied",
                "reason": "export pass was already consumed or revoked",
            }
        return {
            "ok": True,
            "pass_id": export_pass.pass_id,
            "standing": effective_standing,
            "replayed": status == "idempotent",
        }

    def export_passes_for_task(self, task_id: str) -> list[dict[str, Any]]:
        return self._store.active_export_passes(task_id)

    def active_exact_export_passes(
        self,
        *,
        task_id: str,
        payload_hash: str,
        destination_handles: tuple[str, ...] | list[str],
        witness_id: str,
        now_ms: int,
    ) -> list[dict[str, Any]]:
        return self._store.active_exact_export_passes(
            task_id,
            payload_hash,
            destination_handles,
            witness_id,
            now_ms=now_ms,
        )

    def claim_personal_export_pass(
        self,
        *,
        pass_id: str,
        task_id: str,
        payload_hash: str,
        destination_handles: tuple[str, ...] | list[str],
        witness_id: str,
        now_ms: int,
    ) -> bool:
        return self._store.claim_personal_export_pass(
            pass_id,
            task_id,
            payload_hash,
            destination_handles,
            witness_id,
            now_ms=now_ms,
        )

    # -- Personal exact file-commit approval ---------------------------------
    def grant_exact(
        self,
        data: dict[str, Any],
        *,
        now_ms: int,
        expected_binding: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Verify and register one owner-signed exact Personal file approval."""

        try:
            approval = exact_commit_approval_from_dict(data)
        except Exception as exc:
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        if not approval.signature:
            return {"ok": False, "code": "unknown_intent", "reason": "approval is unsigned"}
        if not approval.created_at_ms <= now_ms < approval.expires_at_ms:
            return {"ok": False, "code": "expired", "reason": "exact approval expired"}
        if expected_binding is None:
            return {
                "ok": False,
                "code": "denied",
                "reason": "current draft/witness binding required",
            }
        try:
            expected = _normalize_exact_commit_binding(expected_binding)
        except ValueError as exc:
            return {"ok": False, "code": "bad_message", "reason": str(exc)}
        actual = {
            "task_id": approval.task_id,
            "draft_id": approval.draft_id,
            "witness_id": approval.witness_id,
            "canonical_effect_hash": approval.canonical_effect_hash,
            "directory_handle_id": approval.directory_handle_id,
        }
        if actual != expected:
            return {
                "ok": False,
                "code": "denied",
                "reason": "exact approval does not match current file binding",
            }
        effective = self.effective_grant(approval.task_id, now_ms=now_ms)
        signer = self.active_envelope(approval.task_id, now_ms=now_ms)
        if effective is None or signer is None:
            return {"ok": False, "code": "unknown_intent", "reason": "no active owner intent"}
        if (
            effective.profile != "personal"
            or effective.approval_policy != "exact_commit_required"
            or "file.commit" not in effective.allowed_effect_classes
            or approval.directory_handle_id not in effective.allowed_resource_handles
        ):
            return {
                "ok": False,
                "code": "denied",
                "reason": "exact approval is limited to Personal file.commit",
            }
        public_key = self._store.intent_public_key(signer.intent_id)
        task_keys = self._store.intent_public_keys_for_task(approval.task_id)
        if (
            not public_key
            or task_keys != (public_key,)
            or not approval.verify(public_key)
        ):
            return {
                "ok": False,
                "code": "unknown_intent",
                "reason": "approval signature is not the active intent witness",
            }
        status = self._store.record_exact_commit_approval(
            approval_id=approval.approval_id,
            payload=approval.to_dict(),
            public_key=public_key,
        )
        if status == "conflict":
            return {
                "ok": False,
                "code": "denied",
                "reason": "exact approval id already binds different bytes",
            }
        if not self._store.active_exact_commit_approvals(
            task_id=approval.task_id,
            draft_id=approval.draft_id,
            witness_id=approval.witness_id,
            canonical_effect_hash=approval.canonical_effect_hash,
            directory_handle_id=approval.directory_handle_id,
            now_ms=now_ms,
            approval_id=approval.approval_id,
        ):
            return {
                "ok": False,
                "code": "denied",
                "reason": "exact approval was already consumed",
            }
        return {
            "ok": True,
            "approval_id": approval.approval_id,
            "replayed": status == "idempotent",
        }

    def exact_commit_approvals_for_task(self, task_id: str) -> list[dict[str, Any]]:
        return self._store.exact_commit_approvals_for_task(task_id)

    def active_exact_commit_approvals(
        self,
        *,
        task_id: str,
        draft_id: str,
        witness_id: str,
        canonical_effect_hash: str,
        directory_handle_id: str,
        now_ms: int,
        approval_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._store.active_exact_commit_approvals(
            task_id=task_id,
            draft_id=draft_id,
            witness_id=witness_id,
            canonical_effect_hash=canonical_effect_hash,
            directory_handle_id=directory_handle_id,
            now_ms=now_ms,
            approval_id=approval_id,
        )

    def claim_personal_exact_commit_approval(
        self,
        *,
        approval_id: str,
        task_id: str,
        draft_id: str,
        witness_id: str,
        canonical_effect_hash: str,
        directory_handle_id: str,
        now_ms: int,
    ) -> bool:
        return self._store.claim_personal_exact_commit_approval(
            approval_id=approval_id,
            task_id=task_id,
            draft_id=draft_id,
            witness_id=witness_id,
            canonical_effect_hash=canonical_effect_hash,
            directory_handle_id=directory_handle_id,
            now_ms=now_ms,
        )


def _matching_key(envelope: Any, keys: frozenset[str]) -> str | None:
    for key in keys:
        if key and envelope.verify(key):
            return key
    return None


def _canonical_destinations(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)) or not 1 <= len(values) <= 32:
        raise ValueError("destination handles must contain 1..32 items")
    items = tuple(values)
    if any(not isinstance(item, str) or not item or len(item) > 512 for item in items):
        raise ValueError("destination handles must be bounded strings")
    if len(set(items)) != len(items):
        raise ValueError("duplicate destination handles are forbidden")
    return tuple(sorted(items))


def _normalize_export_binding(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("expected export binding must be an object")
    allowed = {"task_id", "payload_hash", "destination_handles", "witness_id"}
    if set(data) != allowed:
        raise ValueError("expected export binding requires exactly task/hash/destinations/witness")
    task_id = data.get("task_id")
    digest = data.get("payload_hash")
    witness_id = data.get("witness_id")
    if not isinstance(task_id, str) or not task_id.startswith("task:"):
        raise ValueError("expected export task_id is malformed")
    if not isinstance(digest, str) or len(digest) != 71 or not digest.startswith("sha256:"):
        raise ValueError("expected export payload_hash is malformed")
    if not isinstance(witness_id, str) or not witness_id.startswith("state:"):
        raise ValueError("expected export witness_id is malformed")
    return {
        "task_id": task_id,
        "payload_hash": digest,
        "destination_handles": _canonical_destinations(data.get("destination_handles")),
        "witness_id": witness_id,
    }


def _normalize_exact_commit_binding(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("expected exact commit binding must be an object")
    allowed = {
        "task_id",
        "draft_id",
        "witness_id",
        "canonical_effect_hash",
        "directory_handle_id",
    }
    if set(data) != allowed:
        raise ValueError("expected exact binding requires task/draft/witness/hash/directory")
    prefixes = {
        "task_id": "task:",
        "draft_id": "draft:",
        "witness_id": "state:",
        "directory_handle_id": "dirh:",
    }
    normalized: dict[str, Any] = {}
    for name, prefix in prefixes.items():
        value = data.get(name)
        if not isinstance(value, str) or not value.startswith(prefix) or len(value) > 512:
            raise ValueError(f"expected exact {name} is malformed")
        normalized[name] = value
    digest = data.get("canonical_effect_hash")
    if (
        not isinstance(digest, str)
        or len(digest) != 71
        or not digest.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in digest[7:])
    ):
        raise ValueError("expected exact canonical_effect_hash is malformed")
    normalized["canonical_effect_hash"] = digest
    return normalized


__all__ = ["IntentStore"]
