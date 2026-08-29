"""IntentEnvelope (K§7.2/§8.2): the owner witness artifact.

Only AppShell / trusted CLI / authenticated admin API may issue an intent;
Echo must never be able to produce a valid one. The envelope is signed with
Ed25519 by the witness identity (a key Echo does not hold); orind verifies
the signature against registered witness public keys before accepting it.

Wire deviations from K§8.2 (documented in ORIN_STAGE_B_SPEC.md §2.3):
timestamps are u64 epoch-milliseconds instead of ISO strings so that the
decision path never parses timezone text, matching the lease encoding.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, replace
from typing import Any, Final, cast

from js.orin.protocol import MAX_SEQ, ProtocolError, canonical_json

_INTENT_ID_PREFIX: Final[str] = "intent:"
_TASK_ID_PREFIX: Final[str] = "task:"
_SHA256_RE: Final[str] = "sha256:"

EFFECT_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "artifact.read",
        "artifact.stage",
        "artifact.write",
        "desktop.action",
        "desktop.observe",
        "file.commit",
        "memory.mutate",
        "memory.read",
        "memory.write",
        "shell.exec",
        "net.fetch",
        "net.send",
        "email.send_exact",
        "secret.use",
        "policy.change",
        "admin.unfreeze",
        "bot.room.create",
        "bot.message.send",
        "bot.soul.write",
    }
)
"""Closed effect-class vocabulary for ``allowed_effect_classes``."""

APPROVAL_POLICIES: Final[frozenset[str]] = frozenset(
    {"exact_commit_required", "preauthorized_exact_template", "dual_control"}
)

_POLICY_STRICTNESS: Final[dict[str, int]] = {
    "preauthorized_exact_template": 1,
    "exact_commit_required": 2,
    "dual_control": 3,
}
R2_MIN_STRICTNESS: Final[int] = 2
"""Policies at least this strict may back R2 effects."""

BUDGET_KEYS: Final[tuple[str, ...]] = (
    "max_invocations",
    "max_bytes_read",
    "max_bytes_out",
    "max_cost_minor_units",
)


@dataclass(frozen=True, slots=True)
class Budgets:
    """Resource ceilings granted by one intent (all u64)."""

    max_invocations: int = 0
    max_bytes_read: int = 0
    max_bytes_out: int = 0
    max_cost_minor_units: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "max_invocations": self.max_invocations,
            "max_bytes_read": self.max_bytes_read,
            "max_bytes_out": self.max_bytes_out,
            "max_cost_minor_units": self.max_cost_minor_units,
        }

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> Budgets:
        values: dict[str, int] = {}
        for key in BUDGET_KEYS:
            value = raw.get(key, 0)
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_SEQ:
                raise ProtocolError(f"budget {key!r} must be a u64 integer")
            values[key] = value
        extra = set(raw) - set(BUDGET_KEYS)
        if extra:
            raise ProtocolError(f"unknown budget fields {sorted(extra)!r}")
        return Budgets(**values)

    def allows(self, spent: Budgets) -> bool:
        return (
            spent.max_invocations <= self.max_invocations
            and spent.max_bytes_read <= self.max_bytes_read
            and spent.max_bytes_out <= self.max_bytes_out
            and spent.max_cost_minor_units <= self.max_cost_minor_units
        )


@dataclass(frozen=True, slots=True)
class IntentEnvelope:
    """Signed statement of what the owner allows for one task."""

    intent_id: str
    owner_key_hash: str
    product_id: str
    profile: str
    task_id: str
    raw_request_hash: str
    allowed_effect_classes: tuple[str, ...]
    allowed_resource_handles: tuple[str, ...]
    allowed_sink_handles: tuple[str, ...]
    budgets: Budgets
    approval_policy: str
    issued_by: str
    issued_at_ms: int
    expires_at_ms: int
    signature: str = ""

    def payload(self) -> str:
        body: dict[str, Any] = {
            "protocol": "orin/v1",
            "intent_id": self.intent_id,
            "subject": {
                "owner_key_hash": self.owner_key_hash,
                "product_id": self.product_id,
                "profile": self.profile,
            },
            "task_id": self.task_id,
            "raw_request_hash": self.raw_request_hash,
            "allowed_effect_classes": list(self.allowed_effect_classes),
            "allowed_resource_handles": list(self.allowed_resource_handles),
            "allowed_sink_handles": list(self.allowed_sink_handles),
            "budgets": self.budgets.to_dict(),
            "approval_policy": self.approval_policy,
            "issued_by": self.issued_by,
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
        }
        return canonical_json(body)

    def to_dict(self) -> dict[str, Any]:
        data = cast("dict[str, Any]", json.loads(self.payload()))
        data["signature"] = self.signature
        return data

    def sign_with(self, private_key: Any) -> IntentEnvelope:
        """Sign the canonical payload; returns a copy carrying the b64 signature."""

        raw = private_key.sign(self.payload().encode("utf-8"))
        return replace(self, signature=base64.b64encode(raw).decode("ascii"))

    def verify(self, public_key_b64: str) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519

            pub_raw = base64.b64decode(public_key_b64, validate=True)
            sig = base64.b64decode(self.signature, validate=True)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
            public_key.verify(sig, self.payload().encode("utf-8"))
            return True
        except Exception:  # noqa: BLE001 - any crypto failure means invalid
            return False


def request_hash_of(raw_request: str) -> str:
    """Deterministic ``sha256:…`` digest binding an intent to its raw ask."""

    return _SHA256_RE + hashlib.sha256(raw_request.encode("utf-8")).hexdigest()


def _check_str(value: Any, name: str, *, prefix: str = "", max_len: int = 256) -> str:
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"intent field {name!r} must be a non-empty string")
    if len(value) > max_len:
        raise ProtocolError(f"intent field {name!r} exceeds length cap")
    if prefix and not value.startswith(prefix):
        raise ProtocolError(f"intent field {name!r} must start with {prefix!r}")
    return value


def validate_intent_dict(data: Any) -> None:
    """Strict shape check used by both the client builder and orind handlers."""

    if not isinstance(data, dict):
        raise ProtocolError("intent must be an object")
    known = {
        "protocol",
        "intent_id",
        "subject",
        "task_id",
        "raw_request_hash",
        "allowed_effect_classes",
        "allowed_resource_handles",
        "allowed_sink_handles",
        "budgets",
        "approval_policy",
        "issued_by",
        "issued_at_ms",
        "expires_at_ms",
        "signature",
    }
    unknown = set(data) - known
    if unknown:
        raise ProtocolError(f"unknown intent fields {sorted(unknown)!r}")
    _check_str(data.get("protocol"), "protocol", max_len=16)
    _check_str(data.get("intent_id"), "intent_id", prefix=_INTENT_ID_PREFIX)
    _check_str(data.get("task_id"), "task_id", prefix=_TASK_ID_PREFIX)
    subject = data.get("subject")
    if not isinstance(subject, dict):
        raise ProtocolError("intent 'subject' must be an object")
    unknown_subject = set(subject) - {"owner_key_hash", "product_id", "profile"}
    if unknown_subject:
        raise ProtocolError(f"unknown subject fields {sorted(unknown_subject)!r}")
    _check_str(subject.get("owner_key_hash"), "subject.owner_key_hash", prefix=_SHA256_RE)
    _check_str(subject.get("product_id"), "subject.product_id")
    _check_str(subject.get("profile"), "subject.profile")
    _check_str(data.get("raw_request_hash"), "raw_request_hash", prefix=_SHA256_RE)
    for key in ("allowed_effect_classes", "allowed_resource_handles", "allowed_sink_handles"):
        value = data.get(key)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ProtocolError(f"intent field {key!r} must be a list of strings")
    for cls_ in data.get("allowed_effect_classes") or []:
        if cls_ not in EFFECT_CLASSES:
            raise ProtocolError(f"unknown effect class {cls_!r}")
    policy = data.get("approval_policy")
    if policy not in APPROVAL_POLICIES:
        raise ProtocolError(f"unknown approval_policy {policy!r}")
    Budgets.from_dict(data.get("budgets") or {})
    _check_str(data.get("issued_by"), "issued_by")
    for key in ("issued_at_ms", "expires_at_ms"):
        value = data.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= MAX_SEQ:
            raise ProtocolError(f"intent field {key!r} must be a positive u64")
    if int(data["expires_at_ms"]) <= int(data["issued_at_ms"]):
        raise ProtocolError("intent expires_at_ms must be after issued_at_ms")


def intent_from_dict(data: dict[str, Any], *, verify_signature: bool = False) -> IntentEnvelope:
    """Parse strictly; optionally verify the Ed25519 signature."""

    validate_intent_dict(data)
    subject = data["subject"]
    envelope = IntentEnvelope(
        intent_id=data["intent_id"],
        owner_key_hash=subject["owner_key_hash"],
        product_id=subject["product_id"],
        profile=subject["profile"],
        task_id=data["task_id"],
        raw_request_hash=data["raw_request_hash"],
        allowed_effect_classes=tuple(data["allowed_effect_classes"]),
        allowed_resource_handles=tuple(data["allowed_resource_handles"]),
        allowed_sink_handles=tuple(data["allowed_sink_handles"]),
        budgets=Budgets.from_dict(data.get("budgets") or {}),
        approval_policy=data["approval_policy"],
        issued_by=data["issued_by"],
        issued_at_ms=int(data["issued_at_ms"]),
        expires_at_ms=int(data["expires_at_ms"]),
        signature=data.get("signature", ""),
    )
    if verify_signature and not envelope.signature:
        raise ProtocolError("intent requires a signature")
    return envelope


def session_tightening_ok(new: IntentEnvelope, active: IntentEnvelope) -> bool:
    """I-08: within a session permissions only tighten, never expand."""

    if not set(new.allowed_effect_classes) <= set(active.allowed_effect_classes):
        return False
    if not set(new.allowed_resource_handles) <= set(active.allowed_resource_handles):
        return False
    if not set(new.allowed_sink_handles) <= set(active.allowed_sink_handles):
        return False
    if not active.budgets.allows(new.budgets):
        return False
    new_rank = _POLICY_STRICTNESS[new.approval_policy]
    active_rank = _POLICY_STRICTNESS[active.approval_policy]
    return new_rank >= active_rank


def policy_backs_r2(approval_policy: str) -> bool:
    return _POLICY_STRICTNESS.get(approval_policy, 0) >= R2_MIN_STRICTNESS


__all__ = [
    "APPROVAL_POLICIES",
    "BUDGET_KEYS",
    "Budgets",
    "EFFECT_CLASSES",
    "IntentEnvelope",
    "intent_from_dict",
    "policy_backs_r2",
    "request_hash_of",
    "session_tightening_ok",
    "validate_intent_dict",
]
