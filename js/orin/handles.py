"""OriginHandle family (K§7.3): unforgeable, scoped permission objects.

权限型参数必须是句柄；自由文本只进内容型字段。Handles are minted and
sealed by orind (HMAC-SHA256 over the canonical payload — the same trust
anchor as lease MACs) so Echo can select among visible candidates but can
never mint a new one by emitting a similar string.

``DesktopTargetHandle`` keeps its type slot for Stage C but is never issued
in Stage B.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Final, cast

from js.orin.protocol import MAX_SEQ, ProtocolError, canonical_json

HANDLE_KINDS: Final[tuple[str, ...]] = (
    "DirectoryHandle",
    "ArtifactHandle",
    "RecipientHandle",
    "EndpointHandle",
    "AccountHandle",
    "SecretHandle",
    "DesktopTargetHandle",
)

KIND_PREFIXES: Final[dict[str, str]] = {
    "DirectoryHandle": "dirh",
    "ArtifactHandle": "artifact",
    "RecipientHandle": "rcpt",
    "EndpointHandle": "ep",
    "AccountHandle": "acct",
    "SecretHandle": "secret",
    "DesktopTargetHandle": "desktop",
}
_PREFIX_TO_KIND: Final[dict[str, str]] = {v: k for k, v in KIND_PREFIXES.items()}

SOURCE_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "USER_AUTHENTICATED",
        "TRUSTED_LOCAL",
        "PRIVATE_LOCAL",
        "ENTERPRISE_INTERNAL",
        "UNTRUSTED_WEB",
        "UNTRUSTED_MESSAGE",
        "UNTRUSTED_TOOL",
        "MEMORY_RETRIEVED",
        "MODEL_DERIVED",
        "SECRET",
    }
)

INTEGRITY_LEVELS: Final[frozenset[str]] = frozenset(
    {"trusted_local_object", "untrusted_content", "model_derived"}
)
CONFIDENTIALITY_LEVELS: Final[frozenset[str]] = frozenset({"PUBLIC", "CONFIDENTIAL", "SECRET"})
CAPABILITIES: Final[frozenset[str]] = frozenset({"read", "stage", "write", "send", "use"})

_SEAL_PREFIX: Final[str] = "orin-hmac-sha256:"


@dataclass(frozen=True, slots=True)
class OriginHandle:
    """One sealed permission object."""

    handle_id: str
    kind: str
    owner_key_hash: str
    tenant: str
    source_class: str
    integrity: str
    confidentiality: str
    object_digest: str
    capabilities: tuple[str, ...]
    issuer: str
    created_at_ms: int
    expires_at_ms: int
    signature: str = ""

    def payload(self) -> str:
        body: dict[str, Any] = {
            "handle_id": self.handle_id,
            "kind": self.kind,
            "owner_key_hash": self.owner_key_hash,
            "tenant": self.tenant,
            "source_class": self.source_class,
            "integrity": self.integrity,
            "confidentiality": self.confidentiality,
            "object_digest": self.object_digest,
            "capabilities": list(self.capabilities),
            "issuer": self.issuer,
            "created_at_ms": self.created_at_ms,
            "expires_at_ms": self.expires_at_ms,
        }
        return canonical_json(body)

    def to_dict(self) -> dict[str, Any]:
        import json

        data = cast("dict[str, Any]", json.loads(self.payload()))
        data["signature"] = self.signature
        return data

    def sealed_by(self, mac_key: bytes, issuer: str, now_ms: int) -> OriginHandle:
        if self.issuer != issuer:
            raise ProtocolError("handle issuer mismatch")
        digest = hmac.new(mac_key, self.payload().encode("utf-8"), hashlib.sha256).hexdigest()
        return OriginHandle(
            handle_id=self.handle_id,
            kind=self.kind,
            owner_key_hash=self.owner_key_hash,
            tenant=self.tenant,
            source_class=self.source_class,
            integrity=self.integrity,
            confidentiality=self.confidentiality,
            object_digest=self.object_digest,
            capabilities=self.capabilities,
            issuer=self.issuer,
            created_at_ms=self.created_at_ms if self.created_at_ms else now_ms,
            expires_at_ms=self.expires_at_ms,
            signature=_SEAL_PREFIX + digest,
        )

    def verify_seal(self, mac_key: bytes) -> bool:
        if not self.signature.startswith(_SEAL_PREFIX):
            return False
        expected = _SEAL_PREFIX + hmac.new(
            mac_key, self.payload().encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected)


def make_handle_id(kind: str, token: str) -> str:
    prefix = KIND_PREFIXES.get(kind)
    if prefix is None:
        raise ProtocolError(f"unknown handle kind {kind!r}")
    if not token or len(token) > 200 or any(not (c.isalnum() or c in "-_.") for c in token):
        raise ProtocolError("handle token must be bounded [A-Za-z0-9-_.]")
    return f"{prefix}:{token}"


def kind_of_handle_id(handle_id: str) -> str:
    prefix, _, token = handle_id.partition(":")
    kind = _PREFIX_TO_KIND.get(prefix)
    if kind is None or not token:
        raise ProtocolError(f"malformed handle id {handle_id!r}")
    return kind


def validate_handle_dict(data: Any, *, require_signature: bool = False) -> None:
    if not isinstance(data, dict):
        raise ProtocolError("handle must be an object")
    known = {
        "handle_id",
        "kind",
        "owner_key_hash",
        "tenant",
        "source_class",
        "integrity",
        "confidentiality",
        "object_digest",
        "capabilities",
        "issuer",
        "created_at_ms",
        "expires_at_ms",
        "signature",
    }
    unknown = set(data) - known
    if unknown:
        raise ProtocolError(f"unknown handle fields {sorted(unknown)!r}")
    kind = data.get("kind")
    if kind not in HANDLE_KINDS:
        raise ProtocolError(f"unknown handle kind {kind!r}")
    for key in ("handle_id", "owner_key_hash", "tenant", "issuer"):
        value = data.get(key)
        if not isinstance(value, str) or not value or len(value) > 512:
            raise ProtocolError(f"handle field {key!r} must be a bounded string")
    digest = data.get("object_digest")
    if not isinstance(digest, str) or len(digest) > 512:
        raise ProtocolError("handle field 'object_digest' must be a bounded string")
    kind_of_handle_id(data["handle_id"])
    for key in ("source_class", "integrity", "confidentiality"):
        value = data.get(key)
        if not isinstance(value, str) or not value or len(value) > 64:
            raise ProtocolError(f"handle field {key!r} must be a bounded string")
    caps = data.get("capabilities")
    if not isinstance(caps, list) or not caps or any(c not in CAPABILITIES for c in caps):
        raise ProtocolError("handle capabilities must be a non-empty vocabulary list")
    for key in ("created_at_ms", "expires_at_ms"):
        value = data.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_SEQ:
            raise ProtocolError(f"handle field {key!r} must be a u64 integer")
    sig = data.get("signature", "")
    if require_signature and not (isinstance(sig, str) and sig.startswith(_SEAL_PREFIX)):
        raise ProtocolError("handle requires a seal")


def handle_from_dict(data: dict[str, Any], *, require_signature: bool = False) -> OriginHandle:
    validate_handle_dict(data, require_signature=require_signature)
    return OriginHandle(
        handle_id=data["handle_id"],
        kind=data["kind"],
        owner_key_hash=data["owner_key_hash"],
        tenant=data["tenant"],
        source_class=data["source_class"],
        integrity=data["integrity"],
        confidentiality=data["confidentiality"],
        object_digest=data["object_digest"],
        capabilities=tuple(data["capabilities"]),
        issuer=data["issuer"],
        created_at_ms=int(data.get("created_at_ms") or 0),
        expires_at_ms=int(data["expires_at_ms"]),
        signature=data.get("signature", ""),
    )


@dataclass(frozen=True, slots=True)
class SeedCandidate:
    """One pre-registered candidate object Echo may select (M§3.2-2)."""

    kind: str
    token: str
    label: str
    source: str  # contacts | task_history | cron_template | admin

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "token": self.token, "label": self.label, "source": self.source}


__all__ = [
    "CAPABILITIES",
    "CONFIDENTIALITY_LEVELS",
    "HANDLE_KINDS",
    "INTEGRITY_LEVELS",
    "KIND_PREFIXES",
    "OriginHandle",
    "SeedCandidate",
    "SOURCE_CLASSES",
    "handle_from_dict",
    "kind_of_handle_id",
    "make_handle_id",
    "validate_handle_dict",
]
