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
import os
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from js.orin.protocol import MAX_SEQ, ProtocolError, canonical_json

HANDLE_KINDS: Final[tuple[str, ...]] = (
    "DirectoryHandle",
    "ArtifactHandle",
    "RecipientHandle",
    "EndpointHandle",
    "AccountHandle",
    "SecretHandle",
    "ApplicationHandle",
    "DesktopTargetHandle",
    "BotHandle",
    "RoomHandle",
)

KIND_PREFIXES: Final[dict[str, str]] = {
    "DirectoryHandle": "dirh",
    "ArtifactHandle": "artifact",
    "RecipientHandle": "rcpt",
    "EndpointHandle": "ep",
    "AccountHandle": "acct",
    "SecretHandle": "secret",
    "ApplicationHandle": "app",
    "DesktopTargetHandle": "desktop",
    "BotHandle": "bot",
    "RoomHandle": "room",
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
_APPSHELL_DIRECTORY_BINDING_SCHEMA: Final[str] = "AppShellDirectoryBindingV1"
_APPSHELL_DIRECTORY_COMMITMENT_DOMAIN: Final[str] = "orin:appshell-dirh:v1"
_APPSHELL_DESKTOP_APP_BINDING_SCHEMA: Final[str] = "AppShellDesktopAppBindingV1"
_APPSHELL_DESKTOP_APP_COMMITMENT_DOMAIN: Final[str] = "orin:appshell-app:v1"


def _bounded_string(value: Any, name: str, *, max_len: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ProtocolError(f"{name} must be a bounded non-empty string")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise ProtocolError(f"{name} must not contain control characters")
    return value


def canonical_workspace_root(root: Path | str) -> str:
    """Return the strict NFC absolute directory root used by File Cell.

    Symlinks are resolved before the path is serialized. Existence is checked
    against the resolved filesystem object while the returned spelling is NFC,
    so macOS' decomposed on-disk Unicode cannot perturb the wire commitment.
    """

    if not isinstance(root, (Path, str)) or isinstance(root, bool):
        raise ProtocolError("workspace root must be a path or string")
    if isinstance(root, str) and not root:
        raise ProtocolError("workspace root must be non-empty")
    try:
        resolved = Path(root).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ProtocolError("workspace root must resolve to an existing directory") from exc
    if not resolved.is_absolute() or not resolved.is_dir():
        raise ProtocolError("workspace root must resolve to an existing directory")
    normalized = unicodedata.normalize("NFC", os.fspath(resolved))
    # ``OriginHandle.object_digest`` is capped at 512 characters, so reject
    # an unusable owner root before any signed intent or handle is recorded.
    _bounded_string(normalized, "workspace root", max_len=512)
    if not Path(normalized).is_absolute():
        raise ProtocolError("workspace root must be absolute")
    return normalized


@dataclass(frozen=True, slots=True)
class AppShellDirectoryBindingV1:
    """AppShell-only grant material carried by ``intent(register)``.

    The parent AppShell session deliberately remains a top-level protocol
    field. Keeping this object to five exact wire fields prevents a caller
    from smuggling a second identity or authority-bearing root into it.
    """

    principal_owner: str
    principal_epoch: int
    product_id: str
    workspace_root: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": _APPSHELL_DIRECTORY_BINDING_SCHEMA,
            "principal_owner": self.principal_owner,
            "principal_epoch": self.principal_epoch,
            "product_id": self.product_id,
            "workspace_root": self.workspace_root,
        }


def appshell_directory_binding_from_dict(data: Any) -> AppShellDirectoryBindingV1:
    """Strictly parse the five-field AppShell directory-binding grant."""

    if not isinstance(data, dict):
        raise ProtocolError("AppShell directory binding must be an object")
    fields = {
        "schema",
        "principal_owner",
        "principal_epoch",
        "product_id",
        "workspace_root",
    }
    if set(data) != fields:
        missing = fields - set(data)
        unknown = set(data) - fields
        if missing:
            raise ProtocolError(f"missing AppShell directory binding fields {sorted(missing)!r}")
        raise ProtocolError(f"unknown AppShell directory binding fields {sorted(unknown)!r}")
    if data["schema"] != _APPSHELL_DIRECTORY_BINDING_SCHEMA:
        raise ProtocolError("unknown AppShell directory binding schema")
    principal_owner = _bounded_string(data["principal_owner"], "principal_owner")
    product_id = _bounded_string(data["product_id"], "product_id", max_len=256)
    principal_epoch = data["principal_epoch"]
    if (
        not isinstance(principal_epoch, int)
        or isinstance(principal_epoch, bool)
        or not 0 <= principal_epoch <= MAX_SEQ
    ):
        raise ProtocolError("principal_epoch must be a u64 integer")
    workspace_root = data["workspace_root"]
    canonical_root = canonical_workspace_root(workspace_root)
    if workspace_root != canonical_root:
        raise ProtocolError("workspace_root must be its canonical NFC absolute path")
    return AppShellDirectoryBindingV1(
        principal_owner=principal_owner,
        principal_epoch=principal_epoch,
        product_id=product_id,
        workspace_root=canonical_root,
    )


def derive_appshell_directory_handle_id(
    *,
    installation_owner_hash: str,
    product_id: str,
    task_id: str,
    profile: str,
    principal_owner: str,
    principal_session: str,
    principal_epoch: int,
    workspace_root: str,
) -> str:
    """Derive the frozen DirectoryHandle id for one confirmed AppShell task."""

    installation_owner_hash = _bounded_string(installation_owner_hash, "installation_owner_hash")
    product_id = _bounded_string(product_id, "product_id", max_len=256)
    task_id = _bounded_string(task_id, "task_id", max_len=256)
    if not task_id.startswith("task:"):
        raise ProtocolError("task_id must start with 'task:'")
    profile = _bounded_string(profile, "profile", max_len=32)
    if profile not in {"personal", "work"}:
        raise ProtocolError("AppShell directory binding profile must be personal or work")
    principal_owner = _bounded_string(principal_owner, "principal_owner")
    principal_session = _bounded_string(principal_session, "principal_session", max_len=128)
    if (
        not isinstance(principal_epoch, int)
        or isinstance(principal_epoch, bool)
        or not 0 <= principal_epoch <= MAX_SEQ
    ):
        raise ProtocolError("principal_epoch must be a u64 integer")
    workspace_root = _bounded_string(workspace_root, "workspace_root", max_len=512)
    if not Path(workspace_root).is_absolute():
        raise ProtocolError("workspace_root must be absolute")
    if unicodedata.normalize("NFC", workspace_root) != workspace_root:
        raise ProtocolError("workspace_root must be NFC-normalized")

    commitment: list[str | int] = [
        _APPSHELL_DIRECTORY_COMMITMENT_DOMAIN,
        installation_owner_hash,
        product_id,
        task_id,
        profile,
        principal_owner,
        principal_session,
        principal_epoch,
        workspace_root,
    ]
    digest = hashlib.sha256(canonical_json(commitment).encode("utf-8")).hexdigest()
    return make_handle_id("DirectoryHandle", f"appshell-{digest}")


def canonical_bundle_id(bundle_id: Any) -> str:
    """Return a closed reverse-DNS bundle id for an owner-granted application."""

    text = _bounded_string(bundle_id, "bundle_id", max_len=512)
    if unicodedata.normalize("NFC", text) != text:
        raise ProtocolError("bundle_id must be NFC-normalized")
    labels = text.split(".")
    if (
        len(labels) < 2
        or any(not label or not label[0].isalnum() for label in labels)
        or any(not all(char.isalnum() or char in "-_" for char in label) for label in labels)
    ):
        raise ProtocolError("bundle_id must be a reverse-DNS identifier")
    return text


@dataclass(frozen=True, slots=True)
class AppShellDesktopAppBindingV1:
    """AppShell-only grant material for one owner-authorized application."""

    principal_owner: str
    principal_epoch: int
    product_id: str
    bundle_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": _APPSHELL_DESKTOP_APP_BINDING_SCHEMA,
            "principal_owner": self.principal_owner,
            "principal_epoch": self.principal_epoch,
            "product_id": self.product_id,
            "bundle_id": self.bundle_id,
        }


def appshell_desktop_app_binding_from_dict(data: Any) -> AppShellDesktopAppBindingV1:
    if not isinstance(data, dict):
        raise ProtocolError("AppShell desktop app binding must be an object")
    fields = {
        "schema",
        "principal_owner",
        "principal_epoch",
        "product_id",
        "bundle_id",
    }
    if set(data) != fields:
        missing = fields - set(data)
        unknown = set(data) - fields
        if missing:
            raise ProtocolError(f"missing AppShell desktop app binding fields {sorted(missing)!r}")
        raise ProtocolError(f"unknown AppShell desktop app binding fields {sorted(unknown)!r}")
    if data["schema"] != _APPSHELL_DESKTOP_APP_BINDING_SCHEMA:
        raise ProtocolError("unknown AppShell desktop app binding schema")
    principal_epoch = data["principal_epoch"]
    if (
        not isinstance(principal_epoch, int)
        or isinstance(principal_epoch, bool)
        or not 0 <= principal_epoch <= MAX_SEQ
    ):
        raise ProtocolError("principal_epoch must be a u64 integer")
    return AppShellDesktopAppBindingV1(
        principal_owner=_bounded_string(data["principal_owner"], "principal_owner"),
        principal_epoch=principal_epoch,
        product_id=_bounded_string(data["product_id"], "product_id", max_len=256),
        bundle_id=canonical_bundle_id(data["bundle_id"]),
    )


def derive_appshell_application_handle_id(
    *,
    installation_owner_hash: str,
    product_id: str,
    task_id: str,
    profile: str,
    principal_owner: str,
    principal_session: str,
    principal_epoch: int,
    bundle_id: str,
) -> str:
    """Derive the frozen ApplicationHandle id for one confirmed AppShell task."""

    installation_owner_hash = _bounded_string(installation_owner_hash, "installation_owner_hash")
    product_id = _bounded_string(product_id, "product_id", max_len=256)
    task_id = _bounded_string(task_id, "task_id", max_len=256)
    if not task_id.startswith("task:"):
        raise ProtocolError("task_id must start with 'task:'")
    profile = _bounded_string(profile, "profile", max_len=32)
    if profile not in {"personal", "work"}:
        raise ProtocolError("AppShell desktop app binding profile must be personal or work")
    principal_owner = _bounded_string(principal_owner, "principal_owner")
    principal_session = _bounded_string(principal_session, "principal_session", max_len=128)
    if (
        not isinstance(principal_epoch, int)
        or isinstance(principal_epoch, bool)
        or not 0 <= principal_epoch <= MAX_SEQ
    ):
        raise ProtocolError("principal_epoch must be a u64 integer")
    bundle_id = canonical_bundle_id(bundle_id)
    commitment: list[str | int] = [
        _APPSHELL_DESKTOP_APP_COMMITMENT_DOMAIN,
        installation_owner_hash,
        product_id,
        task_id,
        profile,
        principal_owner,
        principal_session,
        principal_epoch,
        bundle_id,
    ]
    digest = hashlib.sha256(canonical_json(commitment).encode("utf-8")).hexdigest()
    return make_handle_id("ApplicationHandle", f"appshell-{digest}")


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
        expected = (
            _SEAL_PREFIX
            + hmac.new(mac_key, self.payload().encode("utf-8"), hashlib.sha256).hexdigest()
        )
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
    if kind_of_handle_id(data["handle_id"]) != kind:
        raise ProtocolError("handle id prefix does not match handle kind")
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


_BOT_HANDLE_DOMAIN: Final[str] = "orin:bot-handle:v1"
_ROOM_HANDLE_DOMAIN: Final[str] = "orin:room-handle:v1"


def echo_cannot_issue_handle() -> None:
    """Echo may select a visible handle; it may never mint one."""

    raise PermissionError("Echo cannot issue OriginHandle objects")


def echo_cannot_issue_intent() -> None:
    """Only AppShell / trusted CLI / admin API may issue an IntentEnvelope."""

    raise PermissionError("Echo cannot issue IntentEnvelope objects")


def derive_bot_handle_id(
    *,
    owner_key_hash: str,
    product_id: str,
    bot_id: str,
    epoch: int,
) -> str:
    owner_key_hash = _bounded_string(owner_key_hash, "owner_key_hash")
    product_id = _bounded_string(product_id, "product_id", max_len=256)
    bot_id = _bounded_string(bot_id, "bot_id", max_len=128)
    if not isinstance(epoch, int) or isinstance(epoch, bool) or not 0 <= epoch <= MAX_SEQ:
        raise ProtocolError("epoch must be a u64 integer")
    digest = hashlib.sha256(
        canonical_json([_BOT_HANDLE_DOMAIN, owner_key_hash, product_id, bot_id, epoch]).encode(
            "utf-8"
        )
    ).hexdigest()
    return make_handle_id("BotHandle", f"scope-{digest[:24]}")


def derive_room_handle_id(
    *,
    owner_key_hash: str,
    product_id: str,
    room_id: str,
    epoch: int,
) -> str:
    owner_key_hash = _bounded_string(owner_key_hash, "owner_key_hash")
    product_id = _bounded_string(product_id, "product_id", max_len=256)
    room_id = _bounded_string(room_id, "room_id", max_len=128)
    if not isinstance(epoch, int) or isinstance(epoch, bool) or not 0 <= epoch <= MAX_SEQ:
        raise ProtocolError("epoch must be a u64 integer")
    digest = hashlib.sha256(
        canonical_json([_ROOM_HANDLE_DOMAIN, owner_key_hash, product_id, room_id, epoch]).encode(
            "utf-8"
        )
    ).hexdigest()
    return make_handle_id("RoomHandle", f"scope-{digest[:24]}")


def seal_scoped_handle(
    *,
    kind: str,
    handle_id: str,
    owner_key_hash: str,
    product_id: str,
    object_digest: str,
    mac_key: bytes,
    issuer: str,
    now_ms: int,
    capabilities: tuple[str, ...] = ("read",),
) -> OriginHandle:
    """orind-only seal. Echo has no MAC key and cannot call this successfully."""

    if not isinstance(mac_key, bytes) or len(mac_key) != 32:
        raise ProtocolError("handle seal requires the 32-byte orind MAC key")
    if issuer.startswith("echo"):
        echo_cannot_issue_handle()
    handle = OriginHandle(
        handle_id=handle_id,
        kind=kind,
        owner_key_hash=owner_key_hash,
        tenant=product_id,
        source_class="TRUSTED_LOCAL",
        integrity="trusted_local_object",
        confidentiality="CONFIDENTIAL",
        object_digest=object_digest,
        capabilities=capabilities,
        issuer=issuer,
        created_at_ms=now_ms,
        expires_at_ms=now_ms + 86_400_000,
    )
    return handle.sealed_by(mac_key, issuer, now_ms)


__all__ = [
    "AppShellDesktopAppBindingV1",
    "AppShellDirectoryBindingV1",
    "CAPABILITIES",
    "CONFIDENTIALITY_LEVELS",
    "HANDLE_KINDS",
    "INTEGRITY_LEVELS",
    "KIND_PREFIXES",
    "OriginHandle",
    "SeedCandidate",
    "SOURCE_CLASSES",
    "appshell_desktop_app_binding_from_dict",
    "appshell_directory_binding_from_dict",
    "canonical_bundle_id",
    "canonical_workspace_root",
    "derive_appshell_application_handle_id",
    "derive_appshell_directory_handle_id",
    "derive_bot_handle_id",
    "derive_room_handle_id",
    "echo_cannot_issue_handle",
    "echo_cannot_issue_intent",
    "handle_from_dict",
    "seal_scoped_handle",
    "kind_of_handle_id",
    "make_handle_id",
    "validate_handle_dict",
]
