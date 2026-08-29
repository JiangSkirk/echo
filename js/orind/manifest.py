"""Signed Effect Manifest registry (K§13.1 / M§1.2-25 / D§6.9).

Server-claimed hints (``readOnlyHint``, ``destructiveHint``, descriptions)
are never trusted: an effect type only gets real semantics from a locally
SEALED manifest entry (HMAC-SHA256 by the same KeyBox key as lease MACs).
Unknown effect types fall through to the open-world row in the Gate Kernel:
writable, possibly destructive, non-idempotent → approval required.

Each entry also carries the K4 connector-capability grid (idempotent /
drafts / etag / reconciliation query). A commit-class entry missing any
grid cell escalates the required approval level — enforced by the kernel.
``description_hash`` keeps the D§6.9 supply-chain pinning: re-registering
an entry whose tool description changed requires a fresh seal.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Final

from js.orin.protocol import ProtocolError, canonical_json

SIDE_EFFECT_CLASSES: Final[frozenset[str]] = frozenset({"R0", "R1", "R2", "R3"})
_SEAL_PREFIX: Final[str] = "orin-hmac-sha256:"


def description_hash_of(description: str) -> str:
    """D§6.9 pinning digest for a tool/effect description string."""

    return "sha256:" + hashlib.sha256(description.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class EffectManifestEntry:
    """One locally-sealed effect type definition."""

    effect_type: str
    # The executor is part of the sealed manifest payload.  Client-provided
    # executor ids are never authoritative during preflight/commit routing.
    executor_id: str = "cell.connector"
    side_effect_class: str = "R2"
    idempotent: bool = False
    drafts_supported: bool = False
    etag_support: bool = False
    reconcile_query: bool = False
    permission_args: dict[str, str] = field(default_factory=dict)
    content_args: tuple[str, ...] = ()
    description_hash: str = ""

    def payload(self) -> str:
        body: dict[str, Any] = {
            "effect_type": self.effect_type,
            "executor_id": self.executor_id,
            "side_effect_class": self.side_effect_class,
            "idempotent": self.idempotent,
            "drafts_supported": self.drafts_supported,
            "etag_support": self.etag_support,
            "reconcile_query": self.reconcile_query,
            "permission_args": dict(sorted(self.permission_args.items())),
            "content_args": list(self.content_args),
            "description_hash": self.description_hash,
        }
        return canonical_json(body)

    @property
    def capability_grid_complete(self) -> bool:
        """K4: every external-service cell must answer all four questions."""

        return (
            self.idempotent
            and self.drafts_supported
            and (self.etag_support or self.reconcile_query)
        )

    def seal(self, mac_key: bytes) -> str:
        digest = hmac.new(mac_key, self.payload().encode("utf-8"), hashlib.sha256)
        return _SEAL_PREFIX + digest.hexdigest()

    def verify_seal(self, mac_key: bytes, seal: str) -> bool:
        if not seal.startswith(_SEAL_PREFIX):
            return False
        expected = self.seal(mac_key)
        return hmac.compare_digest(seal, expected)


def validate_entry_dict(data: Any) -> None:
    if not isinstance(data, dict):
        raise ProtocolError("manifest entry must be an object")
    allowed = {
        "effect_type",
        "executor_id",
        "side_effect_class",
        "idempotent",
        "drafts_supported",
        "etag_support",
        "reconcile_query",
        "permission_args",
        "content_args",
        "description_hash",
    }
    unknown = set(data) - allowed
    if unknown:
        raise ProtocolError(f"unknown manifest fields {sorted(unknown)!r}")
    effect_type = data.get("effect_type")
    if not isinstance(effect_type, str) or not effect_type or len(effect_type) > 128:
        raise ProtocolError("manifest effect_type must be a bounded string")
    if "." not in effect_type:
        raise ProtocolError("manifest effect_type must be '<domain>.<verb>'")
    executor_id = data.get("executor_id", "cell.connector")
    if (
        not isinstance(executor_id, str)
        or not executor_id.startswith("cell.")
        or len(executor_id) > 128
    ):
        raise ProtocolError("manifest executor_id must name a bounded 'cell.*' executor")
    side_effect_class = data.get("side_effect_class", "R2")
    if not isinstance(side_effect_class, str) or side_effect_class not in SIDE_EFFECT_CLASSES:
        raise ProtocolError(f"unknown side_effect_class {side_effect_class!r}")
    for field_name in (
        "idempotent",
        "drafts_supported",
        "etag_support",
        "reconcile_query",
    ):
        value = data.get(field_name, False)
        if not isinstance(value, bool):
            raise ProtocolError(f"{field_name} must be a boolean")
    perm = data.get("permission_args", {})
    if not isinstance(perm, dict) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in perm.items()
    ):
        raise ProtocolError("permission_args must map argument names to handle prefixes")
    content = data.get("content_args", [])
    if not isinstance(content, list) or any(not isinstance(item, str) for item in content):
        raise ProtocolError("content_args must be a list of strings")


def entry_from_dict(data: dict[str, Any]) -> EffectManifestEntry:
    validate_entry_dict(data)
    return EffectManifestEntry(
        effect_type=data["effect_type"],
        executor_id=data.get("executor_id", "cell.connector"),
        side_effect_class=data.get("side_effect_class", "R2"),
        idempotent=data.get("idempotent", False),
        drafts_supported=data.get("drafts_supported", False),
        etag_support=data.get("etag_support", False),
        reconcile_query=data.get("reconcile_query", False),
        permission_args=dict(data.get("permission_args", {})),
        content_args=tuple(data.get("content_args", [])),
        description_hash=data.get("description_hash", ""),
    )


class EffectManifest:
    """Registry of sealed entries; lookups never trust unsealed data."""

    def __init__(self, mac_key: bytes) -> None:
        self._mac_key = mac_key
        self._entries: dict[str, EffectManifestEntry] = {}
        self._seals: dict[str, str] = {}

    def register(
        self,
        entry: EffectManifestEntry,
        *,
        expected_description_hash: str | None = None,
    ) -> None:
        """Seal-and-store. Pinning: a stale ``expected_description_hash``
        refuses the update (tool description drifted since pinning)."""

        if expected_description_hash is not None:
            existing = self._entries.get(entry.effect_type)
            if existing is not None and existing.description_hash != expected_description_hash:
                raise ProtocolError(
                    f"description hash drift for {entry.effect_type!r}; re-pin required"
                )
        if entry.description_hash and not entry.description_hash.startswith("sha256:"):
            raise ProtocolError("description_hash must be sha256:…")
        self._entries[entry.effect_type] = entry
        self._seals[entry.effect_type] = entry.seal(self._mac_key)

    def get(self, effect_type: str) -> EffectManifestEntry | None:
        entry = self._entries.get(effect_type)
        if entry is None:
            return None
        if not entry.verify_seal(self._mac_key, self._seals[effect_type]):
            # Tampered registry state fails closed to the open-world row.
            return None
        return entry

    def __contains__(self, effect_type: str) -> bool:
        return self.get(effect_type) is not None

    def export(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for effect_type, entry in sorted(self._entries.items()):
            data = json.loads(entry.payload())
            data["seal"] = self._seals[effect_type]
            out.append(data)
        return out


def builtin_manifest(
    mac_key: bytes,
    *,
    include_desktop: bool = False,
    include_memory: bool = False,
) -> EffectManifest:
    """Stage-B built-ins for first-party effect types (all sealed)."""

    manifest = EffectManifest(mac_key)
    if include_desktop:
        manifest.register(
            EffectManifestEntry(
                effect_type="desktop.observe",
                executor_id="cell.desktop",
                side_effect_class="R0",
                idempotent=True,
                drafts_supported=True,
                etag_support=True,
                reconcile_query=False,
                content_args=("target", "request"),
                description_hash=description_hash_of(
                    "observe a desktop target inside the authenticated Desktop Cell"
                ),
            )
        )
        manifest.register(
            EffectManifestEntry(
                effect_type="desktop.action",
                executor_id="cell.desktop",
                side_effect_class="R2",
                idempotent=False,
                drafts_supported=True,
                etag_support=True,
                reconcile_query=True,
                permission_args={"desktop_target_handle": "desktop"},
                content_args=("action",),
                description_hash=description_hash_of(
                    "perform one exact action against an observed desktop target"
                ),
            )
        )
    if include_memory:
        manifest.register(
            EffectManifestEntry(
                effect_type="memory.read",
                executor_id="cell.memory",
                side_effect_class="R0",
                idempotent=True,
                drafts_supported=True,
                etag_support=True,
                reconcile_query=False,
                content_args=("owner_key_hash", "profile", "session_id", "key"),
                description_hash=description_hash_of(
                    "read one owner-scoped memory record inside the Memory Cell"
                ),
            )
        )
        manifest.register(
            EffectManifestEntry(
                effect_type="memory.write",
                executor_id="cell.memory",
                side_effect_class="R1",
                idempotent=True,
                drafts_supported=True,
                etag_support=True,
                reconcile_query=True,
                content_args=(
                    "owner_key_hash",
                    "profile",
                    "session_id",
                    "key",
                    "value",
                    "source",
                    "taint",
                    "clearance",
                ),
                description_hash=description_hash_of(
                    "insert one owner-scoped memory record inside the Memory Cell"
                ),
            )
        )
        manifest.register(
            EffectManifestEntry(
                effect_type="memory.mutate",
                executor_id="cell.memory",
                side_effect_class="R2",
                idempotent=False,
                drafts_supported=True,
                etag_support=True,
                reconcile_query=True,
                content_args=(
                    "owner_key_hash",
                    "profile",
                    "session_id",
                    "key",
                    "value",
                    "source",
                    "taint",
                    "clearance",
                ),
                description_hash=description_hash_of(
                    "mutate one owner-scoped memory record inside the Memory Cell"
                ),
            )
        )
    manifest.register(
        EffectManifestEntry(
            effect_type="artifact.read",
            executor_id="cell.file",
            side_effect_class="R0",
            idempotent=True,
            drafts_supported=False,
            etag_support=True,
            reconcile_query=True,
            permission_args={"directory_handle": "dirh"},
            description_hash=description_hash_of("read an approved workspace artifact"),
        )
    )
    manifest.register(
        EffectManifestEntry(
            effect_type="artifact.stage",
            executor_id="cell.file",
            side_effect_class="R1",
            idempotent=True,
            drafts_supported=True,
            etag_support=True,
            reconcile_query=True,
            description_hash=description_hash_of("write into task staging, never the live tree"),
        )
    )
    manifest.register(
        EffectManifestEntry(
            effect_type="net.fetch",
            executor_id="cell.net",
            side_effect_class="R0",
            idempotent=True,
            drafts_supported=False,
            etag_support=False,
            reconcile_query=False,
            permission_args={"endpoint_handle": "ep"},
            content_args=("url", "max_chars", "timeout_s"),
            description_hash=description_hash_of("fetch a signed endpoint manifest URL"),
        )
    )
    manifest.register(
        EffectManifestEntry(
            effect_type="shell.exec",
            executor_id="cell.build",
            side_effect_class="R2",
            idempotent=False,
            drafts_supported=False,
            etag_support=False,
            reconcile_query=False,
            description_hash=description_hash_of("run model-provided code inside the Build Cell"),
        )
    )
    manifest.register(
        EffectManifestEntry(
            effect_type="email.send_exact",
            executor_id="cell.connector",
            side_effect_class="R2",
            idempotent=True,
            drafts_supported=True,
            etag_support=False,
            reconcile_query=True,
            permission_args={"recipient_handle": "rcpt", "recipient_handles": "rcpt"},
            content_args=("subject", "body_draft"),
            description_hash=description_hash_of("send exact bytes to sealed recipients"),
        )
    )
    manifest.register(
        EffectManifestEntry(
            effect_type="file.commit",
            executor_id="cell.file",
            side_effect_class="R2",
            idempotent=True,
            drafts_supported=True,
            etag_support=True,
            reconcile_query=True,
            permission_args={"directory_handle": "dirh"},
            content_args=("changes",),
            description_hash=description_hash_of(
                "atomically rename staged files into the owner root"
            ),
        )
    )
    manifest.register(
        EffectManifestEntry(
            effect_type="bot.room.create",
            executor_id="cell.memory",
            side_effect_class="R2",
            idempotent=True,
            drafts_supported=True,
            etag_support=True,
            reconcile_query=True,
            permission_args={"member_bot_handles": "bot"},
            content_args=("title", "kind"),
            description_hash=description_hash_of(
                "create a bots room addressed only by sealed BotHandles"
            ),
        )
    )
    manifest.register(
        EffectManifestEntry(
            effect_type="bot.message.send",
            executor_id="cell.memory",
            side_effect_class="R1",
            idempotent=True,
            drafts_supported=True,
            etag_support=True,
            reconcile_query=True,
            permission_args={"room_handle": "room", "speaker_bot_handle": "bot"},
            content_args=("body",),
            description_hash=description_hash_of(
                "append one visible room bubble addressed by sealed handles"
            ),
        )
    )
    manifest.register(
        EffectManifestEntry(
            effect_type="bot.soul.write",
            executor_id="cell.memory",
            side_effect_class="R2",
            idempotent=True,
            drafts_supported=True,
            etag_support=True,
            reconcile_query=True,
            permission_args={"bot_handle": "bot"},
            content_args=("soul_text",),
            description_hash=description_hash_of(
                "write an owner-edited SOUL onto a sealed BotHandle"
            ),
        )
    )
    return manifest


__all__ = [
    "SIDE_EFFECT_CLASSES",
    "EffectManifest",
    "EffectManifestEntry",
    "builtin_manifest",
    "description_hash_of",
    "entry_from_dict",
    "validate_entry_dict",
]
