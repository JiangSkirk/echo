"""EffectDraft, StateWitness, CommitPermit and EffectReceipt (K§7.5/§7.6/§8.4/§8.5).

Echo outputs become permission-less drafts; Orin recomputes the real impact
from local Effect Manifests and never trusts ``declared_expectation``.
CommitPermits live on the orind→Cell connection only — the Echo-visible
projection of a permit is deliberately its id and nothing else.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import unicodedata
from dataclasses import dataclass
from typing import Any, Final, cast

from js.orin.handles import OriginHandle, handle_from_dict
from js.orin.protocol import MAX_FRAME_BYTES, MAX_SEQ, ProtocolError, canonical_json

DRAFT_ID_PREFIX: Final[str] = "draft:"
WITNESS_ID_PREFIX: Final[str] = "state:"
PERMIT_ID_PREFIX: Final[str] = "permit:"
RECEIPT_ID_PREFIX: Final[str] = "receipt:"

VISIBILITY_MODES: Final[frozenset[str]] = frozenset(
    {"private", "named_recipients", "tenant_internal", "public"}
)
REVERSIBILITY_MODES: Final[frozenset[str]] = frozenset(
    {"reversible_until_stage", "irreversible_after_provider_accept"}
)
IDEMPOTENCY_SUPPORTS: Final[frozenset[str]] = frozenset(
    {"provider_native", "client_key", "query_only", "none"}
)
RECEIPT_STATUSES: Final[frozenset[str]] = frozenset(
    {"COMMITTED", "UNKNOWN_COMMIT", "RECONCILED_COMMITTED", "RECONCILED_ABSENT", "FAILED"}
)


@dataclass(frozen=True, slots=True)
class EffectDraft:
    """Permission-less proposal produced by Echo."""

    draft_id: str
    task_id: str
    effect_type: str
    arguments: dict[str, Any]
    declared_expectation: dict[str, Any]

    def payload(self) -> str:
        return canonical_json(
            {
                "protocol": "orin/v1",
                "draft_id": self.draft_id,
                "task_id": self.task_id,
                "effect_type": self.effect_type,
                "arguments": self.arguments,
                "declared_expectation": self.declared_expectation,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return cast("dict[str, Any]", json.loads(self.payload()))


def validate_draft_dict(data: Any) -> None:
    if not isinstance(data, dict):
        raise ProtocolError("draft must be an object")
    known = {"protocol", "draft_id", "task_id", "effect_type", "arguments", "declared_expectation"}
    unknown = set(data) - known
    if unknown:
        raise ProtocolError(f"unknown draft fields {sorted(unknown)!r}")
    for key in ("draft_id", "task_id", "effect_type"):
        value = data.get(key)
        if not isinstance(value, str) or not value or len(value) > 256:
            raise ProtocolError(f"draft field {key!r} must be a bounded string")
    if not data["draft_id"].startswith(DRAFT_ID_PREFIX):
        raise ProtocolError("draft_id must start with 'draft:'")
    if not isinstance(data.get("arguments"), dict):
        raise ProtocolError("draft 'arguments' must be an object")
    expectation = data.get("declared_expectation")
    if not isinstance(expectation, dict):
        raise ProtocolError("draft 'declared_expectation' must be an object")
    for key in ("external_visibility", "reversibility"):
        value = expectation.get(key)
        if value is None:
            continue
        pool = VISIBILITY_MODES if key == "external_visibility" else REVERSIBILITY_MODES
        if value not in pool:
            raise ProtocolError(f"declared_expectation {key}={value!r} is not a known mode")


def draft_from_dict(data: dict[str, Any]) -> EffectDraft:
    validate_draft_dict(data)
    return EffectDraft(
        draft_id=data["draft_id"],
        task_id=data["task_id"],
        effect_type=data["effect_type"],
        arguments=dict(data["arguments"]),
        declared_expectation=dict(data.get("declared_expectation") or {}),
    )


PASS_ID_PREFIX: Final[str] = "export:"
EXACT_APPROVAL_ID_PREFIX: Final[str] = "exact:"
EXACT_APPROVAL_SCHEMA: Final[str] = "ExactCommitApprovalV1"


@dataclass(frozen=True, slots=True)
class ExportPass:
    """Two-phase egress permit (K§7.9): user approves exactly
    ``payload_hash + destination_handles (+ witness)`` — never prose."""

    pass_id: str
    task_id: str
    payload_hash: str
    destination_handles: tuple[str, ...]
    witness_id: str
    created_at_ms: int
    expires_at_ms: int
    signature: str = ""

    def __post_init__(self) -> None:
        # Valid passes have one canonical destination representation, so the
        # signed bytes and exact-match tuple are independent of input order.
        # Invalid duplicate-bearing objects remain constructible for negative
        # tests, but strict wire parsing/registration rejects them.
        try:
            canonical = canonical_destination_handles(self.destination_handles)
        except ProtocolError:
            return
        object.__setattr__(self, "destination_handles", canonical)

    def payload(self) -> str:
        return canonical_json(
            {
                "protocol": "orin/v1",
                "pass_id": self.pass_id,
                "task_id": self.task_id,
                "payload_hash": self.payload_hash,
                "destination_handles": list(self.destination_handles),
                "witness_id": self.witness_id,
                "created_at_ms": self.created_at_ms,
                "expires_at_ms": self.expires_at_ms,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        data = cast("dict[str, Any]", json.loads(self.payload()))
        data["signature"] = self.signature
        return data

    def sign_with(self, private_key: Any) -> ExportPass:
        from dataclasses import replace as _replace

        raw = private_key.sign(self.payload().encode("utf-8"))
        return _replace(self, signature=base64.b64encode(raw).decode("ascii"))

    def verify(self, public_key_b64: str) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519

            sig = base64.b64decode(self.signature, validate=True)
            pub = ed25519.Ed25519PublicKey.from_public_bytes(
                base64.b64decode(public_key_b64, validate=True)
            )
            pub.verify(sig, self.payload().encode("utf-8"))
            return True
        except Exception:  # noqa: BLE001 - any failure means invalid
            return False


def canonical_destination_handles(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Reject duplicates, then return the canonical sorted destination tuple."""

    if not isinstance(values, (list, tuple)) or not values or len(values) > 32:
        raise ProtocolError("destination_handles must contain 1..32 handles")
    if any(not isinstance(item, str) or not item or len(item) > 512 for item in values):
        raise ProtocolError("destination_handles must be bounded non-empty strings")
    if len(set(values)) != len(values):
        raise ProtocolError("destination_handles must not contain duplicates")
    return tuple(sorted(values))


def validate_export_pass_dict(data: Any) -> None:
    if not isinstance(data, dict):
        raise ProtocolError("export pass must be an object")
    known = {
        "protocol",
        "pass_id",
        "task_id",
        "payload_hash",
        "destination_handles",
        "witness_id",
        "created_at_ms",
        "expires_at_ms",
        "signature",
    }
    unknown = set(data) - known
    if unknown:
        raise ProtocolError(f"unknown export-pass fields {sorted(unknown)!r}")
    if data.get("protocol") != "orin/v1":
        raise ProtocolError("export pass protocol must be 'orin/v1'")
    if not str(data.get("pass_id", "")).startswith(PASS_ID_PREFIX):
        raise ProtocolError("pass_id must start with 'export:'")
    task_id = data.get("task_id")
    if not isinstance(task_id, str) or not task_id or len(task_id) > 256:
        raise ProtocolError("export pass task_id must be a bounded string")
    digest = data.get("payload_hash")
    if (
        not isinstance(digest, str)
        or len(digest) != 71
        or not digest.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in digest[7:])
    ):
        raise ProtocolError("payload_hash must be sha256:<64 hex>")
    dests = data.get("destination_handles")
    if not isinstance(dests, list):
        raise ProtocolError("destination_handles must be a list")
    canonical_destination_handles(dests)
    witness_id = data.get("witness_id")
    if (
        not isinstance(witness_id, str)
        or not witness_id.startswith(WITNESS_ID_PREFIX)
        or len(witness_id) > 256
    ):
        raise ProtocolError("export pass witness_id must be a bounded 'state:' id")
    for key in ("created_at_ms", "expires_at_ms"):
        value = data.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ProtocolError(f"export pass field {key!r} must be a positive integer")
    if data["expires_at_ms"] <= data["created_at_ms"]:
        raise ProtocolError("export pass expiry must follow creation")
    signature = data.get("signature")
    if not isinstance(signature, str) or len(signature) > 256:
        raise ProtocolError("export pass signature must be a bounded string")


def export_pass_from_dict(data: dict[str, Any]) -> ExportPass:
    validate_export_pass_dict(data)
    return ExportPass(
        pass_id=data["pass_id"],
        task_id=data["task_id"],
        payload_hash=data["payload_hash"],
        destination_handles=canonical_destination_handles(data["destination_handles"]),
        witness_id=data["witness_id"],
        created_at_ms=int(data["created_at_ms"]),
        expires_at_ms=int(data["expires_at_ms"]),
        signature=data["signature"],
    )


@dataclass(frozen=True, slots=True)
class ExactCommitApprovalV1:
    """One owner-signed approval for one exact preflighted file commit.

    This is deliberately not an :class:`ExportPass`: it has no destination
    or standing-authority semantics and is consumable only by a Personal
    ``file.commit`` whose draft, witness, effect hash, and DirectoryHandle all
    match exactly.
    """

    approval_id: str
    task_id: str
    draft_id: str
    witness_id: str
    canonical_effect_hash: str
    directory_handle_id: str
    approved: bool
    created_at_ms: int
    expires_at_ms: int
    signature: str = ""

    def payload(self) -> str:
        return canonical_json(
            {
                "schema": EXACT_APPROVAL_SCHEMA,
                "approval_id": self.approval_id,
                "task_id": self.task_id,
                "draft_id": self.draft_id,
                "witness_id": self.witness_id,
                "canonical_effect_hash": self.canonical_effect_hash,
                "directory_handle_id": self.directory_handle_id,
                "approved": self.approved,
                "created_at_ms": self.created_at_ms,
                "expires_at_ms": self.expires_at_ms,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        data = cast("dict[str, Any]", json.loads(self.payload()))
        data["signature"] = self.signature
        return data

    def sign_with(self, private_key: Any) -> ExactCommitApprovalV1:
        from dataclasses import replace as _replace

        raw = private_key.sign(self.payload().encode("utf-8"))
        return _replace(self, signature=base64.b64encode(raw).decode("ascii"))

    def verify(self, public_key_b64: str) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519

            sig = base64.b64decode(self.signature, validate=True)
            pub = ed25519.Ed25519PublicKey.from_public_bytes(
                base64.b64decode(public_key_b64, validate=True)
            )
            pub.verify(sig, self.payload().encode("utf-8"))
            return True
        except Exception:  # noqa: BLE001 - any failure means invalid
            return False


def validate_exact_commit_approval_dict(data: Any) -> None:
    if not isinstance(data, dict):
        raise ProtocolError("exact commit approval must be an object")
    known = {
        "schema",
        "approval_id",
        "task_id",
        "draft_id",
        "witness_id",
        "canonical_effect_hash",
        "directory_handle_id",
        "approved",
        "created_at_ms",
        "expires_at_ms",
        "signature",
    }
    unknown = set(data) - known
    missing = known - set(data)
    if unknown:
        raise ProtocolError(f"unknown exact-approval fields {sorted(unknown)!r}")
    if missing:
        raise ProtocolError(f"missing exact-approval fields {sorted(missing)!r}")
    if data.get("schema") != EXACT_APPROVAL_SCHEMA:
        raise ProtocolError(f"exact approval schema must be {EXACT_APPROVAL_SCHEMA!r}")
    identifiers = {
        "approval_id": EXACT_APPROVAL_ID_PREFIX,
        "task_id": "task:",
        "draft_id": DRAFT_ID_PREFIX,
        "witness_id": WITNESS_ID_PREFIX,
        "directory_handle_id": "dirh:",
    }
    for name, prefix in identifiers.items():
        value = data.get(name)
        if not isinstance(value, str) or not value.startswith(prefix) or len(value) > 512:
            raise ProtocolError(f"exact approval {name} must be a bounded {prefix!r} id")
    digest = data.get("canonical_effect_hash")
    if (
        not isinstance(digest, str)
        or len(digest) != 71
        or not digest.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in digest[7:])
    ):
        raise ProtocolError("exact approval canonical_effect_hash must be sha256:<64 hex>")
    if type(data.get("approved")) is not bool or data["approved"] is not True:
        raise ProtocolError("exact approval approved must be the boolean true")
    for key in ("created_at_ms", "expires_at_ms"):
        value = data.get(key)
        if type(value) is not int or not 0 < value <= MAX_SEQ:
            raise ProtocolError(f"exact approval {key} must be a positive u64 integer")
    if data["expires_at_ms"] <= data["created_at_ms"]:
        raise ProtocolError("exact approval expiry must follow creation")
    signature = data.get("signature")
    if not isinstance(signature, str) or len(signature) > 256:
        raise ProtocolError("exact approval signature must be a bounded string")


def exact_commit_approval_from_dict(data: dict[str, Any]) -> ExactCommitApprovalV1:
    validate_exact_commit_approval_dict(data)
    return ExactCommitApprovalV1(
        approval_id=data["approval_id"],
        task_id=data["task_id"],
        draft_id=data["draft_id"],
        witness_id=data["witness_id"],
        canonical_effect_hash=data["canonical_effect_hash"],
        directory_handle_id=data["directory_handle_id"],
        approved=data["approved"],
        created_at_ms=data["created_at_ms"],
        expires_at_ms=data["expires_at_ms"],
        signature=data["signature"],
    )


@dataclass(frozen=True, slots=True)
class Impact:
    writes: int = 0
    recipients: int = 0
    bytes_out: int = 0
    cost_upper_bound: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "writes": self.writes,
            "recipients": self.recipients,
            "bytes_out": self.bytes_out,
            "cost_upper_bound": self.cost_upper_bound,
        }


FILE_COMMIT_PREVIEW_SCHEMA: Final[str] = "FileCommitPreviewV1"


@dataclass(frozen=True, slots=True)
class FileCommitPreviewV1:
    """Small machine-only projection of a File Cell staging report."""

    file_count: int
    bytes: int
    overwrites: tuple[str, ...]
    diff_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": FILE_COMMIT_PREVIEW_SCHEMA,
            "file_count": self.file_count,
            "bytes": self.bytes,
            "overwrites": list(self.overwrites),
            "diff_hash": self.diff_hash,
        }


def validate_file_commit_preview_dict(data: Any) -> None:
    if not isinstance(data, dict):
        raise ProtocolError("file commit preview must be an object")
    known = {"schema", "file_count", "bytes", "overwrites", "diff_hash"}
    unknown = set(data) - known
    missing = known - set(data)
    if unknown:
        raise ProtocolError(f"unknown file commit preview fields {sorted(unknown)!r}")
    if missing:
        raise ProtocolError(f"missing file commit preview fields {sorted(missing)!r}")
    if data.get("schema") != FILE_COMMIT_PREVIEW_SCHEMA:
        raise ProtocolError(f"file commit preview schema must be {FILE_COMMIT_PREVIEW_SCHEMA!r}")
    file_count = data.get("file_count")
    byte_count = data.get("bytes")
    if type(file_count) is not int or not 1 <= file_count <= 128:
        raise ProtocolError("file commit preview file_count must be an integer in 1..128")
    if type(byte_count) is not int or not 0 <= byte_count <= 8 * 1024 * 1024:
        raise ProtocolError("file commit preview bytes must be in 0..8 MiB")
    overwrites = data.get("overwrites")
    if not isinstance(overwrites, list) or len(overwrites) > file_count:
        raise ProtocolError("file commit preview overwrites must be a bounded list")
    normalized_paths: list[str] = []
    for path in overwrites:
        if not isinstance(path, str) or not path or len(path.encode("utf-8")) > 1_024:
            raise ProtocolError("file commit preview overwrite must be a bounded path")
        if path.startswith(("/", "\\")) or "\\" in path:
            raise ProtocolError("file commit preview overwrite must be a relative POSIX path")
        parts = path.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise ProtocolError("file commit preview overwrite contains an unsafe component")
        if unicodedata.normalize("NFC", path) != path:
            raise ProtocolError("file commit preview overwrite must be NFC normalized")
        if any(
            len(part.encode("utf-8")) > 255
            or part.casefold() == ".git"
            or any(unicodedata.category(char).startswith("C") for char in part)
            for part in parts
        ):
            raise ProtocolError("file commit preview overwrite contains an unsafe component")
        normalized_paths.append(path)
    folded_paths = {path.casefold() for path in normalized_paths}
    if len(set(normalized_paths)) != len(normalized_paths) or len(folded_paths) != len(
        normalized_paths
    ):
        raise ProtocolError("file commit preview overwrites must be NFC/casefold unique")
    diff_hash = data.get("diff_hash")
    if (
        not isinstance(diff_hash, str)
        or len(diff_hash) != 71
        or not diff_hash.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in diff_hash[7:])
    ):
        raise ProtocolError("file commit preview diff_hash must be sha256:<64 hex>")


def file_commit_preview_from_dict(data: dict[str, Any]) -> FileCommitPreviewV1:
    validate_file_commit_preview_dict(data)
    return FileCommitPreviewV1(
        file_count=data["file_count"],
        bytes=data["bytes"],
        overwrites=tuple(data["overwrites"]),
        diff_hash=data["diff_hash"],
    )


@dataclass(frozen=True, slots=True)
class StateWitness:
    """Read-only preflight truth returned by the target Cell."""

    witness_id: str
    draft_id: str
    executor_id: str
    target_version: str
    canonical_effect_hash: str
    impact: Impact
    reversibility: str
    idempotency_support: str
    created_at_ms: int
    expires_at_ms: int
    file_commit_preview: FileCommitPreviewV1 | None = None

    def payload(self) -> str:
        body: dict[str, Any] = {
            "witness_id": self.witness_id,
            "draft_id": self.draft_id,
            "executor_id": self.executor_id,
            "target_version": self.target_version,
            "canonical_effect_hash": self.canonical_effect_hash,
            "impact": self.impact.to_dict(),
            "reversibility": self.reversibility,
            "idempotency_support": self.idempotency_support,
            "created_at_ms": self.created_at_ms,
            "expires_at_ms": self.expires_at_ms,
        }
        if self.file_commit_preview is not None:
            body["file_commit_preview"] = self.file_commit_preview.to_dict()
        return canonical_json(body)

    def to_dict(self) -> dict[str, Any]:
        return cast("dict[str, Any]", json.loads(self.payload()))

    def expired(self, now_ms: int) -> bool:
        return now_ms >= self.expires_at_ms


def validate_witness_dict(data: Any) -> None:
    if not isinstance(data, dict):
        raise ProtocolError("witness must be an object")
    known = {
        "witness_id",
        "draft_id",
        "executor_id",
        "target_version",
        "canonical_effect_hash",
        "impact",
        "reversibility",
        "idempotency_support",
        "created_at_ms",
        "expires_at_ms",
        "file_commit_preview",
    }
    unknown = set(data) - known
    if unknown:
        raise ProtocolError(f"unknown witness fields {sorted(unknown)!r}")
    for key in ("witness_id", "draft_id", "executor_id", "target_version"):
        value = data.get(key)
        if not isinstance(value, str) or not value or len(value) > 256:
            raise ProtocolError(f"witness field {key!r} must be a bounded string")
    if not data["witness_id"].startswith(WITNESS_ID_PREFIX):
        raise ProtocolError("witness_id must start with 'state:'")
    digest = data.get("canonical_effect_hash")
    if (
        not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or len(digest) != 71
        or any(c not in "0123456789abcdef" for c in digest[7:])
    ):
        raise ProtocolError("canonical_effect_hash must be sha256:<64 hex>")
    impact = data.get("impact")
    if not isinstance(impact, dict):
        raise ProtocolError("witness 'impact' must be an object")
    for key in ("writes", "recipients", "bytes_out", "cost_upper_bound"):
        value = impact.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_SEQ:
            raise ProtocolError(f"impact {key!r} must be a u64 integer")
    if data.get("reversibility") not in REVERSIBILITY_MODES:
        raise ProtocolError("witness reversibility must be a known mode")
    if data.get("idempotency_support") not in IDEMPOTENCY_SUPPORTS:
        raise ProtocolError("witness idempotency_support must be a known mode")
    for key in ("created_at_ms", "expires_at_ms"):
        value = data.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= MAX_SEQ:
            raise ProtocolError(f"witness field {key!r} must be a positive u64")
    preview = data.get("file_commit_preview")
    if preview is not None:
        if data.get("executor_id") != "cell.file":
            raise ProtocolError("file commit preview is valid only for cell.file witnesses")
        validate_file_commit_preview_dict(preview)
        if preview["file_count"] != impact["writes"]:
            raise ProtocolError("file commit preview file_count must equal witness impact writes")


def witness_from_dict(data: dict[str, Any]) -> StateWitness:
    validate_witness_dict(data)
    return StateWitness(
        witness_id=data["witness_id"],
        draft_id=data["draft_id"],
        executor_id=data["executor_id"],
        target_version=data["target_version"],
        canonical_effect_hash=data["canonical_effect_hash"],
        impact=Impact(**{k: int(data["impact"][k]) for k in Impact.__dataclass_fields__}),
        reversibility=data["reversibility"],
        idempotency_support=data["idempotency_support"],
        created_at_ms=int(data["created_at_ms"]),
        expires_at_ms=int(data["expires_at_ms"]),
        file_commit_preview=(
            file_commit_preview_from_dict(data["file_commit_preview"])
            if isinstance(data.get("file_commit_preview"), dict)
            else None
        ),
    )


@dataclass(frozen=True, slots=True)
class CommitPermit:
    """Issued by orind onto the authenticated Cell connection only.

    ``echo_visible()`` is the contract that keeps permits out of Echo:
    anything richer leaking into a tool result is a test-failing violation.
    """

    permit_id: str
    intent_id: str
    draft_id: str
    state_witness_id: str
    executor_id: str
    canonical_effect_hash: str
    idempotency_key: str
    sequence: int
    not_before_ms: int
    expires_at_ms: int

    def payload(self) -> str:
        return canonical_json(
            {
                "protocol": "orin/v1",
                "permit_id": self.permit_id,
                "intent_id": self.intent_id,
                "draft_id": self.draft_id,
                "state_witness_id": self.state_witness_id,
                "executor_id": self.executor_id,
                "canonical_effect_hash": self.canonical_effect_hash,
                "idempotency_key": self.idempotency_key,
                "sequence": self.sequence,
                "not_before_ms": self.not_before_ms,
                "expires_at_ms": self.expires_at_ms,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return cast("dict[str, Any]", json.loads(self.payload()))

    def echo_visible(self) -> dict[str, str]:
        return {"permit_id": self.permit_id}


def validate_permit_dict(data: Any) -> None:
    if not isinstance(data, dict):
        raise ProtocolError("permit must be an object")
    known = {
        "protocol",
        "permit_id",
        "intent_id",
        "draft_id",
        "state_witness_id",
        "executor_id",
        "canonical_effect_hash",
        "idempotency_key",
        "sequence",
        "not_before_ms",
        "expires_at_ms",
    }
    unknown = set(data) - known
    if unknown:
        raise ProtocolError(f"unknown permit fields {sorted(unknown)!r}")
    if data.get("protocol") != "orin/v1":
        raise ProtocolError("permit protocol must be 'orin/v1'")
    for key in ("permit_id", "intent_id", "draft_id", "state_witness_id", "executor_id"):
        value = data.get(key)
        if not isinstance(value, str) or not value or len(value) > 256:
            raise ProtocolError(f"permit field {key!r} must be a bounded string")
    if not data["permit_id"].startswith(PERMIT_ID_PREFIX):
        raise ProtocolError("permit_id must start with 'permit:'")
    for key, prefix in (
        ("intent_id", "intent:"),
        ("draft_id", DRAFT_ID_PREFIX),
        ("state_witness_id", WITNESS_ID_PREFIX),
    ):
        if not data[key].startswith(prefix):
            raise ProtocolError(f"permit field {key!r} must start with {prefix!r}")
    if not data["executor_id"].startswith(("cell.", "cell:")):
        raise ProtocolError("permit executor_id must name a cell executor")
    digest = data.get("canonical_effect_hash")
    if (
        not isinstance(digest, str)
        or len(digest) != 71
        or not digest.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in digest[7:])
    ):
        raise ProtocolError("permit canonical_effect_hash must be sha256:<64 hex>")
    idempotency_key = data.get("idempotency_key")
    if not isinstance(idempotency_key, str) or not idempotency_key or len(idempotency_key) > 256:
        raise ProtocolError("permit idempotency_key must be a bounded string")
    for key in ("sequence", "not_before_ms", "expires_at_ms"):
        value = data.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_SEQ:
            raise ProtocolError(f"permit field {key!r} must be a u64 integer")
    if data["sequence"] < 1:
        raise ProtocolError("permit sequence must be positive")
    if data["expires_at_ms"] <= data["not_before_ms"]:
        raise ProtocolError("permit expiry must follow not_before")


def permit_from_dict(data: dict[str, Any]) -> CommitPermit:
    validate_permit_dict(data)
    return CommitPermit(
        permit_id=data["permit_id"],
        intent_id=data["intent_id"],
        draft_id=data["draft_id"],
        state_witness_id=data["state_witness_id"],
        executor_id=data["executor_id"],
        canonical_effect_hash=data["canonical_effect_hash"],
        idempotency_key=data["idempotency_key"],
        sequence=int(data["sequence"]),
        not_before_ms=int(data["not_before_ms"]),
        expires_at_ms=int(data["expires_at_ms"]),
    )


@dataclass(frozen=True, slots=True)
class CellPackage:
    """Strict Orind -> Cell execution package carried only on ``cells.sock``.

    The package is a peer field beside :class:`CommitPermit`; neither object
    embeds the other.  Preflight packages omit ``state_witness`` while commit
    packages must include it and bind it exactly to the permit.
    """

    draft: EffectDraft
    executor_id: str
    canonical_effect_hash: str
    resolved_handles: tuple[OriginHandle, ...]
    clearance: int
    state_witness: StateWitness | None = None
    protocol: str = "orin/v1"

    def payload(self) -> str:
        body: dict[str, Any] = {
            "protocol": self.protocol,
            "draft": self.draft.to_dict(),
            "executor_id": self.executor_id,
            "canonical_effect_hash": self.canonical_effect_hash,
            "resolved_handles": [handle.to_dict() for handle in self.resolved_handles],
            "clearance": self.clearance,
        }
        if self.state_witness is not None:
            body["state_witness"] = self.state_witness.to_dict()
        return canonical_json(body)

    def to_dict(self) -> dict[str, Any]:
        return cast("dict[str, Any]", json.loads(self.payload()))

    def validate_binding(
        self,
        permit: CommitPermit | None = None,
        *,
        require_witness: bool = False,
    ) -> None:
        """Reject any package/witness/permit identity mismatch."""

        canonical_body = canonical_json(
            {
                "effect_type": self.draft.effect_type,
                "arguments": {
                    key: (
                        sorted(value)
                        if key.endswith("_handles")
                        and isinstance(value, list)
                        and all(isinstance(item, str) for item in value)
                        else value
                    )
                    for key, value in sorted(self.draft.arguments.items())
                },
            }
        )
        recomputed_hash = "sha256:" + hashlib.sha256(canonical_body.encode("utf-8")).hexdigest()
        if self.canonical_effect_hash != recomputed_hash:
            raise ProtocolError("cell package canonical hash does not match draft")
        referenced_handles: set[str] = set()
        for key, value in self.draft.arguments.items():
            if key.endswith("_handle"):
                if isinstance(value, str):
                    referenced_handles.add(value)
            elif key.endswith("_handles") and isinstance(value, list):
                referenced_handles.update(item for item in value if isinstance(item, str))
        resolved_handle_ids = {handle.handle_id for handle in self.resolved_handles}
        application_ids = {
            handle.handle_id
            for handle in self.resolved_handles
            if handle.kind == "ApplicationHandle"
        }
        # Owner-issued ApplicationHandles are attached by orind from the
        # Intent; desktop observe/action drafts do not name them.  Every other
        # resolved handle must still exactly match the draft references.
        if (
            not referenced_handles.issubset(resolved_handle_ids)
            or (resolved_handle_ids - application_ids) - referenced_handles
        ):
            raise ProtocolError("cell package resolved handles do not exactly match draft")
        witness = self.state_witness
        if require_witness and witness is None:
            raise ProtocolError("commit package requires a state_witness")
        if witness is not None:
            if witness.draft_id != self.draft.draft_id:
                raise ProtocolError("package witness draft mismatch")
            if witness.executor_id != self.executor_id:
                raise ProtocolError("package witness executor mismatch")
            if witness.canonical_effect_hash != self.canonical_effect_hash:
                raise ProtocolError("package witness canonical hash mismatch")
        if permit is None:
            return
        if witness is None:
            raise ProtocolError("permit binding requires a state_witness")
        if permit.draft_id != self.draft.draft_id:
            raise ProtocolError("package permit draft mismatch")
        if permit.executor_id != self.executor_id:
            raise ProtocolError("package permit executor mismatch")
        if permit.canonical_effect_hash != self.canonical_effect_hash:
            raise ProtocolError("package permit canonical hash mismatch")
        if permit.state_witness_id != witness.witness_id:
            raise ProtocolError("package permit witness mismatch")


def validate_cell_package_dict(
    data: Any,
    *,
    require_witness: bool = False,
    permit: CommitPermit | None = None,
) -> None:
    """Strictly validate a CellPackage wire object and its cross-bindings."""

    if not isinstance(data, dict):
        raise ProtocolError("cell package must be an object")
    known = {
        "protocol",
        "draft",
        "executor_id",
        "canonical_effect_hash",
        "resolved_handles",
        "clearance",
        "state_witness",
    }
    unknown = set(data) - known
    if unknown:
        raise ProtocolError(f"unknown cell-package fields {sorted(unknown)!r}")
    required = known - {"state_witness"}
    missing = required - set(data)
    if missing:
        raise ProtocolError(f"missing cell-package fields {sorted(missing)!r}")
    if data.get("protocol") != "orin/v1":
        raise ProtocolError("cell package protocol must be 'orin/v1'")
    try:
        encoded_size = len(canonical_json(data).encode("utf-8"))
    except (RecursionError, TypeError, ValueError) as exc:
        raise ProtocolError("cell package must be bounded canonical JSON") from exc
    if encoded_size > MAX_FRAME_BYTES:
        raise ProtocolError("cell package exceeds 64KiB")

    draft_data = data.get("draft")
    if not isinstance(draft_data, dict):
        raise ProtocolError("cell package draft must be an object")
    if draft_data.get("protocol") != "orin/v1":
        raise ProtocolError("cell package draft protocol must be 'orin/v1'")
    draft = draft_from_dict(draft_data)
    executor_id = data.get("executor_id")
    if (
        not isinstance(executor_id, str)
        or not executor_id.startswith("cell.")
        or len(executor_id) > 128
    ):
        raise ProtocolError("cell package executor_id must name a bounded 'cell.*' executor")
    digest = data.get("canonical_effect_hash")
    if (
        not isinstance(digest, str)
        or len(digest) != 71
        or not digest.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in digest[7:])
    ):
        raise ProtocolError("cell package canonical_effect_hash must be sha256:<64 hex>")
    clearance = data.get("clearance")
    if not isinstance(clearance, int) or isinstance(clearance, bool) or clearance not in (0, 1, 2):
        raise ProtocolError("cell package clearance must be 0, 1, or 2")
    raw_handles = data.get("resolved_handles")
    if not isinstance(raw_handles, list) or len(raw_handles) > 64:
        raise ProtocolError("cell package resolved_handles must be a list of at most 64 handles")
    handles: list[OriginHandle] = []
    seen_handles: set[str] = set()
    for raw_handle in raw_handles:
        if not isinstance(raw_handle, dict):
            raise ProtocolError("cell package resolved handle must be an object")
        handle = handle_from_dict(raw_handle, require_signature=True)
        if handle.handle_id in seen_handles:
            raise ProtocolError("cell package contains duplicate resolved handles")
        seen_handles.add(handle.handle_id)
        handles.append(handle)

    raw_witness = data.get("state_witness")
    witness: StateWitness | None = None
    if raw_witness is not None:
        if not isinstance(raw_witness, dict):
            raise ProtocolError("cell package state_witness must be an object")
        witness = witness_from_dict(raw_witness)
    package = CellPackage(
        protocol="orin/v1",
        draft=draft,
        executor_id=executor_id,
        canonical_effect_hash=digest,
        resolved_handles=tuple(handles),
        clearance=clearance,
        state_witness=witness,
    )
    package.validate_binding(permit, require_witness=require_witness)


def cell_package_from_dict(
    data: dict[str, Any],
    *,
    require_witness: bool = False,
    permit: CommitPermit | None = None,
) -> CellPackage:
    validate_cell_package_dict(data, require_witness=require_witness, permit=permit)
    raw_witness = data.get("state_witness")
    return CellPackage(
        protocol="orin/v1",
        draft=draft_from_dict(data["draft"]),
        executor_id=data["executor_id"],
        canonical_effect_hash=data["canonical_effect_hash"],
        resolved_handles=tuple(
            handle_from_dict(item, require_signature=True) for item in data["resolved_handles"]
        ),
        clearance=int(data["clearance"]),
        state_witness=witness_from_dict(raw_witness) if isinstance(raw_witness, dict) else None,
    )


@dataclass(frozen=True, slots=True)
class EffectReceipt:
    """Cell-reported outcome; digests only — no secret material, ever."""

    receipt_id: str
    permit_id: str
    executor_id: str
    status: str
    remote_operation_id: str
    committed_effect_hash: str
    result_digest: str
    started_at_ms: int
    finished_at_ms: int
    previous_receipt_hash: str

    def payload(self) -> str:
        return canonical_json(
            {
                "receipt_id": self.receipt_id,
                "permit_id": self.permit_id,
                "executor_id": self.executor_id,
                "status": self.status,
                "remote_operation_id": self.remote_operation_id,
                "committed_effect_hash": self.committed_effect_hash,
                "result_digest": self.result_digest,
                "started_at_ms": self.started_at_ms,
                "finished_at_ms": self.finished_at_ms,
                "previous_receipt_hash": self.previous_receipt_hash,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return cast("dict[str, Any]", json.loads(self.payload()))


def validate_receipt_dict(data: Any) -> None:
    if not isinstance(data, dict):
        raise ProtocolError("receipt must be an object")
    known = {
        "receipt_id",
        "permit_id",
        "executor_id",
        "status",
        "remote_operation_id",
        "committed_effect_hash",
        "result_digest",
        "started_at_ms",
        "finished_at_ms",
        "previous_receipt_hash",
    }
    unknown = set(data) - known
    if unknown:
        raise ProtocolError(f"unknown receipt fields {sorted(unknown)!r}")
    receipt_id = data.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id.startswith(RECEIPT_ID_PREFIX):
        raise ProtocolError("receipt_id must start with 'receipt:'")
    if data.get("status") not in RECEIPT_STATUSES:
        raise ProtocolError(f"unknown receipt status {data.get('status')!r}")
    for key in ("permit_id", "executor_id", "remote_operation_id", "result_digest"):
        value = data.get(key)
        if not isinstance(value, str) or len(value) > 512:
            raise ProtocolError(f"receipt field {key!r} must be a bounded string")
    for key in ("started_at_ms", "finished_at_ms"):
        value = data.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_SEQ:
            raise ProtocolError(f"receipt field {key!r} must be a u64 integer")


SIGNED_RECEIPT_SCHEMA: Final[str] = "receipt.signed.v1"
_SIGNED_SEAL_PREFIX: Final[str] = "orin-hmac-sha256:"


@dataclass(frozen=True, slots=True)
class SignedEffectReceiptV1:
    """HMAC-sealed Cell outcome.  DecisionReceipt is not a substitute."""

    schema: str
    receipt: EffectReceipt
    signature: str

    def payload(self) -> str:
        return canonical_json(
            {
                "schema": self.schema,
                "receipt": self.receipt.to_dict(),
            }
        )

    def sealed_by(self, mac_key: bytes) -> SignedEffectReceiptV1:
        if not isinstance(mac_key, bytes) or len(mac_key) != 32:
            raise ProtocolError("signed receipt mac key must be 32 bytes")
        digest = hmac.new(
            mac_key,
            self.payload().encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return SignedEffectReceiptV1(
            schema=SIGNED_RECEIPT_SCHEMA,
            receipt=self.receipt,
            signature=_SIGNED_SEAL_PREFIX + digest,
        )

    def verify_seal(self, mac_key: bytes) -> bool:
        if self.schema != SIGNED_RECEIPT_SCHEMA:
            return False
        if not self.signature.startswith(_SIGNED_SEAL_PREFIX):
            return False
        expected = self.sealed_by(mac_key).signature
        return hmac.compare_digest(self.signature, expected)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "receipt": self.receipt.to_dict(),
            "signature": self.signature,
        }


def signed_receipt_from_dict(data: Any, *, mac_key: bytes | None = None) -> SignedEffectReceiptV1:
    if not isinstance(data, dict):
        raise ProtocolError("signed receipt must be an object")
    if data.get("kind") is not None and data.get("verdict") is not None:
        raise ProtocolError("DecisionReceipt is not a Cell EffectReceipt")
    if data.get("schema") != SIGNED_RECEIPT_SCHEMA:
        raise ProtocolError("signed receipt schema must be receipt.signed.v1")
    raw_receipt = data.get("receipt")
    if not isinstance(raw_receipt, dict):
        raise ProtocolError("signed receipt payload is invalid")
    receipt = receipt_from_dict(raw_receipt)
    signed = SignedEffectReceiptV1(
        schema=SIGNED_RECEIPT_SCHEMA,
        receipt=receipt,
        signature=str(data.get("signature") or ""),
    )
    if mac_key is not None and not signed.verify_seal(mac_key):
        raise ProtocolError("signed receipt seal is invalid")
    return signed


def seal_signed_effect_receipt(
    *,
    mac_key: bytes,
    permit_id: str,
    executor_id: str,
    status: str,
    canonical_effect_hash: str,
    result_digest: str,
    started_at_ms: int,
    finished_at_ms: int,
    receipt_id: str,
    remote_operation_id: str = "",
    previous_receipt_hash: str = "",
) -> str:
    """Return canonical JSON for one HMAC-sealed Cell EffectReceipt."""

    signed = SignedEffectReceiptV1(
        schema=SIGNED_RECEIPT_SCHEMA,
        receipt=EffectReceipt(
            receipt_id=receipt_id,
            permit_id=permit_id,
            executor_id=executor_id,
            status=status,
            remote_operation_id=remote_operation_id,
            committed_effect_hash=canonical_effect_hash,
            result_digest=result_digest,
            started_at_ms=started_at_ms,
            finished_at_ms=finished_at_ms,
            previous_receipt_hash=previous_receipt_hash,
        ),
        signature="",
    ).sealed_by(mac_key)
    return canonical_json(signed.to_dict())


def receipt_from_dict(data: dict[str, Any]) -> EffectReceipt:
    validate_receipt_dict(data)
    return EffectReceipt(
        receipt_id=data["receipt_id"],
        permit_id=data["permit_id"],
        executor_id=data["executor_id"],
        status=data["status"],
        remote_operation_id=data["remote_operation_id"],
        committed_effect_hash=data.get("committed_effect_hash", ""),
        result_digest=data.get("result_digest", ""),
        started_at_ms=int(data["started_at_ms"]),
        finished_at_ms=int(data["finished_at_ms"]),
        previous_receipt_hash=data.get("previous_receipt_hash", ""),
    )


__all__ = [
    "CellPackage",
    "CommitPermit",
    "DRAFT_ID_PREFIX",
    "EXACT_APPROVAL_ID_PREFIX",
    "EXACT_APPROVAL_SCHEMA",
    "ExactCommitApprovalV1",
    "ExportPass",
    "EffectDraft",
    "EffectReceipt",
    "FILE_COMMIT_PREVIEW_SCHEMA",
    "FileCommitPreviewV1",
    "IDEMPOTENCY_SUPPORTS",
    "Impact",
    "PERMIT_ID_PREFIX",
    "RECEIPT_STATUSES",
    "SIGNED_RECEIPT_SCHEMA",
    "SignedEffectReceiptV1",
    "StateWitness",
    "VISIBILITY_MODES",
    "canonical_destination_handles",
    "cell_package_from_dict",
    "draft_from_dict",
    "exact_commit_approval_from_dict",
    "export_pass_from_dict",
    "file_commit_preview_from_dict",
    "permit_from_dict",
    "receipt_from_dict",
    "seal_signed_effect_receipt",
    "signed_receipt_from_dict",
    "validate_draft_dict",
    "validate_cell_package_dict",
    "validate_export_pass_dict",
    "validate_exact_commit_approval_dict",
    "validate_file_commit_preview_dict",
    "validate_permit_dict",
    "validate_receipt_dict",
    "validate_witness_dict",
    "witness_from_dict",
]
