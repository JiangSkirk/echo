"""Strict R4 connector execution contracts.

The values in this module are safe authority references only.  Concrete
parameters stay at the runtime boundary, capability leases stay server-side,
and filesystem authority is the single R1 ``DirectoryGrantV1`` contract.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, cast

from js.echo.mode_contract import (
    AppMode,
    ArtifactRefV1,
    AttentionItemV1,
    ConnectionRefV1,
    ConnectorManifestV1,
    DirectoryGrantV1,
    TaskRef,
)
from js.echo.primitives import canonical_json_bytes
from js.echo.types import CapabilityLease

ConnectorOperation = Literal["read", "write"]

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$")
_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_LOCAL_CONNECTORS = frozenset({"local_import", "local_publish"})
_VAULT_HASH_DOMAIN = b"js-agent:vault-ref:v1\0"
_CONNECTION_V2_HASH_DOMAIN = b"js-agent:connection-ref-v2:v1\0"
_EXECUTION_HASH_DOMAIN = b"js-agent:connector-execution:v1\0"
_REQUEST_SAFE_FIELDS = frozenset(
    {
        "task_ref",
        "connection",
        "manifest",
        "operation",
        "scope",
        "params_digest",
        "directory_grant",
        "approval_id",
        "lease_id",
    }
)


def _require_exact_fields(payload: object, fields: frozenset[str], *, name: str) -> dict[str, object]:
    if type(payload) is not dict:
        raise TypeError(f"{name} payload must be an exact dict")
    if any(type(key) is not str for key in payload):
        raise TypeError(f"{name} field names must be strings")
    data = cast("dict[str, object]", payload)
    unknown = set(data) - fields
    missing = fields - set(data)
    if unknown:
        raise ValueError(f"{name} payload contains unknown fields")
    if missing:
        raise ValueError(f"{name} payload is missing required fields")
    return data


def _opaque_id(value: object, *, field: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{field} must be an opaque string")
    if (
        not value
        or len(value) > 192
        or value != value.strip()
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(char).startswith("C") for char in value)
        or "/" in value
        or "\\" in value
        or _OPAQUE_ID_RE.fullmatch(value) is None
    ):
        raise ValueError(f"{field} must be a canonical opaque ID")
    return value


def _digest(value: object, *, field: str) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be sha256: followed by 64 lowercase hex characters")
    return value


def _json_safe(value: object, *, path: str = "params") -> object:
    if value is None or type(value) in {bool, str}:
        return value
    if type(value) is int:
        return value
    if type(value) is float:
        if value != value or value in {float("inf"), float("-inf")}:
            raise ValueError(f"{path} contains a non-finite number")
        return value
    if type(value) is list:
        return [_json_safe(item, path=f"{path}[]") for item in cast("list[object]", value)]
    if type(value) is dict:
        raw = cast("dict[object, object]", value)
        if any(type(key) is not str for key in raw):
            raise TypeError(f"{path} contains a non-string key")
        return {
            cast("str", key): _json_safe(item, path=f"{path}.{key}")
            for key, item in raw.items()
        }
    raise TypeError(f"{path} contains a non-JSON value")


@dataclass(frozen=True, slots=True)
class VaultRefV1:
    """Opaque server-side reference to connection credentials."""

    vault_id: str
    mode: AppMode
    owner: str
    workspace: str | None
    connection_id: str

    def __post_init__(self) -> None:
        vault_id = _opaque_id(self.vault_id, field="vault_id")
        connection_id = _opaque_id(self.connection_id, field="connection_id")
        if type(self.mode) is not AppMode:
            raise TypeError("vault mode must be exact AppMode")
        task = TaskRef(
            mode=self.mode,
            owner=self.owner,
            session="vault-validation",
            run="vault-validation",
            workspace=self.workspace,
        )
        object.__setattr__(self, "vault_id", vault_id)
        object.__setattr__(self, "owner", task.owner)
        object.__setattr__(self, "workspace", task.workspace)
        object.__setattr__(self, "connection_id", connection_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "vault_id": self.vault_id,
            "mode": self.mode.value,
            "owner": self.owner,
            "workspace": self.workspace,
            "connection_id": self.connection_id,
        }

    @classmethod
    def from_dict(cls, payload: object) -> VaultRefV1:
        data = _require_exact_fields(
            payload,
            frozenset({"vault_id", "mode", "owner", "workspace", "connection_id"}),
            name="VaultRefV1",
        )
        try:
            mode = AppMode(cast("str", data["mode"]))
        except (TypeError, ValueError) as exc:
            raise ValueError("vault mode is invalid") from exc
        return cls(
            vault_id=cast("str", data["vault_id"]),
            mode=mode,
            owner=cast("str", data["owner"]),
            workspace=cast("str | None", data["workspace"]),
            connection_id=cast("str", data["connection_id"]),
        )

    def canonical_hash(self) -> str:
        return "sha256:" + hashlib.sha256(
            _VAULT_HASH_DOMAIN + canonical_json_bytes(self.to_dict())
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class ConnectionRefV2:
    """An R1 connection plus its exact manifest and optional vault binding."""

    ref: ConnectionRefV1
    manifest_digest: str
    vault_ref: VaultRefV1 | None

    def __post_init__(self) -> None:
        if type(self.ref) is not ConnectionRefV1:
            raise TypeError("connection ref must be exact ConnectionRefV1")
        _opaque_id(self.ref.connection_id, field="connection_id")
        digest = _digest(self.manifest_digest, field="manifest_digest")
        vault = self.vault_ref
        if vault is not None and type(vault) is not VaultRefV1:
            raise TypeError("vault_ref must be exact VaultRefV1 or None")
        if self.ref.connector_type in _LOCAL_CONNECTORS and vault is not None:
            raise ValueError("local connectors cannot carry a vault reference")
        if vault is not None and (
            vault.connection_id != self.ref.connection_id
            or vault.mode is not self.ref.mode
            or vault.owner != self.ref.owner
            or vault.workspace != self.ref.workspace
        ):
            raise ValueError("vault_ref does not match its connection authority")
        object.__setattr__(self, "manifest_digest", digest)

    def to_dict(self) -> dict[str, object]:
        return {
            "ref": self.ref.to_dict(),
            "manifest_digest": self.manifest_digest,
            "vault_ref": self.vault_ref.to_dict() if self.vault_ref is not None else None,
        }

    @classmethod
    def from_dict(cls, payload: object) -> ConnectionRefV2:
        data = _require_exact_fields(
            payload,
            frozenset({"ref", "manifest_digest", "vault_ref"}),
            name="ConnectionRefV2",
        )
        raw_vault = data["vault_ref"]
        return cls(
            ref=ConnectionRefV1.from_dict(data["ref"]),
            manifest_digest=cast("str", data["manifest_digest"]),
            vault_ref=None if raw_vault is None else VaultRefV1.from_dict(raw_vault),
        )

    def canonical_hash(self) -> str:
        return "sha256:" + hashlib.sha256(
            _CONNECTION_V2_HASH_DOMAIN + canonical_json_bytes(self.to_dict())
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class ConnectorExecutionRequestV1:
    """Complete connector authority binding with a server-issued lease."""

    task_ref: TaskRef
    connection: ConnectionRefV2
    manifest: ConnectorManifestV1
    operation: ConnectorOperation
    scope: str
    params_digest: str
    directory_grant: DirectoryGrantV1 | None
    approval_id: str | None
    lease: CapabilityLease

    def __post_init__(self) -> None:
        if type(self.task_ref) is not TaskRef:
            raise TypeError("task_ref must be exact TaskRef")
        if type(self.connection) is not ConnectionRefV2:
            raise TypeError("connection must be exact ConnectionRefV2")
        if type(self.manifest) is not ConnectorManifestV1:
            raise TypeError("manifest must be exact ConnectorManifestV1")
        if self.operation not in ("read", "write"):
            raise ValueError("connector operation must be read or write")
        if type(self.scope) is not str or not self.scope or self.scope != self.scope.strip():
            raise ValueError("connector scope is invalid")
        _digest(self.params_digest, field="params_digest")
        if self.directory_grant is not None and type(self.directory_grant) is not DirectoryGrantV1:
            raise TypeError("directory_grant must be exact DirectoryGrantV1 or None")
        if type(self.lease) is not CapabilityLease:
            raise TypeError("lease must be an exact server-issued CapabilityLease")

        ref = self.connection.ref
        task = self.task_ref
        if (
            ref.mode is not task.mode
            or ref.owner != task.owner
            or ref.workspace != task.workspace
            or ref.authorized_by != task.owner
        ):
            raise ValueError("connection authority does not match task_ref")
        if ref.connector_type != self.manifest.connector_type:
            raise ValueError("connection connector_type does not match manifest")
        if self.connection.manifest_digest != self.manifest.canonical_hash():
            raise ValueError("connection manifest digest does not match manifest")
        vault = self.connection.vault_ref
        if vault is not None and (
            vault.mode is not task.mode
            or vault.owner != task.owner
            or vault.workspace != task.workspace
        ):
            raise ValueError("vault authority does not match task_ref")
        grant = self.directory_grant
        if grant is not None and (
            grant.mode is not task.mode or grant.workspace != task.workspace
        ):
            raise ValueError("directory grant does not match task_ref")

        if self.operation == "read":
            if self.scope not in self.manifest.read_scopes:
                raise ValueError("scope is not declared by manifest read_scopes")
            if self.approval_id is not None:
                raise ValueError("read connector requests cannot carry approval_id")
        else:
            if self.scope not in self.manifest.write_scopes:
                raise ValueError("scope is not declared by manifest write_scopes")
            if self.manifest.approval_policy in {"read_only", "never"}:
                raise ValueError("manifest policy does not permit writes")
            _opaque_id(self.approval_id, field="approval_id")

    def authority_binding_hash(self) -> str:
        payload = {
            "task_ref_hash": self.task_ref.canonical_hash(),
            "connection_ref_hash": self.connection.canonical_hash(),
            "manifest_hash": self.manifest.canonical_hash(),
            "operation": self.operation,
            "scope": self.scope,
            "params_digest": self.params_digest,
            "directory_grant_hash": (
                self.directory_grant.canonical_hash()
                if self.directory_grant is not None
                else None
            ),
            "vault_ref_hash": (
                self.connection.vault_ref.canonical_hash()
                if self.connection.vault_ref is not None
                else None
            ),
        }
        return "sha256:" + hashlib.sha256(
            _EXECUTION_HASH_DOMAIN + canonical_json_bytes(payload)
        ).hexdigest()

    def to_safe_dict(self) -> dict[str, object]:
        return {
            "task_ref": self.task_ref.to_dict(),
            "connection": self.connection.to_dict(),
            "manifest": self.manifest.to_dict(),
            "operation": self.operation,
            "scope": self.scope,
            "params_digest": self.params_digest,
            "directory_grant": (
                self.directory_grant.to_dict() if self.directory_grant is not None else None
            ),
            "approval_id": self.approval_id,
            "lease_id": self.lease.lease_id,
        }

    @classmethod
    def from_dict(
        cls,
        payload: object,
        *,
        lease: CapabilityLease,
    ) -> ConnectorExecutionRequestV1:
        data = _require_exact_fields(payload, _REQUEST_SAFE_FIELDS, name="connector request")
        if type(lease) is not CapabilityLease:
            raise TypeError("request parsing requires a server-issued CapabilityLease")
        if data["lease_id"] != lease.lease_id:
            raise ValueError("safe lease reference does not match server lease")
        raw_grant = data["directory_grant"]
        return cls(
            task_ref=TaskRef.from_dict(data["task_ref"]),
            connection=ConnectionRefV2.from_dict(data["connection"]),
            manifest=ConnectorManifestV1.from_dict(data["manifest"]),
            operation=cast("ConnectorOperation", data["operation"]),
            scope=cast("str", data["scope"]),
            params_digest=cast("str", data["params_digest"]),
            directory_grant=(
                None if raw_grant is None else DirectoryGrantV1.from_dict(raw_grant)
            ),
            approval_id=cast("str | None", data["approval_id"]),
            lease=lease,
        )


@dataclass(frozen=True, slots=True)
class ConnectorEffect:
    effect_type: Literal["read", "publish"]
    target: str
    digest: str
    bytes_processed: int

    def __post_init__(self) -> None:
        if self.effect_type not in ("read", "publish"):
            raise ValueError("connector effect_type must be read or publish")
        if (
            type(self.target) is not str
            or not self.target
            or self.target.startswith("/")
            or unicodedata.normalize("NFC", self.target) != self.target
            or any(unicodedata.category(char).startswith("C") for char in self.target)
        ):
            raise ValueError("connector effect target must be a safe relative name")
        _digest(self.digest, field="effect digest")
        if type(self.bytes_processed) is not int or self.bytes_processed < 0:
            raise ValueError("bytes_processed must be a non-negative integer")

    def to_dict(self) -> dict[str, object]:
        return {
            "effect_type": self.effect_type,
            "target": self.target,
            "digest": self.digest,
            "bytes_processed": self.bytes_processed,
        }


@dataclass(frozen=True, slots=True)
class ConnectorRunOutcomeV1:
    success: bool
    connector_type: str
    effects: tuple[ConnectorEffect, ...]
    artifact_refs: tuple[ArtifactRefV1, ...]
    attention_items: tuple[AttentionItemV1, ...]
    receipt_id: str
    error_code: str | None = None

    def __post_init__(self) -> None:
        if type(self.success) is not bool:
            raise TypeError("success must be bool")
        _opaque_id(self.connector_type, field="connector_type")
        if type(self.effects) is not tuple or any(
            type(item) is not ConnectorEffect for item in self.effects
        ):
            raise TypeError("effects must be an immutable ConnectorEffect tuple")
        if type(self.artifact_refs) is not tuple or any(
            type(item) is not ArtifactRefV1 for item in self.artifact_refs
        ):
            raise TypeError("artifact_refs must be an immutable ArtifactRefV1 tuple")
        if type(self.attention_items) is not tuple or any(
            type(item) is not AttentionItemV1 for item in self.attention_items
        ):
            raise TypeError("attention_items must be an immutable AttentionItemV1 tuple")
        if type(self.receipt_id) is not str:
            raise TypeError("receipt_id must be text")
        if self.success and self.error_code is not None:
            raise ValueError("successful connector outcomes cannot carry error_code")
        if not self.success and (
            type(self.error_code) is not str
            or _ERROR_CODE_RE.fullmatch(self.error_code) is None
        ):
            raise ValueError("failed connector outcomes require a safe error_code")

    def to_dict(self) -> dict[str, object]:
        return {
            "success": self.success,
            "connector_type": self.connector_type,
            "effects": [item.to_dict() for item in self.effects],
            "artifact_refs": [item.to_dict() for item in self.artifact_refs],
            "attention_items": [item.to_dict() for item in self.attention_items],
            "receipt_id": self.receipt_id,
            "error_code": self.error_code,
        }


def canonical_params_digest(params: Mapping[str, Any]) -> str:
    """Return one RFC 8785 digest for an exact JSON-safe parameter mapping."""

    if not isinstance(params, Mapping) or isinstance(params, (str, bytes, bytearray)):
        raise TypeError("connector params must be a mapping")
    raw = dict(params)
    safe = _json_safe(raw)
    return "sha256:" + hashlib.sha256(canonical_json_bytes(safe)).hexdigest()


__all__ = [
    "ConnectionRefV2",
    "ConnectorEffect",
    "ConnectorExecutionRequestV1",
    "ConnectorOperation",
    "ConnectorRunOutcomeV1",
    "DirectoryGrantV1",
    "VaultRefV1",
    "canonical_params_digest",
]
