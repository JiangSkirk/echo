"""Final connector dispatch shells and test-only connector implementations."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Literal, cast

from js.connectors.contracts import ConnectorEffect, DirectoryGrantV1
from js.echo.mode_contract import ArtifactRefV1, ConnectorManifestV1

if TYPE_CHECKING:
    from js.connectors.manager import ConnectorManager

_AUTHORITY_REQUIRED: Final = "connector_runtime_authority_required"
_PERMIT_FACTORY_KEY = object()


class _ConnectorPermitIssuer:
    __slots__ = ("manager",)

    def __init__(self, factory_key: object, *, manager: object) -> None:
        if factory_key is not _PERMIT_FACTORY_KEY:
            raise PermissionError(_AUTHORITY_REQUIRED)
        self.manager = manager


def _new_dispatch_permit_issuer(*, manager: object) -> _ConnectorPermitIssuer:
    return _ConnectorPermitIssuer(_PERMIT_FACTORY_KEY, manager=manager)


# ---------------------------------------------------------------------------
# R4A-I3: Per-execution dispatch capability (non-forgeable, single-use)
# ---------------------------------------------------------------------------

_CAPABILITY_TTL_SECONDS: Final[int] = 30
_CAPABILITY_DOMAIN: Final[bytes] = b"js-agent:connector-dispatch-capability:v1\0"


class _PendingCapability:
    """Internal registry entry for a pending dispatch capability."""

    __slots__ = (
        "binding_digest",
        "authority_hash",
        "context_fingerprint",
        "appshell_operation_id",
        "approval_claim_receipt_hash",
        "lease_consume_receipt_hash",
        "connector_type",
        "operation",
        "issued_at",
    )

    def __init__(
        self,
        *,
        binding_digest: str,
        authority_hash: str,
        context_fingerprint: str,
        appshell_operation_id: str | None,
        approval_claim_receipt_hash: str | None,
        lease_consume_receipt_hash: str,
        connector_type: str,
        operation: str,
        issued_at: float,
    ) -> None:
        self.binding_digest = binding_digest
        self.authority_hash = authority_hash
        self.context_fingerprint = context_fingerprint
        self.appshell_operation_id = appshell_operation_id
        self.approval_claim_receipt_hash = approval_claim_receipt_hash
        self.lease_consume_receipt_hash = lease_consume_receipt_hash
        self.connector_type = connector_type
        self.operation = operation
        self.issued_at = issued_at


class _ConnectorDispatchCapability:
    """Single-use, short-TTL, non-copyable dispatch capability.

    Created only by :class:`_ConnectorDispatchIssuer` (held by
    EffectInterpreter).  The ``nonce`` is random and the ``binding_digest``
    is an HMAC over the manager's secret capability key, so it cannot be
    forged even if all binding fields are known.

    This is a release-integrity and accidental-bypass control inside one
    Python process.  It is not a sandbox against arbitrary code already
    executing with full interpreter introspection.
    """

    __slots__ = ("_nonce", "_binding_digest", "_issued_at")

    def __init__(
        self,
        factory_key: object,
        *,
        nonce: str,
        binding_digest: str,
        issued_at: float,
    ) -> None:
        if factory_key is not _PERMIT_FACTORY_KEY:
            raise PermissionError(_AUTHORITY_REQUIRED)
        self._nonce = nonce
        self._binding_digest = binding_digest
        self._issued_at = issued_at

    @property
    def nonce(self) -> str:
        return self._nonce

    @property
    def binding_digest(self) -> str:
        return self._binding_digest

    def __copy__(self) -> None:
        raise TypeError("dispatch capability is not copyable")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("dispatch capability is not copyable")


class _ConnectorDispatchIssuer:
    """Closure-like issuer held only by EffectInterpreter.

    Created during manager construction and returned to the caller
    (EffectInterpreter), NOT stored as a public attribute on the manager
    or runtime.  The manager only sees the capabilities it produces,
    never the secret.
    """

    __slots__ = ("_manager", "_capability_secret")

    def __init__(
        self,
        factory_key: object,
        *,
        manager: ConnectorManager,
        capability_secret: bytes,
    ) -> None:
        if factory_key is not _PERMIT_FACTORY_KEY:
            raise PermissionError(_AUTHORITY_REQUIRED)
        self._manager = manager
        self._capability_secret = capability_secret

    def issue(
        self,
        *,
        authority_hash: str,
        context_fingerprint: str,
        appshell_operation_id: str | None,
        approval_claim_receipt_hash: str | None,
        lease_consume_receipt_hash: str,
        connector_type: str,
        operation: str,
    ) -> _ConnectorDispatchCapability:
        nonce = secrets.token_hex(32)
        binding_digest = self._compute_binding_digest(
            nonce=nonce,
            authority_hash=authority_hash,
            context_fingerprint=context_fingerprint,
            appshell_operation_id=appshell_operation_id,
            approval_claim_receipt_hash=approval_claim_receipt_hash,
            lease_consume_receipt_hash=lease_consume_receipt_hash,
            connector_type=connector_type,
            operation=operation,
        )
        pending = _PendingCapability(
            binding_digest=binding_digest,
            authority_hash=authority_hash,
            context_fingerprint=context_fingerprint,
            appshell_operation_id=appshell_operation_id,
            approval_claim_receipt_hash=approval_claim_receipt_hash,
            lease_consume_receipt_hash=lease_consume_receipt_hash,
            connector_type=connector_type,
            operation=operation,
            issued_at=time.monotonic(),
        )
        self._manager._pending_capabilities[nonce] = pending
        return _ConnectorDispatchCapability(
            _PERMIT_FACTORY_KEY,
            nonce=nonce,
            binding_digest=binding_digest,
            issued_at=pending.issued_at,
        )

    def _compute_binding_digest(
        self,
        *,
        nonce: str,
        authority_hash: str,
        context_fingerprint: str,
        appshell_operation_id: str | None,
        approval_claim_receipt_hash: str | None,
        lease_consume_receipt_hash: str,
        connector_type: str,
        operation: str,
    ) -> str:
        import json as _json

        payload = _json.dumps(
            {
                "nonce": nonce,
                "authority_hash": authority_hash,
                "context_fingerprint": context_fingerprint,
                "appshell_operation_id": appshell_operation_id,
                "approval_claim_receipt_hash": approval_claim_receipt_hash,
                "lease_consume_receipt_hash": lease_consume_receipt_hash,
                "connector_type": connector_type,
                "operation": operation,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        digest = hmac.new(self._capability_secret, digestmod=hashlib.sha256)
        digest.update(_CAPABILITY_DOMAIN)
        digest.update(payload)
        return "sha256:" + digest.hexdigest()


def _new_dispatch_issuer(
    *,
    manager: ConnectorManager,
    capability_secret: bytes,
) -> _ConnectorDispatchIssuer:
    return _ConnectorDispatchIssuer(
        _PERMIT_FACTORY_KEY,
        manager=manager,
        capability_secret=capability_secret,
    )


@dataclass(frozen=True, slots=True)
class ConnectorResult:
    """Internal result returned only after the connector dispatch shell authorizes."""

    connector_type: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    effects: tuple[ConnectorEffect, ...] = ()
    artifact_refs: tuple[ArtifactRefV1, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "connector_type": self.connector_type,
            "success": self.success,
            "data": dict(self.data),
            "error": self.error,
            "effects": [effect.to_dict() for effect in self.effects],
            "artifact_refs": [ref.to_dict() for ref in self.artifact_refs],
        }


class _ConnectorDispatchPermit:
    """One-shot private identity permit for one manager/connector operation.

    This is a release-integrity and accidental-bypass control inside one Python
    process.  It is not a sandbox against arbitrary code already executing with
    full interpreter introspection; Task 7's AST gate protects the production
    source call graph as the complementary release control.
    """

    __slots__ = ("_connector", "_issuer", "_manager", "_operation", "_used")

    def __init__(
        self,
        factory_key: object,
        *,
        manager: object,
        connector: ConnectorBase,
        operation: Literal["read", "write"],
        issuer: _ConnectorPermitIssuer,
    ) -> None:
        if factory_key is not _PERMIT_FACTORY_KEY:
            raise PermissionError(_AUTHORITY_REQUIRED)
        self._manager = manager
        self._connector = connector
        self._operation = operation
        self._issuer = issuer
        self._used = False

    def claim(
        self,
        *,
        manager: object,
        connector: ConnectorBase,
        operation: Literal["read", "write"],
    ) -> None:
        if (
            self._used
            or self._manager is not manager
            or self._connector is not connector
            or self._operation != operation
            or getattr(manager, "_permit_issuer", None) is not self._issuer
        ):
            raise PermissionError(_AUTHORITY_REQUIRED)
        self._used = True

    def __copy__(self) -> None:
        raise TypeError("connector dispatch permits cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("connector dispatch permits cannot be copied")


def _issue_dispatch_permit(
    *,
    manager: object,
    connector: ConnectorBase,
    operation: Literal["read", "write"],
    issuer: object,
) -> _ConnectorDispatchPermit:
    if (
        type(issuer) is not _ConnectorPermitIssuer
        or issuer.manager is not manager
        or getattr(manager, "_permit_issuer", None) is not issuer
    ):
        raise PermissionError(_AUTHORITY_REQUIRED)
    return _ConnectorDispatchPermit(
        _PERMIT_FACTORY_KEY,
        manager=manager,
        connector=connector,
        operation=operation,
        issuer=cast("_ConnectorPermitIssuer", issuer),
    )


class ConnectorBase:
    """Base class whose public read/write methods are non-overridable shells."""

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        forbidden = {"read", "write"} & cls.__dict__.keys()
        if forbidden:
            raise TypeError("connector subclasses cannot override final read/write dispatch shells")

    def __init__(self, manifest: ConnectorManifestV1) -> None:
        if type(manifest) is not ConnectorManifestV1:
            raise TypeError("connector manifest must be exact ConnectorManifestV1")
        self._manifest = manifest

    @property
    def manifest(self) -> ConnectorManifestV1:
        return self._manifest

    @property
    def connector_type(self) -> str:
        return self._manifest.connector_type

    async def read(
        self,
        scope: str,
        *,
        params: dict[str, Any] | None = None,
        directory_grant: DirectoryGrantV1 | None = None,
        _permit: object | None = None,
        _manager: object | None = None,
        _context_binding: dict[str, Any] | None = None,
        **_legacy_authority: object,
    ) -> ConnectorResult:
        if type(_permit) is not _ConnectorDispatchPermit or _manager is None:
            return self._authority_required()
        try:
            _permit.claim(manager=_manager, connector=self, operation="read")
        except PermissionError:
            return self._authority_required()
        return await self._read_authorized(
            scope,
            params=dict(params or {}),
            directory_grant=directory_grant,
            context_binding=_context_binding or {},
        )

    async def write(
        self,
        scope: str,
        *,
        params: dict[str, Any] | None = None,
        directory_grant: DirectoryGrantV1 | None = None,
        _permit: object | None = None,
        _manager: object | None = None,
        _context_binding: dict[str, Any] | None = None,
        **_legacy_authority: object,
    ) -> ConnectorResult:
        if type(_permit) is not _ConnectorDispatchPermit or _manager is None:
            return self._authority_required()
        try:
            _permit.claim(manager=_manager, connector=self, operation="write")
        except PermissionError:
            return self._authority_required()
        if self._manifest.approval_policy in ("read_only", "never"):
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_write_policy_denied",
            )
        return await self._write_authorized(
            scope,
            params=dict(params or {}),
            directory_grant=directory_grant,
            context_binding=_context_binding or {},
        )

    def _authority_required(self) -> ConnectorResult:
        return ConnectorResult(
            connector_type=self.connector_type,
            success=False,
            error=_AUTHORITY_REQUIRED,
        )

    async def _read_authorized(
        self,
        scope: str,
        *,
        params: dict[str, Any],
        directory_grant: DirectoryGrantV1 | None,
        context_binding: dict[str, Any] | None = None,
    ) -> ConnectorResult:
        return ConnectorResult(
            connector_type=self.connector_type,
            success=False,
            error="connector_operation_not_supported",
        )

    async def _write_authorized(
        self,
        scope: str,
        *,
        params: dict[str, Any],
        directory_grant: DirectoryGrantV1 | None,
        context_binding: dict[str, Any] | None = None,
    ) -> ConnectorResult:
        return ConnectorResult(
            connector_type=self.connector_type,
            success=False,
            error="connector_operation_not_supported",
        )


class FakeConnector(ConnectorBase):
    """Test-only deterministic connector with no I/O or external dependencies."""

    def __init__(self) -> None:
        super().__init__(
            ConnectorManifestV1(
                connector_type="fake",
                capabilities=("read",),
                read_scopes=("test",),
                write_scopes=(),
                approval_policy="read_only",
            )
        )

    async def _read_authorized(
        self,
        scope: str,
        *,
        params: dict[str, Any],
        directory_grant: DirectoryGrantV1 | None,
        context_binding: dict[str, Any] | None = None,
    ) -> ConnectorResult:
        return ConnectorResult(
            connector_type="fake",
            success=True,
            data={"scope": scope, "items": [], "fake": True},
        )


class ConnectorRegistry:
    """An initially empty registry with duplicate-replacement protection."""

    def __init__(self) -> None:
        self._manifests: dict[str, ConnectorManifestV1] = {}
        self._instances: dict[str, ConnectorBase] = {}

    def register_manifest(self, manifest: ConnectorManifestV1) -> None:
        if manifest.connector_type in self._manifests:
            raise ValueError(f"connector type '{manifest.connector_type}' already registered")
        self._manifests[manifest.connector_type] = manifest

    def register_instance(self, connector: ConnectorBase) -> None:
        if not isinstance(connector, ConnectorBase):
            raise TypeError("connector instance must derive from ConnectorBase")
        connector_type = connector.connector_type
        if connector_type in self._instances or connector_type in self._manifests:
            raise ValueError(f"connector type '{connector_type}' already registered")
        self._manifests[connector_type] = connector.manifest
        self._instances[connector_type] = connector

    def list_manifests(self) -> list[ConnectorManifestV1]:
        return list(self._manifests.values())

    def get_manifest(self, connector_type: str) -> ConnectorManifestV1 | None:
        return self._manifests.get(connector_type)

    def get_instance(self, connector_type: str) -> ConnectorBase | None:
        return self._instances.get(connector_type)

    def has_connector(self, connector_type: str) -> bool:
        return connector_type in self._manifests


__all__ = ["ConnectorBase", "ConnectorRegistry", "ConnectorResult", "FakeConnector"]
