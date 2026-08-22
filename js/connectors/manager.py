"""Runtime-owned connector composition and private authorized dispatch."""

from __future__ import annotations

import secrets
import time
from typing import Any

from js.connectors.base import (
    _CAPABILITY_TTL_SECONDS,
    ConnectorBase,
    ConnectorRegistry,
    ConnectorResult,
    FakeConnector,
    _ConnectorDispatchCapability,
    _ConnectorDispatchIssuer,
    _issue_dispatch_permit,
    _new_dispatch_issuer,
    _new_dispatch_permit_issuer,
)
from js.connectors.contracts import ConnectorExecutionRequestV1
from js.echo.mode_contract import ConnectorManifestV1

_COMPOSITION_KEY = object()


class ConnectorManager:
    """A sealed-by-default registry; public execution always fails closed."""

    def __init__(
        self,
        *,
        production: bool = True,
        _composition_key: object | None = None,
        _runtime_authority: object | None = None,
    ) -> None:
        self._registry = ConnectorRegistry()
        self._production = production
        self._runtime_authority = _runtime_authority
        self._permit_issuer = _new_dispatch_permit_issuer(manager=self)
        self._sealed = _composition_key is not _COMPOSITION_KEY
        # R4A-I3: per-execution dispatch capability system
        self._capability_secret = secrets.token_bytes(32)
        self._pending_capabilities: dict[str, Any] = {}

    def _register_for_composition(self, connector: ConnectorBase) -> None:
        if self._sealed:
            raise PermissionError("connector manager composition is sealed")
        self._registry.register_instance(connector)

    def _seal(self) -> None:
        self._sealed = True

    def _create_dispatch_issuer(self) -> _ConnectorDispatchIssuer:
        """Create a dispatch issuer for EffectInterpreter to hold.

        The issuer is NOT stored on the manager as a public attribute.
        It is returned to the caller (EffectInterpreter) who holds it
        privately.  The manager only sees capabilities via
        ``_consume_capability``.
        """
        return _new_dispatch_issuer(
            manager=self,
            capability_secret=self._capability_secret,
        )

    def _consume_capability(
        self,
        capability: _ConnectorDispatchCapability,
    ) -> Any:
        """Atomically look up and remove a pending capability.

        Returns the ``_PendingCapability`` if valid and not expired.
        Returns ``None`` if the capability is invalid, expired, or already
        consumed.
        """
        pending = self._pending_capabilities.pop(capability.nonce, None)
        if pending is None:
            return None
        if time.monotonic() - pending.issued_at > _CAPABILITY_TTL_SECONDS:
            return None
        # Verify binding digest using the manager's secret
        import hashlib as _hl
        import hmac as _hmac
        import json as _json

        payload = _json.dumps(
            {
                "nonce": capability.nonce,
                "authority_hash": pending.authority_hash,
                "context_fingerprint": pending.context_fingerprint,
                "appshell_operation_id": pending.appshell_operation_id,
                "approval_claim_receipt_hash": pending.approval_claim_receipt_hash,
                "lease_consume_receipt_hash": pending.lease_consume_receipt_hash,
                "connector_type": pending.connector_type,
                "operation": pending.operation,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        digest = _hmac.new(self._capability_secret, digestmod=_hl.sha256)
        digest.update(b"js-agent:connector-dispatch-capability:v1\0")
        digest.update(payload)
        expected = "sha256:" + digest.hexdigest()
        if not _hmac.compare_digest(expected, capability.binding_digest):
            return None
        return pending

    def register_manifest(self, manifest: ConnectorManifestV1) -> None:
        if self._sealed or self._production:
            raise PermissionError("connector manager composition is sealed")
        self._registry.register_manifest(manifest)

    def register_instance(self, connector: ConnectorBase) -> None:
        if self._sealed or self._production:
            raise PermissionError("connector manager composition is sealed")
        self._registry.register_instance(connector)

    def list_available(self) -> list[dict[str, Any]]:
        return [
            {
                "connector_type": manifest.connector_type,
                "capabilities": list(manifest.capabilities),
                "read_scopes": list(manifest.read_scopes),
                "write_scopes": list(manifest.write_scopes),
                "approval_policy": manifest.approval_policy,
            }
            for manifest in self._registry.list_manifests()
        ]

    def is_available(self, connector_type: str) -> bool:
        return self._registry.has_connector(connector_type)

    async def execute_read(
        self,
        connector_type: str,
        scope: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> ConnectorResult:
        return ConnectorResult(
            connector_type=connector_type,
            success=False,
            error="connector_runtime_authority_required",
        )

    async def execute_write(
        self,
        connector_type: str,
        scope: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> ConnectorResult:
        return ConnectorResult(
            connector_type=connector_type,
            success=False,
            error="connector_runtime_authority_required",
        )

    async def _dispatch_authorized(
        self,
        request: ConnectorExecutionRequestV1,
        *,
        params: dict[str, Any],
        capability: _ConnectorDispatchCapability | None = None,
    ) -> ConnectorResult:
        if not self._sealed or capability is None:
            return ConnectorResult(
                connector_type=request.manifest.connector_type,
                success=False,
                error="connector_runtime_authority_required",
            )
        # Consume the capability atomically
        pending = self._consume_capability(capability)
        if pending is None:
            return ConnectorResult(
                connector_type=request.manifest.connector_type,
                success=False,
                error="connector_runtime_authority_required",
            )
        # Verify request matches capability binding
        if request.connection.ref.connector_type != pending.connector_type:
            return ConnectorResult(
                connector_type=request.manifest.connector_type,
                success=False,
                error="connector_runtime_authority_required",
            )
        if request.operation != pending.operation:
            return ConnectorResult(
                connector_type=request.manifest.connector_type,
                success=False,
                error="connector_runtime_authority_required",
            )
        connector_type = request.connection.ref.connector_type
        connector = self._registry.get_instance(connector_type)
        manifest = self._registry.get_manifest(connector_type)
        if connector is None or manifest is None:
            return ConnectorResult(
                connector_type=connector_type,
                success=False,
                error="connector_not_registered",
            )
        if manifest != request.manifest or manifest.canonical_hash() != request.connection.manifest_digest:
            return ConnectorResult(
                connector_type=connector_type,
                success=False,
                error="connector_manifest_binding_mismatch",
            )
        permit = _issue_dispatch_permit(
            manager=self,
            connector=connector,
            operation=request.operation,
            issuer=self._permit_issuer,
        )
        context_binding = {
            "owner": request.task_ref.owner,
            "mode": request.task_ref.mode.value if hasattr(request.task_ref.mode, "value") else str(request.task_ref.mode),
            "workspace": request.task_ref.workspace,
            "session": request.task_ref.session,
            "run": request.task_ref.run,
        }
        if request.operation == "read":
            return await connector.read(
                request.scope,
                params=params,
                directory_grant=request.directory_grant,
                _permit=permit,
                _manager=self,
                _context_binding=context_binding,
            )
        return await connector.write(
            request.scope,
            params=params,
            directory_grant=request.directory_grant,
            _permit=permit,
            _manager=self,
            _context_binding=context_binding,
        )


def build_production_connector_manager(
    *,
    runtime_authority: object | None = None,
    artifact_store: object | None = None,
) -> ConnectorManager:
    """Compose and seal the two local production connector declarations.

    ``runtime_authority`` is retained for backward compatibility but no
    longer authorizes dispatch.  ``artifact_store`` is the
    :class:`ConnectorArtifactStore` passed to local connector instances.
    """

    from js.connectors.local import LimitedWritePublishConnector, ReadOnlyImportConnector

    manager = ConnectorManager(
        production=True,
        _composition_key=_COMPOSITION_KEY,
    )
    manager._register_for_composition(ReadOnlyImportConnector(artifact_store=artifact_store))
    manager._register_for_composition(LimitedWritePublishConnector(artifact_store=artifact_store))
    manager._seal()
    return manager


def build_test_connector_manager(*, runtime_authority: object | None = None) -> ConnectorManager:
    """Compose a fresh isolated Fake-only manager for tests."""

    manager = ConnectorManager(
        production=False,
        _composition_key=_COMPOSITION_KEY,
    )
    manager._register_for_composition(FakeConnector())
    manager._seal()
    return manager


__all__ = [
    "ConnectorManager",
    "build_production_connector_manager",
    "build_test_connector_manager",
]
