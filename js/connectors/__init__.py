"""Security connector framework.

R4 scope: connector manifest registration, fake/schema connector,
real local import/publish connectors, read-only framework.
No real credentials, no network, no background polling.
All outputs enter TaskRef, ArtifactRef and Echo Receipt.
"""

from __future__ import annotations

from js.connectors.contracts import (
    ConnectionRefV2,
    ConnectorEffect,
    ConnectorExecutionRequestV1,
    ConnectorOperation,
    ConnectorRunOutcomeV1,
    DirectoryGrantV1,
    VaultRefV1,
    canonical_params_digest,
)

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
