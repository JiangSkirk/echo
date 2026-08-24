"""Signed decision receipts for Orin verdicts.

Every authoritative orind decision (issue / consume / revoke / freeze)
produces a receipt signed with orind's own Ed25519 key, reusing
``js.security.signer``. The signing key lives under the orind key
directory (``<state_dir>/orin``) and is distinct from both the lease HMAC
key and the main-process signing key.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.orin.protocol import canonical_json
from js.security.signer import generate_signing_key, sign_content, verify_signature

RECEIPT_KINDS = frozenset({"issue", "consume", "revoke", "freeze", "cell"})


@dataclass(frozen=True, slots=True)
class DecisionReceipt:
    """One signed verdict record (Stage A: durable audit trail)."""

    receipt_id: str
    kind: str
    verdict: str
    lease_id: str
    policy_version: int
    created_at: int
    signature: str
    public_key: str

    def payload(self) -> str:
        return canonical_json(
            {
                "receipt_id": self.receipt_id,
                "kind": self.kind,
                "verdict": self.verdict,
                "lease_id": self.lease_id,
                "policy_version": self.policy_version,
                "created_at": self.created_at,
            }
        )

    def verify(self) -> bool:
        return verify_signature(self.payload(), self.signature, self.public_key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "kind": self.kind,
            "verdict": self.verdict,
            "lease_id": self.lease_id,
            "policy_version": self.policy_version,
            "created_at": self.created_at,
            "signature": self.signature,
            "public_key": self.public_key,
        }


class ReceiptSigner:
    """Signs receipts with orind's Ed25519 key (created on first use)."""

    def __init__(self, key_dir: Path) -> None:
        self._key_dir = key_dir
        self._key_dir.mkdir(parents=True, exist_ok=True)
        generate_signing_key(self._key_dir)

    def sign(
        self,
        *,
        kind: str,
        verdict: str,
        lease_id: str,
        policy_version: int,
        created_at: int,
        receipt_id: str,
    ) -> DecisionReceipt:
        if kind not in RECEIPT_KINDS:
            raise ValueError(f"unknown receipt kind {kind!r}")
        receipt = DecisionReceipt(
            receipt_id=receipt_id,
            kind=kind,
            verdict=verdict,
            lease_id=lease_id,
            policy_version=policy_version,
            created_at=created_at,
            signature="",
            public_key="",
        )
        signature = sign_content(receipt.payload(), self._key_dir)
        from js.security.signer import get_public_key

        public_key = get_public_key(self._key_dir)
        return DecisionReceipt(
            receipt_id=receipt.receipt_id,
            kind=receipt.kind,
            verdict=receipt.verdict,
            lease_id=receipt.lease_id,
            policy_version=receipt.policy_version,
            created_at=receipt.created_at,
            signature=signature,
            public_key=public_key,
        )


def receipt_from_dict(payload: dict[str, Any]) -> DecisionReceipt:
    """Rebuild a receipt from a serialized dict (strict field check)."""

    required = (
        "receipt_id",
        "kind",
        "verdict",
        "lease_id",
        "policy_version",
        "created_at",
        "signature",
        "public_key",
    )
    for key in required:
        if key not in payload:
            raise ValueError(f"receipt payload missing {key!r}")
    return DecisionReceipt(
        receipt_id=str(payload["receipt_id"]),
        kind=str(payload["kind"]),
        verdict=str(payload["verdict"]),
        lease_id=str(payload["lease_id"]),
        policy_version=int(payload["policy_version"]),
        created_at=int(payload["created_at"]),
        signature=str(payload["signature"]),
        public_key=str(payload["public_key"]),
    )


__all__ = ["DecisionReceipt", "ReceiptSigner", "RECEIPT_KINDS", "receipt_from_dict"]
