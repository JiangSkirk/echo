"""RFC 6962 Merkle tree and inclusion proofs.

This is the P1-2 inclusion-proof component. ``tip_anchor.py`` remains an
external monotonic counter + MAC and is not a Merkle tree.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

_LEAF_PREFIX: Final[bytes] = b"\x00"
_NODE_PREFIX: Final[bytes] = b"\x01"
_ROOT_PREFIX: Final[str] = "sha256:"


class MerkleError(ValueError):
    """Merkle tree or inclusion proof is invalid."""


@dataclass(frozen=True, slots=True)
class InclusionProof:
    leaf_index: int
    tree_size: int
    leaf_hash: str
    siblings: tuple[str, ...]


def encode_digest(digest: bytes) -> str:
    if len(digest) != 32:
        raise MerkleError("digest must be 32 bytes")
    return _ROOT_PREFIX + digest.hex()


def decode_digest(value: str) -> bytes:
    text = str(value)
    if not text.startswith(_ROOT_PREFIX) or len(text) != 7 + 64:
        raise MerkleError("digest must be sha256:<64 hex>")
    try:
        digest = bytes.fromhex(text[7:])
    except ValueError as exc:
        raise MerkleError("digest is not hex") from exc
    if len(digest) != 32:
        raise MerkleError("digest must be 32 bytes")
    return digest


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def empty_root() -> bytes:
    return hashlib.sha256().digest()


def merkle_tree_hash(leaves: Sequence[bytes]) -> bytes:
    """RFC 6962 MTH over the given leaf payloads (not pre-hashed)."""

    size = len(leaves)
    if size == 0:
        return empty_root()
    if size == 1:
        return leaf_hash(leaves[0])
    split = _largest_power_of_two_less_than(size)
    return node_hash(merkle_tree_hash(leaves[:split]), merkle_tree_hash(leaves[split:]))


def merkle_audit_path(index: int, leaves: Sequence[bytes]) -> tuple[bytes, ...]:
    """RFC 6962 PATH from ``index`` to the root (leaf toward root)."""

    size = len(leaves)
    if size == 0:
        raise MerkleError("cannot prove inclusion in an empty tree")
    if not 0 <= index < size:
        raise MerkleError("leaf index is out of range")
    return tuple(_audit_path(index, leaves))


def inclusion_proof(index: int, leaves: Sequence[bytes]) -> InclusionProof:
    siblings = merkle_audit_path(index, leaves)
    return InclusionProof(
        leaf_index=index,
        tree_size=len(leaves),
        leaf_hash=encode_digest(leaf_hash(leaves[index])),
        siblings=tuple(encode_digest(item) for item in siblings),
    )


def verify_inclusion(
    data: bytes,
    proof: InclusionProof,
    root: bytes | str,
) -> bool:
    expected = decode_digest(root) if isinstance(root, str) else root
    if proof.tree_size < 1 or not 0 <= proof.leaf_index < proof.tree_size:
        return False
    if leaf_hash(data) != decode_digest(proof.leaf_hash):
        return False
    try:
        siblings = tuple(decode_digest(item) for item in proof.siblings)
    except MerkleError:
        return False
    computed = _root_from_path(
        proof.leaf_index,
        proof.tree_size,
        node=leaf_hash(data),
        siblings=siblings,
    )
    return computed == expected


def _largest_power_of_two_less_than(n: int) -> int:
    if n < 2:
        raise MerkleError("split is undefined for n < 2")
    split = 1
    while split * 2 < n:
        split *= 2
    return split


def _audit_path(index: int, leaves: Sequence[bytes]) -> list[bytes]:
    size = len(leaves)
    if size == 1:
        return []
    split = _largest_power_of_two_less_than(size)
    if index < split:
        return _audit_path(index, leaves[:split]) + [merkle_tree_hash(leaves[split:])]
    return _audit_path(index - split, leaves[split:]) + [merkle_tree_hash(leaves[:split])]


def _root_from_path(
    index: int,
    size: int,
    *,
    node: bytes,
    siblings: Sequence[bytes],
) -> bytes:
    remaining = list(siblings)
    return _fold_path(index, size, node, remaining)


def _fold_path(index: int, size: int, node: bytes, siblings: list[bytes]) -> bytes:
    if size == 1:
        return node if not siblings else b""
    split = _largest_power_of_two_less_than(size)
    if not siblings:
        return b""
    sibling = siblings.pop()
    if index < split:
        left = _fold_path(index, split, node, siblings)
        return node_hash(left, sibling)
    right = _fold_path(index - split, size - split, node, siblings)
    return node_hash(sibling, right)


__all__ = [
    "InclusionProof",
    "MerkleError",
    "decode_digest",
    "empty_root",
    "encode_digest",
    "inclusion_proof",
    "leaf_hash",
    "merkle_audit_path",
    "merkle_tree_hash",
    "node_hash",
    "verify_inclusion",
]
