"""Echo T4.1 — AmberTree real-HAMT implementation.

Replaces the T4 flat-dict masquerade with a real Hash Array Mapped Trie
satisfying Echo spec §7's complexity contract:

- **128-bit hash key** (BLAKE2b-16, 5-bit branching → 26 levels max).
- **Path-copy commits**: ``commit_checked`` / ``mark`` walk down at most
  ⌈log32(N)⌉ + bucket_depth branches and copy *only* those — the rest
  of the trie is structurally shared with the previous root.
- **Incremental subhashes**: every internal branch carries a cached
  ``subhash``. A commit recomputes subhashes only along the spine of
  the changed path. The empty-tree hash is a fixed constant.
- **Hash-collision buckets**: when two distinct paths fully collide on
  the 128-bit key, both nodes are stored side-by-side in a
  ``_Bucket`` and looked up by *original-path* equality. Bucket
  payload hashing is order-independent (sorted by path).
- **Dirty-paths tracking**: every derived tree carries the set of
  paths the last commit/mark mutated, used by ``delta_since_last`` to
  emit O(|dirty|) bytes regardless of total tree size.
- **Ready-paths tracking**: a separate ``_ready_paths`` frozenset is
  maintained incrementally so ``ready_index()`` is O(|ready|), not
  O(N).

The public surface — :class:`AmberTreeImpl`, :func:`new_amber_tree`,
the ``AmberTree`` Protocol methods, ``MAX_PATH_LEN``,
``MAX_PAYLOAD_BYTES`` — is unchanged. The internal complexity hooks
required by the T4.1 contract (see :mod:`tests.echo.test_amber_tree_hamt`)
are exposed as private attributes / classmethods:

- ``_BRANCH_FACTOR``      = 32  (constant)
- ``_HASH_KEY_BITS``      = 128 (constant)
- ``_path_hash(path)``    : staticmethod returning the 128-bit key
- ``branches_copied``     : counter on the derived tree
- ``hashes_recomputed``   : counter on the derived tree
- ``_dirty_paths``        : frozenset[str] mutated by last write
- ``_ready_paths_view()`` : frozenset[str] reflecting ready-set

No I/O. No clock. No entropy source. Hermetic under the Echo kernel contract.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Self

from js.echo.amber import (
    AmberTree,
    ContextView,
    Delta,
    NodeStatus,
    ReadyIndex,
)

# ---------------------------------------------------------------------------
# Schema invariants — unchanged from T4
# ---------------------------------------------------------------------------
MAX_PAYLOAD_BYTES: int = 1 << 20  # 1 MiB
MAX_PATH_LEN: int = 4096

_PATH_ALLOWED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_./")


def _check_commit_invariants(path: str, payload: bytes) -> None:
    if not isinstance(path, str):
        raise ValueError(f"AmberTree.commit_checked: path must be str, got {type(path).__name__}")
    if not path:
        raise ValueError("AmberTree.commit_checked: path must not be empty")
    if len(path) > MAX_PATH_LEN:
        raise ValueError(
            f"AmberTree.commit_checked: path length {len(path)} exceeds {MAX_PATH_LEN}"
        )
    if not path.startswith("/"):
        raise ValueError(f"AmberTree.commit_checked: path must start with '/', got {path!r}")
    if "//" in path:
        raise ValueError(f"AmberTree.commit_checked: path must not contain '//' segments: {path!r}")
    for ch in path:
        if ch not in _PATH_ALLOWED:
            raise ValueError(
                f"AmberTree.commit_checked: path contains invalid character {ch!r} in {path!r}"
            )

    if not isinstance(payload, (bytes, bytearray)):
        raise ValueError(
            f"AmberTree.commit_checked: payload must be bytes, got {type(payload).__name__}"
        )
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"AmberTree.commit_checked: payload size {len(payload)} exceeds "
            f"{MAX_PAYLOAD_BYTES} byte cap"
        )


# ---------------------------------------------------------------------------
# HAMT shape constants
# ---------------------------------------------------------------------------
# 5-bit branching → 32 children per internal node. With a 128-bit key
# the trie is at most ⌈128 / 5⌉ = 26 levels deep before a bucket forms.
_BITS_PER_LEVEL: int = 5
_BRANCH_FACTOR: int = 1 << _BITS_PER_LEVEL  # 32
_LEVEL_MASK: int = _BRANCH_FACTOR - 1  # 0b11111
_HASH_KEY_BITS: int = 128
_MAX_LEVELS: int = (_HASH_KEY_BITS + _BITS_PER_LEVEL - 1) // _BITS_PER_LEVEL  # 26


# ---------------------------------------------------------------------------
# Leaf record
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _AmberNode:
    """A single committed path's record (the trie's leaf payload)."""

    path: str
    payload: bytes
    status: NodeStatus

    def with_status(self, status: NodeStatus) -> _AmberNode:
        return _AmberNode(path=self.path, payload=self.payload, status=status)

    def node_hash(self) -> bytes:
        """Deterministic 32-byte SHA-256 of (path, status, payload)."""
        h = hashlib.sha256()
        h.update(b"amber-node-v1:")
        h.update(len(self.path).to_bytes(4, "big"))
        h.update(self.path.encode("utf-8"))
        h.update(self.status.value.encode("utf-8"))
        h.update(b":")
        h.update(len(self.payload).to_bytes(8, "big"))
        h.update(bytes(self.payload))
        return h.digest()


# ---------------------------------------------------------------------------
# HAMT internal records — _Branch (sparse 32-way) and _Bucket (collision)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _Bucket:
    """Holds one or more leaves whose 128-bit keys fully collide.

    The bucket is keyed by *original path*; two distinct paths can land
    here only if their 128-bit hashes collide bit-for-bit (astronomically
    unlikely in production but exercised by the test rig). Lookups
    compare by path, never by key.
    """

    entries: tuple[_AmberNode, ...]  # sorted by path for determinism

    def subhash(self) -> bytes:
        if not self.entries:
            return _EMPTY_BUCKET_HASH
        h = hashlib.sha256()
        h.update(b"amber-bucket-v1:")
        for node in self.entries:  # entries are already sorted by path
            h.update(node.node_hash())
        return h.digest()

    def find(self, path: str) -> _AmberNode | None:
        for node in self.entries:
            if node.path == path:
                return node
        return None

    def upsert(self, node: _AmberNode) -> _Bucket:
        new_entries: list[_AmberNode] = []
        replaced = False
        for existing in self.entries:
            if existing.path == node.path:
                new_entries.append(node)
                replaced = True
            else:
                new_entries.append(existing)
        if not replaced:
            new_entries.append(node)
            new_entries.sort(key=lambda n: n.path)
        return _Bucket(entries=tuple(new_entries))

    def size(self) -> int:
        return len(self.entries)


_EMPTY_BUCKET_HASH = hashlib.sha256(b"amber-bucket-v1:empty").digest()


@dataclass(frozen=True)
class _Branch:
    """Sparse internal node: up to 32 children, indexed by 5-bit slot.

    ``bitmap`` records which slots are occupied; ``children`` is the
    dense tuple of present children, packed in slot-ascending order.
    A child is either a ``_Branch``, a ``_Bucket``, or — in the
    "single leaf" optimisation — a single ``_AmberNode`` (leaf
    promoted to bucket only on second occupant). The cached ``subhash``
    field is the deterministic 32-byte hash of this subtree.
    """

    bitmap: int
    children: tuple[object, ...]
    subhash: bytes

    def get_slot_index(self, slot: int) -> int:
        """Index of slot within ``children`` (popcount of bitmap below slot)."""
        return _popcount(self.bitmap & ((1 << slot) - 1))

    def has(self, slot: int) -> bool:
        return bool(self.bitmap & (1 << slot))


def _popcount(x: int) -> int:
    return x.bit_count()


# Empty-branch and empty-tree hashes — pre-image-versioned so future
# encoding changes can be detected.
_EMPTY_BRANCH_HASH = hashlib.sha256(b"amber-branch-v1:empty").digest()
_EMPTY_TREE_HASH_HEX = hashlib.sha256(b"amber-tree-v1:empty").hexdigest()


def _hash_branch(bitmap: int, children: tuple[object, ...]) -> bytes:
    """Cached subtree hash for a branch with the given bitmap + children.

    Each child contributes its own subhash (or node_hash for a leaf).
    """
    h = hashlib.sha256()
    h.update(b"amber-branch-v1:")
    h.update(bitmap.to_bytes(8, "big"))
    for child in children:
        if isinstance(child, _AmberNode):
            h.update(b"L")
            h.update(child.node_hash())
        elif isinstance(child, _Bucket):
            h.update(b"K")
            h.update(child.subhash())
        else:
            assert isinstance(child, _Branch)
            h.update(b"B")
            h.update(child.subhash)
    return h.digest()


# ---------------------------------------------------------------------------
# Path → 128-bit integer key (with a hookable hash for tests)
# ---------------------------------------------------------------------------
def _default_path_hash(path: str) -> int:
    """BLAKE2b-128 of the path bytes, interpreted as a 128-bit integer."""
    digest = hashlib.blake2b(path.encode("utf-8"), digest_size=16).digest()
    return int.from_bytes(digest, "big")


def _slot_at_level(key: int, level: int) -> int:
    """Extract the 5-bit slot at the given trie level from a 128-bit key."""
    shift = _HASH_KEY_BITS - (level + 1) * _BITS_PER_LEVEL
    if shift < 0:
        # Past the bottom of the key — collapse to a bucket.
        return key & _LEVEL_MASK
    return (key >> shift) & _LEVEL_MASK


# ---------------------------------------------------------------------------
# Insertion / mutation primitives — all path-copy, all count work
# ---------------------------------------------------------------------------
@dataclass
class _MutationStats:
    """Mutable accumulator threaded through one commit/mark for complexity
    bookkeeping. Reset before each public write."""

    branches_copied: int = 0
    hashes_recomputed: int = 0


def _insert(
    branch: _Branch | None,
    node: _AmberNode,
    key: int,
    level: int,
    stats: _MutationStats,
    path_hash_fn: Callable[[str], int],
) -> _Branch:
    """Insert / replace ``node`` into the trie rooted at ``branch``.

    Returns a NEW root branch (path-copied). ``branch`` may be ``None``
    only when called for the top-level empty tree; recursive calls
    always pass a real branch.
    """
    if branch is None:
        # Empty tree → single-leaf branch at level 0.
        slot = _slot_at_level(key, level)
        children: tuple[object, ...] = (node,)
        bitmap = 1 << slot
        subhash = _hash_branch(bitmap, children)
        stats.branches_copied += 1
        stats.hashes_recomputed += 1
        return _Branch(bitmap=bitmap, children=children, subhash=subhash)

    slot = _slot_at_level(key, level)
    if not branch.has(slot):
        # Empty slot → insert leaf in place. Path-copy this branch.
        idx = branch.get_slot_index(slot)
        new_children = branch.children[:idx] + (node,) + branch.children[idx:]
        new_bitmap = branch.bitmap | (1 << slot)
        new_subhash = _hash_branch(new_bitmap, new_children)
        stats.branches_copied += 1
        stats.hashes_recomputed += 1
        return _Branch(bitmap=new_bitmap, children=new_children, subhash=new_subhash)

    idx = branch.get_slot_index(slot)
    existing = branch.children[idx]

    if isinstance(existing, _AmberNode):
        if existing.path == node.path:
            # Replace in place.
            new_children = branch.children[:idx] + (node,) + branch.children[idx + 1 :]
        else:
            # Two distinct leaves at the same slot → must descend further.
            new_children = (
                branch.children[:idx]
                + (
                    _merge_two_leaves(
                        existing,
                        node,
                        level=level + 1,
                        stats=stats,
                        path_hash_fn=path_hash_fn,
                    ),
                )
                + branch.children[idx + 1 :]
            )
        new_subhash = _hash_branch(branch.bitmap, new_children)
        stats.branches_copied += 1
        stats.hashes_recomputed += 1
        return _Branch(bitmap=branch.bitmap, children=new_children, subhash=new_subhash)

    if isinstance(existing, _Bucket):
        # Bucket lives at the leaf level (level == _MAX_LEVELS). Upsert.
        new_bucket = existing.upsert(node)
        new_children = branch.children[:idx] + (new_bucket,) + branch.children[idx + 1 :]
        new_subhash = _hash_branch(branch.bitmap, new_children)
        stats.branches_copied += 1
        stats.hashes_recomputed += 1
        return _Branch(bitmap=branch.bitmap, children=new_children, subhash=new_subhash)

    assert isinstance(existing, _Branch)
    # Recurse into the child branch.
    new_child = _insert(existing, node, key, level + 1, stats, path_hash_fn=path_hash_fn)
    new_children = branch.children[:idx] + (new_child,) + branch.children[idx + 1 :]
    new_subhash = _hash_branch(branch.bitmap, new_children)
    stats.branches_copied += 1
    stats.hashes_recomputed += 1
    return _Branch(bitmap=branch.bitmap, children=new_children, subhash=new_subhash)


def _merge_two_leaves(
    a: _AmberNode,
    b: _AmberNode,
    *,
    level: int,
    stats: _MutationStats,
    path_hash_fn: Callable[[str], int],
) -> object:
    """Combine two leaves at the same trie position into a deeper branch
    or, when keys fully collide, into a bucket."""
    key_a = path_hash_fn(a.path)
    key_b = path_hash_fn(b.path)
    if level >= _MAX_LEVELS:
        # Past the bottom of the 128-bit key → collision bucket.
        entries = sorted([a, b], key=lambda n: n.path)
        return _Bucket(entries=tuple(entries))

    slot_a = _slot_at_level(key_a, level)
    slot_b = _slot_at_level(key_b, level)

    if slot_a != slot_b:
        # Different slots → make a fresh branch with two leaves.
        if slot_a < slot_b:
            children: tuple[object, ...] = (a, b)
        else:
            children = (b, a)
        bitmap = (1 << slot_a) | (1 << slot_b)
        subhash = _hash_branch(bitmap, children)
        stats.branches_copied += 1
        stats.hashes_recomputed += 1
        return _Branch(bitmap=bitmap, children=children, subhash=subhash)

    # Same slot → descend.
    inner = _merge_two_leaves(a, b, level=level + 1, stats=stats, path_hash_fn=path_hash_fn)
    bitmap = 1 << slot_a
    children = (inner,)
    subhash = _hash_branch(bitmap, children)
    stats.branches_copied += 1
    stats.hashes_recomputed += 1
    return _Branch(bitmap=bitmap, children=children, subhash=subhash)


def _lookup(branch: _Branch | None, path: str, key: int, level: int) -> _AmberNode | None:
    """Walk the trie to fetch the node for ``path``, or ``None``."""
    if branch is None:
        return None
    slot = _slot_at_level(key, level)
    if not branch.has(slot):
        return None
    idx = branch.get_slot_index(slot)
    child = branch.children[idx]
    if isinstance(child, _AmberNode):
        return child if child.path == path else None
    if isinstance(child, _Bucket):
        return child.find(path)
    assert isinstance(child, _Branch)
    return _lookup(child, path, key, level + 1)


# ---------------------------------------------------------------------------
# Index / view / delta dataclasses (unchanged shapes from T4)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _ReadyIndexImpl:
    paths: tuple[str, ...]

    def topk(self, n: int) -> list[str]:
        if n < 0:
            raise ValueError(f"topk: n must be >= 0, got {n}")
        return list(self.paths[:n])


@dataclass(frozen=True)
class _ContextViewImpl:
    _digest: bytes

    @property
    def digest(self) -> bytes:
        return self._digest


# ---------------------------------------------------------------------------
# Public class — AmberTreeImpl
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AmberTreeImpl:
    """Real :class:`AmberTree` HAMT implementation (Echo T4.1).

    Construction is internal: callers should use :func:`new_amber_tree`
    for an empty tree, then derive children via ``commit_checked`` /
    ``mark``. The dataclass is frozen; every write returns a new
    instance.

    Internal layout (private):

    - ``_root`` : top branch of the HAMT, or ``None`` for an empty tree.
    - ``_node_count`` : number of leaves under ``_root``.
    - ``_ready_paths`` : frozenset of paths currently ``READY``.
    - ``_dirty_paths`` : frozenset of paths the *last* write touched.
    - ``_previous_version`` : scalar predecessor version used by
      ``delta_since_last`` without retaining the predecessor tree.
    - ``branches_copied`` / ``hashes_recomputed`` : complexity counters
      for the last write — exposed so the T4.1 contract suite can assert
      O(log N) path-copy without resorting to wall-clock thresholds.

    Public hook (private name): ``_path_hash`` is a staticmethod
    returning the 128-bit integer key for a path. Tests monkeypatch it
    to force collision-bucket paths.
    """

    _root: _Branch | None = field(default=None)
    _node_count: int = field(default=0)
    _root_hash: str = field(default=_EMPTY_TREE_HASH_HEX)
    _version: int = field(default=0)
    _ready_paths: frozenset[str] = field(default_factory=frozenset)
    _dirty_paths: frozenset[str] = field(default_factory=frozenset)
    branches_copied: int = field(default=0)
    hashes_recomputed: int = field(default=0)
    _previous_version: int | None = field(default=None, compare=False, repr=False)

    # Class-level constants exposed for the T4.1 complexity tests.
    _BRANCH_FACTOR = _BRANCH_FACTOR
    _HASH_KEY_BITS = _HASH_KEY_BITS

    # Hookable hash. Static so monkeypatching ``AmberTreeImpl._path_hash``
    # affects every instance.
    _path_hash = staticmethod(_default_path_hash)

    # ------------------------------------------------------------------
    # Protocol — read side
    # ------------------------------------------------------------------
    @property
    def root_hash(self) -> str:
        return self._root_hash

    @property
    def version(self) -> int:
        return self._version

    @property
    def node_count(self) -> int:
        return self._node_count

    def get(self, path: str) -> _AmberNode | None:
        if self._root is None:
            return None
        key = type(self)._path_hash(path)
        return _lookup(self._root, path, key, 0)

    # ------------------------------------------------------------------
    # Protocol — write side (path-copy, schema-checked)
    # ------------------------------------------------------------------
    def commit_checked(self, path: str, payload: bytes) -> Self:
        _check_commit_invariants(path, payload)

        existing = self.get(path)
        status = existing.status if existing is not None else NodeStatus.PENDING
        node = _AmberNode(path=path, payload=bytes(payload), status=status)

        return self._derive_with_node(node, dirty_path=path)

    def mark(self, path: str, status: NodeStatus) -> Self:
        if not isinstance(status, NodeStatus):
            raise ValueError(
                f"AmberTree.mark: status must be NodeStatus, got {type(status).__name__}"
            )
        existing = self.get(path)
        if existing is None:
            raise KeyError(f"AmberTree.mark: path {path!r} not found")

        if existing.status is status:
            # No-op mark: keep the trie + hash + ready set, but advance
            # version. dirty paths is empty.
            return replace(
                self,
                _version=self._version + 1,
                _dirty_paths=frozenset(),
                branches_copied=0,
                hashes_recomputed=0,
                _previous_version=self._version,
            )

        updated = existing.with_status(status)
        return self._derive_with_node(updated, dirty_path=path, prev_status=existing.status)

    # ------------------------------------------------------------------
    # Internal derivation — single path-copy insert + ready-set adjust
    # ------------------------------------------------------------------
    def _derive_with_node(
        self,
        node: _AmberNode,
        *,
        dirty_path: str,
        prev_status: NodeStatus | None = None,
    ) -> Self:
        stats = _MutationStats()
        key = type(self)._path_hash(node.path)
        existing = self.get(node.path)
        new_root = _insert(
            self._root,
            node,
            key,
            level=0,
            stats=stats,
            path_hash_fn=type(self)._path_hash,
        )

        size_delta = 0 if existing is not None else 1

        # Ready-set bookkeeping. ``prev_status`` is the status the path
        # had *before* this write — passed in by ``mark`` directly.
        # ``commit_checked`` uses the existing node's status (which it
        # preserves via the policy in T4) so we read it off ``existing``.
        old_status = (
            prev_status
            if prev_status is not None
            else (existing.status if existing is not None else None)
        )
        new_ready = self._ready_paths
        was_ready = old_status is NodeStatus.READY
        is_ready = node.status is NodeStatus.READY
        if was_ready and not is_ready:
            new_ready = new_ready - {node.path}
        elif is_ready and not was_ready:
            new_ready = new_ready | {node.path}

        new_hash = new_root.subhash.hex() if new_root is not None else _EMPTY_TREE_HASH_HEX

        return type(self)(
            _root=new_root,
            _node_count=self._node_count + size_delta,
            _root_hash=new_hash,
            _version=self._version + 1,
            _ready_paths=frozenset(new_ready),
            _dirty_paths=frozenset({dirty_path}),
            branches_copied=stats.branches_copied,
            hashes_recomputed=stats.hashes_recomputed,
            _previous_version=self._version,
        )

    # ------------------------------------------------------------------
    # Protocol — index / view / delta
    # ------------------------------------------------------------------
    def ready_index(self) -> ReadyIndex:
        paths = tuple(sorted(self._ready_paths))
        return _ReadyIndexImpl(paths=paths)

    def _ready_paths_view(self) -> frozenset[str]:
        """T4.1 hook — return the materialised ready-set."""
        return self._ready_paths

    def context_view(self, path: str) -> ContextView:
        node = self.get(path)
        h = hashlib.sha256()
        h.update(b"amber-context-v1:")
        h.update(len(path).to_bytes(4, "big"))
        h.update(path.encode("utf-8"))
        if node is None:
            h.update(b":missing")
        else:
            h.update(node.status.value.encode("utf-8"))
            h.update(b":")
            h.update(len(node.payload).to_bytes(8, "big"))
            h.update(bytes(node.payload))
        return _ContextViewImpl(_digest=h.digest())

    def delta_since_last(self) -> Delta:
        """Versioned delta — touches only ``_dirty_paths``."""
        if self._previous_version is None:
            from_version = 0
        else:
            from_version = self._previous_version

        parts: list[bytes] = []
        for path in sorted(self._dirty_paths):
            cur = self.get(path)
            if cur is None:
                # Path was deleted. T4.1 never deletes, so this branch
                # is reachable only if a future tide deletes nodes.
                parts.append(b"-" + path.encode("utf-8") + b"\n")
            else:
                parts.append(
                    b"+"
                    + path.encode("utf-8")
                    + b"\n"
                    + cur.status.value.encode("utf-8")
                    + b"\n"
                    + cur.payload.hex().encode("ascii")
                    + b"\n"
                )
        return Delta(
            from_version=from_version,
            to_version=self._version,
            payload=b"".join(parts),
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
def new_amber_tree() -> AmberTreeImpl:
    """Build a fresh empty :class:`AmberTreeImpl`.

    The empty tree's ``root_hash`` is the constant ``_EMPTY_TREE_HASH_HEX``.
    """
    return AmberTreeImpl()


# ---------------------------------------------------------------------------
# Type-only Protocol conformance check
# ---------------------------------------------------------------------------
_: AmberTree = AmberTreeImpl()


__all__ = [
    "MAX_PATH_LEN",
    "MAX_PAYLOAD_BYTES",
    "AmberTreeImpl",
    "new_amber_tree",
]
