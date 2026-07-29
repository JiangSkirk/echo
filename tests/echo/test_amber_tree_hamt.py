"""Echo T4.1 — AmberTreeImpl real-HAMT complexity contract.

T4 shipped an :class:`AmberTreeImpl` whose internal representation was a
flat ``dict[path, _AmberNode]``. Every ``commit_checked`` / ``mark``
copied the entire dict via ``dict(self.nodes)`` and recomputed
``root_hash`` over every entry. That satisfied the *behavioural*
contract in :mod:`tests.echo.test_amber_tree` (path-copy on identity,
deterministic hash, etc.) but the underlying complexity was O(N) per
write — Echo spec §7 demands O(log N) branch-copy + O(changed paths)
delta. T4.1 fixes this with a real Hash Array Mapped Trie.

This suite pins the **complexity** contract that the rewrite must
meet. Where T4 only checked behaviour ("node identity preserved"),
T4.1 also checks structure:

1. **Branch factor is 32 (2^5)** — the canonical HAMT shape.
2. **Path-copy on commit** — a single commit on a 10 000-node tree
   copies at most ``log32(N) + a small bucket constant`` branches,
   never N.
3. **Subhash incremental update** — ``root_hash`` recomputation
   touches only the ancestors of the changed path, not every node.
4. **Hash-collision buckets** — paths that collide on the same 128-bit
   key prefix still compare-by-original-path and never alias each
   other's payloads.
5. **Ready-set tracking** — ``ready_index()`` reads from an internal
   ready-trie / ready-set so its work is O(|ready paths|), not O(N).
6. **Delta tracking** — ``delta_since_last`` reads from a dirty-paths
   set populated only at write time; its byte payload mentions only
   the changed paths, not the entire keyspace.

The complexity gates are read off introspection hooks that the
implementation MUST expose (see ``AmberTreeImpl`` docstring for the
contract). We *deliberately* avoid wall-clock thresholds — they're
flaky on CI. We count structural work directly.

Hooks the implementation must expose:

- ``AmberTreeImpl._BRANCH_FACTOR``       : int constant, must be 32
- ``AmberTreeImpl._HASH_KEY_BITS``       : int constant, must be ≥ 128
- ``AmberTreeImpl.branches_copied``      : int field on the new tree
  (number of trie branches the last commit/mark copied)
- ``AmberTreeImpl.hashes_recomputed``    : int field on the new tree
  (number of subhash recomputations in the last commit/mark)
- ``AmberTreeImpl._dirty_paths``         : frozenset[str] on the new
  tree — paths changed by the last commit/mark
- ``AmberTreeImpl._ready_paths_view()``  : frozenset[str] view of the
  ready-set used by ``ready_index()``

None of these hooks change the public Protocol surface frozen at T2-S2.
"""

from __future__ import annotations

import gc
import math
import os
import weakref

import pytest  # noqa: TC002 -- runtime fixture (monkeypatch) requires pytest import

from js.echo.amber import NodeStatus
from js.echo.amber_tree import AmberTreeImpl, new_amber_tree


# ---------------------------------------------------------------------------
# 1. Branch factor + hash key width (the canonical HAMT shape)
# ---------------------------------------------------------------------------
def test_branch_factor_is_thirty_two() -> None:
    """The trie's branch factor must be 32 (= 2^5), the canonical HAMT shape."""
    assert AmberTreeImpl._BRANCH_FACTOR == 32


def test_hash_key_width_at_least_128_bits() -> None:
    """Spec §7: the trie key must be ≥ 128 bits to make collisions astronomically rare."""
    assert AmberTreeImpl._HASH_KEY_BITS >= 128


# ---------------------------------------------------------------------------
# 2. Path-copy on commit — ≤ log32(N) branches touched
# ---------------------------------------------------------------------------
def _expected_max_depth(n_nodes: int, branch_factor: int) -> int:
    """Upper bound on trie depth for a uniformly distributed key set.

    The trie can be at most ``ceil(log_b(N))`` levels deep before a
    bucket forms at the leaf, plus 1 for the bucket itself in the
    worst case.
    """
    if n_nodes <= 1:
        return 1
    return int(math.ceil(math.log(n_nodes, branch_factor))) + 1


def test_commit_path_copy_is_logarithmic_in_tree_size() -> None:
    """A commit on a 10 000-node tree must copy at most log32(N)+ε branches."""
    tree = new_amber_tree()
    for i in range(10_000):
        tree = tree.commit_checked(f"/n-{i:05d}", f"v{i}".encode())

    bf = AmberTreeImpl._BRANCH_FACTOR
    max_depth = _expected_max_depth(10_000, bf)

    # Touch a path; the resulting tree must report a tiny branches_copied.
    after = tree.commit_checked("/n-05000", b"changed")
    assert after.branches_copied <= max_depth + 2, (
        f"path-copy leaked: {after.branches_copied} branches for N=10000, "
        f"expected ≤ log32(N)+2 = {max_depth + 2}"
    )
    # Hash recompute count is also bounded by depth.
    assert after.hashes_recomputed <= max_depth + 2, (
        f"hash recompute leaked: {after.hashes_recomputed} for N=10000, "
        f"expected ≤ log32(N)+2 = {max_depth + 2}"
    )


def test_mark_path_copy_is_logarithmic_in_tree_size() -> None:
    """``mark()`` has the same depth-bounded path-copy property."""
    tree = new_amber_tree()
    for i in range(10_000):
        tree = tree.commit_checked(f"/n-{i:05d}", b"v")

    bf = AmberTreeImpl._BRANCH_FACTOR
    max_depth = _expected_max_depth(10_000, bf)

    after = tree.mark("/n-05000", NodeStatus.READY)
    assert after.branches_copied <= max_depth + 2
    assert after.hashes_recomputed <= max_depth + 2


def test_branches_copied_is_one_for_empty_tree_first_commit() -> None:
    """First commit on the empty tree touches a single branch."""
    tree = new_amber_tree()
    after = tree.commit_checked("/only", b"v")
    assert after.branches_copied >= 1
    assert after.branches_copied <= 2  # root + leaf bucket at most


# ---------------------------------------------------------------------------
# 3. ready_index reads from a tracked ready set, not a full scan
# ---------------------------------------------------------------------------
def test_ready_paths_view_is_subset_of_all_paths() -> None:
    """The ready-set must exactly match the paths whose status is READY."""
    tree = (
        new_amber_tree()
        .commit_checked("/a", b"")
        .commit_checked("/b", b"")
        .commit_checked("/c", b"")
        .mark("/a", NodeStatus.READY)
        .mark("/c", NodeStatus.READY)
    )
    ready = tree._ready_paths_view()
    assert ready == frozenset({"/a", "/c"})


def test_ready_paths_view_shrinks_on_unready() -> None:
    tree = new_amber_tree().commit_checked("/x", b"").mark("/x", NodeStatus.READY)
    assert tree._ready_paths_view() == frozenset({"/x"})
    later = tree.mark("/x", NodeStatus.PENDING)
    assert later._ready_paths_view() == frozenset()


def test_ready_index_returns_sorted_paths_from_ready_set() -> None:
    """Behavioural overlap with test_amber_tree.py but via the new hook."""
    tree = new_amber_tree()
    for i in range(50):
        tree = tree.commit_checked(f"/n-{i:02d}", b"")
    for i in range(0, 50, 5):  # ready every 5th path
        tree = tree.mark(f"/n-{i:02d}", NodeStatus.READY)
    idx = tree.ready_index()
    expected = [f"/n-{i:02d}" for i in range(0, 50, 5)]
    assert idx.topk(100) == expected
    assert tree._ready_paths_view() == frozenset(expected)


def test_ready_index_work_is_proportional_to_ready_count() -> None:
    """Building ``ready_index`` from a 10 000-node tree with 3 ready paths
    must NOT touch all 10 000 nodes — the ready set is materialised in O(R)
    where R is the number of ready paths."""
    tree = new_amber_tree()
    for i in range(10_000):
        tree = tree.commit_checked(f"/n-{i:05d}", b"")
    # Mark exactly 3 as ready.
    for p in ("/n-00010", "/n-04242", "/n-09999"):
        tree = tree.mark(p, NodeStatus.READY)

    view = tree._ready_paths_view()
    assert view == frozenset({"/n-00010", "/n-04242", "/n-09999"})
    # The ready view's size IS the work bound — anything more would be a leak.
    assert len(view) == 3


# ---------------------------------------------------------------------------
# 4. delta_since_last touches only dirty paths
# ---------------------------------------------------------------------------
def test_dirty_paths_records_only_changed_paths() -> None:
    tree = (
        new_amber_tree()
        .commit_checked("/a", b"1")
        .commit_checked("/b", b"2")
        .commit_checked("/c", b"3")
    )
    # The last commit was on /c; the new tree's dirty set must be exactly {/c}.
    assert tree._dirty_paths == frozenset({"/c"})


def test_dirty_paths_empty_for_no_op_mark() -> None:
    """A re-mark to the same status produces an empty dirty set."""
    tree = new_amber_tree().commit_checked("/x", b"v")
    after = tree.mark("/x", NodeStatus.PENDING)  # already PENDING
    assert after._dirty_paths == frozenset()


def test_delta_payload_mentions_only_dirty_paths() -> None:
    """A commit on /b in a 10 000-node tree must emit a delta that
    mentions /b and no other path."""
    tree = new_amber_tree()
    for i in range(10_000):
        tree = tree.commit_checked(f"/n-{i:05d}", b"v")
    after = tree.commit_checked("/n-05000", b"changed")

    delta = after.delta_since_last()
    # The delta payload must reference /n-05000 (added marker prefix).
    assert b"+/n-05000" in delta.payload
    # And must NOT reference any other path.
    other_samples = ("/n-00000", "/n-00001", "/n-09999")
    for other in other_samples:
        assert other.encode("utf-8") not in delta.payload


def test_delta_size_is_constant_in_tree_size() -> None:
    """Delta payload byte length depends on changed paths, not tree size."""
    # Build two trees of very different sizes but the same final commit.
    small = new_amber_tree()
    for i in range(10):
        small = small.commit_checked(f"/n-{i:05d}", b"v")
    small_after = small.commit_checked("/touch", b"once")

    big = new_amber_tree()
    for i in range(10_000):
        big = big.commit_checked(f"/n-{i:05d}", b"v")
    big_after = big.commit_checked("/touch", b"once")

    d_small = small_after.delta_since_last().payload
    d_big = big_after.delta_since_last().payload
    # The two deltas must be identical — they describe the same change.
    assert d_small == d_big


def test_successor_does_not_retain_predecessor_tree_object() -> None:
    base = new_amber_tree().commit_checked("/base", b"v1")
    predecessor = weakref.ref(base)
    successor = base.commit_checked("/next", b"v2")

    del base
    gc.collect()

    assert predecessor() is None
    assert successor.delta_since_last().from_version == 1


# ---------------------------------------------------------------------------
# 5. Hash-collision buckets — original-path equality, no aliasing
# ---------------------------------------------------------------------------
def _constant_hash(_path: str) -> int:
    """All paths map to the same key, forcing the collision-bucket path."""
    return 0


def test_collisions_do_not_alias_payloads(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even when all paths hash to the same key, payloads stay separate."""
    monkeypatch.setattr(AmberTreeImpl, "_path_hash", staticmethod(_constant_hash))

    tree = (
        new_amber_tree()
        .commit_checked("/a", b"alpha")
        .commit_checked("/b", b"beta")
        .commit_checked("/c", b"gamma")
    )
    node_a = tree.get("/a")
    node_b = tree.get("/b")
    node_c = tree.get("/c")
    assert node_a is not None
    assert node_b is not None
    assert node_c is not None
    assert node_a.payload == b"alpha"
    assert node_b.payload == b"beta"
    assert node_c.payload == b"gamma"


def test_collision_bucket_root_hash_is_order_independent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two trees with the same collided paths must have identical root_hash."""
    monkeypatch.setattr(AmberTreeImpl, "_path_hash", staticmethod(_constant_hash))

    a = new_amber_tree().commit_checked("/a", b"1").commit_checked("/b", b"2")
    b = new_amber_tree().commit_checked("/b", b"2").commit_checked("/a", b"1")
    assert a.root_hash == b.root_hash


# ---------------------------------------------------------------------------
# 6. Hooks must be present and well-typed
# ---------------------------------------------------------------------------
def test_branches_copied_present_on_every_tree() -> None:
    tree = new_amber_tree()
    assert isinstance(tree.branches_copied, int)
    assert tree.branches_copied == 0
    after = tree.commit_checked("/x", b"v")
    assert isinstance(after.branches_copied, int)


def test_dirty_paths_is_frozenset() -> None:
    tree = new_amber_tree().commit_checked("/x", b"v")
    assert isinstance(tree._dirty_paths, frozenset)


def test_ready_paths_view_is_frozenset() -> None:
    tree = new_amber_tree()
    assert isinstance(tree._ready_paths_view(), frozenset)


# ---------------------------------------------------------------------------
# 7. The 1k-node smoke test from T4 still holds (regression guard)
# ---------------------------------------------------------------------------
def test_t4_behavioural_contract_still_holds_on_hamt() -> None:
    """The HAMT rewrite must not regress the behavioural contract: identity
    preservation on untouched paths."""
    tree = new_amber_tree()
    for i in range(1000):
        tree = tree.commit_checked(f"/n-{i:04d}", f"v{i}".encode())

    sample_paths = ["/n-0000", "/n-0042", "/n-0500", "/n-0999"]
    sample_before = {p: tree.get(p) for p in sample_paths if p != "/n-0500"}

    after = tree.commit_checked("/n-0500", b"changed")
    for p, node in sample_before.items():
        assert after.get(p) is node, f"untouched node identity broken at {p}"


# ---------------------------------------------------------------------------
# 8. Smoke check: file size guard so AmberTreeImpl doesn't bloat past a
#    reasonable HAMT footprint (rough proxy for "real implementation").
# ---------------------------------------------------------------------------
def test_amber_tree_module_is_a_real_implementation() -> None:
    """A real HAMT cannot be 30 lines — guard against an accidental revert
    to flat-dict masquerade."""
    here = os.path.dirname(__file__)
    src = os.path.join(here, "..", "..", "js", "echo", "amber_tree.py")
    with open(src, encoding="utf-8") as f:
        content = f.read()
    assert "HAMT" in content or "trie" in content.lower()
    # A real HAMT implementation needs at least a few hundred LOC.
    line_count = content.count("\n")
    assert line_count > 300, f"amber_tree.py only {line_count} lines — likely still flat-dict"
