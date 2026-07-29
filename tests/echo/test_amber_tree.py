"""Echo T4 — AmberTreeImpl behaviour contract tests.

This suite pins the real :class:`AmberTreeImpl` (``js/echo/amber_tree.py``)
against the spec §7 / §4 expectations:

1. **Protocol conformance** — ``AmberTreeImpl`` satisfies the
   :class:`AmberTree` runtime-checkable Protocol from
   ``js/echo/amber.py`` (frozen at T2-S2).
2. **Empty-tree contract** — ``new_amber_tree()`` returns a tree whose
   ``root_hash`` is the constant empty-tree hash, ``version == 0``,
   ``ready_index().topk(N) == []``.
3. **Schema-checked commits** — ``commit_checked`` rejects malformed
   paths and oversized / wrong-type payloads via ``ValueError`` and
   does NOT advance the root.
4. **Deterministic hashing** — equal content → equal ``root_hash``
   independent of insertion order; different content → different
   hash.
5. **Structural sharing / immutability** — the original tree is never
   mutated by a commit; the new tree shares structure (proven by
   path-equality on every untouched node).
6. **``mark()`` is index-only** — refuses to introduce new nodes,
   accepts no-op marks, advances version on every call.
7. **``ready_index()`` ordering** — paths returned in sorted order;
   ``topk(0)`` is empty; ``topk(N)`` truncates.
8. **``context_view()``** — stable for unchanged content; differs on
   payload change or status change; produces a sentinel digest for
   missing paths.
9. **``delta_since_last()``** — encodes added / changed entries;
   ``from_version`` / ``to_version`` reflect the chain.
10. **Hermetic** — module uses only stdlib + ``js.echo.*``.

None of these tests touch the filesystem, network, real clock,
randomness, or any legacy engine module. The Hermeticity gate
tests do ``ast.parse`` the ``amber_tree.py`` source as a read-only
self-check; no runtime data files are involved.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from js.echo.amber import AmberTree, ContextView, Delta, NodeStatus, ReadyIndex
from js.echo.amber_tree import (
    MAX_PATH_LEN,
    MAX_PAYLOAD_BYTES,
    AmberTreeImpl,
    new_amber_tree,
)


# ---------------------------------------------------------------------------
# 1. Protocol conformance
# ---------------------------------------------------------------------------
def test_implements_amber_tree_protocol() -> None:
    """``AmberTreeImpl`` must satisfy the runtime-checkable Protocol."""
    tree = new_amber_tree()
    assert isinstance(tree, AmberTree)


def test_factory_returns_empty_tree() -> None:
    """``new_amber_tree()`` is the canonical empty constructor."""
    tree = new_amber_tree()
    assert isinstance(tree, AmberTreeImpl)
    assert tree.version == 0
    assert tree.get("/anything") is None


# ---------------------------------------------------------------------------
# 2. Empty-tree contract
# ---------------------------------------------------------------------------
def test_empty_tree_root_hash_is_constant() -> None:
    """Two empty trees share the same root_hash."""
    a = new_amber_tree()
    b = new_amber_tree()
    assert a.root_hash == b.root_hash
    # Must look like a SHA-256 hex digest.
    assert isinstance(a.root_hash, str)
    assert len(a.root_hash) == 64
    int(a.root_hash, 16)  # raises ValueError if not hex


def test_empty_tree_ready_index_empty() -> None:
    tree = new_amber_tree()
    idx = tree.ready_index()
    assert isinstance(idx, ReadyIndex)
    assert idx.topk(10) == []
    assert idx.topk(0) == []


def test_empty_tree_context_view_returns_sentinel() -> None:
    """``context_view`` for an absent path returns a sentinel digest."""
    tree = new_amber_tree()
    v = tree.context_view("/nowhere")
    assert isinstance(v, ContextView)
    assert isinstance(v.digest, bytes)
    assert len(v.digest) == 32  # SHA-256 digest length


# ---------------------------------------------------------------------------
# 3. Schema-checked commits — invariants
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad_path",
    [
        "",
        "no-leading-slash",
        "/has//double-slash",
        "/has space",
        "/has\x00null",
        "/has\nnewline",
        "/" + "a" * (MAX_PATH_LEN + 1),
    ],
)
def test_commit_rejects_malformed_path(bad_path: str) -> None:
    tree = new_amber_tree()
    original_hash = tree.root_hash
    with pytest.raises(ValueError):
        tree.commit_checked(bad_path, b"payload")
    # The old tree is untouched.
    assert tree.root_hash == original_hash
    assert tree.version == 0


def test_commit_rejects_non_str_path() -> None:
    tree = new_amber_tree()
    with pytest.raises(ValueError):
        tree.commit_checked(b"/binary-path", b"payload")  # type: ignore[arg-type]
    assert tree.version == 0


def test_commit_rejects_non_bytes_payload() -> None:
    tree = new_amber_tree()
    with pytest.raises(ValueError):
        tree.commit_checked("/a", "string-payload")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        tree.commit_checked("/a", 42)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        tree.commit_checked("/a", None)  # type: ignore[arg-type]
    assert tree.version == 0


def test_commit_rejects_oversized_payload() -> None:
    tree = new_amber_tree()
    huge = b"x" * (MAX_PAYLOAD_BYTES + 1)
    with pytest.raises(ValueError):
        tree.commit_checked("/big", huge)
    assert tree.version == 0


def test_commit_accepts_payload_at_cap() -> None:
    tree = new_amber_tree()
    edge = b"x" * MAX_PAYLOAD_BYTES
    new_tree = tree.commit_checked("/edge", edge)
    assert new_tree.version == 1


def test_commit_accepts_bytearray_payload() -> None:
    tree = new_amber_tree()
    new_tree = tree.commit_checked("/x", bytearray(b"abc"))
    # Internally the node payload is bytes, not bytearray.
    node = new_tree.get("/x")
    assert node is not None
    assert isinstance(node.payload, bytes)
    assert node.payload == b"abc"


# ---------------------------------------------------------------------------
# 4. Deterministic hashing
# ---------------------------------------------------------------------------
def test_root_hash_is_order_independent() -> None:
    """Equal content → equal root_hash regardless of insertion order."""
    a = new_amber_tree().commit_checked("/a", b"1").commit_checked("/b", b"2")
    b = new_amber_tree().commit_checked("/b", b"2").commit_checked("/a", b"1")
    assert a.root_hash == b.root_hash


def test_root_hash_changes_on_payload_change() -> None:
    tree = new_amber_tree().commit_checked("/x", b"v1")
    h1 = tree.root_hash
    tree2 = tree.commit_checked("/x", b"v2")
    assert tree2.root_hash != h1


def test_root_hash_changes_on_status_change() -> None:
    tree = new_amber_tree().commit_checked("/x", b"v1")
    h1 = tree.root_hash
    tree2 = tree.mark("/x", NodeStatus.READY)
    assert tree2.root_hash != h1


def test_root_hash_avoids_path_collision() -> None:
    """``/a`` + ``/b/c`` must not hash-collide with ``/a/b`` + ``/c``."""
    a = new_amber_tree().commit_checked("/a", b"").commit_checked("/b/c", b"")
    b = new_amber_tree().commit_checked("/a/b", b"").commit_checked("/c", b"")
    assert a.root_hash != b.root_hash


# ---------------------------------------------------------------------------
# 5. Structural sharing / immutability
# ---------------------------------------------------------------------------
def test_commit_does_not_mutate_original() -> None:
    tree0 = new_amber_tree()
    tree1 = tree0.commit_checked("/a", b"1")
    tree2 = tree1.commit_checked("/b", b"2")

    # tree0 still empty
    assert tree0.version == 0
    assert tree0.get("/a") is None
    assert tree0.root_hash == new_amber_tree().root_hash

    # tree1 has /a but not /b
    assert tree1.version == 1
    assert tree1.get("/a") is not None
    assert tree1.get("/b") is None

    # tree2 has both
    assert tree2.version == 2
    assert tree2.get("/a") is not None
    assert tree2.get("/b") is not None


def test_untouched_nodes_share_reference() -> None:
    """A commit to one path leaves every other path's node identity intact."""
    base = (
        new_amber_tree()
        .commit_checked("/a", b"1")
        .commit_checked("/b", b"2")
        .commit_checked("/c", b"3")
    )
    after = base.commit_checked("/b", b"2-updated")
    # /a and /c nodes should be the SAME object in both trees.
    assert base.get("/a") is after.get("/a")
    assert base.get("/c") is after.get("/c")
    # /b is a fresh object.
    assert base.get("/b") is not after.get("/b")
    node_b = after.get("/b")
    assert node_b is not None
    assert node_b.payload == b"2-updated"


def test_structural_sharing_at_1k_paths() -> None:
    """A commit on a 1000-node tree must complete and preserve untouched nodes."""
    tree = new_amber_tree()
    for i in range(1000):
        tree = tree.commit_checked(f"/n-{i:04d}", f"v{i}".encode())
    base_hash = tree.root_hash

    # Touch one path. Every other node must keep its identity.
    sample_paths = ["/n-0000", "/n-0042", "/n-0500", "/n-0999"]
    sample_before = {p: tree.get(p) for p in sample_paths if p != "/n-0500"}

    tree2 = tree.commit_checked("/n-0500", b"changed")
    assert tree2.version == tree.version + 1
    assert tree2.root_hash != base_hash
    for p, node in sample_before.items():
        assert tree2.get(p) is node, f"untouched node identity broken at {p}"


# ---------------------------------------------------------------------------
# 6. mark() is index-only
# ---------------------------------------------------------------------------
def test_mark_refuses_unknown_path() -> None:
    tree = new_amber_tree()
    with pytest.raises(KeyError):
        tree.mark("/nowhere", NodeStatus.READY)
    assert tree.version == 0


def test_mark_changes_status_and_root_hash() -> None:
    tree = new_amber_tree().commit_checked("/x", b"v")
    h1 = tree.root_hash
    tree2 = tree.mark("/x", NodeStatus.READY)
    node = tree2.get("/x")
    assert node is not None
    assert node.status is NodeStatus.READY
    assert tree2.root_hash != h1
    assert tree2.version == tree.version + 1


def test_mark_noop_still_advances_version() -> None:
    """A re-mark to the SAME status keeps the root_hash but bumps version."""
    tree = new_amber_tree().commit_checked("/x", b"v")
    tree2 = tree.mark("/x", NodeStatus.PENDING)  # already PENDING
    node = tree2.get("/x")
    assert node is not None
    assert node.status is NodeStatus.PENDING
    assert tree2.root_hash == tree.root_hash
    assert tree2.version == tree.version + 1


def test_mark_rejects_non_node_status() -> None:
    tree = new_amber_tree().commit_checked("/x", b"v")
    with pytest.raises(ValueError):
        tree.mark("/x", "ready")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 7. ready_index() ordering
# ---------------------------------------------------------------------------
def test_ready_index_returns_sorted_paths() -> None:
    tree = (
        new_amber_tree()
        .commit_checked("/b", b"")
        .commit_checked("/a", b"")
        .commit_checked("/c", b"")
        .mark("/c", NodeStatus.READY)
        .mark("/a", NodeStatus.READY)
    )
    # /b stayed PENDING; /a and /c are READY (alphabetical).
    idx = tree.ready_index()
    assert idx.topk(10) == ["/a", "/c"]


def test_ready_index_topk_truncates() -> None:
    tree = new_amber_tree()
    for ch in "abcdef":
        tree = tree.commit_checked(f"/{ch}", b"").mark(f"/{ch}", NodeStatus.READY)
    idx = tree.ready_index()
    assert idx.topk(0) == []
    assert idx.topk(2) == ["/a", "/b"]
    assert idx.topk(100) == ["/a", "/b", "/c", "/d", "/e", "/f"]


def test_ready_index_topk_rejects_negative_n() -> None:
    tree = new_amber_tree().commit_checked("/x", b"")
    idx = tree.ready_index()
    with pytest.raises(ValueError):
        idx.topk(-1)


# ---------------------------------------------------------------------------
# 8. context_view stability
# ---------------------------------------------------------------------------
def test_context_view_stable_across_unrelated_commits() -> None:
    """Committing to /a must not change /b's context view digest."""
    tree = new_amber_tree().commit_checked("/a", b"1").commit_checked("/b", b"2")
    d_b1 = tree.context_view("/b").digest
    tree2 = tree.commit_checked("/a", b"1-updated")
    d_b2 = tree2.context_view("/b").digest
    assert d_b1 == d_b2


def test_context_view_changes_on_payload_change() -> None:
    tree = new_amber_tree().commit_checked("/x", b"v1")
    d1 = tree.context_view("/x").digest
    tree2 = tree.commit_checked("/x", b"v2")
    d2 = tree2.context_view("/x").digest
    assert d1 != d2


def test_context_view_changes_on_status_change() -> None:
    tree = new_amber_tree().commit_checked("/x", b"v")
    d1 = tree.context_view("/x").digest
    tree2 = tree.mark("/x", NodeStatus.READY)
    d2 = tree2.context_view("/x").digest
    assert d1 != d2


def test_context_view_missing_path_is_distinct_from_present() -> None:
    tree = new_amber_tree().commit_checked("/x", b"")
    d_present = tree.context_view("/x").digest
    d_missing = tree.context_view("/missing").digest
    assert d_present != d_missing


# ---------------------------------------------------------------------------
# 9. delta_since_last()
# ---------------------------------------------------------------------------
def test_delta_for_empty_tree() -> None:
    tree = new_amber_tree()
    d = tree.delta_since_last()
    assert isinstance(d, Delta)
    assert d.from_version == 0
    assert d.to_version == 0
    assert d.payload == b""


def test_delta_records_added_node() -> None:
    base = new_amber_tree()
    after = base.commit_checked("/x", b"v")
    d = after.delta_since_last()
    assert d.from_version == 0
    assert d.to_version == 1
    assert b"+/x" in d.payload
    assert NodeStatus.PENDING.value.encode("utf-8") in d.payload


def test_delta_records_status_change_but_not_unchanged_paths() -> None:
    tree = new_amber_tree().commit_checked("/a", b"1").commit_checked("/b", b"2")
    after = tree.mark("/a", NodeStatus.READY)
    d = after.delta_since_last()
    assert b"+/a" in d.payload
    # /b unchanged → must not appear
    assert b"+/b" not in d.payload
    assert d.from_version == tree.version
    assert d.to_version == after.version


def test_delta_is_deterministic_for_equal_chains() -> None:
    """Two independent chains producing the same end-state share the same delta."""
    a = new_amber_tree().commit_checked("/x", b"v").mark("/x", NodeStatus.READY)
    b = new_amber_tree().commit_checked("/x", b"v").mark("/x", NodeStatus.READY)
    # The last edge in each chain is the READY mark; deltas at that
    # step are over the same (prev_tree, cur_tree) shape.
    assert a.delta_since_last().payload == b.delta_since_last().payload


# ---------------------------------------------------------------------------
# 10. Hermeticity — no legacy imports, no I/O modules
# ---------------------------------------------------------------------------
_FORBIDDEN_PREFIXES = (
    "js.agent",
    "js.clcr",
    "js.web",
    "js.tools",
    "js.memory",
    "js.models",
    "js.security",
)
_FORBIDDEN_IO = (
    "open(",
    "os.",
    "time.",
    "random",
    "logging",
    "asyncio",
    "subprocess",
    "httpx",
    "requests",
    "pathlib",
)
_AMBER_TREE = pathlib.Path(__file__).resolve().parents[2] / "js" / "echo" / "amber_tree.py"


def test_amber_tree_no_legacy_imports() -> None:
    tree = ast.parse(_AMBER_TREE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                for fbd in _FORBIDDEN_PREFIXES:
                    assert not (alias.name == fbd or alias.name.startswith(fbd + ".")), (
                        f"amber_tree.py imports forbidden module: {alias.name}"
                    )
        elif isinstance(node, ast.ImportFrom) and node.module:
            for fbd in _FORBIDDEN_PREFIXES:
                assert not (node.module == fbd or node.module.startswith(fbd + ".")), (
                    f"amber_tree.py imports forbidden module: {node.module}"
                )


def test_amber_tree_no_io_tokens() -> None:
    src = _AMBER_TREE.read_text(encoding="utf-8")
    for tok in _FORBIDDEN_IO:
        assert tok not in src, f"amber_tree.py mentions forbidden I/O token {tok!r}"
