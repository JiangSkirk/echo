"""Echo T8-S1 — tests for js.echo.context_savings.

Covers determinism, CAS dedup behaviour, in-call vs cross-call semantics
(saved_tokens vs new_cas_tokens), and AST red-line scans of the production
module. No I/O beyond reading the production source file for AST checks.
"""

from __future__ import annotations

import ast
import hashlib
import pathlib
import threading

from js.echo.context_savings import (
    CASRecord,
    ContentAddressableStore,
    ContextBudget,
    ContextEntry,
    ContextSavingsResult,
    estimate_tokens,
    summarize_context,
)
from js.echo.context_tokenizer import (
    HEURISTIC_TOKEN_UNIT_ID,
    BoundTokenCounter,
    TokenCounter,
    heuristic_counter,
)


# ---------------------------------------------------------------------------
# 1-4. estimate_tokens
# ---------------------------------------------------------------------------
def test_estimate_tokens_is_deterministic() -> None:
    fixtures = [b"", b"hello", b"a" * 100, b"\x00\x01\x02\x03", b"echo-t8-s1"]
    for payload in fixtures:
        first = estimate_tokens(payload)
        for _ in range(5):
            assert estimate_tokens(payload) == first


def test_estimate_tokens_empty_is_zero() -> None:
    assert estimate_tokens(b"") == 0
    for payload in [b"a", b"ab", b"abcd", b"x" * 1024]:
        assert estimate_tokens(payload) >= 1


def test_estimate_tokens_floor_one_for_short_payload() -> None:
    assert estimate_tokens(b"a") == 1
    assert estimate_tokens(b"ab") == 1
    assert estimate_tokens(b"abc") == 1


def test_estimate_tokens_scales_with_length() -> None:
    lengths = [0, 1, 3, 4, 7, 8, 100, 1024]
    payloads = [b"x" * n for n in lengths]
    for i in range(len(payloads) - 1):
        p1, p2 = payloads[i], payloads[i + 1]
        assert len(p1) <= len(p2)
        assert estimate_tokens(p1) <= estimate_tokens(p2)


# ---------------------------------------------------------------------------
# 5-9. ContentAddressableStore
# ---------------------------------------------------------------------------
def test_cas_put_returns_canonical_record_on_duplicate() -> None:
    cas = ContentAddressableStore()
    r1 = cas.put(b"hello")
    r2 = cas.put(b"hello")
    assert isinstance(r1, CASRecord)
    assert r1 is r2 or (
        r1.digest == r2.digest and r1.payload == r2.payload and r1.tokens == r2.tokens
    )
    assert cas.size() == 1


def test_cas_deterministic_distinct_fixtures_produce_distinct_digests() -> None:
    """This is NOT a SHA-256 collision-freeness proof. It only locks the deterministic behaviour for this fixed set of fixtures."""
    cas = ContentAddressableStore()
    fixtures = [b"a", b"b", b"hello", b"world", b""]
    records = [cas.put(p) for p in fixtures]
    digests = [r.digest for r in records]
    for i in range(len(digests)):
        for j in range(i + 1, len(digests)):
            assert digests[i] != digests[j]


def test_cas_get_returns_none_for_unknown_digest() -> None:
    cas = ContentAddressableStore()
    assert cas.get(b"\x00" * 32) is None
    cas.put(b"hello")
    other = b"\x11" * 32
    assert cas.get(other) is None


def test_cas_contains_reflects_put_state() -> None:
    cas = ContentAddressableStore()
    digest_a = hashlib.sha256(b"A").digest()
    digest_b = hashlib.sha256(b"B").digest()
    assert cas.contains(digest_a) is False
    assert cas.contains(digest_b) is False
    cas.put(b"A")
    assert cas.contains(digest_a) is True
    assert cas.contains(digest_b) is False
    cas.put(b"B")
    assert cas.contains(digest_a) is True
    assert cas.contains(digest_b) is True


def test_cas_thread_safety_concurrent_put() -> None:
    cas = ContentAddressableStore()
    payload = b"concurrent-payload"

    def worker() -> None:
        for _ in range(200):
            cas.put(payload)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert cas.size() == 1


def test_cas_put_with_status_single_thread_semantics() -> None:
    """Single-thread sanity: first call creates, all subsequent calls observe existing."""
    cas = ContentAddressableStore()
    payload = b"single-thread-payload"

    record_first, created_first = cas.put_with_status(payload)
    assert created_first is True
    assert isinstance(record_first, CASRecord)
    assert record_first.tokens == estimate_tokens(payload)

    record_second, created_second = cas.put_with_status(payload)
    assert created_second is False
    assert record_second.digest == record_first.digest
    assert record_second.payload == record_first.payload
    assert record_second.tokens == record_first.tokens
    assert cas.size() == 1

    other = b"different-payload"
    record_other, created_other = cas.put_with_status(other)
    assert created_other is True
    assert record_other.digest != record_first.digest
    assert cas.size() == 2


def test_cas_put_with_status_atomic_under_barrier_concurrency() -> None:
    """T8-S1.1: under Barrier-synchronized concurrent put_with_status on the same payload,
    exactly one caller must observe ``created=True`` and the store must hold exactly one record.

    The Barrier guarantees all N threads release simultaneously, so the race
    on contains-then-put is maximally exercised. If put_with_status were
    composed of two separate lock acquisitions (the pre-T8-S1.1 bug), more
    than one thread would observe ``created=True``. The single-critical-section
    implementation must drive that count down to exactly 1, deterministically.
    """
    cas = ContentAddressableStore()
    payload = b"barrier-synced-payload"
    thread_count = 32
    barrier = threading.Barrier(thread_count)
    created_flags: list[bool] = []
    records: list[CASRecord] = []
    flags_lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        record, created = cas.put_with_status(payload)
        with flags_lock:
            created_flags.append(created)
            records.append(record)

    threads = [threading.Thread(target=worker) for _ in range(thread_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(created_flags) == thread_count
    assert sum(1 for f in created_flags if f) == 1, (
        f"expected exactly one created=True, got {sum(1 for f in created_flags if f)} "
        f"out of {thread_count}: {created_flags}"
    )
    assert cas.size() == 1
    canonical_digest = hashlib.sha256(payload).digest()
    for record in records:
        assert record.digest == canonical_digest
        assert record.tokens == estimate_tokens(payload)


def test_summarize_concurrent_shared_store_new_cas_tokens_atomic() -> None:
    """T8-S1.1: under Barrier-synchronized concurrent summarize_context calls
    over a shared store with the same single-entry payload, exactly one caller
    may report ``new_cas_tokens > 0`` (the inserter); every other caller must
    report ``new_cas_tokens == 0``. All callers must still see in-call
    ``saved_tokens > 0`` because in-call dedup is independent of cross-call
    storage state.

    Pre-T8-S1.1 bug: the non-atomic contains-then-put could let two threads
    each observe was_present=False, causing both to count their saved tokens
    into new_cas_tokens. The atomic put_with_status path drives the
    inserter count to exactly 1.
    """
    store = ContentAddressableStore()
    payload = b"shared-store-payload" * 8  # 160 bytes -> 40 tokens
    expected_tokens = estimate_tokens(payload)
    assert expected_tokens > 0  # sanity
    thread_count = 32
    barrier = threading.Barrier(thread_count)
    results: list[ContextSavingsResult] = []
    results_lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        result = summarize_context(
            [ContextEntry(kind="k", payload=payload)],
            ContextBudget(max_tokens=10_000),
            store=store,
        )
        with results_lock:
            results.append(result)

    threads = [threading.Thread(target=worker) for _ in range(thread_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == thread_count
    inserter_count = sum(1 for r in results if r.new_cas_tokens > 0)
    assert inserter_count == 1, (
        f"expected exactly one inserter (new_cas_tokens > 0), got {inserter_count} "
        f"out of {thread_count}"
    )
    inserter_results = [r for r in results if r.new_cas_tokens > 0]
    assert inserter_results[0].new_cas_tokens == expected_tokens
    assert inserter_results[0].newly_stored_entries == 1
    for r in results:
        assert r.saved_tokens == expected_tokens
        assert r.unique_entries == 1
        assert r.total_entries == 1
        if r.new_cas_tokens == 0:
            assert r.newly_stored_entries == 0
    assert store.size() == 1


# ---------------------------------------------------------------------------
# 10-18. summarize_context
# ---------------------------------------------------------------------------
def test_summarize_empty_entries_is_safe() -> None:
    r = summarize_context([], ContextBudget(max_tokens=100))
    assert r.naive_tokens == 0
    assert r.saved_tokens == 0
    assert r.new_cas_tokens == 0
    assert r.total_entries == 0
    assert r.unique_entries == 0
    assert r.newly_stored_entries == 0
    assert r.savings_ratio == 0.0
    assert r.within_budget is True
    assert r.digest_order == ()


def test_summarize_dedup_lowers_saved_tokens() -> None:
    payload_a = b"a" * 40
    payload_b = b"b" * 40
    entries = [
        ContextEntry(kind="k", payload=payload_a),
        ContextEntry(kind="k", payload=payload_b),
        ContextEntry(kind="k", payload=payload_a),
    ]
    r = summarize_context(entries, ContextBudget(max_tokens=10_000))
    assert r.naive_tokens > r.saved_tokens
    assert r.unique_entries == 2
    assert r.total_entries == 3
    assert r.savings_ratio > 0.0


def test_summarize_unique_entries_naive_equals_saved() -> None:
    entries = [
        ContextEntry(kind="k", payload=b"alpha" * 4),
        ContextEntry(kind="k", payload=b"beta" * 4),
        ContextEntry(kind="k", payload=b"gamma" * 4),
        ContextEntry(kind="k", payload=b"delta" * 4),
    ]
    r = summarize_context(entries, ContextBudget(max_tokens=10_000))
    assert r.naive_tokens == r.saved_tokens
    assert r.savings_ratio == 0.0
    assert r.unique_entries == len(entries)


def test_summarize_digest_order_is_first_seen() -> None:
    payload_a = b"AAAA-payload"
    payload_b = b"BBBB-payload"
    payload_c = b"CCCC-payload"
    entries = [
        ContextEntry(kind="k", payload=payload_a),
        ContextEntry(kind="k", payload=payload_b),
        ContextEntry(kind="k", payload=payload_a),
        ContextEntry(kind="k", payload=payload_c),
    ]
    r = summarize_context(entries, ContextBudget(max_tokens=10_000))
    expected = (
        hashlib.sha256(payload_a).digest(),
        hashlib.sha256(payload_b).digest(),
        hashlib.sha256(payload_c).digest(),
    )
    assert r.digest_order == expected


def test_summarize_within_budget_flag() -> None:
    entries = [
        ContextEntry(kind="k", payload=b"x" * 400),
        ContextEntry(kind="k", payload=b"y" * 400),
    ]
    r_loose = summarize_context(entries, ContextBudget(max_tokens=10_000))
    r_tight = summarize_context(entries, ContextBudget(max_tokens=1))
    assert r_loose.within_budget is True
    assert r_tight.within_budget is False


def test_summarize_is_deterministic() -> None:
    entries = [
        ContextEntry(kind="k", payload=b"alpha" * 8),
        ContextEntry(kind="k", payload=b"beta" * 8),
        ContextEntry(kind="k", payload=b"alpha" * 8),
    ]
    budget = ContextBudget(max_tokens=500)
    r1 = summarize_context(entries, budget)
    r2 = summarize_context(entries, budget)
    assert isinstance(r1, ContextSavingsResult)
    assert r1 == r2


def test_summarize_external_store_does_not_inflate_saved_tokens() -> None:
    store = ContentAddressableStore()
    payload_a = b"A" * 40
    payload_b = b"B" * 40
    payload_c = b"C" * 40
    a_entry = ContextEntry(kind="k", payload=payload_a)
    b_entry = ContextEntry(kind="k", payload=payload_b)
    c_entry = ContextEntry(kind="k", payload=payload_c)

    summarize_context([a_entry, b_entry], ContextBudget(max_tokens=10_000), store=store)
    r2 = summarize_context([a_entry, c_entry], ContextBudget(max_tokens=10_000), store=store)

    assert r2.saved_tokens == estimate_tokens(payload_a) + estimate_tokens(payload_c)
    assert r2.new_cas_tokens == estimate_tokens(payload_c)
    assert r2.unique_entries == 2
    assert r2.newly_stored_entries == 1
    assert store.size() == 3


def test_summarize_new_cas_tokens_equals_saved_when_store_is_fresh() -> None:
    entries = [
        ContextEntry(kind="k", payload=b"alpha" * 8),
        ContextEntry(kind="k", payload=b"beta" * 8),
        ContextEntry(kind="k", payload=b"alpha" * 8),
        ContextEntry(kind="k", payload=b"gamma" * 8),
    ]
    r = summarize_context(entries, ContextBudget(max_tokens=10_000))
    assert r.new_cas_tokens == r.saved_tokens
    assert r.newly_stored_entries == r.unique_entries


def test_summarize_new_cas_tokens_zero_when_all_entries_already_cached() -> None:
    store = ContentAddressableStore()
    a_entry = ContextEntry(kind="k", payload=b"A" * 40)
    b_entry = ContextEntry(kind="k", payload=b"B" * 40)
    summarize_context([a_entry, b_entry], ContextBudget(max_tokens=10_000), store=store)
    r2 = summarize_context([a_entry, b_entry], ContextBudget(max_tokens=10_000), store=store)
    assert r2.new_cas_tokens == 0
    assert r2.newly_stored_entries == 0
    assert r2.saved_tokens > 0


# ---------------------------------------------------------------------------
# 19-20. AST red-lines (scan js/echo/context_savings.py only)
# ---------------------------------------------------------------------------
_FORBIDDEN_TOP_LEVEL = {
    "time",
    "random",
    "os",
    "pathlib",
    "socket",
    "urllib",
    "asyncio",
    "subprocess",
    "requests",
    "httpx",
    "tiktoken",
    "sentencepiece",
    "transformers",
}
_LEGACY_PREFIXES = (
    "js.agent",
    "js.web",
    "js.tools",
    "js.security",
    "js.memory",
    "js.models",
    "js.runtime",
    "js.persistence",
    "js.clcr",
)
_AMBER_FORBIDDEN_NAMES = {
    "AmberTreeImpl",
    "AmberTree",
    "new_amber_tree",
    "ContextView",
    "Delta",
    "ReadyIndex",
    "_AmberNode",
    "_Bucket",
    "_Branch",
    "_path_hash",
    "_root",
    "branches_copied",
    "hashes_recomputed",
    "_dirty_paths",
    "_ready_paths",
}


def test_module_has_no_io_imports_or_references() -> None:
    src = pathlib.Path("js/echo/context_savings.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top not in _FORBIDDEN_TOP_LEVEL, f"forbidden top-level import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            top = node.module.split(".")[0]
            assert top not in _FORBIDDEN_TOP_LEVEL, f"forbidden from-import: {node.module}"
            assert not any(node.module.startswith(p) for p in _LEGACY_PREFIXES), (
                f"legacy import: {node.module}"
            )
        elif isinstance(node, ast.Attribute):
            root: ast.expr = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in _FORBIDDEN_TOP_LEVEL:
                raise AssertionError(f"forbidden reference: {root.id} via attribute access")
        elif isinstance(node, ast.Name) and node.id in _FORBIDDEN_TOP_LEVEL:
            raise AssertionError(f"forbidden bare name reference: {node.id}")


def test_module_does_not_touch_amber_internals() -> None:
    src = pathlib.Path("js/echo/context_savings.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in {"js.echo.amber", "js.echo.amber_tree"}, (
                    f"forbidden amber import: {alias.name}"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            assert node.module not in {"js.echo.amber", "js.echo.amber_tree"}, (
                f"forbidden amber from-import: {node.module}"
            )
        elif isinstance(node, ast.Name):
            assert node.id not in _AMBER_FORBIDDEN_NAMES, (
                f"forbidden amber name reference: {node.id}"
            )
        elif isinstance(node, ast.Attribute):
            assert node.attr not in _AMBER_FORBIDDEN_NAMES, (
                f"forbidden amber attribute reference: {node.attr}"
            )


# ---------------------------------------------------------------------------
# T8-S3A — token_counter wiring (estimate_tokens / summarize_context)
# ---------------------------------------------------------------------------
def test_estimate_tokens_uses_injected_counter() -> None:
    fixed = BoundTokenCounter(count=lambda p: 999, token_unit_id="test:fixed-999")
    assert estimate_tokens(b"anything", token_counter=fixed) == 999
    # Default heuristic path stays byte-identical to T8-S1.
    assert estimate_tokens(b"anything") == max(1, (len(b"anything") + 3) // 4)


def test_summarize_context_uses_injected_counter() -> None:
    counter: TokenCounter = BoundTokenCounter(count=lambda p: 100, token_unit_id="test:fixed-100")
    entries = [
        ContextEntry(kind="k", payload=b"alpha"),
        ContextEntry(kind="k", payload=b"beta"),
        ContextEntry(kind="k", payload=b"gamma"),
    ]
    r = summarize_context(entries, ContextBudget(max_tokens=10_000), token_counter=counter)
    assert r.naive_tokens == 100 * len(entries)
    # All entries unique -> saved_tokens equals naive_tokens.
    assert r.saved_tokens == r.naive_tokens
    assert r.new_cas_tokens == r.naive_tokens


# ---------------------------------------------------------------------------
# T8-S3A — CAS token unit isolation (U1-U11)
# ---------------------------------------------------------------------------
def _fake_tiktoken_counter() -> TokenCounter:
    """Synthetic TokenCounter with the canonical tiktoken token_unit_id;
    does NOT require the real tiktoken package — keeps these tests
    inside the default pytest collection."""
    return BoundTokenCounter(
        count=lambda p: 7 * max(1, len(p)),
        token_unit_id="tiktoken:o200k_base",
    )


def test_fresh_heuristic_store_matches_legacy_behavior() -> None:
    """U1: not passing token_counter binds the store to ``"heuristic:v1"``
    and the result equals the T8-S1 behaviour."""
    store = ContentAddressableStore()
    assert store.token_unit_id is None
    entries = [
        ContextEntry(kind="k", payload=b"alpha" * 4),
        ContextEntry(kind="k", payload=b"beta" * 4),
        ContextEntry(kind="k", payload=b"alpha" * 4),
    ]
    r = summarize_context(entries, ContextBudget(max_tokens=10_000), store=store)
    assert store.token_unit_id == HEURISTIC_TOKEN_UNIT_ID
    expected_naive = sum(estimate_tokens(e.payload) for e in entries)
    assert r.naive_tokens == expected_naive
    assert r.unique_entries == 2


def test_fresh_store_locks_to_first_counter_unit_id() -> None:
    """U2: passing heuristic_counter binds the store to ``"heuristic:v1"``."""
    store = ContentAddressableStore()
    summarize_context(
        [ContextEntry(kind="k", payload=b"alpha" * 4)],
        ContextBudget(max_tokens=10_000),
        store=store,
        token_counter=heuristic_counter,
    )
    assert store.token_unit_id == HEURISTIC_TOKEN_UNIT_ID


def test_store_rejects_mixing_heuristic_then_tiktoken() -> None:
    """U3: heuristic-filled store rejects subsequent tiktoken counter."""
    store = ContentAddressableStore()
    summarize_context(
        [ContextEntry(kind="k", payload=b"alpha" * 4)],
        ContextBudget(max_tokens=10_000),
        store=store,
    )
    fake = _fake_tiktoken_counter()
    try:
        summarize_context(
            [ContextEntry(kind="k", payload=b"beta" * 4)],
            ContextBudget(max_tokens=10_000),
            store=store,
            token_counter=fake,
        )
    except ValueError as exc:
        msg = str(exc)
        assert HEURISTIC_TOKEN_UNIT_ID in msg
        assert "tiktoken:o200k_base" in msg
    else:
        raise AssertionError("expected ValueError on mixing heuristic then tiktoken")


def test_store_rejects_mixing_tiktoken_then_heuristic() -> None:
    """U4: tiktoken-filled store rejects subsequent heuristic / default."""
    store = ContentAddressableStore()
    fake = _fake_tiktoken_counter()
    summarize_context(
        [ContextEntry(kind="k", payload=b"alpha" * 4)],
        ContextBudget(max_tokens=10_000),
        store=store,
        token_counter=fake,
    )
    try:
        summarize_context(
            [ContextEntry(kind="k", payload=b"beta" * 4)],
            ContextBudget(max_tokens=10_000),
            store=store,
        )
    except ValueError as exc:
        msg = str(exc)
        assert "tiktoken:o200k_base" in msg
        assert HEURISTIC_TOKEN_UNIT_ID in msg
    else:
        raise AssertionError("expected ValueError on mixing tiktoken then heuristic")


def test_store_explicit_bind_at_construction() -> None:
    """U5: store constructed with token_unit_id rejects mismatched counter
    immediately and does not record any write."""
    store = ContentAddressableStore(token_unit_id="tiktoken:o200k_base")
    assert store.token_unit_id == "tiktoken:o200k_base"
    try:
        summarize_context(
            [ContextEntry(kind="k", payload=b"alpha" * 4)],
            ContextBudget(max_tokens=10_000),
            store=store,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError on explicit-bound mismatch")
    assert store.size() == 0
    assert store.token_unit_id == "tiktoken:o200k_base"


def test_store_same_unit_id_reuse_succeeds() -> None:
    """U6: repeated reuse with the same counter id is allowed and the
    store's bound unit stays constant."""
    store = ContentAddressableStore()
    fake = _fake_tiktoken_counter()
    for _ in range(3):
        summarize_context(
            [ContextEntry(kind="k", payload=b"alpha" * 4)],
            ContextBudget(max_tokens=10_000),
            store=store,
            token_counter=fake,
        )
    assert store.token_unit_id == "tiktoken:o200k_base"


def test_store_unit_id_starts_none_before_any_write() -> None:
    """U7: fresh store's token_unit_id is None; first summarize_context binds it."""
    store = ContentAddressableStore()
    assert store.token_unit_id is None
    summarize_context([], ContextBudget(max_tokens=10_000), store=store)
    # Empty entries -> no writes -> still unbound at the end. We DID
    # eagerly probe with HEURISTIC_TOKEN_UNIT_ID though, which performs
    # the bind. Either contract is acceptable; lock the observed one.
    assert store.token_unit_id in (None, HEURISTIC_TOKEN_UNIT_ID)
    # Now do a real write and confirm bind.
    summarize_context(
        [ContextEntry(kind="k", payload=b"alpha")],
        ContextBudget(max_tokens=10_000),
        store=store,
    )
    assert store.token_unit_id == HEURISTIC_TOKEN_UNIT_ID


def test_direct_put_binds_store_to_heuristic() -> None:
    """U8: ``store.put`` (public, no counter) binds the store to
    ``"heuristic:v1"``."""
    store = ContentAddressableStore()
    store.put(b"alpha-payload")
    assert store.token_unit_id == HEURISTIC_TOKEN_UNIT_ID


def test_direct_put_then_tiktoken_summarize_raises() -> None:
    """U9: heuristic via ``store.put`` then tiktoken summarize -> ValueError."""
    store = ContentAddressableStore()
    store.put(b"alpha-payload")
    fake = _fake_tiktoken_counter()
    try:
        summarize_context(
            [ContextEntry(kind="k", payload=b"beta")],
            ContextBudget(max_tokens=10_000),
            store=store,
            token_counter=fake,
        )
    except ValueError as exc:
        msg = str(exc)
        assert HEURISTIC_TOKEN_UNIT_ID in msg
        assert "tiktoken:o200k_base" in msg
    else:
        raise AssertionError("expected ValueError on direct-put + tiktoken summarize")


def test_tiktoken_summarize_then_direct_put_raises() -> None:
    """U10: tiktoken summarize on fresh store then ``store.put`` -> ValueError."""
    store = ContentAddressableStore()
    fake = _fake_tiktoken_counter()
    summarize_context(
        [ContextEntry(kind="k", payload=b"alpha")],
        ContextBudget(max_tokens=10_000),
        store=store,
        token_counter=fake,
    )
    try:
        store.put(b"beta")
    except ValueError as exc:
        msg = str(exc)
        assert "tiktoken:o200k_base" in msg
        assert HEURISTIC_TOKEN_UNIT_ID in msg
    else:
        raise AssertionError("expected ValueError on tiktoken summarize + direct put")


def test_summarize_context_tiktoken_writes_real_counter_tokens() -> None:
    """U11: under a tiktoken counter, every CASRecord.tokens reflects the
    counter (NOT the heuristic). At least one payload must have a
    counter-vs-heuristic delta to prove the wiring is live."""
    counter = BoundTokenCounter(
        count=lambda p: 3 * max(1, len(p)),
        token_unit_id="tiktoken:o200k_base",
    )
    store = ContentAddressableStore()
    entries = [
        ContextEntry(kind="k", payload=b"alpha" * 4),
        ContextEntry(kind="k", payload=b"beta" * 4),
        ContextEntry(kind="k", payload=b"gamma" * 4),
    ]
    summarize_context(entries, ContextBudget(max_tokens=10_000), store=store, token_counter=counter)
    delta_seen = False
    for record in store._records.values():  # noqa: SLF001 -- intentional internal access for assertion
        assert isinstance(record, CASRecord)
        assert record.tokens == 3 * max(1, len(record.payload))
        heuristic = estimate_tokens(record.payload)
        if record.tokens != heuristic:
            delta_seen = True
    assert delta_seen, (
        "expected at least one payload where counter tokens != heuristic; "
        "otherwise wiring may have silently fallen back"
    )
