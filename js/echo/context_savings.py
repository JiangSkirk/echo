"""Echo T8-S1 — Context Savings baseline + Content-Addressed Store (CAS) harness.

Pure-in-memory, deterministic, zero-I/O. Provides:

* :func:`estimate_tokens` — deterministic token-count heuristic over raw bytes;
  **NOT a real tokenizer**. T8-S3A injects real tokenizers through the
  ``token_counter`` keyword-only parameter; default fallback preserves the
  T8-S1 heuristic verbatim.
* :class:`ContentAddressableStore` — thread-safe in-memory CAS keyed by
  SHA-256 of payload bytes. Idempotent ``put``; lookup by digest.
  T8-S3A: bound to a single ``token_unit_id`` for its lifetime — mixing
  heuristic and tiktoken token counts in the same store raises
  ``ValueError``.
* :class:`ContextEntry` / :class:`ContextBudget` / :class:`CASRecord` /
  :class:`ContextSavingsResult` — frozen carriers.
* :func:`summarize_context` — fold a sequence of entries through a CAS and
  compute naive vs in-call-deduped token counters. Accepts
  ``token_counter=None`` keyword-only argument (T8-S3A); default is the
  heuristic, no behaviour change for T8-S1/T8-S2 callers.

Cross-call semantics
--------------------
``ContextSavingsResult.saved_tokens`` is the **in-call** deduped total.
It is NOT "tokens saved across turns". When the caller supplies an external
``store``, ``saved_tokens`` still counts every distinct digest from THIS
call's entries, regardless of whether the payload was already in the store.
Use ``new_cas_tokens`` / ``newly_stored_entries`` to track what this call
genuinely added to long-lived storage.

Token unit isolation (T8-S3A)
-----------------------------
``ContentAddressableStore`` records the ``token_unit_id`` of the first
counter that writes into it (``"heuristic:v1"`` for ``put`` /
``put_with_status`` / a ``summarize_context`` call without
``token_counter``; ``"tiktoken:o200k_base"`` etc. for tiktoken-counter
calls). Subsequent writes using a different unit id raise ``ValueError``;
``CASRecord.tokens`` is therefore guaranteed to be expressed in a single
unit per store. See :mod:`js.echo.context_tokenizer`.

Constraints
-----------
* Does NOT depend on AmberTree HAMT internals.
* Does NOT touch ``js.echo.runtime`` / ``gateway`` / ``capability`` /
  ``sandbox``.
* Does NOT read environment variables or perform any I/O.
* Production module top-level imports avoid ``tiktoken`` /
  ``sentencepiece`` / ``transformers``; real tokenizers come through the
  ``TokenCounter`` Protocol (see :mod:`js.echo.context_tokenizer`).
* Not exported through ``js.echo.__init__.__all__`` (implementation module,
  same convention as ``capability`` / ``sandbox`` / ``runtime``).
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from js.echo.context_tokenizer import HEURISTIC_TOKEN_UNIT_ID, TokenCounter

__all__ = [
    "CASRecord",
    "CASStoreMetrics",
    "ContentAddressableStore",
    "ContextBudget",
    "ContextEntry",
    "ContextSavingsResult",
    "estimate_tokens",
    "summarize_context",
]


# ---------------------------------------------------------------------------
# Frozen carriers
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ContextEntry:
    kind: str
    payload: bytes


@dataclass(frozen=True)
class ContextBudget:
    max_tokens: int


@dataclass(frozen=True)
class CASRecord:
    digest: bytes  # 32-byte SHA-256
    payload: bytes
    tokens: int


@dataclass(frozen=True)
class CASStoreMetrics:
    record_count: int
    retained_payload_bytes: int
    eviction_count: int
    evicted_payload_bytes: int
    rejection_count: int
    rejected_payload_bytes: int


@dataclass(frozen=True)
class ContextSavingsResult:
    naive_tokens: int
    saved_tokens: int
    new_cas_tokens: int
    total_entries: int
    unique_entries: int
    newly_stored_entries: int
    savings_ratio: float
    within_budget: bool
    digest_order: tuple[bytes, ...]


# ---------------------------------------------------------------------------
# Token heuristic
# ---------------------------------------------------------------------------
def estimate_tokens(
    payload: bytes,
    *,
    token_counter: TokenCounter | None = None,
) -> int:
    """Deterministic token-count over raw bytes.

    If ``token_counter`` is provided, delegate to it (real tokenizer
    injection path, T8-S3A). Otherwise fall back to the T8-S1 heuristic
    that approximates ~4 bytes/token with a floor of 1 for any non-empty
    payload.

    The heuristic branch is byte-identical to the T8-S1 implementation
    (``js.echo.context_tokenizer._heuristic_count`` is the same algorithm
    for cross-checks).
    """
    if token_counter is not None:
        return token_counter(payload)
    if not payload:
        return 0
    return max(1, (len(payload) + 3) // 4)


# ---------------------------------------------------------------------------
# Content-Addressable Store
# ---------------------------------------------------------------------------
class ContentAddressableStore:
    """Thread-safe in-memory CAS keyed by SHA-256 of payload bytes.

    ``put`` is idempotent: re-inserting an identical payload returns the
    existing :class:`CASRecord` without mutating insertion order.

    T8-S3A — token unit isolation
    -----------------------------
    Each store is bound to a single ``token_unit_id`` for its lifetime.
    The binding happens on first write (either an explicit ``put`` /
    ``put_with_status``, which binds to ``"heuristic:v1"``, or a
    ``summarize_context(..., token_counter=...)`` call, which binds to
    the counter's ``token_unit_id``). Subsequent writes that present a
    different ``token_unit_id`` raise :class:`ValueError`. This prevents
    silent reuse of ``CASRecord.tokens`` values across heuristic and
    tiktoken counters, which would mean different units in the same
    field.

    Pass ``token_unit_id`` at construction time to lock the binding
    eagerly — useful when the store is reserved for a specific
    tokenizer ahead of any write.

    Optional ``max_payload_bytes`` and ``max_records`` bounds evict the
    oldest records before admitting a new payload. Reservation callbacks let
    a caller enforce a wider shared byte budget without weakening the local
    limits. :meth:`metrics` reports retained payload bytes, evictions, and
    rejected retention attempts atomically.
    """

    __slots__ = (
        "_evicted_payload_bytes",
        "_eviction_count",
        "_insertion_order",
        "_lock",
        "_max_payload_bytes",
        "_max_records",
        "_on_payload_rejected",
        "_records",
        "_rejected_payload_bytes",
        "_rejection_count",
        "_release_payload_bytes",
        "_reserve_payload_bytes",
        "_retained_payload_bytes",
        "_token_unit_id",
    )

    def __init__(
        self,
        *,
        token_unit_id: str | None = None,
        max_payload_bytes: int | None = None,
        max_records: int | None = None,
        reserve_payload_bytes: Callable[[int], bool] | None = None,
        release_payload_bytes: Callable[[int], None] | None = None,
        on_payload_rejected: Callable[[int], None] | None = None,
    ) -> None:
        if max_payload_bytes is not None and max_payload_bytes < 0:
            raise ValueError("max_payload_bytes must be non-negative")
        if max_records is not None and max_records < 0:
            raise ValueError("max_records must be non-negative")
        if (reserve_payload_bytes is None) != (release_payload_bytes is None):
            raise ValueError(
                "reserve_payload_bytes and release_payload_bytes must be provided together"
            )
        self._lock: threading.RLock = threading.RLock()
        self._records: dict[bytes, CASRecord] = {}
        self._insertion_order: list[bytes] = []
        self._token_unit_id: str | None = token_unit_id
        self._max_payload_bytes = max_payload_bytes
        self._max_records = max_records
        self._reserve_payload_bytes = reserve_payload_bytes
        self._release_payload_bytes = release_payload_bytes
        self._on_payload_rejected = on_payload_rejected
        self._retained_payload_bytes = 0
        self._eviction_count = 0
        self._evicted_payload_bytes = 0
        self._rejection_count = 0
        self._rejected_payload_bytes = 0

    @property
    def token_unit_id(self) -> str | None:
        """Currently bound token unit id, or ``None`` if no write has
        bound the store yet."""
        with self._lock:
            return self._token_unit_id

    def _check_or_bind_token_unit(self, unit_id: str) -> None:
        """Bind on first write; reject mismatched reuse after.

        Caller must hold ``self._lock``.
        """
        if self._token_unit_id is None:
            self._token_unit_id = unit_id
            return
        if self._token_unit_id != unit_id:
            raise ValueError(
                f"ContentAddressableStore bound to token_unit_id="
                f"{self._token_unit_id!r}; refusing reuse with "
                f"{unit_id!r}. CAS token units must not mix."
            )

    def put(self, payload: bytes) -> CASRecord:
        record, _created = self.put_with_status(payload)
        return record

    def put_with_status(self, payload: bytes) -> tuple[CASRecord, bool]:
        """Atomically insert-or-fetch ``payload`` and report whether THIS call created the record.

        Returns ``(record, created)`` where ``created`` is ``True`` iff this
        invocation was the one that inserted ``payload`` into the store.
        The lookup-then-insert is performed inside a single critical section,
        so under concurrent calls with the same payload exactly one caller
        sees ``created=True`` and every other caller sees ``created=False``.

        T8-S1.1 atomicity fix: the previous ``contains(digest)`` + ``put(payload)``
        composition used two separate ``_lock`` acquisitions, which let two
        concurrent calls each observe ``contains == False`` and both claim
        to be the inserter — inflating ``summarize_context.new_cas_tokens``
        beyond the true number of records added to the CAS. This method
        collapses that two-step probe into one critical section so callers
        can compute ``new_cas_tokens`` without racing.

        T8-S3A: public ``put`` path always counts tokens with the
        heuristic (binding the store to ``"heuristic:v1"`` if not already
        bound). Counter-driven writes go through
        :meth:`_put_with_status_counted` from inside
        :func:`summarize_context`.
        """
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError(f"payload must be bytes or bytearray, got {type(payload).__name__}")
        payload_bytes = bytes(payload)
        return self._put_with_status_impl(
            payload_bytes,
            tokens=estimate_tokens(payload_bytes),
            token_unit_id=HEURISTIC_TOKEN_UNIT_ID,
        )

    def _put_with_status_counted(
        self,
        payload: bytes,
        *,
        tokens: int,
        token_unit_id: str,
    ) -> tuple[CASRecord, bool]:
        """Internal: insert-or-fetch with caller-supplied tokens / unit id.

        Used by :func:`summarize_context` when a ``token_counter`` is
        injected. Performs the unit-id bind/check before any state
        mutation so a mismatched call leaves the store untouched.

        NOT public; not exported through ``__all__``. Behavioural
        contract mirrors :meth:`put_with_status` but ``tokens`` and the
        binding ``token_unit_id`` come from the caller's counter rather
        than the heuristic.
        """
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError(f"payload must be bytes or bytearray, got {type(payload).__name__}")
        payload_bytes = bytes(payload)
        return self._put_with_status_impl(
            payload_bytes,
            tokens=tokens,
            token_unit_id=token_unit_id,
        )

    def _put_with_status_impl(
        self,
        payload: bytes,
        *,
        tokens: int,
        token_unit_id: str,
    ) -> tuple[CASRecord, bool]:
        digest = hashlib.sha256(payload).digest()
        with self._lock:
            self._check_or_bind_token_unit(token_unit_id)
            existing = self._records.get(digest)
            if existing is not None:
                return existing, False
            record = CASRecord(
                digest=digest,
                payload=payload,
                tokens=tokens,
            )
            payload_size = len(payload)
            if self._max_records == 0 or (
                self._max_payload_bytes is not None and payload_size > self._max_payload_bytes
            ):
                self._record_rejection(payload_size)
                return record, False

            self._evict_until_fits(payload_size)
            if self._reserve_payload_bytes is not None and not self._reserve_payload_bytes(
                payload_size
            ):
                self._record_rejection(payload_size)
                return record, False

            self._records[digest] = record
            self._insertion_order.append(digest)
            self._retained_payload_bytes += payload_size
            return record, True

    def _evict_until_fits(self, payload_size: int) -> None:
        """Evict oldest records until a new payload fits local hard limits.

        Caller must hold ``self._lock``.
        """
        while self._records and (
            (self._max_records is not None and len(self._records) >= self._max_records)
            or (
                self._max_payload_bytes is not None
                and self._retained_payload_bytes + payload_size > self._max_payload_bytes
            )
        ):
            digest = self._insertion_order.pop(0)
            evicted = self._records.pop(digest)
            evicted_size = len(evicted.payload)
            self._retained_payload_bytes -= evicted_size
            self._eviction_count += 1
            self._evicted_payload_bytes += evicted_size
            if self._release_payload_bytes is not None:
                self._release_payload_bytes(evicted_size)

    def _record_rejection(self, payload_size: int) -> None:
        """Record a payload that could not be retained. Caller holds the lock."""
        self._rejection_count += 1
        self._rejected_payload_bytes += payload_size
        if self._on_payload_rejected is not None:
            self._on_payload_rejected(payload_size)

    def get(self, digest: bytes) -> CASRecord | None:
        with self._lock:
            return self._records.get(digest)

    def contains(self, digest: bytes) -> bool:
        with self._lock:
            return digest in self._records

    def size(self) -> int:
        with self._lock:
            return len(self._records)

    def retained_payload_bytes(self) -> int:
        with self._lock:
            return self._retained_payload_bytes

    def eviction_count(self) -> int:
        with self._lock:
            return self._eviction_count

    def metrics(self) -> CASStoreMetrics:
        with self._lock:
            return CASStoreMetrics(
                record_count=len(self._records),
                retained_payload_bytes=self._retained_payload_bytes,
                eviction_count=self._eviction_count,
                evicted_payload_bytes=self._evicted_payload_bytes,
                rejection_count=self._rejection_count,
                rejected_payload_bytes=self._rejected_payload_bytes,
            )

    def digest_order(self) -> tuple[bytes, ...]:
        with self._lock:
            return tuple(self._insertion_order)


# ---------------------------------------------------------------------------
# summarize_context
# ---------------------------------------------------------------------------
def summarize_context(
    entries: Sequence[ContextEntry],
    budget: ContextBudget,
    *,
    store: ContentAddressableStore | None = None,
    token_counter: TokenCounter | None = None,
    llmlingua: bool = False,
    llmlingua_max_ratio: float = 10.0,
) -> ContextSavingsResult:
    """Fold ``entries`` through a CAS and compute savings counters.

    See module docstring for cross-call semantics. ``saved_tokens`` is the
    in-call deduped total; ``new_cas_tokens`` reflects only entries that
    were newly added to ``store`` during this call.

    T8-S3A — token_counter
    ----------------------
    If ``token_counter`` is provided, all token counts come from it (both
    the ``naive`` accumulator and ``CASRecord.tokens`` for newly stored
    entries). The associated ``store`` is bound to
    ``token_counter.token_unit_id`` on first write; subsequent writes
    presenting a different unit raise ``ValueError``. If
    ``token_counter`` is ``None`` the path is byte-identical to T8-S1 and
    the binding id is ``"heuristic:v1"``.
    """
    cas = store if store is not None else ContentAddressableStore()
    effective_unit_id = (
        token_counter.token_unit_id if token_counter is not None else HEURISTIC_TOKEN_UNIT_ID
    )

    # Eagerly probe the unit-id binding so a mismatch fails fast before
    # any per-entry accumulation work. The per-write path
    # (_put_with_status_counted / put_with_status) re-checks under lock,
    # so this is a usability speed-up only — the safety property is
    # enforced by the write paths.
    if store is not None:
        with cas._lock:  # noqa: SLF001 -- intentional internal coupling, same-module access
            cas._check_or_bind_token_unit(effective_unit_id)

    naive_tokens = 0
    saved_tokens = 0
    new_cas_tokens = 0
    digest_order: list[bytes] = []
    seen: set[bytes] = set()
    newly_stored: set[bytes] = set()

    for entry in entries:
        payload = entry.payload
        if llmlingua:
            from js.compression.llmlingua import compact_bytes

            payload = compact_bytes(payload, max_ratio=llmlingua_max_ratio)
        payload_tokens = estimate_tokens(payload, token_counter=token_counter)
        naive_tokens += payload_tokens
        if token_counter is None:
            record, created = cas.put_with_status(payload)
        else:
            record, created = cas._put_with_status_counted(  # noqa: SLF001 -- same-module internal API
                payload,
                tokens=payload_tokens,
                token_unit_id=effective_unit_id,
            )
        if record.digest not in seen:
            seen.add(record.digest)
            digest_order.append(record.digest)
            saved_tokens += record.tokens
            if created:
                newly_stored.add(record.digest)
                new_cas_tokens += record.tokens

    savings_ratio = (naive_tokens - saved_tokens) / naive_tokens if naive_tokens else 0.0
    within_budget = saved_tokens <= budget.max_tokens

    return ContextSavingsResult(
        naive_tokens=naive_tokens,
        saved_tokens=saved_tokens,
        new_cas_tokens=new_cas_tokens,
        total_entries=len(entries),
        unique_entries=len(seen),
        newly_stored_entries=len(newly_stored),
        savings_ratio=savings_ratio,
        within_budget=within_budget,
        digest_order=tuple(digest_order),
    )
