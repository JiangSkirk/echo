"""Token counter adapter for Echo T8-S3A.

Production modules MUST NOT import tiktoken / sentencepiece / transformers
at top level. Real tokenizers are injected through the TokenCounter
Protocol at the call site.

A TokenCounter is the pair (callable, token_unit_id). The token_unit_id
binds the counter to a CAS store so that mixing heuristic and tiktoken
tokens in the same store raises ValueError -- see ContentAddressableStore
in js.echo.context_savings.

Default fallback (heuristic_counter) preserves the T8-S1 estimate_tokens
contract verbatim.

tiktoken_counter_factory() defers ``import tiktoken`` to first call, so
loading js.echo.context_tokenizer itself does NOT pull tiktoken.

Constraints
-----------
* Production module top-level imports are restricted to ``dataclasses``
  and ``typing`` from the standard library. No ``tiktoken`` /
  ``sentencepiece`` / ``transformers`` / ``os`` / ``pathlib`` / ``socket``
  / ``subprocess`` / ``requests`` / ``httpx`` here.
* Not re-exported through ``js.echo.__init__.__all__`` (implementation
  module, same convention as ``context_savings`` /
  ``context_savings_harness``).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

__all__ = [
    "HEURISTIC_TOKEN_UNIT_ID",
    "BoundTokenCounter",
    "TokenCounter",
    "conservative_counter_factory",
    "heuristic_counter",
    "model_token_counter",
    "tiktoken_counter_factory",
]


HEURISTIC_TOKEN_UNIT_ID = "heuristic:v1"
_TOKEN_COUNT_CACHE_MAX_ENTRIES = 512
_TOKENIZER_RESOURCES = {
    "cl100k_base": (
        "9b5ad71b2ce5302211f9c61530b329a4922fc6a4",
        "223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7",
    ),
    "o200k_base": (
        "fb374d419588a4632f3f557e76b4b70aebbca790",
        "446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d",
    ),
}


@runtime_checkable
class TokenCounter(Protocol):
    """Structural protocol for token counters.

    Any object that exposes a ``token_unit_id: str`` attribute (read-only
    is sufficient) and is callable as ``(payload: bytes) -> int``
    satisfies this protocol. All public injection points
    (``estimate_tokens``, ``summarize_context``,
    ``_compute_unsent_prompt_tokens``, ``run_harness``) type-annotate the
    parameter as ``TokenCounter | None`` so mypy can verify
    ``.token_unit_id`` access without ``getattr`` / ``type: ignore``.

    Use :class:`BoundTokenCounter` for the standard concrete
    implementation; tests may use a plain object literal that matches
    the protocol.
    """

    @property
    def token_unit_id(self) -> str: ...

    def __call__(self, payload: bytes) -> int: ...


@dataclass(frozen=True)
class BoundTokenCounter:
    """Concrete TokenCounter binding a callable to an immutable unit id.

    Used by :data:`heuristic_counter` and :func:`tiktoken_counter_factory`.
    Test fakes that need a TokenCounter without a separate callable
    indirection may construct ``BoundTokenCounter(count=lambda p: 1,
    token_unit_id="tiktoken:o200k_base")``.
    """

    count: Callable[[bytes], int]
    token_unit_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.token_unit_id, str) or not self.token_unit_id.strip():
            raise ValueError("token_unit_id must be a non-empty str")

    def __call__(self, payload: bytes) -> int:
        return self.count(payload)


def _heuristic_count(payload: bytes) -> int:
    if not payload:
        return 0
    return max(1, (len(payload) + 3) // 4)


heuristic_counter: TokenCounter = BoundTokenCounter(
    count=_heuristic_count,
    token_unit_id=HEURISTIC_TOKEN_UNIT_ID,
)


def _bounded_digest_memo(counter: TokenCounter) -> TokenCounter:
    """Cache bounded token counts without retaining prompt payload bytes.

    Canonical prompt/message bytes repeat within a turn and across adjacent
    turns.  Keeping only their SHA-256, byte length, and integer count avoids
    re-running a verified encoder while ensuring the cache cannot retain the
    prompt text itself.  The small lock protects LRU metadata; encoding misses
    run outside it so unrelated concurrent requests are not serialized.
    """
    import hashlib  # noqa: PLC0415 -- keep tokenizer imports hermetic
    import threading  # noqa: PLC0415 -- lazy, keeps module import hermetic
    from collections import OrderedDict  # noqa: PLC0415

    cache: OrderedDict[tuple[bytes, int], int] = OrderedDict()
    cache_lock = threading.Lock()

    def _count(payload: bytes) -> int:
        payload_bytes = bytes(payload)
        key = (hashlib.sha256(payload_bytes).digest(), len(payload_bytes))
        with cache_lock:
            if key in cache:
                cached = cache[key]
                cache.move_to_end(key)
                return cached

        counted = counter(payload_bytes)
        with cache_lock:
            cache[key] = counted
            cache.move_to_end(key)
            while len(cache) > _TOKEN_COUNT_CACHE_MAX_ENTRIES:
                cache.popitem(last=False)
        return counted

    return BoundTokenCounter(count=_count, token_unit_id=counter.token_unit_id)


def _declared_tokenizer_resource(encoding_name: str) -> tuple[str, str]:
    """Return the verified cache root and digest for one declared encoding.

    The release ships the required ``*.tiktoken`` BPE blobs under
    ``resources/tokenizer/`` using tiktoken's cache-key convention. An
    explicitly configured ``TIKTOKEN_CACHE_DIR`` is authoritative, so an empty
    or corrupted declared cache fails closed rather than reaching the network
    or silently switching resources.
    """
    import hashlib  # noqa: PLC0415 -- keep tokenizer imports hermetic
    import os  # noqa: PLC0415 -- lazy, keeps module import hermetic
    from pathlib import Path  # noqa: PLC0415

    declared = _TOKENIZER_RESOURCES.get(encoding_name)
    if declared is None:
        raise RuntimeError(f"no declared tokenizer resource for encoding {encoding_name!r}")
    cache_key, expected_digest = declared
    configured = os.environ.get("TIKTOKEN_CACHE_DIR")
    cache_root = (
        Path(configured)
        if configured
        else Path(__file__).resolve().parents[2] / "resources" / "tokenizer"
    )
    resource = cache_root / cache_key
    if not resource.is_file():
        raise RuntimeError(
            "declared tokenizer resource unavailable: "
            f"encoding={encoding_name!r}, cache_key={cache_key!r}"
        )
    actual_digest = hashlib.sha256(resource.read_bytes()).hexdigest()
    if actual_digest != expected_digest:
        raise RuntimeError(
            "declared tokenizer resource digest mismatch: "
            f"encoding={encoding_name!r}, expected={expected_digest}, actual={actual_digest}"
        )
    if not configured:
        os.environ["TIKTOKEN_CACHE_DIR"] = str(cache_root)
    return str(cache_root), expected_digest


def tiktoken_counter_factory(encoding_name: str = "o200k_base") -> TokenCounter:
    """Build a real-tokenizer counter. tiktoken imported lazily.

    Raises RuntimeError if tiktoken is not installed.  The BPE resource is
    loaded from the version-pinned vendored cache when available; if the
    resource is missing AND cannot be fetched, tiktoken raises -- we never
    silently substitute an imprecise counter.  Caller decides whether to
    fall back, fail, or skip -- see test_context_savings_threshold.

    token_unit_id is ``tiktoken:<encoding_name>``.
    """
    _declared_tokenizer_resource(encoding_name)
    try:
        import tiktoken  # noqa: PLC0415 -- deliberate lazy import to keep production hermetic
    except ImportError as e:
        raise RuntimeError(
            "tiktoken not installed. Install with: pip install -e '.[echo-tokenizer]'"
        ) from e
    enc = tiktoken.get_encoding(encoding_name)

    def _count(payload: bytes) -> int:
        if not payload:
            return 0
        text = payload.decode("utf-8", errors="replace")
        return len(enc.encode(text))

    return _bounded_digest_memo(
        BoundTokenCounter(
            count=_count,
            token_unit_id=f"tiktoken:{encoding_name}",
        )
    )


def conservative_counter_factory() -> TokenCounter:
    """Return a named conservative counter bound to the vendored reference.

    The maximum of both release-vendored BPE counters cannot undercount the
    cl100k release benchmark reference, including CJK and structured tool JSON,
    without multiplying normal prompt sizes by raw UTF-8 byte length.
    """
    _, cl100k_digest = _declared_tokenizer_resource("cl100k_base")
    _, o200k_digest = _declared_tokenizer_resource("o200k_base")
    cl100k_counter = tiktoken_counter_factory("cl100k_base")
    o200k_counter = tiktoken_counter_factory("o200k_base")

    def _count(payload: bytes) -> int:
        return max(cl100k_counter(payload), o200k_counter(payload))

    return _bounded_digest_memo(
        BoundTokenCounter(
            count=_count,
            token_unit_id=(
                "conservative:max-vendored-bpe-v1:"
                f"cl100k_base@sha256:{cl100k_digest}:"
                f"o200k_base@sha256:{o200k_digest}"
            ),
        )
    )


def _encoding_for_provider_model(provider_name: str, model: str) -> str | None:
    provider = provider_name.casefold()
    model_id = model.casefold()
    if provider not in {"openai", "azure-openai", "azure_openai"}:
        return None
    if model_id.startswith(("gpt-4o", "gpt-4.1", "gpt-5", "o1", "o3", "o4")):
        return "o200k_base"
    if model_id.startswith(("gpt-4", "gpt-3.5-turbo")):
        return "cl100k_base"
    return None


def model_token_counter(*, provider_name: str | None, model: str | None) -> TokenCounter:
    """Select one offline counter and bind its unit to provider and model.

    Exact vendored encodings are used only for known provider/model contracts.
    Auto-routing and unknown providers use the explicit conservative unit so a
    later provider fallback cannot make the original budget an undercount.
    """
    provider_id = (provider_name or "auto").strip() or "auto"
    model_id = (model or "auto").strip() or "auto"
    encoding_name = _encoding_for_provider_model(provider_id, model_id)
    base_counter = (
        tiktoken_counter_factory(encoding_name)
        if encoding_name is not None
        else conservative_counter_factory()
    )
    return BoundTokenCounter(
        count=base_counter,
        token_unit_id=(f"provider-model:{provider_id}/{model_id}:{base_counter.token_unit_id}"),
    )
