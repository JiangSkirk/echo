"""Lightweight embedding providers for semantic memory search.

No external dependencies — uses deterministic hashing for keyword-based
vectors, with a pluggable interface for future transformer-based models.
"""

from __future__ import annotations

import hashlib
import math
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import cast

import httpx


@dataclass
class EmbedderHealth:
    """Health status of an embedder."""

    provider: str
    active: bool
    failure_count: int = 0
    last_failure: float | None = None
    last_success: float | None = None
    fallback_provider: str | None = None


class Embedder(ABC):
    """Abstract embedding provider."""

    @abstractmethod
    def embed(self, text: str) -> list[float]:
        """Return a dense vector for the given text."""

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Embed multiple texts. Default: sequential embed()."""
        return [self.embed(t) for t in texts]

    def to_json(self, vec: list[float]) -> str:
        import json

        return json.dumps(vec)

    def from_json(self, raw: str) -> list[float]:
        import json

        return cast("list[float]", json.loads(raw))

    def health(self) -> EmbedderHealth:
        """Return health status. Override in subclasses for richer reporting."""
        return EmbedderHealth(provider=self.__class__.__name__, active=True)


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    if len(a) != len(b):
        raise ValueError(f"Vector dimension mismatch: {len(a)} vs {len(b)}")
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    return dot  # Vectors are assumed normalized


class KeywordEmbedder(Embedder):
    """Deterministic keyword-frequency embedder using hash-based indexing.

    Each word is hashed to a fixed position in the vector, making
    embeddings reproducible without maintaining a vocabulary.
    """

    def __init__(self, dims: int = 256) -> None:
        self.dims = dims

    def embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dims
        for word in text.lower().split():
            h = int(hashlib.md5(word.encode(), usedforsecurity=False).hexdigest(), 16)
            idx = h % self.dims
            vec[idx] += 1.0

        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 0:
            vec = [v / norm for v in vec]
        return vec


class LLMEmbedder(Embedder):
    """Embedding provider using an OpenAI-compatible embeddings API.

    Uses a synchronous httpx client so it can be called from the
    synchronous MemoryStore methods.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str = "text-embedding-3-small",
        dims: int | None = None,
    ) -> None:
        self.client = httpx.Client(
            base_url=base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=httpx.Timeout(30.0),
        )
        self.model = model
        self.dims = dims
        self._failure_count = 0
        self._last_failure: float | None = None
        self._last_success: float | None = None

    def embed(self, text: str) -> list[float]:
        result = self.embed_batch([text])
        return result[0]

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        try:
            response = self.client.post(
                "/embeddings",
                json={"model": self.model, "input": texts},
            )
            response.raise_for_status()
            data = response.json()
            vectors = [item["embedding"] for item in data["data"]]
            if self.dims:
                vectors = [v[: self.dims] for v in vectors]
            self._failure_count = 0
            self._last_success = time.time()
            return vectors
        except Exception as e:
            self._failure_count += 1
            self._last_failure = time.time()
            raise RuntimeError(f"Embedding API failed: {e}") from e

    def health(self) -> EmbedderHealth:
        return EmbedderHealth(
            provider=f"LLMEmbedder({self.model})",
            active=True,
            failure_count=self._failure_count,
            last_failure=self._last_failure,
            last_success=self._last_success,
        )


class HybridEmbedder(Embedder):
    """Resilient embedder with circuit-breaker fallback.

    Uses the primary embedder (e.g. LLMEmbedder) under normal conditions.
    If the primary fails ``failure_threshold`` consecutive times, it
    switches to the fallback (e.g. KeywordEmbedder).  After
    ``recovery_timeout`` seconds it probes the primary again with a
    dummy call.  If the probe succeeds, it switches back.

    This guarantees that memory operations never crash because of a
    transient embedding API outage.
    """

    def __init__(
        self,
        primary: Embedder,
        fallback: Embedder | None = None,
        failure_threshold: int = 3,
        recovery_timeout: float = 60.0,
    ) -> None:
        self.primary = primary
        self.fallback = fallback or KeywordEmbedder()
        self.failure_threshold = max(1, failure_threshold)
        self.recovery_timeout = max(0.0, recovery_timeout)
        self._consecutive_failures = 0
        self._last_failure_time: float | None = None
        self._using_fallback = False

    def _try_primary(self, texts: list[str]) -> list[list[float]]:
        """Attempt primary embedder, updating circuit state."""
        try:
            result = self.primary.embed_batch(texts)
            self._consecutive_failures = 0
            self._last_failure_time = None
            self._using_fallback = False
            return result
        except Exception:
            self._consecutive_failures += 1
            self._last_failure_time = time.time()
            if self._consecutive_failures >= self.failure_threshold:
                self._using_fallback = True
            raise

    def _maybe_recover(self) -> bool:
        """If we are in fallback mode and the recovery timeout has passed,
        try a dummy embed to see if the primary is back."""
        if not self._using_fallback:
            return False
        if self._last_failure_time is None:
            return False
        elapsed = time.time() - self._last_failure_time
        if elapsed < self.recovery_timeout:
            return False
        try:
            self.primary.embed("ping")
            self._using_fallback = False
            self._consecutive_failures = 0
            self._last_failure_time = None
            return True
        except Exception:
            self._last_failure_time = time.time()
            return False

    def embed(self, text: str) -> list[float]:
        return self.embed_batch([text])[0]

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        if self._using_fallback:
            if self._maybe_recover():
                try:
                    return self._try_primary(texts)
                except Exception:
                    pass
            return self.fallback.embed_batch(texts)

        try:
            return self._try_primary(texts)
        except Exception:
            # First or intermittent failure: try fallback immediately so
            # the caller never sees an error.
            return self.fallback.embed_batch(texts)

    def health(self) -> EmbedderHealth:
        primary_health = self.primary.health()
        return EmbedderHealth(
            provider=primary_health.provider,
            active=not self._using_fallback,
            failure_count=self._consecutive_failures,
            last_failure=self._last_failure_time,
            last_success=primary_health.last_success,
            fallback_provider=self.fallback.health().provider if self._using_fallback else None,
        )
