"""Lightweight embedding providers for semantic memory search.

No external dependencies — uses deterministic hashing for keyword-based
vectors, with a pluggable interface for future transformer-based models.
"""

from __future__ import annotations

import hashlib
import math
from abc import ABC, abstractmethod
from typing import cast

import httpx


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
            return vectors
        except Exception as e:
            raise RuntimeError(f"Embedding API failed: {e}") from e
