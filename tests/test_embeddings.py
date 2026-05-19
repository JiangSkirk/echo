"""Tests for embedding providers and resilient fallback behaviour."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from js.memory.embeddings import (
    EmbedderHealth,
    HybridEmbedder,
    KeywordEmbedder,
    LLMEmbedder,
    cosine_similarity,
)


class TestKeywordEmbedder:
    def test_embed_produces_normalized_vector(self) -> None:
        emb = KeywordEmbedder(dims=256)
        vec = emb.embed("hello world")
        assert len(vec) == 256
        norm = sum(v * v for v in vec)
        assert norm == pytest.approx(1.0, rel=1e-6)

    def test_embed_is_deterministic(self) -> None:
        emb = KeywordEmbedder(dims=256)
        v1 = emb.embed("test phrase")
        v2 = emb.embed("test phrase")
        assert v1 == v2

    def test_embed_batch(self) -> None:
        emb = KeywordEmbedder(dims=256)
        batch = emb.embed_batch(["a", "b", "c"])
        assert len(batch) == 3
        assert all(len(v) == 256 for v in batch)

    def test_to_json_roundtrip(self) -> None:
        emb = KeywordEmbedder(dims=256)
        vec = emb.embed("roundtrip")
        raw = emb.to_json(vec)
        restored = emb.from_json(raw)
        assert restored == vec


class TestLLMEmbedder:
    def test_health_reports_zero_failures_initially(self) -> None:
        # We don't call the real API; just verify the object state.
        emb = LLMEmbedder(base_url="http://localhost:1234/v1", api_key="dummy")
        h = emb.health()
        assert h.provider == "LLMEmbedder(text-embedding-3-small)"
        assert h.active is True
        assert h.failure_count == 0
        assert h.last_failure is None


class TestHybridEmbedder:
    def test_uses_primary_when_healthy(self) -> None:
        primary = KeywordEmbedder(dims=256)
        fallback = KeywordEmbedder(dims=128)
        hybrid = HybridEmbedder(primary, fallback, failure_threshold=3)

        vec = hybrid.embed("hello")
        assert len(vec) == 256  # primary dimensions
        assert hybrid.health().active is True
        assert hybrid.health().fallback_provider is None

    def test_fallback_on_primary_failure(self) -> None:
        primary = MagicMock(spec=KeywordEmbedder)
        primary.embed_batch.side_effect = RuntimeError("API down")
        primary.health.return_value = EmbedderHealth(
            provider="MockPrimary", active=True
        )
        fallback = KeywordEmbedder(dims=128)
        hybrid = HybridEmbedder(primary, fallback, failure_threshold=2)

        # First failure -> still tries primary internally, returns fallback
        vec1 = hybrid.embed("hello")
        assert len(vec1) == 128
        assert hybrid._consecutive_failures == 1
        assert not hybrid._using_fallback

        # Second failure -> crosses threshold, switches to fallback
        vec2 = hybrid.embed("world")
        assert len(vec2) == 128
        assert hybrid._using_fallback is True
        assert hybrid.health().active is False
        assert hybrid.health().fallback_provider == "KeywordEmbedder"

    def test_fallback_mode_skips_primary(self) -> None:
        primary = MagicMock(spec=KeywordEmbedder)
        primary.embed_batch.side_effect = RuntimeError("API down")
        primary.health.return_value = EmbedderHealth(
            provider="MockPrimary", active=True
        )
        fallback = KeywordEmbedder(dims=128)
        hybrid = HybridEmbedder(primary, fallback, failure_threshold=1)

        # Trigger fallback
        hybrid.embed("x")
        assert hybrid._using_fallback is True

        # Reset mock call count
        primary.embed_batch.reset_mock()

        # Next call should use fallback directly (no primary call)
        hybrid.embed("y")
        primary.embed_batch.assert_not_called()

    def test_auto_recovery_when_primary_returns(self) -> None:
        primary = MagicMock(spec=KeywordEmbedder)
        primary.health.return_value = EmbedderHealth(
            provider="MockPrimary", active=True
        )
        fallback = KeywordEmbedder(dims=128)
        hybrid = HybridEmbedder(
            primary, fallback, failure_threshold=1, recovery_timeout=0.1
        )

        # Trigger fallback
        primary.embed_batch.side_effect = RuntimeError("API down")
        hybrid.embed("x")
        assert hybrid._using_fallback is True

        # Wait for recovery timeout
        time.sleep(0.15)
        primary.embed_batch.side_effect = None
        primary.embed_batch.return_value = [[1.0, 0.0]]

        # Next call should probe primary, succeed, and switch back
        vec = hybrid.embed("y")
        assert vec == [1.0, 0.0]
        assert hybrid._using_fallback is False
        assert hybrid.health().active is True

    def test_health_reflects_state(self) -> None:
        primary = MagicMock(spec=KeywordEmbedder)
        primary.health.return_value = EmbedderHealth(
            provider="P", active=True, last_success=1234.0
        )
        fallback = KeywordEmbedder(dims=128)
        hybrid = HybridEmbedder(primary, fallback, failure_threshold=1)

        h = hybrid.health()
        assert h.provider == "P"
        assert h.active is True
        assert h.last_success == 1234.0

        primary.embed_batch.side_effect = RuntimeError("fail")
        hybrid.embed("x")
        h2 = hybrid.health()
        assert h2.active is False
        assert h2.fallback_provider == "KeywordEmbedder"
        assert h2.failure_count == 1
        assert h2.last_failure is not None

    def test_embed_batch_returns_correct_shapes(self) -> None:
        primary = KeywordEmbedder(dims=64)
        hybrid = HybridEmbedder(primary)
        batch = hybrid.embed_batch(["a", "b"])
        assert len(batch) == 2
        assert all(len(v) == 64 for v in batch)


class TestCosineSimilarity:
    def test_identical_vectors(self) -> None:
        a = [1.0, 0.0, 0.0]
        b = [1.0, 0.0, 0.0]
        assert cosine_similarity(a, b) == pytest.approx(1.0)

    def test_orthogonal_vectors(self) -> None:
        a = [1.0, 0.0]
        b = [0.0, 1.0]
        assert cosine_similarity(a, b) == pytest.approx(0.0)

    def test_dimension_mismatch_raises(self) -> None:
        with pytest.raises(ValueError):
            cosine_similarity([1.0, 0.0], [1.0, 0.0, 0.0])
