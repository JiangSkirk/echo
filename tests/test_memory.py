"""Tests for memory subsystem."""

from pathlib import Path

import pytest

from js.config import MemoryConfig
from js.memory.store import MemoryStore


class TestMemoryStore:
    @pytest.fixture
    def store(self, tmp_path: Path) -> MemoryStore:
        config = MemoryConfig()
        return MemoryStore(tmp_path, config)

    def test_store_and_retrieve(self, store: MemoryStore) -> None:
        store.store("key1", "value1")
        result = store.retrieve("key1")
        assert result == "value1"

    def test_retrieve_missing(self, store: MemoryStore) -> None:
        result = store.retrieve("nonexistent")
        assert result is None

    def test_search(self, store: MemoryStore) -> None:
        store.store("alpha", "first value", category="test")
        store.store("beta", "second value", category="test")
        store.store("gamma", "other", category="other")

        results = store.search("value", category="test")
        assert len(results) == 2

    def test_update(self, store: MemoryStore) -> None:
        store.store("key", "original")
        store.store("key", "updated")
        result = store.retrieve("key")
        assert result == "updated"
