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

    def test_search_prefix_match_via_fts(self, store: MemoryStore) -> None:
        store.store("alpha", "deployment pipeline")
        # FTS5 prefix match: "deploy" should find "deployment".
        results = store.search("deploy")
        assert any(r.key == "alpha" for r in results)

    def test_search_substring_falls_back_to_like(self, store: MemoryStore) -> None:
        store.store("alpha", "kubernetes")
        # "bern" is mid-word — the tokenizer can't prefix-match it, so the LIKE
        # fallback must still find it (no recall regression).
        results = store.search("bern")
        assert any(r.key == "alpha" for r in results)

    def test_search_after_update_reflects_new_value(self, store: MemoryStore) -> None:
        store.store("k", "alpha original")
        store.store("k", "beta replacement")
        assert not store.search("alpha")  # stale FTS row must be gone
        assert any(r.key == "k" for r in store.search("replacement"))

    def test_search_special_characters_do_not_crash(self, store: MemoryStore) -> None:
        store.store("alpha", 'a:b (c) AND d-e "quoted"')
        # FTS operator characters in the query must not raise.
        for q in ("a:b", "AND", '"quoted"', "d-e", "(c)"):
            assert isinstance(store.search(q), list)

    def test_profile_files_are_owner_scoped_and_never_fall_back_to_shared(
        self, store: MemoryStore
    ) -> None:
        store.write_memory_file("user", "shared local profile")
        store.write_memory_file("user", "alice private profile", owner_key_hash="owner-alice")

        assert store.read_memory_file("user") == "shared local profile"
        assert (
            store.read_memory_file("user", owner_key_hash="owner-alice") == "alice private profile"
        )
        assert store.read_memory_file("user", owner_key_hash="owner-bob") == ""

        alice_context = store.get_context_string(owner_key_hash="owner-alice", max_chars=4000)
        bob_context = store.get_context_string(owner_key_hash="owner-bob", max_chars=4000)
        assert "alice private profile" in alice_context
        assert "shared local profile" not in alice_context
        assert "alice private profile" not in bob_context
        assert "shared local profile" not in bob_context

    def test_memory_files_reject_names_outside_allowlist(self, store: MemoryStore) -> None:
        store.write_memory_file("user", "ok")
        extra = store._memory_file_path("user").parent / "notes.md"
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_text("leaked", encoding="utf-8")

        listed = store.list_memory_files()
        assert "user" in listed
        assert "notes" not in listed
        with pytest.raises(ValueError, match="Invalid memory file name"):
            store.read_memory_file("notes")
        with pytest.raises(ValueError, match="Invalid memory file name"):
            store.write_memory_file("../etc/passwd", "nope")
        with pytest.raises(ValueError, match="Invalid memory file name"):
            store.write_memory_file("notes", "nope")
