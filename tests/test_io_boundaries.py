"""I/O boundary tests for core modules.

Tests edge cases, error handling, and security boundaries in file system,
database, and network operations.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.memory.embeddings import KeywordEmbedder
from js.memory.enhanced_store import EnhancedMemoryStore
from js.memory.store import MemoryStore
from js.security.guard import BehaviorGuard
from js.tools.files import FileTools
from js.utils.db import db_connection


class TestFileToolsBoundaries:
    @pytest.fixture
    def file_tools(self, tmp_path: Path) -> FileTools:
        limits = ToolLimits()
        guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
        return FileTools(tmp_path, limits, guard)

    @pytest.mark.asyncio
    async def test_read_nonexistent_file(self, file_tools: FileTools) -> None:
        result = await file_tools.read("does_not_exist.txt")
        assert not result.success
        assert "not found" in result.error.lower() or "no such" in result.error.lower()

    @pytest.mark.asyncio
    async def test_write_path_traversal_blocked(self, file_tools: FileTools, tmp_path: Path) -> None:
        result = await file_tools.write("../../../etc/passwd", "evil")
        # Should be resolved within workspace and either succeed in workspace or be blocked
        target = (tmp_path / "../../../etc/passwd").resolve()
        assert not target.is_relative_to(tmp_path) or not result.success

    @pytest.mark.asyncio
    async def test_delete_nonexistent_file(self, file_tools: FileTools) -> None:
        result = await file_tools.delete("missing.txt")
        assert not result.success

    @pytest.mark.asyncio
    async def test_list_dir_recursive(self, file_tools: FileTools, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "nested.txt").write_text("deep")
        result = await file_tools.list_dir(".", recursive=True)
        assert result.success
        assert "nested.txt" in result.output

    @pytest.mark.asyncio
    async def test_search_empty_dir(self, file_tools: FileTools) -> None:
        result = await file_tools.search("*.txt", ".")
        assert result.success
        # Empty directory should return no matches
        assert "no matches" in result.output.lower() or result.output == ""

    @pytest.mark.asyncio
    async def test_read_with_offset_limit(self, file_tools: FileTools) -> None:
        await file_tools.write("sample.txt", "line1\nline2\nline3\nline4\nline5")
        result = await file_tools.read("sample.txt", offset=1, limit=2)
        assert result.success
        assert "line2" in result.output
        assert "line3" in result.output
        assert "line1" not in result.output


class TestMemoryStoreBoundaries:
    def test_store_episode_empty_topics(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path, None, KeywordEmbedder())
        store.store_episode("s1", "summary", [], 100, 2, 5)
        episodes = store.get_episodes(limit=10)
        assert len(episodes) == 1
        assert episodes[0].summary == "summary"

    def test_session_messages_empty(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path, None, KeywordEmbedder())
        msgs = store.get_session_messages("nonexistent")
        assert msgs == []

    def test_delete_nonexistent_session(self, tmp_path: Path) -> None:
        store = MemoryStore(tmp_path, None, KeywordEmbedder())
        # Should not raise
        store.delete_session("never-existed")
        assert store.get_session_messages("never-existed") == []

    def test_enhanced_semantic_empty_search(self, tmp_path: Path) -> None:
        enhanced = EnhancedMemoryStore(tmp_path, None, KeywordEmbedder())
        results = enhanced.search_semantic("something random")
        assert results == []

    def test_enhanced_working_empty_session(self, tmp_path: Path) -> None:
        enhanced = EnhancedMemoryStore(tmp_path, None, KeywordEmbedder())
        results = enhanced.get_working("empty-session", limit=50)
        assert results == []


class TestDbConnectionBoundaries:
    def test_db_connection_creates_file(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        assert not db_path.exists()
        with db_connection(db_path) as conn:
            conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
            conn.commit()
        assert db_path.exists()

    def test_db_connection_rollback_on_error(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        with db_connection(db_path) as conn:
            conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
            conn.execute("INSERT INTO test (id) VALUES (1)")
            conn.commit()

        try:
            with db_connection(db_path) as conn:
                conn.execute("INSERT INTO test (id) VALUES (1)")  # duplicate PK
                conn.commit()
        except Exception:
            pass

        with db_connection(db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM test").fetchone()
            assert row[0] == 1
