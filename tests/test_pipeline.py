"""Tests for Auto-Fetch Memory Pipeline."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.pipeline.chunker import Chunk, MarkdownChunker
from js.pipeline.connector import ConnectorConfig
from js.pipeline.connectors import (
    CalendarConnector,
    DriveConnector,
    FileConnector,
    GitHubConnector,
    GmailConnector,
    NotionConnector,
    SlackConnector,
)
from js.pipeline.orchestrator import AutoFetchOrchestrator, PipelineConfig
from js.pipeline.sync import ObsidianSync


class TestChunker:
    def test_estimate_tokens_english(self) -> None:
        text = "The quick brown fox jumps over the lazy dog."
        tok = MarkdownChunker.estimate_tokens(text)
        # ~9 words * 1.3 + ~35 other chars * 0.5 ≈ 11.7 + 17.5 ≈ 29
        assert 15 < tok < 50

    def test_estimate_tokens_cjk(self) -> None:
        text = "这是一个中文字符串测试。"
        tok = MarkdownChunker.estimate_tokens(text)
        # 14 CJK chars ~14 tokens
        assert 10 < tok < 20

    def test_chunk_simple(self) -> None:
        chunker = MarkdownChunker(token_limit=50)
        chunks = chunker.chunk("test", "Hello", "Line 1\n\nLine 2\n\nLine 3")
        assert len(chunks) >= 1
        assert all(isinstance(c, Chunk) for c in chunks)
        assert chunks[0].source == "test"

    def test_chunk_respects_limit(self) -> None:
        chunker = MarkdownChunker(token_limit=30)
        # Use newlines so _split_into_pieces produces multiple pieces to merge
        big = "\n\n".join([f"Paragraph {i} with some words here" for i in range(20)])
        chunks = chunker.chunk("test", "Big", big)
        assert len(chunks) >= 2
        for c in chunks:
            assert c.token_estimate <= MarkdownChunker.TOKEN_LIMIT

    def test_chunk_truncate_oversized_single_piece(self) -> None:
        chunker = MarkdownChunker(token_limit=20)
        # Need >3000 tokens to trigger truncation; "a"*15000 ≈ 3750 tokens
        huge = "a" * 15000
        chunks = chunker.chunk("test", "Huge", huge)
        assert len(chunks) == 1
        assert "… *(truncated)*" in chunks[0].body


class TestObsidianSync:
    def test_sync_creates_files(self, tmp_path: Path) -> None:
        sync = ObsidianSync(tmp_path)
        chunks = [
            Chunk(id="src:1:0", source="gmail", title="Email", body="Hello", token_estimate=5),
        ]
        paths = sync.sync(chunks)
        assert len(paths) == 1
        assert paths[0].exists()
        content = paths[0].read_text(encoding="utf-8")
        assert "Email" in content
        assert "Hello" in content
        assert "---" in content

    def test_sync_manifest(self, tmp_path: Path) -> None:
        sync = ObsidianSync(tmp_path)
        sync.sync([Chunk(id="a", source="notion", title="N", body="b", token_estimate=1)])
        manifest = tmp_path / ".meta" / "manifest.json"
        assert manifest.exists()
        import json
        data = json.loads(manifest.read_text())
        assert "notion" in data["sources"]

    def test_delete_source(self, tmp_path: Path) -> None:
        sync = ObsidianSync(tmp_path)
        sync.sync([Chunk(id="a", source="github", title="G", body="b", token_estimate=1)])
        count = sync.delete_source("github")
        assert count == 1
        assert not (tmp_path / "AutoFetch" / "github").exists()


class TestConnectors:
    @pytest.mark.asyncio
    async def test_gmail_mock_fetch(self) -> None:
        c = GmailConnector(ConnectorConfig(mock_mode=True))
        result = await c.fetch()
        assert result.source == "gmail"
        assert len(result.items) == 2
        assert "Project Update" in result.items[0]["title"]

    @pytest.mark.asyncio
    async def test_notion_mock_fetch(self) -> None:
        c = NotionConnector(ConnectorConfig(mock_mode=True))
        result = await c.fetch()
        assert result.source == "notion"
        assert len(result.items) == 1

    @pytest.mark.asyncio
    async def test_github_mock_fetch(self) -> None:
        c = GitHubConnector(ConnectorConfig(mock_mode=True))
        result = await c.fetch()
        assert result.source == "github"
        assert len(result.items) == 2

    @pytest.mark.asyncio
    async def test_slack_mock_fetch(self) -> None:
        c = SlackConnector(ConnectorConfig(mock_mode=True))
        result = await c.fetch()
        assert result.source == "slack"
        assert "alice" in result.items[0]["content"]

    @pytest.mark.asyncio
    async def test_drive_mock_fetch(self) -> None:
        c = DriveConnector(ConnectorConfig(mock_mode=True))
        result = await c.fetch()
        assert result.source == "drive"
        assert "Q3 OKRs" in result.items[0]["title"]

    @pytest.mark.asyncio
    async def test_calendar_mock_fetch(self) -> None:
        c = CalendarConnector(ConnectorConfig(mock_mode=True))
        result = await c.fetch()
        assert result.source == "calendar"
        assert len(result.items) == 2

    @pytest.mark.asyncio
    async def test_file_connector_reads_dir(self, tmp_path: Path) -> None:
        watch = tmp_path / "watch"
        watch.mkdir()
        (watch / "note.md").write_text("# Note\n\nContent")
        # tmp_path lives under /var (macOS) or /tmp (Linux) — both forbidden
        # watch roots now that blocklist entries are compared resolved.  Bypass
        # the constructor guard here to exercise fetch() itself.
        c = FileConnector(ConnectorConfig(extra={"patterns": ["*.md"]}))
        c.watch_dir = watch
        result = await c.fetch()
        assert result.source == "file"
        assert len(result.items) == 1
        assert result.items[0]["title"] == "note"

    def test_file_connector_rejects_symlinked_forbidden_alias(self) -> None:
        # /etc is a symlink to /private/etc on macOS; the unresolved alias must
        # still be rejected because blocklist entries are compared resolved.
        resolved = str(Path("/etc").resolve())
        assert resolved in FileConnector._FORBIDDEN_WATCH_ROOTS
        c = FileConnector(ConnectorConfig(extra={"watch_dir": "/etc"}))
        assert c.watch_dir == Path(".")

    @pytest.mark.asyncio
    async def test_health_checks(self) -> None:
        assert await GmailConnector(ConnectorConfig(mock_mode=True)).health_check()
        assert await NotionConnector(ConnectorConfig(mock_mode=True)).health_check()
        assert await GitHubConnector(ConnectorConfig(mock_mode=True)).health_check()
        assert await SlackConnector(ConnectorConfig(mock_mode=True)).health_check()
        assert await DriveConnector(ConnectorConfig(mock_mode=True)).health_check()
        assert await CalendarConnector(ConnectorConfig(mock_mode=True)).health_check()


class FakeMemoryStore:
    """Stand-in for MemoryStore that records semantic store calls."""

    def __init__(self) -> None:
        self.semantic: list[dict] = []

    def store_semantic(self, key: str, value: str, category: str = "fact", confidence: float = 0.5, source: str = "") -> dict:
        self.semantic.append({
            "key": key,
            "value": value,
            "category": category,
            "confidence": confidence,
            "source": source,
        })
        return {"conflicts": [], "evicted": 0}


class TestOrchestrator:
    @pytest.mark.asyncio
    async def test_ingest_from_mock_connector(self, tmp_path: Path) -> None:
        cfg = PipelineConfig(
            enabled=True,
            poll_interval_minutes=60,
            sources={
                "gmail": {"enabled": True, "mock_mode": True},
            },
        )
        mem = FakeMemoryStore()
        orch = AutoFetchOrchestrator(config=cfg, memory_store=mem, state_dir=tmp_path)
        await orch._tick()
        orch.stop()

        # Should have stored chunks to memory
        assert len(mem.semantic) > 0
        assert all(s["category"] == "external" for s in mem.semantic)
        assert all(s["source"] == "gmail" for s in mem.semantic)

        # Obsidian files should exist
        vault = orch._obsidian.vault_dir
        assert vault.exists()
        md_files = list((vault / "AutoFetch" / "gmail").glob("*.md"))
        assert len(md_files) > 0

    @pytest.mark.asyncio
    async def test_disabled_pipeline(self, tmp_path: Path) -> None:
        cfg = PipelineConfig(enabled=False)
        orch = AutoFetchOrchestrator(config=cfg, memory_store=FakeMemoryStore(), state_dir=tmp_path)
        assert orch._connectors == []
        orch.start()
        assert orch._task is None

    def test_get_context_string_reads_vault(self, tmp_path: Path) -> None:
        cfg = PipelineConfig(enabled=True, vault_dir=str(tmp_path / "vault"))
        orch = AutoFetchOrchestrator(config=cfg, memory_store=FakeMemoryStore(), state_dir=tmp_path)
        # Seed vault manually
        chunk = Chunk(id="x", source="s", title="T", body="Body text", token_estimate=2)
        orch._obsidian.sync([chunk])
        ctx = orch.get_context_string(max_chars=1000)
        assert "Body text" in ctx

    def test_get_context_string_empty_vault(self, tmp_path: Path) -> None:
        cfg = PipelineConfig(enabled=True, vault_dir=str(tmp_path / "vault"))
        orch = AutoFetchOrchestrator(config=cfg, memory_store=FakeMemoryStore(), state_dir=tmp_path)
        ctx = orch.get_context_string(max_chars=1000)
        assert ctx == ""
