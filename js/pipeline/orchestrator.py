"""Auto-Fetch Memory Pipeline orchestrator.

Runs connectors on a schedule, chunks their output, writes to SQLite memory
and an Obsidian-compatible directory.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from js.config import PipelineConfig
from js.pipeline.chunker import Chunk, MarkdownChunker
from js.pipeline.connector import Connector, ConnectorConfig, ConnectorResult
from js.pipeline.connectors import (
    CalendarConnector,
    DriveConnector,
    FileConnector,
    GitHubConnector,
    GmailConnector,
    NotionConnector,
    SlackConnector,
)
from js.pipeline.sync import ObsidianSync
from js.utils.log import get_logger

logger = get_logger("js.pipeline")

_CONNECTOR_MAP: dict[str, type[Connector]] = {
    "gmail": GmailConnector,
    "notion": NotionConnector,
    "github": GitHubConnector,
    "slack": SlackConnector,
    "drive": DriveConnector,
    "calendar": CalendarConnector,
    "file": FileConnector,
}


class AutoFetchOrchestrator:
    """Fetch, chunk, and sync external data into agent memory + Obsidian."""

    def __init__(
        self,
        config: PipelineConfig,
        memory_store: Any,
        state_dir: Path,
    ) -> None:
        self.config = config
        self.memory = memory_store
        self.state_dir = Path(state_dir)
        self.chunker = MarkdownChunker(token_limit=config.token_limit)
        self._connectors: list[Connector] = []
        self._obsidian: ObsidianSync | None = None
        self._task: asyncio.Task[Any] | None = None
        self._stop_event = asyncio.Event()
        self._build_connectors()
        self._init_obsidian()

    def register_connector(self, name: str, cls: type[Connector]) -> None:
        """Dynamically register a connector class (OpenHuman-style extensibility)."""
        _CONNECTOR_MAP[name] = cls
        logger.info(f"Registered connector type: {name}")

    def _build_connectors(self) -> None:
        for name, cls in _CONNECTOR_MAP.items():
            src_cfg = self.config.sources.get(name)
            if src_cfg is None:
                continue
            if not src_cfg.get("enabled", False):
                continue
            # R4-B: fail closed on legacy plaintext credentials
            legacy_api_key = src_cfg.get("api_key", "")
            legacy_token = src_cfg.get("token", "")
            legacy_credentials_path = src_cfg.get("credentials_path", "")
            if legacy_api_key or legacy_token or legacy_credentials_path:
                raise ValueError(
                    "legacy connector credentials require explicit migration to vault_ref"
                )
            cfg = ConnectorConfig(
                enabled=True,
                poll_interval_minutes=src_cfg.get("poll_interval_minutes", self.config.poll_interval_minutes),
                max_items_per_fetch=src_cfg.get("max_items_per_fetch", 50),
                mock_mode=src_cfg.get("mock_mode", False),
                api_key="",
                base_url=src_cfg.get("base_url", ""),
                token="",
                credentials_path="",
                vault_ref=src_cfg.get("vault_ref", ""),
                extra=src_cfg.get("extra", {}),
            )
            self._connectors.append(cls(cfg))
            logger.debug(f"Registered connector: {name}")

    def _init_obsidian(self) -> None:
        vault = self.config.vault_dir
        if vault:
            self._obsidian = ObsidianSync(Path(vault))
        else:
            self._obsidian = ObsidianSync(self.state_dir / "obsidian")

    def start(self) -> None:
        if not self.config.enabled or self._task is not None:
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(self._loop(), name="auto-fetch-pipeline")
        logger.info("Auto-Fetch Pipeline started", extra={"connectors": [c.name for c in self._connectors]})

    def stop(self) -> None:
        if self._task is None:
            return
        self._stop_event.set()
        self._task.cancel()
        self._task = None
        logger.info("Auto-Fetch Pipeline stopped")

    async def close(self) -> None:
        self.stop()
        for c in self._connectors:
            try:
                await c.close()
            except Exception:
                logger.warning(f"Error closing connector {c.name}", exc_info=True)

    async def _loop(self) -> None:
        """Main scheduler loop."""
        # Run immediately on startup
        await self._tick()
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.config.poll_interval_minutes * 60)
            except TimeoutError:
                await self._tick()

    async def _tick(self) -> None:
        """Execute one fetch cycle for all connectors."""
        for connector in self._connectors:
            try:
                if not await connector.health_check():
                    logger.warning(f"Connector {connector.name} unhealthy, skipping")
                    continue
                result = await connector.fetch()
                if result.items:
                    logger.info(
                        f"Fetched {len(result.items)} items from {connector.name}",
                        extra={"source": connector.name},
                    )
                    await self._ingest(result)
            except Exception:
                logger.error(f"Connector {connector.name} failed", exc_info=True)

    async def _ingest(self, result: ConnectorResult) -> None:
        """Chunk, canonicalise, score, and store a connector result.

        OpenHuman-style pipeline:
        Canonicalise → Chunk (≤3k) → Store → Score → Summarise.
        """
        # 1. Canonicalise: provenance-tagged Markdown
        canonical_items: list[str] = []
        for item in result.items:
            canonical_items.append(self._canonicalize(item, result.source))

        # 2. Chunk
        all_chunks: list[Chunk] = []
        for idx, raw in enumerate(result.items):
            chunks = self.chunker.chunk(
                source=result.source,
                title=raw.get("title", "Untitled"),
                content=canonical_items[idx],
                url=raw.get("url", ""),
                metadata={
                    "raw_id": raw.get("id", ""),
                    "fetched_at": result.fetched_at.isoformat(),
                    **raw.get("metadata", {}),
                },
            )
            all_chunks.extend(chunks)

        # 3. Score chunks by hotness/recency
        scored_chunks = [(c, self._score_chunk(c, result.fetched_at)) for c in all_chunks]
        scored_chunks.sort(key=lambda x: x[1], reverse=True)

        # 4. Summarise top chunks per source
        summary = await self._summarize_source(result.source, [c for c, _ in scored_chunks[:10]])

        # 5. Write to Obsidian
        if self._obsidian:
            try:
                self._obsidian.sync([c for c, _ in scored_chunks])
                if summary:
                    logger.info(f"Source summary: {summary}")
            except Exception:
                logger.warning("Obsidian sync failed", exc_info=True)

        # 6. Write to semantic memory (fire-and-forget to thread)
        for chunk, score in scored_chunks:
            try:
                await asyncio.to_thread(
                    self.memory.store_semantic,
                    key=chunk.id,
                    value=f"# {chunk.title}\n\n{chunk.body}",
                    category="external",
                    confidence=min(0.95, 0.7 + score * 0.25),
                    source=chunk.source,
                )
            except Exception:
                logger.warning(f"Memory store failed for {chunk.id}", exc_info=True)

    def _canonicalize(self, item: dict[str, Any], source: str) -> str:
        """Normalise connector output into provenance-tagged Markdown."""
        lines = [
            f"## {item.get('title', 'Untitled')}",
            "",
            item.get("content", "").strip(),
            "",
            f"_Source: {source} | ID: {item.get('id', 'n/a')}_",
        ]
        return "\n".join(lines)

    def _score_chunk(self, chunk: Chunk, fetched_at: datetime) -> float:
        """Hotness scoring: recency + content density.

        Returns 0.0-1.0. Higher = more likely to be relevant.
        """
        age_hours = (datetime.now(UTC) - fetched_at).total_seconds() / 3600
        recency = max(0.0, 1.0 - age_hours / 24.0)  # Decay over 24h
        density = min(1.0, len(chunk.body) / 1000.0)  # Reward denser content
        return recency * 0.6 + density * 0.4

    async def _summarize_source(self, source: str, chunks: list[Chunk]) -> str | None:
        """Generate a per-source summary from top-scored chunks."""
        if not chunks:
            return None
        # Simple rule-based summary; can be upgraded to LLM summary
        titles = [c.title for c in chunks if c.title]
        if not titles:
            return None
        return f"**{source}** — {len(chunks)} items: " + ", ".join(titles[:5])

    async def refresh(self, _query: str = "") -> dict[str, Any]:
        """On-demand refresh, optionally biased by *query*."""
        # TODO: In the future, fetchers can bias their filters using *query*.
        await self._tick()
        return {
            "refreshed_at": datetime.now(UTC).isoformat(),
            "connectors": [c.name for c in self._connectors],
        }

    def get_context_string(self, _query: str = "", max_chars: int = 2000) -> str:
        """Build a context string from Obsidian vault for injection into prompts.

        Reads the most recently synced files and returns a Markdown summary.
        """
        if not self._obsidian:
            return ""
        vault = self._obsidian.vault_dir
        if not vault.exists():
            return ""

        files: list[Path] = []
        for src_dir in (vault / "AutoFetch").iterdir():
            if src_dir.is_dir():
                files.extend(sorted(src_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)[:3])
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)

        parts: list[str] = []
        budget = max_chars
        for f in files[:10]:
            try:
                text = f.read_text(encoding="utf-8")
                # Strip frontmatter
                text = self._strip_frontmatter(text)
                # Truncate to budget
                if len(text) > budget:
                    text = text[:budget].rsplit("\n", 1)[0] + "\n…"
                if text.strip():
                    parts.append(text)
                    budget -= len(text)
                if budget <= 0:
                    break
            except Exception:
                continue
        return "\n\n---\n\n".join(parts) if parts else ""

    @staticmethod
    def _strip_frontmatter(text: str) -> str:
        if text.startswith("---"):
            end = text.find("---", 3)
            if end != -1:
                return text[end + 3 :].lstrip()
        return text
