"""Local file/directory connector — watches markdown/text files."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from js.pipeline.connector import Connector, ConnectorConfig, ConnectorResult


class FileConnector(Connector):
    """Ingest local markdown / text files from a directory."""

    def __init__(self, config: ConnectorConfig) -> None:
        super().__init__(config)
        self.watch_dir = Path(config.extra.get("watch_dir", "."))
        self.patterns = config.extra.get("patterns", ["*.md", "*.txt", "*.rst"])

    @property
    def name(self) -> str:
        return "file"

    async def fetch(self) -> ConnectorResult:
        if self.config.mock_mode:
            return ConnectorResult(
                source=self.name,
                fetched_at=datetime.now(UTC),
                items=[
                    {
                        "id": "mock_doc_1",
                        "title": "Mock Document",
                        "content": "# Mock Document\n\nThis is mock content for testing the pipeline.",
                        "url": "",
                        "created_at": datetime.now(UTC).isoformat(),
                        "updated_at": datetime.now(UTC).isoformat(),
                        "metadata": {"mock": True},
                    }
                ],
            )

        items: list[dict[str, Any]] = []
        if self.watch_dir.exists():
            for pattern in self.patterns:
                for path in self.watch_dir.rglob(pattern):
                    stat = path.stat()
                    items.append({
                        "id": str(path.resolve()),
                        "title": path.stem,
                        "content": path.read_text(encoding="utf-8"),
                        "url": f"file://{path.resolve()}",
                        "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                        "updated_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "metadata": {"size": stat.st_size},
                    })
        return ConnectorResult(source=self.name, fetched_at=datetime.now(UTC), items=items)
