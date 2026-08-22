"""Local file/directory connector — watches markdown/text files."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from js.pipeline.connector import Connector, ConnectorConfig, ConnectorResult


class FileConnector(Connector):
    """Ingest local markdown / text files from a directory."""

    # Paths that must never be used as a watch_dir — reading system files via
    # the pipeline connector would exfiltrate sensitive content into LLM prompts.
    # Each entry is resolved too: on macOS /etc is a symlink to /private/etc
    # (likewise /tmp, /var), so comparing only unresolved strings would let
    # symlinked aliases bypass the blocklist.
    _FORBIDDEN_WATCH_ROOTS: frozenset[str] = frozenset(
        str(Path(root).resolve())
        for root in (
            "/", "/etc", "/usr", "/bin", "/sbin", "/var", "/root",
            "/sys", "/proc", "/dev", "/boot", "/lib", "/lib64",
            "/Users", "/home", "/opt", "/Applications",
            "/Library", "/System", "/Network",
            "/tmp", "/mnt",
        )
    )

    def __init__(self, config: ConnectorConfig) -> None:
        super().__init__(config)
        raw = Path(config.extra.get("watch_dir", ".")).resolve()
        # Reject dangerous system paths
        if str(raw) in self._FORBIDDEN_WATCH_ROOTS or any(
            str(raw).startswith(p + "/") for p in self._FORBIDDEN_WATCH_ROOTS
        ):
            from js.utils.log import get_logger
            _log = get_logger("js.pipeline.file")
            _log.warning("watch_dir %s is a forbidden system path — using '.' instead", raw)
            raw = Path(".")
        self.watch_dir = raw
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
                    # Skip symlinks to prevent traversal outside watch_dir
                    if path.is_symlink():
                        continue
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
