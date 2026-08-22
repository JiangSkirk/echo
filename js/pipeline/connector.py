"""Abstract base for external data connectors."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class ConnectorConfig:
    """Per-connector configuration."""

    enabled: bool = True
    poll_interval_minutes: int = 30
    max_items_per_fetch: int = 50
    mock_mode: bool = False
    # Auth / connection params (subclass-specific)
    # R4-B: plaintext credential fields are parse-only legacy keys.
    # Non-empty values raise a migration error before connector construction.
    api_key: str = ""
    base_url: str = ""
    token: str = ""
    credentials_path: str = ""
    vault_ref: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ConnectorResult:
    """Raw output from a connector fetch cycle."""

    source: str
    fetched_at: datetime
    items: list[dict[str, Any]]
    # Each item expected shape:
    # {
    #   "id": str,
    #   "title": str,
    #   "content": str,          # raw text / markdown / html
    #   "url": str,
    #   "created_at": str,       # ISO-8601
    #   "updated_at": str,
    #   "metadata": dict,
    # }


class Connector(ABC):
    """Base class for all external data connectors."""

    def __init__(self, config: ConnectorConfig) -> None:
        self.config = config
        self._last_fetch: datetime | None = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable connector name."""

    @abstractmethod
    async def fetch(self) -> ConnectorResult:
        """Fetch new/updated items from the external source.

        Must be idempotent: the orchestrator deduplicates by item id.
        """

    async def health_check(self) -> bool:
        """Return True if the connector can reach its source."""
        return True

    async def close(self) -> None:  # noqa: B027
        """Release any network or file resources."""
        pass

    @staticmethod
    def _item_id(source: str, raw_id: str) -> str:
        """Generate a stable global item id."""
        return hashlib.sha256(f"{source}:{raw_id}".encode()).hexdigest()[:16]

    @staticmethod
    def _normalize_datetime(ts: str | datetime | None) -> str:
        if ts is None:
            return datetime.now(UTC).isoformat()
        if isinstance(ts, datetime):
            return ts.isoformat()
        return ts
