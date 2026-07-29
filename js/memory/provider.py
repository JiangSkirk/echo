"""Pluggable memory provider ABC (Hermes-style).

Allows swapping the built-in three-layer memory for external backends
such as Honcho, Mem0, or a custom enterprise store.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.config import MemoryConfig
from js.utils.log import get_logger

logger = get_logger("js.memory.provider")


@dataclass
class MemoryQueryResult:
    """Result from a memory query."""

    key: str
    value: str
    category: str
    confidence: float  # 0.0-1.0
    source: str


class MemoryProvider(ABC):
    """Abstract base for memory backends."""

    @abstractmethod
    async def initialize(self, session_id: str) -> None:
        """Prepare the provider for a new session."""
        ...

    @abstractmethod
    async def prefetch(self, query: str) -> list[MemoryQueryResult]:
        """Recall relevant memories before the agent turn."""
        ...

    @abstractmethod
    async def sync_turn(
        self,
        session_id: str,
        user_message: str,
        assistant_message: str,
        tool_results: list[dict[str, Any]] | None = None,
    ) -> None:
        """Persist a completed turn."""
        ...

    @abstractmethod
    async def shutdown(self) -> None:
        """Release resources."""
        ...

    @abstractmethod
    def health(self) -> dict[str, Any]:
        """Return provider health metrics."""
        ...


class BuiltinMemoryProvider(MemoryProvider):
    """Adapter wrapping the existing MemoryStore as a MemoryProvider."""

    def __init__(self, state_dir: Path, config: MemoryConfig, embedder: Any | None = None) -> None:
        from js.memory.store import MemoryStore

        self._store = MemoryStore(state_dir, config, embedder)
        self._state_dir = state_dir

    async def initialize(self, session_id: str) -> None:
        # Builtin store is always ready; nothing to init per-session
        pass

    async def prefetch(self, query: str) -> list[MemoryQueryResult]:
        """Search episodic + semantic memory for relevant context."""
        from js.echo.turn_context import current_owner_key_hash

        owner = current_owner_key_hash()
        results: list[MemoryQueryResult] = []
        try:
            # Semantic search
            semantic = self._store.enhanced.search_semantic(query, limit=5, owner_key_hash=owner)
            for s in semantic:
                results.append(
                    MemoryQueryResult(
                        key=s.key,
                        value=s.value,
                        category=s.category,
                        confidence=s.confidence,
                        source="semantic",
                    )
                )
        except Exception:
            logger.debug("Semantic prefetch failed", exc_info=True)
        try:
            # Episodic search
            episodes = self._store.enhanced.get_episodes(limit=3, owner_key_hash=owner)
            for ep in episodes:
                results.append(
                    MemoryQueryResult(
                        key=f"ep_{ep.id}",
                        value=ep.summary,
                        category="episode",
                        confidence=0.7,
                        source="episodic",
                    )
                )
        except Exception:
            logger.debug("Episodic prefetch failed", exc_info=True)
        return results

    async def sync_turn(
        self,
        session_id: str,
        user_message: str,
        assistant_message: str,
        tool_results: list[dict[str, Any]] | None = None,
    ) -> None:
        # Delegate to the existing store methods
        import asyncio

        from js.echo.turn_context import current_owner_key_hash

        owner = current_owner_key_hash()
        await asyncio.to_thread(
            self._store.store_messages,
            session_id,
            [
                {"role": "user", "content": user_message},
                {"role": "assistant", "content": assistant_message},
            ],
            owner_key_hash=owner,
        )

    async def shutdown(self) -> None:
        self._store.close()

    def health(self) -> dict[str, Any]:
        return {
            "provider": "builtin",
            "type": "sqlite",
            "path": str(self._state_dir / "memory.db"),
            "ok": True,
        }
