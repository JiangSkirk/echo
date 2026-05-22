"""Protocol definitions for agent interfaces.

These protocols allow external modules (web, daemon, fleet, CLI)
to depend on interfaces rather than the concrete JSAgent class.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class IEmbedder(Protocol):
    """Protocol for text embedding providers."""

    async def embed(self, text: str) -> list[float]:
        ...

    def health(self) -> Any:
        ...


@runtime_checkable
class IMemoryStore(Protocol):
    """Protocol for agent memory storage."""

    async def store_working(self, session_id: str, key: str, value: str, category: str = "general", importance: int = 5) -> None:
        ...

    async def get_working(self, session_id: str, key: str) -> str | None:
        ...

    async def store_episode(self, session_id: str, query: str, response: str) -> None:
        ...

    async def get_episodes(self, session_id: str, limit: int = 10) -> list[dict[str, Any]]:
        ...

    async def store_semantic(self, query: str, response: str, category: str = "general") -> None:
        ...

    async def search_semantic(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        ...

    def get_sessions(self, limit: int = 30) -> list[dict[str, Any]]:
        ...

    def get_session_messages(self, session_id: str) -> list[dict[str, Any]]:
        ...

    def delete_session(self, session_id: str) -> None:
        ...

    def cleanup_empty_sessions(self) -> int:
        ...

    async def get_context_string(self, query: str = "", max_chars: int = 8000) -> str:
        ...


@runtime_checkable
class IToolRegistry(Protocol):
    """Protocol for tool registry."""

    def get_stats(self) -> dict[str, Any]:
        ...

    def get_handler(self, name: str) -> Any | None:
        ...

    def list_tools(self) -> list[Any]:
        ...


@runtime_checkable
class ISkillManager(Protocol):
    """Protocol for skill manager."""

    def get_all(self) -> dict[str, Any]:
        ...

    def list_skills(self, **kwargs: Any) -> list[dict[str, Any]]:
        ...

    def view_skill(self, skill_id: str) -> dict[str, Any] | None:
        ...

    def install(self, source: str, **kwargs: Any) -> Any:
        ...

    def uninstall(self, skill_id: str) -> bool:
        ...


@runtime_checkable
class IAgent(Protocol):
    """Main agent protocol — the facade exposed to web, daemon, fleet, CLI.

    External modules should depend on this protocol, not the concrete JSAgent.
    """

    @property
    def settings(self) -> Any:
        ...

    @property
    def memory(self) -> IMemoryStore:
        ...

    @property
    def registry(self) -> IToolRegistry:
        ...

    @property
    def skills(self) -> ISkillManager:
        ...

    @property
    def degraded(self) -> bool:
        ...

    @property
    def degraded_reason(self) -> str:
        ...

    async def run(self, query: str, session_id: str = "", stream: bool = False, **kwargs: Any) -> AsyncIterator[str]:
        """Execute a conversation turn (or full turn loop). Yields response chunks."""
        ...

    def request_cancel(self, session_id: str) -> bool:
        """Request cancellation of an active run."""
        ...

    def start_background_tasks(self) -> None:
        ...

    def stop_background_tasks(self) -> None:
        ...

    async def close(self) -> None:
        ...
