"""ClawHub registry client for skill marketplace discovery and installation.

Supports fetching, caching, and searching remote skill indexes in
OpenClaw-compatible clawhub.json format.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx

from js.utils.log import get_logger

logger = get_logger("js.skills.clawhub")

DEFAULT_CLAWHUB_URL = "https://raw.githubusercontent.com/openclaw/skills/main/clawhub.json"


class ClawHubClient:
    """Client for discovering and installing skills from a ClawHub registry."""

    def __init__(self, state_dir: Path, index_url: str = DEFAULT_CLAWHUB_URL) -> None:
        self.state_dir = state_dir
        self.index_url = index_url
        self.cache_path = state_dir / "clawhub_cache.json"
        self._index: list[dict[str, Any]] = []
        self._last_fetch: float = 0.0
        self._cache_ttl = 3600  # 1 hour

    async def fetch_index(self, force: bool = False) -> list[dict[str, Any]]:
        """Download and parse the clawhub.json index."""
        if not force and self._is_cache_valid():
            return self._load_cached_index()

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(self.index_url)
                response.raise_for_status()
                data = response.json()
        except Exception as e:
            logger.warning(f"Failed to fetch ClawHub index: {e}")
            # Fall back to cached index if available
            cached = self._load_cached_index()
            if cached:
                return cached
            return []

        skills = data.get("skills", [])
        if not isinstance(skills, list):
            logger.warning("Invalid clawhub.json format: 'skills' is not a list")
            return []

        self._index = skills
        self._last_fetch = time.time()
        self._save_cached_index()
        logger.info(f"Fetched ClawHub index: {len(skills)} skills")
        return skills

    def search_index(self, query: str) -> list[dict[str, Any]]:
        """Search the local index by keyword."""
        query_lower = query.lower()
        results: list[dict[str, Any]] = []
        for skill in self._index:
            text = " ".join(
                str(skill.get(k, ""))
                for k in ("id", "name", "description", "tags", "author")
            ).lower()
            if query_lower in text:
                results.append(skill)
        return results

    def get_skill_source(self, skill_id: str) -> str | None:
        """Get the install source (git URL) for a skill from the index."""
        for skill in self._index:
            if skill.get("id") == skill_id:
                return skill.get("source")
        return None

    def _is_cache_valid(self) -> bool:
        if not self.cache_path.exists():
            return False
        age = time.time() - self.cache_path.stat().st_mtime
        return age < self._cache_ttl

    def _load_cached_index(self) -> list[dict[str, Any]]:
        if not self.cache_path.exists():
            return []
        try:
            with open(self.cache_path, encoding="utf-8") as f:
                data = json.load(f)
            self._index = data.get("skills", [])
            self._last_fetch = data.get("fetched_at", 0.0)
            return self._index
        except Exception:
            return []

    def _save_cached_index(self) -> None:
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(
                    {"skills": self._index, "fetched_at": self._last_fetch},
                    f,
                    indent=2,
                )
        except Exception as e:
            logger.debug(f"Failed to cache ClawHub index: {e}")
