"""ClawHub registry client for skill marketplace discovery and installation.

Supports fetching, caching, and searching remote skill indexes in
OpenClaw-compatible clawhub.json format.

Also provides a GitHub Search API fallback when the primary ClawHub index
is unavailable (e.g. the default openclaw/skills repo was deleted).
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

from js.utils.log import get_logger

logger = get_logger("js.skills.clawhub")

DEFAULT_CLAWHUB_URL = "https://raw.githubusercontent.com/openclaw/skills/main/clawhub.json"
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"

# Builtin fallback index — used when network is completely unavailable.
_BUILTIN_INDEX: list[dict[str, Any]] = [
    {
        "id": "openclaw:excel-barcode-processor",
        "name": "Excel Barcode Processor",
        "description": "Process Excel packing lists and generate barcode data.",
        "author": "openclaw",
        "source": "https://github.com/openclaw/excel-barcode-processor.git",
        "tags": ["openclaw", "excel", "barcode"],
        "stars": 12,
    },
    {
        "id": "openclaw:web-fetch",
        "name": "Web Fetch",
        "description": "Fetch and summarize web pages.",
        "author": "openclaw",
        "source": "https://github.com/openclaw/web-fetch.git",
        "tags": ["openclaw", "web"],
        "stars": 8,
    },
    {
        "id": "openclaw:shell-safety",
        "name": "Shell Safety",
        "description": "Safety checks for shell commands.",
        "author": "openclaw",
        "source": "https://github.com/openclaw/shell-safety.git",
        "tags": ["openclaw", "security"],
        "stars": 15,
    },
]


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
        """Download and parse the clawhub.json index.

        Resolution order:
        1. In-memory cache (if valid)
        2. Network fetch (primary URL)
        3. Disk cache
        4. GitHub Search API
        5. Builtin fallback index (guaranteed offline)
        """
        if not force and self._is_cache_valid():
            return self._load_cached_index()

        # Try primary source first
        try:
            if self.index_url.startswith("file://"):
                local_path = Path(self.index_url[7:])
                data = json.loads(local_path.read_text(encoding="utf-8"))
            else:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(self.index_url)
                    response.raise_for_status()
                    data = response.json()

            skills = data.get("skills", [])
            if isinstance(skills, list) and skills:
                self._index = skills
                self._last_fetch = time.time()
                self._save_cached_index()
                logger.info(f"Fetched ClawHub index: {len(skills)} skills")
                return skills
            else:
                logger.warning("Primary index returned empty or malformed skills list")
        except Exception as e:
            logger.warning(f"Primary ClawHub index failed: {e}")

        # Fallback 1: try cached index
        cached = self._load_cached_index()
        if cached:
            logger.info(f"Using cached ClawHub index: {len(cached)} skills")
            return cached

        # Fallback 2: GitHub Search API for openclaw-skill topic
        try:
            gh_skills = await self._fetch_from_github_search()
            if gh_skills:
                self._index = gh_skills
                self._last_fetch = time.time()
                self._save_cached_index()
                logger.info(f"Fetched {len(gh_skills)} skills from GitHub Search API")
                return gh_skills
        except Exception as e:
            logger.warning(f"GitHub Search fallback failed: {e}")

        # Fallback 3: builtin index — guaranteed to work offline
        logger.info(f"Using builtin ClawHub fallback index: {len(_BUILTIN_INDEX)} skills")
        self._index = list(_BUILTIN_INDEX)
        return self._index

    async def _fetch_from_github_search(self) -> list[dict[str, Any]]:
        """Search GitHub for repositories tagged with 'openclaw-skill'.

        Returns a list of skill dicts in clawhub.json format.
        Unauthenticated requests are rate-limited to ~10/min.
        To stay well under the limit we only fetch metadata for
        the top 10 repos by stars.
        """
        skills: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Search repositories by topic
            resp = await client.get(
                GITHUB_SEARCH_URL,
                params={
                    "q": "topic:openclaw-skill",
                    "sort": "stars",
                    "order": "desc",
                    "per_page": "30",
                },
                headers={"Accept": "application/vnd.github.v3+json"},
            )
            resp.raise_for_status()
            data = resp.json()

            items = data.get("items", [])
            # Limit metadata fetching to top 10 to avoid raw-content rate limits
            metadata_candidates = items[:10]
            meta_map: dict[str, dict[str, str]] = {}
            for repo in metadata_candidates:
                repo_name = repo.get("full_name", "")
                if repo_name:
                    meta = await self._fetch_skill_metadata(client, repo_name)
                    if meta:
                        meta_map[repo_name] = meta

            for repo in items:
                repo_name = repo.get("full_name", "")
                repo_url = repo.get("html_url", "")
                if not repo_name or not repo_url:
                    continue

                skill_meta = meta_map.get(repo_name, {})
                skill = {
                    "id": repo_name.replace("/", ":"),
                    "name": skill_meta.get("name", repo.get("name", "")),
                    "description": skill_meta.get("description", repo.get("description", "")),
                    "author": repo.get("owner", {}).get("login", ""),
                    "source": f"{repo_url}.git",
                    "tags": ["openclaw"],
                    "stars": repo.get("stargazers_count", 0),
                }
                skills.append(skill)

        return skills

    async def _fetch_skill_metadata(
        self, client: httpx.AsyncClient, repo_name: str
    ) -> dict[str, str]:
        """Try to read SKILL.md from a repo to get name/description."""
        paths = ["SKILL.md", "skills/SKILL.md", "skill/SKILL.md"]
        for branch in ["main", "master"]:
            for path in paths:
                url = f"https://raw.githubusercontent.com/{repo_name}/{branch}/{path}"
                try:
                    r = await client.get(url, timeout=10.0)
                    if r.status_code == 200:
                        text = r.text
                        if text.startswith("---"):
                            m = re.match(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
                            if m:
                                fm = yaml.safe_load(m.group(1)) or {}
                                return {
                                    "name": str(fm.get("name", "")),
                                    "description": str(fm.get("description", "")),
                                }
                except Exception:
                    continue
        return {}

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
        try:
            with open(self.cache_path, encoding="utf-8") as f:
                data = json.load(f)
            fetched_at = float(data.get("fetched_at", 0.0))
            age = time.time() - fetched_at
            return age < self._cache_ttl
        except Exception:
            return False

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
