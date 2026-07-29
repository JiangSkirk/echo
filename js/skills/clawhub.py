"""ClawHub registry client for skill marketplace discovery and installation.

Supports fetching, caching, and searching remote skill indexes in
OpenClaw-compatible clawhub.json format.

Also provides a GitHub Search API fallback when the primary ClawHub index
is unavailable (e.g. the default openclaw/skills repo was deleted).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import yaml

from js.security.net_guard import PinnedTransport, resolve_and_validate
from js.tools.registry import current_tool_execution_context
from js.utils.log import get_logger

logger = get_logger("js.skills.clawhub")

DEFAULT_CLAWHUB_URL = "https://raw.githubusercontent.com/openclaw/skills/main/clawhub.json"
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
_ALLOWED_HTTP_HOSTS = frozenset({"api.github.com", "raw.githubusercontent.com"})
_MAX_INDEX_BYTES = 2 * 1024 * 1024
_MAX_INDEX_SKILLS = 1_000

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
        self.state_dir = state_dir.expanduser().resolve()
        self.index_url = self._validated_registry_url(index_url)
        self.cache_path = self.state_dir / "clawhub_cache.json"
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

        network_error = self._network_context_error()
        if network_error is not None:
            logger.warning("ClawHub network disabled: %s", network_error)
            cached = self._load_cached_index()
            if cached:
                return cached
            self._index = list(_BUILTIN_INDEX)
            return list(self._index)

        # Try primary source first. Every request is resolved, validated and
        # pinned immediately before I/O; redirects and proxy environment are
        # disabled so an index cannot pivot to a different destination.
        try:
            response = await self._secure_get(self.index_url)
            response.raise_for_status()
            data = self._bounded_json(response)

            skills = data.get("skills", [])
            if isinstance(skills, list) and skills:
                validated = self._validated_index(skills)
                if validated:
                    self._index = validated
                    self._last_fetch = time.time()
                    self._save_cached_index()
                    logger.info(f"Fetched ClawHub index: {len(self._index)} skills")
                    return list(self._index)
                logger.warning("Primary index did not contain any approved skill sources")
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
        resp = await self._secure_get(
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
        data = self._bounded_json(resp)

        raw_items = data.get("items", [])
        items = raw_items[:30] if isinstance(raw_items, list) else []
        # Limit metadata fetching to top 10 to avoid raw-content rate limits.
        metadata_candidates = items[:10]
        meta_map: dict[str, dict[str, str]] = {}
        for repo in metadata_candidates:
            if not isinstance(repo, dict):
                continue
            repo_name = repo.get("full_name", "")
            if isinstance(repo_name, str) and self._valid_repo_name(repo_name):
                meta = await self._fetch_skill_metadata(repo_name)
                if meta:
                    meta_map[repo_name] = meta

        for repo in items:
            if not isinstance(repo, dict):
                continue
            repo_name = repo.get("full_name", "")
            if not isinstance(repo_name, str) or not self._valid_repo_name(repo_name):
                continue

            skill_meta = meta_map.get(repo_name, {})
            owner = repo.get("owner", {})
            author = owner.get("login", "") if isinstance(owner, dict) else ""
            skill = {
                "id": repo_name.replace("/", ":"),
                "name": skill_meta.get("name", str(repo.get("name", ""))),
                "description": skill_meta.get("description", str(repo.get("description", ""))),
                "author": str(author),
                "source": f"https://github.com/{repo_name}.git",
                "tags": ["openclaw"],
                "stars": int(repo.get("stargazers_count", 0) or 0),
            }
            skills.append(skill)

        return skills

    async def _fetch_skill_metadata(
        self, repo_name: str
    ) -> dict[str, str]:
        """Try to read SKILL.md from a repo to get name/description."""
        paths = ["SKILL.md", "skills/SKILL.md", "skill/SKILL.md"]
        for branch in ["main", "master"]:
            for path in paths:
                url = f"https://raw.githubusercontent.com/{repo_name}/{branch}/{path}"
                try:
                    r = await self._secure_get(url, timeout=10.0)
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

    @staticmethod
    def _validated_registry_url(index_url: str) -> str:
        try:
            parsed = urlsplit(index_url)
            port = parsed.port
        except (TypeError, ValueError) as exc:
            raise ValueError("ClawHub index URL is invalid") from exc
        if (
            parsed.scheme != "https"
            or parsed.hostname != "raw.githubusercontent.com"
            or parsed.username is not None
            or parsed.password is not None
            or port not in (None, 443)
            or not parsed.path.startswith("/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "ClawHub index must use the pinned https://raw.githubusercontent.com origin"
            )
        return index_url

    @staticmethod
    def _valid_repo_name(repo_name: str) -> bool:
        return bool(
            re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}",
                repo_name,
            )
        )

    @classmethod
    def _validate_outbound_url(cls, url: str) -> None:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except (TypeError, ValueError) as exc:
            raise ValueError("ClawHub request URL is invalid") from exc
        if (
            parsed.scheme != "https"
            or parsed.hostname not in _ALLOWED_HTTP_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or port not in (None, 443)
            or not parsed.path.startswith("/")
            or parsed.fragment
        ):
            raise ValueError("ClawHub request destination is not allowlisted")

    async def _secure_get(self, url: str, **kwargs: Any) -> httpx.Response:
        network_error = self._network_context_error()
        if network_error is not None:
            raise PermissionError(network_error)
        self._validate_outbound_url(url)
        validated_ips = await asyncio.to_thread(
            resolve_and_validate,
            url,
            allow_loopback=False,
            allow_private=False,
        )
        timeout = kwargs.pop("timeout", 30.0)
        async with httpx.AsyncClient(
            transport=PinnedTransport(validated_ips[0], verify=True),
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.get(url, **kwargs)
        if response.is_redirect:
            raise ValueError("ClawHub redirects are disabled")
        return response

    @staticmethod
    def _network_context_error() -> str | None:
        context = current_tool_execution_context()
        if context is None:
            return "ClawHub network requires a consumed Echo tool context"
        if context.tool_name not in {
            "control_clawhub_discover",
            "control_clawhub_install",
        }:
            return "ClawHub network requires the dedicated Echo control tool"
        if context.network_policy != "allow":
            return "ClawHub network requires an Echo network grant"
        required = {"api.github.com", "raw.githubusercontent.com"}
        if not required.issubset(context.network_hosts):
            return "ClawHub Echo context is missing exact registry hosts"
        return None

    @staticmethod
    def _bounded_json(response: httpx.Response) -> dict[str, Any]:
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > _MAX_INDEX_BYTES:
                    raise ValueError("ClawHub response exceeds the size limit")
            except ValueError as exc:
                if "exceeds" in str(exc):
                    raise
                raise ValueError("ClawHub response has an invalid content length") from exc
        payload = response.content
        if len(payload) > _MAX_INDEX_BYTES:
            raise ValueError("ClawHub response exceeds the size limit")
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError("ClawHub response must be a JSON object")
        return data

    @classmethod
    def _validated_index(cls, skills: list[Any]) -> list[dict[str, Any]]:
        validated: list[dict[str, Any]] = []
        for raw in skills[:_MAX_INDEX_SKILLS]:
            if not isinstance(raw, dict):
                continue
            skill_id = raw.get("id")
            source = raw.get("source")
            if not isinstance(skill_id, str) or not skill_id or len(skill_id) > 200:
                continue
            if not isinstance(source, str):
                continue
            try:
                parsed = urlsplit(source)
                port = parsed.port
            except ValueError:
                continue
            repo_name = parsed.path.strip("/")
            if repo_name.endswith(".git"):
                repo_name = repo_name[:-4]
            if (
                parsed.scheme != "https"
                or parsed.hostname != "github.com"
                or parsed.username is not None
                or parsed.password is not None
                or port not in (None, 443)
                or parsed.query
                or parsed.fragment
                or not cls._valid_repo_name(repo_name)
            ):
                continue
            try:
                stars = max(0, int(raw.get("stars", 0) or 0))
            except (TypeError, ValueError):
                stars = 0
            normalized = {
                "id": skill_id,
                "name": str(raw.get("name", skill_id))[:300],
                "description": str(raw.get("description", ""))[:2_000],
                "author": str(raw.get("author", ""))[:200],
                "source": f"https://github.com/{repo_name}.git",
                "tags": [str(tag)[:100] for tag in raw.get("tags", [])[:30]]
                if isinstance(raw.get("tags"), list)
                else [],
                "stars": stars,
            }
            validated.append(normalized)
        return validated

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
                validated = self._validated_index([skill])
                return validated[0]["source"] if validated else None
        return None

    def _is_cache_valid(self) -> bool:
        try:
            data = self._read_cache_payload()
            fetched_at = float(data.get("fetched_at", 0.0))
            age = time.time() - fetched_at
            return age < self._cache_ttl
        except Exception:
            return False

    def _load_cached_index(self) -> list[dict[str, Any]]:
        try:
            data = self._read_cache_payload()
            raw_skills = data.get("skills", [])
            if not isinstance(raw_skills, list):
                return []
            self._index = self._validated_index(raw_skills)
            self._last_fetch = float(data.get("fetched_at", 0.0))
            return list(self._index)
        except Exception:
            return []

    def _save_cached_index(self) -> None:
        temp_path: Path | None = None
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            fd, raw_temp_path = tempfile.mkstemp(
                prefix=".clawhub-cache-",
                suffix=".tmp",
                dir=self.state_dir,
            )
            temp_path = Path(raw_temp_path)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(
                    {"skills": self._index, "fetched_at": self._last_fetch},
                    f,
                    indent=2,
                )
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, self.cache_path)
            temp_path = None
            directory_fd = os.open(self.state_dir, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception as e:
            logger.debug(f"Failed to cache ClawHub index: {e}")
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass

    def _read_cache_payload(self) -> dict[str, Any]:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.cache_path, flags)
        try:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(65_536, _MAX_INDEX_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > _MAX_INDEX_BYTES:
                    raise ValueError("ClawHub cache exceeds the size limit")
            data = json.loads(b"".join(chunks))
        finally:
            os.close(fd)
        if not isinstance(data, dict):
            raise ValueError("ClawHub cache must be a JSON object")
        return data
