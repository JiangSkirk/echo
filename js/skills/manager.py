"""Next-generation skill manager: code + prompt + workflow with security & discovery."""

from __future__ import annotations

import asyncio
import io
import json
import os
import re
import shutil
import tarfile
import threading
import time
from collections.abc import Awaitable, Callable
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from js.security.net_guard import PinnedTransport, resolve_and_validate
from js.security.sandbox import SandboxExecutor
from js.skills.executor import MAX_SUBSKILL_DEPTH, execute_skill
from js.skills.hermes_bridge import (
    discover_hermes_skills,
    enhanced_scan_hermes_skill,
    get_bridge_stats,
    load_hermes_skill,
)
from js.skills.promotion_store import PromotionStore
from js.skills.security import ScanResult, scan_skill, verify_integrity
from js.skills.spec import (
    SkillSpec,
    SkillType,
    TrustLevel,
    parse_skill_manifest,
)
from js.tools.registry import ToolParam, ToolResult, ToolSpec
from js.utils.db import db_connection
from js.utils.log import get_logger

logger = get_logger("js.skills")

_REMOTE_SKILL_NETWORK_HOSTS = frozenset({"api.github.com", "codeload.github.com", "github.com"})
_MAX_REMOTE_SKILL_ARCHIVE_BYTES = 25 * 1024 * 1024
_MAX_REMOTE_SKILL_EXPANDED_BYTES = 100 * 1024 * 1024
_MAX_REMOTE_SKILL_FILE_BYTES = 10 * 1024 * 1024
_MAX_REMOTE_SKILL_MEMBERS = 5_000

# Type alias for LLM caller
LLMCaller = Callable[[str, str | None], Awaitable[str]]


class SkillManager:
    """Unified skill lifecycle manager.

    Features:
    - Multi-type support: code, prompt, workflow, meta
    - Category-based organization (Hermes-style)
    - Platform filtering (Hermes-style)
    - Trust levels with security scanning (OpenClaw-inspired)
    - Progressive disclosure: list (metadata) → view (full content)
    - Prerequisites checking (Hermes-style)
    - Usage tracking and auto-evolution hooks
    - Sandbox execution for untrusted code
    """

    SKILL_MANIFEST = "SKILL.md"
    BUILTIN_DIR = Path(__file__).parent / "builtin"

    def __init__(
        self,
        state_dir: Path,
        workspace: Path,
        *,
        promotion_store: PromotionStore | None = None,
        owner_key_hash: str | None = None,
        audit_logger: Any | None = None,
        hermes_skills_enabled: bool = False,
    ) -> None:
        self.state_dir = state_dir
        self.workspace = workspace
        self.hermes_skills_enabled = bool(hermes_skills_enabled)
        self.skills_dir = state_dir / "skills"
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = state_dir / "skills.db"
        self._init_db()
        self._skills: dict[str, SkillSpec] = {}
        self._skills_lock = threading.RLock()
        self._install_lock = asyncio.Lock()
        self._hermes_load_lock = threading.RLock()
        self._closed = threading.Event()
        self._scan_cache: dict[str, ScanResult] = {}
        # Every manager is safe by construction, including CLI/test callers
        # that do not go through JSAgent's composition root.
        self._sandbox: SandboxExecutor | None = SandboxExecutor(
            workspace,
            strict_isolation=True,
        )
        self._composer: Any | None = None
        self._last_skill_by_session: dict[str, str] = {}
        self._tool_registry: Any | None = None
        self._tool_owner = object()
        self._tool_generation = 0
        self._registered_tool_names: frozenset[str] = frozenset()
        # v0.1.5-alpha: PromotionStore powers the auditable trust/variant pipeline.
        # When None, a per-state_dir store is created lazily so SkillManager
        # remains usable in unit tests and CLI contexts that don't wire one.
        self.promotion_store: PromotionStore = promotion_store or PromotionStore(
            state_dir / "skill_promotions.db"
        )
        self._owner_key_hash: str | None = owner_key_hash
        self._audit_logger: Any | None = audit_logger
        self._loaded = False
        self._load_builtin()

    def _init_db(self) -> None:
        with db_connection(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS skill_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    skill_id TEXT NOT NULL,
                    skill_type TEXT,
                    success INTEGER NOT NULL,
                    latency_ms REAL NOT NULL,
                    context TEXT,
                    used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_skill_usage_id ON skill_usage(skill_id)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS skill_scan_cache (
                    skill_id TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    risk_flags TEXT,
                    trust_level TEXT,
                    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS skill_composition_chains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_skill TEXT NOT NULL,
                    to_skill TEXT NOT NULL,
                    frequency INTEGER DEFAULT 1,
                    last_seen REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_chains_from ON skill_composition_chains(from_skill)
            """)
            conn.commit()

    # ------------------------------------------------------------------
    # Sandbox
    # ------------------------------------------------------------------

    def set_sandbox(self, sandbox: SandboxExecutor) -> None:
        """Set the sandbox executor for untrusted code skills."""
        self._sandbox = sandbox

    def set_evolver(self, evolver: Any | None) -> None:
        """Set the skill evolver for feedback loop."""
        self._evolver = evolver

    def set_composer(self, composer: Any | None) -> None:
        """Set the skill composer for chain discovery."""
        self._composer = composer

    def register_as_tools(self, registry: Any, *, load: bool = True) -> None:
        """Register all loaded skills as callable tools in the agent's registry."""
        if load:
            self.ensure_loaded()
        with self._skills_lock:
            self._ensure_open()
            if self._tool_registry is not None and self._tool_registry is not registry:
                self._replace_owned_tools(self._tool_registry, self._tool_generation + 1, [])
            self._tool_registry = registry
            self._publish_skill_tools_locked()

    def register_auto_skill(self, spec: SkillSpec) -> None:
        """Register an auto-generated skill and expose it as a tool."""
        self._ensure_open()
        with self._skills_lock:
            self._skills[spec.id] = spec
            self._publish_skill_tools_locked()
        logger.info(f"Registered auto-skill: {spec.id}")

    def ensure_loaded(self) -> None:
        """Scan builtin + installed skills on first use."""
        if self._loaded or self._closed.is_set():
            return
        with self._skills_lock:
            if self._loaded or self._closed.is_set():
                return
            self._load_all()
            self._loaded = True
            if self._tool_registry is not None:
                self._publish_skill_tools_locked()

    def _skills_snapshot(self) -> tuple[SkillSpec, ...]:
        """Return a stable view while background discovery mutates the registry."""
        self.ensure_loaded()
        with self._skills_lock:
            return tuple(self._skills.values())

    def _ensure_open(self) -> None:
        if self._closed.is_set():
            raise RuntimeError("skill manager is closed")

    def close(self) -> None:
        """Stop discovery and revoke only this manager's registered tools."""
        with self._skills_lock:
            if self._closed.is_set():
                return
            self._closed.set()
            registry = self._tool_registry
            self._tool_generation += 1
            if registry is not None:
                self._replace_owned_tools(registry, self._tool_generation, [])
            self._registered_tool_names = frozenset()
            self._tool_registry = None
            self._sandbox = None
            self._composer = None
            self._evolver = None

    @staticmethod
    def _skill_id_to_tool_name(skill_id: str) -> str:
        """Convert a skill ID to a valid OpenAI tool name.

        OpenAI requires tool names to match ``^[a-zA-Z0-9_-]+$``.
        Hermes skills use ``hermes:<name>`` IDs which contain colons.
        We replace any illegal character with an underscore.
        """
        raw = f"skill_{skill_id}"
        # Replace anything that is NOT a-z, A-Z, 0-9, _ or -
        return re.sub(r"[^a-zA-Z0-9_-]", "_", raw)

    def _should_expose_as_tool(self, spec: SkillSpec) -> bool:
        """Decide whether a skill is allowed into the model-callable tool registry.

        v0.1.4-alpha PR-1.5 hardening: QUARANTINE skills (including auto-created
        draft skills) must NOT appear as tools the model can invoke. Operators
        promote them via ``trust_skill`` once reviewed. Any other trust level
        is permitted — the per-execution scan / sandbox / approval still runs
        downstream in ``execute()``.

        This is the single decision point referenced by every call into
        ``_register_skill_as_tool``; do not duplicate the trust-level check
        at the call sites.
        """
        return spec.trust_level != TrustLevel.QUARANTINE

    def _tool_registration(
        self,
        spec: SkillSpec,
        registry: Any,
        generation: int,
    ) -> tuple[ToolSpec, Callable[..., Awaitable[ToolResult]]]:
        tool_name = self._skill_id_to_tool_name(spec.id)

        # Build parameters from metadata if available, otherwise generic args
        params_meta = spec.metadata.get("parameters", []) if spec.metadata else []
        if params_meta:
            parameters = [
                ToolParam(
                    name=p["name"],
                    type=p.get("type", "string"),
                    description=p.get("description", ""),
                    required=p.get("required", True),
                    enum=p.get("enum"),
                )
                for p in params_meta
            ]
        else:
            parameters = [
                ToolParam(
                    name="args",
                    type="object",
                    description=f"Arguments for skill {spec.name}",
                    required=False,
                )
            ]

        tool_spec = ToolSpec(
            name=tool_name,
            description=spec.description or f"Execute skill: {spec.name}",
            parameters=parameters,
            dangerous=spec.trust_level == TrustLevel.QUARANTINE,
            read_only=spec.type == SkillType.PROMPT,
        )

        async def _handler(**kwargs: Any) -> ToolResult:
            if not self._is_active_tool_registration(registry, tool_name, generation):
                return ToolResult(
                    success=False, error="Skill manager is closed or tool registration is inactive"
                )
            args = kwargs.get("args", {}) if "args" in kwargs else kwargs
            try:
                result = await self.execute(spec.id, args)
            except RuntimeError as exc:
                logger.warning(
                    "Skill tool execution failed for %s: %s",
                    spec.id,
                    type(exc).__name__,
                )
                return ToolResult(success=False, error="Skill execution failed safely")
            return ToolResult(
                success=result.get("success", False),
                output=result.get("output", ""),
                error=result.get("error", ""),
                metadata={
                    "skill_id": spec.id,
                    "skill_type": spec.type.value,
                    "orin_taint_extra": int(result.get("orin_taint", 0)),
                },
            )

        return tool_spec, _handler

    def _is_active_tool_registration(self, registry: Any, tool_name: str, generation: int) -> bool:
        with self._skills_lock:
            return (
                not self._closed.is_set()
                and registry is self._tool_registry
                and generation == self._tool_generation
                and tool_name in self._registered_tool_names
            )

    def _replace_owned_tools(
        self,
        registry: Any,
        generation: int,
        registrations: list[tuple[ToolSpec, Callable[..., Awaitable[ToolResult]]]],
    ) -> frozenset[str]:
        replace_owned = getattr(registry, "replace_owned", None)
        if callable(replace_owned):
            return frozenset(
                str(tool_name)
                for tool_name in replace_owned(self._tool_owner, generation, registrations)
            )

        # Compatibility for small external registry adapters. The production
        # ToolRegistry supplies replace_owned(), which is the atomic path.
        for tool_name in self._registered_tool_names:
            registry.unregister(tool_name)
        for tool_spec, handler in registrations:
            registry.register(tool_spec, handler)
        return frozenset(tool_spec.name for tool_spec, _ in registrations)

    def _publish_skill_tools_locked(self) -> None:
        registry = self._tool_registry
        if registry is None or self._closed.is_set():
            return
        self._tool_generation += 1
        generation = self._tool_generation
        registrations = [
            self._tool_registration(spec, registry, generation)
            for spec in self._skills.values()
            if self._should_expose_as_tool(spec)
        ]
        self._registered_tool_names = self._replace_owned_tools(registry, generation, registrations)
        logger.debug("Published %d skill tools (generation=%d)", len(registrations), generation)

    def _register_skill_as_tool(self, _spec: SkillSpec) -> None:
        """Republish the manager-owned generation after a skill mutation."""
        with self._skills_lock:
            self._publish_skill_tools_locked()

    def _unregister_skill_as_tool(self, skill_id: str) -> None:
        del skill_id
        with self._skills_lock:
            self._publish_skill_tools_locked()

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def _load_builtin(self) -> None:
        """Load shipped skills synchronously so the tool surface is ready."""
        if self.BUILTIN_DIR.exists():
            self._scan_directory(self.BUILTIN_DIR, trust_override=TrustLevel.BUILTIN)

    def _load_all(self) -> None:
        """Load builtin (if missing) + installed user skills. Hermes is separate."""
        if self.BUILTIN_DIR.exists() and not any(
            spec.trust_level == TrustLevel.BUILTIN for spec in self._skills.values()
        ):
            self._load_builtin()
        self._scan_directory(self.skills_dir)
        logger.info(f"Loaded {len(self._skills)} native skills")

    def load_hermes_sync(self) -> None:
        """Synchronously load Hermes skills (for CLI/non-async contexts)."""
        self._load_hermes_skills()

    async def load_hermes_async(self) -> None:
        """Asynchronously load Hermes skills in a background thread."""
        import asyncio

        if self._closed.is_set():
            return
        await asyncio.to_thread(self._load_hermes_skills)

    def _load_hermes_skills(self) -> None:
        self.ensure_loaded()
        self._publish_hermes_skills(replace_existing=False)

    def _publish_hermes_skills(self, *, replace_existing: bool) -> None:
        """Load skills from the Hermes skills directory when explicitly enabled.

        Discovery resolves the Hermes skills path at call time so isolated HOME
        overrides are honored. Default is opt-in/off for privacy-safe starts.
        """
        from js.skills.hermes_bridge import hermes_skills_dir

        with self._hermes_load_lock:
            if self._closed.is_set():
                return
            if not self.hermes_skills_enabled:
                logger.debug("Hermes skills bridge disabled (opt-in required)")
                return
            skills_root = hermes_skills_dir()
            if not skills_root.exists():
                logger.debug("Hermes skills directory not found, skipping Hermes bridge")
                return

            stats = get_bridge_stats()
            stats.failed_loads = 0
            stats.total_loaded = 0
            stats.prompt_count = 0
            stats.code_count = 0

            try:
                manifests = discover_hermes_skills(skills_root)
                discovered: list[SkillSpec] = []
                for manifest in manifests:
                    if self._closed.is_set():
                        break
                    try:
                        spec = load_hermes_skill(manifest)

                        # Security scan (with optional Hermes guard enhancement)
                        cached = self._load_cached_scan(spec.id, spec.content_hash)
                        if cached:
                            spec.risk_flags = cached.risk_flags
                            spec.trust_level = cached.trust_level
                        else:
                            result = enhanced_scan_hermes_skill(spec)
                            spec.risk_flags = result.risk_flags
                            spec.trust_level = result.trust_level
                            self._save_scan_cache(result)

                        if self._closed.is_set():
                            break
                        discovered.append(spec)
                    except Exception as e:
                        stats.failed_loads += 1
                        logger.warning(f"Failed to load Hermes skill from {manifest}: {e}")

                with self._skills_lock:
                    if self._closed.is_set():
                        return
                    next_skills = dict(self._skills)
                    if replace_existing:
                        next_skills = {
                            skill_id: spec
                            for skill_id, spec in next_skills.items()
                            if not skill_id.startswith("hermes:")
                        }
                    for spec in discovered:
                        if spec.id in next_skills:
                            logger.debug(
                                "Skipping Hermes skill %s: ID conflict with existing skill", spec.id
                            )
                            continue
                        next_skills[spec.id] = spec
                        stats.total_loaded += 1
                        if spec.type == SkillType.PROMPT:
                            stats.prompt_count += 1
                        elif spec.type == SkillType.CODE:
                            stats.code_count += 1

                    # The skill map and all manager-owned registry entries are
                    # published together after discovery has completed.
                    self._skills = next_skills
                    self._publish_skill_tools_locked()

                stats.last_refresh_time = time.time()
                stats.refresh_count += 1
                logger.info(
                    f"Hermes bridge loaded {stats.total_loaded} skills "
                    f"({stats.prompt_count} prompt, {stats.code_count} code, "
                    f"{stats.failed_loads} failed)"
                )
            except Exception as e:
                logger.warning(f"Hermes bridge initialization failed: {e}")

    def refresh_hermes_skills(self) -> dict[str, Any]:
        """Refresh Hermes skills from disk without restarting.

        Removes stale Hermes skills, reloads changed ones, and discovers new ones.
        """
        from js.skills.hermes_bridge import hermes_skills_dir

        self._ensure_open()
        if not self.hermes_skills_enabled:
            return {
                "success": False,
                "error": "Hermes skills bridge is disabled (set features.hermes_skills_enabled)",
            }
        skills_root = hermes_skills_dir()
        if not skills_root.exists():
            return {"success": False, "error": "Hermes skills directory not found"}

        self._publish_hermes_skills(replace_existing=True)

        stats = get_bridge_stats()
        return {
            "success": True,
            "reloaded": stats.total_loaded,
            "failed": stats.failed_loads,
            "total_hermes": sum(1 for s in self._skills_snapshot() if s.id.startswith("hermes:")),
        }

    def _scan_directory(self, root: Path, trust_override: TrustLevel | None = None) -> None:
        """Recursively scan a directory for skills.

        Supports both flat structure (JS original) and categorized structure (Hermes):
            skills/                  skills/research/arxiv/SKILL.md
            ├── my-skill/            skills/devops/docker/SKILL.md
            │   └── SKILL.md
            └── another/
                └── SKILL.md
        """
        for path in root.rglob(self.SKILL_MANIFEST):
            try:
                spec = parse_skill_manifest(path)
                if trust_override:
                    spec.trust_level = trust_override

                # Load cached scan result if hash matches
                cached = self._load_cached_scan(spec.id, spec.content_hash)
                if cached:
                    spec.risk_flags = cached.risk_flags
                    if trust_override is None:
                        spec.trust_level = cached.trust_level
                else:
                    # Fresh scan
                    result = scan_skill(spec)
                    spec.risk_flags = result.risk_flags
                    if trust_override is None:
                        spec.trust_level = result.trust_level
                    self._save_scan_cache(result)

                with self._skills_lock:
                    if spec.id not in self._skills:
                        self._skills[spec.id] = spec
            except Exception as e:
                logger.warning(f"Failed to load skill from {path.parent}: {e}")

    def _load_cached_scan(self, skill_id: str, content_hash: str) -> ScanResult | None:
        with db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT content_hash, risk_flags, trust_level FROM skill_scan_cache WHERE skill_id = ?",
                (skill_id,),
            ).fetchone()
        if row and row[0] == content_hash:
            return ScanResult(
                skill_id=skill_id,
                content_hash=row[0],
                risk_flags=json.loads(row[1]) if row[1] else [],
                trust_level=TrustLevel(row[2]) if row[2] else TrustLevel.COMMUNITY,
            )
        return None

    def _save_scan_cache(self, result: ScanResult) -> None:
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO skill_scan_cache (skill_id, content_hash, risk_flags, trust_level)
                VALUES (?, ?, ?, ?)
                """,
                (
                    result.skill_id,
                    result.content_hash,
                    json.dumps(result.risk_flags),
                    result.trust_level.value,
                ),
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Progressive Disclosure API
    # ------------------------------------------------------------------

    # Trust level ordering for comparison (lower index = more trusted)
    _TRUST_ORDER = {
        TrustLevel.BUILTIN: 0,
        TrustLevel.TRUSTED: 1,
        TrustLevel.COMMUNITY: 2,
        TrustLevel.QUARANTINE: 3,
    }

    def list_skills(
        self,
        category: str | None = None,
        skill_type: SkillType | None = None,
        trust_min: TrustLevel | None = None,
        only_compatible: bool = True,
        query: str | None = None,
    ) -> list[dict[str, Any]]:
        """List skills with metadata only — token-efficient (Hermes progressive disclosure tier 1).

        Returns minimal dicts suitable for showing in a list/table.
        """
        results: list[dict[str, Any]] = []
        for spec in self._skills_snapshot():
            if category and spec.category != category:
                continue
            if skill_type and spec.type != skill_type:
                continue
            if trust_min is not None and self._TRUST_ORDER.get(
                spec.trust_level, 99
            ) > self._TRUST_ORDER.get(trust_min, 99):
                continue
            if only_compatible and not spec.is_compatible():
                continue
            if (
                query
                and query.lower()
                not in f"{spec.name} {spec.description} {' '.join(spec.tags)}".lower()
            ):
                continue
            results.append(spec.to_summary_dict())
        return results

    def view_skill(self, skill_id: str) -> dict[str, Any] | None:
        """View full skill content — progressive disclosure tier 2-3.

        Loads the full Markdown body, references, and templates on demand.
        """
        self.ensure_loaded()
        with self._skills_lock:
            spec = self._skills.get(skill_id)
        if not spec:
            return None

        # Load full content if not already loaded (for installed skills)
        if not spec.full_content and spec.path:
            manifest = spec.path / self.SKILL_MANIFEST
            if manifest.exists():
                try:
                    refreshed = parse_skill_manifest(manifest)
                    spec.full_content = refreshed.full_content
                except Exception:
                    logger.warning(f"Failed to refresh manifest for {spec.id}", exc_info=True)

        # Load references
        references: dict[str, str] = {}
        if spec.references_dir and spec.references_dir.exists():
            for ref_file in sorted(spec.references_dir.iterdir()):
                if ref_file.is_file():
                    try:
                        references[ref_file.name] = ref_file.read_text()
                    except Exception:
                        logger.warning(f"Failed to read reference {ref_file.name}", exc_info=True)

        # Load templates
        templates: dict[str, str] = {}
        if spec.templates_dir and spec.templates_dir.exists():
            for tmpl_file in sorted(spec.templates_dir.iterdir()):
                if tmpl_file.is_file():
                    try:
                        templates[tmpl_file.name] = tmpl_file.read_text()
                    except Exception:
                        logger.warning(f"Failed to read template {tmpl_file.name}", exc_info=True)

        data = spec.to_detail_dict()
        data["content"] = spec.full_content
        data["references"] = references
        data["templates"] = templates
        return data

    def get_skill(self, skill_id: str) -> SkillSpec | None:
        with self._skills_lock:
            spec = self._skills.get(skill_id)
        if spec is not None:
            return spec
        self.ensure_loaded()
        with self._skills_lock:
            return self._skills.get(skill_id)

    def get_all(self) -> dict[str, SkillSpec]:
        """Return all loaded skills."""
        self.ensure_loaded()
        with self._skills_lock:
            return dict(self._skills)

    # ------------------------------------------------------------------
    # Categories & Discovery
    # ------------------------------------------------------------------

    def list_categories(self) -> list[dict[str, Any]]:
        """Return all categories with skill counts."""
        from collections import Counter

        cats = Counter(s.category for s in self._skills_snapshot())
        return [{"name": name, "count": count} for name, count in sorted(cats.items())]

    def search_skills(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """Full-text search across name, description, tags, and category."""
        return self.list_skills(query=query)[:limit]

    def check_prerequisites(self, skill_id: str) -> tuple[bool, list[str]]:
        """Check if a skill's prerequisites are satisfied."""
        self.ensure_loaded()
        with self._skills_lock:
            spec = self._skills.get(skill_id)
        if not spec:
            return False, ["Skill not found"]
        return spec.prerequisites.check()

    # ------------------------------------------------------------------
    # Installation
    # ------------------------------------------------------------------

    def _validate_skill_source(self, source: str) -> None:
        """Validate an exact GitHub HTTPS repository or an existing local source.

        Raises ValueError for disallowed sources.
        """
        if not isinstance(source, str) or not source.strip() or "\x00" in source:
            raise ValueError("Remote skill source is invalid")
        if self._github_repo_name(source) is not None:
            return
        parsed = urlsplit(source)
        if parsed.scheme or source.startswith("git@"):
            raise ValueError(
                "Remote skill source must be an exact https://github.com/<owner>/<repo>.git URL"
            )
        local_source = Path(source).expanduser()
        if not local_source.exists():
            raise ValueError(f"Unknown skill source: {source}")
        if local_source.is_symlink():
            raise ValueError("Local skill source cannot be a symlink")
        if local_source.is_dir():
            for item in local_source.rglob("*"):
                if item.is_symlink():
                    raise ValueError(
                        f"Local skill source contains a symlink: {item.relative_to(local_source)}"
                    )

    @staticmethod
    def _github_repo_name(source: str) -> str | None:
        try:
            parsed = urlsplit(source)
            port = parsed.port
        except ValueError:
            return None
        if (
            parsed.scheme != "https"
            or parsed.hostname != "github.com"
            or parsed.username is not None
            or parsed.password is not None
            or port not in (None, 443)
            or parsed.query
            or parsed.fragment
        ):
            return None
        repo_name = parsed.path.strip("/")
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
        if not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}",
            repo_name,
        ):
            return None
        return repo_name

    @staticmethod
    def _remote_install_context_error() -> str | None:
        from js.tools.registry import current_tool_execution_context

        context = current_tool_execution_context()
        if context is None:
            return "Remote skill installation requires a consumed Echo tool context"
        if context.tool_name not in {
            "control_skill_install",
            "control_clawhub_install",
        }:
            return "Remote skill installation requires the dedicated Echo control tool"
        if context.network_policy != "allow":
            return "Remote skill installation requires an Echo network grant"
        if not _REMOTE_SKILL_NETWORK_HOSTS.issubset(context.network_hosts):
            return "Remote skill installation Echo context is missing exact GitHub hosts"
        return None

    async def _secure_github_bytes(
        self,
        url: str,
        *,
        max_bytes: int,
        headers: dict[str, str] | None = None,
    ) -> bytes:
        context_error = self._remote_install_context_error()
        if context_error is not None:
            raise PermissionError(context_error)
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Remote skill download URL is invalid") from exc
        if (
            parsed.scheme != "https"
            or parsed.hostname not in {"api.github.com", "codeload.github.com"}
            or parsed.username is not None
            or parsed.password is not None
            or port not in (None, 443)
            or not parsed.path.startswith("/")
            or parsed.fragment
        ):
            raise ValueError("Remote skill download destination is not allowlisted")
        validated_ips = await asyncio.to_thread(
            resolve_and_validate,
            url,
            allow_loopback=False,
            allow_private=False,
        )
        chunks: list[bytes] = []
        total = 0
        async with (
            httpx.AsyncClient(
                transport=PinnedTransport(validated_ips[0], verify=True),
                timeout=httpx.Timeout(30.0),
                follow_redirects=False,
                trust_env=False,
            ) as client,
            client.stream("GET", url, headers=headers) as response,
        ):
            if response.is_redirect:
                raise ValueError("Remote skill download redirects are disabled")
            response.raise_for_status()
            content_length = response.headers.get("content-length")
            if content_length:
                try:
                    declared_size = int(content_length)
                except ValueError as exc:
                    raise ValueError("Remote skill download has an invalid content length") from exc
                if declared_size < 0 or declared_size > max_bytes:
                    raise ValueError("Remote skill download exceeds the size limit")
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("Remote skill download exceeds the size limit")
                chunks.append(chunk)
        return b"".join(chunks)

    async def _download_github_repository(self, source: str, target_dir: Path) -> None:
        repo_name = self._github_repo_name(source)
        if repo_name is None:
            raise ValueError("Remote skill source is invalid")
        context_error = self._remote_install_context_error()
        if context_error is not None:
            raise PermissionError(context_error)

        metadata_url = f"https://api.github.com/repos/{repo_name}"
        metadata_bytes = await self._secure_github_bytes(
            metadata_url,
            max_bytes=1_000_000,
            headers={"Accept": "application/vnd.github+json"},
        )
        metadata = json.loads(metadata_bytes)
        if not isinstance(metadata, dict):
            raise ValueError("GitHub repository metadata is malformed")
        branch = metadata.get("default_branch")
        if (
            not isinstance(branch, str)
            or not branch
            or len(branch) > 200
            or branch.startswith("/")
            or ".." in PurePosixPath(branch).parts
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", branch)
        ):
            raise ValueError("GitHub repository default branch is invalid")
        owner, repository = repo_name.split("/", 1)
        archive_url = (
            f"https://codeload.github.com/{owner}/{repository}/tar.gz/refs/heads/"
            f"{quote(branch, safe='')}"
        )
        archive_bytes = await self._secure_github_bytes(
            archive_url,
            max_bytes=_MAX_REMOTE_SKILL_ARCHIVE_BYTES,
        )
        await asyncio.to_thread(
            self._extract_github_archive,
            archive_bytes,
            target_dir,
        )

    @staticmethod
    def _extract_github_archive(archive_bytes: bytes, target_dir: Path) -> None:
        if not archive_bytes or len(archive_bytes) > _MAX_REMOTE_SKILL_ARCHIVE_BYTES:
            raise ValueError("Remote skill archive exceeds the size limit")
        if target_dir.exists():
            raise ValueError("Remote skill extraction target already exists")

        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > _MAX_REMOTE_SKILL_MEMBERS:
                raise ValueError("Remote skill archive member limit exceeded")

            normalized: list[tuple[tarfile.TarInfo, PurePosixPath | None]] = []
            root_name: str | None = None
            expanded_bytes = 0
            seen: set[PurePosixPath] = set()
            for member in members:
                raw_path = PurePosixPath(member.name)
                if (
                    not member.name
                    or "\x00" in member.name
                    or raw_path.is_absolute()
                    or ".." in raw_path.parts
                    or not raw_path.parts
                ):
                    raise ValueError("Remote skill archive contains an unsafe path")
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise ValueError("Remote skill archive contains a link or special file")
                if not member.isdir() and not member.isfile():
                    raise ValueError("Remote skill archive contains an unsupported member")
                if root_name is None:
                    root_name = raw_path.parts[0]
                if raw_path.parts[0] != root_name:
                    raise ValueError("Remote skill archive has multiple roots")
                relative = PurePosixPath(*raw_path.parts[1:])
                if not relative.parts:
                    normalized.append((member, None))
                    continue
                if relative.parts[0] in {".git", ".venv"}:
                    raise ValueError("Remote skill archive contains a forbidden directory")
                if relative in seen:
                    raise ValueError("Remote skill archive contains duplicate paths")
                seen.add(relative)
                if member.isfile():
                    if member.size < 0 or member.size > _MAX_REMOTE_SKILL_FILE_BYTES:
                        raise ValueError("Remote skill archive file exceeds the size limit")
                    expanded_bytes += member.size
                    if expanded_bytes > _MAX_REMOTE_SKILL_EXPANDED_BYTES:
                        raise ValueError("Remote skill archive expands beyond the size limit")
                normalized.append((member, relative))

            target_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
            try:
                target_root = target_dir.resolve()
                for member, normalized_relative in normalized:
                    if normalized_relative is None:
                        continue
                    destination = target_dir.joinpath(*normalized_relative.parts)
                    resolved_destination = destination.resolve(strict=False)
                    try:
                        resolved_destination.relative_to(target_root)
                    except ValueError as exc:
                        raise ValueError("Remote skill archive path escapes the target") from exc
                    if member.isdir():
                        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                        continue
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    source_file = archive.extractfile(member)
                    if source_file is None:
                        raise ValueError("Remote skill archive file cannot be read")
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    if hasattr(os, "O_NOFOLLOW"):
                        flags |= os.O_NOFOLLOW
                    try:
                        fd = os.open(destination, flags, 0o600)
                        written = 0
                        try:
                            while True:
                                chunk = source_file.read(65_536)
                                if not chunk:
                                    break
                                written += len(chunk)
                                if written > member.size:
                                    raise ValueError(
                                        "Remote skill archive member size is inconsistent"
                                    )
                                view = memoryview(chunk)
                                while view:
                                    count = os.write(fd, view)
                                    if count <= 0:
                                        raise OSError("Remote skill archive write stalled")
                                    view = view[count:]
                            if written != member.size:
                                raise ValueError("Remote skill archive member size is inconsistent")
                            os.fsync(fd)
                        finally:
                            os.close(fd)
                    finally:
                        source_file.close()
            except Exception:
                shutil.rmtree(target_dir, ignore_errors=True)
                raise

    async def install(
        self, source: str, skill_id: str | None = None, expected_hash: str | None = None
    ) -> SkillSpec:
        """Serialise installation so staging and publication are atomic."""
        async with self._install_lock:
            return await self._install_locked(source, skill_id, expected_hash)

    async def _install_locked(
        self, source: str, skill_id: str | None, expected_hash: str | None
    ) -> SkillSpec:
        """Prepare in a private directory, then atomically publish the skill."""
        self._validate_skill_source(source)

        target_id = skill_id or Path(source).name
        target_id = Path(target_id).name
        if not target_id or target_id in (".", ".."):
            raise ValueError(f"Invalid skill ID: {skill_id or Path(source).name}")
        if not re.match(r"^[a-z0-9_-]+$", target_id) or len(target_id) > 64:
            raise ValueError(
                f"Invalid skill ID: {target_id!r}. "
                f"Allowed: lowercase letters, digits, hyphens, underscores, max 64 chars."
            )
        target_dir = self.skills_dir / target_id
        try:
            target_dir.resolve(strict=False).relative_to(self.skills_dir.resolve())
        except ValueError as e:
            raise ValueError(f"Skill ID escapes skills directory: {target_id}") from e
        staging_dir = self.skills_dir / (
            f".install-{target_id}-{os.getpid()}-{time.monotonic_ns()}"
        )
        try:
            await self._stage_skill_source(source, staging_dir)
            spec, scan_result = self._prepare_skill_spec(
                staging_dir,
                target_id=target_id,
                expected_hash=expected_hash,
            )
            await self._publish_skill_directory(staging_dir, target_dir)
            spec.path = target_dir
            self._save_scan_cache(scan_result)
            with self._skills_lock:
                self._skills[spec.id] = spec
            self._register_skill_as_tool(spec)
            logger.info(f"Installed skill: {spec.id} (trust={spec.trust_level.value})")
            return spec
        finally:
            if staging_dir.exists() or staging_dir.is_symlink():
                await asyncio.to_thread(
                    self._remove_install_path,
                    staging_dir,
                )

    async def _stage_skill_source(self, source: str, staging_dir: Path) -> None:
        if self._github_repo_name(source) is not None:
            await self._download_github_repository(source, staging_dir)
        else:
            local_source = Path(source).expanduser()
            if local_source.is_dir():
                await asyncio.to_thread(
                    shutil.copytree,
                    local_source,
                    staging_dir,
                    True,
                )
                # Align with the remote-archive policy: a top-level .git or
                # .venv is never accepted (the integrity hash excludes .venv,
                # so a shipped interpreter would be invisible to it).
                for top_item in staging_dir.iterdir():
                    if top_item.name in {".git", ".venv"}:
                        raise ValueError("Local skill source contains a forbidden directory")
            elif local_source.is_file():
                staging_dir.mkdir(mode=0o700)
                await asyncio.to_thread(
                    shutil.copy2,
                    local_source,
                    staging_dir / local_source.name,
                    follow_symlinks=False,
                )
            else:
                raise ValueError(f"Unknown skill source: {source}")

        for item in staging_dir.rglob("*"):
            if item.is_symlink():
                raise RuntimeError(f"Skill contains symlinks: {item.relative_to(staging_dir)}")

    def _prepare_skill_spec(
        self,
        staging_dir: Path,
        *,
        target_id: str,
        expected_hash: str | None,
    ) -> tuple[SkillSpec, ScanResult]:
        manifest = staging_dir / self.SKILL_MANIFEST
        if not manifest.exists():
            manifest.write_text(
                f"""---
id: {target_id}
name: {target_id}
description: Auto-generated skill
version: 0.1.0
type: code
entry: main.py
---
""",
                encoding="utf-8",
            )
        if manifest.is_symlink() or not manifest.is_file():
            raise ValueError("Skill manifest must be a regular file")
        if manifest.stat().st_size > 1_000_000:
            raise ValueError("Skill manifest exceeds the size limit")

        spec = parse_skill_manifest(manifest)
        # The administrator-authorised destination is authoritative. An
        # untrusted manifest cannot replace another skill by claiming its ID.
        spec.id = target_id
        spec.path = staging_dir
        if expected_hash:
            # SkillSpec.compute_hash() returns a 32-hex truncated SHA-256;
            # accept both the truncated form and the full 64-hex digest so
            # the pin actually verifies instead of always failing closed.
            if not re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{64}", expected_hash):
                raise ValueError("Skill expected hash must be a SHA-256 digest")
            from js.skills.spec import compute_skill_dir_hash

            actual_full = compute_skill_dir_hash(staging_dir).lower()
            expected = expected_hash.lower()
            if expected not in (actual_full, actual_full[:32]):
                raise ValueError(
                    f"Skill hash mismatch for {spec.id}: "
                    f"expected {expected_hash}, got {actual_full[:32]}"
                )

        self._infer_installed_skill_type(spec, manifest, staging_dir)
        scan_result = scan_skill(spec)
        spec.risk_flags = list(scan_result.risk_flags)
        spec.trust_level = scan_result.trust_level
        if self._validate_requirement_manifest(staging_dir / "requirements.txt", spec.id):
            spec.risk_flags = list(dict.fromkeys([*spec.risk_flags, "dependencies_unprovisioned"]))
        return spec, scan_result

    @staticmethod
    def _infer_installed_skill_type(
        spec: SkillSpec,
        manifest: Path,
        staging_dir: Path,
    ) -> None:
        try:
            import yaml

            text = manifest.read_text(encoding="utf-8")
            match = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
            frontmatter = yaml.safe_load(match.group(1) if match else text) or {}
            has_explicit_type = isinstance(frontmatter, dict) and "type" in frontmatter
        except Exception:
            logger.warning("Skill type inference failed closed", exc_info=True)
            has_explicit_type = True
        if not has_explicit_type:
            scripts_dir = staging_dir / "scripts"
            has_scripts = scripts_dir.is_dir() and any(scripts_dir.iterdir())
            if not has_scripts:
                spec.type = SkillType.PROMPT
                logger.debug(f"Inferred type=prompt for {spec.id} (no scripts/ dir)")

    @staticmethod
    def _validate_requirement_manifest(req_file: Path, skill_id: str) -> bool:
        if not req_file.exists():
            return False
        if req_file.is_symlink() or not req_file.is_file():
            raise ValueError("Skill requirements must be a regular file")
        if req_file.stat().st_size > 1_000_000:
            raise ValueError("Skill requirements exceed the size limit")
        raw_reqs = req_file.read_text(encoding="utf-8")
        for line in raw_reqs.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if (
                stripped.startswith("git+")
                or stripped.startswith("-e ")
                or stripped.startswith(".")
                or stripped.startswith("-")
                or stripped.startswith("file:")
                or stripped.startswith("http:")
                or stripped.startswith("https:")
                or "//" in stripped
                or ";" in stripped
            ):
                raise ValueError(f"Blocked unsafe requirement in {skill_id}: {stripped[:80]}")
        return True

    async def _publish_skill_directory(
        self,
        staging_dir: Path,
        target_dir: Path,
    ) -> None:
        backup_dir = self.skills_dir / (
            f".replace-{target_dir.name}-{os.getpid()}-{time.monotonic_ns()}"
        )
        moved_old = False
        try:
            if target_dir.exists() or target_dir.is_symlink():
                os.replace(target_dir, backup_dir)
                moved_old = True
            os.replace(staging_dir, target_dir)
            directory_fd = os.open(self.skills_dir, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            if moved_old and not target_dir.exists() and backup_dir.exists():
                os.replace(backup_dir, target_dir)
            raise
        if moved_old:
            await asyncio.to_thread(self._remove_install_path, backup_dir)

    @staticmethod
    def _remove_install_path(path: Path) -> None:
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.exists():
            shutil.rmtree(path, ignore_errors=True)

    async def uninstall(self, skill_id: str) -> bool:
        with self._skills_lock:
            spec = self._skills.pop(skill_id, None)
        if spec is None:
            return False
        if spec.path and spec.path.exists() and not self._is_builtin(spec):
            await asyncio.to_thread(shutil.rmtree, spec.path)
        self._unregister_skill_as_tool(skill_id)
        logger.info(f"Uninstalled skill: {skill_id}")
        return True

    def trust_skill(
        self,
        skill_id: str,
        level: TrustLevel,
        *,
        source: str = "operator",
        reason: str | None = None,
        decided_by: str | None = None,
        event_id: str | None = None,
        owner_key_hash: str | None = None,
    ) -> bool:
        """Manually override a skill's trust level after review.

        v0.1.4-alpha PR-1.5 hardening: trust transitions also flip tool
        exposure. Upgrading out of QUARANTINE (operator approve) registers
        the skill as a callable tool; downgrading back to QUARANTINE
        unregisters it. All other transitions are a no-op for the registry
        because the skill was already exposed.

        v0.1.5-alpha extension: every successful mutation is recorded in
        ``promotion_events`` and emits a ``SKILL_PROMOTION`` audit row.
        The old two-arg signature still works — defaults give the legacy
        ``source="operator"`` semantics. When ``event_id`` is supplied the
        caller is finalising a previously-proposed event via
        ``apply_proposal`` and must NOT trigger a duplicate write here.
        """
        spec = self._skills.get(skill_id)
        if not spec:
            return False
        previous = spec.trust_level
        spec.trust_level = level
        # Only mutate the registry when the QUARANTINE boundary is crossed.
        was_exposed = previous != TrustLevel.QUARANTINE
        now_exposed = level != TrustLevel.QUARANTINE
        if not was_exposed and now_exposed:
            self._register_skill_as_tool(spec)
        elif was_exposed and not now_exposed:
            self._unregister_skill_as_tool(skill_id)
        logger.info(f"Trust level for {skill_id} set to {level.value}")

        # Audit + promotion-event persistence. Failures degrade to warnings —
        # operator UX must never depend on telemetry pathing.
        actor = decided_by or "local"
        if event_id is None:
            try:
                self.promotion_store.record_operator_apply(
                    skill_id,
                    previous.value,
                    level.value,
                    owner_key_hash=(
                        owner_key_hash if owner_key_hash is not None else self._owner_key_hash
                    ),
                    decided_by=actor,
                    reason=reason,
                    source=source,
                )
            except Exception:
                logger.warning("promotion_store.record_operator_apply failed", exc_info=True)
        self._emit_promotion_audit(
            skill_id=skill_id,
            from_level=previous.value,
            to_level=level.value,
            source=source,
            reason=reason,
            decided_by=actor,
            event_id=event_id,
            action="skill_trust_changed",
        )
        return True

    # ------------------------------------------------------------------
    # v0.1.5-alpha promotion pipeline: apply / rollback
    # ------------------------------------------------------------------

    async def apply_proposal(
        self,
        event_id: str,
        *,
        decided_by: str,
        owner_key_hash: str | None = None,
        smoke_args: dict[str, Any] | None = None,
        run_tests: bool = True,
        run_smoke: bool = True,
    ) -> dict[str, Any]:
        """Run the promotion gate for ``event_id`` and apply on pass.

        Pipeline:
          1. Load the event (must be ``proposed``).
          2. ``mark_approved`` (audit trail of decision authority).
          3. Run :class:`PromotionGate`.
          4. Pass:
             - if ``variant_id`` / ``artifact_path`` set, back up the entry
               file and overlay the variant.
             - if ``to_level != from_level``, call ``trust_skill`` with the
               event_id so the second event-write is suppressed.
             - ``mark_applied``.
          5. Fail → ``mark_failed``; spec untouched, no file write.
        """
        # Local imports keep promotion_gate optional at module-load time
        # (e.g. cli / web that never apply proposals).
        from js.skills.promotion_gate import PromotionGate

        owner = owner_key_hash if owner_key_hash is not None else self._owner_key_hash

        event = self.promotion_store.get(event_id, owner_key_hash=owner)
        if event is None:
            return {"success": False, "error": f"Promotion event not found: {event_id}"}
        if event.status != "proposed":
            return {
                "success": False,
                "error": f"Promotion event {event_id} is in status {event.status!r}, not 'proposed'",
            }

        spec = self._skills.get(event.skill_id)
        if spec is None:
            self.promotion_store.mark_failed(
                event_id,
                owner_key_hash=owner,
                failed_step="load",
                details={"reason": "skill not registered"},
            )
            return {"success": False, "error": f"Skill not registered: {event.skill_id}"}

        self.promotion_store.mark_approved(event_id, owner_key_hash=owner, decided_by=decided_by)

        gate = PromotionGate(
            workspace=self.workspace,
            sandbox=self._sandbox,
            smoke_args=smoke_args,
            audit_logger=self._audit_logger,
            run_tests=run_tests,
            run_smoke=run_smoke,
        )
        gate_result = await gate.run(spec)
        if not gate_result.passed:
            self.promotion_store.mark_failed(
                event_id,
                owner_key_hash=owner,
                failed_step=gate_result.failed_step or "unknown",
                details=gate_result.details,
            )
            return {
                "success": False,
                "event_id": event_id,
                "failed_step": gate_result.failed_step,
                "details": gate_result.details,
            }

        # Pass: overlay variant code if any, then flip trust if changed.
        overlay_info: dict[str, Any] = {"overlay": False}
        if event.variant_id and event.artifact_path and spec.path is not None:
            try:
                overlay_info = self._overlay_variant_artifact(
                    spec=spec,
                    event_id=event_id,
                    artifact_path=Path(event.artifact_path),
                )
            except Exception as exc:
                self.promotion_store.mark_failed(
                    event_id,
                    owner_key_hash=owner,
                    failed_step="apply",
                    details={"overlay_error": str(exc)[:500]},
                )
                logger.warning("Variant overlay failed for %s", event_id, exc_info=True)
                return {
                    "success": False,
                    "event_id": event_id,
                    "failed_step": "apply",
                    "error": str(exc),
                }

        trust_changed = event.to_level != event.from_level
        if trust_changed:
            try:
                level_enum = TrustLevel(event.to_level)
            except ValueError:
                self.promotion_store.mark_failed(
                    event_id,
                    owner_key_hash=owner,
                    failed_step="apply",
                    details={"reason": f"unknown to_level: {event.to_level}"},
                )
                return {
                    "success": False,
                    "event_id": event_id,
                    "failed_step": "apply",
                    "error": f"unknown to_level: {event.to_level}",
                }
            self.trust_skill(
                event.skill_id,
                level_enum,
                source=event.source,
                reason=event.reason,
                decided_by=decided_by,
                event_id=event_id,
            )

        self.promotion_store.mark_applied(
            event_id,
            owner_key_hash=owner,
            details={**overlay_info, "gate": gate_result.details},
        )
        return {
            "success": True,
            "event_id": event_id,
            "trust_changed": trust_changed,
            "overlay": overlay_info,
            "gate": gate_result.details,
        }

    def revert_promotion(
        self,
        event_id: str,
        *,
        decided_by: str,
        owner_key_hash: str | None = None,
    ) -> dict[str, Any]:
        """Roll back a previously-applied promotion.

        Restores the entry file from the per-event backup (if a variant
        overlay was applied) and rolls trust back to ``from_level``.
        Writes a ``SKILL_PROMOTION`` audit row with ``action="skill_rollback"``
        and transitions the event row to ``rolled_back``.
        """
        owner = owner_key_hash if owner_key_hash is not None else self._owner_key_hash
        event = self.promotion_store.get(event_id, owner_key_hash=owner)
        if event is None:
            return {"success": False, "error": f"Promotion event not found: {event_id}"}
        if event.status != "applied":
            return {
                "success": False,
                "error": f"Promotion event {event_id} is in status {event.status!r}, not 'applied'",
            }

        spec = self._skills.get(event.skill_id)
        if spec is None:
            return {"success": False, "error": f"Skill not registered: {event.skill_id}"}

        restored = self._restore_variant_backup(spec=spec, event_id=event_id)

        trust_reverted = False
        if event.to_level != event.from_level:
            try:
                prior = TrustLevel(event.from_level)
            except ValueError:
                return {
                    "success": False,
                    "error": f"unknown from_level: {event.from_level}",
                }
            self._rollback_trust(spec, prior, event_id=event_id, decided_by=decided_by)
            trust_reverted = True

        self.promotion_store.mark_rolled_back(
            event_id,
            owner_key_hash=owner,
            details={"restored_files": restored, "trust_reverted": trust_reverted},
        )
        self._emit_promotion_audit(
            skill_id=event.skill_id,
            from_level=event.to_level,
            to_level=event.from_level,
            source=event.source,
            reason=event.reason,
            decided_by=decided_by,
            event_id=event_id,
            action="skill_rollback",
        )
        return {
            "success": True,
            "event_id": event_id,
            "trust_reverted": trust_reverted,
            "restored_files": restored,
        }

    # ------------------------------------------------------------------
    # promotion helpers
    # ------------------------------------------------------------------

    def _overlay_variant_artifact(
        self,
        *,
        spec: SkillSpec,
        event_id: str,
        artifact_path: Path,
    ) -> dict[str, Any]:
        """Back up the current entry file and overlay the variant code.

        The backup lives at ``<spec.path>/.promotion_backups/<event_id>/<entry>``;
        ``revert_promotion`` restores from there. Backups are intentionally
        kept inside the skill directory so they ride along with the skill if
        operators move it.
        """
        if spec.path is None:
            raise RuntimeError("spec.path is None; cannot overlay variant")
        entry_name = spec.entry or "main.py"
        target = spec.path / entry_name
        if not artifact_path.exists():
            raise FileNotFoundError(f"variant artifact missing: {artifact_path}")
        backup_dir = spec.path / ".promotion_backups" / event_id
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_file = backup_dir / entry_name
        if target.exists():
            shutil.copy2(target, backup_file)
        shutil.copy2(artifact_path, target)
        return {
            "overlay": True,
            "entry": entry_name,
            "backup": str(backup_file),
        }

    def _restore_variant_backup(self, *, spec: SkillSpec, event_id: str) -> list[str]:
        """Restore the entry file from a per-event backup, if one exists."""
        if spec.path is None:
            return []
        backup_dir = spec.path / ".promotion_backups" / event_id
        if not backup_dir.exists():
            return []
        restored: list[str] = []
        for backup_file in backup_dir.iterdir():
            if not backup_file.is_file():
                continue
            target = spec.path / backup_file.name
            shutil.copy2(backup_file, target)
            restored.append(backup_file.name)
        return restored

    def _rollback_trust(
        self,
        spec: SkillSpec,
        prior: TrustLevel,
        *,
        event_id: str,
        decided_by: str,
    ) -> None:
        """Direct trust mutation used by ``revert_promotion``.

        Skips ``trust_skill`` to avoid writing a *second* operator-apply
        promotion event — the rollback path is audited by
        ``revert_promotion`` itself via ``_emit_promotion_audit``.
        """
        previous = spec.trust_level
        spec.trust_level = prior
        was_exposed = previous != TrustLevel.QUARANTINE
        now_exposed = prior != TrustLevel.QUARANTINE
        if not was_exposed and now_exposed:
            self._register_skill_as_tool(spec)
        elif was_exposed and not now_exposed:
            self._unregister_skill_as_tool(spec.id)
        logger.info(
            "Trust level for %s rolled back from %s to %s (event=%s)",
            spec.id,
            previous.value,
            prior.value,
            event_id,
        )

    def _emit_promotion_audit(
        self,
        *,
        skill_id: str,
        from_level: str,
        to_level: str,
        source: str,
        reason: str | None,
        decided_by: str,
        event_id: str | None,
        action: str,
    ) -> None:
        """Write a SKILL_PROMOTION audit row. Failures degrade to warnings."""
        if self._audit_logger is None:
            return
        try:
            from js.security.audit import AuditEventType

            self._audit_logger.log(
                AuditEventType.SKILL_PROMOTION,
                "",
                "",
                actor=decided_by,
                action=action,
                details={
                    "skill_id": skill_id,
                    "from_level": from_level,
                    "to_level": to_level,
                    "source": source,
                    "reason": reason or "",
                    "event_id": event_id or "",
                },
            )
        except Exception:
            logger.warning("audit emit failed for skill promotion", exc_info=True)

    def _is_builtin(self, spec: SkillSpec) -> bool:
        return spec.trust_level == TrustLevel.BUILTIN

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def execute(
        self,
        skill_id: str,
        args: dict[str, Any],
        llm_caller: LLMCaller | None = None,
        session_id: str = "",
        *,
        _depth: int = 0,
        _ancestors: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        """Execute a skill with full lifecycle tracking.

        ``_depth`` and ``_ancestors`` are internal recursion-guard parameters,
        set only when this method acts as the sub-skill resolver of a
        workflow/meta skill; regular callers must not pass them.
        """

        self._ensure_open()
        self.ensure_loaded()
        # Fail-closed recursion guard (defense in depth — the executor runs
        # the same checks before invoking the resolver).
        if _depth > MAX_SUBSKILL_DEPTH:
            return {
                "success": False,
                "error": f"Maximum skill nesting depth ({MAX_SUBSKILL_DEPTH}) exceeded",
            }
        if skill_id in _ancestors:
            return {
                "success": False,
                "error": f"Recursive skill reference blocked: "
                f"'{skill_id}' is already in the call chain",
            }
        start = time.time()
        with self._skills_lock:
            spec = self._skills.get(skill_id)
        if not spec:
            return {"success": False, "error": f"Skill not found: {skill_id}"}

        # Security checks
        if spec.trust_level == TrustLevel.QUARANTINE:
            return {
                "success": False,
                "error": f"Skill {skill_id} is quarantined. Run 'trust' to review.",
            }

        if spec.trust_level != TrustLevel.BUILTIN and not verify_integrity(spec):
            logger.warning(f"Skill {skill_id} hash mismatch, rescanning")
            result = scan_skill(spec)
            spec.risk_flags = result.risk_flags
            spec.trust_level = result.trust_level
            self._save_scan_cache(result)

        if spec.trust_level == TrustLevel.QUARANTINE:
            return {"success": False, "error": f"Skill {skill_id} was quarantined after rescan."}

        # Prerequisites check (advisory)
        ok, missing = spec.prerequisites.check()
        if not ok:
            logger.warning(f"Skill {skill_id} missing prerequisites: {missing}")

        # Resolve dependencies for META skills
        if spec.type == SkillType.META:
            dep_results = await self._execute_dependencies(
                spec, args, llm_caller, _depth, _ancestors
            )
            if not all(r.get("success", False) for r in dep_results):
                return {
                    "success": False,
                    "error": f"Meta skill dependency failed for {skill_id}",
                    "dependencies": dep_results,
                }

        # Execute
        sanitized_failure = False
        try:
            exec_result: dict[str, Any] = await execute_skill(
                spec,
                args,
                self.workspace,
                llm_caller,
                self._sandbox,
                self.execute,
                _depth=_depth,
                _ancestors=_ancestors,
            )
        except Exception as exc:
            logger.warning(
                "Skill execution failed for %s: %s",
                skill_id,
                type(exc).__name__,
            )
            exec_result = {"success": False, "error": "Skill execution failed safely"}
            sanitized_failure = True

        latency = (time.time() - start) * 1000
        success = exec_result.get("success", False)
        self._record_usage(skill_id, spec.type.value, success, latency)

        # Emit Prometheus metrics
        try:
            from js.utils.metrics import get_metrics

            m = get_metrics()
            source = "hermes" if skill_id.startswith("hermes:") else "native"
            m.skill_usage_total.labels(
                skill_id=skill_id, skill_type=spec.type.value, source=source
            ).inc()
            m.skill_latency_seconds.labels(skill_id=skill_id, skill_type=spec.type.value).observe(
                latency / 1000.0
            )
            # Success rate as a point-in-time gauge (based on in-memory stats)
            if spec.success_rate is not None:
                m.skill_success_rate_gauge.labels(skill_id=skill_id).observe(spec.success_rate)
        except Exception:
            logger.warning("Failed to emit skill metrics", exc_info=True)

        # Record evolution feedback
        if hasattr(self, "_evolver") and self._evolver:
            try:
                score = 1.0 if success else 0.0
                error_msg = exec_result.get("error", "") if not success else ""
                self._evolver.record_execution_feedback(
                    skill_id=skill_id,
                    success=success,
                    score=score,
                    error_message=error_msg,
                    context=session_id or "",
                )
                # Try auto-promotion if the skill is performing well.
                # v0.1.4-alpha hardening: builtin and Hermes skills are
                # never auto-promoted — their entry files must remain
                # exactly as shipped. SkillEvolver.promote_variant() has
                # the same guard, this is defense-in-depth.
                if (
                    success
                    and spec.path
                    and spec.trust_level != TrustLevel.BUILTIN
                    and not skill_id.startswith("hermes:")
                ):
                    self._evolver.promote_variant(
                        skill_id, spec.path, getattr(spec, "entry", "main.py")
                    )
            except Exception:
                logger.warning("Failed to record evolution result for %s", skill_id, exc_info=True)

        # Record composition chain for learning
        self._record_chain(skill_id, success, session_id)

        # Orin WP2 site 6: skill output entering the model context carries
        # SKILL_CONTENT provenance (third-party instruction text). Sanitized
        # harness errors are not skill output and must stay field-identical.
        if not sanitized_failure:
            from js.orin.taint import SKILL_CONTENT as _SKILL_TAINT

            exec_result.setdefault("orin_taint", 0)
            exec_result["orin_taint"] = int(exec_result.get("orin_taint", 0)) | _SKILL_TAINT
        return exec_result

    async def _execute_dependencies(
        self,
        spec: SkillSpec,
        args: dict[str, Any],
        llm_caller: LLMCaller | None,
        _depth: int = 0,
        _ancestors: tuple[str, ...] = (),
    ) -> list[dict[str, Any]]:
        """Execute dependency skills in topological order."""
        results: list[dict[str, Any]] = []
        visited: set[str] = set()

        async def execute_dep(dep_id: str) -> dict[str, Any] | None:
            if dep_id in visited:
                return None
            visited.add(dep_id)
            dep_spec = self._skills.get(dep_id)
            if not dep_spec:
                return {"success": False, "error": f"Dependency skill not found: {dep_id}"}
            # Dependencies run one nesting level below the meta skill, so the
            # recursion guard context must extend with this skill's ID.
            result = await execute_skill(
                dep_spec,
                args,
                self.workspace,
                llm_caller,
                self._sandbox,
                self.execute,
                _depth=_depth + 1,
                _ancestors=(*_ancestors, spec.id),
            )
            return result

        for dep_id in spec.dependencies:
            result = await execute_dep(dep_id)
            if result:
                results.append(result)
                if not result.get("success", False):
                    break  # Stop on first failure

        return results

    def _record_usage(
        self, skill_id: str, skill_type: str, success: bool, latency_ms: float
    ) -> None:
        source = "hermes" if skill_id.startswith("hermes:") else "native"
        with db_connection(self.db_path) as conn:
            conn.execute(
                "INSERT INTO skill_usage (skill_id, skill_type, success, latency_ms, context) VALUES (?, ?, ?, ?, ?)",
                (skill_id, skill_type, int(success), latency_ms, source),
            )
            conn.commit()

        # Update in-memory stats
        spec = self._skills.get(skill_id)
        if spec:
            with db_connection(self.db_path) as conn:
                total = conn.execute(
                    "SELECT COUNT(*), SUM(success) FROM skill_usage WHERE skill_id = ?", (skill_id,)
                ).fetchone()
                avg_lat = conn.execute(
                    "SELECT AVG(latency_ms) FROM skill_usage WHERE skill_id = ?", (skill_id,)
                ).fetchone()
            if total and total[0] > 0:
                spec.usage_count = total[0]
                spec.success_rate = (total[1] or 0) / total[0]
                spec.avg_latency_ms = avg_lat[0] or 0.0

    def _record_chain(self, skill_id: str, _success: bool, session_id: str = "") -> None:
        """Record skill execution for composition chain discovery."""
        if not session_id or not self._composer:
            return

        last_skill = self._last_skill_by_session.get(session_id)
        if last_skill and last_skill != skill_id:
            try:
                self._composer.record_transition(last_skill, skill_id, session_id)
            except Exception:
                logger.warning(
                    f"Failed to record transition {last_skill} -> {skill_id}", exc_info=True
                )

        self._last_skill_by_session[session_id] = skill_id

    # ------------------------------------------------------------------
    # Stats & Admin
    # ------------------------------------------------------------------

    def get_stats(self, skill_id: str) -> dict[str, Any] | None:
        spec = self._skills.get(skill_id)
        if not spec:
            return None
        return {
            "id": spec.id,
            "name": spec.name,
            "version": spec.version,
            "type": spec.type.value,
            "trust_level": spec.trust_level.value,
            "risk_flags": spec.risk_flags,
            "usage_count": spec.usage_count,
            "success_rate": spec.success_rate,
            "avg_latency_ms": spec.avg_latency_ms,
            "prerequisites_ok": spec.prerequisites.check()[0],
            "timeout_seconds": spec.timeout_seconds,
            "network_allowed": spec.network_allowed,
            "dependencies": spec.dependencies,
        }

    def get_global_stats(self) -> dict[str, Any]:
        with db_connection(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(DISTINCT skill_id) FROM skill_usage").fetchone()[0]
            executions = conn.execute("SELECT COUNT(*) FROM skill_usage").fetchone()[0]
            success = conn.execute("SELECT SUM(success) FROM skill_usage").fetchone()[0]
            avg_lat = conn.execute("SELECT AVG(latency_ms) FROM skill_usage").fetchone()[0]

        skills = self._skills_snapshot()
        return {
            "skills_used": total,
            "total_executions": executions,
            "overall_success_rate": (success / executions) if executions else 1.0,
            "avg_latency_ms": avg_lat or 0.0,
            "skills_loaded": len(skills),
            "builtin_count": sum(1 for s in skills if s.trust_level == TrustLevel.BUILTIN),
            "quarantined_count": sum(1 for s in skills if s.trust_level == TrustLevel.QUARANTINE),
        }
