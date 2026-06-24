"""Next-generation skill manager: code + prompt + workflow with security & discovery."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import sys
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from js.security.sandbox import SandboxExecutor
from js.skills.executor import execute_skill
from js.skills.hermes_bridge import (
    discover_hermes_skills,
    enhanced_scan_hermes_skill,
    get_bridge_stats,
    load_hermes_skill,
)
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

    def __init__(self, state_dir: Path, workspace: Path) -> None:
        self.state_dir = state_dir
        self.workspace = workspace
        self.skills_dir = state_dir / "skills"
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = state_dir / "skills.db"
        self._init_db()
        self._skills: dict[str, SkillSpec] = {}
        self._scan_cache: dict[str, ScanResult] = {}
        self._sandbox: SandboxExecutor | None = None
        self._composer: Any | None = None
        self._last_skill_by_session: dict[str, str] = {}
        self._tool_registry: Any | None = None
        self._load_all()

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

    def register_as_tools(self, registry: Any) -> None:
        """Register all loaded skills as callable tools in the agent's registry."""
        self._tool_registry = registry
        for spec in self._skills.values():
            self._register_skill_as_tool(spec)

    def register_auto_skill(self, spec: SkillSpec) -> None:
        """Register an auto-generated skill and expose it as a tool."""
        self._skills[spec.id] = spec
        self._register_skill_as_tool(spec)
        logger.info(f"Registered auto-skill: {spec.id}")

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

    def _register_skill_as_tool(self, spec: SkillSpec) -> None:
        if not self._tool_registry:
            return
        if not self._should_expose_as_tool(spec):
            logger.debug(
                "Skipping tool registration for %s (trust_level=%s)",
                spec.id,
                spec.trust_level.value,
            )
            return

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
            args = kwargs.get("args", {}) if "args" in kwargs else kwargs
            result = await self.execute(spec.id, args)
            return ToolResult(
                success=result.get("success", False),
                output=result.get("output", ""),
                error=result.get("error", ""),
                metadata={"skill_id": spec.id, "skill_type": spec.type.value},
            )

        self._tool_registry.register(tool_spec, _handler)
        logger.debug(f"Registered skill as tool: {tool_name}")

    def _unregister_skill_as_tool(self, skill_id: str) -> None:
        if self._tool_registry:
            self._tool_registry.unregister(self._skill_id_to_tool_name(skill_id))
            logger.debug(f"Unregistered skill tool: {self._skill_id_to_tool_name(skill_id)}")

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def _load_all(self) -> None:
        """Load builtin + installed skills. Hermes skills loaded separately."""
        # 1. Builtin skills (shipped with agent)
        if self.BUILTIN_DIR.exists():
            self._scan_directory(self.BUILTIN_DIR, trust_override=TrustLevel.BUILTIN)

        # 2. User-installed skills
        self._scan_directory(self.skills_dir)

        logger.info(f"Loaded {len(self._skills)} native skills")

    def load_hermes_sync(self) -> None:
        """Synchronously load Hermes skills (for CLI/non-async contexts)."""
        self._load_hermes_skills()

    async def load_hermes_async(self) -> None:
        """Asynchronously load Hermes skills in a background thread."""
        import asyncio

        await asyncio.to_thread(self._load_hermes_skills)

    def _load_hermes_skills(self) -> None:
        """Load skills from the Hermes skills directory (~/.hermes/skills/).

        This enables JS Agent to use all skills already installed by
        OpenClaw Hermes without any migration or re-installation.
        """
        from js.skills.hermes_bridge import HERMES_SKILLS_DIR

        if not HERMES_SKILLS_DIR.exists():
            logger.debug("Hermes skills directory not found, skipping Hermes bridge")
            return

        stats = get_bridge_stats()
        stats.failed_loads = 0
        stats.total_loaded = 0
        stats.prompt_count = 0
        stats.code_count = 0

        try:
            manifests = discover_hermes_skills(HERMES_SKILLS_DIR)
            for manifest in manifests:
                try:
                    spec = load_hermes_skill(manifest)

                    # Skip if a JS Agent skill with the same ID already exists
                    if spec.id in self._skills:
                        logger.debug(
                            f"Skipping Hermes skill {spec.id}: ID conflict with existing skill"
                        )
                        continue

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

                    self._skills[spec.id] = spec
                    stats.total_loaded += 1
                    if spec.type == SkillType.PROMPT:
                        stats.prompt_count += 1
                    elif spec.type == SkillType.CODE:
                        stats.code_count += 1

                    # Auto-register as tool if registry is available
                    self._register_skill_as_tool(spec)
                except Exception as e:
                    stats.failed_loads += 1
                    logger.warning(f"Failed to load Hermes skill from {manifest}: {e}")

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
        from js.skills.hermes_bridge import HERMES_SKILLS_DIR

        if not HERMES_SKILLS_DIR.exists():
            return {"success": False, "error": "Hermes skills directory not found"}

        # 1. Remove all existing Hermes skills
        hermes_ids = [sid for sid in self._skills if sid.startswith("hermes:")]
        for sid in hermes_ids:
            del self._skills[sid]
            self._unregister_skill_as_tool(sid)

        # 2. Re-load from disk
        self._load_hermes_skills()

        stats = get_bridge_stats()
        return {
            "success": True,
            "reloaded": stats.total_loaded,
            "failed": stats.failed_loads,
            "total_hermes": sum(1 for s in self._skills.values() if s.id.startswith("hermes:")),
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
        for spec in self._skills.values():
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
        return self._skills.get(skill_id)

    def get_all(self) -> dict[str, SkillSpec]:
        """Return all loaded skills."""
        return dict(self._skills)

    # ------------------------------------------------------------------
    # Categories & Discovery
    # ------------------------------------------------------------------

    def list_categories(self) -> list[dict[str, Any]]:
        """Return all categories with skill counts."""
        from collections import Counter

        cats = Counter(s.category for s in self._skills.values())
        return [{"name": name, "count": count} for name, count in sorted(cats.items())]

    def search_skills(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """Full-text search across name, description, tags, and category."""
        return self.list_skills(query=query)[:limit]

    def check_prerequisites(self, skill_id: str) -> tuple[bool, list[str]]:
        """Check if a skill's prerequisites are satisfied."""
        spec = self._skills.get(skill_id)
        if not spec:
            return False, ["Skill not found"]
        return spec.prerequisites.check()

    # ------------------------------------------------------------------
    # Installation
    # ------------------------------------------------------------------

    # Allowed git host domains for skill installation.
    _SKILL_SOURCE_ALLOWLIST: frozenset[str] = frozenset(
        {
            "github.com",
            "gitlab.com",
            "bitbucket.org",
            "gitee.com",
            "codeberg.org",
        }
    )

    def _validate_skill_source(self, source: str) -> None:
        """Validate that a skill source URL is from an allowed domain.

        Raises ValueError for disallowed sources.
        """
        if source.startswith("http") or source.startswith("git@"):
            from urllib.parse import urlparse

            parsed = urlparse(source.replace("git@", "https://"))
            hostname = parsed.hostname or ""
            if hostname not in self._SKILL_SOURCE_ALLOWLIST:
                raise ValueError(
                    f"Skill source domain not allowed: {hostname}. "
                    f"Allowed: {', '.join(sorted(self._SKILL_SOURCE_ALLOWLIST))}"
                )
        elif not Path(source).exists():
            raise ValueError(f"Unknown skill source: {source}")

    async def install(
        self, source: str, skill_id: str | None = None, expected_hash: str | None = None
    ) -> SkillSpec:
        """Install a skill from git repo or local path.

        New skills enter quarantine until explicitly trusted.
        If expected_hash is provided, the skill contents are verified against it.
        """
        self._validate_skill_source(source)

        target_id = skill_id or Path(source).name
        # Sanitize target_id to prevent path traversal
        target_id = Path(target_id).name
        if not target_id or target_id in (".", ".."):
            raise ValueError(f"Invalid skill ID: {skill_id or Path(source).name}")
        # Validate ID format (same rules as plugins)
        import re

        if not re.match(r"^[a-z0-9_-]+$", target_id) or len(target_id) > 64:
            raise ValueError(
                f"Invalid skill ID: {target_id!r}. "
                f"Allowed: lowercase letters, digits, hyphens, underscores, max 64 chars."
            )
        target_dir = self.skills_dir / target_id
        # Ensure target_dir is inside skills_dir
        try:
            target_dir.resolve().relative_to(self.skills_dir.resolve())
        except ValueError as e:
            raise ValueError(f"Skill ID escapes skills directory: {target_id}") from e
        if target_dir.exists():
            await asyncio.to_thread(shutil.rmtree, target_dir)

        if source.startswith("http") or source.startswith("git@"):
            proc = await asyncio.create_subprocess_exec(
                "git",
                "clone",
                "--depth",
                "1",
                source,
                str(target_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(f"git clone failed: {stderr.decode()}")
        elif Path(source).exists():
            if Path(source).is_dir():
                # copytree with symlink rejection
                def _safe_copytree(src: str, dst: str) -> None:
                    shutil.copytree(src, dst, symlinks=False)

                await asyncio.to_thread(_safe_copytree, str(source), str(target_dir))
            else:
                target_dir.mkdir(parents=True, exist_ok=True)
                await asyncio.to_thread(shutil.copy2, source, target_dir)
        else:
            raise ValueError(f"Unknown skill source: {source}")

        # Reject any symlinks that may have been created
        for item in target_dir.rglob("*"):
            if item.is_symlink():
                raise RuntimeError(f"Skill contains symlinks: {item.relative_to(target_dir)}")

        # Parse and scan
        manifest = target_dir / self.SKILL_MANIFEST
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
"""
            )

        spec = parse_skill_manifest(manifest)
        spec.path = target_dir

        # Hash verification
        if expected_hash:
            actual_hash = spec.compute_hash()
            if actual_hash.lower() != expected_hash.lower():
                await asyncio.to_thread(shutil.rmtree, target_dir, ignore_errors=True)
                raise ValueError(
                    f"Skill hash mismatch for {spec.id}: expected {expected_hash}, got {actual_hash}"
                )

        # --- OpenClaw / Hermes type inference ---
        # If the manifest did not explicitly declare a type, infer from directory contents.
        # OpenClaw skills default to prompt unless they ship executable scripts.
        has_explicit_type = False
        try:
            import re as _re

            import yaml

            text = manifest.read_text(encoding="utf-8")
            # Try YAML frontmatter format first (---\n...\n---\n)
            match = _re.match(r"^---\s*\n(.*?)\n---\s*\n", text, _re.DOTALL)
            if match:
                frontmatter = yaml.safe_load(match.group(1)) or {}
            else:
                # Fall back to plain YAML (JS Agent native format)
                frontmatter = yaml.safe_load(text) or {}
            has_explicit_type = "type" in frontmatter
        except Exception:
            logger.warning("Operation failed", exc_info=True)
        if not has_explicit_type:
            has_scripts = (target_dir / "scripts").exists() and any(
                (target_dir / "scripts").iterdir()
            )
            if not has_scripts:
                spec.type = SkillType.PROMPT
                logger.debug(f"Inferred type=prompt for {spec.id} (no scripts/ dir)")

        # New installs start in quarantine
        result = scan_skill(spec)
        spec.risk_flags = result.risk_flags
        spec.trust_level = result.trust_level
        self._save_scan_cache(result)

        self._skills[spec.id] = spec

        # Install pip dependencies into a skill-local venv if present
        req_file = target_dir / "requirements.txt"
        if req_file.exists():
            # Safety: reject requirements with git URLs or local paths
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
                    raise ValueError(f"Blocked unsafe requirement in {spec.id}: {stripped[:80]}")
            venv_dir = target_dir / ".venv"
            pip_cmd = [sys.executable, "-m", "pip"]
            if not venv_dir.exists():
                # Create isolated venv for this skill
                venv_proc = await asyncio.create_subprocess_exec(
                    sys.executable,
                    "-m",
                    "venv",
                    str(venv_dir),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(venv_proc.communicate(), timeout=120)
                pip_cmd = [str(venv_dir / "bin" / "python"), "-m", "pip"]
                if sys.platform == "win32":
                    pip_cmd = [str(venv_dir / "Scripts" / "python.exe"), "-m", "pip"]
            else:
                pip_cmd = [str(venv_dir / "bin" / "python"), "-m", "pip"]
                if sys.platform == "win32":
                    pip_cmd = [str(venv_dir / "Scripts" / "python.exe"), "-m", "pip"]
            proc = await asyncio.create_subprocess_exec(
                *pip_cmd,
                "install",
                "-r",
                str(req_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)

        logger.info(f"Installed skill: {spec.id} (trust={spec.trust_level.value})")
        self._register_skill_as_tool(spec)
        return spec

    async def uninstall(self, skill_id: str) -> bool:
        if skill_id not in self._skills:
            return False
        spec = self._skills.pop(skill_id)
        if spec.path and spec.path.exists() and not self._is_builtin(spec):
            await asyncio.to_thread(shutil.rmtree, spec.path)
        self._unregister_skill_as_tool(skill_id)
        logger.info(f"Uninstalled skill: {skill_id}")
        return True

    def trust_skill(self, skill_id: str, level: TrustLevel) -> bool:
        """Manually override a skill's trust level after review.

        v0.1.4-alpha PR-1.5 hardening: trust transitions also flip tool
        exposure. Upgrading out of QUARANTINE (operator approve) registers
        the skill as a callable tool; downgrading back to QUARANTINE
        unregisters it. All other transitions are a no-op for the registry
        because the skill was already exposed.
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
        return True

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
    ) -> dict[str, Any]:
        """Execute a skill with full lifecycle tracking."""

        start = time.time()
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
            dep_results = await self._execute_dependencies(spec, args, llm_caller)
            if not all(r.get("success", False) for r in dep_results):
                return {
                    "success": False,
                    "error": f"Meta skill dependency failed for {skill_id}",
                    "dependencies": dep_results,
                }

        # Execute
        try:
            exec_result: dict[str, Any] = await execute_skill(
                spec, args, self.workspace, llm_caller, self._sandbox, self.execute
            )
        except Exception as e:
            exec_result = {"success": False, "error": str(e)}

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

        return exec_result

    async def _execute_dependencies(
        self,
        spec: SkillSpec,
        args: dict[str, Any],
        llm_caller: LLMCaller | None,
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
            result = await execute_skill(
                dep_spec, args, self.workspace, llm_caller, self._sandbox, self.execute
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

        return {
            "skills_used": total,
            "total_executions": executions,
            "overall_success_rate": (success / executions) if executions else 1.0,
            "avg_latency_ms": avg_lat or 0.0,
            "skills_loaded": len(self._skills),
            "builtin_count": sum(
                1 for s in self._skills.values() if s.trust_level == TrustLevel.BUILTIN
            ),
            "quarantined_count": sum(
                1 for s in self._skills.values() if s.trust_level == TrustLevel.QUARANTINE
            ),
        }
