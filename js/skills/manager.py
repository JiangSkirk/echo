"""Next-generation skill manager: code + prompt + workflow with security & discovery."""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from js.security.sandbox import SandboxExecutor
from js.skills.executor import execute_skill
from js.skills.security import ScanResult, scan_skill, verify_integrity
from js.skills.spec import (
    SkillSpec,
    SkillType,
    TrustLevel,
    parse_skill_manifest,
)
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

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def _load_all(self) -> None:
        """Load builtin + installed skills."""
        # 1. Builtin skills (shipped with agent)
        if self.BUILTIN_DIR.exists():
            self._scan_directory(self.BUILTIN_DIR, trust_override=TrustLevel.BUILTIN)

        # 2. User-installed skills
        self._scan_directory(self.skills_dir)

        logger.info(f"Loaded {len(self._skills)} skills")

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
                (result.skill_id, result.content_hash, json.dumps(result.risk_flags), result.trust_level.value),
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
            if trust_min is not None and self._TRUST_ORDER.get(spec.trust_level, 99) > self._TRUST_ORDER.get(trust_min, 99):
                continue
            if only_compatible and not spec.is_compatible():
                continue
            if query and query.lower() not in f"{spec.name} {spec.description} {' '.join(spec.tags)}".lower():
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
                    pass

        # Load references
        references: dict[str, str] = {}
        if spec.references_dir and spec.references_dir.exists():
            for ref_file in sorted(spec.references_dir.iterdir()):
                if ref_file.is_file():
                    try:
                        references[ref_file.name] = ref_file.read_text()
                    except Exception:
                        pass

        # Load templates
        templates: dict[str, str] = {}
        if spec.templates_dir and spec.templates_dir.exists():
            for tmpl_file in sorted(spec.templates_dir.iterdir()):
                if tmpl_file.is_file():
                    try:
                        templates[tmpl_file.name] = tmpl_file.read_text()
                    except Exception:
                        pass

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

    async def install(self, source: str, skill_id: str | None = None) -> SkillSpec:
        """Install a skill from git repo or local path.

        New skills enter quarantine until explicitly trusted.
        """
        import asyncio

        target_id = skill_id or Path(source).name
        # Sanitize target_id to prevent path traversal
        target_id = Path(target_id).name
        if not target_id or target_id in (".", ".."):
            raise ValueError(f"Invalid skill ID: {skill_id or Path(source).name}")
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
                "git", "clone", "--depth", "1", source, str(target_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(f"git clone failed: {stderr.decode()}")
        elif Path(source).exists():
            if Path(source).is_dir():
                await asyncio.to_thread(shutil.copytree, source, target_dir)
            else:
                target_dir.mkdir(parents=True, exist_ok=True)
                await asyncio.to_thread(shutil.copy2, source, target_dir)
        else:
            raise ValueError(f"Unknown skill source: {source}")

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

        # New installs start in quarantine
        result = scan_skill(spec)
        spec.risk_flags = result.risk_flags
        spec.trust_level = result.trust_level
        self._save_scan_cache(result)

        self._skills[spec.id] = spec

        # Install pip dependencies if present
        req_file = target_dir / "requirements.txt"
        if req_file.exists():
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "pip", "install", "-r", str(req_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)

        logger.info(f"Installed skill: {spec.id} (trust={spec.trust_level.value})")
        return spec

    async def uninstall(self, skill_id: str) -> bool:
        if skill_id not in self._skills:
            return False
        spec = self._skills.pop(skill_id)
        if spec.path and spec.path.exists() and not self._is_builtin(spec):
            await asyncio.to_thread(shutil.rmtree, spec.path)
        logger.info(f"Uninstalled skill: {skill_id}")
        return True

    def trust_skill(self, skill_id: str, level: TrustLevel) -> bool:
        """Manually override a skill's trust level after review."""
        spec = self._skills.get(skill_id)
        if not spec:
            return False
        spec.trust_level = level
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
    ) -> dict[str, Any]:
        """Execute a skill with full lifecycle tracking."""

        start = time.time()
        spec = self._skills.get(skill_id)
        if not spec:
            return {"success": False, "error": f"Skill not found: {skill_id}"}

        # Security checks
        if spec.trust_level == TrustLevel.QUARANTINE:
            return {"success": False, "error": f"Skill {skill_id} is quarantined. Run 'trust' to review."}

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
                spec, args, self.workspace, llm_caller, self._sandbox
            )
        except Exception as e:
            exec_result = {"success": False, "error": str(e)}

        latency = (time.time() - start) * 1000
        self._record_usage(skill_id, spec.type.value, exec_result.get("success", False), latency)

        # Record composition chain for learning
        self._record_chain(skill_id, exec_result.get("success", False))

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
            result = await execute_skill(dep_spec, args, self.workspace, llm_caller, self._sandbox)
            return result

        for dep_id in spec.dependencies:
            result = await execute_dep(dep_id)
            if result:
                results.append(result)
                if not result.get("success", False):
                    break  # Stop on first failure

        return results

    def _record_usage(self, skill_id: str, skill_type: str, success: bool, latency_ms: float) -> None:
        with db_connection(self.db_path) as conn:
            conn.execute(
                "INSERT INTO skill_usage (skill_id, skill_type, success, latency_ms) VALUES (?, ?, ?, ?)",
                (skill_id, skill_type, int(success), latency_ms),
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

    def _record_chain(self, skill_id: str, success: bool) -> None:
        """Record skill execution for composition chain discovery."""
        # Simple: just track that this skill was executed
        # Chain discovery happens in batch via metacognition
        pass

    # ------------------------------------------------------------------
    # Composition Chain Discovery
    # ------------------------------------------------------------------

    def record_skill_transition(self, from_skill: str, to_skill: str) -> None:
        """Record that one skill was followed by another."""
        with db_connection(self.db_path) as conn:
            existing = conn.execute(
                "SELECT frequency FROM skill_composition_chains WHERE from_skill = ? AND to_skill = ?",
                (from_skill, to_skill),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE skill_composition_chains SET frequency = frequency + 1, last_seen = ? WHERE from_skill = ? AND to_skill = ?",
                    (time.time(), from_skill, to_skill),
                )
            else:
                conn.execute(
                    "INSERT INTO skill_composition_chains (from_skill, to_skill, last_seen) VALUES (?, ?, ?)",
                    (from_skill, to_skill, time.time()),
                )
            conn.commit()

    def get_common_chains(self, min_frequency: int = 3) -> list[dict[str, Any]]:
        """Discover commonly used skill chains from execution history."""
        with db_connection(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT from_skill, to_skill, frequency
                FROM skill_composition_chains
                WHERE frequency >= ?
                ORDER BY frequency DESC
                """,
                (min_frequency,),
            ).fetchall()
        return [
            {"from": r[0], "to": r[1], "frequency": r[2]}
            for r in rows
        ]

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
            "builtin_count": sum(1 for s in self._skills.values() if s.trust_level == TrustLevel.BUILTIN),
            "quarantined_count": sum(1 for s in self._skills.values() if s.trust_level == TrustLevel.QUARANTINE),
        }
