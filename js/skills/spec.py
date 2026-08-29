"""Unified skill specification supporting code, prompt, and workflow types."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class SkillType(StrEnum):
    CODE = "code"  # Executable Python/Shell (JS Agent original)
    PROMPT = "prompt"  # LLM instruction doc (Hermes-style)
    WORKFLOW = "workflow"  # Lightweight automation chain
    META = "meta"  # Composed of sub-skills (dependency DAG)


class TrustLevel(StrEnum):
    BUILTIN = "builtin"  # Shipped with JS Agent, signed
    TRUSTED = "trusted"  # Installed from trusted source, scanned
    COMMUNITY = "community"  # User-installed, scanned
    QUARANTINE = "quarantine"  # Pending security review

    @property
    def color(self) -> str:
        """UI color for this trust level."""
        return {
            TrustLevel.BUILTIN: "green",
            TrustLevel.TRUSTED: "blue",
            TrustLevel.COMMUNITY: "yellow",
            TrustLevel.QUARANTINE: "red",
        }.get(self, "gray")

    @property
    def css_classes(self) -> str:
        """Tailwind CSS classes for badges."""
        return {
            TrustLevel.BUILTIN: "bg-green-900 text-green-400",
            TrustLevel.TRUSTED: "bg-blue-900 text-blue-400",
            TrustLevel.COMMUNITY: "bg-yellow-900 text-yellow-400",
            TrustLevel.QUARANTINE: "bg-red-900 text-red-400",
        }.get(self, "bg-gray-800 text-gray-400")


@dataclass
class Prerequisites:
    """Runtime requirements for a skill."""

    commands: list[str] = field(default_factory=list)
    env_vars: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)

    def check(self) -> tuple[bool, list[str]]:
        """Check if all prerequisites are satisfied. Returns (ok, missing)."""
        missing: list[str] = []

        import shutil

        for cmd in self.commands:
            if shutil.which(cmd) is None:
                missing.append(f"command: {cmd}")

        import os

        for env in self.env_vars:
            if not os.getenv(env):
                missing.append(f"env_var: {env}")

        # packages check is advisory (pip list is slow)
        return len(missing) == 0, missing


# Directories excluded from integrity hashing: volatile environments, caches,
# and VCS metadata must not affect the skill content hash.
HASH_EXCLUDED_DIRS = frozenset({".venv", "__pycache__", ".git"})


def compute_skill_dir_hash(skill_dir: Path) -> str:
    """Compute a SHA-256 hash over the full content of a skill directory.

    Every regular file is hashed (contents only) in stable sorted order of
    its relative POSIX path — including subdirectories such as lib/,
    references/, templates/ and assets/. Symlinks, non-regular files, and
    volatile directories (see HASH_EXCLUDED_DIRS) are skipped.

    This is the single source of truth for skill content hashing:
    ``SkillSpec.compute_hash`` and ``js.security.signer`` manifest signatures
    both delegate to it so their coverage can never drift apart.
    """
    import hashlib
    import os

    h = hashlib.sha256()
    entries: list[tuple[str, Path]] = []
    for root, dirnames, filenames in os.walk(skill_dir, followlinks=False):
        root_path = Path(root)
        # Prune excluded directories in place so os.walk never descends into
        # them (a skill-local .venv alone can contain thousands of files).
        dirnames[:] = sorted(d for d in dirnames if d not in HASH_EXCLUDED_DIRS)
        for name in filenames:
            f = root_path / name
            if f.is_symlink() or not f.is_file():
                continue
            entries.append((f.relative_to(skill_dir).as_posix(), f))
    for _rel, f in sorted(entries, key=lambda e: e[0]):
        h.update(f.read_bytes())
    return h.hexdigest()


@dataclass
class SkillSpec:
    """Unified skill specification.

    Compatible with both Hermes-style prompt skills and JS-style code skills.
    """

    # Core identity
    id: str
    name: str
    description: str = ""
    version: str = "0.1.0"
    author: str = "unknown"
    license: str = "MIT"

    # Type & execution
    type: SkillType = SkillType.CODE
    entry: str = "main.py"  # For CODE type: executable file

    # Categorization (Hermes-style)
    category: str = "general"
    tags: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)  # macos, linux, windows

    # Trust & security (OpenClaw-inspired)
    trust_level: TrustLevel = TrustLevel.COMMUNITY
    risk_flags: list[str] = field(default_factory=list)
    content_hash: str = ""
    # Ed25519 cryptographic signature and public key (base64-encoded).
    # When present, these override self-declared trust fields.
    signature: str = ""
    public_key: str = ""

    # Runtime requirements (Hermes-style)
    prerequisites: Prerequisites = field(default_factory=Prerequisites)

    # Execution safety (Phase 5)
    timeout_seconds: int = 30  # Default timeout for code execution
    network_allowed: bool = True  # Whether skill can access network

    # Skill composition (Phase 4)
    dependencies: list[str] = field(default_factory=list)  # IDs of required sub-skills

    # Content (for PROMPT type)
    full_content: str = ""  # Loaded on demand via view_skill()
    metadata: dict[str, Any] = field(default_factory=dict)

    # Paths
    path: Path | None = None
    references_dir: Path | None = None
    templates_dir: Path | None = None
    assets_dir: Path | None = None

    # Usage stats
    usage_count: int = 0
    success_rate: float = 1.0
    avg_latency_ms: float = 0.0

    def is_compatible(self) -> bool:
        """Check if skill is compatible with current platform."""
        if not self.platforms:
            return True
        current = sys.platform
        mapping = {"macos": "darwin", "linux": "linux", "windows": "win32"}
        return any(mapping.get(p, p) == current for p in self.platforms)

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of all skill files (manifest + code + resources).

        Covers every regular file under the skill directory recursively via
        ``compute_skill_dir_hash`` — a change to lib/, references/ or any
        other shipped file therefore invalidates the stored integrity hash.
        """
        if not self.path:
            return ""
        # 128-bit truncation: still ample collision resistance for integrity checks
        return compute_skill_dir_hash(self.path)[:32]

    def to_summary_dict(self) -> dict[str, Any]:
        """Return minimal metadata for list_skills() — progressive disclosure."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "type": self.type.value,
            "category": self.category,
            "tags": self.tags,
            "trust_level": self.trust_level.value,
            "trust_color": self.trust_level.color,
            "trust_css": self.trust_level.css_classes,
            "risk_flags": self.risk_flags,
            "platforms": self.platforms,
            "compatible": self.is_compatible(),
            "prerequisites_ok": self.prerequisites.check()[0],
            "usage_count": self.usage_count,
            "success_rate": self.success_rate,
        }

    def to_detail_dict(self) -> dict[str, Any]:
        """Return full metadata for view_skill()."""
        data = self.to_summary_dict()
        data.update(
            {
                "license": self.license,
                "entry": self.entry,
                "content_length": len(self.full_content),
                "metadata": self.metadata,
                "has_references": self.references_dir is not None and self.references_dir.exists(),
                "has_templates": self.templates_dir is not None and self.templates_dir.exists(),
                "has_assets": self.assets_dir is not None and self.assets_dir.exists(),
                "timeout_seconds": self.timeout_seconds,
                "network_allowed": self.network_allowed,
                "dependencies": self.dependencies,
            }
        )
        return data


def parse_skill_manifest(path: Path) -> SkillSpec:
    """Parse a SKILL.md file into SkillSpec.

    Supports both Hermes format (YAML frontmatter + Markdown body)
    and JS Agent format (plain YAML).
    """
    import yaml

    text = path.read_text(encoding="utf-8")

    # Try YAML frontmatter (Hermes style): ---\n...\n---\n
    frontmatter: dict[str, Any] = {}
    body = ""
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", text, re.DOTALL)
    if match:
        try:
            frontmatter = yaml.safe_load(match.group(1)) or {}
        except yaml.YAMLError:
            frontmatter = {}
        body = match.group(2).strip()
    else:
        # Plain YAML (JS Agent original style)
        try:
            frontmatter = yaml.safe_load(text) or {}
        except yaml.YAMLError:
            frontmatter = {}

    # Normalize type
    raw_type = frontmatter.get("type", "code")
    try:
        skill_type = SkillType(raw_type.lower())
    except ValueError:
        skill_type = SkillType.CODE

    # Normalize trust level
    raw_trust = frontmatter.get("trust_level", "community")
    try:
        trust = TrustLevel(raw_trust.lower())
    except ValueError:
        trust = TrustLevel.COMMUNITY

    # Parse prerequisites (Hermes style)
    prereq_data = frontmatter.get("prerequisites", {})
    if isinstance(prereq_data, dict):
        prereqs = Prerequisites(
            commands=prereq_data.get("commands", []),
            env_vars=prereq_data.get("env_vars", []),
            packages=prereq_data.get("packages", []),
        )
    else:
        prereqs = Prerequisites()

    # Handle legacy JS Agent fields
    if "dependencies" in frontmatter and not prereqs.packages:
        prereqs.packages = frontmatter.get("dependencies", [])

    # Parse execution safety config
    exec_config = frontmatter.get("execution", {})
    if isinstance(exec_config, dict):
        timeout = exec_config.get("timeout_seconds", 30)
        network_allowed = exec_config.get("network_allowed", True)
    else:
        timeout = 30
        network_allowed = True

    # Parse skill dependencies for composition
    skill_deps = frontmatter.get("skill_dependencies", [])
    if isinstance(skill_deps, list):
        dependencies = [str(d) for d in skill_deps]
    else:
        dependencies = []

    spec = SkillSpec(
        id=frontmatter.get("id", path.parent.name),
        name=frontmatter.get("name", path.parent.name),
        description=frontmatter.get("description", ""),
        version=frontmatter.get("version", "0.1.0"),
        author=frontmatter.get("author", "unknown"),
        license=frontmatter.get("license", "MIT"),
        type=skill_type,
        entry=frontmatter.get("entry", "main.py"),
        category=frontmatter.get("category", "general"),
        tags=frontmatter.get("tags", []),
        platforms=[p.lower() for p in frontmatter.get("platforms", [])],
        trust_level=trust,
        prerequisites=prereqs,
        timeout_seconds=timeout,
        network_allowed=network_allowed,
        dependencies=dependencies,
        full_content=body,
        metadata=frontmatter.get("metadata", {}),
        path=path.parent,
        signature=str(frontmatter.get("signature") or ""),
        public_key=str(frontmatter.get("public_key") or ""),
    )

    # Set sub-directories (Hermes style)
    if spec.path:
        spec.references_dir = spec.path / "references"
        spec.templates_dir = spec.path / "templates"
        spec.assets_dir = spec.path / "assets"

    spec.content_hash = spec.compute_hash()
    return spec
