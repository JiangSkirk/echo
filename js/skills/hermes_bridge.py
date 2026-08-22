"""Hermes Skill Bridge — Seamlessly load and execute Hermes-format skills in JS Agent.

This module bridges the OpenClaw Hermes skill ecosystem with the JS Agent skill
system. It discovers skills installed in the Hermes skills directory
(~/.hermes/skills/), converts them to JS Agent SkillSpec objects, and enables
full execution through the unified executor.

Key mappings:
  - Hermes name → JS skill id (with "hermes:" prefix to avoid conflicts)
  - Hermes metadata.hermes.tags → JS tags
  - Hermes metadata.hermes.related_skills → JS dependencies
  - Hermes prerequisites.commands → JS prerequisites
  - Hermes platforms → JS platforms
  - Hermes references/ templates/ scripts/ assets/ → JS sub-directories
  - No explicit type → inferred PROMPT (or CODE if scripts/ dir exists)
  - Installed skills → TRUSTED trust level

Security:
  - All Hermes skills are scanned via JS Agent's scan_skill() on first load
  - Quarantine/block logic identical to native JS skills
  - Content hash verification on every execute()
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from js.skills.security import ScanResult, scan_skill
from js.skills.spec import (
    SkillSpec,
    SkillType,
    TrustLevel,
    parse_skill_manifest,
)
from js.utils.log import get_logger

logger = get_logger("js.skills.hermes_bridge")

# Default Hermes home directory
DEFAULT_HERMES_HOME = Path.home() / ".hermes"
HERMES_SKILLS_DIR = DEFAULT_HERMES_HOME / "skills"
HERMES_HUB_LOCK = HERMES_SKILLS_DIR / ".hub" / "lock.json"

# Prefix to namespace Hermes skills and avoid ID collisions
HERMES_ID_PREFIX = "hermes:"


def _get_hermes_home() -> Path:
    """Return the Hermes home directory from env or default.

    Security: reject env values that escape the user's home directory.
    Resolved at call time so isolated HOME / tests are honored.
    """
    home = Path.home().resolve()
    env_home = os.environ.get("HERMES_HOME")
    if env_home:
        candidate = Path(env_home).resolve()
        if candidate != home and not str(candidate).startswith(str(home) + os.sep):
            logger.warning(f"HERMES_HOME {candidate} is outside home directory, using default")
            return home / ".hermes"
        return candidate
    return home / ".hermes"


def hermes_skills_dir() -> Path:
    """Return the Hermes skills directory resolved at call time."""
    return _get_hermes_home() / "skills"


def _load_hub_lock() -> dict[str, Any]:
    """Load the Hermes hub lock file if it exists."""
    lock_path = _get_hermes_home() / "skills" / ".hub" / "lock.json"
    if lock_path.exists():
        try:
            data: dict[str, Any] = json.loads(lock_path.read_text())
            return data
        except (json.JSONDecodeError, OSError):
            logger.warning("Operation failed", exc_info=True)
    return {}


def _resolve_trust_level(skill_name: str, lock_data: dict[str, Any]) -> TrustLevel:
    """Determine trust level for a Hermes skill.

    The hub lock file (~/.hermes/skills/.hub/lock.json) is an unsigned JSON
    file — it carries no cryptographic proof of authorship.  We therefore cap
    the maximum trust derivable from it at TRUSTED.  Skills not explicitly
    vetted by the lock file default to COMMUNITY.
    """
    entries = lock_data.get("skills", {})
    entry = entries.get(skill_name)
    if entry:
        source = entry.get("source", "").lower()
        # Lock file is unsigned — never grant BUILTIN from it.  Cap at TRUSTED.
        if source in ("builtin", "trusted"):
            return TrustLevel.TRUSTED
        # Unknown source — requires the skill to pass a security scan
        return TrustLevel.COMMUNITY

    # Not in lock file at all — unknown provenance
    return TrustLevel.COMMUNITY


def _infer_skill_type(spec: SkillSpec) -> SkillType:
    """Infer JS Agent skill type from Hermes skill structure.

    Hermes has no explicit type field. We infer:
      - If scripts/ dir has executable files → CODE
      - Otherwise → PROMPT (the Hermes default)
    """
    if spec.path:
        scripts_dir = spec.path / "scripts"
        if scripts_dir.exists() and scripts_dir.is_dir():
            for f in scripts_dir.iterdir():
                if f.is_file() and (f.suffix in (".py", ".sh", ".bash")):
                    # Upgrade to CODE type, set entry to first script found
                    spec.entry = f"scripts/{f.name}"
                    return SkillType.CODE
    return SkillType.PROMPT


def _infer_parameters_from_script(script_path: Path) -> list[dict[str, Any]]:
    """Scan a Python script for argparse definitions and build parameter schema.

    Uses simple regex-based scanning to extract --argument names, types,
    defaults, and help text. Falls back to generic schema if parsing fails.
    """
    import re

    if not script_path.exists():
        return []

    try:
        content = script_path.read_text(errors="ignore")
    except OSError:
        return []

    params: list[dict[str, Any]] = []

    # Pattern 1: argparse add_argument calls
    # Matches: parser.add_argument("--name", ..., help="...", default=...)
    add_arg_pattern = re.compile(
        r"add_argument\(\s*"
        r'["\']((?:--|-)[\w-]+)["\']\s*'
        r"(.*?)\)",
        re.DOTALL,
    )

    for match in add_arg_pattern.finditer(content):
        flag = match.group(1)
        arg_body = match.group(2)

        # Skip short flags (just -x) — we'll capture the long form
        if not flag.startswith("--"):
            continue

        param_name = flag.lstrip("-").replace("-", "_")

        # Detect type
        arg_type = "string"
        if "type=int" in arg_body or "type=\nint" in arg_body:
            arg_type = "integer"
        elif "type=float" in arg_body:
            arg_type = "number"
        elif "type=bool" in arg_body:
            arg_type = "boolean"

        # Detect action=store_true → boolean flag
        is_flag = "store_true" in arg_body or "store_false" in arg_body
        if is_flag:
            arg_type = "boolean"

        # Detect default
        default_match = re.search(r"default\s*=\s*([^,\)]+)", arg_body)
        default = None
        if default_match:
            default_str = default_match.group(1).strip()
            if default_str.startswith(("'", '"')):
                default = default_str.strip("\"'")
            elif default_str == "True":
                default = True
            elif default_str == "False":
                default = False
            elif default_str.isdigit():
                default = int(default_str)

        # Detect help text
        help_match = re.search(r'help\s*=\s*["\']([^"\']+)["\']', arg_body)
        description = help_match.group(1) if help_match else f"{param_name} parameter"

        # Detect choices/enum
        choices_match = re.search(r"choices\s*=\s*\[([^\]]+)\]", arg_body)
        enum = None
        if choices_match:
            choices_str = choices_match.group(1)
            enum = [c.strip().strip("\"'") for c in choices_str.split(",")]

        param: dict[str, Any] = {
            "name": param_name,
            "type": arg_type,
            "description": description,
            "required": default is None and not is_flag,
        }
        if default is not None:
            param["default"] = default
        if enum:
            param["enum"] = enum

        params.append(param)

    # Pattern 2: manual sys.argv parsing (positionals)
    # Look for common patterns like: unpacked_dir = Path(sys.argv[1])
    positional_pattern = re.compile(
        r"(\w+)\s*=\s*(?:Path\()?sys\.argv\[(\d+)\]",
    )
    for match in positional_pattern.finditer(content):
        var_name = match.group(1)
        idx = int(match.group(2))
        if idx >= 1 and not any(p["name"] == var_name for p in params):
            params.insert(
                0,
                {
                    "name": var_name,
                    "type": "string",
                    "description": f"{var_name} (positional argument)",
                    "required": idx == 1,  # First positional is usually required
                },
            )

    # Pattern 3: manual flag parsing (while loop over args)
    # Matches: if args[i] == "--flag" and i + 1 < len(args): var = args[i + 1]; i += 2
    manual_flag_pattern = re.compile(
        r'(?:if|elif)\s+args\[i\]\s*==\s*["\'](--[\w-]+)["\']\s+and\s+i\s*\+\s*1\s*<\s*len\(args\):\s*\n\s+(\w+)\s*=\s*',
        re.MULTILINE,
    )
    for match in manual_flag_pattern.finditer(content):
        flag = match.group(1)
        var_name = match.group(2)
        param_name = flag.lstrip("-").replace("-", "_")
        if not any(p["name"] == param_name for p in params):
            # Detect int() cast from the same line
            line_end = content[match.end() : match.end() + 50]
            arg_type = "integer" if "int(" in line_end else "string"
            params.append(
                {
                    "name": param_name,
                    "type": arg_type,
                    "description": f"{param_name} parameter",
                    "required": False,
                }
            )

    # Pattern 4: manual positional args in while/loop
    # Matches: positional.append(args[i]) followed by query = " ".join(positional)
    positional_collect_pattern = re.compile(
        r"(\w+)\.append\(args\[i\]\)",
    )
    for match in positional_collect_pattern.finditer(content):
        list_name = match.group(1)
        # Find what variable this list gets joined into
        join_pattern = re.compile(
            rf'(\w+)\s*=\s*["\']\s*["\']\.join\({list_name}\)',
        )
        for jm in join_pattern.finditer(content):
            var_name = jm.group(1)
            if not any(p["name"] == var_name for p in params):
                params.insert(
                    0,
                    {
                        "name": var_name,
                        "type": "string",
                        "description": f"{var_name} (positional argument)",
                        "required": False,
                    },
                )

    return params


def _post_process_hermes_spec(spec: SkillSpec, lock_data: dict[str, Any]) -> SkillSpec:
    """Apply Hermes-specific transformations to a parsed SkillSpec."""
    original_id = spec.id

    # Namespace to avoid collisions with JS Agent builtin skills
    if not spec.id.startswith(HERMES_ID_PREFIX):
        spec.id = f"{HERMES_ID_PREFIX}{spec.id}"

    # Infer type if not explicitly set (Hermes skills usually omit 'type')
    if spec.type == SkillType.CODE and not (spec.path and (spec.path / spec.entry).exists()):
        # The default parse gives CODE, but Hermes skills are usually PROMPT
        spec.type = _infer_skill_type(spec)
    elif spec.type != SkillType.CODE:
        # Already parsed as something else, keep it
        pass
    else:
        # Parsed as CODE but may still be PROMPT if no entry exists
        entry_path = spec.path / spec.entry if spec.path else None
        if not entry_path or not entry_path.exists():
            spec.type = _infer_skill_type(spec)

    # Set trust level based on provenance
    spec.trust_level = _resolve_trust_level(original_id, lock_data)

    # Extract Hermes-specific metadata
    hermes_meta = spec.metadata.get("hermes", {}) if spec.metadata else {}
    if hermes_meta:
        # Merge tags
        hermes_tags = hermes_meta.get("tags", [])
        if hermes_tags and not spec.tags:
            spec.tags = [str(t) for t in hermes_tags]
        elif hermes_tags:
            existing = set(spec.tags)
            spec.tags = spec.tags + [str(t) for t in hermes_tags if t not in existing]

        # Merge related_skills into dependencies
        related = hermes_meta.get("related_skills", [])
        if related:
            existing_deps = set(spec.dependencies)
            for r in related:
                r_str = str(r)
                if r_str not in existing_deps:
                    spec.dependencies.append(r_str)

        # Set category from metadata if available
        if not spec.category or spec.category == "general":
            cat = hermes_meta.get("category", "")
            if cat:
                spec.category = str(cat)

    # Infer category from directory path if still general
    if spec.category == "general" and spec.path:
        try:
            # Path: ~/.hermes/skills/<category>/<skill>/SKILL.md
            rel = spec.path.relative_to(hermes_skills_dir())
            parts = rel.parts
            if len(parts) >= 1:
                spec.category = str(parts[0])
        except ValueError:
            logger.warning("Operation failed", exc_info=True)

    # Ensure sub-directories are set (redundant with parse_skill_manifest but safe)
    if spec.path:
        spec.references_dir = spec.path / "references"
        spec.templates_dir = spec.path / "templates"
        spec.assets_dir = spec.path / "assets"

    # For CODE skills, infer parameter schema from the entry script
    if spec.type == SkillType.CODE and spec.path:
        entry_path = spec.path / spec.entry
        inferred_params = _infer_parameters_from_script(entry_path)
        if inferred_params:
            if not spec.metadata:
                spec.metadata = {}
            spec.metadata["parameters"] = inferred_params
            logger.debug(f"Inferred {len(inferred_params)} parameters for {spec.id}")

    # Recompute hash after modifications
    spec.content_hash = spec.compute_hash()

    return spec


def discover_hermes_skills(skills_root: Path | None = None) -> list[Path]:
    """Discover all Hermes skill manifests.

    Scans the Hermes skills directory recursively for SKILL.md files.
    Supports both flat and categorized layouts.

    Returns:
        List of Path objects pointing to SKILL.md files.
    """
    skills_dir = skills_root if skills_root is not None else hermes_skills_dir()
    if not skills_dir.exists():
        logger.debug(f"Hermes skills directory not found: {skills_dir}")
        return []

    manifests: list[Path] = []
    for path in skills_dir.rglob("SKILL.md"):
        # Skip hidden/internal directories
        if any(part.startswith(".") for part in path.relative_to(skills_dir).parts):
            continue
        manifests.append(path)

    logger.info(f"Discovered {len(manifests)} Hermes skills in {skills_dir}")
    return manifests


def load_hermes_skill(
    manifest_path: Path,
    lock_data: dict[str, Any] | None = None,
) -> SkillSpec:
    """Load a single Hermes skill from its SKILL.md manifest.

    Args:
        manifest_path: Path to the SKILL.md file.
        lock_data: Optional pre-loaded hub lock file data.

    Returns:
        A SkillSpec ready for use in JS Agent's SkillManager.
    """
    if lock_data is None:
        lock_data = _load_hub_lock()

    spec = parse_skill_manifest(manifest_path)
    return _post_process_hermes_spec(spec, lock_data)


def load_all_hermes_skills(
    hermes_skills_dir: Path | None = None,
) -> dict[str, SkillSpec]:
    """Load all discoverable Hermes skills.

    Args:
        hermes_skills_dir: Optional override for the Hermes skills directory.

    Returns:
        Dict mapping skill IDs (with "hermes:" prefix) to SkillSpec objects.
    """
    manifests = discover_hermes_skills(hermes_skills_dir)
    lock_data = _load_hub_lock()

    skills: dict[str, SkillSpec] = {}
    for manifest in manifests:
        try:
            spec = load_hermes_skill(manifest, lock_data)
            skills[spec.id] = spec
            logger.debug(
                f"Loaded Hermes skill: {spec.id} (type={spec.type.value}, trust={spec.trust_level.value})"
            )
        except Exception as e:
            logger.warning(f"Failed to load Hermes skill from {manifest}: {e}")

    logger.info(f"Loaded {len(skills)} Hermes skills")
    return skills


def is_hermes_skill(skill_id: str) -> bool:
    """Check if a skill ID belongs to the Hermes namespace."""
    return skill_id.startswith(HERMES_ID_PREFIX)


def hermes_skill_source_dir(skill_id: str) -> Path | None:
    """Get the source directory for a Hermes skill ID.

    Strips the 'hermes:' prefix and looks in the Hermes skills directory.
    """
    if not is_hermes_skill(skill_id):
        return None
    name = skill_id[len(HERMES_ID_PREFIX) :]
    # Try to find the skill directory (may be in a category subdir)
    skills_root = hermes_skills_dir()
    for path in skills_root.rglob(f"{name}/SKILL.md"):
        if not any(part.startswith(".") for part in path.relative_to(skills_root).parts):
            return path.parent
    return None


# ---------------------------------------------------------------------------
# Health & diagnostics
# ---------------------------------------------------------------------------


class HermesBridgeStats:
    """Runtime statistics for the Hermes bridge."""

    def __init__(self) -> None:
        self.total_loaded = 0
        self.prompt_count = 0
        self.code_count = 0
        self.failed_loads = 0
        self.last_refresh_time: float = 0.0
        self.refresh_count = 0
        self.guard_scan_failures = 0
        self.quarantine_blocked = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_loaded": self.total_loaded,
            "prompt_count": self.prompt_count,
            "code_count": self.code_count,
            "failed_loads": self.failed_loads,
            "last_refresh_time": self.last_refresh_time,
            "refresh_count": self.refresh_count,
            "guard_scan_failures": self.guard_scan_failures,
            "quarantine_blocked": self.quarantine_blocked,
        }


# Global stats instance (managed by SkillManager)
_bridge_stats = HermesBridgeStats()


def get_bridge_stats() -> HermesBridgeStats:
    """Get the global Hermes bridge statistics."""
    return _bridge_stats


# ---------------------------------------------------------------------------
# Security bridge: optional enhanced scanning with Hermes's own guard
# ---------------------------------------------------------------------------


def _try_hermes_guard_scan(skill_path: Path) -> ScanResult | None:
    """Attempt to use Hermes's own skills_guard scanner if available.

    This provides an additional security layer by leveraging Hermes's
    80+ threat pattern database. Falls back gracefully if Hermes is not
    installed or the module is unavailable.

    The guard module is attacker-controlled code (it ships with the Hermes
    installation), so it never runs on the bare host: it executes inside
    the same strict OS sandbox used for skill execution, with a scrubbed
    environment that carries no API keys. When no sandbox backend is
    available the scan is skipped (fail-closed) and the JS Agent base
    scan remains the only verdict.
    """
    try:
        # Add Hermes agent tools to path temporarily
        hermes_tools = _get_hermes_home() / "hermes-agent" / "tools"
        if not hermes_tools.exists():
            return None

        # Validate skill_path is within the Hermes skills directory
        skills_dir = _get_hermes_home() / "skills"
        try:
            skill_path.resolve().relative_to(skills_dir.resolve())
        except ValueError:
            logger.warning(
                "Skill path %s is outside Hermes skills directory %s — skipping Hermes guard scan",
                skill_path,
                skills_dir,
            )
            return None

        # Use subprocess to avoid import side-effects.
        # Pass skill_path as a CLI argument instead of embedding it in the
        # script string to prevent injection via the file path.
        script = (
            "import sys\n"
            f"sys.path.insert(0, {str(hermes_tools)!r})\n"
            "from skills_guard import scan_skill\n"
            "skill_path = sys.argv[1]\n"
            "result = scan_skill(skill_path, source='community')\n"
            "print('VERDICT:', result.verdict)\n"
            "flags = []\n"
            "for f in result.findings:\n"
            "    flags.append(f.pattern_id + ':' + f.severity)\n"
            "print('FLAGS:', '|'.join(flags))\n"
        )
        import subprocess

        from js.echo.os_sandbox import SandboxExecutor

        sandbox = SandboxExecutor(
            skills_dir.resolve(),
            timeout=30.0,
            strict_isolation=True,
            trusted_executables=[Path(sys.executable)],
        )
        cmd = [sys.executable, "-c", script, str(skill_path)]
        try:
            wrapped = sandbox._wrap_filesystem_isolation(
                cmd,
                fs_restricted=True,
                read_only_paths=(hermes_tools.resolve(),),
                network_allowed=False,
            )
        except RuntimeError:
            # No sandbox backend — never run attacker-controlled guard code
            # on the bare host; the JS Agent base scan still applies.
            logger.warning(
                "Hermes guard scan skipped: no OS sandbox backend available "
                "(fail-closed, base scan still applies)"
            )
            return None

        proc = subprocess.run(
            wrapped,
            capture_output=True,
            text=True,
            timeout=30,
            env=sandbox._build_env(),
            # Keep the child's cwd inside the sandbox workspace: sys.path's
            # implicit '' entry resolves to the cwd, and importing anything
            # (e.g. pathlib) from the guard would otherwise list a directory
            # the sandbox denies — and fail-closed looks like "no scanner".
            cwd=str(skills_dir.resolve()),
        )
        if proc.returncode == 0:
            # Parse simple output format
            lines = proc.stdout.strip().split("\n")
            verdict = "safe"
            flags: list[str] = []
            for line in lines:
                if line.startswith("VERDICT: "):
                    verdict = line.split(": ", 1)[1]
                elif line.startswith("FLAGS: "):
                    flags_str = line.split(": ", 1)[1]
                    if flags_str:
                        flags = [f.split(":")[0] for f in flags_str.split("|")]
            return ScanResult(
                skill_id=skill_path.parent.name,
                content_hash="",
                risk_flags=flags,
                trust_level=TrustLevel.TRUSTED if verdict == "safe" else TrustLevel.COMMUNITY,
            )
    except Exception:
        logger.warning("Operation failed", exc_info=True)
    return None


def enhanced_scan_hermes_skill(spec: SkillSpec) -> ScanResult:
    """Scan a Hermes skill with both JS Agent and optional Hermes guard.

    Runs the standard JS Agent scan first. If Hermes's skills_guard is
    available, merges its findings for defense-in-depth.
    """
    # Base scan from JS Agent
    result = scan_skill(spec)

    # Attempt Hermes guard enhancement (non-blocking)
    if spec.path:
        hermes_result = _try_hermes_guard_scan(spec.path)
        if hermes_result:
            merged_flags = list(set(result.risk_flags + hermes_result.risk_flags))
            result.risk_flags = merged_flags
            # If either scanner says quarantine, quarantine
            if hermes_result.trust_level == TrustLevel.QUARANTINE:
                result.trust_level = TrustLevel.QUARANTINE

    return result
