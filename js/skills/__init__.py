"""Skill system: discoverable, installable, self-optimizing, multi-type capabilities.

Supports three skill types:
- code: Executable Python/Shell scripts
- prompt: LLM instruction documents (Hermes-compatible)
- workflow: Lightweight automation chains

Features:
- Category-based organization
- Platform filtering
- Trust levels with security scanning
- Progressive disclosure (list → view)
- Prerequisites checking
- Builtin skills shipped with agent
"""

from js.skills.evolver import SkillEvolver
from js.skills.manager import SkillManager
from js.skills.security import ScanResult, scan_skill, verify_integrity
from js.skills.spec import (
    Prerequisites,
    SkillSpec,
    SkillType,
    TrustLevel,
    parse_skill_manifest,
)

__all__ = [
    "SkillManager",
    "SkillEvolver",
    "SkillSpec",
    "SkillType",
    "TrustLevel",
    "Prerequisites",
    "parse_skill_manifest",
    "scan_skill",
    "verify_integrity",
    "ScanResult",
]
