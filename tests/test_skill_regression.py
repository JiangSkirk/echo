"""Regression tests for builtin skills.

Verifies that all builtin skills load correctly, have valid manifests,
and their entry files exist (for code-type skills).

This is a lightweight regression suite that catches packaging errors,
broken imports, and missing files — not a functional test of skill logic.
"""

from __future__ import annotations

from pathlib import Path

from js.skills.manager import SkillManager
from js.skills.spec import SkillType, parse_skill_manifest

BUILTIN_DIR = Path(__file__).parent.parent / "js" / "skills" / "builtin"


class TestBuiltinSkillsLoad:
    """Every builtin skill must parse and load without errors."""

    def test_all_builtin_dirs_have_skill_md(self) -> None:
        """Each subdirectory of builtin/ must contain a SKILL.md file."""
        skill_dirs = [d for d in BUILTIN_DIR.iterdir() if d.is_dir()]
        assert len(skill_dirs) >= 1, "No builtin skill directories found"

        missing = []
        for skill_dir in skill_dirs:
            if not (skill_dir / "SKILL.md").exists():
                missing.append(skill_dir.name)

        assert not missing, f"Missing SKILL.md in builtin skills: {missing}"

    def test_all_builtin_skills_parse(self) -> None:
        """Every SKILL.md must parse into a valid SkillSpec."""
        skill_dirs = [d for d in BUILTIN_DIR.iterdir() if d.is_dir()]
        errors: list[str] = []

        for skill_dir in skill_dirs:
            skill_md = skill_dir / "SKILL.md"
            try:
                spec = parse_skill_manifest(skill_md)
            except Exception as exc:
                errors.append(f"{skill_dir.name}: {exc}")
                continue

            # Basic sanity checks
            if not spec.id:
                errors.append(f"{skill_dir.name}: missing id")
            if not spec.name:
                errors.append(f"{skill_dir.name}: missing name")
            if not spec.version:
                errors.append(f"{skill_dir.name}: missing version")

        assert not errors, f"Builtin skill parse errors: {errors}"

    def test_builtin_skill_ids_match_directory_names(self) -> None:
        """Skill id should match the directory name for predictability."""
        skill_dirs = [d for d in BUILTIN_DIR.iterdir() if d.is_dir()]
        mismatches: list[str] = []

        for skill_dir in skill_dirs:
            skill_md = skill_dir / "SKILL.md"
            try:
                spec = parse_skill_manifest(skill_md)
            except Exception:
                continue  # parse test covers this

            if spec.id != skill_dir.name:
                mismatches.append(
                    f"{skill_dir.name}/SKILL.md has id='{spec.id}' (expected '{skill_dir.name}')"
                )

        assert not mismatches, f"ID/directory mismatches: {mismatches}"


class TestBuiltinCodeSkills:
    """Code-type builtin skills must have an existing entry file."""

    def test_code_skills_have_entry_file(self) -> None:
        """Every code-type skill must have its entry file present."""
        skill_dirs = [d for d in BUILTIN_DIR.iterdir() if d.is_dir()]
        missing: list[str] = []

        for skill_dir in skill_dirs:
            skill_md = skill_dir / "SKILL.md"
            try:
                spec = parse_skill_manifest(skill_md)
            except Exception:
                continue

            if spec.type == SkillType.CODE:
                entry = skill_dir / spec.entry
                if not entry.exists():
                    missing.append(f"{spec.id}: missing entry file '{spec.entry}'")

        assert not missing, f"Missing entry files: {missing}"


class TestBuiltinPromptSkills:
    """Prompt-type builtin skills must have non-empty instructions."""

    def test_prompt_skills_have_instructions(self) -> None:
        """Every prompt-type skill must have instructions content."""
        skill_dirs = [d for d in BUILTIN_DIR.iterdir() if d.is_dir()]
        empty: list[str] = []

        for skill_dir in skill_dirs:
            skill_md = skill_dir / "SKILL.md"
            try:
                spec = parse_skill_manifest(skill_md)
            except Exception:
                continue

            if spec.type == SkillType.PROMPT and (not spec.full_content or not spec.full_content.strip()):
                    empty.append(spec.id)

        assert not empty, f"Prompt skills with empty instructions: {empty}"


class TestSkillManagerIntegration:
    """SkillManager must load all builtin skills successfully."""

    def test_manager_loads_all_builtins(self, tmp_path: Path) -> None:
        """SkillManager discovers and loads every builtin skill."""
        manager = SkillManager(tmp_path, tmp_path / "workspace")
        loaded = manager.list_skills()
        loaded_ids = {s["id"] for s in loaded}

        # Discover expected builtin ids from filesystem
        skill_dirs = [d for d in BUILTIN_DIR.iterdir() if d.is_dir()]
        expected_ids = set()
        for skill_dir in skill_dirs:
            try:
                spec = parse_skill_manifest(skill_dir / "SKILL.md")
                expected_ids.add(spec.id)
            except Exception:
                continue

        missing = expected_ids - loaded_ids
        assert not missing, f"SkillManager failed to load builtins: {missing}"

    def test_builtin_skills_have_compatible_flag(self, tmp_path: Path) -> None:
        """All loaded builtin skills should report compatible=True."""
        manager = SkillManager(tmp_path, tmp_path / "workspace")
        loaded = manager.list_skills()

        incompatible = [
            s["id"] for s in loaded
            if s.get("trust_level") == "builtin" and not s.get("compatible", True)
        ]

        assert not incompatible, f"Incompatible builtin skills: {incompatible}"
