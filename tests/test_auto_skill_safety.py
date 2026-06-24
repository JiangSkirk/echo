"""Regression: v0.1.4-alpha hardening of the auto-skill / auto-evolve path.

Five guards covered here (PR-1 + PR-4 minimal safety closure):

1. Auto-generated skills land in QUARANTINE with metadata.state=="draft".
2. QUARANTINE skills cannot be executed by SkillManager.
3. Hermes skills are never auto-overwritten by promote_variant.
4. Builtin skills are never auto-overwritten by promote_variant.
5. Existing manual install/list flow still works (smoke test, no regression).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from js.skills.auto_creator import AutoSkillCreator
from js.skills.evolver import SkillEvolver, _is_protected_for_promote
from js.skills.spec import SkillType, TrustLevel, parse_skill_manifest

# ---------------------------------------------------------------------------
# 1. Auto-generated skill must be QUARANTINE + state=draft, never executable.
# ---------------------------------------------------------------------------


def test_auto_created_skill_is_quarantine_draft(tmp_path: Path) -> None:
    creator = AutoSkillCreator(tmp_path)
    spec = creator.create_from_pattern(
        "summarize long shell command outputs into bullet points",
        examples=["e1", "e2"],
    )
    assert spec is not None
    # Trust level: QUARANTINE — execute() refuses to run these.
    assert spec.trust_level == TrustLevel.QUARANTINE
    # Marker the operator UI / approve flow keys off of.
    assert spec.metadata.get("state") == "draft"
    assert spec.metadata.get("auto_generated") is True
    # Skill file landed on disk under the auto-generated namespace.
    assert spec.path is not None
    assert spec.path.is_dir()
    manifest_text = (spec.path / "SKILL.md").read_text(encoding="utf-8")
    assert "trust_level: quarantine" in manifest_text
    assert "state: draft" in manifest_text


def test_auto_creator_idempotent(tmp_path: Path) -> None:
    """Second call for same pattern returns None (already on disk)."""
    creator = AutoSkillCreator(tmp_path)
    pattern = "rewrite git commit messages in conventional form"
    first = creator.create_from_pattern(pattern)
    assert first is not None
    second = creator.create_from_pattern(pattern)
    assert second is None


# ---------------------------------------------------------------------------
# 2. QUARANTINE skills are not executable through SkillManager.execute().
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_quarantine_skill_not_executable(tmp_path: Path) -> None:
    """SkillManager.execute() must refuse to run a QUARANTINE skill."""
    from js.skills.manager import SkillManager

    state_dir = tmp_path / "state"
    workspace = tmp_path / "ws"
    state_dir.mkdir()
    workspace.mkdir()

    mgr = SkillManager(state_dir=state_dir, workspace=workspace)

    # Inject a QUARANTINE skill directly into the in-memory registry,
    # bypassing install() so we don't depend on scan heuristics.
    skill_dir = state_dir / "skills" / "auto_generated" / "auto_test123"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        """---
id: auto_test123
name: Auto Test
description: synthetic draft skill
type: prompt
trust_level: quarantine
metadata:
  auto_generated: true
  state: draft
---
# body
""",
        encoding="utf-8",
    )
    spec = parse_skill_manifest(skill_dir / "SKILL.md")
    assert spec.trust_level == TrustLevel.QUARANTINE
    mgr._skills[spec.id] = spec  # type: ignore[attr-defined]

    result = await mgr.execute(spec.id, args={})
    assert result["success"] is False
    assert "quarantine" in result.get("error", "").lower()


# ---------------------------------------------------------------------------
# 3. Hermes skills must not be auto-promoted (no overwrite of bridged files).
# ---------------------------------------------------------------------------


def test_promote_variant_skips_hermes(tmp_path: Path) -> None:
    """promote_variant on a hermes: skill must return False without writing."""
    evolver = SkillEvolver(state_dir=tmp_path)

    skill_path = tmp_path / "hermes_skill_dir"
    skill_path.mkdir()
    entry = skill_path / "main.py"
    original = "# original hermes-bridged code\n"
    entry.write_text(original, encoding="utf-8")

    # Even without any variants registered, the protected path should short-circuit
    # to False BEFORE select_best_variant() runs. We assert the file is untouched.
    result = evolver.promote_variant("hermes:some-skill", skill_path=skill_path)
    assert result is False
    assert entry.read_text(encoding="utf-8") == original


def test_is_protected_hermes_prefix() -> None:
    assert _is_protected_for_promote("hermes:foo", None) is True
    assert _is_protected_for_promote("hermes:bar/baz", None) is True


# ---------------------------------------------------------------------------
# 4. Builtin skills must not be auto-promoted.
# ---------------------------------------------------------------------------


def test_promote_variant_skips_builtin(tmp_path: Path) -> None:
    """A skill whose SKILL.md declares trust_level=builtin must be left alone."""
    evolver = SkillEvolver(state_dir=tmp_path)

    skill_path = tmp_path / "builtin_skill_dir"
    skill_path.mkdir()
    (skill_path / "SKILL.md").write_text(
        """---
id: code-review
name: Code Review
description: builtin
type: prompt
trust_level: builtin
---
# body
""",
        encoding="utf-8",
    )
    entry = skill_path / "main.py"
    original = "# builtin code, must not be rewritten\n"
    entry.write_text(original, encoding="utf-8")

    result = evolver.promote_variant("code-review", skill_path=skill_path)
    assert result is False
    assert entry.read_text(encoding="utf-8") == original


def test_is_protected_builtin_trust_level(tmp_path: Path) -> None:
    skill_path = tmp_path / "b"
    skill_path.mkdir()
    (skill_path / "SKILL.md").write_text(
        """---
id: x
name: X
type: prompt
trust_level: builtin
---
""",
        encoding="utf-8",
    )
    assert _is_protected_for_promote("x", skill_path) is True


def test_is_protected_community_not_protected(tmp_path: Path) -> None:
    """Community skills are NOT protected — auto-promote may still run for them."""
    skill_path = tmp_path / "c"
    skill_path.mkdir()
    (skill_path / "SKILL.md").write_text(
        """---
id: y
name: Y
type: prompt
trust_level: community
---
""",
        encoding="utf-8",
    )
    assert _is_protected_for_promote("y", skill_path) is False


def test_is_protected_missing_manifest_falls_back_to_unprotected(tmp_path: Path) -> None:
    """No SKILL.md → return False so the original promote_variant failure path runs."""
    skill_path = tmp_path / "missing"
    skill_path.mkdir()
    assert _is_protected_for_promote("z", skill_path) is False


# ---------------------------------------------------------------------------
# 5. Smoke: existing manual SKILL.md parse + list path still works.
#    (Catches accidental SkillSpec field break.)
# ---------------------------------------------------------------------------


def test_manual_skill_manifest_still_parses(tmp_path: Path) -> None:
    skill_path = tmp_path / "manual"
    skill_path.mkdir()
    (skill_path / "SKILL.md").write_text(
        """---
id: manual-demo
name: Manual Demo
description: hand-installed
version: 1.0.0
type: prompt
trust_level: community
---
# body
""",
        encoding="utf-8",
    )
    spec = parse_skill_manifest(skill_path / "SKILL.md")
    assert spec.id == "manual-demo"
    assert spec.type == SkillType.PROMPT
    assert spec.trust_level == TrustLevel.COMMUNITY
    assert spec.metadata.get("state") is None  # manually installed != draft
