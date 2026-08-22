"""Regression: install-time expected_hash pin must actually verify.

Round-3 finding: ``SkillManager.install`` required a 64-hex ``expected_hash``
while ``SkillSpec.compute_hash()`` returns a 32-hex truncated digest, so every
pinned install failed closed and the feature was dead.  Both digest lengths
are now accepted and compared against the same full content hash.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from js.skills.manager import SkillManager
from js.skills.spec import compute_skill_dir_hash, parse_skill_manifest


@pytest.fixture
def skill_source(tmp_path: Path) -> Path:
    src = tmp_path / "src" / "demo"
    src.mkdir(parents=True)
    (src / "SKILL.md").write_text("---\nname: demo\ndescription: demo\n---\n# demo\n")
    (src / "main.py").write_text("print('hi')\n")
    return src


@pytest.fixture
def manager(tmp_path: Path) -> SkillManager:
    return SkillManager(state_dir=tmp_path / "state", workspace=tmp_path / "ws")


class TestInstallHashPin:
    @pytest.mark.asyncio
    async def test_correct_truncated_hash_installs(
        self, manager: SkillManager, skill_source: Path
    ) -> None:
        spec = parse_skill_manifest(skill_source / "SKILL.md")
        spec.path = skill_source
        spec_result = await manager.install(
            str(skill_source), skill_id="pin32", expected_hash=spec.compute_hash()
        )
        assert spec_result.id == "pin32"

    @pytest.mark.asyncio
    async def test_correct_full_hash_installs(
        self, manager: SkillManager, skill_source: Path
    ) -> None:
        full = compute_skill_dir_hash(skill_source)
        assert len(full) == 64
        spec_result = await manager.install(
            str(skill_source), skill_id="pin64", expected_hash=full
        )
        assert spec_result.id == "pin64"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad", ["0" * 32, "f" * 64])
    async def test_wrong_hash_rejected(
        self, manager: SkillManager, skill_source: Path, bad: str
    ) -> None:
        with pytest.raises(ValueError, match="hash mismatch"):
            await manager.install(str(skill_source), skill_id="pinbad", expected_hash=bad)

    @pytest.mark.asyncio
    async def test_malformed_hash_rejected(
        self, manager: SkillManager, skill_source: Path
    ) -> None:
        with pytest.raises(ValueError, match="SHA-256"):
            await manager.install(str(skill_source), skill_id="pinzz", expected_hash="zz")
