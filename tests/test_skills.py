"""Tests for the next-generation skill system."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from js.skills.evolver import SkillEvolver
from js.skills.manager import SkillManager
from js.skills.security import scan_skill, verify_integrity
from js.skills.spec import Prerequisites, SkillSpec, SkillType, TrustLevel, parse_skill_manifest

if TYPE_CHECKING:
    from fastapi.testclient import TestClient


class TestSkillSpec:
    def test_parse_hermes_style_manifest(self, tmp_path: Path) -> None:
        """Parse Hermes-style YAML frontmatter + Markdown body."""
        manifest = tmp_path / "SKILL.md"
        manifest.write_text("""---
id: arxiv
name: arXiv Research
description: Search arXiv papers
version: 1.0.0
author: Test
type: prompt
category: research
tags: [papers, academic]
platforms: [macos, linux]
trust_level: trusted
prerequisites:
  commands: [curl]
---

# arXiv Research

Search academic papers from arXiv.
""")
        spec = parse_skill_manifest(manifest)
        assert spec.id == "arxiv"
        assert spec.name == "arXiv Research"
        assert spec.type == SkillType.PROMPT
        assert spec.category == "research"
        assert spec.platforms == ["macos", "linux"]
        assert spec.trust_level == TrustLevel.TRUSTED
        assert "Search academic papers" in spec.full_content
        assert spec.prerequisites.commands == ["curl"]

    def test_parse_js_style_manifest(self, tmp_path: Path) -> None:
        """Parse original JS Agent plain YAML manifest."""
        manifest = tmp_path / "SKILL.md"
        manifest.write_text("""id: calc
name: Calculator
entry: main.py
type: code
""")
        spec = parse_skill_manifest(manifest)
        assert spec.id == "calc"
        assert spec.type == SkillType.CODE
        assert spec.entry == "main.py"

    def test_platform_compatibility(self) -> None:
        spec = SkillSpec(id="test", name="Test", platforms=["linux"])
        import sys
        if sys.platform.startswith("linux"):
            assert spec.is_compatible()
        elif sys.platform == "darwin":
            assert not spec.is_compatible()

    def test_prerequisites_check(self) -> None:
        prereqs = Prerequisites(commands=["python"], env_vars=["HOME"])
        ok, missing = prereqs.check()
        assert ok
        assert missing == []

        prereqs2 = Prerequisites(commands=["nonexistent_command_xyz"])
        ok2, missing2 = prereqs2.check()
        assert not ok2
        assert any("nonexistent_command_xyz" in m for m in missing2)

    def test_summary_dict_progressive_disclosure(self) -> None:
        spec = SkillSpec(
            id="test",
            name="Test Skill",
            description="A test",
            type=SkillType.PROMPT,
            category="test",
            trust_level=TrustLevel.BUILTIN,
        )
        summary = spec.to_summary_dict()
        assert "content" not in summary
        assert summary["id"] == "test"
        assert summary["trust_level"] == "builtin"

    def test_detail_dict_full_content(self) -> None:
        spec = SkillSpec(
            id="test",
            name="Test",
            full_content="# Full instructions",
            type=SkillType.PROMPT,
        )
        detail = spec.to_detail_dict()
        assert detail["content_length"] == len("# Full instructions")


class TestSkillSecurity:
    def test_scan_clean_skill(self, tmp_path: Path) -> None:
        manifest = tmp_path / "SKILL.md"
        manifest.write_text("---\nid: safe\nname: Safe Skill\ntype: code\n---\n")
        spec = parse_skill_manifest(manifest)
        result = scan_skill(spec)
        assert result.skill_id == "safe"
        assert len(result.risk_flags) == 0

    def test_scan_risky_skill(self, tmp_path: Path) -> None:
        manifest = tmp_path / "SKILL.md"
        manifest.write_text("---\nid: risky\nname: Risky\ntype: code\n---\n")
        # Write a risky Python file
        (tmp_path / "main.py").write_text("import os; os.system('rm -rf /')")
        spec = parse_skill_manifest(manifest)
        result = scan_skill(spec)
        assert "file_deletion" in result.risk_flags or "code_execution" in result.risk_flags

    def test_integrity_verification(self, tmp_path: Path) -> None:
        manifest = tmp_path / "SKILL.md"
        manifest.write_text("---\nid: test\nname: Test\n---\n")
        spec = parse_skill_manifest(manifest)
        assert verify_integrity(spec)
        # Tamper with file
        manifest.write_text("---\nid: test\nname: Tampered\n---\n")
        assert not verify_integrity(spec)


class TestSkillManager:
    @pytest.fixture
    def manager(self, tmp_path: Path) -> SkillManager:
        return SkillManager(tmp_path, tmp_path / "workspace")

    def test_builtin_skills_loaded(self, manager: SkillManager) -> None:
        """Builtin skills from js/skills/builtin/ should be auto-loaded."""
        skills = manager.list_skills()
        ids = [s["id"] for s in skills]
        assert "arxiv-research" in ids
        assert "code-review" in ids
        assert "file-search" in ids
        assert "web-fetch" in ids
        assert "shell-safety" in ids

    def test_builtin_trust_level(self, manager: SkillManager) -> None:
        spec = manager.get_skill("arxiv-research")
        assert spec is not None
        assert spec.trust_level == TrustLevel.BUILTIN

    def test_list_skills_filtering(self, manager: SkillManager) -> None:
        research = manager.list_skills(category="research")
        assert all(s["category"] == "research" for s in research)

        prompts = manager.list_skills(skill_type=SkillType.PROMPT)
        assert all(s["type"] == "prompt" for s in prompts)

    def test_list_skills_search(self, manager: SkillManager) -> None:
        results = manager.list_skills(query="arxiv")
        assert len(results) >= 1
        assert any("arxiv" in s["id"] for s in results)

    def test_view_skill_progressive_disclosure(self, manager: SkillManager) -> None:
        # list_skills should NOT include full content
        summary = manager.list_skills()[0]
        assert "content" not in summary

        # view_skill SHOULD include full content
        detail = manager.view_skill("arxiv-research")
        assert detail is not None
        assert "content" in detail
        assert "arXiv" in detail["content"]

    def test_categories(self, manager: SkillManager) -> None:
        cats = manager.list_categories()
        names = [c["name"] for c in cats]
        assert "research" in names
        assert "software-development" in names

    def test_prerequisites_check(self, manager: SkillManager) -> None:
        ok, missing = manager.check_prerequisites("arxiv-research")
        # curl should exist on most systems
        assert isinstance(ok, bool)

    def test_global_stats(self, manager: SkillManager) -> None:
        stats = manager.get_global_stats()
        assert stats["skills_loaded"] >= 5
        assert stats["builtin_count"] >= 5

    @pytest.mark.anyio
    async def test_install_and_uninstall(self, manager: SkillManager, tmp_path: Path) -> None:
        src = tmp_path / "my_skill"
        src.mkdir()
        (src / "SKILL.md").write_text("""---
id: my_skill
name: My Skill
type: code
entry: main.py
---
""")
        (src / "main.py").write_text("print('hello')")

        spec = await manager.install(str(src), "my_skill")
        assert spec.id == "my_skill"
        assert "my_skill" in manager._skills

        assert await manager.uninstall("my_skill")
        assert "my_skill" not in manager._skills

    def test_trust_override(self, manager: SkillManager) -> None:
        assert manager.trust_skill("arxiv-research", TrustLevel.TRUSTED)
        spec = manager.get_skill("arxiv-research")
        assert spec is not None
        assert spec.trust_level == TrustLevel.TRUSTED

    @pytest.mark.anyio
    async def test_quarantine_blocks_execution(self, manager: SkillManager, tmp_path: Path) -> None:
        src = tmp_path / "bad_skill"
        src.mkdir()
        (src / "SKILL.md").write_text("---\nid: bad\nname: Bad\ntype: code\n---\n")
        (src / "main.py").write_text("import os; eval('1+1')")

        await manager.install(str(src), "bad")
        # After scan, should be quarantined or community
        spec = manager.get_skill("bad")
        assert spec is not None


class TestSkillEvolver:
    @pytest.fixture
    def evolver(self, tmp_path: Path) -> SkillEvolver:
        return SkillEvolver(tmp_path)

    def test_create_variant(self, evolver: SkillEvolver) -> None:
        v = evolver.create_variant("test", "print(1)", "test prompt", [{"in": 1, "out": 2}])
        assert v.skill_id == "test"
        assert v.code == "print(1)"

    def test_record_and_select(self, evolver: SkillEvolver) -> None:
        v1 = evolver.create_variant("s1", "code1", "p1", [])
        v2 = evolver.create_variant("s1", "code2", "p2", [])

        evolver.record_result(v1.id, True, 0.9)
        evolver.record_result(v1.id, True, 0.8)
        evolver.record_result(v2.id, False, 0.3)

        best = evolver.select_best_variant("s1")
        assert best is not None
        assert best.id == v1.id

    def test_evolution_report(self, evolver: SkillEvolver) -> None:
        evolver.create_variant("s1", "code", "p", [])
        report = evolver.get_evolution_report("s1")
        assert report["skill_id"] == "s1"
        assert report["total_variants"] == 1


class TestSkillWebAPI:
    @pytest.fixture
    def client(self, tmp_path: Path) -> TestClient:
        from unittest.mock import AsyncMock, MagicMock

        from fastapi.testclient import TestClient

        from js.web import server
        from js.web.server import create_app

        mock_agent = MagicMock()
        mock_agent.settings.workspace = tmp_path / "workspace"
        mock_agent.settings.state_dir = tmp_path / "state"
        mock_agent.settings.max_turns = 10
        mock_agent.settings.security.defense_mode.value = "standard"
        mock_agent.registry.get_stats.return_value = {}
        mock_agent.secrets.get_stats.return_value = {"stored_secrets": 0, "detected_leaks": 0}

        mock_skills = MagicMock()
        mock_skills.list_skills.return_value = [
            {
                "id": "test-skill",
                "name": "Test Skill",
                "type": "prompt",
                "category": "general",
                "trust_level": "builtin",
                "compatible": True,
                "prerequisites_ok": True,
                "usage_count": 5,
                "success_rate": 0.95,
                "description": "A test skill",
                "tags": ["test"],
            },
        ]
        mock_skills.list_categories.return_value = [{"name": "general", "count": 1}]
        mock_skills.get_global_stats.return_value = {"skills_loaded": 1}
        mock_skills.view_skill.return_value = {
            "id": "test-skill",
            "name": "Test Skill",
            "content": "Test content",
            "trust_level": "builtin",
            "compatible": True,
            "prerequisites_ok": True,
        }
        mock_spec = MagicMock()
        mock_spec.id = "new-skill"
        mock_spec.trust_level.value = "community"
        mock_spec.risk_flags = []
        mock_skills.install = AsyncMock(return_value=mock_spec)
        mock_skills.uninstall = AsyncMock(return_value=True)
        mock_skills.trust_skill.return_value = True
        mock_agent.skills = mock_skills

        server._agent = mock_agent
        app = create_app()
        return TestClient(app)

    def test_list_skills_api(self, client: TestClient) -> None:
        resp = client.get("/api/skills")
        assert resp.status_code == 200
        data = resp.json()
        assert "skills" in data
        assert len(data["skills"]) == 1
        assert data["skills"][0]["id"] == "test-skill"
        assert "categories" in data
        assert "global_stats" in data

    def test_skill_detail_api(self, client: TestClient) -> None:
        resp = client.get("/api/skills/test-skill")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "test-skill"
        assert "content" in data

    def test_install_skill_api(self, client: TestClient) -> None:
        resp = client.post("/api/skills/install", json={"source": "/tmp/test", "skill_id": "new-skill"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["skill_id"] == "new-skill"

    def test_uninstall_skill_api(self, client: TestClient) -> None:
        resp = client.delete("/api/skills/test-skill")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True

    def test_trust_skill_api(self, client: TestClient) -> None:
        resp = client.post("/api/skills/test-skill/trust", json={"level": "trusted"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["trust_level"] == "trusted"

    def test_trust_skill_api_invalid_level(self, client: TestClient) -> None:
        resp = client.post("/api/skills/test-skill/trust", json={"level": "invalid"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert "Invalid" in data["error"]
