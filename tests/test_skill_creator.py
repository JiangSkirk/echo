"""Tests for the skill creation wizard."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.skills.creator import create_from_spec, create_skill
from js.skills.spec import Prerequisites, SkillSpec, SkillType


class TestCreateSkillPrompt:
    def test_create_prompt_skill(self, tmp_path: Path) -> None:
        path = create_skill(
            skills_dir=tmp_path,
            skill_id="test-prompt",
            name="Test Prompt",
            description="A test prompt skill",
            skill_type=SkillType.PROMPT,
            instructions="Do something useful.",
            example_query="How do I test?",
            tags=["test", "demo"],
        )
        assert path.exists()
        assert (path / "SKILL.md").exists()
        assert "test-prompt" in (path / "SKILL.md").read_text()
        assert "Do something useful" in (path / "SKILL.md").read_text()

    def test_create_prompt_has_subdirs(self, tmp_path: Path) -> None:
        path = create_skill(
            skills_dir=tmp_path,
            skill_id="test-prompt",
            name="Test Prompt",
            description="A test prompt skill",
            skill_type=SkillType.PROMPT,
        )
        for subdir in ("references", "templates", "assets"):
            assert (path / subdir).is_dir()
            assert (path / subdir / ".gitkeep").exists()

    def test_duplicate_id_raises(self, tmp_path: Path) -> None:
        create_skill(
            skills_dir=tmp_path,
            skill_id="duplicate",
            name="First",
            description="First skill",
            skill_type=SkillType.PROMPT,
        )
        with pytest.raises(FileExistsError):
            create_skill(
                skills_dir=tmp_path,
                skill_id="duplicate",
                name="Second",
                description="Second skill",
                skill_type=SkillType.PROMPT,
            )


class TestCreateSkillCode:
    def test_create_code_skill(self, tmp_path: Path) -> None:
        path = create_skill(
            skills_dir=tmp_path,
            skill_id="test-code",
            name="Test Code",
            description="A test code skill",
            skill_type=SkillType.CODE,
            parameters=[
                {"name": "input_file", "type": "string", "description": "Input path", "required": True},
                {"name": "verbose", "type": "boolean", "description": "Verbose output"},
            ],
        )
        assert (path / "SKILL.md").exists()
        assert (path / "main.py").exists()
        content = (path / "main.py").read_text()
        assert "argparse" in content
        assert "--input_file" in content
        assert "--verbose" in content

    def test_code_skill_argparse_types(self, tmp_path: Path) -> None:
        path = create_skill(
            skills_dir=tmp_path,
            skill_id="code-types",
            name="Code Types",
            description="Test",
            skill_type=SkillType.CODE,
            parameters=[
                {"name": "count", "type": "integer", "description": "Count", "required": True},
                {"name": "ratio", "type": "number", "description": "Ratio"},
            ],
        )
        content = (path / "main.py").read_text()
        assert "type=int" in content
        assert "type=float" in content


class TestCreateSkillWorkflow:
    def test_create_workflow_skill(self, tmp_path: Path) -> None:
        path = create_skill(
            skills_dir=tmp_path,
            skill_id="test-workflow",
            name="Test Workflow",
            description="A workflow",
            skill_type=SkillType.WORKFLOW,
            steps=[
                {"type": "prompt", "input": "Analyze the data"},
                {"type": "shell", "input": "echo done"},
            ],
        )
        content = (path / "SKILL.md").read_text()
        assert "workflow" in content
        assert "Analyze the data" in content


class TestCreateSkillMeta:
    def test_create_meta_skill(self, tmp_path: Path) -> None:
        path = create_skill(
            skills_dir=tmp_path,
            skill_id="test-meta",
            name="Test Meta",
            description="A meta skill",
            skill_type=SkillType.META,
            dependencies=["sub-skill-a", "sub-skill-b"],
            steps=[{"type": "skill", "skill_id": "sub-skill-a"}],
        )
        content = (path / "SKILL.md").read_text()
        assert "sub-skill-a" in content
        assert "meta" in content


class TestCreateFromSpec:
    def test_roundtrip(self, tmp_path: Path) -> None:
        original = SkillSpec(
            id="roundtrip",
            name="Roundtrip",
            description="Test",
            type=SkillType.CODE,
            category="testing",
            tags=["x"],
            author="tester",
            license="MIT",
            version="1.0.0",
            prerequisites=Prerequisites(commands=["python3"]),
        )
        path = create_from_spec(tmp_path, original)
        assert (path / "SKILL.md").exists()
        text = (path / "SKILL.md").read_text()
        assert "roundtrip" in text
        assert "1.0.0" in text


class TestValidationEdgeCases:
    def test_empty_id_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="skill_id"):
            create_skill(tmp_path, "", "Name", "Desc", SkillType.PROMPT)

    def test_empty_name_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="name"):
            create_skill(tmp_path, "id", "", "Desc", SkillType.PROMPT)
