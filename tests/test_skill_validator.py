"""Tests for the skill validation engine."""

from __future__ import annotations

from pathlib import Path

from js.skills.creator import create_skill
from js.skills.spec import SkillType
from js.skills.validator import ValidationIssue, validate_skill


class TestValidateManifest:
    def test_valid_prompt_passes(self, tmp_path: Path) -> None:
        path = create_skill(
            tmp_path, "valid-prompt", "Valid", "A valid prompt", SkillType.PROMPT,
            instructions="Do something.", example_query="How?",
        )
        report = validate_skill(path)
        assert report.passed is True
        assert report.skill_id == "valid-prompt"

    def test_missing_manifest_fails(self, tmp_path: Path) -> None:
        report = validate_skill(tmp_path / "nonexistent")
        assert report.passed is False
        assert any(i.code == "missing_manifest" for i in report.issues)

    def test_missing_required_fields(self, tmp_path: Path) -> None:
        # Manually create a bad manifest
        bad_dir = tmp_path / "bad"
        bad_dir.mkdir()
        (bad_dir / "SKILL.md").write_text("---\nid: bad\n---\n")
        report = validate_skill(bad_dir)
        assert report.passed is False
        assert any(i.code == "missing_field" for i in report.issues)

    def test_invalid_type(self, tmp_path: Path) -> None:
        bad_dir = tmp_path / "bad-type"
        bad_dir.mkdir()
        (bad_dir / "SKILL.md").write_text(
            "---\nid: bad-type\nname: Bad\ndescription: x\ntype: invalid\n---\n",
        )
        report = validate_skill(bad_dir)
        assert any(i.code == "invalid_type" for i in report.issues)


class TestValidateStructure:
    def test_code_missing_entry(self, tmp_path: Path) -> None:
        bad_dir = tmp_path / "no-entry"
        bad_dir.mkdir()
        (bad_dir / "SKILL.md").write_text(
            "---\nid: no-entry\nname: No Entry\ndescription: x\ntype: code\nentry: missing.py\n---\n",
        )
        report = validate_skill(bad_dir)
        assert any(i.code == "missing_entry" for i in report.issues)

    def test_shell_missing_shebang(self, tmp_path: Path) -> None:
        path = create_skill(tmp_path, "shell-skill", "Shell", "x", SkillType.CODE, entry="run.sh")
        (path / "run.sh").write_text("echo hello\n")
        report = validate_skill(path)
        assert any(i.code == "missing_shebang" for i in report.issues)

    def test_shell_with_shebang_ok(self, tmp_path: Path) -> None:
        path = create_skill(tmp_path, "shell-ok", "Shell", "x", SkillType.CODE, entry="run.sh")
        (path / "run.sh").write_text("#!/bin/bash\necho hello\n")
        report = validate_skill(path)
        assert not any(i.code == "missing_shebang" for i in report.issues)


class TestValidateContent:
    def test_short_description_warns(self, tmp_path: Path) -> None:
        path = create_skill(tmp_path, "short-desc", "Short", "x", SkillType.PROMPT, instructions="OK")
        report = validate_skill(path)
        assert any(i.code == "short_description" for i in report.issues)

    def test_no_tags_suggests(self, tmp_path: Path) -> None:
        path = create_skill(tmp_path, "no-tags", "No Tags", "A longer description here", SkillType.PROMPT, instructions="OK")
        report = validate_skill(path)
        assert any(i.code == "no_tags" for i in report.issues)

    def test_empty_prompt_body_warns(self, tmp_path: Path) -> None:
        bad_dir = tmp_path / "empty-body"
        bad_dir.mkdir()
        (bad_dir / "SKILL.md").write_text(
            "---\nid: empty-body\nname: Empty\ndescription: A prompt with no body\ntype: prompt\n---\n",
        )
        report = validate_skill(bad_dir)
        assert any(i.code == "empty_body" for i in report.issues)

    def test_semantic_version_suggestion(self, tmp_path: Path) -> None:
        path = create_skill(tmp_path, "bad-ver", "Ver", "Desc", SkillType.PROMPT, version="v1", instructions="OK")
        report = validate_skill(path)
        assert any(i.code == "non_semantic_version" for i in report.issues)


class TestValidateSecurity:
    def test_risk_pattern_detected(self, tmp_path: Path) -> None:
        path = create_skill(tmp_path, "risky", "Risky", "Desc", SkillType.CODE)
        # Inject a risky pattern
        main_py = path / "main.py"
        content = main_py.read_text()
        content += "\nimport os\nos.system('rm -rf /')\n"
        main_py.write_text(content)
        report = validate_skill(path)
        assert any(i.code.startswith("security_") for i in report.issues)

    def test_id_mismatch_warns(self, tmp_path: Path) -> None:
        bad_dir = tmp_path / "wrong-id"
        bad_dir.mkdir()
        (bad_dir / "SKILL.md").write_text(
            "---\nid: different-id\nname: Wrong\ndescription: x\ntype: prompt\n---\n",
        )
        report = validate_skill(bad_dir)
        assert any(i.code == "id_mismatch" for i in report.issues)


class TestReport:
    def test_to_dict(self) -> None:
        report = validate_skill(Path("/nonexistent"))
        d = report.to_dict()
        assert d["skill_id"] == "nonexistent"
        assert "summary" in d
        assert "issues" in d

    def test_issue_categories(self) -> None:
        issues = [
            ValidationIssue("error", "e1", "err"),
            ValidationIssue("warning", "w1", "warn"),
            ValidationIssue("suggestion", "s1", "sugg"),
        ]
        from js.skills.validator import ValidationReport
        report = ValidationReport(skill_id="x", issues=issues)
        assert len(report.errors) == 1
        assert len(report.warnings) == 1
        assert len(report.suggestions) == 1

    def test_quick_validation(self, tmp_path: Path) -> None:
        from js.skills.validator import validate_quick
        path = create_skill(tmp_path, "quick", "Quick", "Desc", SkillType.PROMPT, instructions="OK")
        assert validate_quick(path) is True
