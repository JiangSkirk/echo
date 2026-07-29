"""Tests for the skill packaging and publishing toolkit."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

from js.skills.creator import create_skill
from js.skills.packager import (
    generate_clawhub_json,
    package_skill,
    sign_package,
    verify_package,
)
from js.skills.spec import SkillType


class TestPackageSkill:
    def test_package_prompt_skill(self, tmp_path: Path) -> None:
        path = create_skill(tmp_path, "pkg-prompt", "Pkg", "Desc", SkillType.PROMPT, instructions="OK")
        out = tmp_path / "dist"
        result = package_skill(path, out)
        assert result.success is True
        assert result.archive_path is not None
        assert result.archive_path.exists()
        assert result.manifest is not None
        assert result.manifest.skill_id == "pkg-prompt"
        assert result.manifest.file_count > 0

    def test_package_code_skill(self, tmp_path: Path) -> None:
        path = create_skill(tmp_path, "pkg-code", "Pkg Code", "Desc", SkillType.CODE)
        out = tmp_path / "dist"
        result = package_skill(path, out)
        assert result.success is True
        assert result.manifest.file_count >= 2  # SKILL.md + main.py

    def test_package_manifest_json(self, tmp_path: Path) -> None:
        path = create_skill(tmp_path, "pkg-manifest", "Pkg", "Desc", SkillType.PROMPT, instructions="OK")
        out = tmp_path / "dist"
        package_skill(path, out)
        manifest_json = out / "pkg-manifest-0.1.0.manifest.json"
        assert manifest_json.exists()
        data = json.loads(manifest_json.read_text())
        assert data["id"] == "pkg-manifest"
        assert data["content_hash"]

    def test_package_clawhub_entry(self, tmp_path: Path) -> None:
        path = create_skill(tmp_path, "pkg-hub", "Pkg", "Desc", SkillType.PROMPT, instructions="OK")
        out = tmp_path / "dist"
        result = package_skill(path, out)
        assert result.clawhub_entry is not None
        assert result.clawhub_entry["id"] == "pkg-hub"

    def test_package_zip_format(self, tmp_path: Path) -> None:
        path = create_skill(tmp_path, "pkg-zip", "Pkg", "Desc", SkillType.PROMPT, instructions="OK")
        out = tmp_path / "dist"
        result = package_skill(path, out, format="zip")
        assert result.archive_path.suffix == ".zip"

    def test_package_missing_manifest_fails(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        result = package_skill(empty, tmp_path)
        assert result.success is False
        assert "SKILL.md not found" in result.error

    def test_tar_contents(self, tmp_path: Path) -> None:
        path = create_skill(tmp_path, "pkg-tar", "Pkg", "Desc", SkillType.PROMPT, instructions="OK")
        out = tmp_path / "dist"
        result = package_skill(path, out)
        with tarfile.open(result.archive_path, "r:gz") as tar:
            names = tar.getnames()
        assert any("SKILL.md" in n for n in names)
        assert any("pkg-tar/" in n for n in names)


class TestSignAndVerify:
    def test_sign_and_verify(self, tmp_path: Path) -> None:
        from js.security.signer import generate_signing_key

        path = create_skill(tmp_path, "sign-test", "Sign", "Desc", SkillType.PROMPT, instructions="OK")
        result = package_skill(path, tmp_path)
        state_dir = tmp_path / "signing-state"
        generate_signing_key(state_dir)
        sig_path = sign_package(result.archive_path, state_dir)
        assert sig_path is not None
        assert sig_path.exists()
        assert verify_package(result.archive_path) is True

    def test_verify_missing_sig(self, tmp_path: Path) -> None:
        fake = tmp_path / "fake.tar.gz"
        fake.write_text("fake")
        assert verify_package(fake) is False


class TestClawHubIndex:
    def test_generate_index(self, tmp_path: Path) -> None:
        s1 = create_skill(tmp_path, "skill-a", "A", "Desc A", SkillType.PROMPT, instructions="OK")
        s2 = create_skill(tmp_path, "skill-b", "B", "Desc B", SkillType.CODE)
        output = tmp_path / "clawhub.json"
        result = generate_clawhub_json([s1, s2], output)
        assert result.exists()
        data = json.loads(result.read_text())
        assert data["version"] == "1.0"
        assert len(data["skills"]) == 2
        ids = {s["id"] for s in data["skills"]}
        assert ids == {"skill-a", "skill-b"}

    def test_generate_index_skips_bad_dirs(self, tmp_path: Path) -> None:
        good = create_skill(tmp_path, "good", "Good", "Desc", SkillType.PROMPT, instructions="OK")
        bad = tmp_path / "bad"
        bad.mkdir()
        output = tmp_path / "clawhub.json"
        result = generate_clawhub_json([good, bad], output)
        data = json.loads(result.read_text())
        assert len(data["skills"]) == 1
        assert data["skills"][0]["id"] == "good"


class TestPublishHelpers:
    def test_publish_to_git_dry_run(self, tmp_path: Path) -> None:
        from js.skills.packager import publish_to_git
        path = create_skill(tmp_path, "git-skill", "Git", "Desc", SkillType.PROMPT, instructions="OK")
        result = publish_to_git(path, "https://github.com/user/repo.git")
        assert result["success"] is True
        assert len(result["commands"]) > 0
        assert any("git commit" in c for c in result["commands"])
