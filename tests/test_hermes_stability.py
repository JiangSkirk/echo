"""Tests for Hermes bridge stability, integration, and security enhancements."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from js.security.sandbox import SandboxExecutor
from js.skills.executor import execute_skill
from js.skills.hermes_bridge import (
    HermesBridgeStats,
    _infer_parameters_from_script,
    get_bridge_stats,
    is_hermes_skill,
)
from js.skills.security import runtime_security_check
from js.skills.spec import SkillSpec, SkillType


def _strict_sandbox(workspace: Path) -> SandboxExecutor:
    workspace.mkdir(parents=True, exist_ok=True)
    return SandboxExecutor(workspace, strict_isolation=True)


class TestHermesBridgeStats:
    def test_stats_initial_state(self):
        stats = HermesBridgeStats()
        assert stats.total_loaded == 0
        assert stats.failed_loads == 0
        assert stats.prompt_count == 0
        assert stats.code_count == 0
        assert stats.refresh_count == 0

    def test_stats_to_dict(self):
        stats = HermesBridgeStats()
        stats.total_loaded = 10
        stats.failed_loads = 2
        d = stats.to_dict()
        assert d["total_loaded"] == 10
        assert d["failed_loads"] == 2
        assert "last_refresh_time" in d

    def test_get_bridge_stats_singleton(self):
        s1 = get_bridge_stats()
        s2 = get_bridge_stats()
        assert s1 is s2


class TestRuntimeSecurityCheck:
    def test_integrity_check_passes_for_unchanged_skill(self, tmp_path: Path):
        skill_dir = tmp_path / "safe_skill"
        skill_dir.mkdir()
        manifest = skill_dir / "SKILL.md"
        manifest.write_text("---\nname: safe\ndescription: Safe skill\n---\n")
        spec = SkillSpec(id="hermes:safe", name="safe", path=skill_dir, type=SkillType.PROMPT)
        spec.content_hash = spec.compute_hash()
        ok, warnings = runtime_security_check(spec)
        assert ok is True
        assert warnings == []

    def test_integrity_check_fails_when_content_changed(self, tmp_path: Path):
        skill_dir = tmp_path / "tampered_skill"
        skill_dir.mkdir()
        manifest = skill_dir / "SKILL.md"
        manifest.write_text("---\nname: safe\ndescription: Safe skill\n---\n")
        spec = SkillSpec(
            id="hermes:tampered", name="tampered", path=skill_dir, type=SkillType.PROMPT
        )
        spec.content_hash = "old_hash_1234"
        ok, warnings = runtime_security_check(spec)
        assert ok is False  # Integrity failure now blocks execution
        assert any("changed" in w for w in warnings)

    def test_quarantine_detection(self, tmp_path: Path):
        skill_dir = tmp_path / "quarantine" / "suspicious"
        skill_dir.mkdir(parents=True)
        manifest = skill_dir / "SKILL.md"
        manifest.write_text("---\nname: suspicious\n---\n")
        spec = SkillSpec(
            id="hermes:suspicious", name="suspicious", path=skill_dir, type=SkillType.PROMPT
        )
        spec.content_hash = spec.compute_hash()
        ok, warnings = runtime_security_check(spec)
        assert ok is False
        assert any("quarantine" in w.lower() for w in warnings)

    def test_sensitive_path_detection(self, tmp_path: Path):
        skill_dir = tmp_path / "leaky_skill"
        skill_dir.mkdir()
        script = skill_dir / "main.py"
        script.write_text("import os\nssh = os.path.expanduser('~/.ssh/id_rsa')\n")
        manifest = skill_dir / "SKILL.md"
        manifest.write_text("---\nname: leaky\n---\n")
        spec = SkillSpec(
            id="hermes:leaky",
            name="leaky",
            path=skill_dir,
            type=SkillType.CODE,
            entry="main.py",
        )
        spec.content_hash = spec.compute_hash()
        ok, warnings = runtime_security_check(spec)
        assert ok is False  # Sensitive-path access now blocks execution
        assert any("sensitive" in w.lower() for w in warnings)

    def test_no_warnings_for_safe_script(self, tmp_path: Path):
        skill_dir = tmp_path / "safe_code"
        skill_dir.mkdir()
        script = skill_dir / "main.py"
        script.write_text("print('hello world')\n")
        manifest = skill_dir / "SKILL.md"
        manifest.write_text("---\nname: safe\n---\n")
        spec = SkillSpec(
            id="hermes:safe-code",
            name="safe-code",
            path=skill_dir,
            type=SkillType.CODE,
            entry="main.py",
        )
        spec.content_hash = spec.compute_hash()
        ok, warnings = runtime_security_check(spec)
        assert ok is True
        assert warnings == []


class TestRefreshFunctionality:
    def test_refresh_adds_new_hermes_skills(self, tmp_path: Path, monkeypatch):
        """Test that refresh_hermes_skills picks up new skills."""
        from js.skills.manager import SkillManager

        # Create a fake Hermes home
        fake_hermes = tmp_path / ".hermes"
        fake_skills = fake_hermes / "skills"
        fake_skills.mkdir(parents=True)

        # Create a skill
        skill_dir = fake_skills / "test-category" / "test-refresh"
        skill_dir.mkdir(parents=True)
        skill_dir.joinpath("SKILL.md").write_text("""---
name: test-refresh
description: A refresh test skill
---
""")

        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("HERMES_HOME", raising=False)
        monkeypatch.setattr("js.skills.hermes_bridge.DEFAULT_HERMES_HOME", fake_hermes)
        monkeypatch.setattr("js.skills.hermes_bridge.HERMES_SKILLS_DIR", fake_skills)

        state_dir = tmp_path / "state"
        workspace = tmp_path / "workspace"
        manager = SkillManager(state_dir, workspace, hermes_skills_enabled=True)
        import asyncio

        asyncio.run(manager.load_hermes_async())

        assert "hermes:test-refresh" in manager.get_all()

        # Now add a new skill and refresh
        new_dir = fake_skills / "test-category" / "new-skill"
        new_dir.mkdir(parents=True)
        new_dir.joinpath("SKILL.md").write_text("""---
name: new-skill
description: New after refresh
---
""")

        result = manager.refresh_hermes_skills()
        assert result["success"] is True
        assert "hermes:new-skill" in manager.get_all()

    def test_refresh_removes_deleted_hermes_skills(self, tmp_path: Path, monkeypatch):
        """Test that refresh removes deleted Hermes skills."""
        from js.skills.manager import SkillManager

        fake_hermes = tmp_path / ".hermes"
        fake_skills = fake_hermes / "skills"
        fake_skills.mkdir(parents=True)

        skill_dir = fake_skills / "to-delete"
        skill_dir.mkdir()
        skill_dir.joinpath("SKILL.md").write_text("---\nname: to-delete\n---\n")

        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("HERMES_HOME", raising=False)
        monkeypatch.setattr("js.skills.hermes_bridge.DEFAULT_HERMES_HOME", fake_hermes)
        monkeypatch.setattr("js.skills.hermes_bridge.HERMES_SKILLS_DIR", fake_skills)

        state_dir = tmp_path / "state"
        workspace = tmp_path / "workspace"
        manager = SkillManager(state_dir, workspace, hermes_skills_enabled=True)
        import asyncio

        asyncio.run(manager.load_hermes_async())

        assert "hermes:to-delete" in manager.get_all()

        # Delete the skill directory
        import shutil

        shutil.rmtree(skill_dir)

        result = manager.refresh_hermes_skills()
        assert result["success"] is True
        assert "hermes:to-delete" not in manager.get_all()


class TestHermesSkillExecutionSecurity:
    def test_hermes_skill_execution_blocked_in_quarantine(self, tmp_path: Path):
        skill_dir = tmp_path / ".hub" / "quarantine" / "dangerous"
        skill_dir.mkdir(parents=True)
        script = skill_dir / "main.py"
        script.write_text("print('I am dangerous')\n")
        manifest = skill_dir / "SKILL.md"
        manifest.write_text("---\nname: dangerous\n---\n")
        spec = SkillSpec(
            id="hermes:dangerous",
            name="dangerous",
            path=skill_dir,
            type=SkillType.CODE,
            entry="main.py",
        )
        spec.content_hash = spec.compute_hash()
        result = asyncio.run(execute_skill(spec, {}, tmp_path / "workspace"))
        assert result["success"] is False
        assert result.get("security_blocked") is True
        assert "quarantine" in result["error"].lower()

    def test_hermes_skill_execution_filters_host_hermes_home(self, tmp_path: Path):
        skill_dir = tmp_path / "hermes_env_test"
        skill_dir.mkdir()
        script = skill_dir / "main.py"
        script.write_text("""
import json, os
print(json.dumps({
    "hermes_home": os.environ.get("HERMES_HOME", "NOT_SET"),
    "js_args": os.environ.get("JS_SKILL_ARGS", "{}"),
}))
""")
        manifest = skill_dir / "SKILL.md"
        manifest.write_text("---\nname: env-test\n---\n")
        spec = SkillSpec(
            id="hermes:env-test",
            name="env-test",
            path=skill_dir,
            type=SkillType.CODE,
            entry="main.py",
        )
        spec.content_hash = spec.compute_hash()
        workspace = tmp_path / "workspace"
        result = asyncio.run(
            execute_skill(
                spec,
                {"test": True},
                workspace,
                sandbox=_strict_sandbox(workspace),
            )
        )
        assert result["success"] is True
        output = json.loads(result["output"].strip())
        assert output["hermes_home"] == "NOT_SET"
        args = json.loads(output["js_args"])
        assert args["test"] is True

    def test_hermes_skill_with_sensitive_path_warning(self, tmp_path: Path):
        skill_dir = tmp_path / "sensitive_test"
        skill_dir.mkdir()
        script = skill_dir / "main.py"
        script.write_text("import os\nprint(os.path.expanduser('~/.ssh/id_rsa'))\n")
        manifest = skill_dir / "SKILL.md"
        manifest.write_text("---\nname: sensitive\n---\n")
        spec = SkillSpec(
            id="hermes:sensitive",
            name="sensitive",
            path=skill_dir,
            type=SkillType.CODE,
            entry="main.py",
        )
        spec.content_hash = spec.compute_hash()
        # Runtime check now blocks execution for sensitive-path references
        result = asyncio.run(execute_skill(spec, {}, tmp_path / "workspace"))
        assert result["success"] is False


class TestHermesNamespace:
    def test_is_hermes_skill(self):
        assert is_hermes_skill("hermes:plan") is True
        assert is_hermes_skill("hermes:anything") is True
        assert is_hermes_skill("plan") is False
        assert is_hermes_skill("file-search") is False

    def test_native_skill_not_affected_by_hermes_security(self, tmp_path: Path):
        """Native JS skills should not be subject to Hermes-specific security checks."""
        skill_dir = tmp_path / "native_skill"
        skill_dir.mkdir()
        script = skill_dir / "main.py"
        script.write_text("import os\nprint(os.path.expanduser('~/.ssh/id_rsa'))\n")
        spec = SkillSpec(
            id="native-test",
            name="native-test",
            path=skill_dir,
            type=SkillType.CODE,
            entry="main.py",
        )
        spec.content_hash = spec.compute_hash()
        # Native skill should not trigger Hermes quarantine check
        ok, warnings = runtime_security_check(spec)
        assert ok is False  # Sensitive-path access blocks even for native skills
        # Flag should still be present
        assert any("sensitive" in w.lower() for w in warnings)


class TestParameterInferenceRobustness:
    def test_infer_from_manual_sysargv(self, tmp_path: Path):
        """Test inference from manual sys.argv parsing (search_arxiv style)."""
        script = tmp_path / "manual_parse.py"
        script.write_text("""
args = sys.argv[1:]
query = None
max_results = 5
sort = "relevance"
i = 0
positional = []
while i < len(args):
    if args[i] == "--max" and i + 1 < len(args):
        max_results = int(args[i + 1]); i += 2
    elif args[i] == "--sort" and i + 1 < len(args):
        sort = args[i + 1]; i += 2
    else:
        positional.append(args[i]); i += 1
if positional:
    query = " ".join(positional)
""")
        params = _infer_parameters_from_script(script)
        names = {p["name"] for p in params}
        assert "max" in names
        assert "sort" in names
        assert "query" in names
        max_param = next(p for p in params if p["name"] == "max")
        assert max_param["type"] == "integer"

    def test_infer_no_false_positives(self, tmp_path: Path):
        """Ensure we don't create phantom parameters."""
        script = tmp_path / "simple.py"
        script.write_text("print('hello')")
        params = _infer_parameters_from_script(script)
        assert params == []
