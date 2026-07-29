"""Tests for Hermes skill optimizations in JS Agent."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from js.security.sandbox import SandboxExecutor
from js.skills.executor import (
    _build_hermes_cli_args,
    _remap_hermes_tools,
    execute_skill,
)
from js.skills.hermes_bridge import (
    _infer_parameters_from_script,
)
from js.skills.spec import SkillSpec, SkillType


def _strict_sandbox(workspace: Path) -> SandboxExecutor:
    workspace.mkdir(parents=True, exist_ok=True)
    return SandboxExecutor(workspace, strict_isolation=True)


class TestHermesCliArgs:
    def test_empty_args(self):
        assert _build_hermes_cli_args({}) == []

    def test_positional_args(self):
        result = _build_hermes_cli_args({"__args__": "hello"})
        assert result == ["hello"]

    def test_list_positional_args(self):
        result = _build_hermes_cli_args({"__args__": ["a", "b", "c"]})
        assert result == ["a", "b", "c"]

    def test_named_string_arg(self):
        result = _build_hermes_cli_args({"query": "transformer"})
        assert result == ["--query", "transformer"]

    def test_named_int_arg(self):
        result = _build_hermes_cli_args({"max_results": 10})
        assert result == ["--max-results", "10"]

    def test_boolean_true_flag(self):
        result = _build_hermes_cli_args({"timestamps": True})
        assert result == ["--timestamps"]

    def test_boolean_false_flag(self):
        result = _build_hermes_cli_args({"timestamps": False})
        assert result == []

    def test_mixed_args(self):
        result = _build_hermes_cli_args({
            "__args__": ["frame.png", "out.mp4"],
            "scene": "night",
            "duration": 6,
            "gif": True,
        })
        assert result == [
            "frame.png", "out.mp4",
            "--scene", "night",
            "--duration", "6",
            "--gif",
        ]

    def test_underscore_to_dash(self):
        result = _build_hermes_cli_args({"max_results": 5, "sort_by": "date"})
        assert "--max-results" in result
        assert "--sort-by" in result

    def test_skips_internal_keys(self):
        result = _build_hermes_cli_args({"_session_id": "abc", "query": "test"})
        assert "--_session-id" not in result
        assert "--query" in result


class TestToolRemapping:
    def test_web_extract_remapped(self):
        content = "Use web_extract(urls=['https://example.com']) to fetch content."
        result = _remap_hermes_tools(content)
        assert "browser_fetch(urls=" in result
        assert "web_extract(" not in result

    def test_write_file_remapped(self):
        content = "Then call write_file(path='test.md', content='hello')."
        result = _remap_hermes_tools(content)
        assert "file_write(path=" in result
        assert "write_file(" not in result

    def test_terminal_remapped(self):
        content = "Use terminal('ls -la') to list files."
        result = _remap_hermes_tools(content)
        assert "shell('ls -la')" in result

    def test_multiple_tools_in_one(self):
        content = (
            "First web_extract(urls=['a.com']), then write_file(path='out.md', content='data'), "
            "and finally read_file(path='out.md')."
        )
        result = _remap_hermes_tools(content)
        assert "browser_fetch(urls=" in result
        assert "file_write(path=" in result
        assert "file_read(path=" in result

    def test_no_false_positives(self):
        content = "The web_extract function is powerful."
        result = _remap_hermes_tools(content)
        # Should NOT remap when not followed by '('
        assert "web_extract function" in result


class TestParameterInference:
    def test_infer_argparse_params(self, tmp_path: Path):
        script = tmp_path / "test_script.py"
        script.write_text("""
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--output", help="Output file path", default="out.txt")
parser.add_argument("--count", type=int, help="Number of items", default=5)
parser.add_argument("--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("--scene", choices=["day", "night"], help="Scene type")
args = parser.parse_args()
""")
        params = _infer_parameters_from_script(script)
        assert len(params) == 4

        output = next(p for p in params if p["name"] == "output")
        assert output["type"] == "string"
        assert output["default"] == "out.txt"
        assert output["required"] is False

        count = next(p for p in params if p["name"] == "count")
        assert count["type"] == "integer"
        assert count["default"] == 5

        verbose = next(p for p in params if p["name"] == "verbose")
        assert verbose["type"] == "boolean"
        assert verbose["required"] is False

        scene = next(p for p in params if p["name"] == "scene")
        assert scene["enum"] == ["day", "night"]

    def test_infer_positional_args(self, tmp_path: Path):
        script = tmp_path / "clean.py"
        script.write_text("""
import sys
from pathlib import Path
unpacked_dir = Path(sys.argv[1])
""")
        params = _infer_parameters_from_script(script)
        assert len(params) >= 1
        assert any(p["name"] == "unpacked_dir" for p in params)

    def test_no_params_on_empty_script(self, tmp_path: Path):
        script = tmp_path / "empty.py"
        script.write_text("print('hello')")
        params = _infer_parameters_from_script(script)
        assert params == []


class TestHermesEnvInjection:
    def test_host_hermes_home_not_injected_into_code_skill(self, tmp_path: Path):
        """Host-scoped Hermes paths must not cross the subprocess boundary."""
        skill_dir = tmp_path / "hermes_test_skill"
        skill_dir.mkdir()
        script = skill_dir / "main.py"
        script.write_text("""
import json, os
print(json.dumps({"hermes_home": os.environ.get("HERMES_HOME", "NOT_SET")}))
""")
        manifest = skill_dir / "SKILL.md"
        manifest.write_text("""---
name: test-skill
description: Test
---
""")

        spec = SkillSpec(
            id="hermes:test-skill",
            name="test-skill",
            type=SkillType.CODE,
            entry="main.py",
            path=skill_dir,
        )

        workspace = tmp_path / "workspace"
        result = asyncio.run(
            execute_skill(spec, {}, workspace, sandbox=_strict_sandbox(workspace))
        )
        assert result["success"] is True
        output = json.loads(result["output"].strip())
        assert output["hermes_home"] == "NOT_SET"

    def test_js_skill_args_still_present(self, tmp_path: Path):
        """Verify JS_SKILL_ARGS is still passed for all skills."""
        skill_dir = tmp_path / "test_skill"
        skill_dir.mkdir()
        script = skill_dir / "main.py"
        script.write_text("""
import json, os
args = json.loads(os.environ.get("JS_SKILL_ARGS", "{}"))
print(json.dumps(args))
""")
        spec = SkillSpec(
            id="hermes:args-test",
            name="args-test",
            type=SkillType.CODE,
            entry="main.py",
            path=skill_dir,
        )

        workspace = tmp_path / "workspace"
        result = asyncio.run(
            execute_skill(
                spec,
                {"foo": "bar"},
                workspace,
                sandbox=_strict_sandbox(workspace),
            )
        )
        assert result["success"] is True
        output = json.loads(result["output"].strip())
        assert output["foo"] == "bar"

    def test_cli_args_mapped_for_hermes(self, tmp_path: Path):
        """Verify JS_SKILL_ARGS are mapped to CLI args for Hermes skills."""
        skill_dir = tmp_path / "hermes_cli_test"
        skill_dir.mkdir()
        script = skill_dir / "main.py"
        script.write_text("""
import json, sys
print(json.dumps({"argv": sys.argv}))
""")
        spec = SkillSpec(
            id="hermes:cli-test",
            name="cli-test",
            type=SkillType.CODE,
            entry="main.py",
            path=skill_dir,
        )

        workspace = tmp_path / "workspace"
        result = asyncio.run(
            execute_skill(
                spec,
                {"query": "test", "max": 10},
                workspace,
                sandbox=_strict_sandbox(workspace),
            )
        )
        assert result["success"] is True
        output = json.loads(result["output"].strip())
        argv = output["argv"]
        assert "--query" in argv
        assert "test" in argv
        assert "--max" in argv
        assert "10" in argv

    def test_non_hermes_skill_no_cli_mapping(self, tmp_path: Path):
        """Verify non-Hermes skills don't get CLI args appended."""
        skill_dir = tmp_path / "native_skill"
        skill_dir.mkdir()
        script = skill_dir / "main.py"
        script.write_text("""
import json, sys
print(json.dumps({"argv": sys.argv}))
""")
        spec = SkillSpec(
            id="native-test",
            name="native-test",
            type=SkillType.CODE,
            entry="main.py",
            path=skill_dir,
        )

        workspace = tmp_path / "workspace"
        result = asyncio.run(
            execute_skill(
                spec,
                {"query": "test"},
                workspace,
                sandbox=_strict_sandbox(workspace),
            )
        )
        assert result["success"] is True
        output = json.loads(result["output"].strip())
        argv = output["argv"]
        assert "--query" not in argv
        assert len(argv) == 1  # just script path (no CLI args appended)


class TestPromptToolRemapping:
    def test_prompt_execution_remaps_tools(self, tmp_path: Path):
        spec = SkillSpec(
            id="hermes:web-test",
            name="web-test",
            type=SkillType.PROMPT,
            full_content="Use web_extract(urls=['a.com']) then write_file(path='out.md', content='data').",
        )
        result = asyncio.run(execute_skill(spec, {}, tmp_path / "workspace"))
        assert result["success"] is True
        assert "browser_fetch(urls=" in result["output"]
        assert "file_write(path=" in result["output"]
        assert "web_extract(urls=" not in result["output"]
