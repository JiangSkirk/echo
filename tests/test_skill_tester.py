"""Tests for the skill test generation and execution framework."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from js.skills.creator import create_skill
from js.skills.spec import SkillType
from js.skills.tester import generate_tests, run_skill_tests


class TestGenerateCodeTests:
    def test_generates_test_file(self, tmp_path: Path) -> None:
        path = create_skill(
            tmp_path, "code-test", "Code Test", "Desc", SkillType.CODE,
            parameters=[{"name": "name", "type": "string", "description": "Name", "required": True}],
        )
        files = generate_tests(path)
        assert len(files) == 1
        assert files[0].name == "test_code_test.py"
        assert "test_basic_execution" in files[0].read_text()

    def test_test_file_has_argparse_tests(self, tmp_path: Path) -> None:
        path = create_skill(
            tmp_path, "code-arg", "Code Arg", "Desc", SkillType.CODE,
            parameters=[
                {"name": "count", "type": "integer", "description": "Count"},
                {"name": "flag", "type": "boolean", "description": "Flag"},
            ],
        )
        files = generate_tests(path)
        content = files[0].read_text()
        assert "--count" in content
        assert "--flag" in content

    def test_generates_help_test(self, tmp_path: Path) -> None:
        path = create_skill(tmp_path, "code-help", "Code Help", "Desc", SkillType.CODE)
        files = generate_tests(path)
        assert "test_help_flag" in files[0].read_text()


class TestGeneratePromptTests:
    def test_generates_prompt_eval(self, tmp_path: Path) -> None:
        path = create_skill(
            tmp_path, "prompt-eval", "Prompt Eval", "Desc", SkillType.PROMPT,
            instructions="Do X when Y.",
        )
        files = generate_tests(path)
        assert len(files) == 1
        content = files[0].read_text()
        assert "test_has_instructions" in content
        assert "test_no_broken_placeholders" in content


class TestGenerateWorkflowTests:
    def test_generates_workflow_tests(self, tmp_path: Path) -> None:
        path = create_skill(
            tmp_path, "wf-test", "WF Test", "Desc", SkillType.WORKFLOW,
            steps=[{"type": "prompt", "input": "Hello"}],
        )
        files = generate_tests(path)
        assert len(files) == 1
        content = files[0].read_text()
        assert "test_has_workflow_definition" in content


class TestGenerateMetaTests:
    def test_generates_meta_tests(self, tmp_path: Path) -> None:
        path = create_skill(
            tmp_path, "meta-test", "Meta Test", "Desc", SkillType.META,
            dependencies=["dep-a"],
        )
        files = generate_tests(path)
        assert len(files) == 1
        content = files[0].read_text()
        assert "test_has_dependencies" in content
        assert "dep-a" in content


class TestRunSkillTests:
    @pytest.mark.asyncio
    async def test_runs_tests_only_through_strict_sandbox(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        path = create_skill(tmp_path, "sandboxed", "Sandboxed", "Desc", SkillType.PROMPT)
        generate_tests(path)
        host_spawn = AsyncMock(side_effect=AssertionError("raw host spawn must not run"))
        monkeypatch.setattr("asyncio.create_subprocess_exec", host_spawn)
        sandbox = SimpleNamespace(
            workspace=path.resolve(),
            strict_isolation=True,
            network_isolation_available=lambda: True,
            filesystem_isolation_available=lambda: True,
            execute=AsyncMock(
                return_value=SimpleNamespace(
                    returncode=0,
                    stdout="1 passed",
                    stderr="",
                )
            ),
        )

        report = await run_skill_tests(path, sandbox=sandbox)

        assert report.passed is True
        sandbox.execute.assert_awaited_once()
        host_spawn.assert_not_awaited()
        assert sandbox.execute.await_args.kwargs["network_allowed"] is False
        assert sandbox.execute.await_args.kwargs["fs_restricted"] is True

    @pytest.mark.asyncio
    async def test_skill_tests_fail_closed_for_non_strict_sandbox(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        path = create_skill(tmp_path, "not-strict", "Not Strict", "Desc", SkillType.PROMPT)
        generate_tests(path)
        host_spawn = AsyncMock(side_effect=AssertionError("raw host spawn must not run"))
        monkeypatch.setattr("asyncio.create_subprocess_exec", host_spawn)
        sandbox = SimpleNamespace(
            workspace=path.resolve(),
            strict_isolation=False,
            network_isolation_available=lambda: True,
            filesystem_isolation_available=lambda: True,
        )

        report = await run_skill_tests(path, sandbox=sandbox)

        assert report.passed is False
        assert "strict OS sandbox" in report.results[-1].error
        host_spawn.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skill_test_generation_error_is_sanitized(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        path = create_skill(tmp_path, "generation-error", "Generation Error", "Desc", SkillType.PROMPT)
        private_detail = "/Users/private/.config/provider-key secret-token"
        monkeypatch.setattr(
            "js.skills.tester.generate_tests",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(private_detail)),
        )

        report = await run_skill_tests(path)

        assert report.results[-1].error == "Failed to generate skill tests safely"
        assert private_detail not in str(report.to_dict())

    @pytest.mark.asyncio
    async def test_runs_generated_code_tests(self, tmp_path: Path) -> None:
        path = create_skill(tmp_path, "run-code", "Run Code", "Desc", SkillType.CODE)
        report = await run_skill_tests(path)
        assert report.skill_id == "run-code"
        # At minimum, manifest_exists and help tests should pass
        assert report.pass_count >= 1

    @pytest.mark.asyncio
    async def test_runs_prompt_tests(self, tmp_path: Path) -> None:
        path = create_skill(
            tmp_path, "run-prompt", "Run Prompt", "Desc", SkillType.PROMPT,
            instructions="Be helpful.",
        )
        report = await run_skill_tests(path)
        assert report.pass_count >= 1

    @pytest.mark.asyncio
    async def test_missing_manifest_fails(self, tmp_path: Path) -> None:
        report = await run_skill_tests(tmp_path / "nonexistent")
        assert report.passed is False
        assert any("not found" in r.error for r in report.results)

    def test_report_summary(self, tmp_path: Path) -> None:
        from js.skills.tester import TestReport, TestResult
        report = TestReport(
            skill_id="x",
            results=[
                TestResult("a", True),
                TestResult("b", False, error="boom"),
            ],
        )
        assert report.passed is False
        assert report.pass_count == 1
        assert report.fail_count == 1
        d = report.to_dict()
        assert d["summary"]["pass"] == 1
        assert d["summary"]["fail"] == 1
