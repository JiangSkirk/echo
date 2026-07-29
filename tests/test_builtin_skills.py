"""Integration tests for builtin skills."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from js.security.sandbox import SandboxExecutor
from js.skills.executor import execute_skill
from js.skills.manager import SkillManager
from js.skills.spec import SkillType


@pytest.fixture
def manager(tmp_path: Path) -> SkillManager:
    """SkillManager with builtins loaded."""
    mgr = SkillManager(tmp_path / "skills", tmp_path / "state")
    return mgr


@pytest.fixture
def skill_sandbox(tmp_path: Path) -> SandboxExecutor:
    return SandboxExecutor(tmp_path, strict_isolation=True)


class TestFileSearchSkill:
    """Test file-search (code skill) with its main.py entry."""

    @pytest.fixture
    def file_search_spec(self, manager: SkillManager):
        spec = manager.get_skill("file-search")
        if spec is None:
            pytest.skip("file-search skill not loaded")
        return spec

    def test_entry_file_exists(self, file_search_spec) -> None:
        """main.py must exist for code-type skills."""
        assert file_search_spec.type == SkillType.CODE
        entry = file_search_spec.path / file_search_spec.entry
        assert entry.exists(), f"Entry file missing: {entry}"

    @pytest.mark.asyncio
    async def test_file_search_by_name(
        self, file_search_spec, tmp_path: Path, skill_sandbox: SandboxExecutor
    ) -> None:
        """Search files by name pattern relative to the skill workspace."""
        (tmp_path / "test_a.py").write_text("# a")
        (tmp_path / "test_b.py").write_text("# b")
        (tmp_path / "readme.md").write_text("# readme")

        result = await execute_skill(
            spec=file_search_spec,
            args={"pattern": "*.py", "path": ".", "max_results": 10},
            workspace=tmp_path,
            sandbox=skill_sandbox,
        )
        assert result["success"] is True
        out = json.loads(result["output"])
        assert out["count"] == 2
        paths = list(out["results"])
        assert any("test_a.py" in p for p in paths)
        assert any("test_b.py" in p for p in paths)

    @pytest.mark.asyncio
    async def test_file_search_by_content(
        self, file_search_spec, tmp_path: Path, skill_sandbox: SandboxExecutor
    ) -> None:
        """Search files by content relative to the skill workspace."""
        (tmp_path / "foo.py").write_text("def hello(): pass\n")
        (tmp_path / "bar.py").write_text("def world(): pass\n")

        result = await execute_skill(
            spec=file_search_spec,
            args={"content": "hello", "path": ".", "max_results": 10},
            workspace=tmp_path,
            sandbox=skill_sandbox,
        )
        assert result["success"] is True
        out = json.loads(result["output"])
        assert out["count"] >= 1
        assert any("foo.py" in r for r in out["results"])

    @pytest.mark.asyncio
    async def test_file_search_no_results(
        self, file_search_spec, tmp_path: Path, skill_sandbox: SandboxExecutor
    ) -> None:
        """Graceful handling when nothing matches — returns friendly message."""
        result = await execute_skill(
            spec=file_search_spec,
            args={"pattern": "*.nonexistent", "path": "."},
            workspace=tmp_path,
            sandbox=skill_sandbox,
        )
        assert result["success"] is True
        out = json.loads(result["output"])
        assert out["count"] == 1
        assert "No files matching" in out["results"][0]

    @pytest.mark.asyncio
    async def test_file_search_rejects_absolute_path(
        self,
        file_search_spec,
        tmp_path: Path,
        skill_sandbox: SandboxExecutor,
    ) -> None:
        """Absolute paths outside the workspace must be rejected."""
        result = await execute_skill(
            spec=file_search_spec,
            args={"pattern": "*.py", "path": "/etc"},
            workspace=tmp_path,
            sandbox=skill_sandbox,
        )
        assert result["success"] is True
        out = json.loads(result["output"])
        assert out["count"] == 0
        assert any("Access denied" in r and "Absolute paths" in r for r in out["results"])

    @pytest.mark.asyncio
    async def test_file_search_rejects_parent_traversal(
        self,
        file_search_spec,
        tmp_path: Path,
        skill_sandbox: SandboxExecutor,
    ) -> None:
        """Parent-directory traversal must be rejected."""
        result = await execute_skill(
            spec=file_search_spec,
            args={"pattern": "*.py", "path": ".."},
            workspace=tmp_path,
            sandbox=skill_sandbox,
        )
        assert result["success"] is True
        out = json.loads(result["output"])
        assert out["count"] == 0
        assert any("Access denied" in r and "Parent-directory" in r for r in out["results"])

    @pytest.mark.asyncio
    async def test_file_search_rejects_symlink_escape(
        self,
        file_search_spec,
        tmp_path: Path,
        skill_sandbox: SandboxExecutor,
    ) -> None:
        """Symlink escapes outside the workspace must be rejected."""
        outside = tmp_path / ".." / "outside_search"
        outside.mkdir(parents=True, exist_ok=True)
        (outside / "secret.txt").write_text("secret")

        link_dir = tmp_path / "link_escape"
        link_dir.symlink_to(outside, target_is_directory=True)

        result = await execute_skill(
            spec=file_search_spec,
            args={"pattern": "*.txt", "path": "link_escape"},
            workspace=tmp_path,
            sandbox=skill_sandbox,
        )
        assert result["success"] is True
        out = json.loads(result["output"])
        assert out["count"] == 0
        assert any("Access denied" in r and "escapes workspace" in r for r in out["results"])

    @pytest.mark.asyncio
    async def test_file_search_content_skips_symlink_file_escape(
        self,
        file_search_spec,
        tmp_path: Path,
        skill_sandbox: SandboxExecutor,
    ) -> None:
        """Content search must not follow symlink files outside the workspace."""
        outside = tmp_path.parent / "outside_search_file"
        outside.mkdir(parents=True, exist_ok=True)
        (outside / "secret.txt").write_text("outside-secret")
        (tmp_path / "visible.txt").write_text("inside-ok")

        (tmp_path / "linked-secret.txt").symlink_to(outside / "secret.txt")

        result = await execute_skill(
            spec=file_search_spec,
            args={"content": "outside-secret", "path": ".", "max_results": 10},
            workspace=tmp_path,
            sandbox=skill_sandbox,
        )
        assert result["success"] is True
        out = json.loads(result["output"])
        assert out["count"] == 1
        assert "No files found" in out["results"][0]

    @pytest.mark.asyncio
    async def test_file_search_can_search_subdirectory(
        self,
        file_search_spec,
        tmp_path: Path,
        skill_sandbox: SandboxExecutor,
    ) -> None:
        """Searching a subdirectory inside the workspace must work."""
        subdir = tmp_path / "src"
        subdir.mkdir()
        (subdir / "module.py").write_text("x = 1")

        result = await execute_skill(
            spec=file_search_spec,
            args={"pattern": "*.py", "path": "src", "max_results": 10},
            workspace=tmp_path,
            sandbox=skill_sandbox,
        )
        assert result["success"] is True
        out = json.loads(result["output"])
        assert out["count"] == 1
        assert any("module.py" in r for r in out["results"])


class TestPromptSkillsLoaded:
    """Verify prompt-type builtin skills are loadable and have content."""

    @pytest.mark.parametrize(
        "skill_id",
        [
            "arxiv-research",
            "code-review",
            "excel-helper",
            "pdf-helper",
            "shell-safety",
            "web-fetch",
        ],
    )
    def test_skill_loaded(self, manager: SkillManager, skill_id: str) -> None:
        spec = manager.get_skill(skill_id)
        assert spec is not None, f"Skill {skill_id} not loaded"
        assert spec.type == SkillType.PROMPT
        assert spec.full_content
        assert len(spec.full_content) > 100

    @pytest.mark.parametrize(
        "skill_id,required_param",
        [
            ("arxiv-research", "query"),
            ("code-review", "code"),
            ("shell-safety", "command"),
            ("web-fetch", "url"),
        ],
    )
    def test_skill_has_required_param(
        self, manager: SkillManager, skill_id: str, required_param: str
    ) -> None:
        spec = manager.get_skill(skill_id)
        assert spec is not None
        params = spec.metadata.get("parameters", [])
        param_names = {p["name"] for p in params}
        assert required_param in param_names


class TestPromptSkillExecution:
    """Test prompt skill execution path."""

    @pytest.mark.asyncio
    async def test_code_review_prompt_execution(
        self, manager: SkillManager, tmp_path: Path
    ) -> None:
        spec = manager.get_skill("code-review")
        assert spec is not None

        llm_caller = AsyncMock(
            return_value="[MEDIUM] Style: Missing type hints\nSuggestion: Add typing"
        )
        result = await execute_skill(
            spec=spec,
            args={"code": "def add(a, b): return a + b", "language": "python"},
            workspace=tmp_path,
            llm_caller=llm_caller,
        )
        assert result["success"] is True
        assert "skill_applied" in result
        llm_caller.assert_called_once()
        prompt = llm_caller.call_args[0][0]
        assert "def add(a, b)" in prompt

    @pytest.mark.asyncio
    async def test_shell_safety_prompt_execution(
        self, manager: SkillManager, tmp_path: Path
    ) -> None:
        spec = manager.get_skill("shell-safety")
        assert spec is not None

        llm_caller = AsyncMock(return_value="[CRITICAL] rm -rf /: System destruction risk")
        result = await execute_skill(
            spec=spec,
            args={"command": "rm -rf /"},
            workspace=tmp_path,
            llm_caller=llm_caller,
        )
        assert result["success"] is True
        llm_caller.assert_called_once()
        prompt = llm_caller.call_args[0][0]
        assert "rm -rf /" in prompt

    @pytest.mark.asyncio
    async def test_arxiv_research_prompt_execution(
        self, manager: SkillManager, tmp_path: Path
    ) -> None:
        spec = manager.get_skill("arxiv-research")
        assert spec is not None

        llm_caller = AsyncMock(return_value="1. [2401.00001] Sample Paper\n   Authors: A. Author")
        result = await execute_skill(
            spec=spec,
            args={"query": "transformer"},
            workspace=tmp_path,
            llm_caller=llm_caller,
        )
        assert result["success"] is True
        llm_caller.assert_called_once()
        prompt = llm_caller.call_args[0][0]
        assert "transformer" in prompt

    @pytest.mark.asyncio
    async def test_web_fetch_prompt_execution(self, manager: SkillManager, tmp_path: Path) -> None:
        spec = manager.get_skill("web-fetch")
        assert spec is not None

        llm_caller = AsyncMock(return_value="Fetched content: Hello World")
        result = await execute_skill(
            spec=spec,
            args={"url": "https://example.com", "max_length": 1000},
            workspace=tmp_path,
            llm_caller=llm_caller,
        )
        assert result["success"] is True
        llm_caller.assert_called_once()
        prompt = llm_caller.call_args[0][0]
        assert "example.com" in prompt


class TestSkillPrerequisites:
    """Verify prerequisite declarations are present where needed."""

    def test_arxiv_has_curl_prerequisite(self, manager: SkillManager) -> None:
        spec = manager.get_skill("arxiv-research")
        assert spec is not None
        preqs = spec.prerequisites
        assert preqs is not None
        assert "curl" in preqs.commands

    def test_file_search_has_find_grep_prerequisite(self, manager: SkillManager) -> None:
        spec = manager.get_skill("file-search")
        assert spec is not None
        preqs = spec.prerequisites
        assert preqs is not None
        assert "find" in preqs.commands
        assert "grep" in preqs.commands

    def test_web_fetch_has_curl_prerequisite(self, manager: SkillManager) -> None:
        spec = manager.get_skill("web-fetch")
        assert spec is not None
        preqs = spec.prerequisites
        assert preqs is not None
        assert "curl" in preqs.commands


class TestWorkflowSkillExecution:
    """Test workflow skill execution with prompt, shell, and skill steps."""

    @pytest.mark.asyncio
    async def test_workflow_prompt_steps(self, tmp_path: Path) -> None:
        """Workflow with prompt steps calls llm_caller."""
        from js.skills.spec import SkillSpec, SkillType, TrustLevel

        spec = SkillSpec(
            id="test-workflow",
            name="Test Workflow",
            type=SkillType.WORKFLOW,
            trust_level=TrustLevel.BUILTIN,
            metadata={
                "workflow": {
                    "steps": [
                        {"type": "prompt", "input": "Hello {name}"},
                        {"type": "prompt", "input": "Goodbye {name}"},
                    ]
                }
            },
        )

        llm_caller = AsyncMock(side_effect=["Hi there", "See ya"])
        result = await execute_skill(
            spec=spec,
            args={"name": "Alice"},
            workspace=tmp_path,
            llm_caller=llm_caller,
        )
        assert result["success"] is True
        assert result["steps_executed"] == 2
        assert result["steps_failed"] == 0
        steps = json.loads(result["output"])
        assert steps[0]["output"] == "Hi there"
        assert steps[1]["output"] == "See ya"
        assert llm_caller.call_count == 2

    @pytest.mark.asyncio
    async def test_workflow_skill_step_resolves_subskill(self, tmp_path: Path) -> None:
        """Workflow with skill step delegates to skill_resolver."""
        from js.skills.spec import SkillSpec, SkillType, TrustLevel

        spec = SkillSpec(
            id="test-workflow-with-skill",
            name="Test Workflow With Skill",
            type=SkillType.WORKFLOW,
            trust_level=TrustLevel.BUILTIN,
            metadata={
                "workflow": {
                    "steps": [
                        {"type": "skill", "skill_id": "sub-skill", "args": {"x": "1"}},
                    ]
                }
            },
        )

        async def skill_resolver(skill_id: str, args: dict) -> dict:
            return {"success": True, "output": f"resolved {skill_id} with {args}"}

        result = await execute_skill(
            spec=spec,
            args={"name": "Alice"},
            workspace=tmp_path,
            skill_resolver=skill_resolver,
        )
        assert result["success"] is True
        steps = json.loads(result["output"])
        assert steps[0]["status"] == "success"
        assert "resolved sub-skill" in steps[0]["output"]

    @pytest.mark.asyncio
    async def test_workflow_skill_step_missing_resolver(self, tmp_path: Path) -> None:
        """Workflow skill step without resolver is marked pending."""
        from js.skills.spec import SkillSpec, SkillType, TrustLevel

        spec = SkillSpec(
            id="test-workflow-no-resolver",
            name="Test Workflow No Resolver",
            type=SkillType.WORKFLOW,
            trust_level=TrustLevel.BUILTIN,
            metadata={
                "workflow": {
                    "steps": [
                        {"type": "skill", "skill_id": "sub-skill"},
                    ]
                }
            },
        )

        result = await execute_skill(
            spec=spec,
            args={},
            workspace=tmp_path,
        )
        # Pending is not a failure — the step simply can't be resolved here
        assert result["success"] is True
        steps = json.loads(result["output"])
        assert steps[0]["status"] == "pending"
        assert "resolver" in steps[0]["note"]

    @pytest.mark.asyncio
    async def test_workflow_condition_skips_step(self, tmp_path: Path) -> None:
        """Workflow condition causes step skip."""
        from js.skills.spec import SkillSpec, SkillType, TrustLevel

        spec = SkillSpec(
            id="test-workflow-condition",
            name="Test Workflow Condition",
            type=SkillType.WORKFLOW,
            trust_level=TrustLevel.BUILTIN,
            metadata={
                "workflow": {
                    "steps": [
                        {
                            "type": "prompt",
                            "input": "skip me",
                            "condition": {"if": "mode", "eq": "debug"},
                        },
                        {"type": "prompt", "input": "run me"},
                    ]
                }
            },
        )

        llm_caller = AsyncMock(return_value="ok")
        result = await execute_skill(
            spec=spec,
            args={"mode": "production"},
            workspace=tmp_path,
            llm_caller=llm_caller,
        )
        assert result["success"] is True
        steps = json.loads(result["output"])
        assert steps[0]["status"] == "skipped"
        assert steps[1]["status"] == "success"
        assert llm_caller.call_count == 1


class TestMetaSkillExecution:
    """Test meta skill execution delegates to sub-skills."""

    @pytest.mark.asyncio
    async def test_meta_skill_executes_subskills(self, tmp_path: Path) -> None:
        """Meta skill calls skill_resolver for each sub-skill."""
        from js.skills.spec import SkillSpec, SkillType, TrustLevel

        spec = SkillSpec(
            id="test-meta",
            name="Test Meta",
            type=SkillType.META,
            trust_level=TrustLevel.BUILTIN,
            metadata={
                "workflow": {
                    "steps": [
                        {"type": "skill", "skill_id": "step-a"},
                        {"type": "skill", "skill_id": "step-b", "arg_mapping": {"task": "job"}},
                    ]
                }
            },
        )

        calls: list[tuple[str, dict]] = []

        async def skill_resolver(skill_id: str, args: dict) -> dict:
            calls.append((skill_id, args))
            return {"success": True, "output": f"done {skill_id}"}

        result = await execute_skill(
            spec=spec,
            args={"job": "test-task"},
            workspace=tmp_path,
            skill_resolver=skill_resolver,
        )
        assert result["success"] is True
        assert len(calls) == 2
        assert calls[0] == ("step-a", {"job": "test-task"})
        assert calls[1] == ("step-b", {"task": "test-task"})
        steps = json.loads(result["output"])
        assert steps[0]["output"] == "done step-a"
        assert steps[1]["output"] == "done step-b"

    @pytest.mark.asyncio
    async def test_meta_skill_subskill_failure(self, tmp_path: Path) -> None:
        """Meta skill reports failure when sub-skill fails."""
        from js.skills.spec import SkillSpec, SkillType, TrustLevel

        spec = SkillSpec(
            id="test-meta-fail",
            name="Test Meta Fail",
            type=SkillType.META,
            trust_level=TrustLevel.BUILTIN,
            metadata={
                "workflow": {
                    "steps": [
                        {"type": "skill", "skill_id": "step-a"},
                        {"type": "skill", "skill_id": "step-b"},
                    ]
                }
            },
        )

        async def skill_resolver(skill_id: str, args: dict) -> dict:
            if skill_id == "step-b":
                return {"success": False, "error": "b failed"}
            return {"success": True, "output": "ok"}

        result = await execute_skill(
            spec=spec,
            args={},
            workspace=tmp_path,
            skill_resolver=skill_resolver,
        )
        assert result["success"] is False
        assert result["steps_failed"] == 1
        steps = json.loads(result["output"])
        assert steps[1]["status"] == "error"
        assert "b failed" in steps[1]["error"]

    @pytest.mark.asyncio
    async def test_meta_skill_missing_skill_id(self, tmp_path: Path) -> None:
        """Meta skill step without skill_id reports error."""
        from js.skills.spec import SkillSpec, SkillType, TrustLevel

        spec = SkillSpec(
            id="test-meta-missing",
            name="Test Meta Missing",
            type=SkillType.META,
            trust_level=TrustLevel.BUILTIN,
            metadata={
                "workflow": {
                    "steps": [
                        {"type": "skill"},  # no skill_id
                    ]
                }
            },
        )

        async def skill_resolver(skill_id: str, args: dict) -> dict:
            return {"success": True, "output": "ok"}

        result = await execute_skill(
            spec=spec,
            args={},
            workspace=tmp_path,
            skill_resolver=skill_resolver,
        )
        assert result["success"] is False
        steps = json.loads(result["output"])
        assert steps[0]["status"] == "error"
        assert "Missing skill_id" in steps[0]["error"]

    @pytest.mark.asyncio
    async def test_meta_skill_no_resolver(self, tmp_path: Path) -> None:
        """Meta skill without resolver reports pending for all steps."""
        from js.skills.spec import SkillSpec, SkillType, TrustLevel

        spec = SkillSpec(
            id="test-meta-no-resolver",
            name="Test Meta No Resolver",
            type=SkillType.META,
            trust_level=TrustLevel.BUILTIN,
            metadata={
                "workflow": {
                    "steps": [
                        {"type": "skill", "skill_id": "step-a"},
                    ]
                }
            },
        )

        result = await execute_skill(
            spec=spec,
            args={},
            workspace=tmp_path,
        )
        assert result["success"] is True  # No actual failure, just pending
        steps = json.loads(result["output"])
        assert steps[0]["status"] == "pending"
