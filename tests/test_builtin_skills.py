"""Integration tests for the 5 builtin skills.

Skills tested:
- arxiv-research (prompt)
- code-review (prompt)
- file-search (code)
- shell-safety (prompt)
- web-fetch (prompt)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from js.skills.executor import execute_skill
from js.skills.manager import SkillManager
from js.skills.spec import SkillType


@pytest.fixture
def manager(tmp_path: Path) -> SkillManager:
    """SkillManager with builtins loaded."""
    mgr = SkillManager(tmp_path / "skills", tmp_path / "state")
    return mgr


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
    async def test_file_search_by_name(self, file_search_spec, tmp_path: Path) -> None:
        """Search files by name pattern."""
        # Create test files
        (tmp_path / "test_a.py").write_text("# a")
        (tmp_path / "test_b.py").write_text("# b")
        (tmp_path / "readme.md").write_text("# readme")

        result = await execute_skill(
            spec=file_search_spec,
            args={"pattern": "*.py", "path": str(tmp_path), "max_results": 10},
            workspace=tmp_path,
        )
        assert result["success"] is True
        out = json.loads(result["output"])
        assert out["count"] == 2
        paths = list(out["results"])
        assert any("test_a.py" in p for p in paths)
        assert any("test_b.py" in p for p in paths)

    @pytest.mark.asyncio
    async def test_file_search_by_content(self, file_search_spec, tmp_path: Path) -> None:
        """Search files by content."""
        (tmp_path / "foo.py").write_text("def hello(): pass\n")
        (tmp_path / "bar.py").write_text("def world(): pass\n")

        result = await execute_skill(
            spec=file_search_spec,
            args={"content": "hello", "path": str(tmp_path), "max_results": 10},
            workspace=tmp_path,
        )
        assert result["success"] is True
        out = json.loads(result["output"])
        assert out["count"] >= 1
        assert any("foo.py" in r for r in out["results"])

    @pytest.mark.asyncio
    async def test_file_search_no_results(self, file_search_spec, tmp_path: Path) -> None:
        """Graceful handling when nothing matches — returns friendly message."""
        result = await execute_skill(
            spec=file_search_spec,
            args={"pattern": "*.nonexistent", "path": str(tmp_path)},
            workspace=tmp_path,
        )
        assert result["success"] is True
        out = json.loads(result["output"])
        assert out["count"] == 1
        assert "No files matching" in out["results"][0]


class TestPromptSkillsLoaded:
    """Verify prompt-type builtin skills are loadable and have content."""

    @pytest.mark.parametrize("skill_id", [
        "arxiv-research",
        "code-review",
        "shell-safety",
        "web-fetch",
    ])
    def test_skill_loaded(self, manager: SkillManager, skill_id: str) -> None:
        spec = manager.get_skill(skill_id)
        assert spec is not None, f"Skill {skill_id} not loaded"
        assert spec.type == SkillType.PROMPT
        assert spec.full_content
        assert len(spec.full_content) > 100

    @pytest.mark.parametrize("skill_id,required_param", [
        ("arxiv-research", "query"),
        ("code-review", "code"),
        ("shell-safety", "command"),
        ("web-fetch", "url"),
    ])
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
    async def test_code_review_prompt_execution(self, manager: SkillManager, tmp_path: Path) -> None:
        spec = manager.get_skill("code-review")
        assert spec is not None

        llm_caller = AsyncMock(return_value="[MEDIUM] Style: Missing type hints\nSuggestion: Add typing")
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
    async def test_shell_safety_prompt_execution(self, manager: SkillManager, tmp_path: Path) -> None:
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
    async def test_arxiv_research_prompt_execution(self, manager: SkillManager, tmp_path: Path) -> None:
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
