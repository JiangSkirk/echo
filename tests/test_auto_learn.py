"""Tests for AutoSkillLearner."""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from js.skills.auto_learn import AutoSkillLearner


@pytest.fixture
def learner(tmp_path: Path) -> AutoSkillLearner:
    return AutoSkillLearner(skills_dir=tmp_path)


# ---------------------------------------------------------------------------
# should_learn
# ---------------------------------------------------------------------------


class TestShouldLearn:
    def test_completed_and_sufficient_turns(self, learner: AutoSkillLearner) -> None:
        assert learner.should_learn("analyze the codebase", "completed", turn_count=5) is True

    def test_not_completed(self, learner: AutoSkillLearner) -> None:
        assert learner.should_learn("query", "in_progress", turn_count=5) is False

    def test_too_few_turns(self, learner: AutoSkillLearner) -> None:
        assert learner.should_learn("query", "completed", turn_count=2) is False

    def test_cooldown_active(self, learner: AutoSkillLearner) -> None:
        learner._last_generation = time.time()  # Just generated
        assert learner.should_learn("query", "completed", turn_count=5) is False

    def test_trivial_query_too_short(self, learner: AutoSkillLearner) -> None:
        assert learner.should_learn("hi", "completed", turn_count=5) is False

    def test_exactly_min_turns(self, learner: AutoSkillLearner) -> None:
        assert learner.should_learn("query with enough turns", "completed", turn_count=3) is True

    def test_cooldown_expired(self, learner: AutoSkillLearner) -> None:
        learner._last_generation = time.time() - 700  # > 600s cooldown
        assert learner.should_learn("this is a sufficiently long query string", "completed", turn_count=5) is True


# ---------------------------------------------------------------------------
# generate_skill
# ---------------------------------------------------------------------------


class TestGenerateSkill:
    def test_generates_skill_with_tool_calls(self, learner: AutoSkillLearner) -> None:
        msg = SimpleNamespace(
            role="assistant",
            tool_calls=[
                {"function": {"name": "file_read", "arguments": '{"path":"/tmp/a"}'}},
                {"function": {"name": "shell", "arguments": '{"command":"ls"}'}},
            ],
        )
        spec = learner.generate_skill("analyze project structure", [msg])
        assert spec is not None
        assert spec.id.startswith("auto_")
        assert (learner.auto_dir / spec.id / "SKILL.md").exists()
        assert (learner.auto_dir / spec.id / "meta.json").exists()

    def test_no_tool_calls_returns_none(self, learner: AutoSkillLearner) -> None:
        msg = SimpleNamespace(role="assistant", tool_calls=[])
        spec = learner.generate_skill("simple greeting", [msg])
        assert spec is None

    def test_no_assistant_messages_returns_none(self, learner: AutoSkillLearner) -> None:
        msg = SimpleNamespace(role="user", content="hello")
        spec = learner.generate_skill("simple greeting", [msg])
        assert spec is None

    def test_deduplicates_tools(self, learner: AutoSkillLearner) -> None:
        msg = SimpleNamespace(
            role="assistant",
            tool_calls=[
                {"function": {"name": "file_read", "arguments": '{"path":"/tmp/a"}'}},
                {"function": {"name": "file_read", "arguments": '{"path":"/tmp/b"}'}},
                {"function": {"name": "shell", "arguments": '{"command":"ls"}'}},
            ],
        )
        spec = learner.generate_skill("read multiple files", [msg])
        assert spec is not None
        # Should only reference each tool once in the prompt
        content = (learner.auto_dir / spec.id / "SKILL.md").read_text()
        # file_read mentioned twice? No, deduplicated
        assert content.count("file_read") == 1

    def test_same_intent_not_duplicated(self, learner: AutoSkillLearner) -> None:
        msg = SimpleNamespace(
            role="assistant",
            tool_calls=[{"function": {"name": "shell", "arguments": '{"command":"ls"}'}}],
        )
        spec1 = learner.generate_skill("analyze project structure", [msg])
        assert spec1 is not None
        spec2 = learner.generate_skill("analyze project structure", [msg])
        assert spec2 is None  # Same intent hash already seen

    def test_skill_prompt_truncation(self, learner: AutoSkillLearner) -> None:
        # Create a message with many tool calls to exceed MAX_SKILL_LENGTH
        tool_calls = [
            {"function": {"name": f"tool_{i}", "arguments": '{"x":1}'}}
            for i in range(500)
        ]
        msg = SimpleNamespace(role="assistant", tool_calls=tool_calls)
        spec = learner.generate_skill("massive operation", [msg])
        assert spec is not None
        content = (learner.auto_dir / spec.id / "SKILL.md").read_text()
        # The _build_skill_prompt returns truncated text; the SKILL.md wraps it
        assert "[truncated]" in content

    def test_meta_json_content(self, learner: AutoSkillLearner) -> None:
        msg = SimpleNamespace(
            role="assistant",
            tool_calls=[{"function": {"name": "shell", "arguments": '{"command":"ls"}'}}],
        )
        spec = learner.generate_skill("list files", [msg])
        assert spec is not None
        import json
        meta = json.loads((learner.auto_dir / spec.id / "meta.json").read_text())
        assert meta["source_query"] == "list files"
        assert meta["tool_count"] == 1
        assert meta["turn_count"] == 1
        assert "generated_at" in meta


# ---------------------------------------------------------------------------
# _build_skill_prompt
# ---------------------------------------------------------------------------


class TestBuildSkillPrompt:
    def test_includes_user_input(self, learner: AutoSkillLearner) -> None:
        prompt = learner._build_skill_prompt("my query", [], [])
        assert "my query" in prompt

    def test_includes_tool_steps(self, learner: AutoSkillLearner) -> None:
        tool_calls = [
            {"name": "file_read"},
            {"name": "shell"},
        ]
        prompt = learner._build_skill_prompt("query", tool_calls, [])
        assert "file_read" in prompt
        assert "shell" in prompt

    def test_skips_duplicate_tools(self, learner: AutoSkillLearner) -> None:
        tool_calls = [
            {"name": "file_read"},
            {"name": "file_read"},
        ]
        prompt = learner._build_skill_prompt("query", tool_calls, [])
        assert prompt.count("file_read") == 1

    def test_truncates_long_prompt(self, learner: AutoSkillLearner) -> None:
        long_input = "x" * learner.MAX_SKILL_LENGTH
        tool_calls = [{"name": f"tool_{i}"} for i in range(200)]
        prompt = learner._build_skill_prompt(long_input, tool_calls, [])
        assert len(prompt) <= learner.MAX_SKILL_LENGTH + 20
        assert "[truncated]" in prompt
