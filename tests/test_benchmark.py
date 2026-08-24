"""Benchmark framework tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.runner import (
    BenchmarkTask,
    MockBenchmarkProvider,
    build_mock_responses_for_task,
    load_tasks,
    run_task,
    score_task,
)


class TestLoadTasks:
    """Test task loading from YAML files."""

    def test_load_tasks_from_directory(self, tmp_path: Path) -> None:
        """Load tasks from a directory containing YAML files."""
        tasks_dir = tmp_path / "tasks"
        tasks_dir.mkdir()
        (tasks_dir / "task1.yaml").write_text(
            "id: t1\nname: Test 1\ninput: hello\nscoring:\n  expected_files: []\n"
        )
        (tasks_dir / "task2.yaml").write_text(
            "id: t2\nname: Test 2\ninput: world\nsetup:\n  files:\n    - path: foo.txt\n      content: bar\nscoring:\n  expected_files: []\n"
        )

        tasks = load_tasks(tasks_dir)
        assert len(tasks) == 2
        assert tasks[0].id == "t1"
        assert tasks[1].setup_files == [{"path": "foo.txt", "content": "bar"}]

    def test_empty_directory_returns_empty(self, tmp_path: Path) -> None:
        """Empty task directory returns empty list."""
        tasks = load_tasks(tmp_path)
        assert tasks == []


class TestMockProvider:
    """Test mock provider for deterministic benchmarking."""

    @pytest.mark.asyncio
    async def test_mock_returns_scripted_responses(self) -> None:
        from js.models.providers import ChatResponse

        provider = MockBenchmarkProvider([
            ChatResponse(content="First", tool_calls=[], model="m", usage={}, finish_reason="stop"),
            ChatResponse(content="Second", tool_calls=[], model="m", usage={}, finish_reason="stop"),
        ])
        resp1 = await provider.chat([], model="m")
        resp2 = await provider.chat([], model="m")
        resp3 = await provider.chat([], model="m")  # Falls back to default
        assert resp1.content == "First"
        assert resp2.content == "Second"
        assert "Done" in (resp3.content or "")

    @pytest.mark.asyncio
    async def test_mock_tracks_tool_calls(self) -> None:
        from js.models.providers import ChatResponse

        provider = MockBenchmarkProvider([
            ChatResponse(
                content="",
                tool_calls=[{
                    "id": "c1",
                    "type": "function",
                    "function": {"name": "file_write", "arguments": "{}"},
                }],
                model="m",
                usage={},
                finish_reason="tool_calls",
            ),
        ])
        await provider.chat([], model="m")
        assert provider.tool_calls_seen == ["file_write"]


class TestScoring:
    """Test benchmark scoring logic."""

    def test_perfect_score_when_all_checks_pass(self, tmp_path: Path) -> None:
        task = BenchmarkTask(
            id="t",
            name="t",
            input="i",
            expected_files=[{"path": "a.txt", "contains": "hello"}],
            expected_output_contains=["done"],
            expected_tool_calls=["shell"],
        )
        (tmp_path / "a.txt").write_text("hello world")
        result = score_task(task, tmp_path, "done", ["shell"])
        assert result.success
        assert result.score == 1.0

    def test_partial_score_when_some_checks_fail(self, tmp_path: Path) -> None:
        task = BenchmarkTask(
            id="t",
            name="t",
            input="i",
            expected_files=[{"path": "missing.txt"}],
            expected_output_contains=["yes"],
        )
        result = score_task(task, tmp_path, "yes here", [])
        assert not result.success
        assert result.score == 0.5

    def test_zero_score_on_empty_task(self, tmp_path: Path) -> None:
        task = BenchmarkTask(id="t", name="t", input="i")
        result = score_task(task, tmp_path, "", [])
        assert result.score == 1.0  # No checks = perfect score


class TestBuildMockResponses:
    """Test mock response generation from task definitions."""

    def test_generates_tool_call_and_completion(self) -> None:
        task = BenchmarkTask(
            id="t",
            name="t",
            input="i",
            expected_tool_calls=["file_write"],
            expected_files=[{"path": "out.txt", "contains": "hi"}],
        )
        responses = build_mock_responses_for_task(task)
        assert len(responses) == 2
        assert responses[0].tool_calls is not None
        assert len(responses[0].tool_calls) == 1
        assert responses[1].content is not None

    def test_no_tool_calls_when_empty(self) -> None:
        task = BenchmarkTask(id="t", name="t", input="i")
        responses = build_mock_responses_for_task(task)
        assert len(responses) == 1
        assert responses[0].tool_calls == []

    @pytest.mark.parametrize(
        ("tool", "setup_files", "expected"),
        [
            (
                "file_delete",
                [{"path": "temp.log", "content": "temporary"}],
                {"path": "temp.log"},
            ),
            (
                "file_search",
                [
                    {"path": "alpha.txt", "content": "alpha"},
                    {"path": "gamma.py", "content": "gamma"},
                ],
                {"pattern": "*.txt", "path": "."},
            ),
        ],
    )
    def test_file_mock_calls_have_executable_arguments(
        self,
        tool: str,
        setup_files: list[dict[str, str]],
        expected: dict[str, str],
    ) -> None:
        task = BenchmarkTask(
            id="t",
            name="t",
            input="i",
            expected_tool_calls=[tool],
            setup_files=setup_files,
        )

        responses = build_mock_responses_for_task(task)

        assert responses[0].tool_calls is not None
        function = responses[0].tool_calls[0]["function"]
        assert json.loads(function["arguments"]) == expected


class TestRunTask:
    """Integration test: run a full benchmark task end-to-end."""

    @pytest.mark.asyncio
    async def test_file_write_task(self, tmp_path: Path) -> None:
        task = BenchmarkTask(
            id="write_test",
            name="Write Test",
            input="Create file x.txt with 'abc'",
            expected_files=[{"path": "x.txt", "contains": "abc"}],
            expected_tool_calls=["file_write"],
        )
        result = await run_task(task, tmp_path, mock=True)
        assert result.score >= 0.5

    @pytest.mark.asyncio
    async def test_shell_task(self, tmp_path: Path) -> None:
        task = BenchmarkTask(
            id="shell_test",
            name="Shell Test",
            input="Echo hello",
            expected_output_contains=["hello"],
            expected_tool_calls=["shell"],
        )
        result = await run_task(task, tmp_path, mock=True)
        assert result.score >= 0.5
