"""Benchmark runner for JS Agent.

Runs a suite of tasks against the agent, scores the results, and compares
against a baseline to detect regressions.

Usage:
    python -m benchmarks.runner [--tasks-dir benchmarks/tasks] [--mock]

Exit code:
    0 if score >= baseline or no baseline exists
    1 if score < baseline - threshold (regression detected)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import yaml

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).parent.parent))

from js.agent import JSAgent
from js.config import JSSettings
from js.models.providers import ChatMessage, ChatResponse, ModelProvider


@dataclass
class BenchmarkTask:
    id: str
    name: str
    input: str
    description: str = ""
    expected_files: list[dict[str, Any]] = field(default_factory=list)
    expected_output_contains: list[str] = field(default_factory=list)
    expected_tool_calls: list[str] = field(default_factory=list)
    setup_files: list[dict[str, Any]] = field(default_factory=list)
    max_turns: int = 5
    tags: list[str] = field(default_factory=list)


@dataclass
class TaskResult:
    task_id: str
    success: bool
    score: float  # 0.0 - 1.0
    details: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0


class MockBenchmarkProvider(ModelProvider):
    """Provider that returns scripted responses for deterministic benchmarking."""

    def __init__(self, responses: list[ChatResponse]) -> None:
        self._responses = responses
        self._index = 0
        self.tool_calls_seen: list[str] = []

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        if self._index < len(self._responses):
            resp = self._responses[self._index]
            self._index += 1
            if resp.tool_calls:
                for tc in resp.tool_calls:
                    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                    name = fn.get("name", "") if isinstance(fn, dict) else ""
                    if name:
                        self.tool_calls_seen.append(name)
            return resp
        # Default: empty completion
        return ChatResponse(
            content="Done.",
            tool_calls=[],
            model="mock",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            finish_reason="stop",
        )

    def chat_stream(self, *args: Any, **kwargs: Any) -> Any:
        async def _gen() -> AsyncIterator[str]:
            yield "Done."
        return _gen()

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


def load_tasks(tasks_dir: Path) -> list[BenchmarkTask]:
    """Load all YAML task definitions from a directory."""
    tasks: list[BenchmarkTask] = []
    for path in sorted(tasks_dir.glob("*.yaml")):
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        tasks.append(BenchmarkTask(
            id=data.get("id", path.stem),
            name=data.get("name", path.stem),
            description=data.get("description", ""),
            input=data.get("input", ""),
            expected_files=data.get("scoring", {}).get("expected_files", []),
            expected_output_contains=data.get("scoring", {}).get("expected_output_contains", []),
            expected_tool_calls=data.get("scoring", {}).get("expected_tool_calls", []),
            setup_files=data.get("setup", {}).get("files", []),
            max_turns=data.get("max_turns", 5),
            tags=data.get("tags", []),
        ))
    return tasks


def score_task(
    task: BenchmarkTask,
    workspace: Path,
    assistant_output: str,
    tool_calls_seen: list[str],
) -> TaskResult:
    """Score a completed task against its expectations."""
    start = time.perf_counter()
    checks: list[tuple[str, bool]] = []

    # File checks
    for fc in task.expected_files:
        fpath = workspace / fc["path"]
        exists = fpath.exists()
        checks.append((f"file_exists:{fc['path']}", exists))
        if exists and "contains" in fc:
            content = fpath.read_text(encoding="utf-8", errors="replace")
            contains = fc["contains"] in content
            checks.append((f"file_contains:{fc['path']}", contains))

    # Output checks
    for phrase in task.expected_output_contains:
        checks.append((f"output_contains:{phrase}", phrase.lower() in assistant_output.lower()))

    # Tool call checks
    for tool in task.expected_tool_calls:
        checks.append((f"tool_called:{tool}", tool in tool_calls_seen))

    total = len(checks)
    passed = sum(1 for _name, ok in checks if ok)
    score = passed / total if total > 0 else 1.0

    return TaskResult(
        task_id=task.id,
        success=score >= 1.0,
        score=round(score, 3),
        details=dict(checks),
        duration_ms=(time.perf_counter() - start) * 1000,
    )


def build_mock_responses_for_task(task: BenchmarkTask) -> list[ChatResponse]:
    """Generate deterministic mock responses that execute expected tool calls."""
    responses: list[ChatResponse] = []

    # First turn: request expected tool calls
    tool_calls: list[dict[str, Any]] = []
    for i, tool in enumerate(task.expected_tool_calls):
        if tool == "file_write":
            # Assume first expected file
            fc = task.expected_files[0] if task.expected_files else {"path": "output.txt", "contains": ""}
            arguments = json.dumps({"path": fc["path"], "content": fc.get("contains", "")})
        elif tool == "file_read":
            fc = task.expected_files[0] if task.expected_files else {"path": "input.txt"}
            arguments = json.dumps({"path": fc["path"]})
        elif tool == "shell":
            arguments = json.dumps({"command": "echo ok"})
        elif tool == "file_list":
            arguments = json.dumps({"path": "."})
        elif tool == "file_delete":
            target = "temp.log"
            if task.setup_files:
                candidate = task.setup_files[0].get("path")
                if isinstance(candidate, str) and candidate:
                    target = candidate
            arguments = json.dumps({"path": target})
        elif tool == "file_search":
            pattern = "*"
            for setup_file in task.setup_files:
                candidate = setup_file.get("path")
                if not isinstance(candidate, str) or not candidate:
                    continue
                suffix = Path(candidate).suffix
                if suffix:
                    pattern = f"*{suffix}"
                    break
            arguments = json.dumps({"pattern": pattern, "path": "."})
        else:
            arguments = json.dumps({})
        tool_calls.append({
            "id": f"call_{i}",
            "type": "function",
            "function": {"name": tool, "arguments": arguments},
        })

    if tool_calls:
        responses.append(ChatResponse(
            content="",
            tool_calls=tool_calls,
            model="mock",
            usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            finish_reason="tool_calls",
        ))

    # Final turn: completion
    final_output = f"Task {task.id} completed."
    if task.expected_output_contains:
        final_output += " " + " ".join(task.expected_output_contains)
    responses.append(ChatResponse(
        content=final_output,
        tool_calls=[],
        model="mock",
        usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
        finish_reason="stop",
    ))
    return responses


async def run_task(
    task: BenchmarkTask,
    tmp_path: Path,
    mock: bool = True,
) -> TaskResult:
    """Execute a single benchmark task."""
    workspace = tmp_path / "workspace"
    state_dir = tmp_path / "state"
    workspace.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)

    settings = JSSettings(workspace=workspace, state_dir=state_dir, max_turns=task.max_turns)
    agent = JSAgent(settings)

    # Auto-approve all tool calls in benchmark mode (construct with AUTO_APPROVE)
    from js.security.approvals import ApprovalMode, ApprovalQueue
    agent.approvals = ApprovalQueue(default_mode=ApprovalMode.AUTO_APPROVE)

    # Setup pre-existing files if defined
    for sf in getattr(task, "setup_files", []):
        fpath = workspace / sf["path"]
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(sf.get("content", ""), encoding="utf-8")

    provider: ModelProvider | None = None
    if mock:
        responses = build_mock_responses_for_task(task)
        provider = MockBenchmarkProvider(responses)
        # Inject mock provider into router
        agent.router._providers.clear()
        agent.router._model_map.clear()
        from js.config import ModelConfig
        agent.router.add_provider("mock", provider, [ModelConfig(id="gpt", name="Mock")])

    try:
        state = await agent.run(task.input)
        assistant_output = ""
        for msg in reversed(state.messages):
            if msg.role == "assistant" and isinstance(msg.content, str):
                assistant_output = msg.content
                break

        tool_calls_seen: list[str] = []
        if isinstance(provider, MockBenchmarkProvider):
            tool_calls_seen = provider.tool_calls_seen
        else:
            # Extract from state for live runs
            for msg in state.messages:
                if msg.role == "assistant" and msg.tool_calls:
                    for tc in (msg.tool_calls or []):
                        fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                        name = fn.get("name", "") if isinstance(fn, dict) else ""
                        if name:
                            tool_calls_seen.append(name)

        result = score_task(task, workspace, assistant_output, tool_calls_seen)
        return result
    except Exception as e:
        return TaskResult(
            task_id=task.id,
            success=False,
            score=0.0,
            details={"error": str(e)},
        )
    finally:
        await agent.close()


def load_baseline(baseline_path: Path) -> dict[str, Any]:
    if baseline_path.exists():
        with open(baseline_path, encoding="utf-8") as f:
            return cast("dict[str, Any]", json.load(f))
    return {}


def save_baseline(baseline_path: Path, data: dict[str, Any]) -> None:
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def print_report(results: list[TaskResult], baseline: dict[str, Any]) -> None:
    total_score = sum(r.score for r in results) / len(results) if results else 0.0
    baseline_score = baseline.get("overall_score", 0.0)
    delta = total_score - baseline_score

    print("\n" + "=" * 60)
    print(f"Benchmark Report ({len(results)} tasks)")
    print("=" * 60)
    for r in results:
        status = "PASS" if r.success else "FAIL"
        print(f"  [{status}] {r.task_id}: score={r.score:.2f} ({r.duration_ms:.0f}ms)")
        if not r.success:
            for check, ok in r.details.items():
                if not ok:
                    print(f"         ✗ {check}")
    print("-" * 60)
    print(f"Overall score: {total_score:.3f}")
    if baseline_score:
        print(f"Baseline:      {baseline_score:.3f} (delta: {delta:+.3f})")
    print("=" * 60)


async def main() -> int:
    parser = argparse.ArgumentParser(description="JS Agent Benchmark Runner")
    parser.add_argument("--tasks-dir", type=Path, default=Path(__file__).parent / "tasks")
    parser.add_argument("--baseline", type=Path, default=Path(__file__).parent / "baseline.json")
    parser.add_argument("--mock", action="store_true", default=True, help="Use mock provider (default)")
    parser.add_argument("--live", action="store_true", help="Use live LLM provider")
    parser.add_argument("--update-baseline", action="store_true", help="Write current score as new baseline")
    parser.add_argument("--threshold", type=float, default=0.05, help="Regression threshold (default 0.05)")
    args = parser.parse_args()

    use_mock = not args.live
    tasks = load_tasks(args.tasks_dir)
    if not tasks:
        print(f"No tasks found in {args.tasks_dir}")
        return 0

    baseline = load_baseline(args.baseline)
    results: list[TaskResult] = []

    import tempfile
    for task in tasks:
        with tempfile.TemporaryDirectory() as tmp:
            result = await run_task(task, Path(tmp), mock=use_mock)
            results.append(result)

    print_report(results, baseline)
    overall = sum(r.score for r in results) / len(results) if results else 0.0

    if args.update_baseline:
        save_baseline(args.baseline, {
            "overall_score": round(overall, 3),
            "task_scores": {r.task_id: r.score for r in results},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        })
        print(f"Baseline updated: {args.baseline}")

    if baseline and overall < baseline.get("overall_score", 0.0) - args.threshold:
        print(f"\nREGRESSION DETECTED: score dropped by more than {args.threshold}")
        return 1
    return 0


if __name__ == "__main__":
    import asyncio
    sys.exit(asyncio.run(main()))
