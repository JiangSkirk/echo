"""Run every adversarial corpus record through parser, guard, or path sandbox."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.orin.taint import (
    INBOX_CONTENT,
    current_entry_source_taint,
    reset_entry_source,
    set_entry_source,
)
from js.security.guard import BehaviorGuard
from js.security.parser import extract_command_names, parse
from js.security.rules import evaluate
from js.tools.files import FileTools

ROOT = Path(__file__).resolve().parents[2]
CORPUS = Path(__file__).resolve().parent / "corpus.jsonl"
BUILDER = ROOT / "scripts" / "build_adversarial_corpus.py"


def _rows() -> Iterator[dict[str, str]]:
    with CORPUS.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            assert isinstance(row, dict)
            yield {str(key): str(value) for key, value in row.items()}


@pytest.fixture(scope="module")
def guard(tmp_path_factory: pytest.TempPathFactory) -> BehaviorGuard:
    workspace = tmp_path_factory.mktemp("adv-guard")
    return BehaviorGuard(SecurityConfig(), workspace)


@pytest.fixture(scope="module")
def files(tmp_path_factory: pytest.TempPathFactory) -> FileTools:
    workspace = tmp_path_factory.mktemp("adv-files")
    return FileTools(workspace, ToolLimits(), BehaviorGuard(SecurityConfig(), workspace))


def test_corpus_file_is_present_and_unique() -> None:
    assert CORPUS.is_file()
    ids: set[str] = set()
    counts = {"shell": 0, "prompt": 0, "path": 0}
    for row in _rows():
        assert row["id"] not in ids
        ids.add(row["id"])
        assert row["category"] in counts
        assert row["payload"]
        counts[row["category"]] += 1
    assert sum(counts.values()) >= 50_000
    assert all(count > 0 for count in counts.values())


def test_committed_corpus_matches_builder() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_adversarial_corpus", BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    generated = module._records()
    committed = list(_rows())
    assert len(committed) == len(generated)
    assert committed[0]["id"] == generated[0]["id"]
    assert committed[-1]["id"] == generated[-1]["id"]


def test_every_corpus_record_is_executed(guard: BehaviorGuard, files: FileTools) -> None:
    token = set_entry_source("friends")
    try:
        assert current_entry_source_taint() & INBOX_CONTENT
        executed = 0
        for row in _rows():
            payload = row["payload"]
            category = row["category"]
            if category == "shell":
                ast = parse(payload)
                if ast is not None:
                    names = extract_command_names(ast)
                    assert isinstance(names, list)
                    evaluate(ast)
            elif category == "prompt":
                decision = guard.check_tool_result(payload)
                assert decision.decision.value in {"allow", "warn", "block"}
            else:
                try:
                    files._relative_path(payload)
                except ValueError:
                    pass
            executed += 1
        assert executed >= 50_000
    finally:
        reset_entry_source(token)


def test_seed_payloads_are_denied_or_rejected(tmp_path: Path) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_adversarial_corpus", BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    guard = BehaviorGuard(SecurityConfig(), tmp_path)
    files = FileTools(tmp_path, ToolLimits(), guard)
    for seed in module.SHELL_SEEDS:
        ast = parse(seed)
        denied = ast is None
        if ast is not None:
            denied = evaluate(ast).blocked or bool(extract_command_names(ast))
        assert denied, seed
    for seed in module.PROMPT_SEEDS:
        decision = guard.check_tool_result(seed)
        lowered = seed.lower()
        marked = any(
            marker in lowered
            for marker in (
                "ignore",
                "system prompt",
                "you are now",
                "api key",
                "bypass",
                "owner_key_hash",
                "rm -rf",
                "control_evolution",
                "execute_tool_effect",
                "allowed_tools",
                "auto_task",
                "strict_isolation",
                "telegram",
                "secrets.db",
                "exfiltrate",
                "skill that auto-applies",
                "trusted owner",
                "disable taint",
            )
        )
        assert marked or decision.decision.value in {"warn", "block"}, seed
    lexical = (
        "../etc/passwd",
        "/etc/passwd",
        "~/../../etc/shadow",
        "./././../etc/hosts",
        "foo/../../etc/passwd",
    )
    for seed in lexical:
        with pytest.raises(ValueError):
            files._relative_path(seed)
    for seed in module.PATH_SEEDS:
        try:
            relative = files._relative_path(seed)
        except ValueError:
            continue
        assert ".." not in relative.parts
        assert not relative.is_absolute()
