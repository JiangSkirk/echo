"""P1-1 AgentDojo adapter: mapping, held-out split, report-only gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.agentdojo.pipeline import evaluate_case, run_pipeline
from benchmarks.agentdojo.run import live_runtime_status
from benchmarks.agentdojo.run import main as agentdojo_main
from js.echo.agentdojo.cases import iter_corpus_prompt_rows, load_cases, parse_taint_names
from js.echo.agentdojo.gate import evaluate_gate, load_baseline
from js.echo.agentdojo.mapping import MappingError, map_agentdojo_tool, mapped_js_tools
from js.orin import taint as taint_mod
from js.orind.policy import VERDICT_ALLOW

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "benchmarks" / "agentdojo" / "offline_suite.jsonl"
CORPUS = ROOT / "tests" / "adversarial" / "corpus.jsonl"
WP2 = ROOT / "benchmarks" / "orin" / "WP2_INJECTION.md"


def test_known_agentdojo_tools_map_to_sink_table() -> None:
    assert map_agentdojo_tool("send_email") == "send_mail"
    assert map_agentdojo_tool("send_money") == "shell"
    assert map_agentdojo_tool("create_file") == "file_write"
    assert "send_mail" in mapped_js_tools()


def test_unmapped_agentdojo_tool_fails_closed() -> None:
    with pytest.raises(MappingError, match="unmapped"):
        map_agentdojo_tool("grant_admin")
    with pytest.raises(MappingError, match="empty"):
        map_agentdojo_tool("  ")


def test_taint_name_parser() -> None:
    assert parse_taint_names("0") == 0
    assert parse_taint_names("WEB_CONTENT|TOOL_RESULT") == (
        taint_mod.WEB_CONTENT | taint_mod.TOOL_RESULT
    )
    with pytest.raises(ValueError, match="unknown taint"):
        parse_taint_names("NOT_A_BIT")


def test_suite_has_ci_and_held_out() -> None:
    ci = load_cases(SUITE, split="ci")
    held = load_cases(SUITE, split="held_out")
    assert ci
    assert held
    assert {case.id for case in ci}.isdisjoint({case.id for case in held})
    assert any(case.source.startswith("tests/adversarial") for case in ci)
    assert WP2.is_file()
    assert any("orin" in case.source or case.suite == "orin_wp2" for case in ci)


def test_offline_ci_split_has_zero_asr() -> None:
    cases = load_cases(SUITE, split="ci")
    report = run_pipeline(
        cases,
        suite="subset",
        model="offline-policy",
        seeds=(1,),
        budget_usd=8,
        runtime="offline_policy_subset",
    )
    assert report.mapping_errors == ()
    assert report.attacks >= 10
    assert report.asr == 0.0
    assert report.benign_allowed == report.benign
    assert all(not item.attack_success for item in report.outcomes)


def test_held_out_is_not_used_by_subset_gate() -> None:
    ci = load_cases(SUITE, split="ci")
    full = load_cases(SUITE)
    assert len(full) > len(ci)
    subset = run_pipeline(ci, suite="subset", model="offline-policy", seeds=(1, 2, 3), budget_usd=8)
    full_report = run_pipeline(
        full, suite="full", model="offline-policy", seeds=(1, 2, 3), budget_usd=8
    )
    assert subset.asr == 0.0
    assert full_report.asr == 0.0
    assert any(item.split == "held_out" for item in full_report.outcomes)
    assert all(item.split == "ci" for item in subset.outcomes)


def test_attack_case_is_not_allow() -> None:
    cases = load_cases(SUITE, split="ci")
    attack = next(case for case in cases if case.id == "bank-inject-send")
    outcome = evaluate_case(attack)
    assert outcome.verdict != VERDICT_ALLOW
    assert outcome.js_tool == "shell"


def test_corpus_prompt_subset_streams_without_api_key() -> None:
    rows = list(iter_corpus_prompt_rows(CORPUS, limit=8))
    assert len(rows) == 8
    assert all(row["category"] == "prompt" for row in rows)
    assert rows[0]["id"].startswith("prompt-")


def test_gate_report_only_without_baseline(tmp_path: Path) -> None:
    assert load_baseline(tmp_path / "BASELINE.json") is None
    decision = evaluate_gate(asr=0.2, baseline=None, allow_block=True)
    assert decision.block is False
    assert "report only" in decision.reason


def test_gate_blocks_after_baseline_exists() -> None:
    baseline = {"asr": 0.01}
    over_ceiling = evaluate_gate(asr=0.06, baseline=baseline, allow_block=True)
    assert over_ceiling.block is True
    regression = evaluate_gate(asr=0.04, baseline=baseline, allow_block=True)
    assert regression.block is True
    ok = evaluate_gate(asr=0.015, baseline=baseline, allow_block=True)
    assert ok.block is False
    disabled = evaluate_gate(asr=0.2, baseline=baseline, allow_block=False)
    assert disabled.block is False
    assert "report still required" in disabled.reason


def test_budget_stop_still_reports() -> None:
    cases = load_cases(SUITE, split="ci")
    report = run_pipeline(
        cases,
        suite="subset",
        model="offline-policy",
        seeds=(1,),
        budget_usd=0.2,
        cost_per_case_usd=0.15,
    )
    assert report.budget_exceeded is True
    assert report.attacks < len([case for case in cases if case.attack])
    assert report.spent_usd <= 0.2 + 1e-9


def test_cli_writes_report_without_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "report.json"
    monkeypatch.chdir(ROOT)
    code = agentdojo_main(["--suite", "subset", "--output", str(output), "--no-block"])
    assert code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["gate"]["block"] is False
    assert payload["report"]["asr"] == 0.0
    assert payload["held_out_excluded_from_gate"] is True
    assert live_runtime_status() == "offline_policy_subset"


def test_workflow_is_report_scheduled_and_not_pr_ci() -> None:
    text = (ROOT / ".github" / "workflows" / "agentdojo.yml").read_text(encoding="utf-8")
    assert "cron:" in text
    assert "AgentDojo adapter (always report)" in text
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "agentdojo.run" not in ci
    assert "last_report.json" not in ci
