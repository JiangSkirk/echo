from __future__ import annotations

from pathlib import Path

from scripts.js_agent_full_function_audit import build_audit_plan, main


def test_full_function_audit_plan_covers_required_groups() -> None:
    plan = build_audit_plan(rounds=7)
    groups = {check.group for check in plan}

    assert {
        "web_api",
        "websocket",
        "stream_thinking",
        "tools",
        "attachments_vision",
        "memory_skills",
        "fleet_cron_setup",
        "work",
        "security",
        "performance",
        "release",
        "quality",
        "code_audit",
    }.issubset(groups)


def test_full_function_audit_plan_keeps_generated_evidence_in_scratch(
    tmp_path: Path,
) -> None:
    plan = build_audit_plan(rounds=2, scratch_dir=tmp_path)
    performance = next(check for check in plan if check.group == "performance")
    code_audits = [check for check in plan if check.group == "code_audit"]
    quality_commands = [check.command for check in plan if check.group == "quality"]
    work = next(check for check in plan if check.group == "work")

    assert str(tmp_path / "ECHO_SLO_BENCHMARK.json") in performance.command
    assert "--baseline" in performance.command
    assert all(str(tmp_path) in " ".join(check.command) for check in code_audits)
    assert all("js_work" in command for command in quality_commands)
    assert any(part.endswith("scripts/js_work_echo_smoke.py") for part in work.command)


def test_full_function_audit_dry_run_does_not_write_or_replace_reports(
    tmp_path: Path,
) -> None:
    json_out = tmp_path / "audit.json"
    md_out = tmp_path / "audit.md"
    json_out.write_text("keep-json", encoding="utf-8")
    md_out.write_text("keep-markdown", encoding="utf-8")

    rc = main(
        [
            "--rounds",
            "7",
            "--dry-run",
            "--json-out",
            str(json_out),
            "--md-out",
            str(md_out),
        ]
    )

    assert rc == 0
    assert json_out.read_text(encoding="utf-8") == "keep-json"
    assert md_out.read_text(encoding="utf-8") == "keep-markdown"
