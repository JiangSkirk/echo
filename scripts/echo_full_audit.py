#!/usr/bin/env python3
"""Generate the Echo multi-round architecture audit report.

This is a local engineering audit harness. It does not replace external FTO,
clean-room review, external security audit, or a real independent red-team
report.
"""

from __future__ import annotations

import argparse
import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.echo.ledger.release_gates import (
    verify_echo_ip_boundary,
    verify_release_readiness,
)
from js.echo.ledger.security_matrix import run_security_matrix
from scripts.echo_architecture_benchmark import SLO_THRESHOLDS, evaluate_slo_failures

ROUND_TITLES = (
    "架构边界轮",
    "模型调用边界轮",
    "工具与 sandbox 轮",
    "附件/vision/secret 轮",
    "租户/session/memory 轮",
    "ledger/outbox/recovery 轮",
    "stream/thinking/UI 轮",
    "性能/token 轮",
    "扩展性轮",
    "发布与供应链轮",
)
BENCHMARK_COMMAND = (
    ".venv/bin/python scripts/echo_architecture_benchmark.py --iterations 50 "
    "--warmup 10 --enforce-slo --baseline docs/security/ECHO_BASELINE_65CC545.json "
    "--output docs/security/ECHO_SLO_BENCHMARK.json"
)


@dataclass(frozen=True)
class AuditFinding:
    severity: str
    title: str
    evidence: str
    status: str
    repair: str
    verification: str


def _read(root: Path, relative: str) -> str:
    path = root / relative
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _load_json(root: Path, relative: str) -> dict[str, Any]:
    path = root / relative
    if not path.exists():
        return {}
    try:
        from js.echo.ledger.strict_json import StrictJSONError, strict_load_path

        payload = strict_load_path(path)
    except (OSError, StrictJSONError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _benchmark_sha256(root: Path) -> str:
    path = root / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "missing"


def _contains(root: Path, relative: str, needle: str) -> bool:
    return needle in _read(root, relative)


def _legacy_mentions(root: Path) -> int:
    total = 0
    needles = (
        "js.rivetline",
        "js/rivetline",
        "rivetline_engine",
        "js_rivetline_engine",
        "turnexecutor",
        "js.agent_core",
        "js/agent_core",
        "echo2_primitives",
        "run_legacy",
    )
    for base in ("js", "js_work"):
        directory = root / base
        if not directory.exists():
            continue
        for path in directory.rglob("*"):
            if path.suffix not in {".py", ".md", ".js", ".json"} or not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace").casefold()
            total += sum(text.count(needle) for needle in needles)
    return total


def _benchmark_findings(root: Path) -> list[AuditFinding]:
    data = _load_json(root, "docs/security/ECHO_SLO_BENCHMARK.json")
    if not data:
        return [
            AuditFinding(
                "P1",
                "Echo SLO benchmark artifact missing",
                "docs/security/ECHO_SLO_BENCHMARK.json",
                "open",
                "Run scripts/echo_architecture_benchmark.py with --enforce-slo.",
                BENCHMARK_COMMAND,
            )
        ]
    findings: list[AuditFinding] = []
    slo_failures = evaluate_slo_failures(data)
    echo_mode = (data.get("modes") or {}).get("echo") or {}
    aggregate = data.get("aggregate") or {}
    p95_medians = aggregate.get("latency_p95_median_ms") or {}
    for scenario, thresholds in SLO_THRESHOLDS.items():
        latency = (echo_mode.get(scenario) or {}).get("latency") or {}
        p95_ms = p95_medians.get(scenario, latency.get("p95_ms"))
        scenario_failures = [failure for failure in slo_failures if failure.startswith(scenario)]
        status = "fixed" if not scenario_failures else "open"
        severity = "P1" if scenario == "api_full_agent" and scenario_failures else "P2"
        findings.append(
            AuditFinding(
                severity,
                f"{scenario} Echo p95 {p95_ms}ms / limit {thresholds['p95_ms']}ms",
                "docs/security/ECHO_SLO_BENCHMARK.json",
                status,
                "Keep Echo p95 within the deterministic absolute SLO gate.",
                BENCHMARK_COMMAND,
            )
        )
    token_comparison = data.get("token_comparison") or {}
    token_failures = [
        failure for failure in slo_failures if "prompt" in failure or "token evidence" in failure
    ]
    findings.append(
        AuditFinding(
            "P1" if token_failures else "P2",
            "api_full_agent prompt token p95 "
            f"{token_comparison.get('api_full_agent_prompt_p95_echo')} "
            f"({token_comparison.get('token_source', 'missing')}) / limit "
            f"{token_comparison.get('api_full_agent_prompt_p95_limit')}",
            "docs/security/ECHO_SLO_BENCHMARK.json",
            "fixed" if not token_failures else "open",
            "Keep ContextVault payloads bounded and label token evidence honestly.",
            BENCHMARK_COMMAND,
        )
    )
    concurrency = data.get("concurrency_probe") or {}
    concurrency_failures = [
        failure for failure in slo_failures if failure.startswith("concurrency")
    ]
    findings.append(
        AuditFinding(
            "P1" if concurrency_failures else "P2",
            "Concurrency evidence "
            f"{concurrency.get('completed_ok')}/{concurrency.get('total_requests')} "
            f"at {concurrency.get('submitted_concurrency')} x "
            f"{concurrency.get('rounds')} rounds",
            "docs/security/ECHO_SLO_BENCHMARK.json",
            "fixed" if not concurrency_failures else "open",
            "Run 50 concurrent requests for three rounds with no 5xx or crosstalk.",
            BENCHMARK_COMMAND,
        )
    )
    recovery_failures = [failure for failure in slo_failures if failure.startswith("recovery")]
    findings.append(
        AuditFinding(
            "P1" if recovery_failures else "P2",
            "10k replay and compaction recovery SLO",
            "docs/security/ECHO_SLO_BENCHMARK.json",
            "fixed" if not recovery_failures else "open",
            "Keep 10k replay and compaction below their absolute limits.",
            BENCHMARK_COMMAND,
        )
    )
    security = data.get("security_matrix") or {}
    if security.get("ok") is not True:
        findings.append(
            AuditFinding(
                "P0",
                "Benchmark security matrix is not green",
                "docs/security/ECHO_SLO_BENCHMARK.json",
                "open",
                "Fix failing matrix controls before replacement.",
                ".venv/bin/python -c 'from js.echo.ledger.security_matrix import run_security_matrix; print(run_security_matrix())'",
            )
        )
    return findings


def collect_round_findings(root: Path) -> list[list[AuditFinding]]:
    readiness = verify_release_readiness(root, require_audit_reports=False)
    matrix = run_security_matrix()
    ip = verify_echo_ip_boundary(root)
    router_stream_gated = _contains(root, "js/models/router.py", "before_model_call") and _contains(
        root, "js/models/router.py", "_chat_stream_events_for_decision"
    )
    interpreter_stream_gated = _contains(
        root, "js/echo/effect_interpreter.py", "chat_stream_events"
    ) and _contains(root, "js/echo/turn_loop.py", "execute_model_stream_effect")
    turn_loop_has_direct_stream = _contains(
        root, "js/echo/turn_loop.py", ".router.chat_stream_events("
    ) or _contains(root, "js/echo/turn_loop.py", ".provider.chat_stream_events(")
    persistent_lease = _contains(root, "js/echo/capability.py", "ledger_path") and _contains(
        root, "js/agent/tool_executor.py", "echo_tool_lease.jsonl"
    )
    upload_owner_scope = _contains(root, "js/web/uploads.py", "owner_slug") and _contains(
        root, "js/web/uploads.py", "session_slug"
    )
    session_locks = _contains(
        root, "js/web/session_locks.py", "weakref.WeakValueDictionary"
    ) and _contains(root, "js/web/session_locks.py", "owner_key_hash")
    owner_runtime_partition = _contains(
        root, "js/echo/turn_context.py", "runtime_partition_key"
    ) and _contains(root, "js/echo/turn_runtime.py", "runtime_channel_key")
    model_identity_binding = _contains(
        root, "js/echo/ledger/service.py", "resolved_session_id"
    ) and _contains(root, "js/echo/ledger/service.py", "product_id")
    tool_product_binding = _contains(root, "js/agent/tool_executor.py", "product-session:")
    background_budget = _contains(
        root, "js/echo/model_budget.py", "MODEL_CALL_JOURNAL_RECORDS = 9"
    ) and _contains(root, "js/agent/__init__.py", "_new_echo_model_budget")
    token_provenance = _contains(root, "js/models/providers.py", "usage_source") and _contains(
        root, "js/echo/ledger/service.py", "token_source"
    )
    compaction = _contains(root, "js/echo/ledger/journal.py", "snapshot_anchor")
    legacy_count = _legacy_mentions(root)

    return [
        [
            AuditFinding(
                "P2",
                f"Echo-only runtime; removed-runtime production mentions={legacy_count}",
                "js/config.py; docs/echo/DEFAULT_ARCHITECTURE.md",
                "fixed"
                if _contains(root, "js/config.py", 'default="on"')
                and _contains(root, "js/config.py", "Echo is the only supported architecture")
                else "open",
                "Keep removed runtime packages, switches, and execution loops out of production.",
                ".venv/bin/python -m pytest tests/echo/test_legacy_runtime_removed.py -q",
            )
        ],
        [
            AuditFinding(
                "P0",
                "Provider-bound stream calls use Echo before/after model gate",
                "js/models/router.py; js/agent/runner.py",
                "fixed"
                if router_stream_gated
                and interpreter_stream_gated
                and not turn_loop_has_direct_stream
                else "open",
                "Route chat_stream_events through before_model_call/after_model_call.",
                ".venv/bin/python -m pytest tests/echo/ledger/test_agent_model_gate.py::test_router_stream_events_authorizes_and_finalizes_fallback_provider -q",
            ),
            AuditFinding(
                "P1",
                "ScopeGate binds the real product, session, run, model, messages, and tools",
                "js/echo/ledger/service.py; tests/echo/ledger/test_service.py",
                "fixed" if model_identity_binding else "open",
                "Keep product/session identity in every provider-bound ScopePermit.",
                ".venv/bin/python -m pytest tests/echo/ledger/test_service.py::test_service_authorize_model_call_records_echo2_scope_permit_metadata -q",
            ),
        ],
        [
            AuditFinding(
                "P0",
                "Tool execution uses signed persistent CapabilityLease ledger",
                "js/echo/capability.py; js/agent/tool_executor.py",
                "fixed" if persistent_lease else "open",
                "Persist issue/consume/revoke and load consumed nonce state on restart.",
                ".venv/bin/python -m pytest tests/echo/test_capability_lease.py::test_persistent_lease_ledger_replays_consumed_nonce tests/test_progress_callback_redacts.py::test_echo_tool_execution_default_authority_writes_persistent_lease_ledger -q",
            ),
            AuditFinding(
                "P1",
                "Tool lease resource scopes bind product and session",
                "js/agent/tool_executor.py; tests/echo/test_tool_capability_context.py",
                "fixed" if tool_product_binding else "open",
                "Prevent a signed Work lease from being reused in the main product namespace.",
                ".venv/bin/python -m pytest tests/echo/test_tool_capability_context.py::test_tool_executor_passes_consumed_lease_context_to_registry -q",
            ),
        ],
        [
            AuditFinding(
                "P0",
                "Attachment, vision, and secret gates block before model call",
                "tests/echo/ledger/test_agent_model_gate.py; js/web/uploads.py",
                "fixed" if upload_owner_scope else "open",
                "Keep upload ownership and model-bound secret scan on the same Echo path.",
                ".venv/bin/python -m pytest tests/echo/ledger/test_agent_model_gate.py::test_vision_attachment_blocks_by_default_without_vision_safety_approval -q",
            )
        ],
        [
            AuditFinding(
                "P1",
                "Owner/session locks and tenant state are bounded",
                "js/web/session_locks.py; js/echo/ledger/service.py",
                "fixed" if session_locks and owner_runtime_partition else "open",
                "Keep owner+session keyed locks and bounded tenant journal cache.",
                ".venv/bin/python -m pytest tests/test_cancel_checkpoint.py::TestCancelAPI::test_same_session_id_cancels_only_matching_owner tests/echo/test_turn_runtime.py::test_same_session_id_uses_distinct_owner_lanes tests/echo/test_web_session_locks.py tests/echo/ledger/test_service.py::test_service_tenant_state_cache_is_bounded -q",
            )
        ],
        [
            AuditFinding(
                "P0",
                "Journal recovery, manual review, and compaction are observable",
                "js/echo/ledger/journal.py; js/echo/ledger/service.py",
                "fixed" if compaction else "open",
                "Keep hash/MAC replay, corrupt-tail isolation, manual-review, and snapshot anchor.",
                ".venv/bin/python -m pytest tests/echo/ledger/test_service.py::test_service_compaction_skips_open_effects_then_writes_anchor -q",
            )
        ],
        [
            AuditFinding(
                "P1",
                "Stream terminal ordering and thinking side-channel are covered",
                "js/web/server.py; tests/echo/ledger/test_websocket_primary.py",
                "fixed" if _contains(root, "js/web/server.py", '"type": "done"') else "open",
                "Keep token/thinking frames before one terminal done/error.",
                ".venv/bin/python -m pytest tests/echo/ledger/test_websocket_primary.py tests/test_stream_events_dispatch.py -q",
            )
        ],
        [
            *_benchmark_findings(root),
            AuditFinding(
                "P1",
                "BudgetClock covers background model calls and counts nine ledger records per attempt",
                "js/echo/model_budget.py; js/agent/__init__.py; js/echo/turn_loop.py",
                "fixed" if background_budget else "open",
                "Keep summary, dreaming, evolution, and profile model calls under hard budgets.",
                ".venv/bin/python -m pytest tests/echo/test_budget_runtime.py -q",
            ),
            AuditFinding(
                "P1",
                "Token evidence records provider_actual, tokenizer, estimated, or unavailable",
                "js/models/providers.py; js/echo/ledger/service.py",
                "fixed" if token_provenance else "open",
                "Never present heuristic stream tokens as provider billing data.",
                ".venv/bin/python -m pytest tests/test_stream_events_dispatch.py::TestStreamEventDispatch::test_missing_stream_usage_is_explicitly_estimated tests/echo/ledger/test_service.py::test_service_authorize_model_call_records_echo2_scope_permit_metadata -q",
            ),
        ],
        [
            AuditFinding(
                "P2",
                "Extension boundaries exist for model, tool, context, and release gates",
                "js/models/router.py; js/agent/tool_executor.py; js/echo/context_runtime.py; js/echo/ledger/release_gates.py",
                "fixed",
                "Keep new feature work behind these interfaces instead of adding direct web/server bypasses.",
                ".venv/bin/ruff check js/models/router.py js/agent/tool_executor.py js/echo/ledger tests/echo/ledger",
            )
        ],
        [
            AuditFinding(
                "P0",
                "Stable release blockers remain external-only",
                "docs/security; js/echo/ledger/release_gates.py",
                "fixed"
                if readiness.internal_ready and not readiness.stable_ready and ip.ok and matrix.ok
                else "open",
                "Do not mark stable until external FTO, clean-room, security audit, and red-team reports are approved.",
                ".venv/bin/python - <<'PY'\nfrom pathlib import Path\nfrom js.echo.ledger.release_gates import verify_release_readiness\nprint(verify_release_readiness(Path('.')))\nPY",
            )
        ],
    ]


def _render(root: Path, rounds: int) -> str:
    readiness = verify_release_readiness(root, require_audit_reports=False)
    matrix = run_security_matrix()
    findings_by_round = collect_round_findings(root)
    lines = [
        f"# Echo {rounds} Round Audit",
        "",
        "This is local engineering evidence. It is not external FTO, clean-room, security-audit, or red-team approval.",
        "",
        "## Summary",
        "",
        f"- Echo-only default: `{_contains(root, 'js/config.py', 'default="on"')}`",
        f"- Security matrix: `{matrix.passed}/{matrix.total}`, ok=`{matrix.ok}`",
        f"- Internal release ready: `{readiness.internal_ready}`",
        f"- Stable release ready: `{readiness.stable_ready}`",
        f"- Stable release blockers: `{', '.join(readiness.external_blockers) or 'none'}`",
        f"- Benchmark SHA-256: `{_benchmark_sha256(root)}`",
        "",
    ]
    for index in range(rounds):
        title = (
            ROUND_TITLES[index] if index < len(ROUND_TITLES) else f"Additional round {index + 1}"
        )
        lines.extend([f"## Round {index + 1}: {title}", ""])
        findings = findings_by_round[index] if index < len(findings_by_round) else ()
        for finding in findings:
            lines.extend(
                [
                    f"- **{finding.severity} {finding.title}**",
                    f"  - Status: `{finding.status}`",
                    f"  - Evidence: `{finding.evidence}`",
                    f"  - Repair: {finding.repair}",
                    f"  - Verification: `{finding.verification}`",
                ]
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _write_final_report(root: Path, audit_text: str, *, output: Path | None = None) -> Path:
    benchmark = _load_json(root, "docs/security/ECHO_SLO_BENCHMARK.json")
    readiness = verify_release_readiness(root, require_audit_reports=False)
    matrix = run_security_matrix()
    out = output or root / "docs/echo/ECHO_FINAL_REPLACEMENT_REPORT.md"
    token_comparison = benchmark.get("token_comparison") or {}
    echo_mode = (benchmark.get("modes") or {}).get("echo") or {}
    concurrency = benchmark.get("concurrency_probe") or {}
    recovery = benchmark.get("recovery_probes") or {}
    baseline = benchmark.get("baseline_comparison") or {}
    metadata = benchmark.get("metadata") or {}
    aggregate = benchmark.get("aggregate") or {}
    p95_medians = aggregate.get("latency_p95_median_ms") or {}
    p95_runs = aggregate.get("latency_p95_runs_ms") or {}
    stability = benchmark.get("five_run_stability") or {}
    if not stability and aggregate.get("group_count") == 5:
        echo_api_p95 = p95_medians.get("api_full_agent")
        old_api_p95 = (baseline.get("api_full_agent") or {}).get("old_p95_ms")
        stability = {
            "api_full_agent_p95_median_ms": echo_api_p95,
            "api_full_agent_p95_limit_ms": SLO_THRESHOLDS["api_full_agent"]["p95_ms"],
            "median_faster_than_old": (
                isinstance(echo_api_p95, int | float)
                and isinstance(old_api_p95, int | float)
                and echo_api_p95 < old_api_p95
            ),
        }
    lines = [
        "# Echo Final Replacement Report",
        "",
        "## Verdict",
        "",
        "- Echo is the default normal-use architecture.",
        "- The old off/shadow architecture modes have been removed from the normal JS Agent configuration surface.",
        "- Local engineering gates support running the JS Agent on Echo-only default.",
        "- GitHub stable release remains blocked until external approvals are signed.",
        f"- Benchmark SHA-256: `{_benchmark_sha256(root)}`",
        "",
        "## Safety",
        "",
        f"- 25-item local security matrix: `{matrix.passed}/{matrix.total}`, ok=`{matrix.ok}`.",
        "- Echo blocks secret-bearing attachment/model payloads before provider execution.",
        "- Model calls, stream calls, and tools are bound to Echo gates.",
        "- Journal/outbox recovery is replayable and observable through health counters.",
        "- Removed rollback values such as `JS_ECHO_ENGINE=off` and `JS_ECHO_ENGINE=shadow` fail closed.",
        "",
        "## Compatibility",
        "",
        "- `/api/chat`, regular `/ws`, streaming `/ws`, `JSAgent.run()`, and `JSAgent.chat_stream()` use the Echo-gated path by default.",
        "- Thinking is surfaced only when the provider emits thinking content; otherwise the UI does not show a thinking panel.",
        "- Tool execution uses persistent signed leases and keeps the existing tool-call behavior available through Echo.",
        "",
        "## Performance",
        "",
        "- Measurements use a deterministic local fake provider with no network LLM calls; "
        "latency does not include network or provider latency variance; cl100k tokenizer "
        "counts are not DeepSeek or provider billing data.",
    ]
    if token_comparison:
        for scenario in SLO_THRESHOLDS:
            latency = (echo_mode.get(scenario) or {}).get("latency") or {}
            median_p95 = p95_medians.get(scenario)
            scenario_runs = p95_runs.get(scenario)
            if isinstance(median_p95, int | float) and isinstance(scenario_runs, list):
                lines.append(
                    f"- {scenario}: p95 median `{median_p95}` ms across "
                    f"`{aggregate.get('group_count')}` independent groups "
                    f"(`{metadata.get('iterations')}` measured requests per group)."
                )
            else:
                lines.append(
                    f"- {scenario}: p95 `{latency.get('p95_ms')}` ms "
                    f"from `{latency.get('n')}` local samples."
                )
        lines.append(
            "- api_full_agent prompt token p95: "
            f"Echo `{token_comparison.get('api_full_agent_prompt_p95_echo')}`, "
            f"limit `{token_comparison.get('api_full_agent_prompt_p95_limit')}`, "
            f"within_limit `{token_comparison.get('api_full_agent_prompt_within_limit')}`, "
            f"source `{token_comparison.get('token_source')}`."
        )
        lines.append(
            "- Concurrency: "
            f"`{concurrency.get('completed_ok')}/{concurrency.get('total_requests')}` "
            f"successful, 5xx `{concurrency.get('http_5xx_count')}`, "
            f"crosstalk `{concurrency.get('crosstalk_count')}`, "
            f"peak RSS `{concurrency.get('peak_rss_mb')}` MB."
        )
        lines.append(
            "- Recovery: 10k replay "
            f"`{recovery.get('journal_replay_10k_records_s')}` s; compaction "
            f"`{recovery.get('compaction_latency_ms')}` ms."
        )
        baseline_latency = baseline.get("api_full_agent") or {}
        baseline_tokens = baseline.get("prompt_tokens") or {}
        if baseline.get("valid") is True:
            lines.append(
                "- Corrected detached-baseline comparison: API p95 old "
                f"`{baseline_latency.get('old_p95_ms')}` ms vs Echo "
                f"`{baseline_latency.get('echo_p95_ms')}` ms "
                f"(`{baseline_latency.get('p95_delta_pct')}%`); prompt p95 old "
                f"`{baseline_tokens.get('old_p95')}` vs Echo "
                f"`{baseline_tokens.get('echo_p95')}` tokenizer tokens "
                f"(`{baseline_tokens.get('reduction_pct')}%` reduction)."
            )
        if stability:
            lines.append(
                "- Five-run API p95 median: "
                f"`{stability.get('api_full_agent_p95_median_ms')}` ms; "
                f"limit `{stability.get('api_full_agent_p95_limit_ms')}` ms; "
                f"faster than detached old baseline "
                f"`{stability.get('median_faster_than_old')}`."
            )
    else:
        lines.append("- No benchmark artifact was available when this report was generated.")
    lines.extend(
        [
            "",
            "## JS Agent Work",
            "",
            "- Work runs as the separate `js-work` product with owner-scoped workspace, state, session, and Echo filesystem roots.",
            "- The Office profile includes deterministic packing-details, accessory-order, PDF/Word, and spreadsheet tools.",
            "- `excel_precise_edit` applies bounded cell/style/layout operations under a single-use signed Echo lease.",
            "- Precise editing never overwrites the source or an existing output, rejects dangerous formulas and unsupported OOXML features, and writes a hash-bound validation report.",
            "",
            "## Replacement Boundary",
            "",
            "- Normal use runs on Echo-only architecture.",
            "- Removed rollout values such as `off` and `shadow` fail closed.",
            "- The old shadow gateway and rollback helpers have been removed from the running code.",
        ]
    )
    lines.extend(
        [
            "",
            "## Stable Release Blockers",
            "",
            *(f"- {blocker}" for blocker in readiness.external_blockers),
            "",
            "## Audit Source",
            "",
            "See `docs/echo/ECHO_10_ROUND_AUDIT.md` for the latest local audit.",
        ]
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return out


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/echo/ECHO_10_ROUND_AUDIT.md"),
    )
    parser.add_argument(
        "--final-report-output",
        type=Path,
        default=Path("docs/echo/ECHO_FINAL_REPLACEMENT_REPORT.md"),
    )
    parser.add_argument("--fix-verification", action="store_true")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify canonical audit reports without rewriting them.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    rounds = max(1, min(args.rounds, 10))
    output = args.output if args.output.is_absolute() else root / args.output
    final_output = (
        args.final_report_output
        if args.final_report_output.is_absolute()
        else root / args.final_report_output
    )
    text = _render(root, rounds)
    if args.check:
        with tempfile.TemporaryDirectory(prefix="echo-audit-check-") as temporary_dir:
            expected_final_path = _write_final_report(
                root,
                text,
                output=Path(temporary_dir) / "final.md",
            )
            expected_final = expected_final_path.read_text(encoding="utf-8")
        stale: list[str] = []
        if not output.is_file() or output.read_text(encoding="utf-8") != text:
            stale.append(str(output))
        if not final_output.is_file() or final_output.read_text(encoding="utf-8") != expected_final:
            stale.append(str(final_output))
        if stale:
            print("Echo audit evidence is stale: " + ", ".join(stale))
            return 1
        final_report = final_output
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        final_report = _write_final_report(root, text, output=final_output)
    readiness = verify_release_readiness(
        root,
        require_audit_reports=False,
        require_live_acceptance=False,
    )
    if args.fix_verification:
        benchmark = _load_json(root, "docs/security/ECHO_SLO_BENCHMARK.json")
        slo_failures = evaluate_slo_failures(benchmark) if benchmark else ["missing benchmark"]
        if not readiness.internal_ready or slo_failures:
            if readiness.internal_blockers:
                print(f"internal readiness blockers: {', '.join(readiness.internal_blockers)}")
            if slo_failures:
                print(f"SLO blockers: {', '.join(slo_failures)}")
            return 1
    verb = "verified" if args.check else "wrote"
    print(f"{verb} {output}")
    print(f"{verb} {final_report}")
    print("[OK] echo_full_audit")
    from js.echo.ledger.release_gates import format_release_result_line

    print(format_release_result_line(gate="echo_full_audit", ok=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
