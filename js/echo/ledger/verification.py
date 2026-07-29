from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RequirementEvidence:
    req_id: str
    requirement: str
    status: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class ArchitectureVerificationReport:
    architecture: str
    engineering_originality_score: int | None
    preview_ready: bool
    stable_ready: bool
    requirements: tuple[RequirementEvidence, ...]
    blocking_issues: tuple[str, ...]


def verify_architecture() -> ArchitectureVerificationReport:
    requirements = (
        RequirementEvidence(
            req_id="REQ-ORI-01",
            requirement="originality measured by an independent external clean-room review",
            status="external_measurement_required",
            evidence=(
                "Echo 2.0 uses original primitives: PulseLoop, FrameLedger, ScopeGate, BudgetClock, EffectOutbox, ContextVault",
                "docs/security/ECHO_2_CLEAN_ROOM.md records avoided open-source API shapes",
                "ORIGIN_LEDGER.md records Echo 2.0 engineering-origin boundary and non-claims",
                "THIRD_PARTY_NOTICES.md records dependency-notice boundary",
                "legal FTO and clean-room reviewer pending files are present but require external approval",
            ),
        ),
        RequirementEvidence(
            req_id="REQ-ECHO2-01",
            requirement="Echo 2.0 primary runtime has original named primitives",
            status="preview_passed",
            evidence=(
                "js.echo exports ScopeGate, FrameLedger, BudgetClock, ContextVault",
                "EchoSafetyService health exposes architecture=echo-2.0 for compatibility status",
                "docs/echo/ECHO_2_ARCHITECTURE.md describes in-place rewrite and old-architecture fallback",
            ),
        ),
        RequirementEvidence(
            req_id="REQ-SEC-02",
            requirement="least privilege and deterministic policy decisions",
            status="preview_passed",
            evidence=(
                "PolicyDecisionRecord uses deny-overrides",
                "PermitSeal creation requires allow decision and binds decision/effect/journal seq",
                "security_controls blocks path traversal, unsafe network destinations, secret logs, and prompt-granted scopes",
                "run_security_matrix executes 25 named controls across audit/privacy/file/network/policy/journal/effects/memory/plugins/sandbox",
            ),
        ),
        RequirementEvidence(
            req_id="REQ-SEC-06",
            requirement="prompt injection cannot mint authority or promote memory directly",
            status="preview_passed",
            evidence=(
                "model output starts as quarantined MemoryCandidate",
                "model calls require ModelPrivacyEnvelope and secret redaction",
            ),
        ),
        RequirementEvidence(
            req_id="REQ-REL-01",
            requirement="recoverable journal",
            status="preview_passed",
            evidence=(
                "EchoJournal verifies seq, prev_hash, record_hash, and MAC",
                "FileEchoLedger persists JSONL records, rejects corrupt crash tails, reloads stale writers, locks, and fsyncs appends",
            ),
        ),
        RequirementEvidence(
            req_id="REQ-REL-02",
            requirement="durable external effect recovery",
            status="preview_passed",
            evidence=(
                "DurableEffectLog dispatches only rows with PermitSeal",
                "recovery probes claimed effects and merges receipts without re-executing",
                "compat mock chat path records intake->decision->policy->permit->outbox->receipt->merge",
            ),
        ),
        RequirementEvidence(
            req_id="REQ-EXT-02",
            requirement="safe plugin extension",
            status="preview_passed",
            evidence=(
                "InMemorySafePluginContext exposes only safe blob/log/budget methods",
                "stable PluginManifest rejects dev bypasses",
                "PluginRegistry supports conformance, quarantine, drain, and revoke",
            ),
        ),
        RequirementEvidence(
            req_id="REQ-OPS-01",
            requirement="long-term maintainability and governance",
            status="internal_gate_passed_external_review_missing",
            evidence=(
                "protocol contracts are test-pinned",
                ".github/CODEOWNERS, ADR 0001, and Echo major-change RFC template are present",
            ),
        ),
        RequirementEvidence(
            req_id="REQ-PERF-01",
            requirement="performance and resource gates",
            status="preview_gate_passed_stable_measurement_required",
            evidence=(
                "SLOSnapshot and evaluate_slo_snapshot encode preview/stable thresholds",
                "preview snapshot passes and stable regressions block in tests",
                "EchoSandboxBackend wraps js.echo.os_sandbox.SandboxExecutor for real process execution",
            ),
        ),
        RequirementEvidence(
            req_id="REQ-COST-01",
            requirement="lower token cost and latency by admission and context selection",
            status="preview_passed_stable_measurement_required",
            evidence=(
                "BudgetClock rejects over-budget prompt/tool/journal/elapsed reservations without consuming budget",
                "ContextVault selects owner/session-scoped relevant context under a token ceiling",
                "release smoke now includes Echo-only runtime checks through scripts/echo_smoke.py",
            ),
        ),
        RequirementEvidence(
            req_id="REQ-COMP-01",
            requirement="open-source compliance gate",
            status="internal_gate_passed_external_review_missing",
            evidence=(
                "verify_release_readiness checks ORIGIN_LEDGER, THIRD_PARTY_NOTICES, CODEOWNERS, ADR, RFC",
                "verify_release_readiness checks 25-case matrix and real sandbox backend",
                "external legal/clean-room/security/redteam evidence remains explicit stable blocker until approved",
            ),
        ),
    )
    blocking_issues = (
        "legal_fto_review_pending",
        "clean_room_reviewer_pending",
        "external_security_audit_pending",
        "redteam_report_pending",
    )
    return ArchitectureVerificationReport(
        architecture="echo-2.0",
        engineering_originality_score=None,
        preview_ready=True,
        stable_ready=False,
        requirements=requirements,
        blocking_issues=blocking_issues,
    )
