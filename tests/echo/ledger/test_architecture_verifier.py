from __future__ import annotations

from js.echo.ledger.verification import verify_architecture


def test_architecture_verifier_marks_preview_passed_but_stable_not_proven() -> None:
    report = verify_architecture()

    assert report.architecture == "echo-2.0"
    assert report.engineering_originality_score is None
    assert report.preview_ready
    assert not report.stable_ready
    assert "legal_fto_review_pending" in report.blocking_issues
    assert "clean_room_reviewer_pending" in report.blocking_issues
    assert "external_security_audit_pending" in report.blocking_issues
    assert "redteam_report_pending" in report.blocking_issues
    assert "stable_slo_benchmark_missing" not in report.blocking_issues
    assert "codeowners_adr_rfc_governance_missing" not in report.blocking_issues


def test_architecture_verifier_does_not_self_certify_originality() -> None:
    report = verify_architecture()
    originality = next(item for item in report.requirements if item.req_id == "REQ-ORI-01")

    assert originality.status == "external_measurement_required"
    assert "external" in originality.requirement.lower()


def test_architecture_verifier_maps_each_user_requirement_to_evidence() -> None:
    report = verify_architecture()

    requirement_ids = {item.req_id for item in report.requirements}

    assert {
        "REQ-ORI-01",
        "REQ-SEC-02",
        "REQ-REL-01",
        "REQ-REL-02",
        "REQ-EXT-02",
        "REQ-OPS-01",
        "REQ-PERF-01",
        "REQ-COMP-01",
        "REQ-ECHO2-01",
        "REQ-COST-01",
    }.issubset(requirement_ids)
    assert all(item.evidence for item in report.requirements)
