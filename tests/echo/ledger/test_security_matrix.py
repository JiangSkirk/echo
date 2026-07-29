from __future__ import annotations

from js.echo.ledger.security_matrix import run_security_matrix


def test_security_matrix_has_25_passing_cases() -> None:
    report = run_security_matrix()

    assert report.ok
    assert report.total == 25
    assert report.passed == 25
    assert report.failed == ()
    assert len({case.case_id for case in report.cases}) == 25


def test_security_matrix_names_required_control_families() -> None:
    report = run_security_matrix()
    families = {case.family for case in report.cases}

    assert families == {
        "audit",
        "privacy",
        "file_scope",
        "network_scope",
        "policy",
        "journal",
        "effects",
        "memory",
        "plugins",
        "sandbox",
    }
