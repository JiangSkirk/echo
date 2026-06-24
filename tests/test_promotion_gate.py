"""Unit tests for js.skills.promotion_gate.PromotionGate.

Covers the 5-step gate: protected → validate → security → tests → smoke.
Each fail step:
 1. short-circuits the rest of the pipeline
 2. emits a `skill_promotion_events_total{decision="fail",failed_step=...}` metric
 3. leaves `skills.db` (skill_usage) empty — the smoke step never writes there
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from js.skills.promotion_gate import GateResult, PromotionGate
from js.skills.spec import SkillSpec, SkillType, TrustLevel

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _write_skill_dir(
    base: Path,
    skill_id: str,
    *,
    entry_body: str = "print('ok')\n",
    risky_body: str | None = None,
    bad_yaml: bool = False,
    trust_level: str = "community",
) -> SkillSpec:
    """Write a minimal CODE skill to disk and return its SkillSpec.

    Notes:
        - ``risky_body`` replaces the entry-file contents with code that will
          trigger the security scanner's risk patterns.
        - ``bad_yaml`` overwrites SKILL.md with malformed frontmatter so the
          validator fails on parse.
    """
    sk_dir = base / skill_id
    sk_dir.mkdir(parents=True, exist_ok=True)

    if bad_yaml:
        (sk_dir / "SKILL.md").write_text("---\nthis: is: not valid: yaml :::\n---\nbody\n")
    else:
        (sk_dir / "SKILL.md").write_text(
            f"""---
id: {skill_id}
name: {skill_id}
description: synthetic test skill for promotion gate
version: 0.1.0
type: code
entry: main.py
trust_level: {trust_level}
---
# body
""",
            encoding="utf-8",
        )

    body = risky_body if risky_body is not None else entry_body
    (sk_dir / "main.py").write_text(body, encoding="utf-8")

    return SkillSpec(
        id=skill_id,
        name=skill_id,
        description="synthetic test skill",
        type=SkillType.CODE,
        entry="main.py",
        trust_level=TrustLevel(trust_level),
        path=sk_dir,
    )


def _count_skill_usage_rows(db_path: Path) -> int:
    if not db_path.exists():
        return 0
    with sqlite3.connect(str(db_path)) as conn:
        try:
            return int(conn.execute("SELECT COUNT(*) FROM skill_usage").fetchone()[0])
        except sqlite3.OperationalError:
            return 0


# ---------------------------------------------------------------------------
# protected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gate_blocks_hermes_skill_short_circuits(tmp_path: Path) -> None:
    """Hermes skills must fail at step 1 — validator should NOT be invoked."""
    spec = _write_skill_dir(tmp_path, "hermes_demo")
    # The protected check keys off the id prefix, regardless of path.
    spec.id = "hermes:demo"

    gate = PromotionGate(workspace=tmp_path / "ws", run_tests=False, run_smoke=False)

    with patch("js.skills.promotion_gate.validate_skill") as mock_validate:
        result = await gate.run(spec)

    assert result.passed is False
    assert result.failed_step == "protected"
    mock_validate.assert_not_called()


@pytest.mark.asyncio
async def test_gate_blocks_builtin_skill(tmp_path: Path) -> None:
    spec = _write_skill_dir(tmp_path, "builtin_skill", trust_level="builtin")
    gate = PromotionGate(workspace=tmp_path / "ws", run_tests=False, run_smoke=False)
    result = await gate.run(spec)
    assert result.passed is False
    assert result.failed_step == "protected"


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gate_fails_when_path_missing(tmp_path: Path) -> None:
    spec = SkillSpec(
        id="ghost",
        name="ghost",
        type=SkillType.CODE,
        trust_level=TrustLevel.COMMUNITY,
        path=tmp_path / "does_not_exist",
    )
    gate = PromotionGate(workspace=tmp_path / "ws", run_tests=False, run_smoke=False)
    result = await gate.run(spec)
    assert result.passed is False
    assert result.failed_step == "validate"


@pytest.mark.asyncio
async def test_gate_fails_on_invalid_manifest(tmp_path: Path) -> None:
    spec = _write_skill_dir(tmp_path, "bad_yaml_skill", bad_yaml=True)
    gate = PromotionGate(workspace=tmp_path / "ws", run_tests=False, run_smoke=False)
    result = await gate.run(spec)
    assert result.passed is False
    assert result.failed_step == "validate"


# ---------------------------------------------------------------------------
# security
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gate_fails_when_security_returns_quarantine(tmp_path: Path) -> None:
    spec = _write_skill_dir(tmp_path, "good_skill")
    gate = PromotionGate(workspace=tmp_path / "ws", run_tests=False, run_smoke=False)

    # Force scan_skill to return a QUARANTINE result.
    from js.skills.security import ScanResult

    fake = ScanResult(
        skill_id=spec.id,
        content_hash="abc",
        risk_flags=["network_exfil", "code_execution", "credential_access"],
        trust_level=TrustLevel.QUARANTINE,
    )
    with patch("js.skills.promotion_gate.scan_skill", return_value=fake):
        result = await gate.run(spec)
    assert result.passed is False
    assert result.failed_step == "security"
    assert result.details["trust_level"] == "quarantine"


@pytest.mark.asyncio
async def test_gate_fails_when_runtime_security_check_returns_false(tmp_path: Path) -> None:
    spec = _write_skill_dir(tmp_path, "rt_fail_skill")
    gate = PromotionGate(workspace=tmp_path / "ws", run_tests=False, run_smoke=False)
    with patch(
        "js.skills.promotion_gate.runtime_security_check",
        return_value=(False, ["sensitive_path_access"]),
    ):
        result = await gate.run(spec)
    assert result.passed is False
    assert result.failed_step == "security"
    assert "sensitive_path_access" in result.details["runtime_warnings"]


# ---------------------------------------------------------------------------
# tests step
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gate_fails_when_tester_reports_failure(tmp_path: Path) -> None:
    spec = _write_skill_dir(tmp_path, "test_fail_skill")
    gate = PromotionGate(workspace=tmp_path / "ws", run_smoke=False)

    from js.skills.tester import TestReport, TestResult

    bad = TestReport(
        skill_id=spec.id,
        results=[TestResult(name="pytest_suite", passed=False, error="boom")],
    )

    async def fake_run_tests(_dir: Path) -> TestReport:
        return bad

    with patch("js.skills.promotion_gate.run_skill_tests", side_effect=fake_run_tests):
        result = await gate.run(spec)
    assert result.passed is False
    assert result.failed_step == "tests"


# ---------------------------------------------------------------------------
# smoke
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gate_fails_when_smoke_returns_failure(tmp_path: Path) -> None:
    spec = _write_skill_dir(tmp_path, "smoke_fail_skill")
    gate = PromotionGate(workspace=tmp_path / "ws", run_tests=False)

    async def fake_exec(*_a: Any, **_kw: Any) -> dict[str, Any]:
        return {"success": False, "error": "boom-smoke"}

    with patch("js.skills.promotion_gate.execute_skill", side_effect=fake_exec):
        result = await gate.run(spec)
    assert result.passed is False
    assert result.failed_step == "smoke"
    assert "boom-smoke" in result.details["smoke_error"]


@pytest.mark.asyncio
async def test_gate_pass_when_smoke_succeeds(tmp_path: Path) -> None:
    spec = _write_skill_dir(tmp_path, "happy_skill")
    gate = PromotionGate(workspace=tmp_path / "ws", run_tests=False)

    async def fake_exec(*_a: Any, **_kw: Any) -> dict[str, Any]:
        return {"success": True, "output": "smoked"}

    with patch("js.skills.promotion_gate.execute_skill", side_effect=fake_exec):
        result = await gate.run(spec)
    assert result.passed is True
    assert result.failed_step is None
    assert result.details["smoke"]["success"] is True


# ---------------------------------------------------------------------------
# telemetry: metric is emitted on every finish
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gate_emits_metric_on_pass(tmp_path: Path) -> None:
    spec = _write_skill_dir(tmp_path, "metric_pass")
    gate = PromotionGate(workspace=tmp_path / "ws", run_tests=False)

    async def fake_exec(*_a: Any, **_kw: Any) -> dict[str, Any]:
        return {"success": True, "output": ""}

    with (
        patch("js.skills.promotion_gate.execute_skill", side_effect=fake_exec),
        patch("js.utils.metrics.get_metrics") as mock_metrics,
    ):
        await gate.run(spec)
    mock_metrics.return_value.skill_promotion_events_total.labels.assert_called_with(
        decision="pass", failed_step=""
    )
    inc = mock_metrics.return_value.skill_promotion_events_total.labels.return_value.inc
    inc.assert_called_once()


@pytest.mark.asyncio
async def test_gate_emits_metric_on_protected(tmp_path: Path) -> None:
    spec = _write_skill_dir(tmp_path, "hermes_x")
    spec.id = "hermes:x"
    gate = PromotionGate(workspace=tmp_path / "ws", run_tests=False, run_smoke=False)
    with patch("js.utils.metrics.get_metrics") as mock_metrics:
        await gate.run(spec)
    mock_metrics.return_value.skill_promotion_events_total.labels.assert_called_with(
        decision="fail", failed_step="protected"
    )


# ---------------------------------------------------------------------------
# anti-regression: gate must NOT pollute skills.db
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gate_does_not_write_to_skill_usage(tmp_path: Path) -> None:
    """The gate goes through ``execute_skill`` (low-level), bypassing
    ``SkillManager.execute`` and its `_record_usage` insert into ``skill_usage``.
    This is the contract that keeps curator's stats clean.
    """
    spec = _write_skill_dir(tmp_path, "no_usage_pollution")
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    from js.skills.manager import SkillManager

    mgr = SkillManager(state_dir=state_dir, workspace=tmp_path / "ws")
    mgr._skills[spec.id] = spec  # type: ignore[attr-defined]

    gate = PromotionGate(workspace=tmp_path / "ws", run_tests=False)

    async def fake_exec(*_a: Any, **_kw: Any) -> dict[str, Any]:
        return {"success": True, "output": ""}

    with patch("js.skills.promotion_gate.execute_skill", side_effect=fake_exec):
        await gate.run(spec)
    assert _count_skill_usage_rows(state_dir / "skills.db") == 0


# ---------------------------------------------------------------------------
# audit event type: pass/fail both emit SKILL_PROMOTION_GATE (NOT SECURITY_BLOCK)
# ---------------------------------------------------------------------------


class _RecordingAuditLogger:
    """Minimal audit logger stand-in that captures the (event_type, action,
    details) tuples we care about for assertions. Mirrors the real
    ``AuditLogger.log`` signature so the production code path is exercised
    without spinning up a SQLite DB.
    """

    def __init__(self) -> None:
        self.events: list[tuple[Any, str, dict[str, Any]]] = []

    def log(
        self,
        event_type: Any,
        session_id: str,
        run_id: str,
        actor: str,
        action: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.events.append((event_type, action, dict(details or {})))


@pytest.mark.asyncio
async def test_gate_pass_emits_skill_promotion_gate_audit(tmp_path: Path) -> None:
    from js.security.audit import AuditEventType

    spec = _write_skill_dir(tmp_path, "audit_pass")
    audit = _RecordingAuditLogger()
    gate = PromotionGate(workspace=tmp_path / "ws", run_tests=False, audit_logger=audit)

    async def fake_exec(*_a: Any, **_kw: Any) -> dict[str, Any]:
        return {"success": True, "output": ""}

    with patch("js.skills.promotion_gate.execute_skill", side_effect=fake_exec):
        await gate.run(spec)

    types = [e[0] for e in audit.events]
    actions = [e[1] for e in audit.events]
    assert AuditEventType.SKILL_PROMOTION_GATE in types
    assert AuditEventType.SECURITY_BLOCK not in types  # never reuse for gate
    assert "skill_promotion_gate" in actions
    # The matching event payload carries the decision marker.
    matching = [e for e in audit.events if e[0] == AuditEventType.SKILL_PROMOTION_GATE]
    assert matching[0][2].get("decision") == "pass"


@pytest.mark.asyncio
async def test_gate_fail_emits_skill_promotion_gate_audit_not_security_block(
    tmp_path: Path,
) -> None:
    """A gate failure (e.g. security step) must still log SKILL_PROMOTION_GATE
    — never SECURITY_BLOCK. The failure reason rides on details.failed_step,
    which is also the metric label that callers query.
    """
    from js.security.audit import AuditEventType
    from js.skills.security import ScanResult

    spec = _write_skill_dir(tmp_path, "audit_fail")
    audit = _RecordingAuditLogger()
    gate = PromotionGate(
        workspace=tmp_path / "ws",
        run_tests=False,
        run_smoke=False,
        audit_logger=audit,
    )

    fake_scan = ScanResult(
        skill_id=spec.id,
        content_hash="abc",
        risk_flags=["code_execution"],
        trust_level=TrustLevel.QUARANTINE,
    )
    with patch("js.skills.promotion_gate.scan_skill", return_value=fake_scan):
        result = await gate.run(spec)

    assert result.passed is False
    assert result.failed_step == "security"
    types = [e[0] for e in audit.events]
    assert AuditEventType.SKILL_PROMOTION_GATE in types
    assert AuditEventType.SECURITY_BLOCK not in types
    matching = [e for e in audit.events if e[0] == AuditEventType.SKILL_PROMOTION_GATE]
    assert matching[0][2].get("decision") == "fail"
    assert matching[0][2].get("failed_step") == "security"


# ---------------------------------------------------------------------------
# GateResult contract
# ---------------------------------------------------------------------------


def test_gate_result_to_dict() -> None:
    r = GateResult(passed=False, failed_step="security", details={"k": "v"})
    d = r.to_dict()
    assert d["passed"] is False
    assert d["failed_step"] == "security"
    assert d["details"]["k"] == "v"


# ---------------------------------------------------------------------------
# smoke timeout: hard ceiling on execute_skill
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gate_smoke_timeout_fails_gracefully(tmp_path: Path) -> None:
    """A hanging skill must fail at ``smoke`` with details.timeout=True.

    Regression guard for the v0.1.5-alpha contract: a runaway smoke
    execution previously could stall ``apply_proposal`` indefinitely.
    The wait_for guard caps it at ``smoke_timeout`` seconds and the
    failure surfaces as a normal gate fail — trust / entry file /
    skill_usage all remain untouched (smoke goes through
    ``execute_skill`` low-level, which never writes ``skill_usage``).
    """
    import asyncio as _asyncio

    spec = _write_skill_dir(tmp_path, "timeout_skill")
    gate = PromotionGate(workspace=tmp_path / "ws", run_tests=False, smoke_timeout=0.05)

    async def hanging_exec(*_a: Any, **_kw: Any) -> dict[str, Any]:
        # Sleep longer than smoke_timeout to force the wait_for to fire.
        await _asyncio.sleep(1.0)
        return {"success": True}

    with patch("js.skills.promotion_gate.execute_skill", side_effect=hanging_exec):
        result = await gate.run(spec)

    assert result.passed is False
    assert result.failed_step == "smoke"
    assert result.details.get("timeout") is True
    assert "timeout" in result.details.get("smoke_error", "")
    # gate did NOT pollute skill_usage (smoke uses low-level execute_skill).
    assert _count_skill_usage_rows(tmp_path / "ws" / "skills.db") == 0


@pytest.mark.asyncio
async def test_gate_smoke_timeout_emits_metric(tmp_path: Path) -> None:
    """Smoke timeout still emits the standard fail metric so callers can alert."""
    import asyncio as _asyncio

    spec = _write_skill_dir(tmp_path, "timeout_metric_skill")
    gate = PromotionGate(workspace=tmp_path / "ws", run_tests=False, smoke_timeout=0.05)

    async def hanging_exec(*_a: Any, **_kw: Any) -> dict[str, Any]:
        await _asyncio.sleep(1.0)
        return {"success": True}

    with (
        patch("js.skills.promotion_gate.execute_skill", side_effect=hanging_exec),
        patch("js.utils.metrics.get_metrics") as mock_metrics,
    ):
        await gate.run(spec)

    mock_metrics.return_value.skill_promotion_events_total.labels.assert_called_with(
        decision="fail", failed_step="smoke"
    )
