"""Skill promotion gate: validate → security → tests → sandbox smoke.

The gate is consulted before any *apply* of a promotion proposal — either a
trust-level change (auto_curator / operator) or an evolver code variant. It
runs the existing skill primitives in order, short-circuiting on the first
failure, and emits a single audit/metric event per run. The gate is purely
in-process and side-effect-free w.r.t. ``skills.db`` — in particular the
sandbox smoke step calls :func:`js.skills.executor.execute_skill` directly,
so the curator's usage statistics are never polluted by gate-only runs.

Failure semantics
-----------------

A failure at any step returns ``GateResult(passed=False, failed_step=...)``
without raising. Internal exceptions are caught and surfaced as
``failed_step="<step>"`` with a truncated traceback in ``details``; this
keeps the apply path deterministic.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from js.security.audit import AuditEventType, AuditLogger
from js.security.sandbox import SandboxExecutor
from js.skills.evolver import _is_protected_for_promote
from js.skills.executor import execute_skill
from js.skills.security import runtime_security_check, scan_skill
from js.skills.spec import SkillSpec, TrustLevel
from js.skills.tester import run_skill_tests
from js.skills.validator import validate_skill
from js.utils.log import get_logger

logger = get_logger("js.skills.promotion_gate")


GATE_STEPS: tuple[str, ...] = ("protected", "validate", "security", "tests", "smoke")


@dataclass
class GateResult:
    """Outcome of a single ``PromotionGate.run`` invocation."""

    passed: bool
    failed_step: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "failed_step": self.failed_step,
            "details": self.details,
        }


class PromotionGate:
    """Run the gate sequence for a single skill spec.

    Construct one gate per evaluation; ``run`` is async and may take seconds
    (the tester runs ``pytest`` in a subprocess with a 60 s timeout).
    """

    def __init__(
        self,
        *,
        workspace: Path,
        sandbox: SandboxExecutor | None = None,
        smoke_args: dict[str, Any] | None = None,
        audit_logger: AuditLogger | None = None,
        session_id: str = "",
        run_id: str = "",
        run_tests: bool = True,
        run_smoke: bool = True,
        smoke_timeout: float = 30.0,
    ) -> None:
        self.workspace = Path(workspace)
        self.sandbox = sandbox
        self.smoke_args = dict(smoke_args or {})
        self.audit_logger = audit_logger
        self.session_id = session_id
        self.run_id = run_id
        # Tests and smoke can be disabled for the cheap-and-fast preview
        # path used by curator/evolver — they only really need
        # protected + validate + security to vet a proposal *into* the queue.
        self.run_tests = run_tests
        self.run_smoke = run_smoke
        # Hard ceiling on the smoke ``execute_skill`` call. A malicious or
        # buggy skill that hangs would otherwise stall ``apply_proposal``
        # indefinitely. On timeout we fail the gate at the "smoke" step with
        # details.timeout=True; trust / entry file / skill_usage stay
        # untouched (smoke goes through ``execute_skill`` directly, which
        # bypasses ``SkillManager.execute._record_usage``).
        self.smoke_timeout = float(smoke_timeout)

    async def run(self, spec: SkillSpec) -> GateResult:
        """Run the gate steps in order, short-circuiting on first failure."""
        # 1. protected: builtin / hermes:* are never auto-modifiable.
        if _is_protected_for_promote(spec.id, spec.path):
            return self._finish(
                passed=False,
                failed_step="protected",
                details={"skill_id": spec.id, "reason": "builtin or hermes skill"},
            )

        # 2. validate
        try:
            if spec.path is None or not spec.path.exists():
                return self._finish(
                    passed=False,
                    failed_step="validate",
                    details={"skill_id": spec.id, "reason": "spec.path missing"},
                )
            validation = await asyncio.to_thread(validate_skill, spec.path)
            if not validation.passed:
                return self._finish(
                    passed=False,
                    failed_step="validate",
                    details={"skill_id": spec.id, "validate": validation.to_dict()},
                )
            validate_details = validation.to_dict()
        except Exception as exc:
            return self._finish(
                passed=False,
                failed_step="validate",
                details=_exc_details(spec.id, exc),
            )

        # 3. security
        try:
            scan = await asyncio.to_thread(scan_skill, spec)
            if scan.trust_level == TrustLevel.QUARANTINE:
                return self._finish(
                    passed=False,
                    failed_step="security",
                    details={
                        "skill_id": spec.id,
                        "trust_level": scan.trust_level.value,
                        "risk_flags": scan.risk_flags,
                    },
                )
            runtime_ok, runtime_warnings = await asyncio.to_thread(runtime_security_check, spec)
            if not runtime_ok:
                return self._finish(
                    passed=False,
                    failed_step="security",
                    details={
                        "skill_id": spec.id,
                        "runtime_warnings": runtime_warnings,
                        "risk_flags": scan.risk_flags,
                    },
                )
            security_details = {
                "trust_level": scan.trust_level.value,
                "risk_flags": scan.risk_flags,
                "runtime_warnings": runtime_warnings,
            }
        except Exception as exc:
            return self._finish(
                passed=False,
                failed_step="security",
                details=_exc_details(spec.id, exc),
            )

        # 4. tests (optional)
        test_details: dict[str, Any] = {"skipped": True}
        if self.run_tests:
            tmp_root = Path(tempfile.mkdtemp(prefix="promo_gate_tests_"))
            try:
                # Copy the skill dir so the auto-generated test_*.py stubs
                # written by tester don't pollute the source tree.
                copy_root = tmp_root / f"skill_copy_{uuid.uuid4().hex[:8]}"
                await asyncio.to_thread(_copy_skill_dir, spec.path, copy_root)
                report = await run_skill_tests(copy_root)
                if not report.passed:
                    return self._finish(
                        passed=False,
                        failed_step="tests",
                        details={
                            "skill_id": spec.id,
                            "tests": report.to_dict(),
                        },
                    )
                test_details = report.to_dict()
            except Exception as exc:
                return self._finish(
                    passed=False,
                    failed_step="tests",
                    details=_exc_details(spec.id, exc),
                )
            finally:
                shutil.rmtree(tmp_root, ignore_errors=True)

        # 5. sandbox smoke (optional)
        smoke_details: dict[str, Any] = {"skipped": True}
        if self.run_smoke:
            tmp_root = Path(tempfile.mkdtemp(prefix="promo_gate_smoke_"))
            try:
                workspace = tmp_root / "workspace"
                workspace.mkdir(parents=True, exist_ok=True)
                try:
                    exec_result = await asyncio.wait_for(
                        execute_skill(
                            spec,
                            self.smoke_args,
                            workspace,
                            llm_caller=None,
                            sandbox=self.sandbox,
                            skill_resolver=None,
                        ),
                        timeout=self.smoke_timeout,
                    )
                except TimeoutError:
                    return self._finish(
                        passed=False,
                        failed_step="smoke",
                        details={
                            "skill_id": spec.id,
                            "timeout": True,
                            "smoke_error": f"timeout after {self.smoke_timeout:g}s",
                        },
                    )
                if not exec_result.get("success", False):
                    return self._finish(
                        passed=False,
                        failed_step="smoke",
                        details={
                            "skill_id": spec.id,
                            "smoke_error": str(exec_result.get("error", ""))[:500],
                        },
                    )
                smoke_details = {
                    "success": True,
                    "output_preview": str(exec_result.get("output", ""))[:200],
                }
            except Exception as exc:
                return self._finish(
                    passed=False,
                    failed_step="smoke",
                    details=_exc_details(spec.id, exc),
                )
            finally:
                shutil.rmtree(tmp_root, ignore_errors=True)

        return self._finish(
            passed=True,
            failed_step=None,
            details={
                "skill_id": spec.id,
                "validate": validate_details,
                "security": security_details,
                "tests": test_details,
                "smoke": smoke_details,
            },
        )

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _finish(
        self,
        *,
        passed: bool,
        failed_step: str | None,
        details: dict[str, Any],
    ) -> GateResult:
        # Telemetry: audit + metrics never raise into the caller.
        decision = "pass" if passed else "fail"
        details_with_meta = dict(details)
        details_with_meta.setdefault("decision", decision)
        details_with_meta.setdefault("failed_step", failed_step or "")
        details_with_meta.setdefault("timestamp", time.time())

        try:
            if self.audit_logger is not None:
                # v0.1.5-alpha提交前修正：pass / fail 一律打 SKILL_PROMOTION_GATE，
                # 不要复用 SECURITY_BLOCK —— gate 失败的原因已经在
                # details.failed_step 和 skill_promotion_events_total{decision,
                # failed_step} 里有专门的承载，复用安全事件会让审计查询
                # 把 gate 的常规拒绝和真实的安全告警混在一起。
                self.audit_logger.log(
                    AuditEventType.SKILL_PROMOTION_GATE,
                    self.session_id,
                    self.run_id,
                    actor="promotion_gate",
                    action="skill_promotion_gate",
                    details=details_with_meta,
                )
        except Exception:
            logger.warning("Audit emit failed for promotion_gate", exc_info=True)

        try:
            from js.utils.metrics import get_metrics

            m = get_metrics()
            m.skill_promotion_events_total.labels(
                decision=decision,
                failed_step=failed_step or "",
            ).inc()
        except Exception:
            logger.warning("Metric emit failed for promotion_gate", exc_info=True)

        return GateResult(passed=passed, failed_step=failed_step, details=details_with_meta)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _exc_details(skill_id: str, exc: BaseException) -> dict[str, Any]:
    tb = "".join(traceback.format_exception_only(type(exc), exc)).strip()
    return {
        "skill_id": skill_id,
        "exception": tb[-500:],
    }


def _copy_skill_dir(src: Path, dst: Path) -> None:
    """Copy skill directory while rejecting symlinks defensively."""
    shutil.copytree(src, dst, symlinks=False)
    for item in dst.rglob("*"):
        if item.is_symlink():
            raise RuntimeError(f"Skill copy contains symlinks: {item.relative_to(dst)}")
