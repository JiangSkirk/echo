"""Manual validation script for js-agent security subsystem."""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path


def test_behavior_guard_loop_detection() -> bool:
    print("[1/4] Testing BehaviorGuard loop detection...")
    from js.config import DefenseMode, SecurityConfig
    from js.security.guard import BehaviorGuard

    config = SecurityConfig(defense_mode=DefenseMode.ENFORCE, max_loop_iterations=3)
    workspace = Path(tempfile.mkdtemp(prefix="js_guard_"))
    guard = BehaviorGuard(config, workspace)

    run_id = "test-run-001"
    tool_name = "test_tool"
    args_key = "arg1=val1"

    # With max_loop_iterations=3:
    # count=1 -> ALLOW, count=2 -> WARN (2 > 3//2), count=3 -> WARN, count=4 -> BLOCK
    decision = guard.check_loop(run_id, tool_name, args_key)
    assert decision.decision == "allow", f"Call 1 should be allowed, got {decision.decision}"

    decision = guard.check_loop(run_id, tool_name, args_key)
    assert decision.decision == "warn", f"Call 2 should warn, got {decision.decision}"

    decision = guard.check_loop(run_id, tool_name, args_key)
    assert decision.decision == "warn", f"Call 3 should warn, got {decision.decision}"

    # 4th call should trigger loop detection (max=3)
    decision = guard.check_loop(run_id, tool_name, args_key)
    assert decision.decision == "block", f"Call 4 should be blocked, got {decision.decision}"
    assert "loop" in decision.reason.lower(), f"Expected loop reason, got: {decision.reason}"

    print("     ✓ Loop detection works correctly")
    return True


async def test_sandbox_executor() -> bool:
    print("[2/4] Testing SandboxExecutor...")
    from js.security.sandbox import SandboxExecutor

    workspace = Path(tempfile.mkdtemp(prefix="js_sandbox_"))
    executor = SandboxExecutor(workspace=workspace, timeout=10.0)

    result = await executor.execute("echo hello")
    assert result.returncode == 0, f"Expected rc=0, got {result.returncode}"
    assert "hello" in result.stdout, f"Expected 'hello' in stdout, got: {result.stdout!r}"

    print(f"     ✓ SandboxExecutor ran successfully (stdout={result.stdout.strip()!r}, duration={result.duration_ms:.1f}ms)")
    return True


def test_audit_logger() -> bool:
    print("[3/4] Testing AuditLogger...")
    from js.security.audit import AuditEventType, AuditLogger

    state_dir = Path(tempfile.mkdtemp(prefix="js_audit_"))
    logger = AuditLogger(state_dir=state_dir)

    event = logger.log(
        event_type=AuditEventType.SECURITY_BLOCK,
        session_id="session-001",
        run_id="run-001",
        actor="manual_test",
        action="blocked_rm_rf",
        details={"command": "rm -rf /", "reason": "hardline"},
    )

    assert event.checksum, "Event should have a checksum"

    # Query it back
    results = logger.query(session_id="session-001", event_type=AuditEventType.SECURITY_BLOCK)
    assert len(results) == 1, f"Expected 1 result, got {len(results)}"
    assert results[0].action == "blocked_rm_rf"
    assert results[0].details["command"] == "rm -rf /"

    # Verify chain integrity
    valid, first_invalid = logger.verify_chain()
    assert valid, f"Chain invalid at id {first_invalid}"

    print("     ✓ AuditLogger wrote, queried, and verified chain integrity")
    return True


def test_approvals() -> bool:
    print("[4/4] Testing ApprovalMode and ApprovalQueue...")
    from js.security.approvals import ApprovalMode, ApprovalQueue

    # Test enum values
    assert ApprovalMode.AUTO_APPROVE == "auto_approve"
    assert ApprovalMode.AUTO_DENY == "auto_deny"
    assert ApprovalMode.CRON_DENY == "cron_deny"
    assert ApprovalMode.MANUAL == "manual"

    # Test queue with auto_approve
    queue = ApprovalQueue(default_mode=ApprovalMode.AUTO_APPROVE)
    approved = queue.request("dangerous_tool", {"path": "/etc/passwd"}, context="cli")
    assert approved is True, "AUTO_APPROVE should return True"

    # Test queue with auto_deny
    queue2 = ApprovalQueue(default_mode=ApprovalMode.AUTO_DENY)
    denied = queue2.request("dangerous_tool", {"path": "/etc/passwd"}, context="cli")
    assert denied is False, "AUTO_DENY should return False"

    # Test queue with cron_deny in cron context
    queue3 = ApprovalQueue(default_mode=ApprovalMode.CRON_DENY)
    denied = queue3.request("dangerous_tool", {"path": "/etc/passwd"}, context="cron")
    assert denied is False, "CRON_DENY in cron context should return False"

    # Test queue with cron_deny in non-cron context (falls back to manual, no callback -> deny)
    denied = queue3.request("dangerous_tool", {"path": "/etc/passwd"}, context="cli")
    assert denied is False, "CRON_DENY in cli context without callback should return False"

    print("     ✓ ApprovalMode and ApprovalQueue work correctly")
    return True


async def main() -> None:
    print("=" * 60)
    print("Manual Validation: js-agent Security Subsystem")
    print("=" * 60)

    results: dict[str, bool] = {}

    try:
        results["BehaviorGuard loop detection"] = test_behavior_guard_loop_detection()
    except Exception as e:
        print(f"     ✗ FAILED: {e}")
        results["BehaviorGuard loop detection"] = False

    try:
        results["SandboxExecutor"] = await test_sandbox_executor()
    except Exception as e:
        print(f"     ✗ FAILED: {e}")
        results["SandboxExecutor"] = False

    try:
        results["AuditLogger"] = test_audit_logger()
    except Exception as e:
        print(f"     ✗ FAILED: {e}")
        results["AuditLogger"] = False

    try:
        results["Approvals"] = test_approvals()
    except Exception as e:
        print(f"     ✗ FAILED: {e}")
        results["Approvals"] = False

    print("=" * 60)
    passed = sum(results.values())
    total = len(results)
    print(f"Results: {passed}/{total} validations passed")
    for name, ok in results.items():
        status = "✓ PASS" if ok else "✗ FAIL"
        print(f"  {status}: {name}")
    print("=" * 60)

    if passed == total:
        print("All manual validations PASSED ✓")
    else:
        print("Some manual validations FAILED ✗")


if __name__ == "__main__":
    asyncio.run(main())
