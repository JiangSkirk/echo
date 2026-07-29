"""Tests for approval system."""

import json
from pathlib import Path

import pytest

from js.security.approvals import (
    ApprovalDecisionType,
    ApprovalMode,
    ApprovalQueue,
)


class TestApprovalQueue:
    @pytest.fixture
    def queue(self) -> ApprovalQueue:
        return ApprovalQueue(default_mode=ApprovalMode.MANUAL)

    def test_auto_approve(self, queue: ApprovalQueue) -> None:
        result = queue.request("shell", {"command": "ls"}, mode=ApprovalMode.AUTO_APPROVE)
        assert result is True

    def test_auto_deny(self, queue: ApprovalQueue) -> None:
        result = queue.request("shell", {"command": "ls"}, mode=ApprovalMode.AUTO_DENY)
        assert result is False

    def test_cron_deny(self, queue: ApprovalQueue) -> None:
        result = queue.request("shell", {"command": "ls"}, context="cron", mode=ApprovalMode.CRON_DENY)
        assert result is False

    def test_cron_allow_non_cron(self, queue: ApprovalQueue) -> None:
        # In CRON_DENY mode, non-cron context falls through to manual
        # Use callback to avoid input()
        arguments = {"command": "ls"}
        queue.set_callback(
            "test_session",
            lambda req: True,
            owner_key_hash="owner-a",
            run_id="run-a",
            tool_name="shell",
            arguments=arguments,
        )
        result = queue.request_decision(
            "shell",
            arguments,
            context="cli",
            mode=ApprovalMode.CRON_DENY,
            session_id="test_session",
            run_id="run-a",
            owner_key_hash="owner-a",
        )
        assert result.approved is True

    def test_stats(self, queue: ApprovalQueue) -> None:
        # Use callback to avoid input()
        queue.set_callback(
            "test_session",
            lambda req: True,
            owner_key_hash="owner-a",
            run_id="run-a",
            tool_name="shell",
            arguments={"command": "ls"},
        )
        queue.request_decision(
            "shell",
            {"command": "ls"},
            mode=ApprovalMode.MANUAL,
            session_id="test_session",
            run_id="run-a",
            owner_key_hash="owner-a",
        )
        queue.set_callback(
            "test_session",
            lambda req: False,
            owner_key_hash="owner-a",
            run_id="run-b",
            tool_name="shell",
            arguments={"command": "rm"},
        )
        queue.request_decision(
            "shell",
            {"command": "rm"},
            mode=ApprovalMode.MANUAL,
            session_id="test_session",
            run_id="run-b",
            owner_key_hash="owner-a",
        )
        stats = queue.get_stats()
        assert stats["total_requests"] == 2

    def test_callback_registration_requires_complete_effect_binding(
        self,
        queue: ApprovalQueue,
    ) -> None:
        with pytest.raises(ValueError, match="complete Echo effect binding"):
            queue.set_callback("test_session", lambda _request: True)

    @pytest.mark.parametrize(
        ("request_overrides", "expected_reason"),
        [
            ({"owner_key_hash": "owner-b"}, "callback_binding_mismatch"),
            ({"run_id": "run-b"}, "callback_binding_mismatch"),
            ({"tool_name": "file_delete"}, "callback_binding_mismatch"),
            ({"arguments": {"command": "cat /etc/passwd"}}, "callback_binding_mismatch"),
        ],
    )
    def test_bound_callback_cannot_approve_a_different_request(
        self,
        queue: ApprovalQueue,
        request_overrides: dict[str, object],
        expected_reason: str,
    ) -> None:
        queue.set_callback(
            "sess-a",
            lambda _request: True,
            owner_key_hash="owner-a",
            run_id="run-a",
            tool_name="shell",
            arguments={"command": "ls"},
        )
        request = {
            "tool_name": "shell",
            "arguments": {"command": "ls"},
            "context": "web",
            "session_id": "sess-a",
            "run_id": "run-a",
            "owner_key_hash": "owner-a",
            "queue_if_unhandled": True,
        }
        request.update(request_overrides)

        decision = queue.request_decision(**request)  # type: ignore[arg-type]

        assert decision.action == ApprovalDecisionType.PENDING
        assert decision.reason == expected_reason

    def test_bound_callback_approves_only_the_exact_request(
        self,
        queue: ApprovalQueue,
    ) -> None:
        arguments = {"command": "ls"}
        queue.set_callback(
            "sess-a",
            lambda _request: True,
            owner_key_hash="owner-a",
            run_id="run-a",
            tool_name="shell",
            arguments=arguments,
        )

        decision = queue.request_decision(
            "shell",
            arguments,
            context="web",
            session_id="sess-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )

        assert decision.action == ApprovalDecisionType.APPROVE

    def test_echo_queue_pending_request_can_be_edited_and_audited(
        self,
        tmp_path: Path,
    ) -> None:
        ledger_path = tmp_path / "echo_approvals.jsonl"
        queue = ApprovalQueue(
            default_mode=ApprovalMode.MANUAL,
            ledger_path=ledger_path,
        )

        decision = queue.request_decision(
            "shell",
            {"command": "rm -rf build"},
            context="web",
            session_id="sess-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )

        assert decision.action == ApprovalDecisionType.PENDING
        assert decision.request_id
        assert len(queue.get_pending()) == 1

        resolved = queue.decide(
            decision.request_id,
            ApprovalDecisionType.EDIT,
            edited_arguments={"command": "ls build"},
            reason="narrow command",
        )

        assert resolved.action == ApprovalDecisionType.EDIT
        assert resolved.edited_arguments == {"command": "ls build"}
        assert queue.get_pending() == []
        ledger_text = ledger_path.read_text(encoding="utf-8")
        assert '"event_type":"approval_requested"' in ledger_text
        assert '"event_type":"approval_edited"' in ledger_text
        assert "rm -rf build" not in ledger_text

    def test_echo_queue_supports_respond_decision(self, tmp_path: Path) -> None:
        queue = ApprovalQueue(
            default_mode=ApprovalMode.MANUAL,
            ledger_path=tmp_path / "echo_approvals.jsonl",
        )

        pending = queue.request_decision(
            "shell",
            {"command": "deploy"},
            context="web",
            session_id="sess-a",
            run_id="run-a",
            queue_if_unhandled=True,
        )
        response = queue.decide(
            pending.request_id,
            ApprovalDecisionType.RESPOND,
            response="Deployment requires manual release approval.",
        )

        assert response.action == ApprovalDecisionType.RESPOND
        assert response.response == "Deployment requires manual release approval."
        stats = queue.get_stats()
        assert stats["resolved"] == 1
        assert stats["denied"] == 1

    def test_client_reason_is_redacted_before_approval_ledger_write(
        self,
        tmp_path: Path,
    ) -> None:
        ledger_path = tmp_path / "echo_approvals.jsonl"
        queue = ApprovalQueue(ledger_path=ledger_path)
        secret = "sk-test12345678901234567890ABCDEFGH"
        pending = queue.request_decision(
            "shell",
            {"command": "pwd"},
            context="web",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )

        queue.decide(
            pending.request_id,
            ApprovalDecisionType.RESPOND,
            response="safe",
            reason=f"diagnostic {secret}",
        )

        ledger_text = ledger_path.read_text(encoding="utf-8")
        assert secret not in ledger_text
        assert "[REDACTED:openai_key]" in ledger_text

    def test_pending_requests_are_owner_scoped(self, queue: ApprovalQueue) -> None:
        first = queue.request_decision(
            "shell",
            {"command": "echo owner-a"},
            context="web",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )
        queue.request_decision(
            "shell",
            {"command": "echo owner-b"},
            context="web",
            session_id="session-b",
            run_id="run-b",
            owner_key_hash="owner-b",
            queue_if_unhandled=True,
        )

        pending = queue.get_pending(owner_key_hash="owner-a")
        assert [request.id for request in pending] == [first.request_id]
        assert queue.get_pending_request(first.request_id, owner_key_hash="owner-a") is not None
        assert queue.get_pending_request(first.request_id, owner_key_hash="owner-b") is None

    def test_resolved_decision_can_be_consumed_exactly_once(self, queue: ApprovalQueue) -> None:
        pending = queue.request_decision(
            "shell",
            {"command": "echo safe"},
            context="web",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )
        queue.decide(pending.request_id, ApprovalDecisionType.APPROVE, reason="operator")

        consumed = queue.take_decision(pending.request_id)
        assert consumed is not None
        assert consumed.action == ApprovalDecisionType.APPROVE
        assert queue.take_decision(pending.request_id) is None

    def test_resolved_decision_cannot_be_consumed_by_another_owner(
        self,
        queue: ApprovalQueue,
    ) -> None:
        pending = queue.request_decision(
            "shell",
            {"command": "echo safe"},
            context="web",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )
        queue.decide(pending.request_id, ApprovalDecisionType.APPROVE)

        assert queue.take_decision(
            pending.request_id,
            owner_key_hash="owner-b",
        ) is None
        assert queue.take_decision(
            pending.request_id,
            owner_key_hash="owner-a",
        ) is not None

    def test_ledger_sequence_continues_after_restart(self, tmp_path: Path) -> None:
        ledger_path = tmp_path / "echo_approvals.jsonl"
        first_queue = ApprovalQueue(ledger_path=ledger_path)
        first_queue.request_decision(
            "shell",
            {"command": "echo first"},
            context="web",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )

        second_queue = ApprovalQueue(ledger_path=ledger_path)
        second_queue.request_decision(
            "shell",
            {"command": "echo second"},
            context="web",
            session_id="session-b",
            run_id="run-b",
            owner_key_hash="owner-b",
            queue_if_unhandled=True,
        )

        rows = [json.loads(line) for line in ledger_path.read_text().splitlines()]
        assert [row["seq"] for row in rows] == [0, 1]

    def test_decide_rejects_cross_owner_resolution(self, tmp_path: Path) -> None:
        """P0-4: decide 必须校验 owner，拒绝跨 owner 审批（§3.5 隔离要求）."""
        ledger_path = tmp_path / "echo_approvals.jsonl"
        queue = ApprovalQueue(ledger_path=ledger_path, default_mode=ApprovalMode.MANUAL)
        # owner-a 创建审批
        pending = queue.request_decision(
            "shell",
            {"command": "ls"},
            context="web",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )
        assert pending is not None
        request_id = pending.request_id

        # owner-b 试图解决 owner-a 的审批 -> 应被拒绝
        decision = queue.decide(
            request_id,
            ApprovalDecisionType.APPROVE,
            owner_key_hash="owner-b",
        )
        assert decision.action == ApprovalDecisionType.PENDING, (
            "跨 owner decide 应返回 PENDING，不解决审批"
        )
        # owner-a 仍可解决
        decision_a = queue.decide(
            request_id,
            ApprovalDecisionType.APPROVE,
            owner_key_hash="owner-a",
        )
        assert decision_a.action == ApprovalDecisionType.APPROVE

    def test_auto_approve_writes_ledger_event(self, tmp_path: Path) -> None:
        """P0-2: AUTO_APPROVE 也必须写审批账本（§8 所有审批事件写入）."""
        ledger_path = tmp_path / "echo_approvals.jsonl"
        queue = ApprovalQueue(ledger_path=ledger_path)
        queue.request_decision(
            "shell",
            {"command": "ls"},
            context="web",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            mode=ApprovalMode.AUTO_APPROVE,
        )
        rows = [json.loads(line) for line in ledger_path.read_text().splitlines()]
        assert len(rows) > 0, "AUTO_APPROVE 也应写审批账本"
        assert any(r["event_type"] == "approval_approved" for r in rows), (
            f"应有 approval_approved 事件, got {[r['event_type'] for r in rows]}"
        )

    def test_auto_deny_writes_ledger_event(self, tmp_path: Path) -> None:
        """P0-2: AUTO_DENY 也必须写审批账本."""
        ledger_path = tmp_path / "echo_approvals.jsonl"
        queue = ApprovalQueue(ledger_path=ledger_path)
        queue.request_decision(
            "shell",
            {"command": "ls"},
            context="web",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            mode=ApprovalMode.AUTO_DENY,
        )
        rows = [json.loads(line) for line in ledger_path.read_text().splitlines()]
        assert len(rows) > 0, "AUTO_DENY 也应写审批账本"
        assert any(r["event_type"] == "approval_rejected" for r in rows), (
            f"应有 approval_rejected 事件, got {[r['event_type'] for r in rows]}"
        )
