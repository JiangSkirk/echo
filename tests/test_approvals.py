"""Tests for approval system."""

import pytest

from js.approvals.queue import ApprovalMode, ApprovalQueue


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
        queue.set_callback("test_session", lambda req: True)
        result = queue.request("shell", {"command": "ls"}, context="cli", mode=ApprovalMode.CRON_DENY, session_id="test_session")
        assert result is True

    def test_stats(self, queue: ApprovalQueue) -> None:
        # Use callback to avoid input()
        queue.set_callback("test_session", lambda req: True)
        queue.request("shell", {"command": "ls"}, mode=ApprovalMode.MANUAL, session_id="test_session")
        queue.set_callback("test_session", lambda req: False)
        queue.request("shell", {"command": "rm"}, mode=ApprovalMode.MANUAL, session_id="test_session")
        stats = queue.get_stats()
        assert stats["total_requests"] == 2
