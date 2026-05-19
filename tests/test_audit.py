"""Tests for audit logging."""

from pathlib import Path

import pytest

from js.security.audit import AuditEventType, AuditLogger


class TestAuditLogger:
    @pytest.fixture
    def audit(self, tmp_path: Path) -> AuditLogger:
        return AuditLogger(tmp_path)

    def test_log_and_query(self, audit: AuditLogger) -> None:
        event = audit.log(
            AuditEventType.TOOL_CALL,
            "session1",
            "run1",
            "agent",
            "shell",
            {"command": "ls"},
        )
        assert event.checksum != ""

        results = audit.query(session_id="session1")
        assert len(results) == 1
        assert results[0].action == "shell"

    def test_chain_integrity(self, audit: AuditLogger) -> None:
        audit.log(AuditEventType.USER_MESSAGE, "s1", "r1", "user", "msg", {})
        audit.log(AuditEventType.MODEL_RESPONSE, "s1", "r1", "agent", "chat", {})

        valid, first_bad = audit.verify_chain()
        assert valid
        assert first_bad == 0

    def test_filter_by_type(self, audit: AuditLogger) -> None:
        audit.log(AuditEventType.TOOL_CALL, "s1", "r1", "agent", "shell", {})
        audit.log(AuditEventType.USER_MESSAGE, "s1", "r1", "user", "msg", {})

        results = audit.query(event_type=AuditEventType.TOOL_CALL)
        assert len(results) == 1
