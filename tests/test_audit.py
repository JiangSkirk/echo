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

    def test_db_attacker_cannot_forge_chain_with_public_sha256(
        self, audit: AuditLogger
    ) -> None:
        """F-22: an attacker with DB write access who rewrites history and
        recomputes the legacy unkeyed SHA-256 chain must still fail
        verification, because the chain is now keyed with HMAC-SHA256."""
        import hashlib
        import sqlite3

        audit.log(AuditEventType.TOOL_CALL, "s1", "r1", "agent", "shell", {"cmd": "ls"})
        audit.log(AuditEventType.TOOL_CALL, "s1", "r1", "agent", "shell", {"cmd": "id"})

        valid, _ = audit.verify_chain()
        assert valid

        # Attacker rewrites the first record's action and recomputes every
        # checksum using the OLD public sha256(data) scheme.
        with sqlite3.connect(str(audit.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
            prev = rows[0]["prev_checksum"]
            for index, row in enumerate(rows):
                action = "rm -rf /" if index == 0 else row["action"]
                if index == 0:
                    conn.execute(
                        "UPDATE audit_log SET action = ? WHERE id = ?",
                        (action, row["id"]),
                    )
                data = (
                    f"{prev}:{row['timestamp']}:{row['event_type']}:{row['session_id']}"
                    f":{row['run_id']}:{row['actor']}:{action}:{row['details']}"
                )
                forged = hashlib.sha256(data.encode()).hexdigest()
                conn.execute(
                    "UPDATE audit_log SET checksum = ? WHERE id = ?",
                    (forged, row["id"]),
                )
                if index + 1 < len(rows):
                    conn.execute(
                        "UPDATE audit_log SET prev_checksum = ? WHERE id = ?",
                        (forged, rows[index + 1]["id"]),
                    )
                prev = forged
            conn.execute(
                "UPDATE audit_chain_state SET chain_tip = ? WHERE id = 1", (prev,)
            )
            conn.commit()

        valid, first_bad = audit.verify_chain()
        assert not valid
        assert first_bad == rows[0]["id"]

    def test_direct_record_tamper_fails_closed(self, audit: AuditLogger) -> None:
        import sqlite3

        audit.log(AuditEventType.USER_MESSAGE, "s1", "r1", "user", "msg", {})
        with sqlite3.connect(str(audit.db_path)) as conn:
            conn.execute("UPDATE audit_log SET action = 'forged' WHERE id = 1")
            conn.commit()

        valid, first_bad = audit.verify_chain()
        assert not valid
        assert first_bad == 1
