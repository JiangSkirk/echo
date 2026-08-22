"""Tests for security subsystem."""

import multiprocessing
import os
import sqlite3
import stat
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from js.config import SecurityConfig
from js.security.audit import AuditEventType, AuditLogger
from js.security.guard import BehaviorGuard, SecurityDecisionType
from js.security.sandbox import SandboxExecutor
from js.security.secrets import SecretManager


def _race_secret_material_creation(
    state_dir: str,
    filename: str,
    master_key: str | None,
    material_created: object,
    results: object,
    delay_writer: bool,
) -> None:
    """Expose a created-but-not-yet-written key file to a second process."""
    import js.security.secrets as secrets_module

    original_open = secrets_module.os.open

    def synchronized_open(path: object, flags: int, mode: int = 0o777) -> int:
        fd = original_open(path, flags, mode)
        if delay_writer and Path(path).name == filename and flags & os.O_EXCL:
            material_created.set()  # type: ignore[attr-defined]
            time.sleep(0.3)
        return fd

    secrets_module.os.open = synchronized_open
    try:
        if not delay_writer:
            assert material_created.wait(timeout=10)  # type: ignore[attr-defined]
        SecretManager(Path(state_dir), master_key=master_key)
        results.put(("ok", (Path(state_dir) / filename).read_bytes()))  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover - assertion reports child failure
        results.put(("error", f"{type(exc).__name__}: {exc}"))  # type: ignore[attr-defined]


class TestBehaviorGuard:
    def test_tool_network_is_disabled_by_default_and_allowlist_is_exact(self) -> None:
        default = SecurityConfig()
        configured = SecurityConfig(
            network_enabled=True,
            network_allowlist=["Example.COM.", "example.com"],
        )

        assert default.network_enabled is False
        assert default.network_allowlist == []
        assert configured.network_allowlist == ["example.com"]

    @pytest.mark.parametrize(
        "host",
        [
            "localhost",
            "127.0.0.1",
            "169.254.169.254",
            "https://example.com",
            "*.example.com",
        ],
    )
    def test_tool_network_allowlist_rejects_unsafe_or_non_exact_hosts(
        self,
        host: str,
    ) -> None:
        with pytest.raises(ValueError, match="network_allowlist"):
            SecurityConfig(network_enabled=True, network_allowlist=[host])

    def test_high_risk_command_blocked(self, tmp_path: Path) -> None:
        config = SecurityConfig()
        guard = BehaviorGuard(config, tmp_path)

        result = guard.check_command("rm -rf /")
        assert result.decision == SecurityDecisionType.BLOCK

    def test_safe_command_allowed(self, tmp_path: Path) -> None:
        config = SecurityConfig()
        guard = BehaviorGuard(config, tmp_path)

        result = guard.check_command("ls -la")
        assert result.decision == SecurityDecisionType.ALLOW

    def test_protected_path_blocked(self, tmp_path: Path) -> None:
        config = SecurityConfig()
        guard = BehaviorGuard(config, tmp_path)

        result = guard.check_path_operation("/etc/passwd", "write")
        assert result.decision == SecurityDecisionType.BLOCK

    def test_workspace_delete_allowed(self, tmp_path: Path) -> None:
        config = SecurityConfig(allow_workspace_delete=False)
        guard = BehaviorGuard(config, tmp_path)

        result = guard.check_path_operation("/tmp/test.txt", "delete")
        assert result.decision == SecurityDecisionType.BLOCK

    def test_loop_detection(self, tmp_path: Path) -> None:
        config = SecurityConfig(max_loop_iterations=5)
        guard = BehaviorGuard(config, tmp_path)

        # First 2 calls should be allowed
        result = guard.check_loop("run1", "shell", "ls")
        assert result.decision == SecurityDecisionType.ALLOW
        result = guard.check_loop("run1", "shell", "ls")
        assert result.decision == SecurityDecisionType.ALLOW

        # 3rd call triggers warning (count=3 > 5//2=2)
        result = guard.check_loop("run1", "shell", "ls")
        assert result.decision == SecurityDecisionType.WARN

        # 6th call triggers block
        guard.check_loop("run1", "shell", "ls")
        guard.check_loop("run1", "shell", "ls")
        result = guard.check_loop("run1", "shell", "ls")
        assert result.decision == SecurityDecisionType.BLOCK


class TestSecretManager:
    def test_detect_openai_key(self, tmp_path: Path) -> None:
        sm = SecretManager(tmp_path)
        fake_key = "sk-" + "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
        text = f"My key is {fake_key}"
        result = sm.detect_and_redact(text)
        assert "[REDACTED" in result
        assert "sk-" not in result

    def test_store_and_retrieve(self, tmp_path: Path) -> None:
        sm = SecretManager(tmp_path)
        sm.store("test_key", "secret_value")
        retrieved = sm.retrieve("test_key")
        assert retrieved == "secret_value"

    def test_new_master_password_uses_versioned_600k_kdf(self, tmp_path: Path) -> None:
        sm = SecretManager(tmp_path, master_key="correct horse battery staple")
        sm.store("test_key", "secret_value")

        encoded_salt = (tmp_path / ".secret_salt").read_bytes()
        restarted = SecretManager(tmp_path, master_key="correct horse battery staple")

        assert encoded_salt[:4] == b"JSS1"
        assert int.from_bytes(encoded_salt[4:8], "big") == 600_000
        assert len(encoded_salt[8:]) == 16
        assert restarted.retrieve("test_key") == "secret_value"
        assert stat.S_IMODE((tmp_path / ".secret_salt").stat().st_mode) == 0o600

    def test_legacy_100k_master_password_salt_remains_readable(self, tmp_path: Path) -> None:
        tmp_path.mkdir(parents=True, exist_ok=True)
        salt_path = tmp_path / ".secret_salt"
        salt_path.write_bytes(os.urandom(16))
        salt_path.chmod(0o600)

        original = SecretManager(tmp_path, master_key="legacy-password")
        original.store("legacy", "still-readable")
        restarted = SecretManager(tmp_path, master_key="legacy-password")

        assert restarted.retrieve("legacy") == "still-readable"

    @pytest.mark.parametrize(
        ("filename", "master_key"),
        ((".secret_key", None), (".secret_salt", "shared-password")),
    )
    def test_secret_material_creation_is_cross_process_safe(
        self, tmp_path: Path, filename: str, master_key: str | None
    ) -> None:
        context = multiprocessing.get_context("spawn")
        material_created = context.Event()
        results = context.Queue()
        processes = [
            context.Process(
                target=_race_secret_material_creation,
                args=(
                    str(tmp_path),
                    filename,
                    master_key,
                    material_created,
                    results,
                    delay_writer,
                ),
            )
            for delay_writer in (True, False)
        ]

        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=15)

        outcomes = [results.get(timeout=2) for _ in processes]
        assert all(process.exitcode == 0 for process in processes)
        assert outcomes[0][0] == outcomes[1][0] == "ok", outcomes
        assert outcomes[0][1] == outcomes[1][1]


class TestAuditLogger:
    def test_prune_keeps_chain_valid_for_future_appends(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        audit = AuditLogger(tmp_path, retention_days=1)
        now = 1_000_000.0
        timestamps = iter((now - 172_800, now - 43_200, now - 3_600, now, now + 1))
        monkeypatch.setattr(
            "js.security.audit.time", SimpleNamespace(time=lambda: next(timestamps))
        )

        for action in ("old", "new1", "new2"):
            audit.log(AuditEventType.USER_MESSAGE, "session", "run", "user", action)

        assert audit.prune() == 1
        audit.log(AuditEventType.USER_MESSAGE, "session", "run", "user", "new3")

        assert audit.verify_chain() == (True, 0)

    def test_verify_chain_detects_unanchored_prefix_deletion(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path)
        for action in ("old", "new1", "new2"):
            audit.log(AuditEventType.USER_MESSAGE, "session", "run", "user", action)

        with sqlite3.connect(audit.db_path) as conn:
            conn.execute("DELETE FROM audit_log WHERE id = (SELECT MIN(id) FROM audit_log)")

        valid, _ = audit.verify_chain()
        assert not valid

    def test_prune_applies_hard_row_cap_without_breaking_chain(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path, retention_days=3_650)
        for index in range(6):
            audit.log(
                AuditEventType.USER_MESSAGE,
                f"session-{index}",
                f"run-{index}",
                "user",
                f"action-{index}",
            )

        assert audit.prune(max_entries=3) == 3
        assert [event.action for event in audit.query(limit=10)] == [
            "action-5",
            "action-4",
            "action-3",
        ]
        assert audit.verify_chain() == (True, 0)

        audit.log(AuditEventType.USER_MESSAGE, "session-new", "run-new", "user", "new")
        assert audit.verify_chain() == (True, 0)

    def test_prune_rejects_negative_hard_cap(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path)

        with pytest.raises(ValueError, match="max_entries"):
            audit.prune(max_entries=-1)

    def test_missing_chain_state_with_rows_fails_closed(self, tmp_path: Path) -> None:
        """A missing chain-state row with a non-empty log means the anchor was
        wiped independently of the log; silently re-anchoring would make a full
        history wipe indistinguishable from a fresh install."""
        audit = AuditLogger(tmp_path)
        audit.log(AuditEventType.USER_MESSAGE, "session", "run", "user", "existing")

        with sqlite3.connect(audit.db_path) as conn:
            conn.execute("DELETE FROM audit_chain_state")

        with pytest.raises(RuntimeError, match="manual forensic review"):
            AuditLogger(tmp_path)

    def test_missing_chain_state_empty_db_with_sentinel_rebuilds_fail_visible(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Wiping an initialized state_dir down to an empty DB (rows + chain
        state) must be fail-visible: raise a critical alert, then rebuild so
        the system can start."""
        from unittest.mock import Mock

        audit = AuditLogger(tmp_path)
        audit.log(AuditEventType.USER_MESSAGE, "session", "run", "user", "event")

        with sqlite3.connect(audit.db_path) as conn:
            conn.execute("DELETE FROM audit_log")
            conn.execute("DELETE FROM audit_chain_state")

        mock_logger = Mock()
        monkeypatch.setattr("js.security.audit.logger", mock_logger)

        rebuilt = AuditLogger(tmp_path)
        mock_logger.critical.assert_called_once()
        assert rebuilt.verify_chain() == (True, 0)

        rebuilt.log(AuditEventType.USER_MESSAGE, "session", "run", "user", "new")
        assert rebuilt.verify_chain() == (True, 0)

    def test_fresh_init_creates_initialized_sentinel(self, tmp_path: Path) -> None:
        """Brand-new initialization leaves an audit.initialized sentinel so a
        later wipe-to-empty is detectable; normal restarts stay silent."""
        audit = AuditLogger(tmp_path)
        assert (tmp_path / "audit.initialized").exists()

        audit.log(AuditEventType.USER_MESSAGE, "session", "run", "user", "event")
        restarted = AuditLogger(tmp_path)
        assert restarted.verify_chain() == (True, 0)


class TestSandbox:
    @pytest.mark.asyncio
    async def test_basic_execution(self, tmp_path: Path) -> None:
        executor = SandboxExecutor(tmp_path)
        result = await executor.execute("echo hello")
        assert result.returncode == 0
        assert "hello" in result.stdout

    @pytest.mark.asyncio
    async def test_timeout(self, tmp_path: Path) -> None:
        executor = SandboxExecutor(tmp_path, timeout=0.5)
        result = await executor.execute("sleep 10")
        assert result.killed
        assert result.returncode != 0
