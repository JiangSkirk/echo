from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from js.config import JSSettings, SecurityConfig
from js.echo.ledger.service import EchoHealth
from js.web.echo_status import echo_status
from js.web.routers.system import status
from js.web.server import create_app


@pytest.mark.asyncio
async def test_system_status_includes_echo_health(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
        echo_engine="on",
    )
    agent = MagicMock()
    agent.settings = settings
    agent.degraded = False
    agent.degraded_reason = ""
    agent._check_degraded = AsyncMock()
    agent.registry.get_stats.return_value = {}
    agent.secrets.get_stats.return_value = {}

    monkeypatch.setattr("js.web.routers.system.get_agent", lambda: agent)

    body = await status(auth={})

    assert "rivetline" not in body
    assert body["echo"] == {
        "mode": "on",
        "architecture": "echo-2.0",
        "architecture_state": "primary_healthy",
        "default_architecture": True,
        "ledger_mode": "on",
        "core": {
            "ledger": "FrameLedger",
            "journal_impl": "FileEchoLedger",
            "scope_gate": "ScopeGate",
            "budget": "BudgetClock",
            "context": "ContextVault",
            "outbox": "EffectOutbox",
        },
    }
    assert body["echo_ledger"]["mode"] == "on"
    assert body["echo_ledger"]["architecture"] == "echo-2.0"
    assert body["echo_ledger"]["component"] == "internal_echo_safety_ledger"
    assert body["echo_ledger"]["ledger_name"] == "FrameLedger"
    assert body["echo_ledger"]["ledger_contract"] == "FrameLedger"
    assert body["echo_ledger"]["journal_impl"] == "FileEchoLedger"
    assert body["echo_ledger"]["scope_gate_name"] == "ScopeGate"
    assert body["echo_ledger"]["ok"] is True
    assert body["echo_ledger"]["record_count"] == 0
    assert body["echo_ledger"]["pending_effect_count"] == 0
    assert body["echo_ledger"]["claimed_effect_count"] == 0
    assert body["echo_ledger"]["manual_review_effect_count"] == 0
    assert body["echo_ledger"]["journal_append_p95_ms"] is None
    assert body["echo_ledger"]["slo"]["journal_append_preview_ok"] is None


@pytest.mark.asyncio
async def test_system_status_uses_single_echo_health_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
        echo_engine="on",
    )
    agent = MagicMock()
    agent.settings = settings
    agent.degraded = False
    agent.degraded_reason = ""
    agent._check_degraded = AsyncMock()
    agent.registry.get_stats.return_value = {}
    agent.secrets.get_stats.return_value = {}
    monkeypatch.setattr("js.web.routers.system.get_agent", lambda: agent)

    class _Service:
        def __init__(self) -> None:
            self.calls = 0

        def health(self, *, max_verify_age_seconds: float = 0.0) -> EchoHealth:
            self.calls += 1
            assert max_verify_age_seconds > 0
            return EchoHealth(
                mode="on",
                ok=True,
                journal_path=str(tmp_path / "echo" / "ledger" / "chat.jsonl"),
                record_count=0,
                error_count=0,
                last_error=None,
                journal_append_p95_ms=None,
            )

    service = _Service()
    monkeypatch.setattr("js.web.routers.system.get_echo_safety_service", lambda _settings: service)

    def fail_if_echo_status_builds_service(_settings: JSSettings) -> None:
        raise AssertionError("echo_status must use the already-read health snapshot")

    monkeypatch.setattr(
        "js.web.echo_status.EchoSafetyService.from_settings",
        fail_if_echo_status_builds_service,
    )

    body = await status(auth={})

    assert body["echo"]["architecture_state"] == "primary_healthy"
    assert service.calls == 1


def test_web_lifespan_rejects_removed_echo_env_rollback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                'version: "0.1.5"',
                f'workspace: "{tmp_path / "workspace"}"',
                f'state_dir: "{tmp_path / "state"}"',
                'echo_engine: "on"',
                "providers: []",
                "models: []",
                "security:",
                "  api_key_required: false",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("JS_CONFIG_PATH", str(config_path))
    monkeypatch.setenv("JS_ECHO_ENGINE", "off")
    monkeypatch.delenv("JS_STATE_DIR", raising=False)

    with pytest.raises(ValueError, match="Echo is the only supported architecture"), TestClient(
        create_app(),
        base_url="http://localhost",
        headers={"Origin": "http://localhost"},
    ):
        pass


def test_echo_status_derives_architecture_state_from_modes_and_health(tmp_path: Path) -> None:
    broken_health = EchoHealth(
        mode="on",
        ok=False,
        journal_path=str(tmp_path / "echo" / "ledger" / "chat.jsonl"),
        record_count=0,
        error_count=1,
        last_error="frame_hash_mismatch",
        journal_append_p95_ms=None,
    )
    degraded = echo_status(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            echo_engine="on",
        ),
        health=broken_health,
    )

    assert degraded["architecture_state"] == "primary_degraded"
    assert degraded["ledger_mode"] == "on"
    assert "safety_wrapper_mode" not in degraded
