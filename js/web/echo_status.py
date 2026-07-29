from __future__ import annotations

from js.config import JSSettings
from js.echo import ECHO_2_ARCHITECTURE
from js.echo.ledger.service import EchoHealth, EchoSafetyService
from js.echo.slo_contract import SLO_CONTRACT


def echo_status(
    settings: JSSettings,
    *,
    health: EchoHealth | None = None,
) -> dict[str, object]:
    health = health or EchoSafetyService.from_settings(settings).health()
    return {
        "mode": settings.echo_engine,
        "architecture": ECHO_2_ARCHITECTURE,
        "architecture_state": "primary_healthy" if health.ok else "primary_degraded",
        "default_architecture": settings.echo_engine == "on",
        "ledger_mode": health.mode,
        "core": {
            "ledger": "FrameLedger",
            "journal_impl": "FileEchoLedger",
            "scope_gate": "ScopeGate",
            "budget": "BudgetClock",
            "context": "ContextVault",
            "outbox": "EffectOutbox",
        },
    }


def echo_ledger_status(health: EchoHealth) -> dict[str, object]:
    return {
        "mode": health.mode,
        "architecture": health.architecture,
        "component": "internal_echo_safety_ledger",
        "ok": health.ok,
        "journal_path": health.journal_path,
        "record_count": health.record_count,
        "error_count": health.error_count,
        "last_error": health.last_error,
        "journal_append_p95_ms": health.journal_append_p95_ms,
        "pending_effect_count": health.pending_effect_count,
        "claimed_effect_count": health.claimed_effect_count,
        "manual_review_effect_count": health.manual_review_effect_count,
        "loaded_tenant_state_count": health.loaded_tenant_state_count,
        "tenant_state_limit": health.tenant_state_limit,
        "journal_state_scan_truncated": health.journal_state_scan_truncated,
        "ledger_name": health.ledger_name,
        "ledger_contract": health.ledger_contract,
        "journal_impl": health.journal_impl,
        "scope_gate_name": health.scope_gate_name,
        "slo": {
            "contract": SLO_CONTRACT.as_dict(),
            "journal_append_p95_ms": health.journal_append_p95_ms,
            "journal_append_ok": (
                None
                if health.journal_append_p95_ms is None
                else health.journal_append_p95_ms <= SLO_CONTRACT.journal_append_p95_ms
            ),
            "journal_append_preview_ok": (
                None
                if health.journal_append_p95_ms is None
                else health.journal_append_p95_ms <= SLO_CONTRACT.journal_append_p95_ms
            ),
        },
    }
