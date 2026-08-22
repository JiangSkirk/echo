from __future__ import annotations

import json
import multiprocessing
import os
import sqlite3
import stat
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import js.echo.ledger.journal as journal_module
import js.echo.ledger.service as service_module
from js.config import EchoLedgerConfig, JSSettings
from js.echo import stable_payload_hash
from js.echo.ledger.archive_store import ArchiveStore
from js.echo.ledger.journal import FileEchoLedger, VerificationReport, verify_file
from js.echo.ledger.service import EchoSafetyService, EchoTurnContext, EchoUnavailableError


def _sqlite_archive_path(journal_path: Path) -> Path:
    return journal_path.with_suffix(journal_path.suffix + ".archive.sqlite3")


def _tamper_first_archived_record(journal_path: Path) -> None:
    with sqlite3.connect(_sqlite_archive_path(journal_path)) as connection:
        connection.execute("UPDATE archive_records SET canonical_payload = '{}' WHERE sequence = 1")


def _preloaded_turn_worker(
    state_dir: str,
    label: str,
    start: Any,
    results: Any,
    clock_offset_ms: int = 0,
) -> None:
    settings = JSSettings(state_dir=Path(state_dir))
    service = EchoSafetyService.from_settings(settings)
    service.journal_path_for("owner-a")
    if clock_offset_ms:
        system_monotonic_ns = service_module.monotonic_ns
        service_module.monotonic_ns = lambda: system_monotonic_ns() + clock_offset_ms * 1_000_000
    results.put((label, "ready", None))
    if not start.wait(timeout=10):
        results.put((label, "error", "start timeout"))
        return
    try:
        service.record_chat_turn(
            tenant_id="owner-a",
            run_id="shared-run",
            user_text="same durable effect",
            assistant_text=f"executed by {label}",
            status="completed",
            token_totals={"input": 1, "output": 1},
        )
    except Exception as exc:  # noqa: BLE001 - child reports the fail-closed result
        health = service.health()
        results.put(
            (
                label,
                "blocked",
                (exc.__class__.__name__, str(exc), health.record_count, health.ok),
            )
        )
    else:
        results.put((label, "executed", service.health().record_count))
    finally:
        service.close()


def _load_key_worker(path: str, start: Any, results: Any) -> None:
    if not start.wait(timeout=10):
        results.put(("error", "start timeout"))
        return
    try:
        key = service_module._load_or_create_key(Path(path))
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except Exception as exc:  # noqa: BLE001 - child reports initialization races
        results.put(("error", f"{exc.__class__.__name__}: {exc}"))
    else:
        results.put(("ok", key.hex(), mode))


def _hold_partition_guard_worker(
    state_dir: str,
    ready: Any,
    release: Any,
) -> None:
    service = EchoSafetyService.from_settings(JSSettings(state_dir=Path(state_dir)))
    with service._partition_lifecycle_lock(exclusive=False):
        ready.set()
        if not release.wait(timeout=10):
            raise RuntimeError("partition guard release timed out")


@pytest.mark.parametrize(
    ("env_name", "value"),
    (
        ("JS_ECHO_ENGINE", "off"),
        ("JS_ECHO_ENGINE", "shadow"),
    ),
)
def test_removed_engine_modes_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    env_name: str,
    value: str,
) -> None:
    monkeypatch.setenv(env_name, value)

    with pytest.raises(ValidationError, match="Echo is the only supported architecture"):
        JSSettings()


def test_echo_default_engine_is_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("JS_ECHO_ENGINE", raising=False)

    settings = JSSettings()

    assert settings.echo_engine == "on"


def test_echo_ledger_config_defaults_and_validation() -> None:
    settings = JSSettings()

    assert settings.echo_ledger == EchoLedgerConfig(
        retain_records=2_048,
        trigger_records=4_096,
        max_archives=1,
        max_open_effects_per_tenant=1_024,
    )
    with pytest.raises(ValidationError, match="trigger_records must be greater"):
        EchoLedgerConfig(retain_records=10, trigger_records=10)
    with pytest.raises(ValidationError):
        EchoLedgerConfig(retain_records=0)
    with pytest.raises(ValidationError):
        EchoLedgerConfig(max_archives=0)
    with pytest.raises(ValidationError):
        EchoLedgerConfig(max_open_effects_per_tenant=0)
    with pytest.raises(ValidationError):
        EchoLedgerConfig(max_retired_artifact_refs_per_owner=0)
    with pytest.raises(ValidationError):
        EchoLedgerConfig(max_retired_artifact_bytes_per_owner=0)


def test_open_effect_admission_is_bounded_per_tenant(tmp_path: Path) -> None:
    settings = JSSettings(
        state_dir=tmp_path,
        echo_ledger=EchoLedgerConfig(
            retain_records=100,
            trigger_records=200,
            max_archives=1,
            max_open_effects_per_tenant=2,
        ),
    )
    service = EchoSafetyService.from_settings(settings)

    for index in range(2):
        service.begin_chat_turn(
            tenant_id="owner-a",
            run_id=f"open-{index}",
            user_text=f"open request {index}",
            model_id="mock",
        )

    with pytest.raises(EchoUnavailableError, match="open effect capacity"):
        service.begin_chat_turn(
            tenant_id="owner-a",
            run_id="open-overflow",
            user_text="one request too many",
            model_id="mock",
        )

    other_tenant = service.begin_chat_turn(
        tenant_id="owner-b",
        run_id="independent",
        user_text="other owner",
        model_id="mock",
    )
    assert other_tenant.tenant_id == "owner-b"


def test_repeated_compaction_keeps_one_incremental_verified_archive(
    tmp_path: Path,
) -> None:
    path = tmp_path / "chat.jsonl"
    mac_key = b"archive-chain-test-key"
    journal = FileEchoLedger(path, mac_key=mac_key)
    for index in range(5):
        journal.append(
            record_type="decision",
            tenant_id="owner-a",
            run_id=f"run-{index}",
            payload={"decision_id": f"d{index}"},
        )
    assert journal.compact(max_records=2, max_archives=1) is True

    for index in range(5, 9):
        journal.append(
            record_type="decision",
            tenant_id="owner-a",
            run_id=f"run-{index}",
            payload={"decision_id": f"d{index}"},
        )
    assert journal.compact(max_records=2, max_archives=1) is True

    archive_path = _sqlite_archive_path(path)
    assert archive_path.is_file()
    ref = journal_module._archive_ref_from_payload(journal.records[0].payload)
    store = ArchiveStore(
        archive_path,
        tenant_id="owner-a",
        mac_key=journal_module._archive_mac_key(mac_key),
    )
    rows = tuple(store.iter_records(ref))
    assert [
        row.payload["decision_id"]
        for row in rows
        if isinstance(row.payload, dict) and "decision_id" in row.payload
    ] == [f"d{index}" for index in range(9)]
    assert store.generation_count() == 2
    assert journal.verify_required_archives().ok is True


def test_echo_on_is_the_only_supported_engine_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")

    settings = JSSettings()

    assert settings.echo_engine == "on"


def test_removed_secondary_engine_is_not_a_setting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JS_RIVETLINE_ENGINE", "off")

    settings = JSSettings()

    assert "rivetline_engine" not in JSSettings.model_fields
    assert settings.echo_engine == "on"


def test_removed_env_override_is_rejected_over_file_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                f'workspace: "{tmp_path / "workspace"}"',
                f'state_dir: "{tmp_path / "state"}"',
                'echo_engine: "on"',
                "providers: []",
                "models: []",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("JS_CONFIG_PATH", str(config_path))
    monkeypatch.setenv("JS_ECHO_ENGINE", "off")

    with pytest.raises(ValueError, match="Echo is the only supported architecture"):
        JSSettings.from_file()


def test_echo_env_override_does_not_mutate_cached_file_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                f'workspace: "{tmp_path / "workspace"}"',
                f'state_dir: "{tmp_path / "state"}"',
                'echo_engine: "on"',
                "providers: []",
                "models: []",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("JS_CONFIG_PATH", str(config_path))
    monkeypatch.setenv("JS_ECHO_ENGINE", "off")

    with pytest.raises(ValueError, match="Echo is the only supported architecture"):
        JSSettings.from_file()

    monkeypatch.delenv("JS_ECHO_ENGINE", raising=False)

    settings = JSSettings.from_file()

    assert settings.echo_engine == "on"


def test_service_creates_state_paths_and_default_health(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)

    service = EchoSafetyService.from_settings(settings)
    health = service.health()

    assert service.journal_path == tmp_path / "echo" / "ledger" / "chat.jsonl"
    assert service.journal_path.parent.is_dir()
    assert health.mode == "on"
    assert health.record_count == 0
    assert health.error_count == 0
    assert health.ok


def test_service_from_settings_uses_echo_ledger_config(tmp_path: Path) -> None:
    settings = JSSettings(
        state_dir=tmp_path,
        echo_ledger=EchoLedgerConfig(
            retain_records=3,
            trigger_records=8,
            max_archives=2,
        ),
    )

    service = EchoSafetyService.from_settings(settings)

    assert service.ledger_config == settings.echo_ledger


def test_service_count_hot_paths_do_not_snapshot_journal_records(tmp_path: Path) -> None:
    class ExistingRecordsMustNotBeIterated(list[object]):
        def __iter__(self):  # type: ignore[no-untyped-def]
            raise AssertionError("service count hot path iterated journal records")

    settings = JSSettings(
        state_dir=tmp_path,
        echo_ledger=EchoLedgerConfig(
            retain_records=10,
            trigger_records=20,
            max_archives=1,
        ),
    )
    service = EchoSafetyService.from_settings(settings)
    state = service._tenant_state("owner-a")
    state.journal.append(
        record_type="decision",
        tenant_id="owner-a",
        run_id="seed",
        payload={"decision_id": "seed"},
    )
    state.journal._records = ExistingRecordsMustNotBeIterated(state.journal._records)  # type: ignore[assignment]

    assert state.journal.record_count == 1
    assert state.journal.tip is not None
    assert state.journal.tip.payload["decision_id"] == "seed"
    assert service.maybe_compact(state) is False
    assert service.health().record_count == 1
    context = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="session-a",
        user_text="hello",
        model_id="mock",
    )

    assert context.record_start == 1


def test_direct_service_construction_uses_safe_ledger_defaults(tmp_path: Path) -> None:
    service = EchoSafetyService(state_dir=tmp_path)

    assert service.ledger_config == EchoLedgerConfig()


def test_service_records_chat_turn_and_survives_restart(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)

    result = service.record_chat_turn(
        tenant_id="owner-a",
        run_id="session-a",
        user_text="hello",
        assistant_text="hi",
        status="completed",
        token_totals={"input": 3, "output": 2},
    )
    restarted = EchoSafetyService.from_settings(settings)

    assert result.record_types == (
        "intake",
        "decision",
        "policy_decision",
        "permit",
        "model_privacy_envelope",
        "outbox",
        "outbox_claimed",
        "receipt",
        "merge",
    )
    assert restarted.health().record_count == 9
    assert verify_file(
        service.journal_path_for("owner-a"),
        mac_key=service.journal_key_for("owner-a"),
    ).ok
    tenant_root = service.journal_path_for("owner-a").parent
    assert (tenant_root / "journal.key").is_file()
    assert (tenant_root / "permit.key").is_file()
    health = service.health()
    assert health.journal_append_p95_ms is not None
    assert health.journal_append_p95_ms >= 0


def test_service_health_can_reuse_recent_full_journal_verification(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    service.record_chat_turn(
        tenant_id="owner-a",
        run_id="session-a",
        user_text="hello",
        assistant_text="hi",
        status="completed",
        token_totals={"input": 3, "output": 2},
    )
    verify_calls = 0
    real_verify_file = verify_file

    def counting_verify_file(path: Path, *, mac_key: bytes) -> VerificationReport:
        nonlocal verify_calls
        verify_calls += 1
        return real_verify_file(path, mac_key=mac_key)

    monkeypatch.setattr(service_module, "verify_file", counting_verify_file)

    first = service.health(max_verify_age_seconds=60.0)
    first_verify_calls = verify_calls
    service.record_chat_turn(
        tenant_id="owner-a",
        run_id="session-b",
        user_text="hello again",
        assistant_text="hi again",
        status="completed",
        token_totals={"input": 4, "output": 2},
    )
    second = service.health(max_verify_age_seconds=60.0)

    assert first.ok is True
    assert first.record_count == 9
    assert first_verify_calls == 0
    assert verify_calls == first_verify_calls
    assert second.ok is True
    assert second.record_count == 18


def test_service_health_refreshes_external_journal_and_effect_state(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)
    writer = EchoSafetyService.from_settings(settings)
    observer = EchoSafetyService.from_settings(settings)
    writer.journal_path_for("owner-a")
    observer.journal_path_for("owner-a")

    context = writer.begin_chat_turn(
        tenant_id="owner-a",
        run_id="shared-run",
        user_text="hello",
        model_id="mock",
    )
    pending_health = observer.health()

    assert pending_health.record_count == 6
    assert pending_health.pending_effect_count == 1
    assert pending_health.ok is False

    writer.assert_model_execution_permitted(context)
    writer.finish_chat_turn(
        context,
        assistant_text="done",
        status="completed",
        token_totals={"input": 1, "output": 1},
    )
    completed_health = observer.health()

    assert completed_health.record_count == 9
    assert completed_health.pending_effect_count == 0
    assert completed_health.claimed_effect_count == 0
    assert completed_health.ok is True
    observer.close()
    writer.close()


@pytest.mark.parametrize("begin_kind", ("model", "tool"))
def test_cached_service_repeated_begin_fails_closed_after_active_journal_deleted(
    tmp_path: Path,
    begin_kind: str,
) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    if begin_kind == "tool":
        tenant_path = service.journal_path_for_scope(
            "owner-a",
            product_id="product-a",
            session_id="session-a",
        )
    else:
        tenant_path = service.journal_path_for("owner-a")
        service.record_chat_turn(
            tenant_id="owner-a",
            run_id="seed-run",
            user_text="seed",
            assistant_text="done",
            status="completed",
            token_totals={"input": 1, "output": 1},
        )
    tenant_path.unlink()

    def begin() -> object:
        if begin_kind == "model":
            return service.begin_chat_turn(
                tenant_id="owner-a",
                run_id="missing-model-run",
                user_text="hello",
                model_id="mock",
            )
        return service.begin_tool_effect(
            tenant_id="owner-a",
            product_id="product-a",
            session_id="session-a",
            run_id="missing-tool-run",
            tool_name="file_write",
            tool_call_id="call-a",
            args_hash=stable_payload_hash({"path": "safe.txt"}),
            lease_id="lease-a",
            replay_class="non_idempotent",
        )

    try:
        for _attempt in range(2):
            with pytest.raises(EchoUnavailableError, match="journal") as raised:
                begin()
        assert isinstance(raised.value.__cause__, OSError)
        assert not tenant_path.exists()
    finally:
        service.close()


def test_service_uses_tenant_scoped_journals_and_keys(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)

    for tenant_id in ("owner-a", "owner-b"):
        context = service.begin_chat_turn(
            tenant_id=tenant_id,
            run_id=f"{tenant_id}-session",
            user_text="hello",
            model_id="mock",
        )
        service.assert_model_execution_permitted(context)
        service.finish_chat_turn(
            context,
            assistant_text="hi",
            status="completed",
            token_totals={"input": 1, "output": 1},
        )

    owner_a_path = service.journal_path_for("owner-a")
    owner_b_path = service.journal_path_for("owner-b")

    assert owner_a_path != owner_b_path
    assert service.journal_key_for("owner-a") != service.journal_key_for("owner-b")
    assert verify_file(owner_a_path, mac_key=service.journal_key_for("owner-a")).ok
    assert verify_file(owner_b_path, mac_key=service.journal_key_for("owner-b")).ok
    assert service.health().record_count == 18


def test_runtime_effects_use_physical_product_owner_session_partitions(
    tmp_path: Path,
) -> None:
    from js.models.providers import ChatMessage

    service = EchoSafetyService.from_settings(JSSettings(state_dir=tmp_path))

    contexts = []
    for session_id in ("session-a", "session-b"):
        context = service.authorize_model_call(
            tenant_id="owner-a",
            product_id="js-work",
            session_id=session_id,
            run_id=f"run-{session_id}",
            provider_id="mock-provider",
            model_id="mock-model",
            messages=[ChatMessage(role="user", content=f"hello {session_id}")],
        )
        contexts.append(context)
        service.finish_chat_turn(
            context,
            assistant_text="done",
            status="completed",
            token_totals={"input": 1, "output": 1},
        )

    first_path = service.journal_path_for_scope(
        "owner-a",
        product_id="js-work",
        session_id="session-a",
    )
    second_path = service.journal_path_for_scope(
        "owner-a",
        product_id="js-work",
        session_id="session-b",
    )

    assert first_path != second_path
    assert first_path.parent.parent.parent.parent.name == "partitions"
    assert "owner-a" not in str(first_path)
    assert "session-a" not in str(first_path)
    assert contexts[0].product_id == "js-work"
    assert contexts[0].session_id == "session-a"
    assert verify_file(
        first_path,
        mac_key=service.journal_key_for_scope(
            "owner-a",
            product_id="js-work",
            session_id="session-a",
        ),
    ).ok
    assert service.journal_key_for_scope(
        "owner-a",
        product_id="js-work",
        session_id="session-a",
    ) != service.journal_key_for_scope(
        "owner-a",
        product_id="js-work",
        session_id="session-b",
    )


def test_completed_session_partitions_are_retired_to_a_bounded_authenticated_checkpoint(
    tmp_path: Path,
) -> None:
    from js.models.providers import ChatMessage

    settings = JSSettings(
        state_dir=tmp_path,
        echo_ledger=EchoLedgerConfig(
            max_session_partitions_per_owner=3,
            max_retired_session_receipts_per_owner=2,
        ),
    )
    service = EchoSafetyService.from_settings(settings)

    for index in range(8):
        context = service.authorize_model_call(
            tenant_id="owner-a",
            product_id="js-work",
            session_id=f"bounded-session-{index}",
            run_id=f"bounded-run-{index}",
            provider_id="mock-provider",
            model_id="mock-model",
            messages=[ChatMessage(role="user", content=f"hello {index}")],
        )
        service.finish_chat_turn(
            context,
            assistant_text="done",
            status="completed",
            token_totals={"input": 1, "output": 1},
        )

    owner_roots = tuple(
        path
        for path in (tmp_path / "echo" / "ledger" / "partitions").glob("*/*")
        if path.is_dir()
    )
    assert len(owner_roots) == 1
    owner_root = owner_roots[0]
    session_roots = tuple(owner_root.glob("session_*"))
    checkpoint_path = owner_root / "retired-sessions.json"
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))

    assert len(session_roots) == 3
    assert checkpoint["schema_version"] == "echo-session-retention-v2"
    assert checkpoint["retired_count"] == 5
    assert checkpoint["compacted_count"] == 3
    assert len(checkpoint["receipts"]) == 2
    assert checkpoint["legacy_unindexed_retired_count"] == 0
    assert checkpoint["artifact_ref_count"] == 0
    assert checkpoint["artifact_bytes"] == 0
    assert checkpoint["artifact_catalog"] == []
    assert checkpoint["pending_retirement"] is None
    assert checkpoint_path.stat().st_size < 16 * 1024
    assert stat.S_IMODE(owner_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(checkpoint_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((owner_root / "retention.key").stat().st_mode) == 0o600
    assert service.health().ok is True
    service.close()

    restarted = EchoSafetyService.from_settings(settings)
    assert restarted.health().ok is True
    assert restarted.health().retired_session_partition_count == 5

    reused = restarted.authorize_model_call(
        tenant_id="owner-a",
        product_id="js-work",
        session_id="bounded-session-0",
        run_id="bounded-run-reused",
        provider_id="mock-provider",
        model_id="mock-model",
        messages=[ChatMessage(role="user", content="hello again")],
    )
    restarted.finish_chat_turn(
        reused,
        assistant_text="done again",
        status="completed",
        token_totals={"input": 1, "output": 1},
    )

    reused_path = restarted.journal_path_for_scope(
        "owner-a",
        product_id="js-work",
        session_id="bounded-session-0",
    )
    reused_records = FileEchoLedger(
        reused_path,
        mac_key=restarted.journal_key_for_scope(
            "owner-a",
            product_id="js-work",
            session_id="bounded-session-0",
        ),
    ).records
    assert len(tuple(owner_root.glob("session_*"))) == 3
    assert reused_records[0].record_type == "partition_resume"
    assert reused_records[0].payload["retention_checkpoint_tip"].startswith("sha256:")
    assert restarted.health().ok is True


def test_session_partition_hard_cap_fails_closed_when_every_partition_is_open(
    tmp_path: Path,
) -> None:
    from js.models.providers import ChatMessage

    settings = JSSettings(
        state_dir=tmp_path,
        echo_ledger=EchoLedgerConfig(max_session_partitions_per_owner=2),
    )
    service = EchoSafetyService.from_settings(settings)
    contexts = [
        service.authorize_model_call(
            tenant_id="owner-a",
            product_id="js-work",
            session_id=f"open-session-{index}",
            run_id=f"open-run-{index}",
            provider_id="mock-provider",
            model_id="mock-model",
            messages=[ChatMessage(role="user", content=f"hello {index}")],
        )
        for index in range(2)
    ]

    with pytest.raises(EchoUnavailableError, match="partition capacity"):
        service.authorize_model_call(
            tenant_id="owner-a",
            product_id="js-work",
            session_id="open-session-overflow",
            run_id="open-run-overflow",
            provider_id="mock-provider",
            model_id="mock-model",
            messages=[ChatMessage(role="user", content="must fail closed")],
        )

    owner_root = next((tmp_path / "echo" / "ledger" / "partitions").glob("*/*"))
    assert len(tuple(owner_root.glob("session_*"))) == 2
    for context in contexts:
        assert context.outbox_id
    service.close()


def test_partition_retention_preserves_manual_review_and_retires_only_closed_sessions(
    tmp_path: Path,
) -> None:
    from js.models.providers import ChatMessage

    settings = JSSettings(
        state_dir=tmp_path,
        echo_ledger=EchoLedgerConfig(max_session_partitions_per_owner=2),
    )
    service = EchoSafetyService.from_settings(settings)
    manual_context = service.authorize_model_call(
        tenant_id="owner-a",
        product_id="js-work",
        session_id="manual-session",
        run_id="manual-run",
        provider_id="mock-provider",
        model_id="mock-model",
        messages=[ChatMessage(role="user", content="leave for review")],
    )
    manual_path = service.journal_path_for_scope(
        "owner-a",
        product_id="js-work",
        session_id="manual-session",
    )
    service.close()

    restarted = EchoSafetyService.from_settings(settings)
    assert restarted.health().manual_review_effect_count == 1
    for index in range(2):
        context = restarted.authorize_model_call(
            tenant_id="owner-a",
            product_id="js-work",
            session_id=f"closed-session-{index}",
            run_id=f"closed-run-{index}",
            provider_id="mock-provider",
            model_id="mock-model",
            messages=[ChatMessage(role="user", content=f"hello {index}")],
        )
        restarted.finish_chat_turn(
            context,
            assistant_text="done",
            status="completed",
            token_totals={"input": 1, "output": 1},
        )

    assert manual_path.is_file()
    assert restarted.health().manual_review_effect_count == 1
    assert restarted.health().retired_session_partition_count == 1
    assert any(
        review.effect_id == manual_context.effect_id
        for review in restarted.list_manual_reviews(tenant_id="owner-a")
    )


def test_retention_checkpoint_tamper_fails_health_without_deleting_hot_partitions(
    tmp_path: Path,
) -> None:
    from js.models.providers import ChatMessage

    settings = JSSettings(
        state_dir=tmp_path,
        echo_ledger=EchoLedgerConfig(max_session_partitions_per_owner=2),
    )
    service = EchoSafetyService.from_settings(settings)
    for index in range(3):
        context = service.authorize_model_call(
            tenant_id="owner-a",
            product_id="js-work",
            session_id=f"tamper-session-{index}",
            run_id=f"tamper-run-{index}",
            provider_id="mock-provider",
            model_id="mock-model",
            messages=[ChatMessage(role="user", content=f"hello {index}")],
        )
        service.finish_chat_turn(
            context,
            assistant_text="done",
            status="completed",
            token_totals={"input": 1, "output": 1},
        )
    service.close()

    owner_root = next((tmp_path / "echo" / "ledger" / "partitions").glob("*/*"))
    checkpoint_path = owner_root / "retired-sessions.json"
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    checkpoint["retired_count"] = 99
    checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
    hot_before = {path.name for path in owner_root.glob("session_*")}

    tampered = EchoSafetyService.from_settings(settings)
    health = tampered.health()

    assert health.ok is False
    assert "MAC" in str(health.partition_retention_error)
    assert {path.name for path in owner_root.glob("session_*")} == hot_before


def test_restart_finishes_receipt_first_partition_retirement_after_crash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from js.models.providers import ChatMessage

    settings = JSSettings(
        state_dir=tmp_path,
        echo_ledger=EchoLedgerConfig(max_session_partitions_per_owner=2),
    )
    service = EchoSafetyService.from_settings(settings)
    for index in range(2):
        context = service.authorize_model_call(
            tenant_id="owner-a",
            product_id="js-work",
            session_id=f"crash-session-{index}",
            run_id=f"crash-run-{index}",
            provider_id="mock-provider",
            model_id="mock-model",
            messages=[ChatMessage(role="user", content=f"hello {index}")],
        )
        service.finish_chat_turn(
            context,
            assistant_text="done",
            status="completed",
            token_totals={"input": 1, "output": 1},
        )

    original_finish = service._finish_interrupted_retirement_locked

    def crash_after_atomic_rename(owner_root: Path) -> None:
        if (owner_root / ".retiring").is_dir():
            raise OSError("simulated crash after partition rename")
        original_finish(owner_root)

    monkeypatch.setattr(
        service,
        "_finish_interrupted_retirement_locked",
        crash_after_atomic_rename,
    )
    with pytest.raises(EchoUnavailableError, match="partition retirement failed"):
        service.authorize_model_call(
            tenant_id="owner-a",
            product_id="js-work",
            session_id="crash-session-overflow",
            run_id="crash-run-overflow",
            provider_id="mock-provider",
            model_id="mock-model",
            messages=[ChatMessage(role="user", content="trigger retirement")],
        )

    owner_root = next((tmp_path / "echo" / "ledger" / "partitions").glob("*/*"))
    assert (owner_root / ".retiring").is_dir()
    assert (owner_root / "retired-sessions.json").is_file()

    recovered = EchoSafetyService.from_settings(settings)

    assert not (owner_root / ".retiring").exists()
    assert recovered.health().ok is True
    assert recovered.health().retired_session_partition_count == 1


def test_partition_retention_never_follows_or_deletes_an_unexpected_symlink(
    tmp_path: Path,
) -> None:
    from js.models.providers import ChatMessage

    settings = JSSettings(
        state_dir=tmp_path,
        echo_ledger=EchoLedgerConfig(max_session_partitions_per_owner=2),
    )
    service = EchoSafetyService.from_settings(settings)
    first_path: Path | None = None
    for index in range(2):
        context = service.authorize_model_call(
            tenant_id="owner-a",
            product_id="js-work",
            session_id=f"symlink-session-{index}",
            run_id=f"symlink-run-{index}",
            provider_id="mock-provider",
            model_id="mock-model",
            messages=[ChatMessage(role="user", content=f"hello {index}")],
        )
        service.finish_chat_turn(
            context,
            assistant_text="done",
            status="completed",
            token_totals={"input": 1, "output": 1},
        )
        if index == 0:
            first_path = service.journal_path_for_scope(
                "owner-a",
                product_id="js-work",
                session_id="symlink-session-0",
            )
    assert first_path is not None
    private_sentinel = tmp_path / "synthetic-private-sentinel.txt"
    private_sentinel.write_text("must remain local and untouched", encoding="utf-8")
    (first_path.parent / "unexpected-link").symlink_to(private_sentinel)

    with pytest.raises(EchoUnavailableError, match="partition retirement failed"):
        service.authorize_model_call(
            tenant_id="owner-a",
            product_id="js-work",
            session_id="symlink-session-overflow",
            run_id="symlink-run-overflow",
            provider_id="mock-provider",
            model_id="mock-model",
            messages=[ChatMessage(role="user", content="must fail closed")],
        )

    assert private_sentinel.read_text(encoding="utf-8") == "must remain local and untouched"
    assert first_path.is_file()
    assert (first_path.parent / "unexpected-link").is_symlink()


def test_partition_lifecycle_guard_rejects_symlink_without_touching_target(
    tmp_path: Path,
) -> None:
    sentinel = tmp_path / "synthetic-guard-sentinel.txt"
    sentinel.write_text("do not chmod or overwrite", encoding="utf-8")
    sentinel.chmod(0o640)
    ledger_root = tmp_path / "echo" / "ledger"
    ledger_root.mkdir(parents=True, mode=0o700)
    (ledger_root / "partitions.guard").symlink_to(sentinel)
    service = EchoSafetyService.from_settings(JSSettings(state_dir=tmp_path))

    with pytest.raises(EchoUnavailableError, match="partition guard"):
        service.journal_path_for_scope(
            "owner-a",
            product_id="js-work",
            session_id="guard-symlink-session",
        )

    assert sentinel.read_text(encoding="utf-8") == "do not chmod or overwrite"
    assert stat.S_IMODE(sentinel.stat().st_mode) == 0o640


def test_key_creation_lock_rejects_symlink_without_touching_target(tmp_path: Path) -> None:
    sentinel = tmp_path / "synthetic-key-lock-sentinel.txt"
    sentinel.write_text("do not chmod or overwrite", encoding="utf-8")
    sentinel.chmod(0o640)
    key_path = tmp_path / "journal.key"
    (tmp_path / "journal.key.lock").symlink_to(sentinel)

    with pytest.raises((OSError, ValueError)):
        service_module._load_or_create_key(key_path)

    assert not key_path.exists()
    assert sentinel.read_text(encoding="utf-8") == "do not chmod or overwrite"
    assert stat.S_IMODE(sentinel.stat().st_mode) == 0o640


def test_partition_retirement_exclusive_lock_waits_for_other_process_reader(
    tmp_path: Path,
) -> None:
    from js.models.providers import ChatMessage

    settings = JSSettings(
        state_dir=tmp_path,
        echo_ledger=EchoLedgerConfig(max_session_partitions_per_owner=2),
    )
    service = EchoSafetyService.from_settings(settings)
    for index in range(2):
        context = service.authorize_model_call(
            tenant_id="owner-a",
            product_id="js-work",
            session_id=f"lock-session-{index}",
            run_id=f"lock-run-{index}",
            provider_id="mock-provider",
            model_id="mock-model",
            messages=[ChatMessage(role="user", content=f"hello {index}")],
        )
        service.finish_chat_turn(
            context,
            assistant_text="done",
            status="completed",
            token_totals={"input": 1, "output": 1},
        )

    process_context = multiprocessing.get_context("spawn")
    ready = process_context.Event()
    release = process_context.Event()
    reader = process_context.Process(
        target=_hold_partition_guard_worker,
        args=(str(tmp_path), ready, release),
    )
    reader.start()
    assert ready.wait(timeout=10)

    completed = threading.Event()
    result: list[EchoTurnContext | BaseException] = []

    def create_overflow_partition() -> None:
        try:
            result.append(
                service.authorize_model_call(
                    tenant_id="owner-a",
                    product_id="js-work",
                    session_id="lock-session-overflow",
                    run_id="lock-run-overflow",
                    provider_id="mock-provider",
                    model_id="mock-model",
                    messages=[ChatMessage(role="user", content="wait for exclusive lock")],
                )
            )
        except BaseException as exc:  # noqa: BLE001 - thread returns exact failure
            result.append(exc)
        finally:
            completed.set()

    creator = threading.Thread(target=create_overflow_partition)
    creator.start()
    assert completed.wait(timeout=0.2) is False
    release.set()
    assert completed.wait(timeout=10) is True
    creator.join(timeout=1)
    reader.join(timeout=10)

    assert reader.exitcode == 0
    assert len(result) == 1
    assert isinstance(result[0], EchoTurnContext)
    service.finish_chat_turn(
        result[0],
        assistant_text="done",
        status="completed",
        token_totals={"input": 1, "output": 1},
    )
    assert len(
        tuple((tmp_path / "echo" / "ledger" / "partitions").glob("*/*/session_*"))
    ) == 2


def test_service_tenant_state_cache_is_bounded(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)

    for index in range(520):
        service.journal_path_for(f"owner-{index}")

    health = service.health()

    assert health.loaded_tenant_state_count == health.tenant_state_limit
    assert health.tenant_state_limit == 512
    assert health.journal_state_scan_truncated is True
    assert len(service._health_verify_cache) <= health.tenant_state_limit + 1


def test_service_begin_then_finish_records_primary_wrapper_sequence(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)

    context = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="session-a",
        user_text="hello",
        model_id="mock",
    )
    mid_records = FileEchoLedger(
        service.journal_path_for("owner-a"),
        mac_key=service.journal_key_for("owner-a"),
    ).records
    service.assert_model_execution_permitted(context)
    result = service.finish_chat_turn(
        context,
        assistant_text="hi from real adapter",
        status="completed",
        token_totals={"input": 3, "output": 2},
    )

    assert tuple(record.record_type for record in mid_records) == (
        "intake",
        "decision",
        "policy_decision",
        "permit",
        "model_privacy_envelope",
        "outbox",
    )
    assert result.record_types == ("receipt", "merge")
    records = FileEchoLedger(
        service.journal_path_for("owner-a"),
        mac_key=service.journal_key_for("owner-a"),
    ).records
    assert records[-2].payload["status"] == "completed"
    assert records[-2].payload["output_ref"].startswith("assistant:sha256:")


def test_service_finish_keeps_claimed_outbox_when_receipt_journal_append_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    context = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="session-a",
        user_text="hello",
        model_id="mock",
    )
    service.assert_model_execution_permitted(context)
    tenant_state = service._tenant_state("owner-a")

    def fail_append_many(*args: object, **kwargs: object) -> object:
        raise OSError("disk full")

    monkeypatch.setattr(tenant_state.journal, "append_many", fail_append_many)

    with pytest.raises(EchoUnavailableError, match="disk full") as raised:
        service.finish_chat_turn(
            context,
            assistant_text="hi",
            status="completed",
            token_totals={"input": 1, "output": 1},
        )
    assert isinstance(raised.value.__cause__, OSError)

    health = service.health()
    assert tenant_state.effects.status(context.outbox_id) == "claimed"
    assert health.ok is False
    assert health.error_count == 1
    assert health.claimed_effect_count == 1


def test_service_restart_completes_durable_receipt_missing_merge(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    context = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="session-a",
        user_text="hello",
        model_id="mock",
    )
    service.assert_model_execution_permitted(context)
    tenant_state = service._tenant_state("owner-a")
    external = FileEchoLedger(
        service.journal_path_for("owner-a"),
        mac_key=service.journal_key_for("owner-a"),
    )
    external.append(
        record_type="receipt",
        tenant_id="owner-a",
        run_id="session-a",
        payload={
            "effect_id": context.effect_id,
            "outbox_id": context.outbox_id,
            "status": "completed",
            "output_ref": "assistant:sha256:" + "1" * 64,
            "token_totals": {"input": 1, "output": 1},
            "token_source": "estimated",
        },
    )
    service._release_claim_lock(tenant_state, context.outbox_id)

    restarted = EchoSafetyService.from_settings(settings)

    records = FileEchoLedger(
        restarted.journal_path_for("owner-a"),
        mac_key=restarted.journal_key_for("owner-a"),
    ).records
    assert records[-1].record_type == "merge"
    assert restarted.health().ok is True


def test_echo_ledger_state_directories_are_private_under_permissive_umask(
    tmp_path: Path,
) -> None:
    old_umask = os.umask(0)
    try:
        service = EchoSafetyService.from_settings(JSSettings(state_dir=tmp_path))
        context = service.begin_chat_turn(
            tenant_id="owner-a",
            run_id="session-a",
            user_text="hello",
            model_id="mock",
        )
        service.assert_model_execution_permitted(context)
        tenant_dir = service.journal_path_for("owner-a").parent
        claims_dir = tenant_dir / "claims"
    finally:
        os.umask(old_umask)

    assert stat.S_IMODE((tmp_path / "echo" / "ledger").stat().st_mode) == 0o700
    assert stat.S_IMODE(tenant_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(claims_dir.stat().st_mode) == 0o700


def test_service_authorize_model_call_records_echo2_scope_permit_metadata(
    tmp_path: Path,
) -> None:
    from js.models.providers import ChatMessage

    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)

    context = service.authorize_model_call(
        tenant_id="owner-a",
        session_id="session-a",
        run_id="run-a",
        product_id="js-work",
        provider_id="mock-provider",
        model_id="mock-model",
        messages=[ChatMessage(role="user", content="hello")],
        tools_schema=[{"name": "safe_tool", "input_schema": {"type": "object"}}],
    )
    service.finish_chat_turn(
        context,
        assistant_text="hi",
        status="completed",
        token_totals={"input": 1, "output": 1},
        token_source="estimated",
    )

    records = FileEchoLedger(
        service.journal_path_for_scope(
            "owner-a", product_id="js-work", session_id="session-a"
        ),
        mac_key=service.journal_key_for_scope(
            "owner-a", product_id="js-work", session_id="session-a"
        ),
    ).records
    intake = records[0].payload
    permit = records[3].payload
    receipt = records[7].payload

    assert intake["model_call"]["architecture"] == "echo-2.0"
    assert intake["model_call"]["scope_gate"] == "ScopeGate"
    assert intake["model_call"]["request_hash"].startswith("sha256:")
    assert permit["scope_permit"]["architecture"] == "echo-2.0"
    assert permit["scope_permit"]["session_id"] == "session-a"
    assert permit["scope_permit"]["run_id"] == "run-a"
    assert permit["scope_permit"]["request_hash"] == intake["model_call"]["request_hash"]
    assert intake["model_call"]["product_id"] == "js-work"
    assert "model:invoke" in permit["scope_permit"]["granted_scopes"]
    assert "product:js-work" in permit["scope_permit"]["granted_scopes"]
    assert "tool:safe_tool" in permit["scope_permit"]["granted_scopes"]
    assert receipt["token_source"] == "estimated"


def test_service_authorize_model_call_records_unified_execution_contract(
    tmp_path: Path,
) -> None:
    from js.models.providers import ChatMessage

    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)

    context = service.authorize_model_call(
        tenant_id="owner-a",
        run_id="session-a",
        provider_id="mock-provider",
        model_id="mock-model",
        messages=[ChatMessage(role="user", content="hello")],
        tools_schema=None,
    )

    records = FileEchoLedger(
        service.journal_path_for_scope(
            "owner-a", product_id="js-agent", session_id="session-a"
        ),
        mac_key=service.journal_key_for_scope(
            "owner-a", product_id="js-agent", session_id="session-a"
        ),
    ).records
    outbox = records[5].payload
    execution_contract = outbox["execution_contract"]

    assert execution_contract["architecture"] == "echo-2.0"
    assert execution_contract["executor_kind"] == "model"
    assert execution_contract["executor_route"] == "JSAgent.authorized_model_chat"
    assert execution_contract["effect"]["effect_id"] == context.effect_id
    assert execution_contract["effect"]["action_kind"] == "model.js_agent_chat"
    assert execution_contract["outbox"]["outbox_id"] == context.outbox_id
    assert execution_contract["outbox"]["effect_id"] == context.effect_id
    assert execution_contract["side_effect"]["commitment"] == "probe_before_merge"
    assert execution_contract["state_mapping"]["journal_record_start"] == 0
    assert "rollback" not in str(execution_contract).lower()


def test_service_authorize_model_call_combines_begin_and_claim_append(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from js.models.providers import ChatMessage

    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    tenant_state = service._partition_state(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
    )
    append_many = tenant_state.journal.append_many
    append_sizes: list[int] = []

    def spy_append_many(entries: tuple[object, ...], **kwargs: object) -> object:
        append_sizes.append(len(entries))
        return append_many(entries, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(tenant_state.journal, "append_many", spy_append_many)

    context = service.authorize_model_call(
        tenant_id="owner-a",
        run_id="session-a",
        provider_id="mock-provider",
        model_id="mock-model",
        messages=[ChatMessage(role="user", content="hello")],
        tools_schema=None,
    )

    assert context.outbox_id
    assert append_sizes == [7]
    records = FileEchoLedger(
        service.journal_path_for_scope(
            "owner-a", product_id="js-agent", session_id="session-a"
        ),
        mac_key=service.journal_key_for_scope(
            "owner-a", product_id="js-agent", session_id="session-a"
        ),
    ).records
    assert tuple(record.record_type for record in records) == (
        "intake",
        "decision",
        "policy_decision",
        "permit",
        "model_privacy_envelope",
        "outbox",
        "outbox_claimed",
    )


def test_service_authorize_model_call_binds_real_provider_and_attachment_manifest(
    tmp_path: Path,
) -> None:
    from js.models.providers import ChatMessage

    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    attachment_manifest = (
        {
            "name": "note.txt",
            "size": 5,
            "sha256": "sha256:" + "a" * 64,
            "media_type": "text/plain",
        },
    )

    context = service.authorize_model_call(
        tenant_id="owner-a",
        session_id="session-a",
        run_id="run-a",
        product_id="js-work",
        provider_id="provider-a",
        model_id="model-a",
        messages=[ChatMessage(role="user", content="hello")],
        tools_schema=None,
        attachments_manifest=attachment_manifest,
    )

    records = FileEchoLedger(
        service.journal_path_for_scope(
            "owner-a", product_id="js-work", session_id="session-a"
        ),
        mac_key=service.journal_key_for_scope(
            "owner-a", product_id="js-work", session_id="session-a"
        ),
    ).records
    permit = next(record for record in records if record.record_type == "permit")
    privacy = next(
        record for record in records if record.record_type == "model_privacy_envelope"
    )
    intake = next(record for record in records if record.record_type == "intake")
    scope_permit = permit.payload["scope_permit"]
    model_call = intake.payload["model_call"]

    assert scope_permit["provider_id"] == "provider-a"
    assert scope_permit["model_id"] == "model-a"
    assert scope_permit["attachments_hash"] != stable_payload_hash(())
    assert privacy.payload["provider_id"] == "provider-a"
    assert model_call["provider_id"] == "provider-a"
    assert model_call["attachments_manifest"] == list(attachment_manifest)
    assert context.permit_seal is not None
    assert context.permit_seal.action_kind == "model.js_agent_chat"
    service.finish_chat_turn(
        context,
        assistant_text="done",
        status="completed",
        token_totals={"input": 1, "output": 1},
        token_source="estimated",
    )


def test_service_requires_valid_permit_before_model_execution(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    context = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="session-a",
        user_text="hello",
        model_id="mock",
    )

    service.assert_model_execution_permitted(context)

    with pytest.raises(PermissionError, match="not queued"):
        service.assert_model_execution_permitted(context)

    seal = context.permit_seal
    assert seal is not None
    bad_context = replace(
        context,
        permit_seal=replace(seal, mac=b"bad-mac"),
    )
    with pytest.raises(PermissionError, match="MAC invalid"):
        service.assert_model_execution_permitted(bad_context)

    missing_context = replace(context, permit_seal=None)
    with pytest.raises(PermissionError, match="missing PermitSeal"):
        service.assert_model_execution_permitted(missing_context)

    missing_outbox_context = replace(context, outbox_id="missing-outbox")
    with pytest.raises(PermissionError, match="outbox row missing"):
        service.assert_model_execution_permitted(missing_outbox_context)


def test_finish_without_durable_claim_does_not_append_receipt(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    context = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="session-a",
        user_text="hello",
        model_id="mock",
    )

    with pytest.raises(PermissionError, match="claimed"):
        service.finish_chat_turn(
            context,
            assistant_text="must not persist",
            status="completed",
            token_totals={"input": 1, "output": 1},
        )

    records = FileEchoLedger(
        service.journal_path_for("owner-a"),
        mac_key=service.journal_key_for("owner-a"),
    ).records
    assert "receipt" not in {record.record_type for record in records}
    assert "merge" not in {record.record_type for record in records}


def test_replay_rejects_orphan_claim_instead_of_reporting_healthy(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    service._default_state.journal.append(
        record_type="outbox_claimed",
        tenant_id="owner-a",
        run_id="run-a",
        payload={"outbox_id": "missing", "effect_id": "effect-missing"},
    )

    with pytest.raises(ValueError, match="orphan outbox_claimed"):
        EchoSafetyService.from_settings(settings)


@pytest.mark.parametrize(
    ("record_type", "payload", "expected_error"),
    [
        (
            "receipt",
            {
                "outbox_id": "missing-outbox",
                "effect_id": "missing-effect",
                "status": "completed",
            },
            "orphan receipt",
        ),
        (
            "merge",
            {"effect_id": "missing-effect"},
            "orphan merge",
        ),
    ],
)
def test_replay_rejects_orphan_effect_terminals(
    tmp_path: Path,
    record_type: str,
    payload: dict[str, str],
    expected_error: str,
) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    service._default_state.journal.append(
        record_type=record_type,
        tenant_id="owner-a",
        run_id="run-a",
        payload=payload,
    )

    with pytest.raises(ValueError, match=expected_error):
        EchoSafetyService.from_settings(settings)


@pytest.mark.parametrize(
    ("record_type", "payload"),
    [
        (
            "receipt",
            {
                "outbox_id": "missing-outbox",
                "effect_id": "missing-effect",
                "status": "completed",
            },
        ),
        (
            "merge",
            {"effect_id": "missing-effect"},
        ),
    ],
)
def test_replay_orphan_after_compaction_makes_health_unhealthy(
    tmp_path: Path,
    record_type: str,
    payload: dict[str, str],
) -> None:
    """compaction 后 orphan receipt/merge 不应静默跳过，必须使 health 不健康（§4 要求）."""
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    context = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="run-a",
        user_text="hello",
        model_id="mock",
    )
    service.assert_model_execution_permitted(context)
    service.finish_chat_turn(
        context,
        status="completed",
        assistant_text="ok",
        token_totals={},
        token_source="estimated",
    )
    service.close()

    # compact 产生 snapshot_anchor
    ledger_path = service.journal_path_for("owner-a")
    journal_key = service.journal_key_for("owner-a")
    journal = FileEchoLedger(ledger_path, mac_key=journal_key)
    journal.compact(max_records=1, archive=True)

    # 追加一条 orphan 终态记录（effect_id 不在 snapshot tombstone 中）
    journal.append(
        record_type=record_type,
        tenant_id="owner-a",
        run_id="run-a",
        payload=payload,
    )

    # 加载 service，health 应不健康
    service2 = EchoSafetyService.from_settings(settings)
    health = service2.health()
    assert health.ok is False, (
        f"compaction 后 orphan {record_type} 应使 health 不健康, got ok={health.ok}"
    )
    service2.close()


def test_second_service_does_not_manual_review_a_live_claim(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)
    active = EchoSafetyService.from_settings(settings)
    context = active.begin_chat_turn(
        tenant_id="owner-a",
        run_id="session-a",
        user_text="hello",
        model_id="mock",
    )
    active.assert_model_execution_permitted(context)

    observer = EchoSafetyService.from_settings(settings)
    health = observer.health()

    assert health.manual_review_effect_count == 0
    assert health.claimed_effect_count == 1
    assert health.ok is False
    observer.close()
    active.close()


def test_preloaded_process_cannot_reexecute_peer_committed_effect(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    first_start = context.Event()
    stale_start = context.Event()
    processes = (
        context.Process(
            target=_preloaded_turn_worker,
            args=(str(tmp_path), "first", first_start, results),
        ),
        context.Process(
            target=_preloaded_turn_worker,
            args=(str(tmp_path), "stale", stale_start, results),
        ),
    )
    for process in processes:
        process.start()
    try:
        ready = {results.get(timeout=15)[:2] for _ in processes}
        assert ready == {("first", "ready"), ("stale", "ready")}

        first_start.set()
        first_result = results.get(timeout=15)
        assert first_result[:2] == ("first", "executed")

        stale_start.set()
        stale_result = results.get(timeout=15)
        assert stale_result[:2] == ("stale", "blocked")
        error_name, error_message, observed_count, observed_ok = stale_result[2]
        assert error_name in {"PermissionError", "EchoUnavailableError"}
        assert "effect" in error_message.lower() or "outbox" in error_message.lower()
        assert observed_count == 9
        assert observed_ok is True
    finally:
        first_start.set()
        stale_start.set()
        for process in processes:
            process.join(timeout=15)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)

    restarted = EchoSafetyService.from_settings(JSSettings(state_dir=tmp_path))
    records = FileEchoLedger(
        restarted.journal_path_for("owner-a"),
        mac_key=restarted.journal_key_for("owner-a"),
    ).records

    assert tuple(record.record_type for record in records).count("outbox_claimed") == 1
    assert tuple(record.record_type for record in records).count("receipt") == 1
    assert restarted.health().ok is True
    restarted.close()


def test_concurrent_preloaded_processes_execute_same_effect_at_most_once(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    start = context.Event()
    processes = tuple(
        context.Process(
            target=_preloaded_turn_worker,
            args=(str(tmp_path), label, start, results),
        )
        for label in ("first", "second")
    )
    for process in processes:
        process.start()
    try:
        ready = {results.get(timeout=15)[:2] for _ in processes}
        assert ready == {("first", "ready"), ("second", "ready")}
        start.set()
        outcomes = [results.get(timeout=15) for _ in processes]
    finally:
        start.set()
        for process in processes:
            process.join(timeout=15)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)

    assert sorted(outcome[1] for outcome in outcomes) == ["blocked", "executed"]
    restarted = EchoSafetyService.from_settings(JSSettings(state_dir=tmp_path))
    records = FileEchoLedger(
        restarted.journal_path_for("owner-a"),
        mac_key=restarted.journal_key_for("owner-a"),
    ).records

    assert tuple(record.record_type for record in records).count("outbox_claimed") == 1
    assert tuple(record.record_type for record in records).count("receipt") == 1
    assert restarted.health().ok is True
    restarted.close()


def test_high_contention_preloaded_processes_write_one_effect_lifecycle(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    start = context.Event()
    labels = tuple(f"worker-{index}" for index in range(6))
    processes = tuple(
        context.Process(
            target=_preloaded_turn_worker,
            args=(str(tmp_path), label, start, results, index * 1_000),
        )
        for index, label in enumerate(labels)
    )
    for process in processes:
        process.start()
    try:
        ready = {results.get(timeout=20)[:2] for _ in processes}
        assert ready == {(label, "ready") for label in labels}
        start.set()
        outcomes = [results.get(timeout=20) for _ in processes]
    finally:
        start.set()
        for process in processes:
            process.join(timeout=20)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)

    assert [outcome[1] for outcome in outcomes].count("executed") == 1
    assert [outcome[1] for outcome in outcomes].count("blocked") == len(processes) - 1
    restarted = EchoSafetyService.from_settings(JSSettings(state_dir=tmp_path))
    journal_path = restarted.journal_path_for("owner-a")
    records = FileEchoLedger(
        journal_path,
        mac_key=restarted.journal_key_for("owner-a"),
    ).records

    assert tuple(record.record_type for record in records).count("outbox") == 1
    assert tuple(record.record_type for record in records).count("outbox_claimed") == 1
    assert tuple(record.record_type for record in records).count("receipt") == 1
    assert tuple((journal_path.parent / "claims").glob("*.lock")) == ()
    assert restarted.health().ok is True
    restarted.close()


def test_service_on_mode_blocks_obvious_secret_before_model_call(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)

    with pytest.raises(PermissionError, match="Secret"):
        service.begin_chat_turn(
            tenant_id="owner-a",
            run_id="session-a",
            user_text="please use sk-test-1234567890abcdef",
            model_id="mock",
        )


def test_service_replays_claimed_outbox_after_restart(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    context = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="session-a",
        user_text="hello",
        model_id="mock",
    )
    service.assert_model_execution_permitted(context)
    service.close()

    restarted = EchoSafetyService.from_settings(settings)
    health = restarted.health()

    assert health.ok is False
    assert health.claimed_effect_count == 0
    assert health.pending_effect_count == 0
    assert health.manual_review_effect_count == 1

    restarted_again = EchoSafetyService.from_settings(settings)
    replayed_health = restarted_again.health()
    assert replayed_health.ok is False
    assert replayed_health.manual_review_effect_count == 1


def test_service_manual_review_resolution_persists_and_restores_health(
    tmp_path: Path,
) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    context = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="session-a",
        user_text="hello",
        model_id="mock",
    )
    service.assert_model_execution_permitted(context)
    service.close()
    restarted = EchoSafetyService.from_settings(settings)
    assert restarted.health().manual_review_effect_count == 1

    result = restarted.resolve_manual_review(
        tenant_id="owner-a",
        effect_id=context.effect_id,
        action="cancel",
        operator="tester",
        reason="confirmed no external side effect",
    )
    resolved_health = restarted.health()
    replayed = EchoSafetyService.from_settings(settings)

    assert result.ok
    assert result.record_types == ("manual_review_resolution", "merge")
    assert resolved_health.ok is True
    assert resolved_health.manual_review_effect_count == 0
    assert replayed.health().ok is True


def test_service_health_fails_when_tenant_scan_is_truncated(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    for idx in range(520):
        service.journal_path_for(f"owner-{idx}")

    health = service.health()

    assert health.journal_state_scan_truncated is True
    assert health.ok is False
    assert "truncated" in str(health.last_error).lower()


def test_service_compaction_retains_open_effects_then_writes_anchor(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    context = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="session-a",
        user_text="hello",
        model_id="mock",
    )
    service.assert_model_execution_permitted(context)

    first = service.compact_journals(max_records=2)
    assert first[str(service.journal_path_for("owner-a"))] is True
    first_records = FileEchoLedger(
        service.journal_path_for("owner-a"),
        mac_key=service.journal_key_for("owner-a"),
    ).records
    assert [record.record_type for record in first_records] == [
        "snapshot_anchor",
        "outbox",
        "outbox_claimed",
    ]

    service.finish_chat_turn(
        context,
        assistant_text="hi",
        status="completed",
        token_totals={"input": 1, "output": 1},
    )
    second = service.compact_journals(max_records=2)
    records = FileEchoLedger(
        service.journal_path_for("owner-a"),
        mac_key=service.journal_key_for("owner-a"),
    ).records

    assert second[str(service.journal_path_for("owner-a"))] is True
    assert records[0].record_type == "snapshot_anchor"
    assert verify_file(
        service.journal_path_for("owner-a"),
        mac_key=service.journal_key_for("owner-a"),
    ).ok


def test_compacted_irreversible_effect_uses_disk_tombstone_without_lifetime_memory(
    tmp_path: Path,
) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    tool = service.begin_tool_effect(
        tenant_id="owner-a",
        product_id="product-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="file_write",
        tool_call_id="call-a",
        args_hash=stable_payload_hash({"path": "a.txt"}),
        lease_id="lease-a",
        replay_class="non_idempotent",
    )
    service.finish_tool_effect(
        tool,
        status="ok",
        output_hash="sha256:" + "0" * 64,
    )
    for index in range(3):
        later = service.begin_tool_effect(
            tenant_id="owner-a",
            product_id="product-a",
            session_id="session-a",
            run_id=f"later-{index}",
            tool_name="file_write",
            tool_call_id=f"later-call-{index}",
            args_hash=stable_payload_hash({"path": f"later-{index}.txt"}),
            lease_id=f"later-lease-{index}",
            replay_class="non_idempotent",
        )
        service.finish_tool_effect(
            later,
            status="ok",
            output_hash=stable_payload_hash({"later": index}),
        )

    path = service.journal_path_for_scope(
        "owner-a", product_id="product-a", session_id="session-a"
    )
    assert service.compact_journals(max_records=1)[str(path)] is True
    state = service._partition_state(
        tenant_id="owner-a", product_id="product-a", session_id="session-a"
    )
    assert tool.effect_id not in state.effects.completed_effect_ids()
    assert state.journal.contains_archived_effect(tool.effect_id)
    service.close()

    restarted = EchoSafetyService.from_settings(settings)
    restarted_state = restarted._partition_state(
        tenant_id="owner-a", product_id="product-a", session_id="session-a"
    )
    assert tool.effect_id not in restarted_state.effects.completed_effect_ids()
    assert len(restarted_state.effects.completed_effect_ids()) <= 1
    assert restarted_state.effects.row_for_effect(tool.effect_id) is None
    with pytest.raises(PermissionError, match="durable|already"):
        restarted.begin_tool_effect(
            tenant_id="owner-a",
            product_id="product-a",
            session_id="session-a",
            run_id="run-a",
            tool_name="file_write",
            tool_call_id="call-a",
            args_hash=stable_payload_hash({"path": "a.txt"}),
            lease_id="lease-a",
            replay_class="non_idempotent",
        )
    restarted.close()


def test_service_health_fails_when_required_compaction_archive_is_missing(
    tmp_path: Path,
) -> None:
    service = EchoSafetyService.from_settings(JSSettings(state_dir=tmp_path))
    service.record_chat_turn(
        tenant_id="owner-a",
        run_id="run-a",
        user_text="hello",
        assistant_text="done",
        status="completed",
        token_totals={"input": 1, "output": 1},
    )
    assert service.compact_journals(max_records=2)[str(service.journal_path_for("owner-a"))]
    archive = _sqlite_archive_path(service.journal_path_for("owner-a"))
    archive.unlink()

    health = service.health()

    assert health.ok is False
    assert "archive_missing" in str(health.last_error)


def test_service_health_fails_when_compaction_archive_hash_no_longer_matches(
    tmp_path: Path,
) -> None:
    service = EchoSafetyService.from_settings(JSSettings(state_dir=tmp_path))
    service.record_chat_turn(
        tenant_id="owner-a",
        run_id="run-a",
        user_text="hello",
        assistant_text="done",
        status="completed",
        token_totals={"input": 1, "output": 1},
    )
    assert service.compact_journals(max_records=2)[str(service.journal_path_for("owner-a"))]
    _tamper_first_archived_record(service.journal_path_for("owner-a"))

    health = service.health()

    assert health.ok is False
    assert "archive" in str(health.last_error).lower()


def test_model_execution_claim_fails_closed_when_required_archive_is_missing(
    tmp_path: Path,
) -> None:
    service = EchoSafetyService.from_settings(JSSettings(state_dir=tmp_path))
    service.record_chat_turn(
        tenant_id="owner-a",
        run_id="seed-run",
        user_text="seed",
        assistant_text="done",
        status="completed",
        token_totals={"input": 1, "output": 1},
    )
    tenant_path = service.journal_path_for("owner-a")
    assert service.compact_journals(max_records=2)[str(tenant_path)] is True
    context = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="run-a",
        user_text="hello",
        model_id="mock",
    )
    archive = _sqlite_archive_path(tenant_path)
    archive.unlink()

    assert service.health().ok is False
    journal_before = tenant_path.read_bytes()
    try:
        with pytest.raises(EchoUnavailableError, match="archive"):
            service.assert_model_execution_permitted(context)
        assert tenant_path.read_bytes() == journal_before
        assert service._claim_lock_fds == {}
    finally:
        try:
            service.close()
        except ValueError:
            pass


def test_combined_model_authorization_fails_closed_on_required_archive_damage(
    tmp_path: Path,
) -> None:
    service = EchoSafetyService.from_settings(JSSettings(state_dir=tmp_path))
    seed = service.authorize_model_call(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="seed-run",
        provider_id="mock-provider",
        model_id="mock",
        messages=(),
    )
    service.finish_chat_turn(
        seed,
        assistant_text="done",
        status="completed",
        token_totals={"input": 1, "output": 1},
    )
    tenant_path = service.journal_path_for_scope(
        "owner-a", product_id="js-agent", session_id="session-a"
    )
    assert service.compact_journals(max_records=2)[str(tenant_path)] is True
    _tamper_first_archived_record(tenant_path)

    assert service.health().ok is False
    journal_before = tenant_path.read_bytes()
    try:
        with pytest.raises(EchoUnavailableError, match="archive"):
            service.authorize_model_call(
                tenant_id="owner-a",
                session_id="session-a",
                run_id="run-a",
                provider_id="mock-provider",
                model_id="mock",
                messages=(),
            )
        assert tenant_path.read_bytes() == journal_before
        assert service._claim_lock_fds == {}
    finally:
        try:
            service.close()
        except ValueError:
            pass


def test_compaction_cannot_replace_a_missing_required_archive(
    tmp_path: Path,
) -> None:
    service = EchoSafetyService.from_settings(JSSettings(state_dir=tmp_path))
    service.record_chat_turn(
        tenant_id="owner-a",
        run_id="run-a",
        user_text="hello",
        assistant_text="done",
        status="completed",
        token_totals={"input": 1, "output": 1},
    )
    tenant_path = service.journal_path_for("owner-a")
    assert service.compact_journals(max_records=2)[str(tenant_path)] is True
    anchor_before = FileEchoLedger(
        tenant_path,
        mac_key=service.journal_key_for("owner-a"),
    ).records[0]
    archive = tenant_path.parent / str(anchor_before.payload["archive_name"])
    archive.unlink()
    journal_before = tenant_path.read_bytes()

    result = service.compact_journals(max_records=1)
    health = service.health()
    anchor_after = FileEchoLedger(
        tenant_path,
        mac_key=service.journal_key_for("owner-a"),
    ).records[0]

    assert result[str(tenant_path)] is False
    assert tenant_path.read_bytes() == journal_before
    assert anchor_after.payload["archive_name"] == anchor_before.payload["archive_name"]
    assert health.ok is False
    assert "archive" in str(health.last_compaction_error).lower()
    service.close()


def test_finish_chat_turn_compacts_while_another_effect_is_still_open(
    tmp_path: Path,
) -> None:
    settings = JSSettings(
        state_dir=tmp_path,
        echo_ledger=EchoLedgerConfig(
            retain_records=3,
            trigger_records=8,
            max_archives=1,
        ),
    )
    service = EchoSafetyService.from_settings(settings)
    first = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="session-a",
        user_text="first",
        model_id="mock",
    )
    service.assert_model_execution_permitted(first)
    second = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="session-b",
        user_text="second",
        model_id="mock",
    )
    service.assert_model_execution_permitted(second)

    service.finish_chat_turn(
        first,
        assistant_text="first done",
        status="completed",
        token_totals={"input": 1, "output": 1},
    )
    open_health = service.health()
    records_with_open_effect = FileEchoLedger(
        service.journal_path_for("owner-a"),
        mac_key=service.journal_key_for("owner-a"),
    ).records
    assert records_with_open_effect[0].record_type == "snapshot_anchor"
    assert open_health.claimed_effect_count == 1
    assert open_health.last_compaction_skip_reason is None
    assert verify_file(
        service.journal_path_for("owner-a"),
        mac_key=service.journal_key_for("owner-a"),
    ).ok

    service.finish_chat_turn(
        second,
        assistant_text="second done",
        status="completed",
        token_totals={"input": 1, "output": 1},
    )
    compacted_health = service.health()
    records = FileEchoLedger(
        service.journal_path_for("owner-a"),
        mac_key=service.journal_key_for("owner-a"),
    ).records

    assert records[0].record_type == "snapshot_anchor"
    record_types = [record.record_type for record in records]
    assert record_types.count("outbox") == 2
    assert record_types.count("outbox_claimed") == 2
    assert record_types.count("receipt") == 2
    assert record_types.count("merge") == 2
    assert compacted_health.last_compaction_skip_reason is None
    assert verify_file(
        service.journal_path_for("owner-a"),
        mac_key=service.journal_key_for("owner-a"),
    ).ok
    restarted = EchoSafetyService.from_settings(settings)
    assert restarted.health().ok


def test_auto_compaction_preserves_manual_review_and_records_failure_in_health(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = JSSettings(
        state_dir=tmp_path,
        echo_ledger=EchoLedgerConfig(
            retain_records=2,
            trigger_records=3,
            max_archives=1,
        ),
    )
    service = EchoSafetyService.from_settings(settings)
    context = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="session-a",
        user_text="hello",
        model_id="mock",
    )
    service.assert_model_execution_permitted(context)
    state = service._tenant_state("owner-a")
    service.close()

    assert service.maybe_compact(state) is True
    compacted = FileEchoLedger(
        service.journal_path_for("owner-a"),
        mac_key=service.journal_key_for("owner-a"),
    ).records
    assert [record.record_type for record in compacted] == [
        "snapshot_anchor",
        "outbox",
        "outbox_claimed",
        "outbox_manual_review",
    ]
    assert service.health().last_compaction_skip_reason is None

    service.resolve_manual_review(
        tenant_id="owner-a",
        effect_id=context.effect_id,
        action="resolved",
        operator="test-operator",
        reason="verified safe",
    )

    def fail_compact(**kwargs: object) -> bool:
        raise OSError("archive cleanup failed")

    monkeypatch.setattr(state.journal, "compact", fail_compact)
    assert service.maybe_compact(state) is False
    health = service.health()
    assert health.ok is False
    assert health.last_compaction_error == "OSError: archive cleanup failed"


def test_raw_journal_compaction_preserves_open_effect_lifecycle(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)
    service = EchoSafetyService.from_settings(settings)
    context = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="session-a",
        user_text="hello",
        model_id="mock",
    )
    service.assert_model_execution_permitted(context)

    state = service._tenant_state("owner-a")
    assert state.journal.compact(max_records=1) is True
    compacted_types = [record.record_type for record in state.journal.records]
    assert compacted_types == ["snapshot_anchor", "outbox", "outbox_claimed"]

    service.close()
    restarted = EchoSafetyService.from_settings(settings)
    health = restarted.health()

    assert verify_file(
        restarted.journal_path_for("owner-a"),
        mac_key=restarted.journal_key_for("owner-a"),
    ).ok
    assert health.manual_review_effect_count == 1


def test_auto_compaction_stays_bounded_with_unresolved_manual_review(
    tmp_path: Path,
) -> None:
    settings = JSSettings(
        state_dir=tmp_path,
        echo_ledger=EchoLedgerConfig(
            retain_records=2,
            trigger_records=12,
            max_archives=1,
        ),
    )
    service = EchoSafetyService.from_settings(settings)
    unresolved = service.begin_chat_turn(
        tenant_id="owner-a",
        run_id="unresolved",
        user_text="needs review",
        model_id="mock",
    )
    service.assert_model_execution_permitted(unresolved)
    service.close()

    for index in range(40):
        service.record_chat_turn(
            tenant_id="owner-a",
            run_id=f"completed-{index}",
            user_text="hello",
            assistant_text="done",
            status="completed",
            token_totals={"input": 1, "output": 1},
        )

    records = FileEchoLedger(
        service.journal_path_for("owner-a"),
        mac_key=service.journal_key_for("owner-a"),
    ).records
    restarted = EchoSafetyService.from_settings(settings)

    assert len(records) <= 12
    assert records[0].record_type == "snapshot_anchor"
    assert restarted.health().manual_review_effect_count == 1
    assert restarted.health().record_count <= 12


def test_service_key_files_are_owner_only(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path)

    EchoSafetyService.from_settings(settings)

    for key_name in ("journal.key", "permit.key"):
        mode = stat.S_IMODE((tmp_path / "echo" / "ledger" / key_name).stat().st_mode)
        assert mode == 0o600


@pytest.mark.parametrize("encoded_key", ("", "00" * 16, "not-hex"))
def test_service_rejects_invalid_existing_mac_key(
    tmp_path: Path,
    encoded_key: str,
) -> None:
    key_path = tmp_path / "journal.key"
    key_path.write_text(encoded_key, encoding="utf-8")

    with pytest.raises(ValueError, match="32-byte"):
        service_module._load_or_create_key(key_path)


def test_service_concurrent_key_creation_returns_one_strict_key(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    key_path = tmp_path / "journal.key"
    start = context.Event()
    results = context.Queue()
    processes = tuple(
        context.Process(target=_load_key_worker, args=(str(key_path), start, results))
        for _ in range(8)
    )
    for process in processes:
        process.start()
    start.set()
    try:
        loaded = [results.get(timeout=15) for _ in processes]
    finally:
        for process in processes:
            process.join(timeout=15)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)

    assert {result[0] for result in loaded} == {"ok"}
    assert len({result[1] for result in loaded}) == 1
    assert len(loaded[0][1]) == 64
    assert {result[2] for result in loaded} == {0o600}
    assert len(bytes.fromhex(key_path.read_text(encoding="utf-8"))) == 32


def test_claim_lock_files_are_removed_after_completed_effects(tmp_path: Path) -> None:
    service = EchoSafetyService.from_settings(JSSettings(state_dir=tmp_path))

    for index in range(32):
        service.record_chat_turn(
            tenant_id="owner-a",
            run_id=f"run-{index}",
            user_text=f"message-{index}",
            assistant_text="done",
            status="completed",
            token_totals={"input": 1, "output": 1},
        )

    claims_dir = service.journal_path_for("owner-a").parent / "claims"
    assert list(claims_dir.glob("*.lock")) == []
    service.close()


def test_close_releases_all_claim_fds_when_required_archive_is_missing(
    tmp_path: Path,
) -> None:
    service = EchoSafetyService.from_settings(JSSettings(state_dir=tmp_path))
    service.record_chat_turn(
        tenant_id="owner-a",
        run_id="seed-run",
        user_text="seed",
        assistant_text="done",
        status="completed",
        token_totals={"input": 1, "output": 1},
    )
    owner_a_path = service.journal_path_for("owner-a")
    assert service.compact_journals(max_records=2)[str(owner_a_path)] is True
    owner_a = service.begin_tool_effect(
        tenant_id="owner-a",
        product_id="product-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="file_write",
        tool_call_id="call-a",
        args_hash=stable_payload_hash({"path": "a.txt"}),
        lease_id="lease-a",
        replay_class="non_idempotent",
    )
    owner_b = service.begin_tool_effect(
        tenant_id="owner-b",
        product_id="product-a",
        session_id="session-b",
        run_id="run-b",
        tool_name="file_write",
        tool_call_id="call-b",
        args_hash=stable_payload_hash({"path": "b.txt"}),
        lease_id="lease-b",
        replay_class="non_idempotent",
    )
    archive = _sqlite_archive_path(owner_a_path)
    archive.unlink()
    claim_fds = tuple(service._claim_lock_fds.values())

    service.close()

    assert service._claim_lock_fds == {}
    for fd in claim_fds:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert (
        service._partition_state(
            tenant_id="owner-a", product_id="product-a", session_id="session-a"
        ).effects.status(owner_a.outbox_id)
        == "manual_review"
    )
    assert (
        service._partition_state(
            tenant_id="owner-b", product_id="product-a", session_id="session-b"
        ).effects.status(owner_b.outbox_id)
        == "manual_review"
    )
