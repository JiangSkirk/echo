from __future__ import annotations

from pathlib import Path

from js.config import JSSettings
from js.echo.ledger.service import EchoSafetyService


def test_manual_review_listing_refreshes_other_process_state_and_redacts_input(
    tmp_path: Path,
) -> None:
    settings = JSSettings(state_dir=tmp_path)
    writer = EchoSafetyService.from_settings(settings)
    observer = EchoSafetyService.from_settings(settings)
    context = writer.begin_chat_turn(
        tenant_id="tenant-a",
        run_id="session-a",
        user_text="secret manual review input must not escape",
        model_id="mock",
    )
    writer.assert_model_execution_permitted(context)
    writer.close()

    rows = observer.list_manual_reviews(tenant_id="tenant-a")

    assert len(rows) == 1
    row = rows[0]
    assert row.effect_id == context.effect_id
    assert row.tenant_id == "tenant-a"
    assert row.action_kind == "model.js_agent_chat"
    assert row.status == "manual_review"
    assert "secret manual review input must not escape" not in repr(row)
    assert not hasattr(row, "sealed_input_ref")
    assert observer.health().manual_review_effect_count == 1
