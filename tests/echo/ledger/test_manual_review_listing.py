from __future__ import annotations

from pathlib import Path

import pytest

from js.config import JSSettings
from js.echo.ledger._hashing import stable_hash
from js.echo.ledger.service import EchoSafetyService, EchoUnavailableError


def test_manual_review_listing_refreshes_other_process_state_and_redacts_input(
    tmp_path: Path,
) -> None:
    settings = JSSettings(state_dir=tmp_path)
    writer = EchoSafetyService.from_settings(settings)
    observer = EchoSafetyService.from_settings(settings)
    context = writer.begin_chat_turn(
        tenant_id="tenant-a",
        run_id="run-a",
        user_text="secret manual review input must not escape",
        model_id="mock",
        call_metadata={
            "product_id": "js-work",
            "session_id": "session-a",
        },
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
    assert row.session_id == "session-a"
    assert row.run_id == "run-a"
    assert row.effect_digest.startswith("sha256:")
    assert row.args_digest.startswith("sha256:")
    assert "secret manual review input must not escape" not in repr(row)
    assert not hasattr(row, "sealed_input_ref")
    assert observer.health().manual_review_effect_count == 1


def test_exact_manual_review_projection_is_not_starved_by_513_other_owners(
    tmp_path: Path,
) -> None:
    settings = JSSettings(state_dir=tmp_path)
    candidates = [f"noise-owner-{index}" for index in range(700)]
    target_owner = max(
        candidates,
        key=lambda owner: stable_hash({"owner_id": owner}),
    )
    noise_owners = [owner for owner in candidates if owner != target_owner][:513]
    writer = EchoSafetyService.from_settings(settings)
    context = writer.begin_chat_turn(
        tenant_id=target_owner,
        run_id="target-run",
        user_text="target review",
        model_id="mock",
        call_metadata={
            "product_id": "js-agent",
            "session_id": "target-session",
        },
    )
    writer.assert_model_execution_permitted(context)
    writer.close()

    observer = EchoSafetyService.from_settings(settings)
    for index, owner in enumerate(noise_owners):
        observer.journal_path_for_scope(
            owner,
            product_id="js-agent",
            session_id=f"noise-session-{index}",
        )

    rows = observer.list_manual_reviews(
        tenant_id=target_owner,
        product_id="js-agent",
    )

    assert [row.effect_id for row in rows] == [context.effect_id]
    with pytest.raises(EchoUnavailableError, match="truncated|complete"):
        observer.list_manual_reviews(tenant_id=target_owner)


def test_exact_manual_review_projection_ignores_unrelated_corruption_but_not_target(
    tmp_path: Path,
) -> None:
    settings = JSSettings(state_dir=tmp_path)
    writer = EchoSafetyService.from_settings(settings)
    context = writer.begin_chat_turn(
        tenant_id="target-owner",
        run_id="target-run",
        user_text="target review",
        model_id="mock",
        call_metadata={
            "product_id": "js-agent",
            "session_id": "target-session",
        },
    )
    writer.assert_model_execution_permitted(context)
    writer.close()
    observer = EchoSafetyService.from_settings(settings)
    unrelated = observer.journal_path_for_scope(
        "unrelated-owner",
        product_id="js-agent",
        session_id="unrelated-session",
    )
    unrelated.write_text("not a journal\n", encoding="utf-8")

    rows = observer.list_manual_reviews(
        tenant_id="target-owner",
        product_id="js-agent",
    )
    assert [row.effect_id for row in rows] == [context.effect_id]

    target = observer.journal_path_for_scope(
        "target-owner",
        product_id="js-agent",
        session_id="target-session",
    )
    target.write_text("not a journal\n", encoding="utf-8")
    with pytest.raises((EchoUnavailableError, ValueError), match="manual review|journal"):
        observer.list_manual_reviews(
            tenant_id="target-owner",
            product_id="js-agent",
        )
