"""Echo cannot mint Intent/Handle. bots_ask cannot widen authority."""

from __future__ import annotations

import pytest

from js.bots.authority import refuse_ask_depth, refuse_echo_issuance
from js.bots.exceptions import BotsStateError
from js.orin.draft import EffectDraft
from js.orin.handles import (
    derive_bot_handle_id,
    echo_cannot_issue_handle,
    echo_cannot_issue_intent,
    seal_scoped_handle,
)
from js.orind.kernel import GateInputs, GateKernel
from js.orind.manifest import builtin_manifest


def test_echo_cannot_issue_intent_or_handle() -> None:
    with pytest.raises(PermissionError, match="Echo cannot issue IntentEnvelope"):
        echo_cannot_issue_intent()
    with pytest.raises(PermissionError, match="Echo cannot issue OriginHandle"):
        echo_cannot_issue_handle()
    with pytest.raises(PermissionError):
        refuse_echo_issuance(kind="intent")


def test_echo_issuer_cannot_seal_a_bot_handle() -> None:
    handle_id = derive_bot_handle_id(
        owner_key_hash="sha256:" + "a" * 64,
        product_id="js-agent",
        bot_id="b" + "1" * 32,
        epoch=1,
    )
    with pytest.raises(PermissionError, match="Echo cannot issue"):
        seal_scoped_handle(
            kind="BotHandle",
            handle_id=handle_id,
            owner_key_hash="sha256:" + "a" * 64,
            product_id="js-agent",
            object_digest="digest",
            mac_key=b"k" * 32,
            issuer="echo-runtime",
            now_ms=1,
        )


def test_free_text_bot_name_cannot_authorize_room_create() -> None:
    kernel = GateKernel(secret_taint_bit=1 << 12, manifest=builtin_manifest(b"k" * 32))
    draft = EffectDraft(
        draft_id="draft:bots",
        task_id="task:bots",
        effect_type="bot.room.create",
        arguments={"member_bot_handles": ["调查bot"], "title": "组", "kind": "group"},
        declared_expectation={},
    )
    decision = kernel.assess(draft, GateInputs(now_ms=1))
    assert decision.verdict == "deny_policy"
    assert "free_text_permission_arg" in decision.reason_code


def test_bots_ask_depth_two_is_refused() -> None:
    refuse_ask_depth(0)
    refuse_ask_depth(1)
    with pytest.raises(BotsStateError, match="depth exceeds 1"):
        refuse_ask_depth(2)
