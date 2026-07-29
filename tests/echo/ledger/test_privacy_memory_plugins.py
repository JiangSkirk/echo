from __future__ import annotations

import inspect

import pytest

from js.echo.ledger.memory import MemoryCandidate, MemoryGate
from js.echo.ledger.plugins import InMemorySafePluginContext, PluginManifest
from js.echo.ledger.privacy import (
    ModelCallRequest,
    ProviderCapability,
    build_model_privacy_envelope,
    contains_secret_shape,
    redact_for_model,
)


def test_model_privacy_envelope_defaults_to_no_training_and_rejects_secret_data() -> None:
    request = ModelCallRequest(
        model_request_id="mr-1",
        tenant_id="tenant-a",
        provider_id="third-party",
        model_id="mock",
        prompt="hello",
        data_classes=("Secret",),
        prompt_slots_used=("user",),
        max_tokens=128,
        cost_budget=10,
        policy_decision_id="pdr-1",
    )

    with pytest.raises(PermissionError, match="Secret"):
        build_model_privacy_envelope(
            request,
            ProviderCapability(
                provider_id="third-party",
                zero_data_retention=False,
                retention_class="standard",
                region_policy=None,
            ),
        )

    safe_request = request.with_data_classes(("UserPrivate",))
    envelope = build_model_privacy_envelope(
        safe_request,
        ProviderCapability(
            provider_id="third-party",
            zero_data_retention=True,
            retention_class="zero-retention",
            region_policy="us",
        ),
    )

    assert envelope.allow_training is False
    assert envelope.pii_minimized is True
    assert envelope.secrets_removed is True


def test_redaction_removes_common_secret_shapes_before_model_call() -> None:
    text = "token sk-test-1234567890abcdef and Authorization: Bearer abc.def.ghi"

    redacted = redact_for_model(text)

    assert "sk-test" not in redacted.text
    assert "Bearer abc" not in redacted.text
    assert redacted.secrets_removed


@pytest.mark.parametrize(
    "text",
    [
        "aws AKIA1234567890ABCDEF",
        "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
        "jwt abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwx.abcdefghijklmnop",
        "password=correct-horse-battery-staple",
        "token: ghp_abcdefghijklmnopqrstuvwxyz123456",
        "Bearer abcdefghijklmnopqrstuvwxyz123456",
    ],
)
def test_secret_shape_detection_covers_common_provider_credentials(text: str) -> None:
    assert contains_secret_shape(text)


def test_memory_gate_quarantines_model_output_and_requires_owner_review() -> None:
    gate = MemoryGate()
    candidate = MemoryCandidate(
        candidate_id="mem-1",
        tenant_id="tenant-a",
        source_parcel_id="parcel-1",
        extracted_claims_ref="blob:claims",
        trust_level="model",
        taint_labels=("model_output",),
        owner_visible_summary="A model claim",
        proposed_retention="30d",
        confidence=0.7,
        created_by="model",
        promotion_policy_id="policy-1",
    )

    stored = gate.submit(candidate)

    assert stored.state == "quarantine"
    with pytest.raises(PermissionError, match="owner review"):
        gate.promote("tenant-a", "mem-1")

    promoted = gate.promote("tenant-a", "mem-1", owner_review=True)
    assert promoted.state == "active"


def test_memory_retrieve_filters_tenant_and_expired_or_revoked_records() -> None:
    gate = MemoryGate()
    user_candidate = MemoryCandidate(
        candidate_id="mem-user",
        tenant_id="tenant-a",
        source_parcel_id="parcel-user",
        extracted_claims_ref="blob:user",
        trust_level="user",
        taint_labels=(),
        owner_visible_summary="User fact",
        proposed_retention="30d",
        confidence=1.0,
        created_by="user",
        promotion_policy_id="policy-1",
    )
    other_candidate = MemoryCandidate(
        candidate_id="mem-other",
        tenant_id="tenant-b",
        source_parcel_id="parcel-other",
        extracted_claims_ref="blob:other",
        trust_level="user",
        taint_labels=(),
        owner_visible_summary="Other fact",
        proposed_retention="30d",
        confidence=1.0,
        created_by="user",
        promotion_policy_id="policy-1",
    )

    gate.submit(user_candidate)
    gate.submit(other_candidate)
    gate.promote("tenant-a", "mem-user")
    gate.promote("tenant-b", "mem-other")
    gate.revoke("tenant-a", "mem-user", reason="superseded")

    assert gate.retrieve(tenant_id="tenant-a", min_trust_level="user") == ()
    assert tuple(record.candidate_id for record in gate.retrieve(tenant_id="tenant-b")) == (
        "mem-other",
    )


def test_safe_plugin_context_does_not_expose_raw_host_capabilities() -> None:
    ctx = InMemorySafePluginContext(input_blob=b"hello", budget_tokens=10)

    public_methods = {
        name
        for name, member in inspect.getmembers(ctx, predicate=callable)
        if not name.startswith("_")
    }

    assert public_methods == {
        "emit_output_blob",
        "log_safe",
        "read_input_blob",
        "remaining_budget",
    }
    assert not hasattr(ctx, "open")
    assert not hasattr(ctx, "environ")
    assert not hasattr(ctx, "socket")
    assert not hasattr(ctx, "journal")


def test_stable_plugin_manifest_cannot_use_dev_bypass() -> None:
    with pytest.raises(ValueError, match="dev bypass"):
        PluginManifest(
            plugin_id="unsafe",
            version="1.0.0",
            license="MIT",
            permissions=("tool:echo",),
            mode="stable",
            dev_bypasses=("hot_reload",),
        )
