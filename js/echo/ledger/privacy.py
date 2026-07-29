from __future__ import annotations

import re
from dataclasses import dataclass, replace

SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_-]{10,}"),
    re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9._-]+", re.IGNORECASE),
    re.compile(r"\bBearer\s+[A-Za-z0-9._-]{16,}", re.IGNORECASE),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(
        r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{16,}\b"
    ),
    re.compile(
        r"\b(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{8,}",
        re.IGNORECASE,
    ),
)


@dataclass(frozen=True)
class RedactionResult:
    text: str
    secrets_removed: bool


@dataclass(frozen=True)
class ProviderCapability:
    provider_id: str
    zero_data_retention: bool
    retention_class: str
    region_policy: str | None


@dataclass(frozen=True)
class ModelCallRequest:
    model_request_id: str
    tenant_id: str
    provider_id: str
    model_id: str
    prompt: str
    data_classes: tuple[str, ...]
    prompt_slots_used: tuple[str, ...]
    max_tokens: int
    cost_budget: int
    policy_decision_id: str

    def with_data_classes(self, data_classes: tuple[str, ...]) -> ModelCallRequest:
        return replace(self, data_classes=data_classes)


@dataclass(frozen=True)
class ModelPrivacyEnvelope:
    model_request_id: str
    tenant_id: str
    provider_id: str
    model_id: str
    data_classes: tuple[str, ...]
    pii_minimized: bool
    secrets_removed: bool
    prompt_slots_used: tuple[str, ...]
    allow_training: bool
    provider_retention_class: str
    region_policy: str | None
    max_tokens: int
    cost_budget: int
    policy_decision_id: str


def redact_for_model(text: str) -> RedactionResult:
    redacted = text
    removed = False
    for pattern in SECRET_PATTERNS:
        redacted, count = pattern.subn("[REDACTED_SECRET]", redacted)
        removed = removed or count > 0
    return RedactionResult(text=redacted, secrets_removed=removed)


def contains_secret_shape(text: str) -> bool:
    return any(pattern.search(text) is not None for pattern in SECRET_PATTERNS)


def build_model_privacy_envelope(
    request: ModelCallRequest,
    provider: ProviderCapability,
) -> ModelPrivacyEnvelope:
    blocked_classes = {"Secret", "Regulated", "SecurityEvidence"}
    found_blocked = tuple(item for item in request.data_classes if item in blocked_classes)
    if found_blocked:
        raise PermissionError(
            "model call blocked for data class: " + ",".join(found_blocked)
        )

    redacted = redact_for_model(request.prompt)
    if contains_secret_shape(redacted.text):
        raise PermissionError("model call blocked because secrets remain after redaction")

    return ModelPrivacyEnvelope(
        model_request_id=request.model_request_id,
        tenant_id=request.tenant_id,
        provider_id=provider.provider_id,
        model_id=request.model_id,
        data_classes=request.data_classes,
        pii_minimized=True,
        secrets_removed=True,
        prompt_slots_used=request.prompt_slots_used,
        allow_training=False,
        provider_retention_class=provider.retention_class,
        region_policy=provider.region_policy,
        max_tokens=request.max_tokens,
        cost_budget=request.cost_budget,
        policy_decision_id=request.policy_decision_id,
    )
