"""F-01: runtime id validation and DOM-safe UI binding."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from js.config import ModelConfig, ModelProviderConfig
from js.web.ids import InvalidRuntimeIdError, validate_model_ref, validate_runtime_id


@pytest.mark.parametrize(
    "value",
    [
        "gpt-4o",
        "claude-3-5-sonnet",
        "qwen2.5:14b",
        "openai/gpt-4o-mini",
        "local/llama3.2:latest",
    ],
)
def test_accepts_common_model_ids(value: str) -> None:
    assert validate_model_ref(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "');window.__xss=1;//",
        'x" onclick="alert(1)',
        "a<script>alert(1)</script>",
        "id\nwith\nnewline",
        "id\x00null",
        "a" * 200,
        "../../../etc/passwd",
        "",
        "bad id with spaces",
        "`tick`",
    ],
)
def test_rejects_malicious_or_invalid_ids(value: str) -> None:
    with pytest.raises(InvalidRuntimeIdError):
        validate_runtime_id(value)


def test_model_config_rejects_bad_id() -> None:
    with pytest.raises(ValidationError):
        ModelConfig(id="bad'id", name="x", provider="p")


def test_provider_config_rejects_bad_name() -> None:
    with pytest.raises(ValidationError):
        ModelProviderConfig(name="bad name!", base_url="http://127.0.0.1:1")


def test_static_sources_avoid_inline_handlers_for_dynamic_ids() -> None:
    """Regression guard: dynamic IDs must not be spliced into onclick/onchange."""
    roots = [
        Path("js/web/static/app.js"),
        Path("js/web/static/tabs/models.js"),
    ]
    forbidden = (
        "onchange=\"wizardSelectModel('${escapeHtml",
        "onclick=\"testWizardModel('${escapeHtml",
        "onclick=\"switchModel('${escapeHtml",
        "onclick=\"loadFleetSessionToChat('${escapeHtml",
        "onclick=\"deleteFleetSession('${escapeHtml",
        'onclick="switchModel(${JSON.stringify',
        "onclick='updateProviderKey(${JSON.stringify",
        "onclick='deleteProvider(${JSON.stringify",
    )
    for path in roots:
        text = path.read_text(encoding="utf-8")
        for needle in forbidden:
            assert needle not in text, f"{path} still contains {needle!r}"
