"""P3-3 speculative-decoding config is optional and ignored by the router."""

from __future__ import annotations

from pathlib import Path

from js.config import JSSettings, ModelConfig, ModelProviderConfig
from js.models.router import ModelRouter


def test_draft_model_defaults_off() -> None:
    settings = JSSettings()
    assert all(getattr(provider, "draft_model", None) is None for provider in settings.providers)
    model = ModelConfig(id="llama3.2", name="Local", draft_model="llama3.2:1b")
    assert model.draft_model == "llama3.2:1b"
    unset = ModelConfig(id="llama3.2", name="Local")
    assert unset.draft_model is None
    provider = ModelProviderConfig(
        name="ollama",
        base_url="http://127.0.0.1:11434/v1",
        draft_model="llama3.2:1b",
    )
    assert provider.draft_model == "llama3.2:1b"
    lmstudio = ModelProviderConfig(
        name="lmstudio",
        base_url="http://127.0.0.1:1234/v1",
    )
    assert lmstudio.draft_model is None


def test_example_yaml_and_docs_exist() -> None:
    root = Path("docs/models")
    assert (root / "speculative-decoding.md").read_text(encoding="utf-8").count("draft_model") >= 2
    example = (root / "draft-model.example.yaml").read_text(encoding="utf-8")
    assert "127.0.0.1:11434" in example
    assert "127.0.0.1:1234" in example
    assert "draft_model: null" in example


def test_router_select_model_does_not_read_draft_model() -> None:
    source = Path("js/models/router.py").read_text(encoding="utf-8")
    assert "draft_model" not in source
    assert hasattr(ModelRouter.select_model, "__code__")
