from __future__ import annotations

from pathlib import Path

import pytest

from js.config import ModelConfig, ModelProviderConfig
from js.models.provider_manager import ProviderManager, ProviderManagerError


def _provider(name: str, *, api_key: str = "") -> ModelProviderConfig:
    return ModelProviderConfig(
        name=name,
        base_url=f"https://{name}.example/v1",
        api_key=api_key,
        default_model="model-a",
        models=[ModelConfig(id="model-a", name="Model A", provider=name)],
    )


def test_stale_provider_manager_instance_merges_instead_of_losing_updates(
    tmp_path: Path,
) -> None:
    first = ProviderManager(tmp_path / "state")
    stale = ProviderManager(tmp_path / "state")

    first.add(_provider("first"))
    stale.add(_provider("second"))

    reloaded = ProviderManager(tmp_path / "state")
    assert {provider.name for provider in reloaded.get_all()} == {"first", "second"}


def test_provider_save_is_atomic_and_does_not_publish_partial_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = ProviderManager(tmp_path / "state")
    manager.add(_provider("stable"))
    before = (tmp_path / "state" / "providers.json").read_bytes()

    def fail_write(_providers: list[ModelProviderConfig]) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(manager, "_atomic_write_unlocked", fail_write, raising=False)

    with pytest.raises(ProviderManagerError):
        manager.add(_provider("partial"))

    assert (tmp_path / "state" / "providers.json").read_bytes() == before
    assert [provider.name for provider in manager.get_all()] == ["stable"]


def test_provider_api_key_is_encrypted_and_can_be_cleared(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    manager = ProviderManager(state_dir)
    manager.add(_provider("secret-provider", api_key="provider-super-secret"))

    serialized = (state_dir / "providers.json").read_text(encoding="utf-8")
    assert "provider-super-secret" not in serialized
    assert ProviderManager(state_dir).get("secret-provider").api_key == (
        "provider-super-secret"
    )

    assert manager.update_api_key("secret-provider", "") is True
    assert ProviderManager(state_dir).get("secret-provider").api_key in {None, ""}
