"""Tests for the v0.1.6 model capability / probing layer (``js/models/capability.py``).

These tests exercise:

* API key redaction edge cases (None, empty, short, long).
* Capability inference from model ids (vision / thinking / reasoner-no-tools / embedding).
* ``probe_provider`` happy path for OpenAI-compatible /models (with context window
  pulled from the API response — ``context_source == "api"``).
* ``probe_provider`` for Anthropic native /v1/models (uses ``x-api-key`` +
  ``anthropic-version`` headers, no context length exposed by the API).
* ``probe_provider`` for Volcano Ark base_url (``/api/v3``) still parsed as
  OpenAI-compatible.
* 401/403 produces an authentication-failed message (NOT the verbatim key).
* Verbatim API keys are never leaked into the error string.
* Empty / no model body is reported as failure with non-empty error.

The HTTP layer is stubbed via a fake ``httpx.AsyncClient`` so no real network
traffic happens. SSRF guard (``resolve_and_validate``) is also stubbed for the
synthetic hostnames used here.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from js.models import capability as cap
from js.models.capability import (
    ProbeResult,
    infer_capabilities_from_id,
    probe_provider,
    redact_api_key,
)

# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestRedactApiKey:
    def test_none_and_empty_return_not_set_marker(self) -> None:
        assert redact_api_key(None) == "<not-set>"
        assert redact_api_key("") == "<not-set>"

    def test_short_key_collapses_to_stars(self) -> None:
        # ≤ 8 characters: no surface area to safely show prefix/suffix.
        assert redact_api_key("abc") == "***"
        assert redact_api_key("12345678") == "***"

    def test_long_key_keeps_only_four_each_side(self) -> None:
        assert redact_api_key("sk-abcd1234EFGH") == "sk-a****EFGH"
        # The verbatim key MUST NOT appear in the redacted form.
        assert "abcd1234" not in redact_api_key("sk-abcd1234EFGH")


class TestInferCapabilitiesFromId:
    def test_reasoner_id_implies_thinking_and_no_tools(self) -> None:
        caps = infer_capabilities_from_id("deepseek-reasoner")
        assert caps.get("supports_thinking") is True
        assert caps.get("supports_tools") is False

    def test_vision_model_id_implies_vision(self) -> None:
        assert infer_capabilities_from_id("claude-sonnet-4-6").get("supports_vision") is True
        assert infer_capabilities_from_id("qwen-vl-max").get("supports_vision") is True

    def test_embedding_model_loses_tools(self) -> None:
        caps = infer_capabilities_from_id("text-embedding-3-small")
        assert caps.get("supports_tools") is False

    def test_unknown_id_returns_empty_dict(self) -> None:
        # An unknown id must NOT pretend to know anything; the caller keeps
        # whatever defaults the ModelConfig has.
        assert infer_capabilities_from_id("totally-bespoke-model-xyz") == {}

    def test_empty_id_is_empty_dict(self) -> None:
        assert infer_capabilities_from_id("") == {}


# ---------------------------------------------------------------------------
# probe_provider — stubbed HTTP layer
# ---------------------------------------------------------------------------


class _StubResponse:
    """Minimal stand-in for ``httpx.Response`` returned by the fake client."""

    def __init__(self, status_code: int, json_body: Any = None, text: str = "") -> None:
        self.status_code = status_code
        self._json = json_body
        self.text = text or (str(json_body) if json_body is not None else "")

    def json(self) -> Any:
        return self._json


class _StubClient:
    """Fake ``httpx.AsyncClient`` capturing the request and returning a fixed reply."""

    captured: dict[str, Any] = {}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # Capture how the real probe constructed the client (transport / timeout).
        type(self).captured["client_kwargs"] = kwargs

    async def __aenter__(self) -> _StubClient:
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        return None

    async def get(self, url: str, headers: dict[str, str] | None = None) -> _StubResponse:
        type(self).captured["url"] = url
        type(self).captured["headers"] = dict(headers or {})
        return type(self).response  # type: ignore[attr-defined]


def _install_stub(
    monkeypatch: pytest.MonkeyPatch,
    *,
    response: _StubResponse,
) -> type[_StubClient]:
    """Wire ``_StubClient`` into ``httpx`` and bypass net_guard for synthetic hosts."""
    klass = type("_StubClientInstance", (_StubClient,), {})
    klass.captured = {}
    klass.response = response  # type: ignore[attr-defined]
    monkeypatch.setattr(httpx, "AsyncClient", klass)
    # net_guard.resolve_and_validate would refuse synthetic hostnames; stub it.
    monkeypatch.setattr(
        "js.security.net_guard.resolve_and_validate",
        lambda *_args, **_kwargs: ["203.0.113.10"],
    )
    # PinnedTransport is referenced but never used by the stub client — make it
    # a no-op constructor so the import path is safe.
    monkeypatch.setattr(
        "js.security.net_guard.PinnedTransport",
        lambda *_a, **_kw: None,
    )
    return klass


@pytest.mark.asyncio
class TestProbeProviderHappyPaths:
    async def test_openai_compatible_returns_models_with_api_context(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        klass = _install_stub(
            monkeypatch,
            response=_StubResponse(
                200,
                {
                    "data": [
                        {
                            "id": "deepseek-v4-flash",
                            "context_length": 1_000_000,
                            "max_output_tokens": 384_000,
                        },
                        {"id": "deepseek-v3.2"},  # no API context → falls back to heuristic
                    ]
                },
            ),
        )

        result = await probe_provider("https://api.deepseek.com/v1", "sk-deepseek-test-key-1234")

        assert result.ok is True
        assert result.status == 200
        assert result.transport == "openai"
        assert {m.id for m in result.models} == {"deepseek-v4-flash", "deepseek-v3.2"}

        flash = next(m for m in result.models if m.id == "deepseek-v4-flash")
        assert flash.context_window == 1_000_000
        assert flash.context_source == "api"  # API explicitly returned it
        assert flash.max_output_tokens == 384_000
        assert flash.probed_at is not None

        v32 = next(m for m in result.models if m.id == "deepseek-v3.2")
        # No API field → heuristic path. Inferred for deepseek-v3.2 is 131_072.
        assert v32.context_source == "heuristic"

        # The request must have used Bearer auth on /models.
        headers = klass.captured["headers"]
        assert headers.get("Authorization") == "Bearer sk-deepseek-test-key-1234"
        assert klass.captured["url"].endswith("/models")

    async def test_volcano_ark_base_url_treated_as_openai(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Volcano Ark uses /api/v3 — not /v1 — but the wire format is the same.
        klass = _install_stub(
            monkeypatch,
            response=_StubResponse(
                200,
                {"data": [{"id": "doubao-1.5-pro-32k", "context_length": 32_000}]},
            ),
        )

        result = await probe_provider(
            "https://ark.cn-beijing.volces.com/api/v3",
            "ark-key-abcdefg12345",
        )

        assert result.ok is True
        assert result.transport == "openai"
        assert result.models[0].context_source == "api"
        assert result.models[0].context_window == 32_000
        # Ark requires Authorization: Bearer.
        assert klass.captured["headers"].get("Authorization", "").startswith("Bearer ")
        assert klass.captured["url"].endswith("/api/v3/models")

    async def test_anthropic_native_uses_xapikey_and_inferred_context(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        klass = _install_stub(
            monkeypatch,
            response=_StubResponse(
                200,
                {
                    "data": [
                        {
                            "type": "model",
                            "id": "claude-sonnet-4-6",
                            "display_name": "Claude Sonnet 4.6",
                        }
                    ]
                },
            ),
        )

        result = await probe_provider(
            "https://api.anthropic.com",
            "sk-ant-test-key-XYZ123",
        )

        assert result.ok is True
        assert result.transport == "anthropic"
        # /v1 must be auto-appended when the caller passes the bare host.
        assert klass.captured["url"].endswith("/v1/models")
        # Anthropic native auth headers — never Authorization: Bearer.
        h = klass.captured["headers"]
        assert h.get("x-api-key") == "sk-ant-test-key-XYZ123"
        assert h.get("anthropic-version") == "2023-06-01"
        assert "Authorization" not in h

        m = result.models[0]
        assert m.id == "claude-sonnet-4-6"
        assert m.name == "Claude Sonnet 4.6"
        # Anthropic /models doesn't expose context window → heuristic path.
        assert m.context_source == "heuristic"
        # ID hints vision support.
        assert m.supports_vision is True


@pytest.mark.asyncio
class TestProbeProviderErrorPaths:
    async def test_401_returns_authentication_failed_and_no_key_in_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = "sk-super-secret-1234567890"
        _install_stub(
            monkeypatch,
            response=_StubResponse(401, text=f"Invalid key: {secret}"),
        )

        result = await probe_provider("https://api.openai.com/v1", secret)

        assert result.ok is False
        assert result.status == 401
        assert "authentication" in result.error.lower()
        # CRITICAL: the verbatim key MUST NOT appear in the error.
        assert secret not in result.error

    async def test_5xx_body_is_scrubbed_of_verbatim_api_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = "sk-leaky-XYZABC987654"
        _install_stub(
            monkeypatch,
            response=_StubResponse(
                503,
                text=f"upstream error echoed {secret} back at us",
            ),
        )

        result = await probe_provider("https://api.openai.com/v1", secret)

        assert result.ok is False
        assert result.status == 503
        assert secret not in result.error
        # The redacted form should be visible — proves the scrubber ran.
        assert redact_api_key(secret) in result.error

    async def test_empty_models_list_is_failure_with_message(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_stub(monkeypatch, response=_StubResponse(200, {"data": []}))

        result = await probe_provider("https://api.openai.com/v1", "sk-empty-test-key")

        assert result.ok is False
        assert result.status == 200
        assert "no models" in result.error.lower()

    async def test_missing_base_url_short_circuits(self) -> None:
        # No HTTP layer is touched in this path.
        result = await probe_provider("", "sk-key")
        assert result.ok is False
        assert result.status == 0
        assert "base_url" in result.error

    async def test_to_dict_does_not_include_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        secret = "sk-confidential-9876543210"
        _install_stub(
            monkeypatch,
            response=_StubResponse(200, {"data": [{"id": "m1"}]}),
        )

        result = await probe_provider("https://api.openai.com/v1", secret)
        serialised = result.to_dict()

        # to_dict is what flows to logs / web responses. It MUST be key-free.
        flat = repr(serialised)
        assert secret not in flat


# ---------------------------------------------------------------------------
# Probe result serialisation sanity check
# ---------------------------------------------------------------------------


def test_probe_result_to_dict_round_trips_model_fields() -> None:
    from js.config import ModelConfig

    r = ProbeResult(
        ok=True,
        status=200,
        latency_ms=12.345,
        models=[
            ModelConfig(
                id="m1",
                name="M1",
                context_window=16_384,
                max_tokens=4096,
                context_source="preset",
            )
        ],
        transport="openai",
        base_url="https://x",
    )
    d = r.to_dict()
    assert d["ok"] is True
    assert d["latency_ms"] == 12.35  # rounded
    assert d["models"][0]["context_source"] == "preset"
    assert d["models"][0]["id"] == "m1"


# ---------------------------------------------------------------------------
# Module symbol surface
# ---------------------------------------------------------------------------


def test_public_exports_present() -> None:
    # Guard against accidental removal of public names that downstream PRs
    # (PR-4.2 / PR-4.5) will rely on.
    for name in ("redact_api_key", "infer_capabilities_from_id", "probe_provider", "ProbeResult"):
        assert hasattr(cap, name), f"capability.{name} disappeared"
