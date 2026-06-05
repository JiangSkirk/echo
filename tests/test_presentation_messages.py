"""Presentation-layer Chinese message mapping (js/web/messages.py).

These guard the factory-floor UX: the agent core keeps English status/error
wording (asserted elsewhere), and this layer must turn it into friendly Chinese
without ever leaking a raw English string or Python exception to employees.
"""

from __future__ import annotations

import pytest

from js.web.messages import _GENERIC_ERROR, health_summary, humanize_error


class TestHumanizeError:
    def test_empty_returns_generic_chinese(self) -> None:
        assert humanize_error(None) == _GENERIC_ERROR
        assert humanize_error("") == _GENERIC_ERROR

    def test_cancellation_is_chinese(self) -> None:
        # The exact core string asserted by test_cancel_checkpoint.py.
        out = humanize_error("Run cancelled by user request")
        assert out == "已取消本次请求。"

    def test_empty_response_after_retries(self) -> None:
        out = humanize_error("Model returned empty response after maximum retries")
        assert "重试" in out
        assert out != _GENERIC_ERROR

    @pytest.mark.parametrize(
        "raw,needle",
        [
            ("HTTP 429 Too Many Requests", "频繁"),
            ("Rate limit exceeded for model", "频繁"),
            ("401 Unauthorized: invalid api key", "认证"),
            ("Connection refused by upstream", "网络"),
            ("Request timed out after 30s", "网络"),
            ("All providers unhealthy", "模型"),
        ],
    )
    def test_keyword_buckets_map_to_chinese(self, raw: str, needle: str) -> None:
        out = humanize_error(raw)
        assert needle in out
        assert out != _GENERIC_ERROR

    def test_unknown_falls_back_to_generic(self) -> None:
        # An unrecognised exception string must NOT leak through verbatim.
        raw = "KeyError: 'frobnicator'"
        out = humanize_error(raw)
        assert out == _GENERIC_ERROR
        assert raw not in out

    def test_never_returns_english_for_known_buckets(self) -> None:
        for raw in (
            "Run cancelled by user request",
            "Model returned empty response after maximum retries",
            "All providers unhealthy",
        ):
            out = humanize_error(raw)
            # Crude ASCII-letter check: a Chinese message has no long English run.
            assert not any(ch.isascii() and ch.isalpha() for ch in out)


class TestHealthSummary:
    def test_no_provider_takes_priority_even_when_degraded(self) -> None:
        # No models configured → "no_provider", regardless of degraded flag.
        s = health_summary(degraded=True, providers_configured=False)
        assert s["overall_status"] == "no_provider"
        assert "模型" in s["overall_status_text"]
        assert s["suggestion"]

    def test_degraded_when_configured_but_unhealthy(self) -> None:
        s = health_summary(degraded=True, providers_configured=True)
        assert s["overall_status"] == "degraded"
        assert s["suggestion"]

    def test_ok_when_healthy(self) -> None:
        s = health_summary(degraded=False, providers_configured=True)
        assert s["overall_status"] == "ok"
        assert s["overall_status_text"] == "运行正常"
        assert s["suggestion"] == ""

    def test_keys_are_stable(self) -> None:
        s = health_summary(degraded=False, providers_configured=True)
        assert set(s) == {"overall_status", "overall_status_text", "suggestion"}
