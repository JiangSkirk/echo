"""Contract for the shared local Host launcher."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from js.web.local_host import run_local_host


def test_run_local_host_serves_app_without_opening_a_browser() -> None:
    app = object()
    console = MagicMock()
    with patch("uvicorn.run") as run, patch("rich.console.Console", return_value=console):
        run_local_host(app, host="127.0.0.1", port=8765, title="Test Host", notes=("n1",))
    run.assert_called_once_with(app, host="127.0.0.1", port=8765, reload=False)
    printed = " ".join(str(call) for call in console.print.call_args_list)
    assert "Test Host" in printed
    assert "http://127.0.0.1:8765" in printed


def test_otel_stays_off_unless_explicitly_enabled(monkeypatch) -> None:
    from js.web.server import _otel_enabled

    monkeypatch.delenv("JS_ENABLE_OTEL", raising=False)
    assert _otel_enabled() is False
    monkeypatch.setenv("JS_ENABLE_OTEL", "true")
    assert _otel_enabled() is True
