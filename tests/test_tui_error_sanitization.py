from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from js.tui.app import JSTuiApp


@pytest.mark.anyio
async def test_tui_chat_error_does_not_echo_private_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_detail = "/Users/private/Documents/customer.xlsx secret-token"
    app = JSTuiApp(settings=MagicMock())
    app.agent = MagicMock()
    chat_log = MagicMock()
    input_widget = SimpleNamespace(value="hello")

    def query(selector: str, _widget_type: object) -> object:
        if selector == "#chat-input":
            return input_widget
        if selector == "#chat-log":
            return chat_log
        raise AssertionError(selector)

    async def fail_stream(_message: str):
        if False:
            yield ""
        raise RuntimeError(private_detail)

    monkeypatch.setattr(app, "query_one", query)
    monkeypatch.setattr(app, "_stream_response", fail_stream)
    monkeypatch.setattr(app, "_update_status", lambda: None)

    await app.on_input_submitted(SimpleNamespace(value="hello"))

    chat_log.add_assistant.assert_called_once_with("❌ 处理失败，请重试。")
    assert private_detail not in str(chat_log.mock_calls)


@pytest.mark.anyio
async def test_tui_initialization_error_does_not_echo_private_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_detail = "/Users/private/.config/provider-key secret-token"
    app = JSTuiApp(settings=MagicMock())
    chat_log = MagicMock()
    monkeypatch.setattr(app, "query_one", lambda *_args, **_kwargs: chat_log)

    with patch("js.tui.app.JSAgent", side_effect=RuntimeError(private_detail)):
        await app.on_mount()

    assert chat_log.add_system.call_args_list[-1].args == ("❌ Agent 初始化失败，请检查本地配置。",)
    assert private_detail not in str(chat_log.mock_calls)
