"""Status bar widget for TUI."""

from __future__ import annotations

from textual.reactive import reactive
from textual.widgets import Static


class StatusBar(Static):
    """Bottom status bar showing agent state."""

    DEFAULT_CSS = """
    StatusBar {
        height: 1;
        background: $primary-darken-2;
        color: $text;
        content-align: center middle;
    }
    """

    is_thinking: reactive[bool] = reactive(False)
    session: reactive[str] = reactive("default")

    def render(self) -> str:
        thinking = "⏳ 思考中..." if self.is_thinking else "✅ 就绪"
        return f" {thinking} | 会话: {self.session[:16]} | Ctrl+H 帮助 "
