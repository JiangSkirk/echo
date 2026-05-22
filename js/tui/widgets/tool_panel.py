"""Tool output panel for TUI."""

from __future__ import annotations

from typing import Any

from textual.containers import VerticalScroll
from textual.widgets import Static


class ToolPanel(VerticalScroll):
    """Panel showing tool call outputs and system events."""

    DEFAULT_CSS = """
    ToolPanel {
        background: $surface-darken-1;
        border-left: solid $success;
        padding: 0 1;
    }
    ToolPanel.-hidden {
        display: none;
    }
    ToolPanel > Static {
        margin: 1 0;
    }
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._lines: list[str] = []

    def add_line(self, text: str) -> None:
        self._lines.append(text)
        if len(self._lines) > 100:
            self._lines = self._lines[-100:]
        self.mount(Static(f"[dim]{text}[/dim]"))
        self.scroll_end()

    def clear(self) -> None:
        self._lines.clear()
        for child in list(self.children):
            child.remove()
