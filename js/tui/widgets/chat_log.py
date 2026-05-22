"""Chat log widget for TUI."""

from __future__ import annotations

from textual.containers import VerticalScroll
from textual.widgets import Static


class ChatLog(VerticalScroll):
    """Scrollable chat message display."""

    DEFAULT_CSS = """
    ChatLog {
        padding: 0 1;
    }
    ChatLog > Static {
        margin: 1 0;
        padding: 0;
    }
    .msg-system {
        color: $text-muted;
        text-style: dim;
    }
    .msg-user {
        color: $text;
        text-style: bold;
    }
    .msg-assistant {
        color: $text;
    }
    .msg-tool {
        color: $success;
        text-style: italic;
    }
    """

    def add_system(self, text: str) -> None:
        self.mount(Static(f"[dim]{text}[/]", classes="msg-system"))
        self.scroll_end()

    def add_user(self, text: str) -> None:
        self.mount(Static(f"[bold]👤 你:[/bold] {text}", classes="msg-user"))
        self.scroll_end()

    def add_assistant(self, text: str) -> None:
        self.mount(Static(f"[bold cyan]🤖 Agent:[/bold cyan] {text}", classes="msg-assistant"))
        self.scroll_end()

    def add_tool(self, text: str) -> None:
        self.mount(Static(f"[italic green]🔧 工具:[/italic green] {text}", classes="msg-tool"))
        self.scroll_end()

    def append_to_last(self, text: str) -> None:
        """Append text to the last message (for streaming)."""
        children = list(self.children)
        if not children:
            self.add_assistant(text)
            return
        last = children[-1]
        if isinstance(last, Static):
            renderable = getattr(last, "renderable", None)
            if renderable is not None:
                current = renderable.plain if hasattr(renderable, "plain") else str(renderable)
                last.update(current + text)
        self.scroll_end()
