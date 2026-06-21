"""Sidebar widget for TUI."""

from __future__ import annotations

from typing import Any

from textual.widgets import Static

from js import __version__


class Sidebar(Static):
    """Navigation sidebar showing sessions and shortcuts."""

    DEFAULT_CSS = """
    Sidebar {
        width: 24;
        background: $surface-darken-1;
        border-right: solid $primary-darken-2;
        padding: 1;
    }
    Sidebar.-hidden {
        display: none;
    }
    """

    def compose(self) -> Any:
        yield Static("[bold]JS Agent[/bold]", id="sidebar-title")
        yield Static("[dim]终端版[/dim]", id="sidebar-subtitle")
        yield Static("")
        yield Static("[bold]快捷操作[/bold]")
        yield Static("• Ctrl+N 新会话")
        yield Static("• Ctrl+T 工具面板")
        yield Static("• Ctrl+C 退出")
        yield Static("")
        yield Static("[bold]命令[/bold]")
        yield Static("• /help  帮助")
        yield Static("• /new   新会话")
        yield Static("• /clear 清空")
        yield Static("• /status 状态")
        yield Static("")
        yield Static(f"[dim]v{__version__}[/dim]")
