"""Textual TUI application for JS Agent."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Footer, Header, Input

from js.agent import JSAgent
from js.config import JSSettings
from js.echo.turn_runtime import run_echo_turn
from js.tui.widgets.chat_log import ChatLog
from js.tui.widgets.sidebar import Sidebar
from js.tui.widgets.status_bar import StatusBar
from js.tui.widgets.tool_panel import ToolPanel
from js.utils.log import get_logger

logger = get_logger("js.tui")


class JSTuiApp(App[None]):
    """Main Textual application for JS Agent."""

    CSS = """
    Screen {
        layout: vertical;
    }
    #main {
        layout: horizontal;
        height: 1fr;
    }
    #sidebar {
        width: 24;
        dock: left;
    }
    #chat-container {
        width: 2fr;
        height: 1fr;
    }
    #right-panel {
        width: 1fr;
        height: 1fr;
    }
    #chat-log {
        height: 1fr;
        border: solid $primary;
    }
    #tool-panel {
        height: 1fr;
        border: solid $success;
    }
    #input-area {
        height: 3;
        border-top: solid $primary-darken-2;
    }
    Input {
        width: 1fr;
    }
    """

    BINDINGS = [
        Binding("ctrl+c", "quit", "退出", show=True),
        Binding("ctrl+n", "new_session", "新会话", show=True),
        Binding("ctrl+s", "toggle_sidebar", "侧边栏", show=True),
        Binding("ctrl+t", "toggle_tools", "工具面板", show=True),
        Binding("slash", "focus_input", "输入", show=False),
        Binding("up", "history_up", "上一条", show=False),
        Binding("down", "history_down", "下一条", show=False),
    ]

    agent: JSAgent | None = None
    settings: JSSettings | None = None
    current_session = reactive("default")
    is_thinking = reactive(False)

    def __init__(self, settings: JSSettings | None = None) -> None:
        super().__init__()
        self.settings = settings if settings is not None else JSSettings.from_file()
        self._history: list[str] = []
        self._history_index = 0
        self._pending_input = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main"):
            yield Sidebar(id="sidebar")
            with Vertical(id="chat-container"):
                yield ChatLog(id="chat-log")
                with Horizontal(id="input-area"):
                    yield Input(placeholder="输入消息... (Ctrl+Enter 发送, /help 查看命令)", id="chat-input")
            yield ToolPanel(id="tool-panel")
        yield StatusBar(id="status-bar")
        yield Footer()

    async def on_mount(self) -> None:
        """Initialize agent on app start."""
        self.title = "JS Agent"
        self.sub_title = "终端版"
        chat_log = self.query_one("#chat-log", ChatLog)
        chat_log.add_system("🚀 JS Agent TUI 已启动")
        chat_log.add_system("正在初始化 Agent...")
        assert self.settings is not None
        try:
            self.agent = JSAgent(self.settings)
            self.agent.start_background_tasks()
            chat_log.add_system("✅ Agent 就绪。输入 /help 查看可用命令。")
        except Exception as exc:
            chat_log.add_system("❌ Agent 初始化失败，请检查本地配置。")
            logger.error("TUI agent init failed: %s", type(exc).__name__)

    async def on_unmount(self) -> None:
        """Stop maintenance tasks and flush Agent state before the TUI exits."""
        agent, self.agent = self.agent, None
        if agent is not None:
            await agent.close()

    # ------------------------------------------------------------------
    # Input handling
    # ------------------------------------------------------------------

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle user message submission."""
        if not event.value.strip():
            return
        text = event.value.strip()
        input_widget = self.query_one("#chat-input", Input)
        input_widget.value = ""
        self._history.append(text)
        self._history_index = len(self._history)

        chat_log = self.query_one("#chat-log", ChatLog)
        chat_log.add_user(text)

        # Slash commands
        if text.startswith("/"):
            await self._handle_slash_command(text)
            return

        # Normal chat
        if self.agent is None:
            chat_log.add_assistant("❌ Agent 未初始化，无法处理消息。")
            return

        self.is_thinking = True
        self._update_status()
        try:
            async for chunk in self._stream_response(text):
                chat_log.append_to_last(chunk)
        except Exception as exc:
            chat_log.add_assistant("❌ 处理失败，请重试。")
            logger.error("TUI chat error: %s", type(exc).__name__)
        finally:
            self.is_thinking = False
            self._update_status()

    async def _stream_response(self, message: str) -> Any:
        """Stream agent response token-by-token via Echo runtime callbacks."""
        if self.agent is None:
            return
        assert self.agent is not None

        token_queue: asyncio.Queue[str | None] = asyncio.Queue()
        saw_token = False

        async def _on_token(token: str) -> None:
            nonlocal saw_token
            if not token:
                return
            saw_token = True
            await token_queue.put(token)

        async def _run_turn() -> Any:
            try:
                return await run_echo_turn(
                    self.agent,
                    message,
                    channel="tui",
                    owner_key_hash="js-tui-local",
                    session_id=self.current_session,
                    stream_callback=_on_token,
                )
            finally:
                await token_queue.put(None)

        task = asyncio.create_task(_run_turn())
        try:
            while True:
                item = await token_queue.get()
                if item is None:
                    break
                yield item

            state = await task
            if state is not None and getattr(state, "session_id", None):
                self.current_session = state.session_id

            # Provider produced no stream tokens — fall back once to final text.
            if not saw_token and state is not None:
                response_text = ""
                for msg in reversed(getattr(state, "messages", []) or []):
                    if (
                        getattr(msg, "role", None) == "assistant"
                        and isinstance(msg.content, str)
                        and msg.content
                    ):
                        response_text = msg.content
                        break
                if response_text:
                    yield response_text
        except BaseException:
            if not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
            raise

    async def _handle_slash_command(self, text: str) -> None:
        """Process slash commands."""
        chat_log = self.query_one("#chat-log", ChatLog)
        parts = text.split(None, 1)
        cmd = parts[0].lower()

        handlers: dict[str, Callable[[], Any]] = {
            "/help": lambda: chat_log.add_assistant(self._help_text()),
            "/new": self.action_new_session,
            "/clear": lambda: [c.remove() for c in list(chat_log.children)],
            "/model": lambda: chat_log.add_assistant(f"当前模型: {getattr(self.settings, 'model', 'default')}"),
            "/status": self._cmd_status,
            "/tools": self._cmd_tools,
            "/memory": self._cmd_memory,
            "/compress": self._cmd_compress,
        }

        handler = handlers.get(cmd)
        if handler:
            await handler() if asyncio.iscoroutinefunction(handler) else handler()
        else:
            chat_log.add_assistant(f"未知命令: {cmd}。输入 /help 查看可用命令。")

    def _help_text(self) -> str:
        return (
            "📖 可用命令:\n"
            "  /new      — 新建会话\n"
            "  /clear    — 清空聊天记录\n"
            "  /model    — 查看当前模型\n"
            "  /status   — 查看系统状态\n"
            "  /tools    — 查看可用工具\n"
            "  /memory   — 查看记忆统计\n"
            "  /compress — 手动触发上下文压缩\n"
            "  /help     — 显示此帮助\n"
            "\n快捷键: Ctrl+N 新会话 | Ctrl+T 切换工具面板 | Ctrl+C 退出"
        )

    async def _cmd_status(self) -> None:
        chat_log = self.query_one("#chat-log", ChatLog)
        if self.agent is None:
            chat_log.add_assistant("Agent 未初始化")
            return
        lines = [
            "📊 系统状态:",
            f"  模型: {getattr(self.settings, 'model', 'N/A')}",
            f"  提供商: {len(self.settings.providers) if self.settings else 0}",
        ]
        chat_log.add_assistant("\n".join(lines))

    async def _cmd_tools(self) -> None:
        chat_log = self.query_one("#chat-log", ChatLog)
        chat_log.add_assistant("🔧 工具列表功能正在开发中...")

    async def _cmd_memory(self) -> None:
        chat_log = self.query_one("#chat-log", ChatLog)
        chat_log.add_assistant("🧠 记忆统计功能正在开发中...")

    async def _cmd_compress(self) -> None:
        chat_log = self.query_one("#chat-log", ChatLog)
        chat_log.add_assistant("🗜️ 上下文压缩已触发")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_new_session(self) -> None:
        import uuid
        self.current_session = f"session_{uuid.uuid4().hex[:8]}"
        chat_log = self.query_one("#chat-log", ChatLog)
        for c in list(chat_log.children):
            c.remove()
        chat_log.add_system("🆕 新会话已开始")

    def action_toggle_sidebar(self) -> None:
        sidebar = self.query_one("#sidebar", Sidebar)
        sidebar.toggle_class("-hidden")

    def action_toggle_tools(self) -> None:
        tool_panel = self.query_one("#tool-panel", ToolPanel)
        tool_panel.toggle_class("-hidden")

    def action_focus_input(self) -> None:
        self.query_one("#chat-input", Input).focus()

    def action_history_up(self) -> None:
        if self._history and self._history_index > 0:
            if self._history_index == len(self._history):
                self._pending_input = self.query_one("#chat-input", Input).value
            self._history_index -= 1
            self.query_one("#chat-input", Input).value = self._history[self._history_index]

    def action_history_down(self) -> None:
        if self._history and self._history_index < len(self._history) - 1:
            self._history_index += 1
            self.query_one("#chat-input", Input).value = self._history[self._history_index]
        elif self._history_index == len(self._history) - 1:
            self._history_index = len(self._history)
            self.query_one("#chat-input", Input).value = self._pending_input

    def _update_status(self) -> None:
        status = self.query_one("#status-bar", StatusBar)
        status.is_thinking = self.is_thinking
        status.session = self.current_session
