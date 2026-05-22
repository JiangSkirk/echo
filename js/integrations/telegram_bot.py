"""Telegram Bot integration for JS Agent.

Allows users to interact with the agent via Telegram messages.
Supports text messages, file uploads, and inline commands.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any

from js.agent import JSAgent
from js.config import JSSettings
from js.utils.log import get_logger

logger = get_logger("js.integrations.telegram")


class TelegramBotIntegration:
    """Wraps JSAgent inside a python-telegram-bot application."""

    def __init__(self, token: str, settings: JSSettings) -> None:
        self.token = token
        self.settings = settings
        self.agent = JSAgent(settings)
        self._session_map: dict[int, str] = {}  # chat_id -> session_id

    async def start(self) -> None:
        """Start the Telegram bot and block until stopped."""
        try:
            from telegram.ext import (
                Application,
                CommandHandler,
                MessageHandler,
                filters,
            )
        except ImportError as e:
            raise RuntimeError(
                "python-telegram-bot not installed. Run: pip install python-telegram-bot"
            ) from e

        app = Application.builder().token(self.token).build()
        app.add_handler(CommandHandler("start", self._cmd_start))
        app.add_handler(CommandHandler("help", self._cmd_help))
        app.add_handler(CommandHandler("reset", self._cmd_reset))
        app.add_handler(CommandHandler("status", self._cmd_status))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self._on_text))
        app.add_handler(MessageHandler(filters.Document.ALL, self._on_document))

        logger.info("Telegram bot starting...")
        await app.initialize()
        await app.start()
        await app.updater.start_polling(drop_pending_updates=True)  # type: ignore[union-attr]
        logger.info("Telegram bot is running. Press Ctrl+C to stop.")

        # Block until SIGINT/SIGTERM
        stop_event = asyncio.Event()

        def _signal_handler() -> None:
            stop_event.set()

        try:
            for sig in (2, 15):  # SIGINT, SIGTERM
                asyncio.get_running_loop().add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            pass  # Windows

        await stop_event.wait()

        logger.info("Telegram bot shutting down...")
        await app.updater.stop()  # type: ignore[union-attr]
        await app.stop()
        await app.shutdown()
        await self.agent.close()

    async def _cmd_start(self, update: Any, _context: Any) -> None:
        chat_id = update.effective_chat.id
        self._session_map.pop(chat_id, None)
        await update.message.reply_text(
            "🤖 JS Agent ready!\n\n"
            "Send me any message and I'll help you.\n"
            "/status — show agent status\n"
            "/reset — clear conversation history\n"
            "/help — show this message"
        )

    async def _cmd_help(self, update: Any, _context: Any) -> None:
        await update.message.reply_text(
            "*JS Agent Telegram Commands*\n"
            "/start — start a new session\n"
            "/reset — clear current session\n"
            "/status — show system status\n"
            "/help — show this message\n\n"
            "You can also send text messages and documents.",
            parse_mode="Markdown",
        )

    async def _cmd_reset(self, update: Any, _context: Any) -> None:
        chat_id = update.effective_chat.id
        self._session_map.pop(chat_id, None)
        await update.message.reply_text("✅ Session cleared. Starting fresh!")

    async def _cmd_status(self, update: Any, _context: Any) -> None:
        status = {
            "models": len(self.agent.settings.providers),
            "tools": len(self.agent.registry._tools) if hasattr(self.agent.registry, "_tools") else 0,
            "memory_sessions": "active",
        }
        text = (
            f"*JS Agent Status*\n"
            f"Models: {status['models']}\n"
            f"Tools: {status['tools']}\n"
            f"Memory: {status['memory_sessions']}"
        )
        await update.message.reply_text(text, parse_mode="Markdown")

    async def _on_text(self, update: Any, _context: Any) -> None:
        chat_id = update.effective_chat.id
        user_text = update.message.text or ""

        session_id = self._session_map.get(chat_id)

        # Send "typing" indicator
        await update.message.chat.send_action(action="typing")

        try:
            state = await self.agent.run(
                user_text,
                session_id=session_id,
            )
            self._session_map[chat_id] = state.session_id

            # Extract assistant message
            assistant_msg = ""
            for msg in reversed(state.messages):
                if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                    assistant_msg = msg.content
                    break

            # Telegram message limit is 4096 chars
            if len(assistant_msg) > 4000:
                assistant_msg = assistant_msg[:4000] + "\n... [message truncated]"

            await update.message.reply_text(assistant_msg or "Done.")
        except Exception as e:
            logger.error(f"Telegram message handling failed: {e}", exc_info=True)
            await update.message.reply_text(f"❌ Error: {e}")

    async def _on_document(self, update: Any, _context: Any) -> None:
        chat_id = update.effective_chat.id
        doc = update.message.document

        # Download file to temp dir
        try:
            file_obj = await doc.get_file()
            with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{doc.file_name}") as tmp:
                await file_obj.download_to_drive(tmp.name)
                tmp_path = tmp.name

            session_id = self._session_map.get(chat_id)
            prompt = f"User uploaded a file: {doc.file_name}\nPlease analyze or process it as appropriate."
            state = await self.agent.run(
                prompt,
                session_id=session_id,
                attachments=[tmp_path],
            )
            self._session_map[chat_id] = state.session_id

            assistant_msg = ""
            for msg in reversed(state.messages):
                if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                    assistant_msg = msg.content
                    break

            await update.message.reply_text(assistant_msg or "File processed.")

            # Cleanup
            Path(tmp_path).unlink(missing_ok=True)
        except Exception as e:
            logger.error(f"Telegram document handling failed: {e}", exc_info=True)
            await update.message.reply_text(f"❌ Error processing file: {e}")
