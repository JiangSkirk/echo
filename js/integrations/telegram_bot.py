"""Telegram Bot integration for JS Agent.

Allows users to interact with the agent via Telegram messages.
Supports text messages, file uploads, and inline commands.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import signal
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from js.agent import JSAgent
from js.agent.tool_executor import CONTROL_UPLOAD_MUTATE_TOOL
from js.config import JSSettings
from js.echo.attachment_gate import (
    SecureUploadWriter,
    safe_upload_filename,
    validate_agent_attachment_path,
)
from js.echo.effect_interpreter import ToolEffect
from js.echo.turn_runtime import run_echo_turn
from js.utils.log import get_logger

logger = get_logger("js.integrations.telegram")

_MAX_TELEGRAM_SESSIONS = 2_048
_TELEGRAM_SESSION_TTL_SECONDS = 24 * 60 * 60
# Comma-separated list of Telegram chat IDs allowed to drive the agent.
# Fail-closed: the bot refuses to start when this is unset or empty.
TELEGRAM_ALLOWED_CHATS_ENV = "JS_TELEGRAM_ALLOWED_CHATS"


class TelegramBotIntegration:
    """Wraps JSAgent inside a python-telegram-bot application."""

    def __init__(self, token: str, settings: JSSettings) -> None:
        # Validate the allowlist BEFORE constructing the agent: without an
        # explicit allowlist any Telegram user could drive the agent, so the
        # bot must refuse to start (fail-closed).
        self.allowed_chat_ids = self._load_allowed_chat_ids()
        if not self.allowed_chat_ids:
            raise RuntimeError(
                "Telegram bot refuses to start without a chat allowlist. "
                f"Set {TELEGRAM_ALLOWED_CHATS_ENV} to a comma-separated list "
                "of allowed chat IDs."
            )
        self.token = token
        self.settings = settings
        self.agent = JSAgent(settings)
        self._session_map: OrderedDict[int, tuple[str, float]] = OrderedDict()

    @staticmethod
    def _load_allowed_chat_ids() -> frozenset[int]:
        """Parse the chat allowlist from JS_TELEGRAM_ALLOWED_CHATS."""
        raw = os.environ.get(TELEGRAM_ALLOWED_CHATS_ENV, "")
        chat_ids: set[int] = set()
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                chat_ids.add(int(part))
            except ValueError as exc:
                raise ValueError(
                    f"{TELEGRAM_ALLOWED_CHATS_ENV} contains a non-numeric "
                    f"chat ID: {part!r}"
                ) from exc
        return frozenset(chat_ids)

    def _is_chat_allowed(self, chat_id: int) -> bool:
        """Fail-closed allowlist check; logs rejected chats as security events."""
        allowed = getattr(self, "allowed_chat_ids", None)
        if not allowed:
            logger.warning(
                "Security: Telegram chat_id=%s rejected — no allowlist configured",
                chat_id,
            )
            return False
        if chat_id not in allowed:
            logger.warning(
                "Security: ignoring Telegram message from non-allowlisted chat_id=%s",
                chat_id,
            )
            return False
        return True

    def _get_session(self, chat_id: int) -> str | None:
        entry = self._session_map.get(chat_id)
        if entry is None:
            return None
        session_id, touched_at = entry
        if time.monotonic() - touched_at > _TELEGRAM_SESSION_TTL_SECONDS:
            self._session_map.pop(chat_id, None)
            return None
        self._session_map.move_to_end(chat_id)
        return session_id

    def _set_session(self, chat_id: int, session_id: str) -> None:
        self._session_map[chat_id] = (session_id, time.monotonic())
        self._session_map.move_to_end(chat_id)
        while len(self._session_map) > _MAX_TELEGRAM_SESSIONS:
            self._session_map.popitem(last=False)

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

        stop_event = asyncio.Event()
        registered_signals: list[signal.Signals] = []
        initialized = False
        started = False
        polling = False

        def _signal_handler() -> None:
            stop_event.set()

        self.agent.start_background_tasks()
        try:
            logger.info("Telegram bot starting...")
            await app.initialize()
            initialized = True
            await app.start()
            started = True
            if app.updater is None:
                raise RuntimeError("Telegram updater is unavailable")
            await app.updater.start_polling(drop_pending_updates=True)
            polling = True
            logger.info("Telegram bot is running. Press Ctrl+C to stop.")

            try:
                for sig in (signal.SIGINT, signal.SIGTERM):
                    asyncio.get_running_loop().add_signal_handler(sig, _signal_handler)
                    registered_signals.append(sig)
            except (NotImplementedError, ValueError, RuntimeError):
                pass  # Windows, non-main thread, or already closed loop
            await stop_event.wait()
        finally:
            logger.info("Telegram bot shutting down...")
            try:
                loop = asyncio.get_running_loop()
                for sig in registered_signals:
                    loop.remove_signal_handler(sig)
            except (NotImplementedError, RuntimeError, ValueError):
                pass
            if polling and app.updater is not None:
                try:
                    await app.updater.stop()
                except Exception:
                    logger.warning("Telegram updater shutdown failed", exc_info=True)
            if started:
                try:
                    await app.stop()
                except Exception:
                    logger.warning("Telegram application stop failed", exc_info=True)
            if initialized:
                try:
                    await app.shutdown()
                except Exception:
                    logger.warning("Telegram application shutdown failed", exc_info=True)
            await self.agent.close()

    async def _cmd_start(self, update: Any, _context: Any) -> None:
        chat_id = update.effective_chat.id
        if not self._is_chat_allowed(chat_id):
            return
        self._session_map.pop(chat_id, None)
        await update.message.reply_text(
            "🤖 JS Agent ready!\n\n"
            "Send me any message and I'll help you.\n"
            "/status — show agent status\n"
            "/reset — clear conversation history\n"
            "/help — show this message"
        )

    async def _cmd_help(self, update: Any, _context: Any) -> None:
        if not self._is_chat_allowed(update.effective_chat.id):
            return
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
        if not self._is_chat_allowed(chat_id):
            return
        self._session_map.pop(chat_id, None)
        await update.message.reply_text("✅ Session cleared. Starting fresh!")

    async def _cmd_status(self, update: Any, _context: Any) -> None:
        if not self._is_chat_allowed(update.effective_chat.id):
            return
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
        if not self._is_chat_allowed(chat_id):
            return
        user_text = update.message.text or ""
        owner = f"telegram:{chat_id}"
        session_id = self._get_session(chat_id)

        # Send "typing" indicator
        await update.message.chat.send_action(action="typing")

        try:
            state = await run_echo_turn(
                self.agent,
                user_text,
                channel="telegram",
                owner_key_hash=owner,
                session_id=session_id,
            )
            self._set_session(chat_id, state.session_id)

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
        except Exception as exc:
            logger.error(
                "Telegram message handling failed: %s",
                type(exc).__name__,
            )
            await update.message.reply_text("❌ Error processing message.")

    async def _on_document(self, update: Any, _context: Any) -> None:
        chat_id = update.effective_chat.id
        if not self._is_chat_allowed(chat_id):
            return
        doc = update.message.document
        owner = f"telegram:{chat_id}"
        session_id = self._get_session(chat_id) or f"telegram-{secrets.token_hex(16)}"
        self._set_session(chat_id, session_id)
        upload_path: Path | None = None

        try:
            max_size = 100 * 1024 * 1024
            if getattr(doc, "file_size", None) is not None and doc.file_size > max_size:
                raise ValueError("File too large (max 100MB)")
            file_obj = await doc.get_file()
            safe_name = safe_upload_filename(doc.file_name)
            with SecureUploadWriter(
                self.settings.workspace,
                owner,
                session_id,
                safe_name,
                max_bytes=max_size,
            ) as writer:
                await file_obj.download_to_memory(out=writer)
                payload_ref = self.agent.stage_upload_commit(
                    owner,
                    session_id,
                    writer,
                )
                if not payload_ref:
                    raise RuntimeError("Upload admission is unavailable")
                try:
                    result = await self._execute_upload_effect(
                        action="commit",
                        payload_ref=payload_ref,
                        owner=owner,
                        session_id=session_id,
                    )
                finally:
                    self.agent.discard_upload_commit(
                        payload_ref,
                        owner,
                        session_id=session_id,
                    )
                if not result.success:
                    raise RuntimeError(result.error or "Upload commit failed")
                result_ref = result.metadata.get("result_ref")
                if not isinstance(result_ref, str) or not result_ref:
                    raise RuntimeError("Upload result handoff failed")
                upload_result = self.agent.take_upload_mutation_result(
                    result_ref,
                    owner,
                    product_id=str(getattr(self.settings, "product_id", "js-agent")),
                    session_id=session_id,
                )
                if not isinstance(upload_result, dict):
                    raise RuntimeError("Upload result handoff failed")
                relative_path = upload_result.get("path")
                if not isinstance(relative_path, str) or not relative_path:
                    raise RuntimeError("Upload result handoff failed")
                upload_path = validate_agent_attachment_path(
                    workspace=self.settings.workspace,
                    path=relative_path,
                    owner_key_hash=owner,
                    session_id=session_id,
                )

            prompt = (
                f"User uploaded a file named {safe_name!r}.\n"
                "Please analyze or process it as appropriate."
            )
            state = await run_echo_turn(
                self.agent,
                prompt,
                channel="telegram",
                owner_key_hash=owner,
                session_id=session_id,
                attachments=[upload_path.relative_to(self.settings.workspace).as_posix()],
            )
            self._set_session(chat_id, state.session_id)

            assistant_msg = ""
            for msg in reversed(state.messages):
                if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                    assistant_msg = msg.content
                    break

            await update.message.reply_text(assistant_msg or "File processed.")
        except Exception as exc:
            logger.error(
                "Telegram document handling failed: %s",
                type(exc).__name__,
            )
            await update.message.reply_text("❌ Error processing file.")
        finally:
            if upload_path is not None:
                await self._delete_uploaded_document(
                    owner=owner,
                    session_id=session_id,
                    filename=upload_path.name,
                )

    async def _execute_upload_effect(
        self,
        *,
        action: str,
        payload_ref: str,
        owner: str,
        session_id: str,
    ) -> Any:
        runtime = self.agent.echo_runtime
        context = runtime.build_context(
            channel=f"telegram_upload_{action}",
            owner_key_hash=owner,
            session_id=session_id,
            role="user",
            capabilities=(CONTROL_UPLOAD_MUTATE_TOOL,),
        )
        _message, result = await runtime.execute_tool_effect(
            ToolEffect.from_arguments(
                CONTROL_UPLOAD_MUTATE_TOOL,
                {"action": action, "payload_ref": payload_ref},
                user_input=f"Apply owner-bound Telegram upload action: {action}",
                allowed_tools=(CONTROL_UPLOAD_MUTATE_TOOL,),
            ),
            context,
        )
        return result

    async def _delete_uploaded_document(
        self,
        *,
        owner: str,
        session_id: str,
        filename: str,
    ) -> None:
        payload_ref = self.agent.stage_upload_mutation_payload(
            owner,
            {"filename": filename, "session_id": session_id},
            product_id=str(getattr(self.settings, "product_id", "js-agent")),
            session_id=session_id,
        )
        if not payload_ref:
            logger.error("Telegram upload cleanup admission failed")
            return
        try:
            result = await self._execute_upload_effect(
                action="delete",
                payload_ref=payload_ref,
                owner=owner,
                session_id=session_id,
            )
        except Exception:
            logger.error("Telegram upload cleanup failed", exc_info=True)
            return
        finally:
            self.agent.discard_upload_mutation_payload(
                payload_ref,
                owner,
                product_id=str(getattr(self.settings, "product_id", "js-agent")),
                session_id=session_id,
            )
        if not result.success and result.metadata.get("status_code") != 404:
            logger.error("Telegram upload cleanup was rejected")
