"""Prompt + context construction for the agent.

Builds the system message (with multi-layer memory context), vision/multimodal
user content, attachment context, and summary formatting.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Any

from js.agent.base import AgentBase
from js.security.audit import AuditEventType
from js.utils.attachments import extract_excel_text, extract_pdf_text, format_size

if TYPE_CHECKING:
    from js.models.providers import ChatMessage


class PromptBuilderMixin(AgentBase):
    """System prompt, vision content, attachment context, summary formatting."""

    async def _build_attachment_context(self, attachments: list[str]) -> str:
        """Build context text describing uploaded attachments."""
        if not attachments:
            return ""

        parts: list[str] = ["\n\n## 附件文件\n"]
        for path_str in attachments:
            path = self.settings.workspace / path_str
            if not path.exists():
                parts.append(f"- `{path_str}`: (文件不存在)")
                continue

            suffix = path.suffix.lower()
            size = path.stat().st_size

            if suffix in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg"}:
                parts.append(f"- 📷 图片: `{path.name}` ({format_size(size)})")
            elif suffix in {".mp4", ".mov", ".avi", ".mkv", ".webm"}:
                parts.append(f"- 🎬 视频: `{path.name}` ({format_size(size)})")
            elif suffix in {".mp3", ".wav", ".ogg", ".m4a", ".flac"}:
                parts.append(f"- 🎵 音频: `{path.name}` ({format_size(size)})")
            elif suffix in {".xlsx", ".xls", ".csv"}:
                parts.append(f"- 📊 表格: `{path.name}` ({format_size(size)})")
                try:
                    content = (await asyncio.to_thread(extract_excel_text, path))[:5000]
                    if content:
                        parts.append(f"  提取内容:\n```\n{content}\n```")
                except Exception:
                    self.logger.warning('Operation failed', exc_info=True)
            elif suffix == ".pdf":
                parts.append(f"- 📑 PDF: `{path.name}` ({format_size(size)})")
                try:
                    content = (await asyncio.to_thread(extract_pdf_text, path))[:5000]
                    if content:
                        parts.append(f"  提取内容:\n```\n{content}\n```")
                except Exception:
                    self.logger.warning('Operation failed', exc_info=True)
            elif suffix in {".txt", ".md", ".py", ".js", ".json", ".yaml", ".yml", ".csv", ".html", ".css", ".xml", ".sh", ".log", ".docx"}:
                parts.append(f"- 📄 文档: `{path.name}` ({format_size(size)})")
                if suffix in {".txt", ".md", ".py", ".js", ".json", ".yaml", ".yml", ".csv", ".html", ".css", ".xml", ".sh", ".log"}:
                    try:
                        def _read_file(p: Path) -> str:
                            return p.read_text(encoding="utf-8", errors="replace")[:8000]

                        content = await asyncio.to_thread(_read_file, path)
                        parts.append(f"  预览:\n```\n{content}\n```")
                    except Exception:
                        self.logger.warning('Operation failed', exc_info=True)
            else:
                parts.append(f"- 📎 文件: `{path.name}` ({format_size(size)})")

        return "\n".join(parts)

    def _init_default_prompt_variant(self) -> None:
        """Register the base system prompt as a variant for A/B optimization."""
        if not self.optimizer:
            return
        try:
            variant = self.optimizer.select_variant("system")
            if variant is None:
                self.optimizer.register_variant("system", self.SYSTEM_PROMPT, "baseline")
        except Exception:
            self.logger.warning("Failed to register default prompt variant", exc_info=True)

    def _build_vision_content(
        self,
        user_input: str,
        attachments: list[str],
        supports_vision: bool,
    ) -> str | list[dict[str, Any]]:
        """Build user message content, using multimodal format for vision models."""
        if not supports_vision or not attachments:
            return ""

        from js.tools.images import create_image_message, is_image

        parts: list[dict[str, Any]] = [{"type": "text", "text": user_input}]
        for path_str in attachments:
            path = self.settings.workspace / path_str
            if path.exists() and is_image(path):
                try:
                    parts.append(create_image_message(path))
                except Exception as e:
                    self.logger.warning(f"Failed to encode image {path}: {e}")
        if len(parts) > 1:
            return parts
        return ""

    def _build_system_message(
        self,
        query: str = "",
        session_id: str = "",
        attachments: list[str] | None = None,
        model: str | None = None,
    ) -> str:
        """Build system message with rich multi-layer memory context."""
        cache_key = (query, session_id, model or "")
        cached = self._system_message_cache.get(cache_key)
        if cached is not None:
            return cached

        parts = [self.SYSTEM_PROMPT]

        # Local-model appendix: simplify instructions because weak FC models
        # struggle with long prompts and complex multi-step tool workflows.
        # We also strip WebBridge references so the model doesn't hallucinate
        # tools that have been removed from its schema.
        if model and self.router.is_local_model(model):
            parts = [
                "You are JS, a helpful AI assistant with access to a small set of tools.",
                "",
                "Available tools:",
                "- web_search: Search the web. Call it ONCE with your query, then answer.",
                "- file_read / file_view: Read files.",
                "- file_edit: Edit files with exact search/replace.",
                "- file_write: Create new files.",
                "- shell: Run shell commands.",
                "- python: Run Python code.",
                "",
                "CRITICAL RULES:",
                "1. Call web_search ONCE. Do NOT call it again.",
                "2. If a tool returns an error, STOP and tell the user.",
                "3. NEVER repeat the same tool call.",
                "4. After any tool result, answer immediately.",
            ]

        # Inject learned insights from past interactions
        if self.learner:
            hint = self.learner.generate_context_hint(query)
            if hint:
                parts.append(f"\n## Learned Insight\n{hint}")

        # A/B test prompt variant
        if self.optimizer:
            try:
                variant = self.optimizer.select_variant("system")
                if variant:
                    variant_id, prompt_template = variant
                    parts.append(f"\n## Optimization Variant\n{prompt_template}")
                    self._last_system_variant_id = variant_id
            except Exception:
                self.logger.warning("Failed to select prompt variant", exc_info=True)

        if self.settings.memory.enabled:
            try:
                # Cap memory context so system prompt + context stays well within
                # typical local model context windows (4k-8k). Base prompt is ~2.5k.
                max_memory = min(self.settings.memory.max_memory_chars, 2000)
                from js.web.auth import _session_owner_hash
                memory_context = self.memory.get_context_string(
                    query=query,
                    session_id=session_id,
                    max_chars=max_memory,
                    owner_key_hash=_session_owner_hash.get(None),
                )
                if memory_context:
                    # Security scan memory context before injection
                    memory_context = self.secrets.detect_and_redact(
                        memory_context, "memory_context"
                    )
                    scan = self.guard.check_tool_result(memory_context)
                    if scan.decision.value in ("block", "warn"):
                        self.logger.warning(
                            f"Memory context security scan {scan.decision.value}: {scan.reason}"
                        )
                        self.audit.log(
                            AuditEventType.SECURITY_ALERT,
                            session_id or "",
                            "",
                            "agent",
                            "memory_scan",
                            {"decision": scan.decision.value, "reason": scan.reason},
                        )
                        # Degrade to empty context on block
                        if scan.decision.value == "block":
                            memory_context = ""
                    if memory_context:
                        parts.append(f"\n## Relevant Context\n{memory_context}")
            except Exception:
                self.logger.warning("Failed to build memory context", exc_info=True)

        result = "\n".join(parts)
        # Hard cap total system prompt length to prevent context overflow
        if len(result) > 4000:
            result = result[:4000] + "\n...[truncated]"
        self._system_message_cache[cache_key] = result
        return result

    def _format_messages_for_summary(self, messages: list[ChatMessage]) -> str:
        """Format messages for the summarizer prompt."""
        parts: list[str] = []
        for msg in messages:
            if msg.role == "user":
                content = msg.content if isinstance(msg.content, str) else str(msg.content)
                parts.append(f"User: {content[:500]}")
            elif msg.role == "assistant":
                content = msg.content if isinstance(msg.content, str) else str(msg.content)
                parts.append(f"Assistant: {content[:500]}")
            elif msg.role == "tool":
                content = msg.content if isinstance(msg.content, str) else str(msg.content)
                parts.append(f"Tool ({msg.name}): {content[:300]}")
        return "\n---\n".join(parts)
