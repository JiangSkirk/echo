"""Prompt + context construction for the agent.

Builds the system message (with multi-layer memory context), vision/multimodal
user content, attachment context, and summary formatting.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from js.agent.base import AgentBase
from js.echo.attachment_gate import read_agent_attachment, validate_agent_attachment_path
from js.echo.ledger.service import EchoBlockedError
from js.security.audit import AuditEventType
from js.utils.attachments import extract_excel_text, extract_pdf_text, format_size

if TYPE_CHECKING:
    from js.models.providers import ChatMessage


_SYSTEM_PROMPT_CACHE_VERSION = "system-message-v2"
_INSECURE_CACHE_OWNERS = frozenset({"local-user", "__legacy_local__"})
_SELECTED_PROMPT_VARIANT: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "echo_selected_prompt_variant",
    default=None,
)
_LOCAL_MODEL_BASE_PROMPT = """You are JS, a helpful AI assistant with access to a small set of tools.

Use only the tools listed for this request. Investigate before changing files, never expose secrets, and report a tool error instead of repeating the same call."""
_WORK_BOUNDARY_HEADING = "## JS Agent Work Boundary"


def consume_selected_prompt_variant_id() -> str | None:
    variant_id = _SELECTED_PROMPT_VARIANT.get()
    _SELECTED_PROMPT_VARIANT.set(None)
    return variant_id


@dataclass(frozen=True)
class _SystemPromptCacheKey:
    product_id: str
    owner_key_hash: str
    session_id: str
    model: str
    profile: str
    capabilities: tuple[str, ...]
    prompt_version: str
    query: str


class PromptBuilderMixin(AgentBase):
    """System prompt, vision content, attachment context, summary formatting."""

    def _local_model_product_appendix(self) -> str:
        """Preserve the Work product boundary when compacting local prompts."""
        start = self.SYSTEM_PROMPT.find(_WORK_BOUNDARY_HEADING)
        return self.SYSTEM_PROMPT[start:] if start >= 0 else ""

    def _local_model_tool_appendix(self, model: str) -> str:
        """Describe only tools present in this local model's schema."""
        tool_names: list[str] = []
        for schema in self._get_tools_schema(model) or []:
            name = str(schema.get("function", {}).get("name", ""))
            if name:
                tool_names.append(name)

        if not tool_names:
            return "## Available Tools\nNo tools are available for this request."
        return "## Available Tools\n" + "\n".join(f"- `{name}`" for name in sorted(tool_names))

    async def _build_attachment_context(
        self, attachments: list[str], session_id: str | None = None
    ) -> str:
        """Build context text describing uploaded attachments."""
        if not attachments:
            return ""

        parts: list[str] = ["\n\n## 附件文件\n"]
        for path_str in attachments:
            snapshot = await asyncio.to_thread(
                self._read_attachment_snapshot,
                path_str,
                session_id,
            )
            suffix = snapshot.suffix
            size = snapshot.size
            name = snapshot.name

            if suffix in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg"}:
                parts.append(f"- 📷 图片: `{name}` ({format_size(size)})")
            elif suffix in {".mp4", ".mov", ".avi", ".mkv", ".webm"}:
                parts.append(f"- 🎬 视频: `{name}` ({format_size(size)})")
            elif suffix in {".mp3", ".wav", ".ogg", ".m4a", ".flac"}:
                parts.append(f"- 🎵 音频: `{name}` ({format_size(size)})")
            elif suffix in {".xlsx", ".xls", ".csv"}:
                parts.append(f"- 📊 表格: `{name}` ({format_size(size)})")
                try:
                    content = (
                        await asyncio.to_thread(
                            extract_excel_text,
                            BytesIO(snapshot.data),
                        )
                    )[:5000]
                    if content:
                        content = self._reject_secret_attachment_text(
                            content,
                            "attachment_excel_preview",
                        )
                        parts.append(f"  提取内容:\n```\n{content}\n```")
                except PermissionError:
                    raise
                except Exception:
                    self.logger.warning("Operation failed", exc_info=True)
            elif suffix == ".pdf":
                parts.append(f"- 📑 PDF: `{name}` ({format_size(size)})")
                try:
                    content = (
                        await asyncio.to_thread(
                            extract_pdf_text,
                            BytesIO(snapshot.data),
                        )
                    )[:5000]
                    if content:
                        content = self._reject_secret_attachment_text(
                            content,
                            "attachment_pdf_preview",
                        )
                        parts.append(f"  提取内容:\n```\n{content}\n```")
                except PermissionError:
                    raise
                except Exception:
                    self.logger.warning("Operation failed", exc_info=True)
            elif suffix in {
                ".txt",
                ".md",
                ".py",
                ".js",
                ".json",
                ".yaml",
                ".yml",
                ".csv",
                ".html",
                ".css",
                ".xml",
                ".sh",
                ".log",
                ".docx",
            }:
                parts.append(f"- 📄 文档: `{name}` ({format_size(size)})")
                if suffix in {
                    ".txt",
                    ".md",
                    ".py",
                    ".js",
                    ".json",
                    ".yaml",
                    ".yml",
                    ".csv",
                    ".html",
                    ".css",
                    ".xml",
                    ".sh",
                    ".log",
                }:
                    try:
                        content = snapshot.data.decode(
                            "utf-8",
                            errors="replace",
                        )[:8000]
                        content = self._reject_secret_attachment_text(
                            content,
                            "attachment_text_preview",
                        )
                        parts.append(f"  预览:\n```\n{content}\n```")
                    except PermissionError:
                        raise
                    except Exception:
                        self.logger.warning("Operation failed", exc_info=True)
            else:
                parts.append(f"- 📎 文件: `{name}` ({format_size(size)})")

        return "\n".join(parts)

    def _reject_secret_attachment_text(self, content: str, source: str) -> str:
        redacted = self.secrets.detect_and_redact(content, source)
        if redacted != content:
            raise EchoBlockedError("Attachment contains secret-like content")
        return content

    def _read_attachment_snapshot(
        self,
        path_str: str,
        session_id: str | None,
    ) -> Any:
        return read_agent_attachment(
            workspace=self.settings.workspace,
            path=path_str,
            owner_key_hash=self._attachment_owner(),
            session_id=session_id,
        )

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
        session_id: str | None = None,
    ) -> str | list[dict[str, Any]]:
        """Build user message content, using multimodal format for vision models."""
        if not supports_vision or not attachments:
            return ""

        from js.tools.images import (
            MAX_IMAGE_SIZE,
            create_image_message_bytes,
            is_image,
        )

        parts: list[dict[str, Any]] = [{"type": "text", "text": user_input}]
        for path_str in attachments:
            path = self._resolve_attachment_path(path_str, session_id=session_id)
            if is_image(path):
                # F-24: vision uploads are unconditionally blocked on the Echo model
                # path; no environment variable may weaken this gate.
                raise PermissionError(
                    "Vision attachments require explicit Echo vision safety approval"
                )
            else:
                try:
                    snapshot = read_agent_attachment(
                        workspace=self.settings.workspace,
                        path=path_str,
                        owner_key_hash=self._attachment_owner(),
                        session_id=session_id,
                        max_bytes=MAX_IMAGE_SIZE,
                    )
                    parts.append(create_image_message_bytes(snapshot.data, snapshot.suffix))
                except (PermissionError, ValueError):
                    raise
                except Exception as e:
                    self.logger.warning(f"Failed to encode image {path}: {e}")
        if len(parts) > 1:
            return parts
        return ""

    @staticmethod
    def _attachment_owner() -> str | None:
        from js.echo.turn_context import current_owner_key_hash

        return current_owner_key_hash()

    def _resolve_attachment_path(self, path_str: str, *, session_id: str | None = None) -> Path:
        """Resolve attachment paths inside the configured workspace only."""
        return validate_agent_attachment_path(
            workspace=self.settings.workspace,
            path=str(path_str),
            owner_key_hash=self._attachment_owner(),
            session_id=session_id,
        )

    def _system_prompt_cache_key(
        self,
        *,
        query: str,
        session_id: str,
        model: str | None,
    ) -> _SystemPromptCacheKey | None:
        from js.echo.turn_context import current_owner_key_hash, current_runtime_context

        context = current_runtime_context()
        owner = current_owner_key_hash()
        if (
            query
            or context is None
            or not owner
            or owner in _INSECURE_CACHE_OWNERS
            or context.owner_key_hash != owner
            or getattr(self, "optimizer", None) is not None
        ):
            return None

        effective_session = session_id or context.session_id
        if session_id and context.session_id and session_id != context.session_id:
            return None

        prompt_digest = hashlib.sha256(self.SYSTEM_PROMPT.encode("utf-8")).hexdigest()
        return _SystemPromptCacheKey(
            product_id=context.product_id,
            owner_key_hash=owner,
            session_id=effective_session,
            model=model or "",
            profile=context.profile,
            capabilities=tuple(context.capabilities),
            prompt_version=f"{_SYSTEM_PROMPT_CACHE_VERSION}:{prompt_digest}",
            query=query,
        )

    def _build_system_message(
        self,
        query: str = "",
        session_id: str = "",
        attachments: list[str] | None = None,
        model: str | None = None,
    ) -> str:
        """Build system message with rich multi-layer memory context."""
        _SELECTED_PROMPT_VARIANT.set(None)
        cache_key = self._system_prompt_cache_key(
            query=query,
            session_id=session_id,
            model=model,
        )
        prompt_cache = cast("Any", self._system_message_cache)
        if cache_key is not None:
            cached = prompt_cache.get(cache_key)
            if cached is not None:
                return cast("str", cached)

        preserve_product_prompt = str(getattr(self.settings, "product_id", "")) == "js-work"
        parts = [self.SYSTEM_PROMPT]

        # Compact local prompts while retaining the Work product boundary and
        # describing only the tools actually sent in this model's schema.
        if model and self.router.is_local_model(model):
            if preserve_product_prompt:
                parts.append(self._local_model_tool_appendix(model))
            else:
                parts = [_LOCAL_MODEL_BASE_PROMPT]
                product_appendix = self._local_model_product_appendix()
                if product_appendix:
                    parts.append(product_appendix)
                parts.append(self._local_model_tool_appendix(model))

        from js.echo.turn_context import current_owner_key_hash

        # Inject learned insights from past interactions
        if self.learner:
            hint = self.learner.generate_context_hint(
                query,
                owner_key_hash=current_owner_key_hash(),
            )
            if hint:
                parts.append(f"\n## Learned Insight\n{hint}")

        # A/B test prompt variant
        if self.optimizer:
            try:
                variant = self.optimizer.select_variant("system")
                if variant:
                    variant_id, prompt_template = variant
                    parts.append(f"\n## Optimization Variant\n{prompt_template}")
                    _SELECTED_PROMPT_VARIANT.set(variant_id)
            except Exception:
                self.logger.warning("Failed to select prompt variant", exc_info=True)

        if self.settings.memory.enabled:
            try:
                # Cap memory context so system prompt + context stays well within
                # typical local model context windows (4k-8k). Base prompt is ~2.5k.
                max_memory = min(self.settings.memory.max_memory_chars, 2000)
                memory_context = self.memory.get_context_string(
                    query=query,
                    session_id=session_id,
                    max_chars=max_memory,
                    owner_key_hash=current_owner_key_hash(),
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
        if len(result) > 4000 and not preserve_product_prompt:
            result = result[:4000] + "\n...[truncated]"
        if cache_key is not None:
            prompt_cache[cache_key] = result
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
