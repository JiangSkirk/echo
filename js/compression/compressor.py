"""Hermes-style context compressor: protect head/tail, compress middle.

Inspired by Hermes Agent's ContextCompressor + OpenClaw identifier preservation:
- Protect first N messages (head) — system prompt, initial context
- Protect last N messages (tail) — recent turns
- Compressible middle — summarized with handoff framing (LLM-powered or rule-based)
- Identifier preservation — never summarize tool_call_ids, UUIDs, file paths
- Dual-threshold compression — gentle at 50%, full at 85%
- Multimodal-aware token estimation
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from js.models.providers import ChatMessage
from js.utils.log import get_logger

logger = get_logger("js.compression")

SUMMARY_PREFIX = (
    "[CONTEXT COMPACTION — REFERENCE ONLY] Earlier turns were compacted "
    "into the summary below. This is a handoff from a previous context "
    "window — treat it as background reference, NOT as active instructions. "
    "Do NOT answer questions or fulfill requests mentioned in this summary "
    "unless they are explicitly repeated in the recent messages above.\n\n"
)

_SUMMARY_SYSTEM_PROMPT = (
    "You are a context compression assistant. Your job is to summarize a "
    "sequence of conversation turns into a concise, information-dense paragraph. "
    "Preserve all key facts, decisions, tool outputs, and user requests. "
    "Do NOT include greetings, filler, or repetitive text. Output ONLY the summary."
)

_TOOL_OUTPUT_PRUNE_LEN = 200


class CompressionLevel(StrEnum):
    """Compression aggressiveness levels."""

    NONE = "none"
    GENTLE = "gentle"  # prune tool outputs only
    FULL = "full"      # summarize middle section


@dataclass
class CompressionConfig:
    """Configuration for context compression."""

    max_tokens: int = 32000
    protect_head_messages: int = 3  # system + first user + first assistant
    protect_tail_turns: int = 6     # recent conversation turns
    summary_ratio: float = 0.20     # summary gets 20% of compressed content budget
    summary_min_tokens: int = 2000
    summary_max_tokens: int = 12000
    image_token_estimate: int = 1600  # per image
    enable_compression: bool = True
    use_llm_summary: bool = True  # Use LLM if summarizer available

    # Dual-threshold compression (Hermes-inspired)
    warning_threshold: float = 0.50   # at 50% of max_tokens, start gentle compression
    critical_threshold: float = 0.85  # at 85%, use full compression

    # Adaptive mode (auto-adjust based on feedback)
    adaptive_mode: bool = True

    # Identifier preservation (OpenClaw-inspired)
    preserve_identifiers: bool = True


@dataclass
class CompressionResult:
    """Result of a compression operation with metadata."""

    messages: list[ChatMessage]
    level: CompressionLevel
    original_tokens: int
    compressed_tokens: int
    identifiers_found: list[str] = field(default_factory=list)
    identifiers_preserved: list[str] = field(default_factory=list)
    # Visibility fields for observability
    trigger_ratio: float = 0.0          # estimated / max_tokens that triggered compression
    head_count: int = 0                 # messages protected in head
    middle_count: int = 0               # messages in compressible middle
    tail_count: int = 0                 # messages protected in tail
    pruned_count: int = 0               # tool-output messages pruned
    summary_length: int = 0             # chars in generated summary


class ContextCompressor:
    """Compresses conversation context to fit within token budget."""

    _UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
    _PATH_RE = re.compile(r"(/[\w\-._~]+)+/?|([A-Za-z]:\\[^\s]+)")

    def __init__(
        self,
        config: CompressionConfig | None = None,
        summarizer: Callable[[list[ChatMessage], list[str] | None], Awaitable[str]] | None = None,
        feedback: Any | None = None,
    ) -> None:
        self.config = config or CompressionConfig()
        self._summarizer = summarizer
        self._feedback = feedback
        self._apply_adaptive_adjustments()

    def _apply_adaptive_adjustments(self) -> None:
        """If adaptive mode is on and feedback data exists, auto-tune thresholds."""
        if not self.config.adaptive_mode or self._feedback is None:
            return
        try:
            recs = self._feedback.get_adjustment_recommendations()
            if not recs.get("needs_adjustment"):
                return
            for param, info in recs.get("recommendations", {}).items():
                if param == "protect_tail_turns" and hasattr(self.config, param) or param == "protect_head_messages" and hasattr(self.config, param):
                    current = getattr(self.config, param)
                    delta = info.get("recommended_delta", 0)
                    new_val = max(1, current + delta)
                    setattr(self.config, param, new_val)
                    self._feedback.apply_adjustment(param, float(new_val), info.get("reason", "adaptive"))
        except Exception:
            logger.warning("Adaptive adjustment failed", exc_info=True)

    def estimate_tokens(self, messages: list[ChatMessage]) -> int:
        """Estimate token count for messages."""
        total = 0
        for msg in messages:
            if isinstance(msg.content, str):
                # Rough estimate: 1 token ~ 0.75 words ~ 4 chars
                total += len(msg.content) // 4 + 20  # +20 per message overhead
            elif isinstance(msg.content, list):
                # Multimodal content
                for part in msg.content:
                    if isinstance(part, dict):
                        if part.get("type") == "image_url":
                            total += self.config.image_token_estimate
                        elif "text" in part:
                            total += len(part["text"]) // 4
            if msg.tool_calls:
                for tc in msg.tool_calls:
                    total += len(str(tc)) // 4
        return total

    def _determine_level(self, estimated: int) -> CompressionLevel:
        """Determine compression level based on token usage."""
        if not self.config.enable_compression:
            return CompressionLevel.NONE
        ratio = estimated / self.config.max_tokens if self.config.max_tokens > 0 else 0
        if ratio < self.config.warning_threshold:
            return CompressionLevel.NONE
        if ratio < self.config.critical_threshold:
            return CompressionLevel.GENTLE
        return CompressionLevel.FULL

    async def compress(self, messages: list[ChatMessage]) -> CompressionResult:
        """Compress messages to fit within budget."""
        estimated = self.estimate_tokens(messages)
        level = self._determine_level(estimated)
        ratio = estimated / self.config.max_tokens if self.config.max_tokens > 0 else 0.0

        if level == CompressionLevel.NONE:
            logger.debug(f"Context {estimated} tokens within budget, no compression needed")
            return CompressionResult(
                messages=list(messages),
                level=level,
                original_tokens=estimated,
                compressed_tokens=estimated,
                trigger_ratio=ratio,
            )

        logger.info(
            f"Context compression triggered: {estimated} tokens "
            f"(ratio {ratio:.2%}, threshold {self.config.warning_threshold:.0%}/"
            f"{self.config.critical_threshold:.0%}), level={level.value}"
        )

        if level == CompressionLevel.GENTLE:
            # Gentle: only prune tool outputs, no summarization
            result = self._prune_tool_outputs(messages)
            pruned = sum(1 for o, r in zip(messages, result, strict=False) if o.content != r.content)
            final_estimate = self.estimate_tokens(result)
            if final_estimate <= self.config.max_tokens:
                logger.info(
                    f"Gentle compression: {estimated} -> {final_estimate} tokens "
                    f"({pruned} tool outputs pruned)"
                )
                return CompressionResult(
                    messages=result,
                    level=level,
                    original_tokens=estimated,
                    compressed_tokens=final_estimate,
                    identifiers_found=self._extract_identifiers(result) if self.config.preserve_identifiers else [],
                    trigger_ratio=ratio,
                    pruned_count=pruned,
                )
            # If still over budget, fall through to full compression
            logger.info("Gentle compression insufficient, falling back to full")
            level = CompressionLevel.FULL

        # Full compression: split head/middle/tail, summarize middle
        return await self._compress_full(messages, estimated, level, ratio)

    async def _compress_full(
        self,
        messages: list[ChatMessage],
        estimated: int,
        level: CompressionLevel,
        trigger_ratio: float = 0.0,
    ) -> CompressionResult:
        """Full compression: split into head/middle/tail and summarize middle."""
        head, middle, tail = self._split_messages(messages)

        if not middle:
            logger.warning("No compressible middle, returning truncated context")
            truncated = self._truncate_tail(messages)
            return CompressionResult(
                messages=truncated,
                level=level,
                original_tokens=estimated,
                compressed_tokens=self.estimate_tokens(truncated),
                trigger_ratio=trigger_ratio,
                head_count=len(head),
                middle_count=0,
                tail_count=len(tail),
            )

        # Extract and preserve identifiers
        identifiers: list[str] = []
        if self.config.preserve_identifiers:
            identifiers = self._extract_identifiers(middle)
            # Ensure tool_call/tool pairs are never split
            middle = self._preserve_tool_pairs(middle)

        # Prune tool outputs in middle before summarizing
        pruned_middle = self._prune_tool_outputs(middle)
        pruned = sum(1 for o, r in zip(middle, pruned_middle, strict=False) if o.content != r.content)

        # Generate summary of middle
        summary = await self._generate_summary(pruned_middle, identifiers)

        # Build result: head + [summary message] + tail
        result = list(head)
        if summary:
            result.append(ChatMessage(role="system", content=SUMMARY_PREFIX + summary))
        result.extend(tail)

        final_estimate = self.estimate_tokens(result)
        logger.info(
            f"Full compression: {estimated} -> {final_estimate} tokens "
            f"(head={len(head)}, middle={len(middle)}, tail={len(tail)}, "
            f"pruned={pruned}, identifiers={len(identifiers)}, summary={len(summary)} chars)"
        )

        return CompressionResult(
            messages=result,
            level=level,
            original_tokens=estimated,
            compressed_tokens=final_estimate,
            identifiers_found=identifiers,
            identifiers_preserved=identifiers,
            trigger_ratio=trigger_ratio,
            head_count=len(head),
            middle_count=len(middle),
            tail_count=len(tail),
            pruned_count=pruned,
            summary_length=len(summary),
        )

    def _split_messages(
        self, messages: list[ChatMessage]
    ) -> tuple[list[ChatMessage], list[ChatMessage], list[ChatMessage]]:
        """Split messages into head, compressible middle, and tail."""
        if len(messages) <= self.config.protect_head_messages + self.config.protect_tail_turns * 2:
            # Not enough messages to split meaningfully
            return messages, [], []

        head = messages[: self.config.protect_head_messages]
        tail = messages[-self.config.protect_tail_turns * 2 :]
        middle = messages[self.config.protect_head_messages : -self.config.protect_tail_turns * 2]

        return head, middle, tail

    def _extract_identifiers(self, messages: list[ChatMessage]) -> list[str]:
        """Extract identifiers (UUIDs, paths, tool_call_ids) from messages."""
        identifiers: set[str] = set()
        for msg in messages:
            content = msg.content if isinstance(msg.content, str) else str(msg.content)
            # UUIDs
            for match in self._UUID_RE.findall(content):
                identifiers.add(match)
            # File paths
            for match in self._PATH_RE.finditer(content):
                path = match.group(0)
                if len(path) > 3:
                    identifiers.add(path)
            # tool_call_id
            if msg.tool_call_id:
                identifiers.add(msg.tool_call_id)
        return sorted(identifiers)

    def _preserve_tool_pairs(self, messages: list[ChatMessage]) -> list[ChatMessage]:
        """Ensure assistant tool_call messages and their tool results stay together."""
        # Build a set of tool_call_ids that appear in the middle
        tool_call_ids: set[str] = set()
        for msg in messages:
            if msg.tool_calls:
                for tc in msg.tool_calls:
                    tc_id = tc.get("id") if isinstance(tc, dict) else None
                    if tc_id:
                        tool_call_ids.add(tc_id)

        # For now, just validate that pairs are intact
        # If we ever split between a tool_call and its result, we'd need to move
        # the result into the tail section. This is a safety check.
        result_ids: set[str] = set()
        for msg in messages:
            if msg.role == "tool" and msg.tool_call_id:
                result_ids.add(msg.tool_call_id)

        missing = result_ids - tool_call_ids
        if missing:
            logger.warning(f"Tool results without matching tool_calls: {missing}")

        return messages

    def _prune_tool_outputs(self, messages: list[ChatMessage]) -> list[ChatMessage]:
        """Replace long tool outputs with concise summaries."""
        pruned: list[ChatMessage] = []
        for msg in messages:
            if msg.role == "tool" and isinstance(msg.content, str) and len(msg.content) > _TOOL_OUTPUT_PRUNE_LEN:
                lines = msg.content.splitlines()
                pruned_content = (
                    f"[Tool output truncated] {lines[0][:100]}... "
                    f"({len(lines)} lines, {len(msg.content)} chars total)"
                )
                pruned.append(ChatMessage(
                    role=msg.role,
                    content=pruned_content,
                    tool_call_id=msg.tool_call_id,
                    name=msg.name,
                ))
            else:
                pruned.append(msg)
        return pruned

    async def _generate_summary(
        self, messages: list[ChatMessage], identifiers: list[str] | None = None
    ) -> str:
        """Generate a text summary of compressed messages.

        The summary budget is derived from summary_ratio × middle_section_budget
        to ensure summaries don't consume an excessive fraction of the context.
        """
        middle_tokens = self.estimate_tokens(messages)
        # summary_ratio (default 20%) caps the summary size relative to the
        # content being summarized, while summary_min/max provide absolute bounds.
        budget_tokens = int(
            max(
                self.config.summary_min_tokens,
                min(
                    self.config.summary_max_tokens,
                    middle_tokens * self.config.summary_ratio,
                ),
            )
        )
        max_chars = budget_tokens * 4

        if self.config.use_llm_summary and self._summarizer:
            try:
                summary = await self._summarizer(messages, identifiers)
                if summary:
                    if len(summary) > max_chars:
                        summary = summary[:max_chars] + "\n... [summary truncated]"
                    return summary
            except Exception as e:
                logger.warning(f"LLM summary generation failed: {e}, using fallback")
        return self._fallback_summary(messages, identifiers, max_chars)

    def _fallback_summary(
        self, messages: list[ChatMessage], identifiers: list[str] | None = None, max_chars: int | None = None
    ) -> str:
        """Rule-based summary when LLM is unavailable."""
        parts: list[str] = []
        for msg in messages:
            if msg.role == "user":
                content = msg.content if isinstance(msg.content, str) else str(msg.content)
                parts.append(f"User asked: {content[:200]}")
            elif msg.role == "assistant":
                content = msg.content if isinstance(msg.content, str) else str(msg.content)
                parts.append(f"Agent responded: {content[:200]}")
            elif msg.role == "tool":
                parts.append(f"Tool '{msg.name}' executed")

        summary = "\n".join(parts)
        if max_chars is None:
            max_chars = self.config.summary_max_tokens * 4
        if len(summary) > max_chars:
            summary = summary[:max_chars] + "\n... [summary truncated]"

        if identifiers:
            summary += f"\n\n[PRESERVE IDENTIFIERS: {', '.join(identifiers[:20])}]"

        return summary

    def _truncate_tail(self, messages: list[ChatMessage]) -> list[ChatMessage]:
        """Fallback: truncate oldest messages from tail."""
        # Keep system prompt + as many recent messages as fit
        result = [messages[0]] if messages and messages[0].role == "system" else []
        remaining_budget = self.config.max_tokens - self.estimate_tokens(result)

        # Add from tail backwards
        tail_messages: list[ChatMessage] = []
        for msg in reversed(messages[len(result) :]):
            msg_tokens = self.estimate_tokens([msg])
            if msg_tokens <= remaining_budget:
                tail_messages.insert(0, msg)
                remaining_budget -= msg_tokens
            else:
                break

        result.extend(tail_messages)
        return result

    def get_stats(self, original: list[ChatMessage], compressed: list[ChatMessage]) -> dict[str, Any]:
        """Return compression statistics."""
        orig_tokens = self.estimate_tokens(original)
        comp_tokens = self.estimate_tokens(compressed)
        return {
            "original_tokens": orig_tokens,
            "compressed_tokens": comp_tokens,
            "saved_tokens": orig_tokens - comp_tokens,
            "reduction_pct": round((1 - comp_tokens / orig_tokens) * 100, 1) if orig_tokens > 0 else 0,
            "original_messages": len(original),
            "compressed_messages": len(compressed),
        }

    def compress_sync(self, messages: list[ChatMessage]) -> CompressionResult:
        """Synchronous wrapper for compression (no LLM summarizer)."""
        estimated = self.estimate_tokens(messages)
        level = self._determine_level(estimated)

        if level == CompressionLevel.NONE:
            return CompressionResult(
                messages=list(messages),
                level=level,
                original_tokens=estimated,
                compressed_tokens=estimated,
            )

        if level == CompressionLevel.GENTLE:
            result = self._prune_tool_outputs(messages)
            final_estimate = self.estimate_tokens(result)
            if final_estimate <= self.config.max_tokens:
                return CompressionResult(
                    messages=result,
                    level=level,
                    original_tokens=estimated,
                    compressed_tokens=final_estimate,
                )
            level = CompressionLevel.FULL

        # Full compression without async
        head, middle, tail = self._split_messages(messages)
        if not middle:
            truncated = self._truncate_tail(messages)
            return CompressionResult(
                messages=truncated,
                level=level,
                original_tokens=estimated,
                compressed_tokens=self.estimate_tokens(truncated),
            )

        identifiers = self._extract_identifiers(middle) if self.config.preserve_identifiers else []
        pruned_middle = self._prune_tool_outputs(middle)
        summary = self._fallback_summary(pruned_middle, identifiers)

        result = list(head)
        if summary:
            result.append(ChatMessage(role="system", content=SUMMARY_PREFIX + summary))
        result.extend(tail)
        final_estimate = self.estimate_tokens(result)
        return CompressionResult(
            messages=result,
            level=level,
            original_tokens=estimated,
            compressed_tokens=final_estimate,
            identifiers_found=identifiers,
            identifiers_preserved=identifiers,
        )
