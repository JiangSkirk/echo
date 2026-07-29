"""MemoryOrganizer — LLM-driven structured extraction into the memory library.

After a conversation (or during the idle/dream cycle), the organizer reads the
recent transcript, asks the model to extract durable facts about the user —
identity, personality, body, people (family/friends), work, plans, preferences
— and stages them as *proposed changes*.  Sensitive blocks (identity / family /
body) and low-confidence items wait for the user to confirm; everything else is
applied immediately.  A one-line conversation summary is always written to
``/history/chats``.

This builds on the existing infrastructure rather than replacing it:
* auto block-classification + conflict/eviction live in ``EnhancedMemoryStore``
* the proposal gate (``_should_auto_apply``) lives in ``store_semantic`` land
* LLM calls go through the agent-provided authorized chat callable in production.
"""

from __future__ import annotations

import inspect
import json
import re
from collections.abc import Awaitable, Callable
from typing import Any, cast

from js.models.providers import ChatMessage, ChatResponse
from js.utils.log import get_logger

logger = get_logger("js.memory.organizer")

# Categories the model is allowed to emit; anything else is coerced to "fact".
_ALLOWED_CATEGORIES = {"fact", "preference", "insight"}
_MAX_FACTS_PER_CYCLE = 20

_SYSTEM_PROMPT = (
    "You are a meticulous memory archivist for a personal AI assistant. "
    "From a conversation, you extract durable, reusable facts about the USER "
    "(not the assistant) and return them as strict JSON. Be conservative: only "
    "record things likely to stay true and useful later. Respond in the same "
    "language as the conversation."
)

_INSTRUCTIONS = (
    "Extract durable facts about the user. Cover any of: identity (name, age, "
    "birthday, job, location), personality/values, body/health, family, "
    "friends, company, projects, colleagues, plans/goals, preferences, devices.\n"
    "For each fact provide:\n"
    '  - "key": a short stable identifier (snake_case or a concise noun phrase)\n'
    '  - "value": the concise fact\n'
    '  - "category": one of "fact", "preference", "insight"\n'
    '  - "confidence": 0.0-1.0 (how certain you are it is true & durable)\n'
    '  - "evidence": the exact phrase from the conversation that supports it\n'
    "Also write a one-sentence \"summary\" of the conversation.\n"
    "Return ONLY a JSON object of the form:\n"
    '{"summary": "...", "facts": [{"key": "...", "value": "...", '
    '"category": "fact", "confidence": 0.8, "evidence": "..."}]}\n'
    "If nothing is worth remembering, return "
    '{"summary": "", "facts": []}.'
)


class MemoryOrganizer:
    """Extracts structured memories from conversations into the proposal queue."""

    def __init__(self, memory: Any, llm_chat: Any, config: Any | None = None) -> None:
        self.memory = memory
        self._llm_chat, self._llm_chat_parameters = self._coerce_llm_chat(llm_chat)
        self.config = config

    @staticmethod
    def _coerce_llm_chat(
        llm_chat: Any,
    ) -> tuple[Callable[..., Awaitable[ChatResponse]], frozenset[str]]:
        if callable(llm_chat) and not hasattr(llm_chat, "chat"):
            target = llm_chat
        else:
            target = getattr(llm_chat, "chat", None)
        if callable(target):
            try:
                parameters = frozenset(inspect.signature(target).parameters)
            except (TypeError, ValueError):
                parameters = frozenset()

            async def _call(*args: Any, **kwargs: Any) -> ChatResponse:
                return cast("ChatResponse", await target(*args, **kwargs))

            return _call, parameters
        raise TypeError("MemoryOrganizer requires an llm chat callable or router")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def extract(
        self,
        conversation_buffer: list[dict[str, str]],
        session_id: str = "",
        owner_key_hash: str | None = None,
    ) -> dict[str, Any]:
        """Extract facts from a conversation buffer and stage them as proposals.

        Returns a report: ``{ok, proposed, auto_applied, pending, summary, error}``.
        Never raises — extraction is best-effort background work.
        """
        report: dict[str, Any] = {
            "ok": False, "proposed": 0, "auto_applied": 0,
            "pending": 0, "duplicate": 0, "summary": "", "error": None,
        }
        if self.config is not None and not getattr(self.config, "auto_extract", True):
            report["ok"] = True
            report["skipped"] = "auto_extract disabled"
            return report

        transcript = self._build_transcript(conversation_buffer)
        if not transcript.strip():
            report["ok"] = True
            return report

        try:
            content = await self._call_llm(
                transcript,
                session_id=session_id,
                owner_key_hash=owner_key_hash,
            )
        except Exception as e:  # noqa: BLE001 — background task must not crash
            logger.warning("记忆整理 LLM 调用失败，已降级跳过：%s", e)
            report["error"] = str(e)
            return report

        parsed = self._parse_payload(content)
        if parsed is None:
            report["error"] = "could not parse extraction output"
            return report

        facts = parsed.get("facts") or []
        summary = (parsed.get("summary") or "").strip()
        report["summary"] = summary

        for fact in facts[:_MAX_FACTS_PER_CYCLE]:
            res = self._propose_fact(fact, session_id, owner_key_hash)
            if res is None:
                continue
            status = res.get("status")
            if status == "duplicate":
                report["duplicate"] += 1
                continue
            report["proposed"] += 1
            if status == "auto_applied":
                report["auto_applied"] += 1
            elif status == "pending":
                report["pending"] += 1

        # Always record a conversation summary under /history/chats.
        if summary and session_id:
            try:
                self.memory.propose_change(
                    action="create",
                    key=f"chat_summary_{session_id}",
                    value=summary,
                    category="insight",
                    memory_path="/history/chats",
                    entity_type="chat",
                    relation_type="discussed",
                    confidence=0.7,
                    source="organizer",
                    session_id=session_id,
                    evidence="",
                    owner_key_hash=owner_key_hash,
                    auto_apply=True,
                )
            except Exception:
                logger.debug("Failed to record chat summary", exc_info=True)

        report["ok"] = True
        return report

    async def bootstrap(
        self, owner_key_hash: str | None = None, max_sessions: int = 5
    ) -> dict[str, Any]:
        """One-shot extraction over recent stored history.

        Triggered once after a model first connects so existing conversations
        seed the library.  Best-effort and idempotent (proposals/upserts dedupe
        by key).
        """
        report: dict[str, Any] = {"ok": False, "sessions": 0, "proposed": 0}
        try:
            sessions = self.memory.get_sessions(limit=max_sessions, owner_key_hash=owner_key_hash)
        except Exception:
            sessions = []
        for sess in sessions:
            sid = sess.get("session_id") if isinstance(sess, dict) else None
            if not sid:
                continue
            try:
                messages = self.memory.get_session_messages(sid, owner_key_hash=owner_key_hash)
            except Exception:
                continue
            buffer = self._messages_to_buffer(messages)
            if not buffer:
                continue
            res = await self.extract(buffer, session_id=sid, owner_key_hash=owner_key_hash)
            report["sessions"] += 1
            report["proposed"] += res.get("proposed", 0)
        report["ok"] = True
        return report

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _build_transcript(buffer: list[dict[str, str]]) -> str:
        lines: list[str] = []
        for turn in buffer or []:
            user = (turn.get("user") or "").strip()
            assistant = (turn.get("assistant") or "").strip()
            if user:
                lines.append(f"User: {user}")
            if assistant:
                lines.append(f"Assistant: {assistant}")
        return "\n".join(lines)

    @staticmethod
    def _messages_to_buffer(messages: list[dict[str, Any]]) -> list[dict[str, str]]:
        """Fold a flat role/content message list into user/assistant turns."""
        buffer: list[dict[str, str]] = []
        pending_user = ""
        for m in messages or []:
            role = m.get("role")
            content = m.get("content") or ""
            if not isinstance(content, str):
                continue
            if role == "user":
                if pending_user:
                    buffer.append({"user": pending_user, "assistant": ""})
                pending_user = content
            elif role == "assistant":
                buffer.append({"user": pending_user, "assistant": content})
                pending_user = ""
        if pending_user:
            buffer.append({"user": pending_user, "assistant": ""})
        return buffer

    async def _call_llm(
        self,
        transcript: str,
        *,
        session_id: str,
        owner_key_hash: str | None,
    ) -> str:
        messages = [
            ChatMessage(role="system", content=_SYSTEM_PROMPT),
            ChatMessage(role="user", content=f"{_INSTRUCTIONS}\n\nConversation:\n{transcript}"),
        ]
        kwargs: dict[str, Any] = {"temperature": 0.2}
        if "tenant_id" in self._llm_chat_parameters:
            kwargs["tenant_id"] = owner_key_hash or "local"
        if "run_id" in self._llm_chat_parameters:
            kwargs["run_id"] = f"memory:{session_id or 'bootstrap'}"
        resp = await self._llm_chat(messages, **kwargs)
        return resp.content or ""

    @staticmethod
    def _parse_payload(text: str) -> dict[str, Any] | None:
        """Robustly pull the JSON object out of a model response."""
        if not text:
            return None
        candidate = text.strip()
        # Strip Markdown code fences if present.
        fence = re.search(r"```(?:json)?\s*(.+?)```", candidate, re.DOTALL)
        if fence:
            candidate = fence.group(1).strip()
        # Narrow to the outermost object braces.
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = candidate[start : end + 1]
        try:
            data = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        return data

    def _propose_fact(
        self, fact: Any, session_id: str, owner_key_hash: str | None
    ) -> dict[str, Any] | None:
        if not isinstance(fact, dict):
            return None
        key = str(fact.get("key") or "").strip()
        value = str(fact.get("value") or "").strip()
        if not key or not value:
            return None
        category = str(fact.get("category") or "fact").strip().lower()
        if category not in _ALLOWED_CATEGORIES:
            category = "fact"
        try:
            confidence = float(fact.get("confidence", 0.6))
        except (TypeError, ValueError):
            confidence = 0.6
        confidence = max(0.0, min(1.0, confidence))
        evidence = str(fact.get("evidence") or "").strip()
        try:
            result: dict[str, Any] = self.memory.propose_change(
                action="create",
                key=key,
                value=value,
                category=category,
                confidence=confidence,
                source="organizer",
                session_id=session_id,
                evidence=evidence,
                owner_key_hash=owner_key_hash,
                skip_if_pending=True,
            )
            return result
        except Exception:
            logger.debug("propose_change failed for key=%s", key, exc_info=True)
            return None
