"""Orin taint tags: u64 source bits, propagation, decay, arg overlap.

Taint mounting design (Stage A, decided before any instrumentation):

1. ``ChatMessage.taint: int = 0`` — a u64 bitmask describing where the
   message content came from. The field is dataclass-tail with a default
   and is LOCAL bookkeeping only: provider serialization
   (``_convert_messages``) and state persistence (``AgentState.to_dict``,
   memory store) select fields explicitly, so the tag never reaches a
   model API (Orin decision 11).

2. ``AgentState.context_taint: int = 0`` — the active-context
   accumulation: OR of every live message's taint. Recomputed whenever
   messages enter/leave the window; NOT persisted.

3. ``AgentState.clearance: int = 1`` — active context classification
   (0=PUBLIC, 1=INTERNAL, 2=SECRET). Derived from the SECRET bit, which
   never decays inside a run: once any live message carries SECRET the
   context stays SECRET. Cross-turn stickiness rides compression
   (summaries force-inherit SECRET) because the memory store does not
   persist per-message taint in Stage A.

4. Window decay: when a message slides out of the active window (trimmed,
   compressed, evicted) its bits leave ``context_taint`` on recompute —
   except SECRET, which sticky-propagates to the replacement (compression)
   or, for plain eviction, drops only when no remaining message carries it.

5. Tool-call time snapshot: the adapter attaches
   ``context_taint`` (accumulated) and ``arg_taint`` (how much of the
   arguments overlaps recent dirty text, via 8-gram Jaccard) plus
   ``clearance`` to every consume request.

Iron law (Stage A red line): taint never authorizes anything. A clean
taint NEVER skips lease checks, path sandboxing, or origin validation;
taint can only produce ``approval_required`` / ``deny`` verdicts and
tighter follow-on scopes.
"""

from __future__ import annotations

import re
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Final

# ---------------------------------------------------------------------------
# u64 source bits (D §6.1 — frozen)
# ---------------------------------------------------------------------------
USER_TURN: Final[int] = 1 << 0
USER_HISTORY: Final[int] = 1 << 1
TOOL_RESULT: Final[int] = 1 << 2
WEB_CONTENT: Final[int] = 1 << 3
ATTACHMENT: Final[int] = 1 << 4
MEMORY_READ: Final[int] = 1 << 5
SKILL_CONTENT: Final[int] = 1 << 6
MODEL_OUTPUT: Final[int] = 1 << 7
CANARY_ADJACENT: Final[int] = 1 << 8
COMPRESSED: Final[int] = 1 << 9
AUTO_TASK: Final[int] = 1 << 10
INBOX_CONTENT: Final[int] = 1 << 11
SECRET: Final[int] = 1 << 12

BOT_PEER: Final[int] = 1 << 13
BOT_SOUL: Final[int] = 1 << 14
ROOM_SHARED: Final[int] = 1 << 15
RESERVED_LOW: Final[int] = BOT_PEER
RESERVED_MASK: Final[int] = BOT_PEER | BOT_SOUL | ROOM_SHARED
"""bits 13–15: BOT_PEER / BOT_SOUL / ROOM_SHARED. Tighten only — never authorize."""

SESSION_CUSTOM_BASE: Final[int] = 1 << 16

FULL_MASK: Final[int] = (1 << 64) - 1

TAINT_NAMES: Final[dict[int, str]] = {
    USER_TURN: "USER_TURN",
    USER_HISTORY: "USER_HISTORY",
    TOOL_RESULT: "TOOL_RESULT",
    WEB_CONTENT: "WEB_CONTENT",
    ATTACHMENT: "ATTACHMENT",
    MEMORY_READ: "MEMORY_READ",
    SKILL_CONTENT: "SKILL_CONTENT",
    MODEL_OUTPUT: "MODEL_OUTPUT",
    CANARY_ADJACENT: "CANARY_ADJACENT",
    COMPRESSED: "COMPRESSED",
    AUTO_TASK: "AUTO_TASK",
    INBOX_CONTENT: "INBOX_CONTENT",
    SECRET: "SECRET",
    BOT_PEER: "BOT_PEER",
    BOT_SOUL: "BOT_SOUL",
    ROOM_SHARED: "ROOM_SHARED",
}

# Bits that make tool arguments "dirty" for the write-file policy row.
DIRTY_FOR_WRITE: Final[int] = WEB_CONTENT | TOOL_RESULT | BOT_PEER

# Bits that block or gate network egress.
EGRESS_SENSITIVE: Final[int] = MEMORY_READ

# ---------------------------------------------------------------------------
# Clearance levels (D §7.1)
# ---------------------------------------------------------------------------
CLEARANCE_PUBLIC: Final[int] = 0
CLEARANCE_INTERNAL: Final[int] = 1
CLEARANCE_SECRET: Final[int] = 2


def combine(*taints: int) -> int:
    """Propagation rule: concatenation is OR."""

    result = 0
    for value in taints:
        result |= int(value) & FULL_MASK
    return result


def recompute_context_taint(taints: list[int]) -> int:
    """Recompute the active-context accumulation over live messages."""

    result = 0
    for value in taints:
        result |= int(value) & FULL_MASK
    return result


def clearance_of(context_taint: int) -> int:
    """SECRET bit ⇒ SECRET clearance; otherwise INTERNAL (Stage A default)."""

    return CLEARANCE_SECRET if context_taint & SECRET else CLEARANCE_INTERNAL


def compressed_summary_taint(original_taint: int) -> int:
    """Compression rule: summary inherits original | MODEL_OUTPUT | COMPRESSED.

    SECRET is force-inherited (never launders through summarization).
    """

    return combine(original_taint, MODEL_OUTPUT, COMPRESSED)


def describe(taint: int) -> str:
    names = [name for bit, name in TAINT_NAMES.items() if taint & bit]
    unknown = taint & ~(sum(TAINT_NAMES.keys()) | RESERVED_MASK)
    if unknown:
        names.append(f"UNKNOWN:{unknown:#x}")
    return "|".join(names) if names else "CLEAN"


# ---------------------------------------------------------------------------
# arg_taint: 8-gram Jaccard overlap between arguments and recent dirty text
# ---------------------------------------------------------------------------
_NGRAM_SIZE: Final[int] = 8
DEFAULT_OVERLAP_THRESHOLD: Final[float] = 0.18
_MAX_COMPARE_CHARS: Final[int] = 8 * 1024


def _ngrams(text: str, size: int = _NGRAM_SIZE) -> set[str]:
    cleaned = " ".join(text.split())
    if len(cleaned) < size:
        return {cleaned} if cleaned else set()
    return {cleaned[i : i + size] for i in range(len(cleaned) - size + 1)}


def jaccard_overlap(arguments_text: str, dirty_text: str) -> float:
    """8-gram Jaccard similarity between arguments and one dirty sample."""

    left = _ngrams(arguments_text[:_MAX_COMPARE_CHARS])
    right = _ngrams(dirty_text[:_MAX_COMPARE_CHARS])
    if not left or not right:
        return 0.0
    intersection = len(left & right)
    union = len(left | right)
    return intersection / union if union else 0.0


def arg_taint(
    arguments_text: str,
    dirty_samples: list[str],
    *,
    threshold: float = DEFAULT_OVERLAP_THRESHOLD,
) -> int:
    """Return the taint of arguments that materially overlap dirty content.

    Heuristic by design (D §6.1): used ONLY to trigger approval or patrol
    features — never as an authorization basis.
    """

    for sample in dirty_samples:
        if jaccard_overlap(arguments_text, sample) >= threshold:
            return TOOL_RESULT
    return 0


def dirty_text_of(messages: list[tuple[int, str]]) -> list[str]:
    """Extract text of messages carrying dirty bits (for overlap checks)."""

    dirty_bits = WEB_CONTENT | TOOL_RESULT | ATTACHMENT | CANARY_ADJACENT | BOT_PEER | ROOM_SHARED
    return [
        text[:_MAX_COMPARE_CHARS] for taint, text in messages if taint & dirty_bits and text.strip()
    ]


# ---------------------------------------------------------------------------
# Tool-call-time snapshot (turn loop → adapter, via ContextVar)
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ToolTaintSnapshot:
    """Taint state at the moment a tool batch is dispatched.

    Set by the turn loop before tool execution; read lazily by the Orin
    adapter when it builds issue/consume requests. Task-local by design:
    asyncio copies the context into spawned tool tasks, so the snapshot
    follows each batch without crossing sessions.
    """

    context_taint: int = 0
    clearance: int = CLEARANCE_INTERNAL
    dirty_samples: tuple[str, ...] = field(default_factory=tuple)


_current_snapshot: ContextVar[ToolTaintSnapshot | None] = ContextVar(
    "orin_tool_taint_snapshot", default=None
)

_ENTRY_SOURCE_TAINT: ContextVar[int] = ContextVar("orin_entry_source_taint", default=0)


_UNTRUSTED_ENTRY_PREFIXES: Final[tuple[str, ...]] = (
    "telegram",
    "webhook",
    "discord",
    "gateway",
    "friends",
)


def set_entry_source(channel: str) -> object:
    """Tag the entry channel (Orin site 8): cron/daemon ⇒ AUTO_TASK.

    Called by ``run_echo_turn`` — the single Echo turn boundary — so every
    automatic task's user input carries AUTO_TASK instead of plain trust.
    Gateway / messaging channels carry INBOX_CONTENT | WEB_CONTENT so taint
    can only tighten later verdicts.
    """

    if channel.startswith(("cron", "daemon")):
        value = AUTO_TASK
    elif channel.startswith(_UNTRUSTED_ENTRY_PREFIXES):
        value = INBOX_CONTENT | WEB_CONTENT
    else:
        value = 0
    return _ENTRY_SOURCE_TAINT.set(value)


def reset_entry_source(token: object) -> None:
    _ENTRY_SOURCE_TAINT.reset(token)  # type: ignore[arg-type]


def current_entry_source_taint() -> int:
    return _ENTRY_SOURCE_TAINT.get()


def set_tool_taint_snapshot(snapshot: ToolTaintSnapshot | None) -> object:
    """Set (or clear) the current snapshot; returns a reset token."""

    return _current_snapshot.set(snapshot)


def reset_tool_taint_snapshot(token: object) -> None:
    """Reset the snapshot using the token from :func:`set_tool_taint_snapshot`."""

    _current_snapshot.reset(token)  # type: ignore[arg-type]


def current_tool_taint_snapshot() -> ToolTaintSnapshot | None:
    """Read the current snapshot (``None`` when the caller is untagged)."""

    return _current_snapshot.get()


def snapshot_from_messages(
    messages: list[tuple[int, str]],
) -> ToolTaintSnapshot:
    """Build a snapshot from (taint, text) pairs of the active window."""

    context_taint = recompute_context_taint([taint for taint, _ in messages])
    return ToolTaintSnapshot(
        context_taint=context_taint,
        clearance=clearance_of(context_taint),
        dirty_samples=tuple(dirty_text_of(messages)),
    )


# ---------------------------------------------------------------------------
# Tool-result tagging helpers
# ---------------------------------------------------------------------------
METADATA_SECRET_FLAG: Final[str] = "orin_secret"
"""ToolResult.metadata key forcing the SECRET bit on the result message."""

METADATA_TAINT_EXTRA: Final[str] = "orin_taint_extra"
"""ToolResult.metadata key carrying producer-side taint bits (OR-ed in)."""

WEB_RESULT_TOOLS: Final[frozenset[str]] = frozenset(
    {"browser_fetch", "web_search", "webbridge_navigate", "webbridge_read"}
)
WEB_RESULT_PREFIXES: Final[tuple[str, ...]] = ("webbridge_",)
SKILL_TOOLS: Final[frozenset[str]] = frozenset({"skill", "use_skill"})

CREDENTIAL_PATH_PATTERNS: Final[tuple[str, ...]] = (
    ".env",
    ".pem",
    ".p12",
    ".pfx",
    ".key",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credentials.json",
    ".git-credentials",
    "secrets/",
    ".aws/credentials",
    ".ssh/",
    ".gnupg/",
)
"""Deterministic credential-path table (D §6.1 tag point 11)."""

_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|credential)\b\s*[:=]"
)


def path_is_credential(path_text: str) -> bool:
    """True when a path matches the credential pattern table."""

    normalized = path_text.replace("\\\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    for pattern in CREDENTIAL_PATH_PATTERNS:
        if pattern.endswith("/"):
            if f"/{pattern}" in f"/{normalized}" or normalized.startswith(pattern):
                return True
        elif pattern.startswith("."):
            if name == pattern or name.endswith(pattern) or f"/{pattern}" in normalized:
                return True
        elif pattern in normalized:
            return True
    return False


def secret_hint(text: str) -> bool:
    """Deterministic sensitive-value heuristic (never a semantic judgment)."""

    return _SENSITIVE_VALUE_RE.search(text[:_MAX_COMPARE_CHARS]) is not None


def source_taint_for_tool(tool_name: str, metadata: dict[str, Any] | None = None) -> int:
    """Taint bits for one tool-result message (site 2 of the tag table).

    TOOL_RESULT always; WEB_CONTENT for network-fetched content;
    SKILL_CONTENT for skill instructions; SECRET only via explicit
    deterministic markers (credential paths, vault reads).
    """

    bits = TOOL_RESULT
    if tool_name in WEB_RESULT_TOOLS or tool_name.startswith(WEB_RESULT_PREFIXES):
        bits |= WEB_CONTENT
    if tool_name in SKILL_TOOLS:
        bits |= SKILL_CONTENT
    if tool_name in {"bots_ask", "rooms_create"}:
        bits |= ROOM_SHARED
    if tool_name == "bots_ask":
        bits |= BOT_PEER
    if metadata:
        if metadata.get(METADATA_SECRET_FLAG):
            bits |= SECRET
        extra = metadata.get(METADATA_TAINT_EXTRA)
        if isinstance(extra, int) and extra:
            bits |= extra
    return bits


__all__ = [
    "ATTACHMENT",
    "AUTO_TASK",
    "BOT_PEER",
    "BOT_SOUL",
    "CANARY_ADJACENT",
    "CLEARANCE_INTERNAL",
    "CLEARANCE_PUBLIC",
    "CLEARANCE_SECRET",
    "COMPRESSED",
    "DEFAULT_OVERLAP_THRESHOLD",
    "DIRTY_FOR_WRITE",
    "EGRESS_SENSITIVE",
    "FULL_MASK",
    "INBOX_CONTENT",
    "MEMORY_READ",
    "METADATA_SECRET_FLAG",
    "METADATA_TAINT_EXTRA",
    "MODEL_OUTPUT",
    "RESERVED_LOW",
    "RESERVED_MASK",
    "ROOM_SHARED",
    "SECRET",
    "SESSION_CUSTOM_BASE",
    "SKILL_CONTENT",
    "SKILL_TOOLS",
    "TAINT_NAMES",
    "TOOL_RESULT",
    "USER_HISTORY",
    "USER_TURN",
    "WEB_CONTENT",
    "WEB_RESULT_PREFIXES",
    "WEB_RESULT_TOOLS",
    "ToolTaintSnapshot",
    "arg_taint",
    "clearance_of",
    "combine",
    "compressed_summary_taint",
    "current_entry_source_taint",
    "current_tool_taint_snapshot",
    "describe",
    "dirty_text_of",
    "jaccard_overlap",
    "path_is_credential",
    "recompute_context_taint",
    "reset_entry_source",
    "reset_tool_taint_snapshot",
    "secret_hint",
    "set_entry_source",
    "set_tool_taint_snapshot",
    "snapshot_from_messages",
    "source_taint_for_tool",
]
