"""LLMLingua-style prompt compaction. Default off; no GPU required.

Caps compression at 10× (keep at least 10% of the original). Without a
local compressor model this module uses a stopword heuristic, which is
the documented fallback — it never imports ``llmlingua`` or torch.
"""

from __future__ import annotations

import math
import re
from typing import Final

MAX_COMPRESSION_RATIO: Final[float] = 10.0
_IDENT = re.compile(r"[A-Za-z0-9_./:@-]{3,}")
_TOKEN = re.compile(r"\S+")
_STOP: Final[frozenset[str]] = frozenset(
    {
        "a",
        "an",
        "the",
        "and",
        "or",
        "of",
        "to",
        "in",
        "for",
        "on",
        "at",
        "by",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "this",
        "that",
        "with",
        "as",
        "from",
        "it",
        "its",
    }
)


def clamp_ratio(max_ratio: float) -> float:
    if max_ratio > MAX_COMPRESSION_RATIO:
        return MAX_COMPRESSION_RATIO
    if max_ratio < 1.0:
        return 1.0
    return max_ratio


def gpu_available() -> bool:
    """P3-1 never requires a GPU. Always false so callers stay on the heuristic."""

    return False


def compact_text(text: str, *, max_ratio: float = MAX_COMPRESSION_RATIO) -> str:
    """Extractive compact. Never shrinks past ``len(text) / max_ratio``."""

    if not text:
        return text
    ratio = clamp_ratio(max_ratio)
    floor = max(1, math.ceil(len(text) / ratio))
    kept: list[str] = []
    for token in _TOKEN.findall(text):
        lower = token.lower().strip(".,;:!?")
        if lower in _STOP and not _IDENT.fullmatch(token):
            continue
        kept.append(token)
    compacted = " ".join(kept) if kept else text[:floor]
    if len(compacted) < floor:
        return text[:floor]
    return compacted


def compact_bytes(payload: bytes, *, max_ratio: float = MAX_COMPRESSION_RATIO) -> bytes:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return payload
    return compact_text(text, max_ratio=max_ratio).encode("utf-8")
