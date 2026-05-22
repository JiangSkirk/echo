"""Chunk and compress external documents into ≤3k-token Markdown segments."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class Chunk:
    """A single Markdown chunk ready for memory ingestion."""

    id: str
    source: str
    title: str
    body: str
    token_estimate: int
    url: str = ""
    metadata: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}


class MarkdownChunker:
    """Split documents into ~3k-token Markdown chunks.

    Strategy:
    1. Convert raw content to clean Markdown.
    2. Split on logical boundaries (headers, paragraphs, code blocks).
    3. Greedy-merge small pieces until near the token limit.
    4. Compress oversized single pieces by truncation with ellipsis.
    """

    TOKEN_LIMIT = 3000
    # Safety margin so we never exceed 3k with real tokenizers
    TARGET_TOKENS = 2800

    def __init__(self, token_limit: int | None = None) -> None:
        self.target = token_limit or self.TARGET_TOKENS

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Fast approximate token count without tiktoken."""
        if not text:
            return 0
        # CJK characters ~1 token each
        cjk = len(re.findall(r"[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af]", text))
        # English-ish words
        words = len(re.findall(r"[a-zA-Z]+", text))
        # Everything else (digits, punctuation, whitespace, symbols)
        other = len(text) - cjk - sum(len(w) for w in re.findall(r"[a-zA-Z]+", text))
        base = int(cjk + words * 1.3 + max(other, 0) * 0.5)
        # Safety floor: long runs of identical characters fool the word counter
        floor = len(text) // 4
        return max(base, floor)

    def chunk(self, source: str, title: str, content: str, url: str = "", metadata: dict[str, Any] | None = None) -> list[Chunk]:
        """Turn raw content into a list of Chunk objects."""
        metadata = metadata or {}
        content = self._to_markdown(content)
        pieces = self._split_into_pieces(content)
        merged = self._greedy_merge(pieces)
        chunks: list[Chunk] = []
        for idx, body in enumerate(merged):
            body = body.strip()
            if not body:
                continue
            tok = self.estimate_tokens(body)
            chunks.append(
                Chunk(
                    id=f"{source}:{metadata.get('raw_id', '')}:{idx}",
                    source=source,
                    title=title if idx == 0 else f"{title} (part {idx + 1})",
                    body=body,
                    token_estimate=tok,
                    url=url,
                    metadata={**metadata, "chunk_index": idx, "chunk_total": len(merged)},
                )
            )
        return chunks

    @classmethod
    def _to_markdown(cls, text: str) -> str:
        """Minimal normalization: strip excessive whitespace, ensure line endings."""
        text = text.replace("\r\n", "\n")
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    @classmethod
    def _split_into_pieces(cls, text: str) -> list[str]:
        """Split on headers, code fences, and double-newlines."""
        # Split by markdown headers or code fences, keeping delimiters
        pattern = r"(?=\n#{1,6}\s)|(?=\n```)|(?<=\n```\n)"
        parts = re.split(pattern, text)
        pieces: list[str] = []
        for part in parts:
            if "\n\n" in part:
                pieces.extend(part.split("\n\n"))
            else:
                pieces.append(part)
        return [p.strip() for p in pieces if p.strip()]

    def _greedy_merge(self, pieces: list[str]) -> list[str]:
        """Merge adjacent small pieces until near token limit."""
        if not pieces:
            return []
        result: list[str] = []
        buffer = pieces[0]
        buf_tok = self.estimate_tokens(buffer)
        for piece in pieces[1:]:
            piece_tok = self.estimate_tokens(piece)
            if buf_tok + piece_tok <= self.target:
                buffer += "\n\n" + piece
                buf_tok += piece_tok
            else:
                result.append(self._truncate_if_needed(buffer))
                buffer = piece
                buf_tok = piece_tok
        if buffer:
            result.append(self._truncate_if_needed(buffer))
        return result

    def _truncate_if_needed(self, text: str) -> str:
        """If a single piece exceeds limit, truncate with ellipsis."""
        tok = self.estimate_tokens(text)
        if tok <= self.TOKEN_LIMIT:
            return text
        # Binary search for a character cutoff that lands under limit
        low, high = 0, len(text)
        while low < high:
            mid = (low + high + 1) // 2
            if self.estimate_tokens(text[:mid]) <= self.TOKEN_LIMIT:
                low = mid
            else:
                high = mid - 1
        return text[:low].rstrip() + "\n\n… *(truncated)*"
