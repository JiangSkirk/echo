"""Incremental binary CSV reader."""

from __future__ import annotations

import codecs
import os
from collections.abc import Iterator

from js.tools.office.csv_utils import _csv_file_fingerprint, _csv_reader_pending_limits


class _BinaryIncrementalCSVReader:
    """Binary byte counter feeding an incremental text decoder for csv.reader."""

    _CHUNK_SIZE = 64 * 1024

    def __init__(
        self,
        fd: int,
        encoding: str,
        *,
        max_bytes: int,
        max_field_chars: int = 10_000,
        max_columns: int = 256,
        expected_fingerprint: tuple[int, int, int, int, int] | None = None,
    ) -> None:
        self._fd = fd
        self._decoder = codecs.getincrementaldecoder(encoding)()
        self.bytes_read = 0
        self._max_bytes = max_bytes
        self._pending = ""
        self._eof = False
        self._expected_fingerprint = expected_fingerprint
        self.changed = False
        self.max_physical_line_chars, self.max_pending_chars = _csv_reader_pending_limits(
            max_bytes=max_bytes,
            max_field_chars=max_field_chars,
            max_columns=max_columns,
        )
        self.pending_high_water = 0
        self._decoded_pushback = ""

    @property
    def fd_offset(self) -> int:
        return os.lseek(self._fd, 0, os.SEEK_CUR)

    def fileno(self) -> int:
        return self._fd

    def close(self) -> None:
        os.close(self._fd)

    def _decoder_held_bytes(self) -> int:
        """Bytes retained inside the incremental decoder (``getstate()`` buffer)."""
        try:
            state = self._decoder.getstate()
        except (AttributeError, TypeError, ValueError):
            return 0
        if isinstance(state, tuple) and state and isinstance(state[0], (bytes, bytearray)):
            return len(state[0])
        if isinstance(state, (bytes, bytearray)):
            return len(state)
        return 0

    def _unified_buffer_chars(self) -> int:
        """Decoded buffers plus decoder-held bytes under one hard pending budget.

        Incomplete multibyte sequences kept by ``IncrementalDecoder.getstate()``
        count toward the same hard cap as ``_pending`` / ``_decoded_pushback`` so
        they cannot bypass the budget. The held-byte count is taken directly from
        ``getstate()[0]`` — not via ``_decoder_held_bytes`` — so stubbing the
        helper cannot hide decoder buffer pressure.
        """
        held = 0
        try:
            state = self._decoder.getstate()
        except (AttributeError, TypeError, ValueError):
            state = None
        if isinstance(state, tuple) and state and isinstance(state[0], (bytes, bytearray)):
            held = len(state[0])
        elif isinstance(state, (bytes, bytearray)):
            held = len(state)
        return len(self._pending) + len(self._decoded_pushback) + held

    def _physical_content_len(self, text: str | None = None) -> int:
        """Content length excluding a pending/complete LF or CRLF terminator."""
        pending = self._pending if text is None else text
        if pending.endswith("\r\n"):
            return len(pending) - 2
        if pending.endswith("\n"):
            return len(pending) - 1
        if pending.endswith("\r") and not self._eof:
            # Bare CR may be the first half of CRLF while more input remains.
            return len(pending) - 1
        return len(pending)

    def _assert_stable(self) -> None:
        if self._expected_fingerprint is None:
            return
        current = _csv_file_fingerprint(os.fstat(self._fd))
        if current != self._expected_fingerprint:
            self.changed = True
            raise ValueError("CSV file changed during read")

    def _read_binary(self, size: int | None = None) -> bytes:
        if self._eof:
            return b""
        self._assert_stable()
        remaining = self._max_bytes - self.bytes_read
        if remaining < 0:
            raise ValueError("CSV content exceeds byte limit during parse")
        to_read = min(self._CHUNK_SIZE, remaining + 1)
        if size is not None:
            if size < 0:
                raise ValueError("invalid CSV read size")
            to_read = min(to_read, size)
        if to_read <= 0:
            return b""
        chunk = os.read(self._fd, to_read)
        if not chunk:
            self._eof = True
            self._assert_stable()
            return b""
        self.bytes_read += len(chunk)
        if self.bytes_read > self._max_bytes:
            raise ValueError("CSV content exceeds byte limit during parse")
        self._assert_stable()
        return chunk

    def _note_pending_size(self) -> None:
        pending_len = self._unified_buffer_chars()
        if pending_len > self.pending_high_water:
            self.pending_high_water = pending_len

    def _check_pending_limits(self, *, physical_line: bool) -> None:
        self._note_pending_size()
        if self._unified_buffer_chars() > self.max_pending_chars:
            raise ValueError("CSV pending buffer exceeds limit during parse")
        if (
            physical_line
            and "\n" not in self._pending
            and self._physical_content_len() > self.max_physical_line_chars
        ):
            raise ValueError("CSV physical line exceeds length limit during parse")

    def _char_fill_budget(self, *, char_limit: int | None) -> int:
        """Chars that may still enter the unified buffer without crossing hard caps."""
        unified_room = self.max_pending_chars - self._unified_buffer_chars()
        # Physical-line room applies to unfinished content (LF/CRLF terminator excluded).
        physical_room = self.max_physical_line_chars - self._physical_content_len()
        # Reserve one unit when a CR is held as a potential CRLF lead-in.
        if self._pending.endswith("\r") and "\n" not in self._pending:
            physical_room = max(physical_room, 1)
        room = min(unified_room, physical_room)
        if char_limit is not None:
            room = min(room, char_limit - len(self._pending))
        return max(0, room)

    def _store_pushback(self, text: str) -> None:
        """Store pushback only within the unified pending hard budget."""
        if not text:
            return
        room = self.max_pending_chars - self._unified_buffer_chars()
        if room <= 0:
            raise ValueError("CSV pending buffer exceeds limit during parse")
        if len(text) > room:
            # Refuse to hide overshoot in a second buffer.
            raise ValueError("CSV pending buffer exceeds limit during parse")
        self._decoded_pushback = text + self._decoded_pushback
        self._note_pending_size()

    def _append_pending_chars(self, text: str, *, budget: int) -> None:
        """Append at most ``budget`` chars into ``_pending``.

        Leftover may enter pushback only when the unified hard pending budget still
        has room; otherwise raise without hiding overshoot in a second buffer.
        """
        if not text:
            return
        if budget <= 0:
            raise ValueError("CSV pending buffer exceeds limit during parse")
        if len(text) <= budget:
            self._pending += text
            self._note_pending_size()
            return
        self._pending += text[:budget]
        leftover = text[budget:]
        room = self.max_pending_chars - self._unified_buffer_chars()
        if len(leftover) > room:
            self._note_pending_size()
            raise ValueError(
                "CSV physical line exceeds length limit during parse"
                if len(self._pending) >= self.max_physical_line_chars
                else "CSV pending buffer exceeds limit during parse"
            )
        self._decoded_pushback = leftover + self._decoded_pushback
        self._note_pending_size()

    def _fill_pending_bounded(self, *, char_limit: int | None) -> bool:
        """Read more input into ``_pending`` without exceeding hard caps.

        Returns True when any progress was made (chars appended or EOF reached).
        """
        budget = self._char_fill_budget(char_limit=char_limit)
        if budget <= 0:
            return False
        if self._decoded_pushback:
            take = self._decoded_pushback[:budget]
            self._decoded_pushback = self._decoded_pushback[budget:]
            self._pending += take
            self._note_pending_size()
            return True
        remaining = self._max_bytes - self.bytes_read
        if remaining < 0:
            raise ValueError("CSV content exceeds byte limit during parse")
        # Prefer 1 byte/char reads so ASCII cannot overshoot; multibyte scalars that
        # decode to fewer chars simply continue the fill loop.
        byte_budget = min(self._CHUNK_SIZE, remaining + 1, max(budget, 1))
        if byte_budget <= 0:
            self._eof = True
            return True
        chunk = self._read_binary(size=byte_budget)
        if not chunk:
            return True
        decoded = self._decoder.decode(chunk)
        # Decoder-held incomplete sequences count toward the unified hard budget.
        self._check_pending_limits(physical_line=True)
        if not decoded:
            return True
        self._append_pending_chars(decoded, budget=budget)
        return True

    def _peek_one_char(self) -> str:
        """Consume at most one decoded character without exceeding the unified budget."""
        if self._decoded_pushback:
            ch = self._decoded_pushback[0]
            self._decoded_pushback = self._decoded_pushback[1:]
            return ch
        remaining = self._max_bytes - self.bytes_read
        if remaining <= 0:
            return ""
        # Read up to 4 bytes for one UTF-8 scalar; hold incomplete sequences in decoder only.
        while True:
            # Refuse reads that would let decoder-held bytes bypass the hard budget.
            if self._unified_buffer_chars() >= self.max_pending_chars:
                return ""
            peek = self._read_binary(size=min(4, remaining + 1))
            if not peek:
                final = self._decoder.decode(b"", final=True)
                self._check_pending_limits(physical_line=False)
                return final[:1] if final else ""
            decoded = self._decoder.decode(peek)
            self._check_pending_limits(physical_line=False)
            if not decoded:
                remaining = self._max_bytes - self.bytes_read
                if remaining <= 0:
                    return ""
                continue
            if len(decoded) == 1:
                return decoded
            # Extra decoded chars must fit the unified budget as pushback.
            self._store_pushback(decoded[1:])
            return decoded[0]

    def _accept_line_terminator_at_cap(self, first: str) -> bool:
        """Accept LF or CRLF as the terminator for an exact-length physical line."""
        if self._physical_content_len() != self.max_physical_line_chars:
            return False
        if first == "\n":
            self._pending += "\n"
            self._note_pending_size()
            return True
        if first == "\r":
            second = self._peek_one_char()
            if second == "\n":
                self._pending += "\r\n"
                self._note_pending_size()
                return True
            # Lone CR / CR+non-LF is not a completing terminator; discard lookahead.
            return False
        return False

    def _reject_if_past_hard_line_cap(self) -> None:
        """At the hard line/pending cap without a newline, accept only LF/CRLF.

        Exact ``max_physical_line_chars`` of content followed by ``\\n`` or ``\\r\\n``
        is legal. Exact content at EOF (no terminator) is also legal. Any other
        following character is oversize. Lookahead never stores excess past the
        unified pending hard budget (including decoder ``getstate()`` bytes).
        """
        if "\n" in self._pending:
            return
        content_len = self._physical_content_len()
        if content_len < self.max_physical_line_chars and self._unified_buffer_chars() < (
            self.max_pending_chars
        ):
            return
        at_physical_cap = content_len >= self.max_physical_line_chars
        at_pending_cap = self._unified_buffer_chars() >= self.max_pending_chars
        if not at_physical_cap and not at_pending_cap:
            return
        if at_pending_cap and not at_physical_cap and not self._decoded_pushback:
            if self._decoder_held_bytes() > 0:
                raise ValueError("CSV pending buffer exceeds limit during parse")
            # Pending unified buffer is full without completing a physical line.
            raise ValueError("CSV pending buffer exceeds limit during parse")
        peeked = self._peek_one_char()
        if not peeked:
            # EOF at exact content length is a legal final physical line.
            return
        if at_physical_cap and self._accept_line_terminator_at_cap(peeked):
            return
        # Oversize content — do not retain the excess character in any buffer.
        raise ValueError(
            "CSV physical line exceeds length limit during parse"
            if at_physical_cap
            else "CSV pending buffer exceeds limit during parse"
        )

    def readline(self, size: int = -1) -> str:
        if size == 0:
            return ""
        char_limit = None if size < 0 else size
        while "\n" not in self._pending and not self._eof:
            if char_limit is not None and len(self._pending) >= char_limit:
                break
            budget = self._char_fill_budget(char_limit=char_limit)
            if budget <= 0:
                self._reject_if_past_hard_line_cap()
                break
            progressed = self._fill_pending_bounded(char_limit=char_limit)
            self._check_pending_limits(physical_line=True)
            if not progressed:
                break
        if not self._pending and self._eof and not self._decoded_pushback:
            final = self._decoder.decode(b"", final=True)
            if final:
                budget = self._char_fill_budget(char_limit=char_limit)
                if budget <= 0:
                    # Exact-cap + leftover final decode: only LF/CRLF may complete.
                    if self._physical_content_len() == self.max_physical_line_chars and (
                        final.startswith("\n") or final.startswith("\r\n")
                    ):
                        if final.startswith("\r\n"):
                            self._pending += "\r\n"
                            rest = final[2:]
                        else:
                            self._pending += "\n"
                            rest = final[1:]
                        if rest:
                            self._store_pushback(rest)
                        self._note_pending_size()
                    else:
                        raise ValueError(
                            "CSV physical line exceeds length limit during parse"
                            if self._physical_content_len() >= self.max_physical_line_chars
                            else "CSV pending buffer exceeds limit during parse"
                        )
                else:
                    self._append_pending_chars(final, budget=budget)
                    self._check_pending_limits(physical_line="\n" not in self._pending)
            elif self._decoder_held_bytes() > 0:
                raise ValueError("CSV pending buffer exceeds limit during parse")
        if not self._pending and self._decoded_pushback:
            budget = self._char_fill_budget(char_limit=char_limit)
            if budget <= 0:
                self._reject_if_past_hard_line_cap()
            else:
                take = self._decoded_pushback[:budget]
                self._decoded_pushback = self._decoded_pushback[budget:]
                self._pending += take
                self._note_pending_size()
                self._check_pending_limits(physical_line="\n" not in self._pending)
        if not self._pending:
            return ""
        # Prefer returning a complete physical line before rejecting leftover short rows.
        newline_at = self._pending.find("\n")
        if newline_at >= 0:
            if char_limit is not None and newline_at >= char_limit:
                line = self._pending[:char_limit]
                self._pending = self._pending[char_limit:]
                self._note_pending_size()
                return line
            line = self._pending[: newline_at + 1]
            if self._physical_content_len(line) > self.max_physical_line_chars:
                raise ValueError("CSV physical line exceeds length limit during parse")
            self._pending = self._pending[newline_at + 1 :]
            self._note_pending_size()
            return line
        if char_limit is not None and len(self._pending) > char_limit:
            line = self._pending[:char_limit]
            self._pending = self._pending[char_limit:]
            self._note_pending_size()
            return line
        self._reject_if_past_hard_line_cap()
        if "\n" in self._pending:
            newline_at = self._pending.find("\n")
            line = self._pending[: newline_at + 1]
            self._pending = self._pending[newline_at + 1 :]
            self._note_pending_size()
            return line
        # Exact-length final line at EOF (no LF/CRLF) is legal.
        if (
            self._eof
            and not self._decoded_pushback
            and self._decoder_held_bytes() == 0
            and self._physical_content_len() > self.max_physical_line_chars
        ):
            raise ValueError("CSV physical line exceeds length limit during parse")
        line = self._pending
        self._pending = ""
        self._note_pending_size()
        return line

    def __iter__(self) -> Iterator[str]:
        return self

    def __next__(self) -> str:
        line = self.readline()
        if line == "":
            raise StopIteration
        return line
