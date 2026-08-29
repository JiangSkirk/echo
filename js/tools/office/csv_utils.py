"""CSV encoding and budget helpers for Office tools."""

from __future__ import annotations

import codecs
import os
import threading

_CSV_FIELD_SIZE_LOCK = threading.Lock()
_CSV_ALLOWED_ENCODINGS = frozenset(
    {
        "utf-8",
        "utf-8-sig",
        "utf-16",
        "utf-16-le",
        "utf-16-be",
        "ascii",
        "latin-1",
        "iso-8859-1",
    }
)
_GENERIC_CSV_ALLOWED_ENCODINGS = _CSV_ALLOWED_ENCODINGS | frozenset({"gbk"})

def _validate_csv_encoding(encoding: object, *, work_runtime: bool) -> str:
    if type(encoding) is not str:
        raise TypeError("encoding must be a string")
    normalized = encoding.strip().lower().replace("_", "-")
    allowed = _CSV_ALLOWED_ENCODINGS if work_runtime else _GENERIC_CSV_ALLOWED_ENCODINGS
    if normalized not in allowed:
        raise ValueError(f"Unsupported or unsafe CSV encoding: {encoding}")
    try:
        canonical = codecs.lookup(normalized).name
        decoder = codecs.getincrementaldecoder(canonical)(errors="strict")
        if not isinstance(decoder.decode(b"", final=False), str):
            raise TypeError("CSV codec must decode bytes to text")
    except (LookupError, TypeError) as exc:
        raise ValueError(f"Unsupported or unsafe CSV encoding: {encoding}") from exc
    return canonical


def _csv_file_fingerprint(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _csv_reader_pending_limits(
    *,
    max_bytes: int,
    max_field_chars: int,
    max_columns: int,
) -> tuple[int, int]:
    quote_overhead = 2
    per_field = max_field_chars + quote_overhead
    delimiter_budget = max(max_columns - 1, 0)
    max_physical_line_chars = min(
        max_bytes,
        max_columns * per_field + delimiter_budget,
    )
    max_pending_chars = min(
        max_bytes,
        max_columns * (max_field_chars * 2 + quote_overhead) + delimiter_budget + 1,
    )
    return max_physical_line_chars, max(max_pending_chars, max_physical_line_chars)

