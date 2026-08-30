"""Adapter cases: JSONL schema, held-out split, taint name parsing."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

from js.orin import taint as taint_mod

CaseSplit = Literal["ci", "held_out"]

_TAINT_LOOKUP: Final[dict[str, int]] = {
    "USER_TURN": taint_mod.USER_TURN,
    "USER_HISTORY": taint_mod.USER_HISTORY,
    "TOOL_RESULT": taint_mod.TOOL_RESULT,
    "WEB_CONTENT": taint_mod.WEB_CONTENT,
    "ATTACHMENT": taint_mod.ATTACHMENT,
    "MEMORY_READ": taint_mod.MEMORY_READ,
    "SKILL_CONTENT": taint_mod.SKILL_CONTENT,
    "MODEL_OUTPUT": taint_mod.MODEL_OUTPUT,
    "INBOX_CONTENT": taint_mod.INBOX_CONTENT,
    "SECRET": taint_mod.SECRET,
    "DIRTY_FOR_WRITE": taint_mod.DIRTY_FOR_WRITE,
    "EGRESS_SENSITIVE": taint_mod.EGRESS_SENSITIVE,
}


@dataclass(frozen=True, slots=True)
class AdapterCase:
    id: str
    suite: str
    split: CaseSplit
    agentdojo_tool: str
    user_task: str
    injected: str
    context_taint: int
    arg_taint: int
    args_overlap_dirty: bool
    attack: bool
    source: str
    payload: str = ""

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> AdapterCase:
        split = str(row.get("split") or "ci")
        if split not in {"ci", "held_out"}:
            raise ValueError(f"invalid case split: {split}")
        return cls(
            id=str(row["id"]),
            suite=str(row.get("suite") or "workspace"),
            split=split,  # type: ignore[arg-type]
            agentdojo_tool=str(row["agentdojo_tool"]),
            user_task=str(row.get("user_task") or ""),
            injected=str(row.get("injected") or ""),
            context_taint=parse_taint_names(row.get("context_taint") or "USER_TURN"),
            arg_taint=parse_taint_names(row.get("arg_taint") or "0"),
            args_overlap_dirty=bool(row.get("args_overlap_dirty")),
            attack=bool(row.get("attack")),
            source=str(row.get("source") or "adapter"),
            payload=str(row.get("payload") or ""),
        )


def parse_taint_names(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    text = str(value or "").strip()
    if not text or text == "0":
        return 0
    bits = 0
    for part in text.split("|"):
        name = part.strip()
        if not name:
            continue
        if name not in _TAINT_LOOKUP:
            raise ValueError(f"unknown taint name: {name}")
        bits |= _TAINT_LOOKUP[name]
    return bits


def load_cases(path: Path, *, split: CaseSplit | None = None) -> tuple[AdapterCase, ...]:
    cases: list[AdapterCase] = []
    seen: set[str] = set()
    for row in _read_jsonl(path):
        case = AdapterCase.from_row(row)
        if case.id in seen:
            raise ValueError(f"duplicate adapter case id: {case.id}")
        seen.add(case.id)
        if split is not None and case.split != split:
            continue
        cases.append(case)
    return tuple(cases)


def iter_corpus_prompt_rows(path: Path, *, limit: int) -> Iterator[dict[str, str]]:
    """Stream prompt-category rows from the adversarial corpus (offline subset)."""

    if limit < 1:
        return
    taken = 0
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if taken >= limit:
                return
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if not isinstance(row, dict) or row.get("category") != "prompt":
                continue
            yield {str(key): str(value) for key, value in row.items()}
            taken += 1


def _read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line:
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number} is not an object")
            yield row
