"""Data models for JS Agent Work routines."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class RoutineStatus(StrEnum):
    """Lifecycle state for Work-native routines."""

    DRAFT = "draft"
    ENABLED = "enabled"
    DISABLED = "disabled"


@dataclass
class WorkRoutine:
    """A narrow, auditable Work routine. This is not a JS Agent skill."""

    routine_id: str
    name: str
    trigger_phrases: list[str]
    routine_type: str
    status: RoutineStatus = RoutineStatus.DRAFT
    version: int = 1
    field_mapping: dict[str, str] = field(default_factory=dict)
    extraction_rules: dict[str, Any] = field(default_factory=dict)
    statistics: dict[str, Any] = field(default_factory=dict)
    validation_rules: dict[str, Any] = field(default_factory=dict)
    row_filters: list[dict[str, Any]] = field(default_factory=list)
    header_aliases: dict[str, list[str]] = field(default_factory=dict)
    aggregation_rules: dict[str, Any] = field(default_factory=dict)
    source_sheet: str = ""
    review_policy: dict[str, Any] = field(default_factory=dict)
    output_naming: dict[str, Any] = field(default_factory=dict)
    template_path: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    @property
    def enabled(self) -> bool:
        return self.status == RoutineStatus.ENABLED

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorkRoutine:
        payload = dict(data)
        payload["status"] = RoutineStatus(payload.get("status", RoutineStatus.DRAFT.value))
        payload.setdefault("row_filters", [])
        payload.setdefault("header_aliases", {})
        payload.setdefault("aggregation_rules", {})
        payload.setdefault("source_sheet", "")
        payload.setdefault("review_policy", {})
        return cls(**payload)


@dataclass(frozen=True)
class RoutineRunResult:
    """Result returned by a routine runner."""

    status: str
    output_path: str
    report_path: str
    row_count: int
    issues: list[dict[str, Any]]
    reviewer: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
