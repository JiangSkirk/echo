"""Lightweight routine discovery from repeated explicit work."""

from __future__ import annotations

from hashlib import sha256
from typing import Any, cast

from js_work.routines.models import WorkRoutine
from js_work.routines.store import WorkRoutineStore


class WorkRoutineMiner:
    """Create disabled routine drafts after repeated similar observations."""

    def __init__(self, store: WorkRoutineStore, *, threshold: int = 3) -> None:
        self.store = store
        self.threshold = threshold
        self.path = store.routines_dir / "observations.json"

    def observe(
        self,
        *,
        task_text: str,
        routine_type: str,
        trigger_phrase: str,
        field_mapping: dict[str, str],
        validation_rules: dict[str, Any] | None = None,
    ) -> WorkRoutine | None:
        key = self._key(routine_type, trigger_phrase)
        deterministic_routine_id = f"routine-{key}"

        def update(observations: dict[str, Any]) -> dict[str, Any]:
            raw_entry = observations.get(key)
            entry = dict(raw_entry) if isinstance(raw_entry, dict) else {}
            if not entry.get("routine_id"):
                entry.setdefault("count", 0)
                entry.setdefault("task_text", task_text)
                entry.setdefault("routine_type", routine_type)
                entry.setdefault("trigger_phrase", trigger_phrase)
                entry.setdefault("field_mapping", dict(field_mapping))
                entry.setdefault("validation_rules", dict(validation_rules or {}))
                entry["count"] = int(entry.get("count", 0)) + 1
                if entry["count"] >= self.threshold:
                    entry["routine_id"] = deterministic_routine_id
            observations[key] = entry
            return observations

        observations = self.store.mutate_miner_observations(update)
        raw_entry = observations.get(key)
        if not isinstance(raw_entry, dict):
            return None
        entry = raw_entry
        routine_id = entry.get("routine_id")
        if not isinstance(routine_id, str) or not routine_id:
            return None

        try:
            return self.store.get(routine_id)
        except KeyError:
            pass

        stored_mapping = entry.get("field_mapping")
        stored_validation = entry.get("validation_rules")
        try:
            return self.store.create_draft(
                routine_id=routine_id,
                name=str(entry.get("trigger_phrase") or trigger_phrase),
                trigger_phrases=[str(entry.get("trigger_phrase") or trigger_phrase)],
                routine_type=str(entry.get("routine_type") or routine_type),
                field_mapping=(
                    cast("dict[str, str]", stored_mapping)
                    if isinstance(stored_mapping, dict)
                    else field_mapping
                ),
                validation_rules=(
                    cast("dict[str, Any]", stored_validation)
                    if isinstance(stored_validation, dict)
                    else validation_rules or {}
                ),
            )
        except FileExistsError:
            return self.store.get(routine_id)

    def _load(self) -> dict[str, Any]:
        return self.store.load_miner_observations()

    def _save(self, observations: dict[str, Any]) -> None:
        self.store.save_miner_observations(observations)

    @staticmethod
    def _key(routine_type: str, trigger_phrase: str) -> str:
        raw = f"{routine_type}:{trigger_phrase.strip().lower()}"
        return sha256(raw.encode("utf-8")).hexdigest()[:16]
