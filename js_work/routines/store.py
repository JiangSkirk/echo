"""Persistent store for Work-native routines."""

from __future__ import annotations

import re
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from js.echo.attachment_gate import owner_slug, session_slug
from js_work.routines.json_store import RoutineJsonDirectory
from js_work.routines.models import RoutineStatus, WorkRoutine

DEFAULT_WORK_OWNER_KEY_HASH = "js-work-local"
DEFAULT_WORK_SESSION_ID = "default"
_MAX_ROUTINE_ID_LEN = 64
_ROUTINE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def validate_routine_id(routine_id: str) -> str:
    """Reject path traversal, separators, absolute paths, and illegal ids."""
    if not isinstance(routine_id, str) or not routine_id:
        raise ValueError("invalid routine_id")
    if len(routine_id) > _MAX_ROUTINE_ID_LEN:
        raise ValueError("invalid routine_id: too long")
    if routine_id.startswith(("/", "\\", "~")) or Path(routine_id).is_absolute():
        raise ValueError("invalid routine_id: absolute paths are not allowed")
    if "/" in routine_id or "\\" in routine_id:
        raise ValueError("invalid routine_id: path separators are not allowed")
    if ".." in routine_id:
        raise ValueError("invalid routine_id: path traversal is not allowed")
    if not _ROUTINE_ID_RE.fullmatch(routine_id):
        raise ValueError("invalid routine_id: illegal characters")
    return routine_id


class WorkRoutineStore:
    """JSON-backed routine store under ``state/routines/<owner>/<session>``.

    Routine definitions (draft/approve/disable) are partitioned by
    owner AND session, as required by the product isolation baseline
    (product + owner + session).  Execution artifacts (inputs, outputs,
    reports, locks) are session-scoped via ``WorkOwnerFileScope``.
    """

    def __init__(
        self,
        state_dir: Path,
        *,
        owner_key_hash: str | None = None,
        session_id: str | None = None,
    ) -> None:
        self.state_dir = state_dir
        self.owner_key_hash = owner_key_hash or DEFAULT_WORK_OWNER_KEY_HASH
        self.owner_dir_slug = owner_slug(self.owner_key_hash)
        self.session_id = session_id or DEFAULT_WORK_SESSION_ID
        self.session_dir_slug = session_slug(self.session_id)
        self.routines_dir = state_dir / "routines" / self.owner_dir_slug / self.session_dir_slug
        self._records = RoutineJsonDirectory(
            state_dir / "routines" / self.owner_dir_slug,
            self.session_dir_slug,
        )

    def _path(self, routine_id: str) -> Path:
        safe_id = validate_routine_id(routine_id)
        return self.routines_dir / f"{safe_id}.json"

    def create_draft(
        self,
        *,
        routine_id: str | None = None,
        name: str,
        trigger_phrases: list[str],
        routine_type: str,
        field_mapping: dict[str, str] | None = None,
        extraction_rules: dict[str, Any] | None = None,
        statistics: dict[str, Any] | None = None,
        validation_rules: dict[str, Any] | None = None,
        row_filters: list[dict[str, Any]] | None = None,
        header_aliases: dict[str, list[str]] | None = None,
        aggregation_rules: dict[str, Any] | None = None,
        source_sheet: str = "",
        review_policy: dict[str, Any] | None = None,
        output_naming: dict[str, Any] | None = None,
        template_path: str = "",
    ) -> WorkRoutine:
        resolved_routine_id = (
            validate_routine_id(routine_id)
            if routine_id is not None
            else f"routine-{uuid.uuid4().hex[:12]}"
        )
        routine = WorkRoutine(
            routine_id=resolved_routine_id,
            name=name,
            trigger_phrases=trigger_phrases,
            routine_type=routine_type,
            status=RoutineStatus.DRAFT,
            field_mapping=field_mapping or {},
            extraction_rules=extraction_rules or {},
            statistics=statistics or {},
            validation_rules=validation_rules or {},
            row_filters=row_filters or [],
            header_aliases=header_aliases or {},
            aggregation_rules=aggregation_rules or {},
            source_sheet=source_sheet,
            review_policy=review_policy or {},
            output_naming=output_naming or {},
            template_path=template_path,
        )
        routine.updated_at = time.time()
        self._records.write(
            routine.routine_id,
            routine.to_dict(),
            create_only=True,
        )
        return routine

    def load_miner_observations(self) -> dict[str, Any]:
        """Read owner-scoped routine-miner observations safely."""
        return self._records.read("observations") or {}

    def save_miner_observations(self, observations: dict[str, Any]) -> None:
        """Atomically replace owner-scoped routine-miner observations."""
        self._records.write("observations", observations)

    def mutate_miner_observations(
        self,
        transform: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        """Serialize one observation read-modify-write across processes."""
        return self._records.upsert_mutate("observations", transform)

    def save(self, routine: WorkRoutine) -> WorkRoutine:
        routine.updated_at = time.time()
        validate_routine_id(routine.routine_id)
        self._records.write(routine.routine_id, routine.to_dict())
        return routine

    def get(self, routine_id: str) -> WorkRoutine:
        safe_id = validate_routine_id(routine_id)
        data = self._records.read(safe_id)
        if data is None or data.get("routine_id") != safe_id:
            raise KeyError(f"routine not found: {routine_id}")
        try:
            return WorkRoutine.from_dict(data)
        except (KeyError, TypeError, ValueError) as exc:
            raise KeyError(f"routine not found: {routine_id}") from exc

    def list_routines(self) -> list[WorkRoutine]:
        routines: list[WorkRoutine] = []
        for data in self._records.list_records():
            routine_id = data.get("routine_id")
            if not isinstance(routine_id, str):
                continue
            try:
                validate_routine_id(routine_id)
                routines.append(WorkRoutine.from_dict(data))
            except (KeyError, TypeError, ValueError):
                continue
        return sorted(routines, key=lambda item: item.created_at)

    def approve(self, routine_id: str) -> WorkRoutine:
        return self._set_status(routine_id, RoutineStatus.ENABLED)

    def disable(self, routine_id: str) -> WorkRoutine:
        return self._set_status(routine_id, RoutineStatus.DISABLED)

    def _set_status(self, routine_id: str, status: RoutineStatus) -> WorkRoutine:
        safe_id = validate_routine_id(routine_id)

        def update(data: dict[str, Any]) -> dict[str, Any]:
            if data.get("routine_id") != safe_id:
                raise KeyError(f"routine not found: {safe_id}")
            try:
                routine = WorkRoutine.from_dict(data)
            except (KeyError, TypeError, ValueError) as exc:
                raise KeyError(f"routine not found: {safe_id}") from exc
            routine.status = status
            routine.updated_at = time.time()
            return routine.to_dict()

        updated = self._records.mutate(safe_id, update)
        if updated is None:
            raise KeyError(f"routine not found: {safe_id}")
        return WorkRoutine.from_dict(updated)
