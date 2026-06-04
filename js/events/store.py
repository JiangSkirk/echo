"""Append-only event store for agent observability.

Events are written to daily-rotated JSONL files for durability and easy ingestion.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from js.events.models import AgentEvent
from js.utils.log import get_logger

logger = get_logger("js.events")


class EventStore:
    """Write-only event store with daily log rotation.

    Events are encrypted at rest using the same Fernet key as SecretManager.
    """

    def __init__(self, base_dir: Path | str, retention_days: int = 90) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._retention_days = retention_days
        self._lock = threading.Lock()

    @property
    def _secrets(self) -> Any:
        if not hasattr(self, "_secrets_inst"):
            from js.security.secrets import SecretManager
            self._secrets_inst = SecretManager(self.base_dir.parent)
        return self._secrets_inst

    def _get_file(self) -> Path:
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        return self.base_dir / f"events_{today}.jsonl"

    def emit(self, event: AgentEvent) -> None:
        """Append an encrypted event to the current log file."""
        with self._lock:
            try:
                path = self._get_file()
                raw = json.dumps(event.to_dict(), ensure_ascii=False, default=str)
                encrypted = self._secrets.encrypt_blob(raw.encode("utf-8")).decode("ascii")
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write(encrypted + "\n")
            except Exception:
                logger.warning("Failed to write event", exc_info=True)

    def query(
        self,
        session_id: str | None = None,
        run_id: str | None = None,
        agent_id: str | None = None,
        task_id: str | None = None,
        group_id: str | None = None,
        event_type: str | None = None,
        limit: int = 500,
    ) -> list[AgentEvent]:
        """Query events from log files (newest first)."""
        results: list[AgentEvent] = []
        files = sorted(self.base_dir.glob("events_*.jsonl"), reverse=True)
        for f in files:
            try:
                with open(f, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            # Decrypt the encrypted JSONL line
                            decrypted = self._secrets.decrypt_blob(line.encode("ascii"))
                            data = json.loads(decrypted.decode("utf-8"))
                        except (json.JSONDecodeError, Exception):
                            # Fallback: legacy unencrypted lines
                            try:
                                data = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                        if session_id and data.get("session_id") != session_id:
                            continue
                        if run_id and data.get("run_id") != run_id:
                            continue
                        if agent_id and data.get("agent_id") != agent_id:
                            continue
                        if task_id and data.get("task_id") != task_id:
                            continue
                        if group_id and data.get("group_id") != group_id:
                            continue
                        if event_type and data.get("event_type") != event_type:
                            continue
                        results.append(AgentEvent(**data))
                        if len(results) >= limit:
                            return results
            except Exception:
                logger.warning(f"Failed to read event file {f}", exc_info=True)
        return results

    def prune(self) -> int:
        """Remove event files older than retention_days."""
        from datetime import timedelta

        cutoff = datetime.now(UTC) - timedelta(days=self._retention_days)
        deleted = 0
        for f in self.base_dir.glob("events_*.jsonl"):
            try:
                date_str = f.stem.replace("events_", "")
                file_date = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=UTC)
                if file_date < cutoff:
                    f.unlink()
                    deleted += 1
            except Exception:
                pass
        return deleted
