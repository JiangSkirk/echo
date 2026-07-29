"""Fail-closed Echo journal recovery UX (M4).

Never deletes, truncates, or auto-repairs a user journal. Operators may:
1. back up the ledger tree
2. run a read-only integrity check
3. quarantine the tree for manual review
4. only migrate/repair after explicit confirmation elsewhere
"""

from __future__ import annotations

import os
import shutil
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class JournalRecoveryReport:
    ok: bool
    state_dir: str
    ledger_root: str
    error: str | None = None
    error_class: str | None = None
    backup_path: str | None = None
    quarantine_path: str | None = None
    options: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    inspected_utc: str = field(
        default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def render_cli(self) -> str:
        lines = [
            "Echo journal recovery status",
            f"  state_dir: {self.state_dir}",
            f"  ledger_root: {self.ledger_root}",
            f"  ok: {self.ok}",
        ]
        if self.error:
            lines.append(f"  error: {self.error_class}: {self.error}")
        if self.backup_path:
            lines.append(f"  backup: {self.backup_path}")
        if self.quarantine_path:
            lines.append(f"  quarantine: {self.quarantine_path}")
        if self.options:
            lines.append("  recovery options:")
            for option in self.options:
                lines.append(f"    - {option}")
        for note in self.notes:
            lines.append(f"  note: {note}")
        return "\n".join(lines)


_DEFAULT_OPTIONS: tuple[str, ...] = (
    "Keep using the backup; do not delete the original journal.",
    "Quarantine the ledger tree for offline manual review.",
    "Inspect /api/manual-reviews after a healthy boot from a clean state_dir.",
    "Only migrate or repair after explicit operator confirmation (no automatic seal rewrite).",
)


def ledger_root_for_state(state_dir: Path) -> Path:
    return Path(state_dir).expanduser().resolve() / "echo" / "ledger"


def backup_ledger_tree(
    state_dir: Path,
    *,
    backup_parent: Path | None = None,
) -> Path:
    """Copy the ledger tree to a sibling backup directory. Read-source only."""
    root = ledger_root_for_state(state_dir)
    if not root.exists():
        raise FileNotFoundError(f"ledger root missing: {root}")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    parent = (
        Path(backup_parent).expanduser().resolve()
        if backup_parent is not None
        else root.parent / "recovery_backups"
    )
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / f"ledger-backup-{stamp}"
    if destination.exists():
        destination = parent / f"ledger-backup-{stamp}-{os.getpid()}"
    shutil.copytree(root, destination)
    return destination


def quarantine_ledger_tree(
    state_dir: Path,
    *,
    quarantine_parent: Path | None = None,
) -> Path:
    """Move the ledger tree aside for manual review without deleting bytes."""
    root = ledger_root_for_state(state_dir)
    if not root.exists():
        raise FileNotFoundError(f"ledger root missing: {root}")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    parent = (
        Path(quarantine_parent).expanduser().resolve()
        if quarantine_parent is not None
        else root.parent / "quarantine"
    )
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / f"ledger-quarantine-{stamp}"
    if destination.exists():
        destination = parent / f"ledger-quarantine-{stamp}-{os.getpid()}"
    shutil.move(str(root), str(destination))
    return destination


def inspect_journal_readonly(state_dir: Path) -> JournalRecoveryReport:
    """Attempt a read-only EchoSafetyService open; never mutate the journal."""
    resolved = Path(state_dir).expanduser().resolve()
    root = ledger_root_for_state(resolved)
    notes = (
        "This check does not rewrite journal seals or outbox rows.",
        "Automatic repair is intentionally unavailable.",
    )
    if not root.exists():
        return JournalRecoveryReport(
            ok=True,
            state_dir=str(resolved),
            ledger_root=str(root),
            notes=("Ledger root not present yet (fresh state).", *notes),
            options=_DEFAULT_OPTIONS,
        )
    try:
        from js.echo.ledger.service import EchoSafetyService

        service = EchoSafetyService(state_dir=resolved)
        health = service.health()
        ok = bool(getattr(health, "ok", False))
        error = None if ok else str(getattr(health, "last_error", None) or "echo unhealthy")
        return JournalRecoveryReport(
            ok=ok,
            state_dir=str(resolved),
            ledger_root=str(root),
            error=error,
            error_class=None if ok else "EchoHealthError",
            options=_DEFAULT_OPTIONS,
            notes=notes,
        )
    except Exception as exc:
        message = str(exc)
        error_class = type(exc).__name__
        if "outbox seal is missing" in message or "semantic journal error" in message:
            error_class = "SemanticJournalError"
        return JournalRecoveryReport(
            ok=False,
            state_dir=str(resolved),
            ledger_root=str(root),
            error=message,
            error_class=error_class,
            options=_DEFAULT_OPTIONS,
            notes=notes,
        )


def prepare_recovery(
    state_dir: Path,
    *,
    backup: bool = True,
    quarantine: bool = False,
    backup_parent: Path | None = None,
    quarantine_parent: Path | None = None,
) -> JournalRecoveryReport:
    """Backup (always recommended) then inspect; quarantine only when requested."""
    resolved = Path(state_dir).expanduser().resolve()
    backup_path: Path | None = None
    quarantine_path: Path | None = None
    if backup and ledger_root_for_state(resolved).exists():
        backup_path = backup_ledger_tree(resolved, backup_parent=backup_parent)
    report = inspect_journal_readonly(resolved)
    if quarantine and ledger_root_for_state(resolved).exists():
        quarantine_path = quarantine_ledger_tree(resolved, quarantine_parent=quarantine_parent)
        report = JournalRecoveryReport(
            ok=report.ok,
            state_dir=report.state_dir,
            ledger_root=report.ledger_root,
            error=report.error,
            error_class=report.error_class,
            backup_path=str(backup_path) if backup_path else report.backup_path,
            quarantine_path=str(quarantine_path),
            options=report.options,
            notes=(
                *report.notes,
                "Ledger tree was moved to quarantine; agent may boot with a fresh ledger.",
            ),
            inspected_utc=report.inspected_utc,
        )
        return report
    if backup_path is not None:
        return JournalRecoveryReport(
            ok=report.ok,
            state_dir=report.state_dir,
            ledger_root=report.ledger_root,
            error=report.error,
            error_class=report.error_class,
            backup_path=str(backup_path),
            quarantine_path=report.quarantine_path,
            options=report.options,
            notes=report.notes,
            inspected_utc=report.inspected_utc,
        )
    return report
