"""WP-C6 fault matrix: no blind replay after UNKNOWN_COMMIT."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from js.echo.capability import LeaseDenied
from js.orin.protocol import ProtocolError
from tests.orin.test_orin_stagec_c2_desktop_cell import _preflighted_action
from tests.orin.test_orin_stagec_c3_memory import _cell, _draft, _package, _permit, _scope
from tests.orin.test_orin_stagec_c5_enforce import _c3_memory_adapter, _memory_write_draft


def test_desktop_unknown_commit_does_not_blindly_replay(tmp_path: Path) -> None:
    cell, _incoming, _witness, permit, committed = _preflighted_action(tmp_path)
    cell._receipts.record(  # noqa: SLF001
        {
            "permit_id": permit.permit_id,
            "draft_id": committed.draft.draft_id,
            "before_digest": "sha256:" + "b" * 64,
            "after_digest": "",
            "target_digest": "sha256:" + "c" * 64,
            "state": "unknown",
            "created_at_ms": 1,
        }
    )
    report = cell._action_reports[committed.draft.draft_id]  # noqa: SLF001
    report.attempted = True

    with pytest.raises(ProtocolError, match="already committed|replay"):
        cell._commit_package(permit, committed)  # noqa: SLF001
    reconciled = cell._reconcile_effect(
        committed.draft.draft_id,
        {"permit_id": permit.permit_id, "draft_id": committed.draft.draft_id},
    )
    assert reconciled["state"] == "UNKNOWN_COMMIT"


def test_memory_unknown_commit_does_not_insert_again(tmp_path: Path) -> None:
    cell = _cell(tmp_path)
    task_id = f"task:{uuid4().hex}"
    draft = _draft(task_id, "memory.write", _scope(key="once", value="first", source="user"))
    package = _package(draft)
    preflight = cell._preflight_package(package)  # noqa: SLF001
    committed = replace(package, state_witness=preflight.witness)
    permit = _permit(committed, preflight.witness)
    cell._conn.execute(  # noqa: SLF001
        "INSERT INTO commits(draft_id, effect_hash, record_id, state) VALUES (?, ?, ?, ?)",
        (draft.draft_id, package.canonical_effect_hash, "memory:partial", "unknown"),
    )
    cell._conn.commit()  # noqa: SLF001

    result = cell._commit_package(permit, committed)  # noqa: SLF001
    assert result["status"] == "UNKNOWN_COMMIT"
    assert (
        cell._row(  # noqa: SLF001
            cell._scope(committed)  # noqa: SLF001
        )
        is None
    )
    assert cell._reconcile_effect(draft.draft_id, {"draft_id": draft.draft_id}) == {
        "state": "UNKNOWN_COMMIT"
    }


def test_disconnected_cell_reconcile_is_unknown_not_a_retry(tmp_path: Path) -> None:
    from js.orind.daemon import OrinDaemon

    daemon = OrinDaemon(
        state_dir=tmp_path,
        stage_b=True,
        cell_desktop=True,
        cell_identity_enforce=True,
        c1_test_harness=True,
    )
    try:
        assert daemon._cell_by_cap("cell.desktop") is None  # noqa: SLF001

        async def _run() -> dict[str, str]:
            return await daemon._reconcile_desktop_action(  # noqa: SLF001
                permit_id="permit:missing",
                draft_id="draft:missing",
            )

        import asyncio

        outcome = asyncio.run(_run())
        assert outcome["state"] == "unknown"
    finally:
        daemon._store.close()  # noqa: SLF001


def test_memory_unknown_commit_via_client_does_not_insert(tmp_path: Path) -> None:
    import sqlite3

    orind, adapter, task_id, owner = _c3_memory_adapter(tmp_path)
    try:
        draft = _memory_write_draft(task_id, owner, key="once")
        proposed = adapter.submit_draft(draft.to_dict())
        assert proposed.get("ok") is True
        preflight = adapter.preflight_draft(draft.draft_id, "cell.memory", session_id="session:c5")
        assert preflight.get("ok") is True
        db = next(
            root / "state" / "memory-cell.db"
            for root in orind.daemon._cell_runtime_roots.values()  # noqa: SLF001
            if (root / "state" / "memory-cell.db").exists()
        )
        conn = sqlite3.connect(str(db))
        conn.execute(
            "INSERT INTO commits(draft_id, effect_hash, record_id, state) VALUES (?, ?, ?, ?)",
            (draft.draft_id, "sha256:" + "a" * 64, "memory:partial", "unknown"),
        )
        conn.commit()
        conn.close()
        result = adapter.consume_draft(draft.draft_id, session_id="session:c5")
        assert result.get("status") == "UNKNOWN_COMMIT"
        conn = sqlite3.connect(str(db))
        count = conn.execute(
            "SELECT COUNT(*) FROM memories WHERE key = ?",
            ("once",),
        ).fetchone()
        conn.close()
        assert count is not None
        assert count[0] == 0
    finally:
        orind.stop()


def test_memory_cell_disconnect_via_client_denies_consume(tmp_path: Path) -> None:
    orind, adapter, task_id, owner = _c3_memory_adapter(tmp_path)
    try:
        draft = _memory_write_draft(task_id, owner, key="lost")
        proposed = adapter.submit_draft(draft.to_dict())
        assert proposed.get("ok") is True
        preflight = adapter.preflight_draft(draft.draft_id, "cell.memory", session_id="session:c5")
        assert preflight.get("ok") is True
        proc = orind.daemon._memory_proc  # noqa: SLF001
        assert proc is not None
        orind.daemon._shutting_down = True  # noqa: SLF001
        proc.kill()
        proc.wait(timeout=5)
        with pytest.raises(LeaseDenied):
            adapter.consume_draft(draft.draft_id, session_id="session:c5")
    finally:
        orind.stop()
