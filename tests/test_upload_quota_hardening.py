"""F-11: durable quota SM, fail-closed scan, idempotent commit, recovery."""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from js.echo.attachment_gate import (
    AttachmentGateError,
    SecureUploadWriter,
    owner_slug,
    session_slug,
)
from js.echo.upload_quota import UploadQuotaLedger, UploadQuotaLimits


def _limits(**kwargs: int) -> UploadQuotaLimits:
    base = {
        "owner_max_bytes": 5_000,
        "owner_max_files": 10,
        "session_max_bytes": 5_000,
        "session_max_files": 10,
        "min_free_disk_bytes": 0,
    }
    base.update(kwargs)
    return UploadQuotaLimits(**base)


def test_parent_owner_symlink_rejected(tmp_path: Path) -> None:
    limits = _limits()
    owner = owner_slug("owner-a")
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    real = tmp_path / "elsewhere"
    real.mkdir()
    (uploads / owner).symlink_to(real)
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    with pytest.raises(AttachmentGateError) as exc:
        ledger.reserve(
            session_id="sess-1",
            bytes_needed=10,
            files_needed=1,
            reservation_id="r1",
        )
    assert exc.value.status_code == 500


def test_negative_schema_forces_rescan(tmp_path: Path) -> None:
    limits = _limits()
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "a.txt", max_bytes=100, quota_limits=limits
    ) as writer:
        writer.write(b"ok")
        writer.commit()
    owner = owner_slug("owner-a")
    ledger_path = tmp_path / "uploads" / owner / ".quota.json"
    raw = json.loads(ledger_path.read_text())
    raw["owner_bytes"] = -1
    ledger_path.write_text(json.dumps(raw))
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    data = ledger.rebuild()
    assert data["owner_bytes"] >= 0
    assert data["owner_files"] >= 1


def test_duplicate_commit_idempotent(tmp_path: Path) -> None:
    limits = _limits()
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    rid = "dup-commit"
    ledger.reserve(session_id="sess-1", bytes_needed=50, files_needed=1, reservation_id=rid)
    sess = session_slug("sess-1")
    owner_root = tmp_path / "uploads" / owner_slug("owner-a") / sess
    owner_root.mkdir(parents=True)
    (owner_root / "a.txt").write_bytes(b"x" * 20)
    ledger.mark_published(
        session_id="sess-1",
        reservation_id=rid,
        filename="a.txt",
        actual_bytes=20,
    )
    ledger.commit(
        session_id="sess-1",
        reservation_id=rid,
        actual_bytes=20,
        filename="a.txt",
    )
    before = ledger.rebuild()
    # Idempotent retry with identical params must not double-count.
    ledger.commit(
        session_id="sess-1",
        reservation_id=rid,
        actual_bytes=20,
        filename="a.txt",
    )
    after = ledger.rebuild()
    assert after["owner_files"] == before["owner_files"]
    assert after["owner_bytes"] == before["owner_bytes"]


def test_quota_save_failure_unlinks_published(tmp_path: Path) -> None:
    limits = _limits()
    real_save = UploadQuotaLedger._save_unlocked

    def flaky(self: UploadQuotaLedger, owner_fd: int, data: dict[str, Any]) -> None:
        for meta in (data.get("reservations") or {}).values():
            if isinstance(meta, dict) and meta.get("state") == "committed":
                raise OSError("simulated quota save failure")
        # Also fail when commit receipt is being written (reservation popped).
        commits = data.get("commits") or {}
        if commits and any(
            isinstance(m, dict) and m.get("filename") == "a.txt" for m in commits.values()
        ):
            # Allow first publish saves; fail when commits gain the new receipt
            # while owner_files was just incremented from a reservation path.
            if (
                int(data.get("owner_files", 0)) >= 1
                and not (tmp_path / "uploads" / owner_slug("owner-a") / ".quota.json").exists()
            ):
                pass
            reservations = data.get("reservations") or {}
            if (
                not any(
                    isinstance(m, dict) and m.get("state") == "published"
                    for m in reservations.values()
                )
                and int(data.get("owner_files", 0)) >= 1
            ):
                raise OSError("simulated quota save failure")
        return real_save(self, owner_fd, data)

    with (
        patch.object(UploadQuotaLedger, "_save_unlocked", flaky),
        pytest.raises(OSError, match="simulated quota save failure"),
        SecureUploadWriter(
            tmp_path,
            "owner-a",
            "sess-1",
            "a.txt",
            max_bytes=100,
            quota_limits=limits,
        ) as writer,
    ):
        writer.write(b"payload")
        writer.commit()
    sess = session_slug("sess-1")
    sess_dir = tmp_path / "uploads" / owner_slug("owner-a") / sess
    leftovers = [p for p in sess_dir.iterdir() if not p.name.startswith(".")]
    assert leftovers == []


def test_scan_io_error_fail_closed(tmp_path: Path) -> None:
    limits = _limits()
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "a.txt", max_bytes=100, quota_limits=limits
    ) as writer:
        writer.write(b"x")
        writer.commit()
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)

    real_scandir = os.scandir

    def flaky_scandir(path: Any) -> Any:
        iterator = real_scandir(path)

        class _Wrap:
            def __enter__(self) -> Any:
                return self

            def __exit__(self, *args: Any) -> None:
                iterator.__exit__(*args)

            def __iter__(self) -> Any:
                for entry in iterator:
                    if not entry.name.startswith("."):
                        raise OSError("simulated scan I/O")
                    yield entry

        return _Wrap()

    with patch.object(os, "scandir", flaky_scandir), pytest.raises(AttachmentGateError) as exc:
        ledger.rebuild()
    assert exc.value.status_code == 500


def test_recover_published_after_crash(tmp_path: Path) -> None:
    limits = _limits()
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    rid = "crash-pub"
    ledger.reserve(session_id="sess-1", bytes_needed=40, files_needed=1, reservation_id=rid)
    sess = session_slug("sess-1")
    owner = owner_slug("owner-a")
    (tmp_path / "uploads" / owner / sess).mkdir(parents=True)
    (tmp_path / "uploads" / owner / sess / "left.bin").write_bytes(b"y" * 11)
    ledger.mark_published(
        session_id="sess-1",
        reservation_id=rid,
        filename="left.bin",
        actual_bytes=11,
    )
    recovered = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    recovered.recover()
    data = recovered.rebuild()
    assert data["owner_files"] >= 1
    assert data["owner_bytes"] >= 11


def _mp_worker(workspace: str, name: str) -> str:
    limits = UploadQuotaLimits(
        owner_max_bytes=500,
        owner_max_files=1,
        session_max_bytes=500,
        session_max_files=1,
        min_free_disk_bytes=0,
    )
    try:
        with SecureUploadWriter(
            Path(workspace),
            "owner-a",
            "sess-1",
            name,
            max_bytes=400,
            quota_limits=limits,
        ) as writer:
            writer.write(b"x" * 50)
            writer.commit()
        return "ok"
    except AttachmentGateError:
        return "reject"


def test_true_multiprocess_quota(tmp_path: Path) -> None:
    limits = _limits(owner_max_bytes=500, session_max_bytes=500, owner_max_files=1)
    UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    ctx = mp.get_context("spawn")
    with ProcessPoolExecutor(max_workers=4, mp_context=ctx) as pool:
        results = list(
            pool.map(
                _mp_worker,
                [str(tmp_path)] * 4,
                [f"m{i}.txt" for i in range(4)],
            )
        )
    assert results.count("ok") == 1
    assert results.count("reject") == 3


def test_delete_state_machine_recoverable(tmp_path: Path) -> None:
    limits = _limits()
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "a.txt", max_bytes=100, quota_limits=limits
    ) as writer:
        writer.write(b"abcdef")
        path = writer.commit()
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    did = "del-1"
    ledger.begin_delete(session_id="sess-1", bytes_freed=6, delete_id=did)
    path.unlink()
    ledger.mark_deleted(delete_id=did)
    UploadQuotaLedger(tmp_path, "owner-a", limits=limits).recover()
    data = ledger.rebuild()
    assert data["owner_files"] == 0
    assert data["owner_bytes"] == 0


# ---------------------------------------------------------------------------
# F-11 hardening regressions (idempotent recover, crash windows, fail-closed)
# ---------------------------------------------------------------------------


def test_recover_published_twice_does_not_double_count(tmp_path: Path) -> None:
    """a. Published leftover + recover()×2 must not double-bill owner/session."""
    limits = _limits()
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    rid = "pub-twice"
    ledger.reserve(session_id="sess-1", bytes_needed=40, files_needed=1, reservation_id=rid)
    sess = session_slug("sess-1")
    owner = owner_slug("owner-a")
    (tmp_path / "uploads" / owner / sess).mkdir(parents=True)
    (tmp_path / "uploads" / owner / sess / "left.bin").write_bytes(b"y" * 11)
    ledger.mark_published(
        session_id="sess-1",
        reservation_id=rid,
        filename="left.bin",
        actual_bytes=11,
    )
    ledger.recover()
    ledger.recover()
    data = ledger.rebuild()
    assert data["owner_files"] == 1
    assert data["owner_bytes"] == 11
    sess_usage = data["sessions"][sess]
    assert sess_usage["files"] == 1
    assert sess_usage["bytes"] == 11


def test_recover_delete_twice_keeps_surviving_file_billed(tmp_path: Path) -> None:
    """b. Delete one of two files; recover()×2 must leave the survivor billed."""
    limits = _limits()
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "a.txt", max_bytes=100, quota_limits=limits
    ) as writer:
        writer.write(b"aaaaaa")
        path_a = writer.commit()
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "b.txt", max_bytes=100, quota_limits=limits
    ) as writer:
        writer.write(b"bbbbbb")
        writer.commit()
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    before = ledger.rebuild()
    assert before["owner_files"] == 2
    assert before["owner_bytes"] == 12
    did = "del-survivor"
    ledger.begin_delete(session_id="sess-1", bytes_freed=6, delete_id=did)
    path_a.unlink()
    ledger.mark_deleted(delete_id=did)
    ledger.recover()
    ledger.recover()
    data = ledger.rebuild()
    assert data["owner_files"] == 1
    assert data["owner_bytes"] == 6
    sess = session_slug("sess-1")
    assert data["sessions"][sess]["files"] == 1
    assert data["sessions"][sess]["bytes"] == 6


def _crash_after_link_fsync_worker(workspace: str) -> None:
    """Child: die after link+dir fsync, before commit finalize (real SecureUploadWriter)."""
    from js.echo.attachment_gate import SecureUploadWriter as Writer
    from js.echo.upload_quota import UploadQuotaLimits

    limits = UploadQuotaLimits(
        owner_max_bytes=5_000,
        owner_max_files=10,
        session_max_bytes=5_000,
        session_max_files=10,
        min_free_disk_bytes=0,
    )
    Writer._test_fault_after_publish_fsync = "os_exit"  # type: ignore[attr-defined]
    try:
        with Writer(
            Path(workspace),
            "owner-a",
            "sess-1",
            "crash.bin",
            max_bytes=200,
            quota_limits=limits,
        ) as writer:
            writer.write(b"z" * 17)
            writer.commit()
    finally:
        Writer._test_fault_after_publish_fsync = None  # type: ignore[attr-defined]


def test_crash_after_link_before_mark_published_recovers_via_writer(
    tmp_path: Path,
) -> None:
    """c. os._exit after link+dir fsync (pre-commit); restart bills via writer path."""
    limits = _limits()
    UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    ctx = mp.get_context("spawn")
    proc = ctx.Process(target=_crash_after_link_fsync_worker, args=(str(tmp_path),))
    proc.start()
    proc.join(timeout=30)
    assert proc.exitcode != 0

    sess = session_slug("sess-1")
    owner = owner_slug("owner-a")
    published = tmp_path / "uploads" / owner / sess / "crash.bin"
    assert published.is_file()
    assert published.stat().st_size == 17

    # Restart through real SecureUploadWriter path (recover on reserve), not rebuild.
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "other.txt", max_bytes=50, quota_limits=limits
    ) as writer:
        writer.write(b"ok")
        writer.commit()

    raw = json.loads((tmp_path / "uploads" / owner / ".quota.json").read_text())
    assert int(raw["owner_files"]) >= 2
    assert int(raw["owner_bytes"]) >= 17 + 2
    sess_usage = raw["sessions"][sess]
    assert int(sess_usage["files"]) >= 2
    assert int(sess_usage["bytes"]) >= 17 + 2
    assert published.is_file()


def test_commit_save_and_unlink_both_fail_does_not_leave_unbilled(
    tmp_path: Path,
) -> None:
    """d. Quota commit save failure + rollback unlink failure must fail-closed."""
    limits = _limits()
    real_save = UploadQuotaLedger._save_unlocked

    def flaky_save(self: UploadQuotaLedger, owner_fd: int, data: dict[str, Any]) -> None:
        commits = data.get("commits") or {}
        if any(isinstance(m, dict) and m.get("filename") == "sticky.txt" for m in commits.values()):
            raise OSError("simulated quota commit save failure")
        return real_save(self, owner_fd, data)

    SecureUploadWriter._test_fault_rollback_unlink = "raise"  # type: ignore[attr-defined]
    try:
        with (
            patch.object(UploadQuotaLedger, "_save_unlocked", flaky_save),
            pytest.raises(OSError, match="simulated quota commit save failure"),
            SecureUploadWriter(
                tmp_path,
                "owner-a",
                "sess-1",
                "sticky.txt",
                max_bytes=100,
                quota_limits=limits,
            ) as writer,
        ):
            writer.write(b"sticky-payload")
            writer.commit()
    finally:
        SecureUploadWriter._test_fault_rollback_unlink = None  # type: ignore[attr-defined]

    sess = session_slug("sess-1")
    owner = owner_slug("owner-a")
    sticky = tmp_path / "uploads" / owner / sess / "sticky.txt"
    assert sticky.is_file(), "file survived failed unlink — must stay billed"

    raw = json.loads((tmp_path / "uploads" / owner / ".quota.json").read_text())
    reservations = raw.get("reservations") or {}
    published = [
        m
        for m in reservations.values()
        if isinstance(m, dict)
        and m.get("filename") == "sticky.txt"
        and m.get("state") == "published"
    ]
    billed = int(raw.get("owner_files", 0)) >= 1 and int(raw.get("owner_bytes", 0)) >= len(
        b"sticky-payload"
    )
    assert published or billed, "must not abandon an unbilled visible file"

    UploadQuotaLedger(tmp_path, "owner-a", limits=limits).recover()
    raw2 = json.loads((tmp_path / "uploads" / owner / ".quota.json").read_text())
    assert int(raw2["owner_files"]) >= 1
    assert int(raw2["owner_bytes"]) >= len(b"sticky-payload")
    assert sticky.is_file()


def _delete_accounting_crash_worker(workspace: str, filename: str) -> None:
    """Child: delete_owned_upload_by_name dies after unlink, before mark_deleted."""
    from js.echo import attachment_gate as gate

    gate._test_fault_after_delete_unlink = "os_exit"  # type: ignore[attr-defined]
    try:
        gate.delete_owned_upload_by_name(Path(workspace), "owner-a", filename, "sess-1")
        os._exit(92)
    finally:
        gate._test_fault_after_delete_unlink = None  # type: ignore[attr-defined]


def test_delete_after_unlink_accounting_fail_recovers_on_restart(
    tmp_path: Path,
) -> None:
    """e. Production delete: unlink ok, accounting fails; restart via delete path."""
    limits = _limits()
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "gone.txt", max_bytes=100, quota_limits=limits
    ) as writer:
        writer.write(b"12345678")
        writer.commit()
    owner = owner_slug("owner-a")
    before = json.loads((tmp_path / "uploads" / owner / ".quota.json").read_text())
    assert int(before["owner_files"]) == 1

    from js.echo.attachment_gate import delete_owned_upload_by_name

    ctx = mp.get_context("spawn")
    proc = ctx.Process(
        target=_delete_accounting_crash_worker,
        args=(str(tmp_path), "gone.txt"),
    )
    proc.start()
    proc.join(timeout=30)
    assert proc.exitcode is not None and proc.exitcode != 0

    sess = session_slug("sess-1")
    assert not (tmp_path / "uploads" / owner / sess / "gone.txt").exists()

    # Mid-crash ledger must still show usage until delete/recover finishes.
    mid = json.loads((tmp_path / "uploads" / owner / ".quota.json").read_text())
    assert int(mid["owner_files"]) == 1

    # Restart must finish accounting through the real delete path (idempotent).
    delete_owned_upload_by_name(tmp_path, "owner-a", "gone.txt", "sess-1")

    raw = json.loads((tmp_path / "uploads" / owner / ".quota.json").read_text())
    assert int(raw["owner_files"]) == 0
    assert int(raw["owner_bytes"]) == 0


def test_scan_capacity_fail_closed_on_4097_empty_session_dirs(tmp_path: Path) -> None:
    """f. 4097 empty session directories must trip scan capacity (all entries count)."""
    limits = _limits()
    owner = owner_slug("owner-a")
    owner_root = tmp_path / "uploads" / owner
    owner_root.mkdir(parents=True)
    for i in range(4097):
        (owner_root / f"s_empty_{i:04d}").mkdir()
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    with pytest.raises(AttachmentGateError) as exc:
        ledger.rebuild()
    assert exc.value.status_code in {429, 500}


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda d: d["reservations"].__setitem__(
                "rid",
                {
                    "owner": d["owner"],
                    "session": session_slug("sess-1"),
                    "bytes": 1,
                    "files": 1,
                    "created_at": time.time(),
                    # missing state
                },
            ),
            id="missing_state",
        ),
        pytest.param(
            lambda d: d["reservations"].__setitem__(
                "",
                {
                    "owner": d["owner"],
                    "session": session_slug("sess-1"),
                    "bytes": 1,
                    "files": 1,
                    "created_at": time.time(),
                    "state": "reserved",
                },
            ),
            id="empty_reservation_id",
        ),
        pytest.param(
            lambda d: d["reservations"].__setitem__(
                "rid",
                {
                    "owner": d["owner"],
                    "session": "",
                    "bytes": 1,
                    "files": 1,
                    "created_at": time.time(),
                    "state": "reserved",
                },
            ),
            id="empty_session",
        ),
        pytest.param(
            lambda d: d["reservations"].__setitem__(
                "rid",
                {
                    "owner": d["owner"],
                    "session": session_slug("sess-1"),
                    "bytes": 1,
                    "files": 1,
                    "created_at": -1.0,
                    "state": "reserved",
                },
            ),
            id="negative_created_at",
        ),
        pytest.param(
            lambda d: d.__setitem__(
                "commits",
                {
                    "cid": {
                        "session": session_slug("sess-1"),
                        "actual_bytes": 1,
                        "filename": "a.txt",
                        # missing committed_at
                    }
                },
            ),
            id="commit_missing_committed_at",
        ),
    ],
)
def test_reject_invalid_ledger_schema(tmp_path: Path, mutate: Any) -> None:
    """g. Strict ledger schema: missing/empty/negative fields are rejected."""

    limits = _limits()
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "seed.txt", max_bytes=50, quota_limits=limits
    ) as writer:
        writer.write(b"x")
        writer.commit()
    owner = owner_slug("owner-a")
    ledger_path = tmp_path / "uploads" / owner / ".quota.json"
    raw = json.loads(ledger_path.read_text())
    mutate(raw)
    ledger_path.write_text(json.dumps(raw))
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    with pytest.raises(AttachmentGateError) as exc:
        ledger.reserve(
            session_id="sess-2",
            bytes_needed=1,
            files_needed=1,
            reservation_id="schema-probe",
        )
    assert exc.value.status_code == 500
    assert "schema" in exc.value.detail.lower() or "invalid" in exc.value.detail.lower()
