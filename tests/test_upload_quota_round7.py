"""F-11 round7: recover idempotency, publish/delete intents, scan limits, schema."""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from js.echo.attachment_gate import (
    AttachmentGateError,
    SecureUploadWriter,
    delete_owned_upload_by_name,
    owner_slug,
    session_slug,
)
from js.echo.upload_quota import UploadQuotaLedger, UploadQuotaLimits


def _limits(**kwargs: int) -> UploadQuotaLimits:
    base = {
        "owner_max_bytes": 50_000,
        "owner_max_files": 100,
        "session_max_bytes": 50_000,
        "session_max_files": 100,
        "min_free_disk_bytes": 0,
    }
    base.update(kwargs)
    return UploadQuotaLimits(**base)


def _ledger_path(workspace: Path, owner: str = "owner-a") -> Path:
    return workspace / "uploads" / owner_slug(owner) / ".quota.json"


def test_recover_published_twice_does_not_double_count(tmp_path: Path) -> None:
    limits = _limits()
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "a.txt", max_bytes=100, quota_limits=limits
    ) as writer:
        writer.write(b"hello")
        # Force published-without-commit via ledger after a normal publish intent path.
        published = writer.commit()
    assert published.exists()
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    raw = json.loads(_ledger_path(tmp_path).read_text(encoding="utf-8"))
    # Simulate crash after publish accounting was partially applied: reinject published.
    rid = next(iter(raw.get("commits") or {}))
    commit = raw["commits"].pop(rid)
    raw["reservations"][rid] = {
        "owner": owner_slug("owner-a"),
        "session": session_slug("sess-1"),
        "bytes": 100,
        "files": 1,
        "created_at": time.time(),
        "state": "published",
        "filename": commit["filename"],
        "actual_bytes": commit["actual_bytes"],
    }
    # Roll back usage so recover must re-apply once.
    raw["owner_bytes"] = 0
    raw["owner_files"] = 0
    raw["sessions"] = {session_slug("sess-1"): {"bytes": 0, "files": 0}}
    _ledger_path(tmp_path).write_text(json.dumps(raw), encoding="utf-8")

    first = ledger.recover()
    second = ledger.recover()
    assert first["owner_files"] == 1
    assert first["owner_bytes"] == 5
    assert second["owner_files"] == 1
    assert second["owner_bytes"] == 5
    assert second["sessions"][session_slug("sess-1")]["files"] == 1


def test_delete_one_of_two_then_recover_keeps_survivor_billed(tmp_path: Path) -> None:
    limits = _limits()
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "a.txt", max_bytes=100, quota_limits=limits
    ) as w1:
        w1.write(b"aaaa")
        w1.commit()
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "b.txt", max_bytes=100, quota_limits=limits
    ) as w2:
        w2.write(b"bbbbbb")
        w2.commit()
    assert delete_owned_upload_by_name(tmp_path, "owner-a", "a.txt", session_id="sess-1")
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    once = ledger.recover()
    twice = ledger.recover()
    assert once["owner_files"] == 1
    assert once["owner_bytes"] == 6
    assert twice["owner_files"] == 1
    assert twice["owner_bytes"] == 6
    sess = session_slug("sess-1")
    assert (tmp_path / "uploads" / owner_slug("owner-a") / sess / "b.txt").exists()
    assert not (tmp_path / "uploads" / owner_slug("owner-a") / sess / "a.txt").exists()


def _crash_between_link_and_commit(workspace: str, ready_path: str) -> None:
    """Child: persist publish intent, link+fsync, exit before quota commit."""

    from js.echo.attachment_gate import SecureUploadWriter as W
    from js.echo.upload_quota import UploadQuotaLimits as L

    ws = Path(workspace)
    limits = L(
        owner_max_bytes=50_000,
        owner_max_files=100,
        session_max_bytes=50_000,
        session_max_files=100,
        min_free_disk_bytes=0,
    )
    writer = W(ws, "owner-a", "sess-crash", "crash.txt", max_bytes=100, quota_limits=limits)
    writer.write(b"crash-me")

    def boom(**kwargs: Any) -> None:
        Path(ready_path).write_text("ready", encoding="utf-8")
        os._exit(99)

    writer._quota.commit = boom  # type: ignore[method-assign]
    try:
        writer.commit()
    finally:
        writer.close()


def test_sigkill_between_link_and_mark_published_recovers(tmp_path: Path) -> None:
    limits = _limits()
    ready = tmp_path / "ready.flag"
    ctx = mp.get_context("spawn")
    proc = ctx.Process(
        target=_crash_between_link_and_commit,
        args=(str(tmp_path), str(ready)),
    )
    proc.start()
    deadline = time.time() + 5.0
    while time.time() < deadline and not ready.exists():
        time.sleep(0.05)
    if proc.is_alive():
        proc.kill()
    proc.join(timeout=2.0)
    assert ready.exists() or proc.exitcode not in (0, None)

    sess = session_slug("sess-crash")
    sess_dir = tmp_path / "uploads" / owner_slug("owner-a") / sess
    # File may exist (linked) without ledger commit.
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits, recover_on_init=True)
    data = ledger.recover()
    # After recover: either billed consistently or file removed — never unbilled file.
    files = (
        [p for p in sess_dir.iterdir() if not p.name.startswith(".")] if sess_dir.exists() else []
    )
    if files:
        assert data["owner_files"] >= 1
        assert data["owner_bytes"] >= 8
        assert data["sessions"].get(sess, {}).get("files", 0) >= 1
    else:
        assert data["owner_files"] == 0
        assert data["owner_bytes"] == 0


def test_commit_save_fail_and_unlink_fail_leaves_no_unbilled_file(tmp_path: Path) -> None:
    limits = _limits()
    real_save = UploadQuotaLedger._save_unlocked
    real_unlink = os.unlink
    fail_save = {"n": 0}

    def flaky_save(self: UploadQuotaLedger, owner_fd: int, data: dict[str, Any]) -> None:
        commits = data.get("commits") or {}
        if commits:
            fail_save["n"] += 1
            if fail_save["n"] == 1:
                raise OSError("simulated quota save failure")
        return real_save(self, owner_fd, data)

    def flaky_unlink(path: str, *args: Any, **kwargs: Any) -> None:
        # Fail rollback unlink of the published candidate once.
        name = path if isinstance(path, str) else ""
        if ("a.txt" in name or (not name and kwargs.get("dir_fd") is not None)) and not getattr(
            flaky_unlink, "_failed", False
        ):
            flaky_unlink._failed = True  # type: ignore[attr-defined]
            raise OSError("simulated unlink failure")
        return real_unlink(path, *args, **kwargs)

    with (
        patch.object(UploadQuotaLedger, "_save_unlocked", flaky_save),
        patch.object(os, "unlink", flaky_unlink),
        pytest.raises(OSError),
        SecureUploadWriter(
            tmp_path, "owner-a", "sess-1", "a.txt", max_bytes=100, quota_limits=limits
        ) as writer,
    ):
        writer.write(b"payload")
        writer.commit()

    # Must not leave an unbilled visible file: recover or fail-closed cleanup.
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    data = ledger.recover()
    sess = session_slug("sess-1")
    sess_dir = tmp_path / "uploads" / owner_slug("owner-a") / sess
    files = (
        [p for p in sess_dir.iterdir() if not p.name.startswith(".")] if sess_dir.exists() else []
    )
    if files:
        assert data["owner_files"] >= len(files)
        assert data["owner_bytes"] >= sum(p.stat().st_size for p in files)
    else:
        assert data["owner_files"] == 0


def test_delete_accounting_fail_after_unlink_recovers(tmp_path: Path) -> None:
    limits = _limits()
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "gone.txt", max_bytes=100, quota_limits=limits
    ) as writer:
        writer.write(b"delete-me")
        writer.commit()
    before = UploadQuotaLedger(tmp_path, "owner-a", limits=limits).rebuild()
    assert before["owner_files"] == 1

    def boom_finalize(self: UploadQuotaLedger, **kwargs: Any) -> None:
        raise OSError("simulated delete accounting failure")

    with (
        patch.object(UploadQuotaLedger, "finalize_delete", boom_finalize),
        pytest.raises(OSError),
    ):
        delete_owned_upload_by_name(tmp_path, "owner-a", "gone.txt", session_id="sess-1")

    # Restart recovery must restore consistent billing (file gone ⇒ files==0).
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits, recover_on_init=True)
    data = ledger.recover()
    sess = session_slug("sess-1")
    sess_dir = tmp_path / "uploads" / owner_slug("owner-a") / sess
    files = (
        [p for p in sess_dir.iterdir() if not p.name.startswith(".")] if sess_dir.exists() else []
    )
    assert files == []
    assert data["owner_files"] == 0
    assert data["owner_bytes"] == 0


def test_scan_4097_empty_session_dirs_fail_closed(tmp_path: Path) -> None:
    limits = _limits()
    owner_root = tmp_path / "uploads" / owner_slug("owner-a")
    owner_root.mkdir(parents=True)
    for i in range(4097):
        (owner_root / f"sess_{i:04d}").mkdir()
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    with pytest.raises(AttachmentGateError) as exc:
        ledger.rebuild()
    assert exc.value.status_code == 429


def test_ledger_schema_rejects_invalid_fields(tmp_path: Path) -> None:
    limits = _limits()
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "ok.txt", max_bytes=100, quota_limits=limits
    ) as writer:
        writer.write(b"x")
        writer.commit()
    path = _ledger_path(tmp_path)
    good = json.loads(path.read_text(encoding="utf-8"))

    def assert_invalid(mutator: Any) -> None:
        bad = json.loads(json.dumps(good))
        mutator(bad)
        path.write_text(json.dumps(bad), encoding="utf-8")
        ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
        with pytest.raises(AttachmentGateError, match="schema"):
            ledger._with_owner_lock(lambda fd: ledger._load_unlocked(fd, rebuild_if_invalid=False))

    assert_invalid(
        lambda d: (
            d["reservations"].__setitem__(
                "r1",
                {
                    "owner": owner_slug("owner-a"),
                    "session": session_slug("sess-1"),
                    "bytes": 1,
                    "files": 1,
                    "created_at": time.time(),
                    # missing state
                },
            )
            or None
        )
    )

    def empty_id(d: dict[str, Any]) -> None:
        d["reservations"] = {
            "": {
                "owner": owner_slug("owner-a"),
                "session": session_slug("sess-1"),
                "bytes": 1,
                "files": 1,
                "created_at": time.time(),
                "state": "reserved",
            }
        }

    assert_invalid(empty_id)

    def empty_session(d: dict[str, Any]) -> None:
        d["reservations"] = {
            "r1": {
                "owner": owner_slug("owner-a"),
                "session": "",
                "bytes": 1,
                "files": 1,
                "created_at": time.time(),
                "state": "reserved",
            }
        }

    assert_invalid(empty_session)

    def neg_created(d: dict[str, Any]) -> None:
        d["reservations"] = {
            "r1": {
                "owner": owner_slug("owner-a"),
                "session": session_slug("sess-1"),
                "bytes": 1,
                "files": 1,
                "created_at": -1,
                "state": "reserved",
            }
        }

    assert_invalid(neg_created)

    def commit_missing_ts(d: dict[str, Any]) -> None:
        cid = next(iter(d["commits"]))
        d["commits"][cid].pop("committed_at", None)

    assert_invalid(commit_missing_ts)
