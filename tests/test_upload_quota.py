"""F-11: owner/session upload quota reserve → commit/release."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from js.echo.attachment_gate import AttachmentGateError, SecureUploadWriter
from js.echo.upload_quota import UploadQuotaLedger, UploadQuotaLimits


def _limits(**kwargs: int) -> UploadQuotaLimits:
    base = {
        "owner_max_bytes": 2_000,
        "owner_max_files": 3,
        "session_max_bytes": 1_500,
        "session_max_files": 2,
        "min_free_disk_bytes": 0,
    }
    base.update(kwargs)
    return UploadQuotaLimits(**base)


def test_reserve_commit_and_delete_releases(
    tmp_path: Path,
) -> None:
    limits = _limits()
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "a.txt", max_bytes=500, quota_limits=limits
    ) as writer:
        writer.write(b"hello")
        path = writer.commit()
    assert path.exists()
    ledger = UploadQuotaLedger(tmp_path, "owner-a", limits=limits)
    data = ledger.rebuild()
    assert data["owner_files"] >= 1
    assert data["owner_bytes"] >= 5

    from js.echo.attachment_gate import delete_owned_upload_by_name

    assert delete_owned_upload_by_name(tmp_path, "owner-a", "a.txt", "sess-1")
    data = ledger.rebuild()
    assert data["owner_files"] == 0
    assert data["owner_bytes"] == 0


def test_owner_byte_quota_returns_413(tmp_path: Path) -> None:
    limits = _limits(owner_max_bytes=500, session_max_bytes=10_000)
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "a.txt", max_bytes=400, quota_limits=limits
    ) as writer:
        writer.write(b"x" * 100)
        writer.commit()
    # Remaining capacity is 400; reserving another 400-byte max should fail once
    # committed usage (100) + new reservation (400) exceeds 500.
    with pytest.raises(AttachmentGateError) as exc:
        SecureUploadWriter(
            tmp_path, "owner-a", "sess-2", "b.txt", max_bytes=450, quota_limits=limits
        )
    assert exc.value.status_code == 413


def test_session_file_quota_returns_429(tmp_path: Path) -> None:
    limits = _limits(session_max_files=1, owner_max_files=10, owner_max_bytes=10_000)
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "a.txt", max_bytes=100, quota_limits=limits
    ) as writer:
        writer.write(b"a")
        writer.commit()
    with pytest.raises(AttachmentGateError) as exc:
        SecureUploadWriter(
            tmp_path, "owner-a", "sess-1", "b.txt", max_bytes=100, quota_limits=limits
        )
    assert exc.value.status_code == 429


def test_failed_upload_releases_reservation(tmp_path: Path) -> None:
    limits = _limits(owner_max_bytes=600, session_max_bytes=600)
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "a.txt", max_bytes=500, quota_limits=limits
    ) as writer:
        writer.write(b"partial")
        # no commit — close releases reservation
    # Should still be able to reserve again at full capacity.
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "b.txt", max_bytes=500, quota_limits=limits
    ) as writer:
        writer.write(b"ok")
        writer.commit()


def test_owner_isolation(tmp_path: Path) -> None:
    limits = _limits(owner_max_bytes=500, session_max_bytes=500, owner_max_files=1)
    with SecureUploadWriter(
        tmp_path, "owner-a", "sess-1", "a.txt", max_bytes=400, quota_limits=limits
    ) as writer:
        writer.write(b"a" * 50)
        writer.commit()
    # Different owner is unaffected.
    with SecureUploadWriter(
        tmp_path, "owner-b", "sess-1", "a.txt", max_bytes=400, quota_limits=limits
    ) as writer:
        writer.write(b"b" * 50)
        writer.commit()


def test_concurrent_reservations_do_not_overcommit(tmp_path: Path) -> None:
    limits = _limits(owner_max_bytes=500, session_max_bytes=500, owner_max_files=2)
    results: list[str] = []

    def worker(name: str) -> None:
        try:
            with SecureUploadWriter(
                tmp_path,
                "owner-a",
                "sess-1",
                name,
                max_bytes=400,
                quota_limits=limits,
            ) as writer:
                writer.write(b"x" * 50)
                writer.commit()
            results.append("ok")
        except AttachmentGateError:
            results.append("reject")

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(worker, [f"f{i}.txt" for i in range(4)]))
    assert results.count("ok") == 1
    assert results.count("reject") == 3


def test_low_disk_returns_507(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    limits = _limits(min_free_disk_bytes=10_000)

    class _Usage:
        f_bavail = 1
        f_frsize = 1

    monkeypatch.setattr("js.echo.upload_quota.os.statvfs", lambda _path: _Usage())
    with pytest.raises(AttachmentGateError) as exc:
        SecureUploadWriter(
            tmp_path, "owner-a", "sess-1", "a.txt", max_bytes=100, quota_limits=limits
        )
    assert exc.value.status_code == 507
