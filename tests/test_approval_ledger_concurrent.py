"""RED: ApprovalQueue concurrent multi-instance must not corrupt the hash chain.

Two ``ApprovalQueue`` instances pointing at the *same* ledger path and
running concurrently must either:
  1. coordinate via a file lock so only one writes at a time, or
  2. refuse to start a second instance (fail closed).

Currently the implementation gives each instance its own in-memory
``_ledger_seq``/``_ledger_prev_hash`` and appends independently, which
breaks the hash chain.  This test exercises the concurrent case and
expects the ledger to remain consistent (no broken prev_hash links).
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from js.security.approvals import ApprovalQueue


def _request(queue: ApprovalQueue, session_id: str, owner: str) -> None:
    queue.request_decision(
        "shell",
        {"command": f"echo {session_id}"},
        context="web",
        session_id=session_id,
        run_id=f"run-{session_id}",
        owner_key_hash=owner,
        queue_if_unhandled=True,
    )


def test_concurrent_approval_queues_same_ledger_must_not_corrupt_chain(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "echo_approvals.jsonl"
    queue_a = ApprovalQueue(ledger_path=ledger_path)
    queue_b = ApprovalQueue(ledger_path=ledger_path)

    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def _worker(queue: ApprovalQueue, session_id: str, owner: str) -> None:
        try:
            barrier.wait(timeout=5.0)
            _request(queue, session_id, owner)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t_a = threading.Thread(
        target=_worker, args=(queue_a, "session-a", "owner-a"), name="qa"
    )
    t_b = threading.Thread(
        target=_worker, args=(queue_b, "session-b", "owner-b"), name="qb"
    )
    t_a.start()
    t_b.start()
    t_a.join(timeout=10.0)
    t_b.join(timeout=10.0)

    assert errors == [], f"workers raised: {errors}"

    rows = [json.loads(line) for line in ledger_path.read_text().splitlines()]
    assert len(rows) == 2
    prev_hash = "0" * 64
    for row in rows:
        assert row["prev_hash"] == prev_hash, (
            f"hash chain broken: expected prev_hash={prev_hash}, got {row['prev_hash']}"
        )
        prev_hash = row["record_hash"].removeprefix("sha256:")
