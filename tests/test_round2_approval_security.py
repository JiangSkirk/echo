"""Round 2 attack tests: Approval ledger security gaps.

1. The MAC key is a hardcoded constant in source (``echo-approval-ledger-mac``).
   Any attacker with source access can forge ledger entries.  The key must be
   derived from a per-installation secret.
2. ``approval_execution_claimed`` / ``approval_finalized`` lifecycle events
   must be recorded for consumer-token-bound execution.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from js.security.approvals import ApprovalQueue


def test_ledger_mac_key_is_not_hardcoded_constant() -> None:
    """The approval ledger MAC key must not be a source-level constant."""
    import inspect

    source = inspect.getsource(ApprovalQueue)
    assert "echo-approval-ledger-mac" not in source, (
        "ApprovalQueue source still contains the hardcoded MAC key literal "
        "'echo-approval-ledger-mac'; the key must be derived from a "
        "per-installation secret."
    )


def test_two_independent_installations_have_different_mac_keys(tmp_path: Path) -> None:
    """Two queues with different state dirs must derive different MAC keys."""
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    q_a = ApprovalQueue(ledger_path=dir_a / "ledger.jsonl")
    q_b = ApprovalQueue(ledger_path=dir_b / "ledger.jsonl")
    assert q_a._ledger_mac_key != q_b._ledger_mac_key, (
        "Different installations must derive different MAC keys."
    )


def test_ledger_entry_forged_mac_rejected(tmp_path: Path) -> None:
    """A ledger entry with a wrong MAC must be rejected on load."""
    ledger = tmp_path / "ledger.jsonl"
    q = ApprovalQueue(ledger_path=ledger)
    # Write a valid entry via the queue.
    from js.security.approvals import ApprovalRequest
    req = ApprovalRequest(
        id="test-1",
        tool_name="shell",
        arguments={"cmd": "ls"},
        timestamp=1.0,
        context="test",
    )
    q._append_ledger("approval_requested", req)

    # Append a forged entry with a bad MAC.
    with ledger.open("a") as f:
        f.write(json.dumps({
            "seq": 99,
            "event_type": "approval_approved",
            "request_id": "forged",
            "tool_name": "shell",
            "context": "test",
            "session_id": "",
            "run_id": "",
            "owner_key_hash": "",
            "arguments_hash": "x",
            "timestamp": 1.0,
            "prev_hash": "forged",
            "reason": "forged",
            "record_hash": "sha256:forged",
            "mac": "forged",
        }) + "\n")

    # Reloading must raise.
    with pytest.raises(ValueError, match="chain broken|record_hash mismatch|MAC mismatch"):
        ApprovalQueue(ledger_path=ledger)


def test_multiprocess_concurrent_append_no_duplicate_seq(tmp_path: Path) -> None:
    """N processes racing first-init + appends must ALL succeed with exact counts.

    P1-10: previously this test never asserted child exit codes nor the exact
    record count, so a process dying on the O_EXCL key race could go unnoticed.
    """
    ledger = tmp_path / "ledger.jsonl"
    code = f"""
import json, os, sys, time
from pathlib import Path
sys.path.insert(0, {repr(str(Path(__file__).resolve().parents[1]))})
from js.security.approvals import ApprovalQueue, ApprovalRequest
q = ApprovalQueue(ledger_path=Path({repr(str(ledger))}))
for i in range(20):
    req = ApprovalRequest(
        id=f"p{{os.getpid()}}-{{i}}",
        tool_name="shell",
        arguments={{"cmd": "ls"}},
        timestamp=time.time(),
        context="test",
    )
    q._append_ledger("approval_requested", req)
print("child-ok", flush=True)
"""
    repo_root = str(Path(__file__).resolve().parents[1])
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": repo_root}
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", code],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    # Every child MUST exit 0 -- a crashed child is a failure, not a skip.
    for p in procs:
        stdout, stderr = p.communicate(timeout=60)
        assert p.returncode == 0, (
            f"child exited {p.returncode}; stdout={stdout!r} stderr={stderr!r}"
        )
        assert "child-ok" in stdout

    # Exactly 40 records, no duplicates, contiguous seqs.
    seqs = []
    with ledger.open() as f:
        for line in f:
            row = json.loads(line)
            seqs.append(row["seq"])
    assert len(seqs) == 40, f"expected exactly 40 records, got {len(seqs)}"
    assert len(seqs) == len(set(seqs)), f"Duplicate seq numbers found: {seqs}"
    assert sorted(seqs) == list(range(40)), f"non-contiguous seqs: {sorted(seqs)}"

    # Key file: exact length, 0600 permission, shared by both processes.
    key_path = tmp_path / ".approval_ledger_mac_key"
    assert key_path.exists()
    import stat as _stat

    assert _stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert len(key_path.read_bytes()) == 32

    # Reloading must succeed (chain valid) and share the persisted key.
    reloaded = ApprovalQueue(ledger_path=ledger)
    assert reloaded._ledger_mac_key == key_path.read_bytes()
