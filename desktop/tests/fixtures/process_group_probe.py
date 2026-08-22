#!/usr/bin/python3
"""Real process-group fixture for the Tauri sidecar lifecycle tests."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def _sleep_forever() -> None:
    while True:
        time.sleep(60)


def _spawn_member(
    *,
    escaped: bool = False,
    ignore_term: bool = False,
    own_group: bool = False,
) -> subprocess.Popen[bytes]:
    arguments = [sys.executable, __file__, "--member"]
    if ignore_term:
        arguments.append("--ignore-term")
    return subprocess.Popen(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=escaped,
        preexec_fn=os.setpgrp if own_group else None,
    )


def _write_evidence(
    member: subprocess.Popen[bytes],
    escaped: subprocess.Popen[bytes] | None,
    launch_pgid: int,
    setpgid_errno: int | None,
) -> None:
    evidence_path = Path(os.environ["JS_AGENT_PROCESS_GROUP_EVIDENCE"])
    payload = {
        "leader_pid": os.getpid(),
        "member_pid": member.pid,
        "pgid": launch_pgid,
        "leader_current_pgid": os.getpgrp(),
        "setpgid_errno": setpgid_errno,
        "escaped_pid": escaped.pid if escaped is not None else None,
    }
    temporary = evidence_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    os.replace(temporary, evidence_path)


def _sentinel(pid: int, source_digest: str, *, schema: str = "JSAgentHostReadyV1") -> dict[str, object]:
    return {
        "pid": pid,
        "port": 43127,
        "schema": schema,
        "source_digest": source_digest,
    }


def _emit(payload: dict[str, object], *, canonical: bool = True) -> None:
    separators = (",", ":") if canonical else None
    print(json.dumps(payload, separators=separators), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--member", action="store_true")
    parser.add_argument("--ignore-term", action="store_true")
    parser.add_argument("--source-digest")
    args = parser.parse_args()
    if args.member:
        if args.ignore_term:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        _sleep_forever()
        return 0

    mode = os.environ["JS_AGENT_PROCESS_GROUP_MODE"]
    ignore_term = os.environ.get("JS_AGENT_PROCESS_GROUP_IGNORE_TERM") == "1"
    if ignore_term:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    launch_pgid = os.getpgrp()
    member = _spawn_member(ignore_term=ignore_term)
    setpgid_errno = None
    if mode == "escaped_pid":
        escaped = _spawn_member(escaped=True)
    elif mode == "leader_group_escape_attempt":
        escaped = _spawn_member(own_group=True)
        try:
            os.setpgid(0, escaped.pid)
        except OSError as error:
            setpgid_errno = error.errno
    else:
        escaped = None
    _write_evidence(member, escaped, launch_pgid, setpgid_errno)

    if mode == "stdin_failure":
        os.close(0)
        _sleep_forever()
    if mode == "eof":
        os.close(1)
        _sleep_forever()
    if mode == "read_error":
        os.write(1, b"\xff\n")
        os.close(1)
        _sleep_forever()
    if mode == "timeout":
        _sleep_forever()

    assert args.source_digest is not None
    ready = _sentinel(os.getpid(), args.source_digest)
    if mode == "malformed":
        print("not-json", flush=True)
    elif mode == "noncanonical":
        _emit(ready, canonical=False)
    elif mode == "unknown_field":
        ready["unexpected"] = True
        _emit(ready)
    elif mode == "wrong_schema":
        _emit(_sentinel(os.getpid(), args.source_digest, schema="WrongReadyV1"))
    elif mode == "wrong_digest":
        _emit(_sentinel(os.getpid(), "cd" * 32))
    elif mode == "invalid_pid":
        _emit(_sentinel(0, args.source_digest))
    elif mode == "escaped_pid":
        assert escaped is not None
        _emit(_sentinel(escaped.pid, args.source_digest))
    elif mode in {"leader_group_escape_attempt", "ready_then_exit", "valid"}:
        _emit(ready)
    else:
        raise ValueError(f"unknown probe mode: {mode}")

    if mode == "ready_then_exit":
        return 0
    _sleep_forever()
    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    raise SystemExit(main())
