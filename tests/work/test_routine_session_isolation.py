"""Verify: Work routine execution is session-isolated.

Session A and Session B share the same owner but must not be able to
read each other's input/output files.  This test creates a source file
under session A's private root and confirms session B cannot resolve
the same relative path to session A's file.
"""

from __future__ import annotations

from pathlib import Path

from js.echo.attachment_gate import session_slug
from js_work.file_scope import LOCAL_WORK_OWNER, WorkOwnerFileScope


def test_routine_input_is_session_isolated(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    scope_a = WorkOwnerFileScope(workspace, owner=LOCAL_WORK_OWNER, session_id="session-a")
    scope_b = WorkOwnerFileScope(workspace, owner=LOCAL_WORK_OWNER, session_id="session-b")

    # Create a source file under session A
    source_a = scope_a.private_root / "source.xlsx"
    source_a.parent.mkdir(parents=True, exist_ok=True)
    source_a.write_bytes(b"session-a-secret")

    # Session A can resolve it
    resolved_a = scope_a.resolve_routine_input("source.xlsx")
    assert resolved_a == source_a
    assert resolved_a.read_bytes() == b"session-a-secret"

    # Session B resolving the same relative name must NOT see session A's file
    resolved_b = scope_b.resolve_routine_input("source.xlsx")
    assert resolved_b != source_a
    assert not resolved_b.exists()


def test_routine_output_is_session_isolated(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    scope_a = WorkOwnerFileScope(workspace, owner=LOCAL_WORK_OWNER, session_id="session-a")
    scope_b = WorkOwnerFileScope(workspace, owner=LOCAL_WORK_OWNER, session_id="session-b")

    # Session A writes an output
    output_a = scope_a.resolve_output("reports/result.xlsx")
    output_a.parent.mkdir(parents=True, exist_ok=True)
    output_a.write_bytes(b"session-a-output")

    # Session B's output path must be in a different directory
    output_b = scope_b.resolve_output("reports/result.xlsx")
    assert output_a != output_b
    assert session_slug("session-a") in str(output_a)
    assert session_slug("session-b") in str(output_b)
