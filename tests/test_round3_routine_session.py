"""Round 3 tests: Work routine owner+session isolation (P0/P1-3).

The requirements baseline (js agent要求.md §3.5) mandates that routines are
partitioned by product + owner + session.  An earlier version of this file
codified owner-scoped (shared-across-sessions) routine definitions; that
contradicted the baseline and has been corrected.

Required behavior:
- routine definitions live under state/routines/<owner_slug>/<session_slug>;
- same owner, different sessions cannot read, approve, disable, or overwrite
  each other's routines;
- different owners cannot see each other's routines (any session);
- the default/local owner is NOT degraded to a shared partition.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from js_work.routines.store import WorkRoutineStore

_OWNER_A = "owner-a-hash-12345678901234567890"
_OWNER_B = "owner-b-hash-123456789012345678901"


def _draft(store: WorkRoutineStore, name: str = "test-routine"):
    return store.create_draft(
        name=name,
        trigger_phrases=["test"],
        routine_type="accessory_order",
    )


def test_routine_store_isolates_by_owner(tmp_path: Path) -> None:
    """Owner B must not see routines created by owner A."""
    store_a = WorkRoutineStore(tmp_path, owner_key_hash=_OWNER_A, session_id="sess-1")
    store_b = WorkRoutineStore(tmp_path, owner_key_hash=_OWNER_B, session_id="sess-1")

    routine = _draft(store_a)
    routines_b = store_b.list_routines()
    assert routine.routine_id not in [r.routine_id for r in routines_b], (
        "Owner B can see owner A's routine - store is not owner-isolated."
    )


def test_routine_definitions_are_session_partitioned(tmp_path: Path) -> None:
    """Same owner, different sessions: full isolation of routine definitions."""
    store_s1 = WorkRoutineStore(tmp_path, owner_key_hash=_OWNER_A, session_id="sess-1")
    store_s2 = WorkRoutineStore(tmp_path, owner_key_hash=_OWNER_A, session_id="sess-2")

    routine = _draft(store_s1)

    # Physical layout includes the session partition.
    assert store_s1.routines_dir.parent.name == store_s1.owner_dir_slug
    assert store_s1.routines_dir != store_s2.routines_dir
    assert store_s1.routines_dir.name.startswith("s_")

    # Session 2 cannot read session 1's routines.
    assert routine.routine_id not in [r.routine_id for r in store_s2.list_routines()]
    with pytest.raises(KeyError):
        store_s2.get(routine.routine_id)

    # Session 2 cannot approve or disable session 1's routine.
    with pytest.raises(KeyError):
        store_s2.approve(routine.routine_id)
    with pytest.raises(KeyError):
        store_s2.disable(routine.routine_id)

    # Session 2 cannot overwrite session 1's routine (create_only guard is
    # per-partition; a same-id draft in session 2 is a *different* routine).
    other = _draft(store_s2, name="other-routine")
    assert other.routine_id != routine.routine_id or store_s1.get(routine.routine_id).name == "test-routine"


def test_same_session_can_manage_own_routine(tmp_path: Path) -> None:
    store = WorkRoutineStore(tmp_path, owner_key_hash=_OWNER_A, session_id="sess-1")
    routine = _draft(store)
    approved = store.approve(routine.routine_id)
    assert approved.status.value == "enabled"
    disabled = store.disable(routine.routine_id)
    assert disabled.status.value == "disabled"


def test_default_local_owner_is_session_partitioned(tmp_path: Path) -> None:
    """The implicit local owner must not degrade into a shared partition."""
    store_s1 = WorkRoutineStore(tmp_path, session_id="sess-1")
    store_s2 = WorkRoutineStore(tmp_path, session_id="sess-2")
    assert store_s1.routines_dir != store_s2.routines_dir
    routine = _draft(store_s1)
    assert routine.routine_id not in [r.routine_id for r in store_s2.list_routines()]
