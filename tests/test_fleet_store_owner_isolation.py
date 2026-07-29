"""Fleet persistence stores enforce per-owner isolation (F-21 regression)."""

from __future__ import annotations

from pathlib import Path

from js.orchestration.fleet import AgentRole, Task
from js.persistence.agent_store import AgentStore
from js.persistence.task_store import TaskStore

_OWNER_A = "owner-a-hash"
_OWNER_B = "owner-b-hash"


def _task(task_id: str, *, group_id: str | None = None) -> Task:
    return Task(
        id=task_id,
        description=f"task {task_id}",
        role_hint=AgentRole.WORKER,
        group_id=group_id,
    )


class TestAgentStoreOwnerIsolation:
    def test_cross_owner_list_is_empty(self, tmp_path: Path) -> None:
        store = AgentStore(tmp_path / "agents.db")
        store.save("agent-1", "alpha", AgentRole.WORKER, owner_key_hash=_OWNER_A)

        assert [a["id"] for a in store.list_all(_OWNER_A)] == ["agent-1"]
        assert store.list_all(_OWNER_B) == []

    def test_cross_owner_delete_is_denied(self, tmp_path: Path) -> None:
        store = AgentStore(tmp_path / "agents.db")
        store.save("agent-1", "alpha", AgentRole.WORKER, owner_key_hash=_OWNER_A)

        store.delete("agent-1", owner_key_hash=_OWNER_B)

        assert [a["id"] for a in store.list_all(_OWNER_A)] == ["agent-1"]

    def test_cross_owner_upsert_cannot_overwrite(self, tmp_path: Path) -> None:
        store = AgentStore(tmp_path / "agents.db")
        store.save("agent-1", "alpha", AgentRole.WORKER, owner_key_hash=_OWNER_A)

        # Same id under a different owner must create a distinct row, not
        # hijack owner A's record.
        store.save("agent-1", "evil", AgentRole.WORKER, owner_key_hash=_OWNER_B)

        owner_a_rows = store.list_all(_OWNER_A)
        assert len(owner_a_rows) == 1
        assert owner_a_rows[0]["name"] == "alpha"
        assert [a["name"] for a in store.list_all(_OWNER_B)] == ["evil"]

    def test_default_owner_does_not_see_authenticated_rows(self, tmp_path: Path) -> None:
        store = AgentStore(tmp_path / "agents.db")
        store.save("agent-1", "alpha", AgentRole.WORKER, owner_key_hash=_OWNER_A)

        assert store.list_all() == []


class TestTaskStoreOwnerIsolation:
    def test_cross_owner_load_returns_none(self, tmp_path: Path) -> None:
        store = TaskStore(tmp_path / "tasks.db")
        store.save(_task("t-1"), owner_key_hash=_OWNER_A)

        assert store.load("t-1", owner_key_hash=_OWNER_A) is not None
        assert store.load("t-1", owner_key_hash=_OWNER_B) is None

    def test_cross_owner_upsert_cannot_overwrite(self, tmp_path: Path) -> None:
        store = TaskStore(tmp_path / "tasks.db")
        store.save(_task("t-1"), owner_key_hash=_OWNER_A)

        forged = _task("t-1")
        forged.status = "done"
        forged.result = "forged"
        store.save(forged, owner_key_hash=_OWNER_B)

        owner_a_task = store.load("t-1", owner_key_hash=_OWNER_A)
        assert owner_a_task is not None
        assert owner_a_task.status == "pending"
        assert owner_a_task.result is None

    def test_cross_owner_list_recent_is_empty(self, tmp_path: Path) -> None:
        store = TaskStore(tmp_path / "tasks.db")
        store.save(_task("t-1"), owner_key_hash=_OWNER_A)

        assert [t.id for t in store.list_recent(owner_key_hash=_OWNER_A)] == ["t-1"]
        assert store.list_recent(owner_key_hash=_OWNER_B) == []
        assert store.list_recent() == []

    def test_cross_owner_list_by_group_is_empty(self, tmp_path: Path) -> None:
        store = TaskStore(tmp_path / "tasks.db")
        store.save(_task("t-1", group_id="g-1"), owner_key_hash=_OWNER_A)

        assert [t.id for t in store.list_by_group("g-1", owner_key_hash=_OWNER_A)] == ["t-1"]
        assert store.list_by_group("g-1", owner_key_hash=_OWNER_B) == []

    def test_prune_is_scoped_to_owner(self, tmp_path: Path) -> None:
        import sqlite3

        db_path = tmp_path / "tasks.db"
        store = TaskStore(db_path)
        for index in range(3):
            store.save(_task(f"a-{index}"), owner_key_hash=_OWNER_A)
            store.save(_task(f"b-{index}"), owner_key_hash=_OWNER_B)
        # Spread timestamps so pruning is deterministic.
        with sqlite3.connect(str(db_path)) as conn:
            for index in range(3):
                conn.execute(
                    "UPDATE fleet_tasks SET updated_at = ? WHERE id = ?",
                    (f"2026-01-0{index + 1} 00:00:00", f"a-{index}"),
                )
                conn.execute(
                    "UPDATE fleet_tasks SET updated_at = ? WHERE id = ?",
                    (f"2026-01-0{index + 1} 00:00:00", f"b-{index}"),
                )
            conn.commit()

        pruned = store.prune(keep=1, owner_key_hash=_OWNER_A)

        assert pruned == 1
        assert len(store.list_recent(owner_key_hash=_OWNER_A)) == 2
        assert len(store.list_recent(owner_key_hash=_OWNER_B)) == 3


class TestFleetStoreMigration:
    def test_legacy_tables_gain_owner_column(self, tmp_path: Path) -> None:
        import sqlite3

        db_path = tmp_path / "legacy.db"
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                """
                CREATE TABLE fleet_agents (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    model TEXT,
                    capabilities TEXT DEFAULT '[]',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                "INSERT INTO fleet_agents (id, name, role) VALUES ('a-1', 'alpha', 'worker')"
            )
            conn.execute(
                """
                CREATE TABLE fleet_tasks (
                    id TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    role_hint TEXT NOT NULL,
                    priority INTEGER DEFAULT 5,
                    deps TEXT DEFAULT '[]',
                    result TEXT,
                    status TEXT DEFAULT 'pending',
                    assigned_to TEXT,
                    group_id TEXT,
                    conversation_log TEXT DEFAULT '[]',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                "INSERT INTO fleet_tasks (id, description, role_hint) VALUES ('t-1', 'legacy', 'worker')"
            )
            conn.commit()

        agent_store = AgentStore(db_path)
        task_store = TaskStore(db_path)

        # Legacy rows are attributed to the legacy-local sentinel owner and
        # remain invisible to authenticated owners.
        assert [a["id"] for a in agent_store.list_all()] == ["a-1"]
        assert agent_store.list_all(_OWNER_A) == []
        assert task_store.load("t-1") is not None
        assert task_store.load("t-1", owner_key_hash=_OWNER_A) is None
