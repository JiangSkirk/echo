"""Tests for the long-running task manager."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.tasks.manager import TaskManager


@pytest.fixture
def manager(tmp_path: Path) -> TaskManager:
    return TaskManager(tmp_path / "tasks.db")


class TestTaskManagerLifecycle:
    """Tests for task CRUD and status transitions."""

    def test_register_task(self, manager: TaskManager) -> None:
        task_id = manager.register(name="Test Task", type="chat")
        assert task_id.startswith("task-")
        task = manager.get(task_id)
        assert task is not None
        assert task["name"] == "Test Task"
        assert task["type"] == "chat"
        assert task["status"] == "running"
        assert task["progress"] == 0.0

    def test_update_progress(self, manager: TaskManager) -> None:
        task_id = manager.register(name="Progress Task", type="chat")
        ok = manager.update_progress(task_id, 0.5, "halfway done")
        assert ok is True
        task = manager.get(task_id)
        assert task["progress"] == 0.5
        assert task["result_preview"] == "halfway done"

    def test_complete_task(self, manager: TaskManager) -> None:
        task_id = manager.register(name="Complete Task", type="chat")
        ok = manager.complete(task_id, "done")
        assert ok is True
        task = manager.get(task_id)
        assert task["status"] == "completed"
        assert task["progress"] == 1.0

    def test_fail_task(self, manager: TaskManager) -> None:
        task_id = manager.register(name="Fail Task", type="chat")
        ok = manager.fail(task_id, "timeout")
        assert ok is True
        task = manager.get(task_id)
        assert task["status"] == "failed"
        assert task["error"] == "timeout"

    def test_pause_and_resume(self, manager: TaskManager) -> None:
        task_id = manager.register(name="Pause Task", type="chat")
        manager.pause(task_id)
        task = manager.get(task_id)
        assert task["status"] == "paused"
        manager.resume(task_id)
        task = manager.get(task_id)
        assert task["status"] == "running"

    def test_pause_resume_delete_are_owner_scoped(self, manager: TaskManager) -> None:
        task_id = manager.register(name="Owner Task", type="chat", owner_key_hash="owner-a")

        assert manager.pause(task_id, owner_key_hash="owner-b") is False
        assert manager.get(task_id, owner_key_hash="owner-a")["status"] == "running"

        assert manager.pause(task_id, owner_key_hash="owner-a") is True
        assert manager.get(task_id, owner_key_hash="owner-a")["status"] == "paused"

        assert manager.resume(task_id, owner_key_hash="owner-b") is False
        assert manager.get(task_id, owner_key_hash="owner-a")["status"] == "paused"

        assert manager.resume(task_id, owner_key_hash="owner-a") is True
        assert manager.delete(task_id, owner_key_hash="owner-b") is False
        assert manager.get(task_id, owner_key_hash="owner-a") is not None
        assert manager.delete(task_id, owner_key_hash="owner-a") is True

    def test_local_task_is_not_visible_or_mutable_to_named_owner(
        self,
        manager: TaskManager,
    ) -> None:
        task_id = manager.register(name="Local Task", type="chat")

        assert manager.get(task_id, owner_key_hash="owner-a") is None
        assert manager.pause(task_id, owner_key_hash="owner-a") is False
        assert manager.resume(task_id, owner_key_hash="owner-a") is False
        assert manager.delete(task_id, owner_key_hash="owner-a") is False
        assert manager.list(owner_key_hash="owner-a") == []
        assert manager.get(task_id, owner_key_hash="local-user") is not None

    def test_delete_task(self, manager: TaskManager) -> None:
        task_id = manager.register(name="Delete Task", type="chat")
        ok = manager.delete(task_id)
        assert ok is True
        assert manager.get(task_id) is None

    def test_checkpoint_data(self, manager: TaskManager) -> None:
        task_id = manager.register(name="Checkpoint Task", type="chat")
        ok = manager.update_checkpoint(task_id, {"turn": 3, "messages": []})
        assert ok is True
        task = manager.get(task_id)
        assert task["checkpoint_data"]["turn"] == 3


class TestTaskManagerList:
    """Tests for task listing and filtering."""

    def test_list_all(self, manager: TaskManager) -> None:
        manager.register(name="Task 1", type="chat")
        manager.register(name="Task 2", type="cron")
        tasks = manager.list()
        assert len(tasks) == 2

    def test_list_by_status(self, manager: TaskManager) -> None:
        manager.register(name="Running", type="chat")
        t2 = manager.register(name="Paused", type="chat")
        manager.pause(t2)
        running = manager.list(status="running")
        paused = manager.list(status="paused")
        assert len(running) == 1
        assert len(paused) == 1

    def test_list_by_type(self, manager: TaskManager) -> None:
        manager.register(name="Chat 1", type="chat")
        manager.register(name="Chat 2", type="chat")
        manager.register(name="Cron 1", type="cron")
        chats = manager.list(type="chat")
        assert len(chats) == 2

    def test_list_limit(self, manager: TaskManager) -> None:
        for i in range(10):
            manager.register(name=f"Task {i}", type="chat")
        tasks = manager.list(limit=5)
        assert len(tasks) == 5

    def test_get_by_session(self, manager: TaskManager) -> None:
        manager.register(name="Session Task", type="chat", session_id="sess-123")
        manager.register(name="Other Task", type="chat", session_id="sess-456")
        sess_tasks = manager.get_by_session("sess-123")
        assert len(sess_tasks) == 1
        assert sess_tasks[0]["session_id"] == "sess-123"


class TestTaskManagerPrune:
    """Tests for task pruning."""

    def test_prune_old_tasks(self, manager: TaskManager) -> None:
        for i in range(10):
            tid = manager.register(name=f"Task {i}", type="chat")
            manager.complete(tid)
        pruned = manager.prune(keep=5)
        assert pruned == 5
        remaining = manager.list()
        assert len(remaining) == 5
