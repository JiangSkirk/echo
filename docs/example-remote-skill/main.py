#!/usr/bin/env python3
"""Todo manager skill implementation."""

import json
import os
from pathlib import Path

TODO_FILE = Path(os.environ.get("JS_SKILL_WORKSPACE", ".")) / "todos.json"


def load_todos() -> list[dict]:
    if TODO_FILE.exists():
        return json.loads(TODO_FILE.read_text())
    return []


def save_todos(todos: list[dict]) -> None:
    TODO_FILE.write_text(json.dumps(todos, indent=2))


def add_task(task: str, priority: str = "medium") -> dict:
    todos = load_todos()
    todos.append({"task": task, "priority": priority, "done": False})
    save_todos(todos)
    return {"success": True, "output": f"Added: {task} ({priority})"}


def list_tasks() -> dict:
    todos = load_todos()
    pending = [t for t in todos if not t.get("done")]
    if not pending:
        return {"success": True, "output": "No pending tasks."}
    lines = [f"[{i+1}] {t['task']} ({t['priority']})" for i, t in enumerate(pending)]
    return {"success": True, "output": "\n".join(lines)}


def done_task(index: int) -> dict:
    todos = load_todos()
    pending = [t for t in todos if not t.get("done")]
    if index < 1 or index > len(pending):
        return {"success": False, "error": f"Invalid task index: {index}"}
    task = pending[index - 1]
    task["done"] = True
    save_todos(todos)
    return {"success": True, "output": f"Done: {task['task']}"}


def remove_task(index: int) -> dict:
    todos = load_todos()
    pending = [t for t in todos if not t.get("done")]
    if index < 1 or index > len(pending):
        return {"success": False, "error": f"Invalid task index: {index}"}
    task = pending[index - 1]
    todos.remove(task)
    save_todos(todos)
    return {"success": True, "output": f"Removed: {task['task']}"}


if __name__ == "__main__":
    args = json.loads(os.environ.get("JS_SKILL_ARGS", "{}"))
    action = args.get("action", "list")
    task = args.get("task", "")
    priority = args.get("priority", "medium")
    index = args.get("index", 0)

    if action == "add":
        result = add_task(task, priority)
    elif action == "list":
        result = list_tasks()
    elif action == "done":
        result = done_task(index)
    elif action == "remove":
        result = remove_task(index)
    else:
        result = {"success": False, "error": f"Unknown action: {action}"}

    print(json.dumps(result))
