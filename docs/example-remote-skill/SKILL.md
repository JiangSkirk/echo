---
id: todo-manager
name: Todo Manager
description: "Manage todo lists with priorities, deadlines, and categories."
version: 1.0.0
author: JS Agent Community
type: code
entry: main.py
category: productivity
tags: [todo, task, productivity]
trust_level: community
platforms: [macos, linux, windows]
prerequisites:
  commands: [python]
metadata:
  parameters:
    - name: action
      type: string
      description: Action to perform (add, list, done, remove)
      required: true
      enum: [add, list, done, remove]
    - name: task
      type: string
      description: Task description (for add action)
      required: false
    - name: priority
      type: string
      description: Task priority
      required: false
      enum: [low, medium, high]
---

# Todo Manager

A simple todo list manager that persists tasks to a JSON file.

## Supported Actions

- `add` — Add a new task
- `list` — List all pending tasks
- `done` — Mark a task as completed
- `remove` — Remove a task
