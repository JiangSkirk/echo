---
id: file-search
name: Advanced File Search
description: "Search files by content, name patterns, or metadata across the workspace."
version: 1.0.0
author: JS Team
type: code
entry: main.py
category: productivity
tags: [files, search, grep, find]
trust_level: builtin
platforms: [macos, linux, windows]
prerequisites:
  commands: [find, grep]
metadata:
  parameters:
    - name: pattern
      type: string
      description: File name pattern to search for (e.g., '*.py')
      required: false
    - name: content
      type: string
      description: Text content to search within files
      required: false
    - name: path
      type: string
      description: Directory path to search in
      required: false
---

# Advanced File Search

Search for files and content within the workspace using powerful patterns.

## Usage

```python
import json, os, subprocess, sys
args = json.loads(os.environ.get("JS_SKILL_ARGS", "{}"))

pattern = args.get("pattern", "*")
search_content = args.get("content", "")
path = args.get("path", ".")

if search_content:
    result = subprocess.run(
        ["grep", "-r", "-l", "-n", search_content, path],
        capture_output=True, text=True
    )
    print(result.stdout or result.stderr)
else:
    result = subprocess.run(
        ["find", path, "-name", pattern],
        capture_output=True, text=True
    )
    print(result.stdout or result.stderr)
```
