---
id: python-debug
name: Python Debug Assistant
description: "Python debugging workflow using pdb, logging, and traceback analysis."
version: 1.0.0
author: JS Team
type: prompt
category: software-development
tags: [python, debugging, pdb, logging, traceback]
trust_level: builtin
platforms: [macos, linux, windows]
metadata:
  parameters:
    - name: code
      type: string
      description: Python code or error traceback to debug
      required: false
---

# Python Debug Assistant

Guide for debugging Python code effectively.

## Quick pdb Commands

| Command | Action |
|---------|--------|
| `python -m pdb script.py` | Start with debugger |
| `import pdb; pdb.set_trace()` | Breakpoint in code |
| `breakpoint()` | Python 3.7+ breakpoint |
| `n` / `s` | Next / Step into |
| `c` / `q` | Continue / Quit |
| `p var` / `pp var` | Print / Pretty-print |
| `l` / `w` | List source / Where (stack) |
| `u` / `d` | Up / Down stack frame |

## Logging Over Print

```python
import logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s')
logging.debug("variable x = %s", x)
```

## Traceback Analysis Tips

1. Read bottom-up: the last line is the actual error
2. Check the line numbers in the stack trace
3. Look for `NoneType` errors → missing return/assignment
4. `KeyError` / `IndexError` → validate data before access
5. `ModuleNotFoundError` → check virtualenv and `pip list`

## Execution

When the user shares Python code or an error, guide them to identify the root cause using the debugging techniques above.
