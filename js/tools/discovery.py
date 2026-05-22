"""AST-based automatic tool discovery — no manual imports needed.

Inspired by Hermes tools/registry.py: discovers tools by AST-inspecting modules
for top-level registry.register() calls.
"""

from __future__ import annotations

import ast
from pathlib import Path

from js.utils.log import get_logger

logger = get_logger("js.tools.discovery")


def _module_has_tool_registration(path: Path) -> bool:
    """Check if a Python file contains tool registration calls."""
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "register" and isinstance(func.value, ast.Name):
                return True
    return False



