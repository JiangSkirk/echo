"""AST-based automatic tool discovery — no manual imports needed.

Inspired by Hermes tools/registry.py: discovers tools by AST-inspecting modules
for top-level registry.register() calls.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

from js.tools.registry import ToolRegistry
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


def discover_tools_in_directory(tools_dir: Path, registry: ToolRegistry) -> int:
    """Auto-discover and register tools from a directory."""
    count = 0
    if not tools_dir.exists():
        return 0

    # Add parent to path for imports
    import sys
    parent = str(tools_dir.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)

    for path in sorted(tools_dir.glob("*.py")):
        if path.name in ("__init__.py", "registry.py", "discovery.py"):
            continue

        if not _module_has_tool_registration(path):
            continue

        module_name = f"{tools_dir.name}.{path.stem}"
        try:
            importlib.import_module(module_name)
            count += 1
            logger.info(f"Auto-discovered tools from {module_name}")
        except Exception as e:
            logger.warning(f"Failed to import tool module {module_name}: {e}")

    return count
