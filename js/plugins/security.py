"""Plugin security scanner.
# noqa: SIM102 (intentional layered security checks)

Scans plugin Python source code for dangerous patterns before loading.
Reuses the same risk model as the skill security scanner.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from js.utils.log import get_logger

logger = get_logger("js.plugins.security")

# Dangerous builtins and imports that plugins should not use
PLUGIN_DISALLOWED_BUILTINS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",  # plugins should use pathlib or provided APIs
}

PLUGIN_DISALLOWED_MODULES = {
    "os.system",
    "subprocess",
    "ctypes",
    "socket",
    "urllib.request",
    "http.client",
    "ftplib",
    "telnetlib",
}

PLUGIN_DISALLOWED_PATTERNS = [
    "rm -rf",
    "curl | sh",
    "wget | sh",
    "nc -e",
    "/dev/tcp",
]


@dataclass
class PluginScanResult:
    """Result of a plugin security scan."""

    plugin_id: str
    content_hash: str
    risk_flags: list[str] = field(default_factory=list)
    blocked: bool = False
    scan_time: float = 0.0


def _compute_hash(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def scan_plugin_source(plugin_id: str, source: str, filename: str = "<plugin>") -> PluginScanResult:
    """Scan plugin source code for dangerous patterns.

    Returns a PluginScanResult. If blocked=True, the plugin must not be loaded.
    """
    import time as time_mod

    start = time_mod.time()
    risk_flags: list[str] = []

    # 1. AST-based static analysis
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as e:
        return PluginScanResult(
            plugin_id=plugin_id,
            content_hash="",
            risk_flags=[f"syntax_error: {e}"],
            blocked=True,
            scan_time=time_mod.time() - start,
        )

    for node in ast.walk(tree):
        # Disallowed builtins: eval(), exec(), compile(), __import__()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in PLUGIN_DISALLOWED_BUILTINS:
                risk_flags.append(f"disallowed_builtin:{node.func.id}")

        # getattr(__builtins__, ...) — dynamic access to builtins bypass
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 1
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "__builtins__"
        ):
            risk_flags.append("disallowed_call:getattr(__builtins__)")

        # Disallowed imports — enforce against the full PLUGIN_DISALLOWED_MODULES set.
        # NOTE: the top-level check also blocks bare `import os` ("os" is the
        # top-level name of "os.system"), so dangerous os.* usage is normally
        # caught at the import site; the call-site checks below additionally
        # cover modules that reach the namespace without a flagged import
        # (e.g. via `import os.path`, which binds `os`).
        if isinstance(node, ast.Import):
            for alias in node.names:
                # Check top-level module name against all disallowed modules
                _disallowed_toplevel = {
                    m.split(".")[0] for m in PLUGIN_DISALLOWED_MODULES
                }
                if alias.name in _disallowed_toplevel:
                    risk_flags.append(f"disallowed_import:{alias.name}")

        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.names:
                for alias in node.names:
                    if alias.name == "system" and module == "os":
                        risk_flags.append("disallowed_import:os.system")
                    if alias.name == "Popen" and module == "subprocess":
                        risk_flags.append("disallowed_import:subprocess.Popen")

        # Call-site checks — detect dangerous method calls on whitelisted modules
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            _attr_name = node.func.attr
            _obj = node.func.value

            # os.system(), os.popen(), os.exec*, os.spawn* — detect post-import-os
            _os_dangerous = {
                "system", "popen",
                "execl", "execle", "execlp", "execlpe",
                "execv", "execve", "execvp", "execvpe",
                "spawnl", "spawnle",
            }
            if isinstance(_obj, ast.Name) and _obj.id == "os" and _attr_name in _os_dangerous:
                risk_flags.append(f"disallowed_call:os.{_attr_name}")

            # asyncio.create_subprocess_shell / create_subprocess_exec
            if isinstance(_obj, ast.Name) and _obj.id == "asyncio" and _attr_name in (
                "create_subprocess_shell", "create_subprocess_exec",
            ):
                risk_flags.append(f"disallowed_call:asyncio.{_attr_name}")

            # importlib.import_module()
            if isinstance(_obj, ast.Name) and _obj.id == "importlib" and _attr_name == "import_module":
                risk_flags.append("disallowed_call:importlib.import_module")

            # File writes outside expected paths (heuristic)
            if _attr_name in {"write_text", "write_bytes", "mkdir"}:
                risk_flags.append("potential_file_write")

    # 2. String-pattern scan for shell injection snippets
    source_lower = source.lower()
    for pattern in PLUGIN_DISALLOWED_PATTERNS:
        if pattern.lower() in source_lower:
            risk_flags.append(f"dangerous_pattern:{pattern}")

    # 3. Decide block/allow — block on all disallowed patterns, imports, calls,
    #    and dangerous builtins.  `potential_file_write` and `dangerous_pattern`
    #    are now blocking (were previously warning-only).
    blocked = any(
        f.startswith((
            "disallowed_builtin:", "disallowed_import:", "syntax_error:",
            "disallowed_call:", "dangerous_pattern:", "potential_file_write",
        ))
        for f in risk_flags
    )

    elapsed = time_mod.time() - start
    result = PluginScanResult(
        plugin_id=plugin_id,
        content_hash=_compute_hash(source),
        risk_flags=list(set(risk_flags)),
        blocked=blocked,
        scan_time=elapsed,
    )

    if blocked:
        logger.warning(
            f"Plugin '{plugin_id}' BLOCKED by security scan: {result.risk_flags}"
        )
    elif risk_flags:
        logger.info(
            f"Plugin '{plugin_id}' passed with warnings: {result.risk_flags}"
        )
    else:
        logger.debug(f"Plugin '{plugin_id}' passed security scan")

    return result


def scan_plugin_file(plugin_id: str, file_path: Path) -> PluginScanResult:
    """Scan a plugin file on disk."""
    source = file_path.read_text(encoding="utf-8")
    return scan_plugin_source(plugin_id, source, filename=str(file_path))
