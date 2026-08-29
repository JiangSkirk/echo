"""Gateway stays off the Host / AppShell startup import graph."""

from __future__ import annotations

import ast
from pathlib import Path

from js.config import GatewayConfig, JSSettings

ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN = ("js.gateway",)
STARTUP_MODULES = (
    ROOT / "js" / "appshell" / "server.py",
    ROOT / "js" / "appshell" / "launcher.py",
    ROOT / "js" / "web" / "server.py",
    ROOT / "js" / "web" / "lifespan.py",
    ROOT / "js" / "agent" / "__init__.py",
    ROOT / "js_work" / "web.py",
)


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_host_startup_sources_do_not_import_gateway() -> None:
    for path in STARTUP_MODULES:
        imported = _imported_modules(path)
        offenders = [
            name for name in imported if name in FORBIDDEN or name.startswith("js.gateway.")
        ]
        assert not offenders, f"{path}: {offenders}"


def test_gateway_import_has_no_adapter_side_effects() -> None:
    import js.gateway as gateway

    assert gateway.GatewayService is not None
    assert GatewayConfig.model_fields["enabled"].default is False
    assert JSSettings.model_fields["gateway"].default_factory is GatewayConfig


def test_gateway_rejects_coerced_enabled_flag() -> None:
    try:
        GatewayConfig(enabled="true")  # type: ignore[arg-type]
    except Exception as exc:
        assert "exact boolean" in str(exc)
    else:
        raise AssertionError("expected validation error")
