"""Reserved packages stay off the default Host / AppShell startup import graph."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = ("js.pipeline", "js.friends", "js.mobile")
STARTUP_MODULES = (
    ROOT / "js" / "appshell" / "server.py",
    ROOT / "js" / "appshell" / "launcher.py",
    ROOT / "js" / "web" / "server.py",
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


def test_host_startup_sources_do_not_import_reserved_packages() -> None:
    for path in STARTUP_MODULES:
        imported = _imported_modules(path)
        offenders = [
            name
            for name in imported
            if name in FORBIDDEN or name.startswith(tuple(f"{item}." for item in FORBIDDEN))
        ]
        assert not offenders, f"{path}: {offenders}"


def test_mobile_closeout_declares_not_implemented() -> None:
    text = (ROOT / "docs" / "mobile" / "MOBILE_CLOSEOUT.md").read_text(encoding="utf-8")
    assert "not_implemented" in text
    assert "376" in text
    assert "mobile_enabled" in text
    assert "js.mobile" in text
    assert "Bonjour" in text
    assert "ACP" in text
    assert "tests/test_r5_mobile.py" in text
    assert "Mobile is implemented" in text
    assert "do not import" in text.lower() or "Must not import" in text


def test_evolution_mutate_routes_require_admin_in_source() -> None:
    source = (ROOT / "js" / "web" / "server.py").read_text(encoding="utf-8")
    assert "Depends(require_admin)" in source
    assert "async def evolution_run(auth: dict[str, Any] = Depends(require_admin))" in source
    assert "async def evolution_reflect(auth: dict[str, Any] = Depends(require_admin))" in source
    assert "async def evolution_approve(" in source
    assert "async def evolution_reject(" in source
    approve_idx = source.index("async def evolution_approve(")
    reject_idx = source.index("async def evolution_reject(")
    assert "Depends(require_admin)" in source[approve_idx : approve_idx + 220]
    assert "Depends(require_admin)" in source[reject_idx : reject_idx + 220]
    assert '_execute_evolution_action("approve", auth, proposal_id=proposal_id)' in source
    assert '_execute_evolution_action("reject", auth, proposal_id=proposal_id)' in source
