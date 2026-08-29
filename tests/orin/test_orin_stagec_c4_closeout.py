"""C4: Office/WebBridge stay classified; Build staging is Cell-private."""

from __future__ import annotations

from pathlib import Path

from js.orind.cells.build import BuildCell, build_cell_private_staging


def test_build_cell_default_staging_is_state_private(tmp_path: Path) -> None:
    expected = build_cell_private_staging(tmp_path)
    assert expected == tmp_path / "orin" / "cell-private" / "build"
    cell = BuildCell(socket_path=tmp_path / "unused.sock", state_dir=tmp_path)
    assert cell._workspace == expected  # noqa: SLF001
    assert expected.is_dir()
    assert not (tmp_path / ".js-code").exists()


def test_build_cell_workspace_override_stays_explicit(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    cell = BuildCell(
        socket_path=tmp_path / "unused.sock",
        state_dir=tmp_path,
        workspace=workspace,
    )
    assert cell._workspace == workspace  # noqa: SLF001
