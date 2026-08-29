"""Product Desktop/Memory Cell routes stay inert while enforce is off."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.config import MemoryConfig, OrinConfig
from js.memory.store import MemoryStore
from js.orin.stage_c import (
    bind_product_enforce,
    desktop_memory_cells_allowed,
    reset_product_enforce,
)
from js.orind.daemon import OrinDaemon
from js.tools.desktop_tools import DesktopTools


def test_default_desktop_tools_still_construct_without_cell_backend() -> None:
    tools = DesktopTools.__new__(DesktopTools)
    tools._cell_backend = None
    assert tools._cell_backend is None


def test_identity_without_harness_does_not_spawn_desktop_or_memory(tmp_path: Path) -> None:
    daemon = OrinDaemon(
        state_dir=tmp_path,
        stage_b=True,
        cell_desktop=True,
        cell_memory=True,
        cell_identity_enforce=True,
        c1_test_harness=False,
    )
    try:
        assert daemon._cell_identity_enforce is True  # noqa: SLF001
        assert daemon._cell_desktop_enabled is False  # noqa: SLF001
        assert daemon._cell_memory_enabled is False  # noqa: SLF001
        assert desktop_memory_cells_allowed(identity=True, harness=False, enforce=False) is False
        assert desktop_memory_cells_allowed(identity=True, harness=True, enforce=False) is True
        assert daemon._cells_kept_resident is True  # noqa: SLF001
    finally:
        daemon._store.close()  # noqa: SLF001


def test_ambient_memory_writes_blocked_only_when_product_enforce_bound(
    tmp_path: Path,
) -> None:
    store = MemoryStore(tmp_path, MemoryConfig())
    store.store("note", "hello")
    token = bind_product_enforce(True)
    try:
        with pytest.raises(RuntimeError, match="orin.enforce"):
            store.store("note-two", "nope")
    finally:
        reset_product_enforce(token)


def test_orin_config_product_flags_do_not_enable_enforce() -> None:
    config = OrinConfig(cell_desktop=True, cell_memory=True, cell_identity_enforce=True)
    assert config.enforce is False
    assert config.echo_minimal_os is False
