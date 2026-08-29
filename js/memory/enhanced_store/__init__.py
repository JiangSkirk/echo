"""Enhanced multi-layer memory system with dreaming, episodes, and semantic search."""

from __future__ import annotations

import sys
from types import ModuleType
from typing import Any

from js.memory.enhanced_store import store as _store
from js.memory.enhanced_store.constants import _LEGACY_LOCAL_OWNER
from js.memory.enhanced_store.models import Episode, SemanticMemory
from js.memory.enhanced_store.store import EnhancedMemoryStore
from js.memory.enhanced_store.store import db_connection as db_connection


class _EnhancedStoreModule(ModuleType):
    """Keep ``js.memory.enhanced_store.db_connection`` pointing at store.py.

    Tests monkeypatch this package-level name; EnhancedMemoryStore looks the
    name up in ``store``'s globals.
    """

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "db_connection":
            _store.db_connection = value
        super().__setattr__(name, value)


_mod = sys.modules[__name__]
_pkg = _EnhancedStoreModule(__name__, _mod.__doc__)
_pkg.__dict__.update(_mod.__dict__)
sys.modules[__name__] = _pkg

__all__ = [
    "EnhancedMemoryStore",
    "Episode",
    "SemanticMemory",
    "_LEGACY_LOCAL_OWNER",
    "db_connection",
]
