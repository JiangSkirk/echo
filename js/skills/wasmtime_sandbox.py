"""Wasmtime skill sandbox — prototype only. Not on the production path.

``js.skills.executor`` runs Python and shell. This module must not be
imported from the executor. See docs/prototypes/wasmtime-skill-sandbox.md.
"""

from __future__ import annotations

PRODUCTION_ENABLED: bool = False


def wasmtime_on_production_path() -> bool:
    return False


def wasmtime_runtime_available() -> bool:
    """Always false until an explicit extra is adopted. Not a production gate."""

    return False
