"""AppShell package — unified shell protocols (not a merged data plane)."""

from __future__ import annotations

from js.appshell.global_prefs import GlobalPrefs, load_global_prefs, save_global_prefs
from js.appshell.switch import (
    SWITCH_ORDER,
    SwitchResult,
    SwitchStep,
    WorkspaceProduct,
    run_workspace_switch,
)

__all__ = [
    "SWITCH_ORDER",
    "GlobalPrefs",
    "SwitchResult",
    "SwitchStep",
    "WorkspaceProduct",
    "load_global_prefs",
    "run_workspace_switch",
    "save_global_prefs",
]
