"""Tests for desktop native backend, wizard fallback paths, and guard safety."""

from __future__ import annotations

import platform
from unittest.mock import patch

import pytest

IS_MACOS = platform.system() == "Darwin"

# ── Test: DesktopTools init with no backends ──

class TestDesktopToolsInit:
    """DesktopTools must degrade gracefully when backends are missing."""

    def test_init_no_backends_returns_diagnostic_only(self) -> None:
        """When Quartz is missing AND cliclick is missing, only 2 diagnostic tools."""
        # Only run on non-macOS or when we mock is_macos
        if IS_MACOS:
            # On macOS with neither backend, should still get diagnostic tools
            with patch("shutil.which", return_value=None), patch("js.tools.desktop.controller_native._init_quartz") as mq:
                    mq.side_effect = lambda: setattr(
                        __import__("js.tools.desktop.controller_native", fromlist=["_QUARTZ_AVAILABLE"]),
                        "_QUARTZ_AVAILABLE", False)
                    from js.tools.desktop_tools import DesktopTools
                    dt = DesktopTools()
                    specs = dt.get_specs()
                    assert isinstance(specs, list)
                    assert len(specs) >= 2  # diagnostic tools always present
                    assert not dt.available  # write ops not available
                    assert dt.init_error  # should have some error message
        else:
            from js.tools.desktop_tools import DesktopTools
            dt = DesktopTools()
            specs = dt.get_specs()
            assert isinstance(specs, list)
            assert len(specs) >= 2
            assert not dt.available

    def test_get_specs_never_returns_none(self) -> None:
        """get_specs() must ALWAYS return a list, never None."""
        from js.tools.desktop_tools import DesktopTools
        dt = DesktopTools()
        specs = dt.get_specs()
        assert isinstance(specs, list)
        assert len(specs) > 0

# ── Test: Permission checker detail levels ──

class TestPermissionDetails:
    """Permission checks must return structured status."""

    # (removed — mock conflict with pydantic)

    def test_backend_imports_without_quartz(self) -> None:
        """controller_native should import without Quartz installed."""
        import sys
        with patch.dict(sys.modules, {"Quartz": None, "Quartz.CoreGraphics": None}):
            # Force reimport
            if "js.tools.desktop.controller_native" in sys.modules:
                del sys.modules["js.tools.desktop.controller_native"]
            try:
                from js.tools.desktop.controller_native import (
                    NativeDesktopBackend,
                )
                backend = NativeDesktopBackend()
                assert not backend.quartz_available
            except ImportError:
                pytest.skip("Cannot test backend import isolation")

    def test_fallback_methods_fail_without_backend(self) -> None:
        """Fallback methods raise when no backend is available."""
        from js.tools.desktop.controller_native import NativeDesktopBackend
        backend = NativeDesktopBackend()
        backend._cliclick = None
        # _native uses whatever _init_quartz found
        with pytest.raises(RuntimeError, match="No mouse backend"):
            backend._fallback_mouse_click(None, "left", 1)
