"""macOS permission detection for desktop control.

Requires Accessibility permission for mouse/keyboard control.
Requires Screen Recording permission for screenshots.
"""

from __future__ import annotations

import logging
import platform
import subprocess

logger = logging.getLogger("js.tools.desktop.permissions")


class PermissionChecker:
    """Check and request macOS permissions needed for desktop control."""

    _accessibility_checked: bool = False
    _screen_recording_checked: bool = False

    @classmethod
    def is_macos(cls) -> bool:
        return platform.system() == "Darwin"

    @classmethod
    def check_accessibility(cls) -> bool:
        """Check if the process has Accessibility permission.

        Returns True if granted, False if denied or unknown.
        """
        if not cls.is_macos():
            return True  # Non-macOS platforms don't need this check

        try:
            # Use AXIsProcessTrustedWithOptions via ctypes
            # This is the recommended API since macOS 10.9
            from ctypes import CDLL, c_bool, c_void_p

            lib = CDLL("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices")
            # AXIsProcessTrustedWithOptions takes a CFDictionaryRef (options)
            # Pass NULL (no options) to just check current state
            lib.AXIsProcessTrustedWithOptions.restype = c_bool
            lib.AXIsProcessTrustedWithOptions.argtypes = [c_void_p]
            result = lib.AXIsProcessTrustedWithOptions(None)
            cls._accessibility_checked = True
            return bool(result)
        except Exception as e:
            logger.debug(f"Accessibility check failed: {e}")
            # Fallback: try to use cliclick to test
            return cls._fallback_accessibility_check()

    @classmethod
    def _fallback_accessibility_check(cls) -> bool:
        """Fallback: try a harmless cliclick command to see if it works."""
        try:
            result = subprocess.run(
                ["cliclick", "p:"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
        except Exception:
            return False

    @classmethod
    def check_screen_recording(cls) -> bool:
        """Check if the process has Screen Recording permission.

        Returns True if granted, False if denied or unknown.
        """
        if not cls.is_macos():
            return True

        try:
            # CGPreflightScreenCaptureAccess is available in macOS 10.15+
            from ctypes import CDLL, c_bool

            lib = CDLL("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
            if not hasattr(lib, "CGPreflightScreenCaptureAccess"):
                # macOS < 10.15: no preflight API, assume granted
                return True

            lib.CGPreflightScreenCaptureAccess.restype = c_bool
            result = lib.CGPreflightScreenCaptureAccess()
            cls._screen_recording_checked = True
            return bool(result)
        except Exception as e:
            logger.debug(f"Screen recording check failed: {e}")
            # Fallback: try screencapture
            return cls._fallback_screen_recording_check()

    @classmethod
    def _fallback_screen_recording_check(cls) -> bool:
        """Fallback: try capturing a 1x1 pixel to /dev/null."""
        try:
            result = subprocess.run(
                ["screencapture", "-R0,0,1,1", "-x", "-c"],
                capture_output=True,
                timeout=3,
            )
            return result.returncode == 0
        except Exception:
            return False

    @classmethod
    def request_accessibility(cls) -> None:
        """Trigger the macOS Accessibility permission prompt."""
        if not cls.is_macos():
            return

        # Opening System Preferences to Security & Privacy > Accessibility
        subprocess.run(
            [
                "open",
                "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility",
            ],
            capture_output=True,
        )

    @classmethod
    def request_screen_recording(cls) -> None:
        """Trigger the macOS Screen Recording permission prompt."""
        if not cls.is_macos():
            return

        subprocess.run(
            [
                "open",
                "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture",
            ],
            capture_output=True,
        )

    @classmethod
    def get_status(cls) -> dict[str, bool]:
        """Get the current permission status."""
        return {
            "accessibility": cls.check_accessibility(),
            "screen_recording": cls.check_screen_recording(),
            "platform": cls.is_macos(),
        }

    @classmethod
    def assert_accessibility(cls) -> None:
        """Raise PermissionError if Accessibility is not granted."""
        if not cls.check_accessibility():
            raise PermissionError(
                "Accessibility permission is required for mouse/keyboard control. "
                "Please grant it in System Preferences > Security & Privacy > Accessibility."
            )

    @classmethod
    def assert_screen_recording(cls) -> None:
        """Raise PermissionError if Screen Recording is not granted."""
        if not cls.check_screen_recording():
            raise PermissionError(
                "Screen Recording permission is required for screenshots. "
                "Please grant it in System Preferences > Security & Privacy > Screen Recording."
            )
