from __future__ import annotations

import plistlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_macos_transport_security_allows_only_local_networking() -> None:
    info_path = REPO_ROOT / "desktop" / "src-tauri" / "Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    transport = info["NSAppTransportSecurity"]
    assert transport["NSAllowsLocalNetworking"] is True
    assert "NSAllowsArbitraryLoads" not in transport
    assert "NSExceptionDomains" not in transport
