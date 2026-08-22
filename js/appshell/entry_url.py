"""Build local AppShell entry URLs that can carry a bootstrap fragment.

The fragment never enters HTTP request logs; the Web UI exchanges it for an
HttpOnly session cookie and strips it from the address bar.
"""

from __future__ import annotations

import stat
from pathlib import Path
from urllib.parse import quote


def bootstrap_browser_url(url: str, state_dir: Path | None) -> str:
    """Return ``url`` or ``url#bootstrap-api-key=...`` when a safe key file exists."""
    if state_dir is None:
        return url
    key_file = Path(state_dir) / "bootstrap_admin_key.txt"
    try:
        metadata = key_file.lstat()
        if key_file.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            return url
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            return url
        key = key_file.read_text(encoding="utf-8").strip()
    except OSError:
        return url
    if not key:
        return url
    return url.rstrip("/") + "/#bootstrap-api-key=" + quote(key, safe="")
