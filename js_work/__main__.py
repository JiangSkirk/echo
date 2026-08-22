"""Allow ``python -m js_work`` to invoke the Work CLI entrypoint."""

from __future__ import annotations

from js_work.cli import compat_main

if __name__ == "__main__":
    compat_main()
