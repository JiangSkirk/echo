"""Test-only loader for exercising the source Host with an embedded digest fixture."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EMBEDDED_DIGEST = Path(__file__).with_name("embedded_source_digest.txt")


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    embedded_path = DEFAULT_EMBEDDED_DIGEST
    if arguments[:1] == ["--embedded-digest-file"]:
        if len(arguments) < 2:
            raise SystemExit("missing test embedded digest fixture")
        embedded_path = Path(arguments[1])
        del arguments[:2]

    sys.path.insert(0, str(REPO_ROOT))
    from desktop import source_digest
    from desktop.sidecar.host import main as host_main

    if os.environ.get("JS_AGENT_TEST_UNSAFE_EMBEDDED_LOADER") == "1":
        source_digest._EMBEDDED_DIGEST_FILE = embedded_path

        def unsafe_loader() -> str:
            return embedded_path.read_text(encoding="ascii")

        source_digest.load_embedded_sidecar_digest = unsafe_loader
        return host_main(arguments)

    if embedded_path != DEFAULT_EMBEDDED_DIGEST:
        source_digest._EMBEDDED_DIGEST_FILE = embedded_path
        return host_main(arguments)

    # apply_patch-managed text fixtures have a final newline. Stage the exact
    # 64-byte build resource so production parsing remains strict.
    with tempfile.TemporaryDirectory(prefix="js-agent-host-fixture-") as temporary:
        staged = Path(temporary) / ".embedded_source_digest"
        staged.write_bytes(DEFAULT_EMBEDDED_DIGEST.read_text(encoding="ascii").strip().encode())
        source_digest._EMBEDDED_DIGEST_FILE = staged
        return host_main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
