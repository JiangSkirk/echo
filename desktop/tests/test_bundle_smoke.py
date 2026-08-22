from __future__ import annotations

import os
import plistlib
import subprocess

from desktop.tests.candidate_app import resolve_candidate_app as resolve_candidate_app


def test_unsigned_arm64_app_contains_exactly_one_executable_sidecar() -> None:
    app = resolve_candidate_app()
    assert app.is_dir(), f"missing bundle: {app}"

    info_path = app / "Contents" / "Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    executable = app / "Contents" / "MacOS" / str(info["CFBundleExecutable"])
    assert executable.is_file()
    assert os.access(executable, os.X_OK)

    sidecars = sorted((app / "Contents" / "MacOS").glob("js-agent-host*"))
    assert [path.name for path in sidecars] == ["js-agent-host"]
    assert os.access(sidecars[0], os.X_OK)

    for binary in (executable, sidecars[0]):
        archs = subprocess.check_output(["/usr/bin/lipo", "-archs", binary], text=True)
        assert archs.strip() == "arm64"

    signature = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert signature.returncode == 0, (
        f"bundle signature must verify cleanly: {signature.stderr}"
    )
    details = subprocess.run(
        ["/usr/bin/codesign", "-dv", str(app)],
        text=True,
        capture_output=True,
        check=False,
    )
    descriptor = details.stderr + details.stdout
    assert "Signature=adhoc" in descriptor, descriptor
    assert "TeamIdentifier=not set" in descriptor, descriptor
