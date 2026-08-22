"""PoC (post-fix verification): tamper-evident audit chain wipe detection.

Original finding: `_init_db` (js/security/audit.py) silently re-anchored the
chain whenever the `audit_chain_state` row was missing, so deleting all rows
+ chain state made a full wipe indistinguishable from a fresh install.

Fix under test:
  1. state row missing while audit_log is NON-empty -> RuntimeError
     (fail-closed, manual forensics required).
  2. state row missing + empty log + `audit.initialized` sentinel present ->
     logger.critical "possible audit chain wipe" (fail-visible), then re-anchor.
  3. genuine first run -> sentinel created, no alarm.

Residual: an attacker who also deletes the sentinel file still degrades to a
"fresh install" shape — documented in REPORT.md (host-level write access to
the state dir is outside the agent's threat containment).
"""

from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from js.security.audit import AuditEventType, AuditLogger  # noqa: E402

RESULTS: list[tuple[str, str, str]] = []


def record(case: str, verdict: str, detail: str) -> None:
    RESULTS.append((case, verdict, detail))
    print(f"[{verdict:>10}] {case}: {detail}")


def wipe(tmp: Path, *, rows: bool, state: bool) -> None:
    conn = sqlite3.connect(tmp / "audit.db")
    if rows:
        conn.execute("DELETE FROM audit_log")
    if state:
        conn.execute("DELETE FROM audit_chain_state")
    conn.commit()
    conn.close()


class _CriticalCapture:
    """Wrap the audit module's structlog logger and record critical() calls."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.messages: list[str] = []

    def critical(self, msg: str, *args: object, **kwargs: object) -> None:
        self.messages.append(str(msg))
        self._inner.critical(msg, *args, **kwargs)

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)


def main() -> None:
    import js.security.audit as audit_mod

    capture = _CriticalCapture(audit_mod.logger)
    audit_mod.logger = capture

    # ---- case 1: non-empty log + missing chain state -> refuse to start ----
    tmp = Path(tempfile.mkdtemp(prefix="redteam-audit-"))
    try:
        log = AuditLogger(tmp)
        for i in range(5):
            log.log(AuditEventType.SECURITY_ALERT, f"s{i}", f"r{i}",
                    "attacker", f"evil_action_{i}", {"i": i})
        del log
        wipe(tmp, rows=False, state=True)
        try:
            AuditLogger(tmp)
            record("non-empty log + state deleted", "CONFIRMED", "silent re-anchor still happens")
        except RuntimeError:
            record("non-empty log + state deleted", "REFUTED", "startup refused (fail-closed)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # ---- case 2: full wipe with sentinel present -> critical alert ---------
    tmp = Path(tempfile.mkdtemp(prefix="redteam-audit-"))
    try:
        log = AuditLogger(tmp)
        log.log(AuditEventType.SECURITY_ALERT, "s", "r", "attacker", "act", {})
        del log
        assert (tmp / "audit.initialized").exists(), "sentinel missing after first init"
        capture.messages.clear()
        wipe(tmp, rows=True, state=True)
        log2 = AuditLogger(tmp)  # restart after full wipe
        alerted = any("wipe" in m.lower() for m in capture.messages)
        record("full wipe + sentinel present", "REFUTED" if alerted else "CONFIRMED",
               "critical alert raised" if alerted else "re-anchored silently")
        ok, n = log2.verify_chain()
        record("chain still functions after alert", "PASS" if ok else "FAIL",
               f"verify_chain=({ok}, {n})")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # ---- case 3: genuine first run stays quiet ------------------------------
    tmp = Path(tempfile.mkdtemp(prefix="redteam-audit-"))
    try:
        capture.messages.clear()
        log = AuditLogger(tmp)
        log.log(AuditEventType.SECURITY_ALERT, "s", "r", "user", "act", {})
        ok, n = log.verify_chain()
        quiet = not capture.messages
        record("fresh install", "PASS" if ok and quiet and (tmp / "audit.initialized").exists()
               else "FAIL", f"verify_chain=({ok}, {n}) critical_alerts={len(capture.messages)}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n=== SUMMARY ===")
    failures = [case for case, verdict, _ in RESULTS if verdict in ("CONFIRMED", "FAIL")]
    for case, verdict, _ in RESULTS:
        print(f"  {verdict:>10}  {case}")
    print("\n" + ("ATTACK REMAINS: " + ", ".join(failures) if failures
                  else "AUDIT WIPE NOW DETECTED/REFUSED"))


if __name__ == "__main__":
    main()
