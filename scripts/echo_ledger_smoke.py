#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from js.config import JSSettings
from js.echo.ledger.service import EchoSafetyService


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local Echo long-running smoke.")
    parser.add_argument("--turns", type=int, default=5)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--keep-state", action="store_true")
    args = parser.parse_args()

    if args.state_dir.exists() and not args.keep_state:
        shutil.rmtree(args.state_dir)
    settings = JSSettings(state_dir=args.state_dir)
    service = EchoSafetyService.from_settings(settings)
    for index in range(args.turns):
        result = service.record_chat_turn(
            tenant_id="local-smoke",
            run_id=f"smoke-session-{index}",
            user_text=f"hello {index}",
            assistant_text=f"hi {index}",
            status="completed",
            token_totals={"input": 2, "output": 2},
        )
        if not result.ok:
            print(f"echo_ledger_smoke failed error={result.error}")
            return 1

    restarted = EchoSafetyService.from_settings(settings)
    health = restarted.health()
    if not health.ok:
        print(f"echo_ledger_smoke failed health={health}")
        return 1
    print(
        "echo_ledger_smoke ok "
        f"mode={health.mode} records={health.record_count} journal={health.journal_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
