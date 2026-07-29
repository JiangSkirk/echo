# Local Red-Team Simulation Packet

Status: COMPLETE_LOCAL_SIMULATION_REAL_REDTEAM_REQUIRED
Generated: 2026-07-16T21:27:26Z

This packet records local adversarial simulation evidence. It is not a real independent red-team report.

## Attack Families Simulated Locally

- Prompt injection and secret exfiltration before model call.
- Attachment owner/session bypass.
- Tool lease missing, tampered, cross-run, and args-mismatch paths.
- WebSocket terminal ordering and same-session concurrency.
- Journal corrupt tail, replay, claim/receipt/merge, and compaction behavior.
- Sandbox real-process backend probe.
- Echo self-developed/IP boundary drift.

## Evidence

### Echo Ledger Smoke

```text
$ /Users/jiangxuanzhen/titan-agent/.venv/bin/python scripts/echo_ledger_smoke.py --turns 5 --state-dir <temporary-state-dir>
exit=0
echo_ledger_smoke ok mode=on records=45 journal=<temporary-state-dir>/echo/ledger/chat.jsonl
```

### Release Smoke

```text
$ /Users/jiangxuanzhen/titan-agent/.venv/bin/python scripts/release_smoke.py --all
exit=0
[检查] package
[OK] package
[检查] web/model
[OK] web/model
[OK] model 已包含在 web/provider 烟测中
[检查] skills
[OK] skills
[检查] dream
[OK] dream
[检查] evolution
[OK] evolution
[检查] fleet
[OK] fleet
[检查] work
[OK] work
[检查] echo
[OK] echo
[检查] echo_ledger
[OK] echo_ledger
发布烟测通过。
```

### Benchmark And Safety Matrix

See `docs/security/ECHO_SLO_BENCHMARK.json` for latest benchmark artifact and 25-case security matrix result.

## Real Red-Team Needed

A real red team must still attack a deployed or deployment-like environment with independent operators and retest closure.
