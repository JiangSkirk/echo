# Stage C C6/C7 evidence index (2026-08-28)

Evidence tags follow `ORIN_STAGE_C_SPEC.md` §1.1. This file is not a
release statement. **Stage C is not implemented. Echo RCE is not closed.**
The WP-C7 release verdict is [`ORIN_STAGE_C_CLOSEOUT.md`](ORIN_STAGE_C_CLOSEOUT.md).

## C6 fault / replay (harness observation)

| Case | Status | Notes |
|------|--------|-------|
| Desktop/Memory UNKNOWN_COMMIT no blind replay | harness 观察 | Existing C2/C3 harness tests |
| Memory client Cell-offline deny | harness 观察 | `tests/orin/test_orin_stagec_c6_faults.py` |
| Irreversible Connector provider idempotency | blocked | No test-account evidence in this tree |
| Physical power-loss exactly-once | untested | Not claimed |
| Production enforce crash matrix | untested | `orin.enforce` still fail-fast |

## C7 K§10.4 / product (honest)

| Gate | Status |
|------|--------|
| K§10.4 latency / RSS / start / backpressure | untested (harness fixtures only) |
| K§15.6 #8 real-model observe→act→observe | blocked | Opt-in `JS_K156_8_REAL_MODEL=1` only; default evidence bit stays false |
| K§15.6 #9 independent red team | external-pending |
| Official TCC / Developer ID / notary | external-pending |
| `orin.enforce` default true | forbidden until the ten gates close |

## Software observations added this wave

- Opt-in AppShell/Echo process-split **observation** (default off).
- Opt-in provider-via-cell transport (default off; no ambient fallback).
- Supervisor may pass `--cell-desktop` / `--cell-memory` when Stage B +
  identity + those flags are on. Still never passes `--orin-enforce`.
- K§8.5 HMAC receipts attached on Build/File/Services public results
  when a 32-byte Cell key is present.

None of the above opens `orin.enforce`.
