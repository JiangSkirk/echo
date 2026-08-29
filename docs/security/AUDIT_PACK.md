# External audit pack

This is the in-repo handoff for an independent reviewer. It does **not**
claim that an external red team has run. Local tests cannot close
`TECH_DEBT.md` ⚫ items that require people outside this tree.

## 1. Boundary statement

Read first:

- [`SECURITY.md`](../../SECURITY.md) / [`SECURITY_en.md`](../../SECURITY_en.md)
- [`docs/security/THREAT_MODEL.md`](THREAT_MODEL.md)
- [`docs/security/orin/ORIN_STAGE_C_CLOSEOUT.md`](orin/ORIN_STAGE_C_CLOSEOUT.md)

Facts that must not be contradicted in a report:

- JS Agent is a local single-tenant harness, not multi-tenant SaaS.
- The load-bearing boundary for adversarial model output is OS isolation
  (per-tool `sandbox-exec` / `bwrap`, optional whole-process container).
- Echo leases, ledger, guard, and taint are authorization / defense in depth.
- `orin.enabled` and `orin.enforce` default to false. Stage C cells are
  `not_implemented`.
- Gateway and Friends default off. Host cold start must not import them.
- Evolution never auto-applies. There is no unattended self-modify path.

## 2. Attack surface list

| Surface | Default | Entry | Notes |
|---------|---------|-------|-------|
| Desktop Host / AppShell | on | loopback HTTP + desktop window | API key / session cookie |
| Echo turn | on | `run_echo_turn` | only production turn path |
| Tools + OS sandbox | on | Echo lease | fail-closed if backend missing |
| Memory / bots / fleet | on | owner-scoped SQLite | same `state_dir` |
| Gateway (Telegram / Discord / webhook) | off | inbound adapters | unpaired drop; taint |
| Friends v1 | off | HMAC inbound | L2 tasks `allowed_tools=[]` |
| Cron / daemon | opt-in | scheduled Echo | owner on the job row |
| Evolution cycle | admin | approve endpoint | mock benchmark rollback |
| Pipeline / mobile | reserved | not on Host cold start | mobile closeout: [`docs/mobile/MOBILE_CLOSEOUT.md`](../mobile/MOBILE_CLOSEOUT.md) (`not_implemented`) |

## 3. Known-unfixed list

Copy of the current ⚫ table in [`TECH_DEBT.md`](../../TECH_DEBT.md):

1. External tip anchor is not TPM.
2. Lease compaction scheduling depends on the governor.
3. `os_sandbox` process-tree RSS; `setsid` still a blind spot.
4. Parser vs `_fs_restricted_rejection` dual engines (ADR 0006).
5. TRUSTED skills need an operated public-key directory.
6. Shell allowlist is the boundary if `strict_isolation` is off.
7. `code.py` blacklists are depth, not the boundary.
8. bwrap placeholder deny for missing workspace `.git`.
9. Residual low-risk red-team items (R3) as recorded.

Plus: no official TCC / Developer ID / notarization; no independent red team
report in `docs/security/external/` (create that directory when one exists).

## 4. Reproduce the in-repo evidence

```bash
uv sync --frozen --extra dev --extra monitor --extra echo-tokenizer
uv run ruff check .
uv run mypy js --no-error-summary
uv run pytest tests/ -q
uv run python scripts/check_quality_labels.py --peak
uv run python scripts/test_density_report.py --min 1.2
python -m benchmarks.runner --mock
```

Multi-owner abuse matrix: `uv run pytest tests/multiuser -q`.

Internal live-deployment trial (process-level AppShell, not an external
audit): `uv run python scripts/staging_trial.py`. Dated receipt:
[`docs/security/staging-trial-2026-08-29.md`](staging-trial-2026-08-29.md).
The container recipe `docker-compose.staging.yaml` was not executed on the
authoring host (no Docker).

Isolation posture: `js doctor --security`.

Container trial:

- Hardened: `docker compose -f docker-compose.hardened.yaml up --build`
- Staging (two logical owners, audit volume):
  `docker compose -f docker-compose.staging.yaml up --build`

## 5. Suggested external procedure (out of repo)

1. Pick an independent reviewer (not the authors of the last 30 days of commits).
2. Work from this pack + a tagged commit SHA.
3. File findings privately (GitHub Security Advisories). No bounty.
4. Archive the signed report under `docs/security/external/` (gitignored
   until the operator chooses to publish a redacted copy).
5. Feed each finding back into `TECH_DEBT.md` or a fix PR that re-runs the
   §2 quality gate.
