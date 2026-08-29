# Internal live-deployment trial (2026-08-29)

This is an **internal live-deployment trial, not an external audit**.
Local process HTTP cannot close `TECH_DEBT.md` ⚫ items that require
people outside this tree.

## Environment

- Host: `http://127.0.0.1:57994` via `js appshell` (uvicorn loopback)
- Docker staging compose ran: `False`
- Reason: docker is not available on this host; process-level only
- Work dir: `/var/folders/t8/hp9mcjnd0_s08_43cp5f3xnm0000gn/T/js-staging-trial-1fcyxeul`
- Result: 9/9 PASS

Reproduce:

```bash
uv run python scripts/staging_trial.py
```

Container path (not run this round):
`docker compose -f docker-compose.staging.yaml up --build`

## Cases

| Case | Result | Detail |
|------|--------|--------|
| `anon_status_401` | PASS | status=401 |
| `raw_key_without_appshell_session` | PASS | status=401 |
| `session_exchange` | PASS | 200/200/200 |
| `authed_status` | PASS | 200/200 |
| `alice_write_memory` | PASS | status=200 body={'success': True, 'key': 'trial-secret', 'conflicts': [], 'evicted': 0, 'memory_id': 1, 'memory_path': '/general', 'entity_type': 'general', 'layered': {'claim_id': '52ca9057-d9a9-4019-8bdc-e7ef0ce5235b', 'status': 'active', 'subject_id': '8bd73c22-e5da-4b54-ac6b-37fc31aae334', 'superseded': [], 'skipped_duplicate': False}} |
| `bob_cannot_search_alice_memory` | PASS | status=200 leaked=False n=0 |
| `non_owner_or_user_audit` | PASS | bob=200 user=403 |
| `api_key_header_still_accepted_on_host` | PASS | 200 |
| `concurrent_session_list` | PASS | codes=[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200] |
